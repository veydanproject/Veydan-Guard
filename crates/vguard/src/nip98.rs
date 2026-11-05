//! Who is asking the access API: NIP-98, and the authorization of Blossom
//! (kind 24242) for the media host.
//!
//! A request of the API carries `Authorization: Nostr <base64 of an
//! event>`: kind 27235, signed by the user's key, naming the address
//! (`u`), the method and the sha256 of the body (`payload`) it was signed
//! for, made within a minute of now. An event opens one request: its id
//! is remembered for as long as it could be used again.
//!
//! `services/push/crates/vpush-server/src/auth.rs` has the same check of
//! NIP-98; the two move to a shared crate of Veydan-Common later.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use nostr::prelude::{Event, Kind};

/// How far the client's clock may be from the server's, either way.
pub const WINDOW_SECS: u64 = 60;
/// How long a used event is remembered: an event dated a window ahead is
/// good now and for two windows more (and a second, the clock counting
/// whole seconds).
const REMEMBER: Duration = Duration::from_secs(2 * WINDOW_SECS + 2);
/// Used events remembered at one time; past this many a request is
/// refused, not remembered.
const MAX_REMEMBERED: usize = 100_000;
/// Longer than any header of this kind has a reason to be.
const MAX_HEADER: usize = 16 * 1024;
const SCHEME: &str = "Nostr ";
/// The kind of NIP-98.
pub const KIND_HTTP_AUTH: u16 = 27235;
/// The kind of the authorization of Blossom (BUD-01).
pub const KIND_BLOSSOM_AUTH: u16 = 24242;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Invalid(String),
    Expired,
    Replay,
    /// As many used events are remembered as may be.
    Busy,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The signed event of an `Authorization: Nostr …` header, its id and
/// signature checked.
fn event_of(header: Option<&str>) -> Result<Event, AuthError> {
    let header = header.ok_or(AuthError::Missing)?;
    if header.len() > MAX_HEADER {
        return Err(AuthError::Invalid("the header is too long".into()));
    }
    let encoded = header
        .strip_prefix(SCHEME)
        .ok_or_else(|| AuthError::Invalid("the scheme is not Nostr".into()))?;
    let json = STANDARD
        .decode(encoded.trim())
        .map_err(|_| AuthError::Invalid("not base64".into()))?;
    let event: Event = serde_json::from_slice(&json).map_err(|_| AuthError::Invalid("not an event".into()))?;
    event
        .verify()
        .map_err(|_| AuthError::Invalid("the id or the signature does not check".into()))?;
    Ok(event)
}

fn tag<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|t| match t.as_slice() {
        [kind, value, ..] if kind == name => Some(value.as_str()),
        _ => None,
    })
}

/// The ids of the events used, for as long as they could be used again.
#[derive(Default)]
struct Seen {
    ids: HashSet<[u8; 32]>,
    order: VecDeque<([u8; 32], Instant)>,
}

impl Seen {
    fn take(&mut self, id: [u8; 32], now: Instant) -> Result<(), AuthError> {
        while let Some((old, at)) = self.order.front() {
            if now.saturating_duration_since(*at) < REMEMBER {
                break;
            }
            self.ids.remove(old);
            self.order.pop_front();
        }
        if self.ids.contains(&id) {
            return Err(AuthError::Replay);
        }
        if self.ids.len() >= MAX_REMEMBERED {
            return Err(AuthError::Busy);
        }
        self.ids.insert(id);
        self.order.push_back((id, now));
        Ok(())
    }
}

/// Checks the requests of the API, and remembers their events.
pub struct Nip98 {
    /// The server's address as clients see it, without a trailing slash.
    public_url: String,
    seen: Mutex<Seen>,
}

impl Nip98 {
    pub fn new(public_url: &str) -> Self {
        Self { public_url: public_url.trim_end_matches('/').to_string(), seen: Mutex::default() }
    }

    /// The address a request for `path_and_query` is signed for.
    pub fn url_of(&self, path_and_query: &str) -> String {
        format!("{}{}", self.public_url, path_and_query)
    }

    /// The key (hex) that signed the request, with its event used up.
    /// `now`: unix seconds.
    pub fn check(
        &self,
        header: Option<&str>,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: u64,
    ) -> Result<String, AuthError> {
        let event = event_of(header)?;
        if event.kind != Kind::from(KIND_HTTP_AUTH) {
            return Err(AuthError::Invalid(format!("the event is not of kind {KIND_HTTP_AUTH}")));
        }
        if event.created_at.as_secs().abs_diff(now) > WINDOW_SECS {
            return Err(AuthError::Expired);
        }
        match tag(&event, "u") {
            Some(u) if u == self.url_of(path_and_query) => {}
            Some(_) => return Err(AuthError::Invalid("signed for another address".into())),
            None => return Err(AuthError::Invalid("no `u` tag".into())),
        }
        match tag(&event, "method") {
            Some(m) if m.eq_ignore_ascii_case(method) => {}
            Some(_) => return Err(AuthError::Invalid("signed for another method".into())),
            None => return Err(AuthError::Invalid("no `method` tag".into())),
        }
        if !body.is_empty() {
            match tag(&event, "payload") {
                Some(p) if p.eq_ignore_ascii_case(&sha256_hex(body)) => {}
                Some(_) => return Err(AuthError::Invalid("signed for another body".into())),
                None => return Err(AuthError::Invalid("no `payload` tag".into())),
            }
        }
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(event.id.to_bytes(), Instant::now())?;
        Ok(event.pubkey.to_hex())
    }
}

/// The key (hex) of a Blossom authorization (kind 24242, as the app sends
/// with every upload): signed, its `expiration` still ahead. It is made to
/// be used more than once until then (an upload is retried), so nothing is
/// remembered.
pub fn blossom_signer(header: Option<&str>, now: u64) -> Result<String, AuthError> {
    let event = event_of(header)?;
    if event.kind != Kind::from(KIND_BLOSSOM_AUTH) {
        return Err(AuthError::Invalid(format!("the event is not of kind {KIND_BLOSSOM_AUTH}")));
    }
    let expiration = tag(&event, "expiration")
        .and_then(|e| e.parse::<u64>().ok())
        .ok_or_else(|| AuthError::Invalid("no expiration".into()))?;
    if expiration <= now {
        return Err(AuthError::Expired);
    }
    Ok(event.pubkey.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::*;

    const BASE: &str = "https://relay.example.org";
    const PATH: &str = "/.well-known/veydan-access/v1/join";
    const NOW: u64 = 1_800_000_000;

    fn header(keys: &Keys, kind: u16, tags: &[(&str, String)], at: u64) -> String {
        let ev = EventBuilder::new(Kind::from(kind), "")
            .tags(tags.iter().map(|(k, v)| Tag::parse([*k, v.as_str()]).unwrap()))
            .custom_created_at(Timestamp::from_secs(at))
            .finalize(keys)
            .unwrap();
        format!("Nostr {}", STANDARD.encode(serde_json::to_vec(&ev).unwrap()))
    }

    fn signed(keys: &Keys, url: &str, method: &str, body: &[u8], at: u64) -> String {
        header(keys, KIND_HTTP_AUTH, &[("u", url.into()), ("method", method.into()), ("payload", sha256_hex(body))], at)
    }

    #[test]
    fn a_request_is_signed_for_its_address_method_body_and_minute() {
        let n = Nip98::new(&format!("{BASE}/"));
        let keys = Keys::generate();
        let url = format!("{BASE}{PATH}");
        let body = br#"{"invite":"x"}"#;
        let h = signed(&keys, &url, "POST", body, NOW);
        assert_eq!(n.check(Some(&h), "POST", PATH, body, NOW + 30), Ok(keys.public_key().to_hex()));
        assert_eq!(n.check(Some(&h), "POST", PATH, body, NOW + 30), Err(AuthError::Replay), "once");
        let h = signed(&keys, &url, "POST", body, NOW);
        let h2 = signed(&keys, &url, "POST", body, NOW + 1);
        assert_eq!(n.check(Some(&h), "POST", PATH, body, NOW + 61), Err(AuthError::Expired));
        assert!(matches!(n.check(Some(&h2), "GET", PATH, body, NOW), Err(AuthError::Invalid(_))));
        assert!(matches!(n.check(Some(&h2), "POST", "/other", body, NOW), Err(AuthError::Invalid(_))));
        assert!(matches!(n.check(Some(&h2), "POST", PATH, b"{}", NOW), Err(AuthError::Invalid(_))));
        assert_eq!(n.check(None, "POST", PATH, body, NOW), Err(AuthError::Missing));
        assert!(matches!(n.check(Some("Basic x"), "POST", PATH, body, NOW), Err(AuthError::Invalid(_))));
        assert!(matches!(n.check(Some("Nostr !!"), "POST", PATH, body, NOW), Err(AuthError::Invalid(_))));
        let other_kind = header(&keys, 1, &[("u", url.clone()), ("method", "POST".into())], NOW);
        assert!(matches!(n.check(Some(&other_kind), "POST", PATH, b"", NOW), Err(AuthError::Invalid(_))));
        // A GET has no body to sign.
        let get = header(&keys, KIND_HTTP_AUTH, &[("u", url.clone()), ("method", "GET".into())], NOW);
        assert!(n.check(Some(&get), "GET", PATH, b"", NOW).is_ok());
        // A tampered event does not check.
        let mut ev: serde_json::Value = serde_json::from_slice(&STANDARD.decode(&h2["Nostr ".len()..]).unwrap()).unwrap();
        ev["created_at"] = (NOW + 2).into();
        let bad = format!("Nostr {}", STANDARD.encode(ev.to_string()));
        assert!(matches!(n.check(Some(&bad), "POST", PATH, body, NOW), Err(AuthError::Invalid(_))));
    }

    #[test]
    fn the_used_events_are_forgotten_after_two_windows() {
        let mut s = Seen::default();
        let t = Instant::now();
        assert!(s.take([1; 32], t).is_ok());
        assert_eq!(s.take([1; 32], t + Duration::from_secs(60)), Err(AuthError::Replay));
        assert!(s.take([1; 32], t + REMEMBER).is_ok());
        assert_eq!(s.order.len(), 1);
    }

    #[test]
    fn a_blossom_authorization_until_its_expiration() {
        let keys = Keys::generate();
        let h = header(&keys, KIND_BLOSSOM_AUTH, &[("t", "upload".into()), ("expiration", (NOW + 60).to_string())], NOW);
        assert_eq!(blossom_signer(Some(&h), NOW), Ok(keys.public_key().to_hex()));
        assert_eq!(blossom_signer(Some(&h), NOW), Ok(keys.public_key().to_hex()), "used again");
        assert_eq!(blossom_signer(Some(&h), NOW + 60), Err(AuthError::Expired));
        let none = header(&keys, KIND_BLOSSOM_AUTH, &[("t", "upload".into())], NOW);
        assert!(matches!(blossom_signer(Some(&none), NOW), Err(AuthError::Invalid(_))));
        let nip98 = header(&keys, KIND_HTTP_AUTH, &[("expiration", (NOW + 60).to_string())], NOW);
        assert!(matches!(blossom_signer(Some(&nip98), NOW), Err(AuthError::Invalid(_))));
        assert_eq!(blossom_signer(None, NOW), Err(AuthError::Missing));
    }
}
