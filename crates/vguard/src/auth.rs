//! NIP-42: which key a connection signed in with.
//!
//! vguard checks the AUTH event itself, as strfry does: a kind 22242 signed
//! by its key, over a challenge this connection was given, naming this
//! relay, made about now. Without the name of the relay a relay elsewhere
//! could pass our challenge on to its own user and sign in here as them.

use nostr::prelude::*;
use serde_json::Value;

use crate::config::Config;

/// NIP-42's kind.
pub const KIND_AUTH: u16 = 22242;

/// A signed-in key and the event that did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    /// Hex.
    pub pubkey: String,
    /// Hex.
    pub event_id: String,
    pub challenge: String,
}

/// The id of an AUTH event, as far as it can be read: what the OK names.
pub fn event_id_of(event: &Value) -> String {
    event
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .chars()
        .take(64)
        .collect()
}

fn tag<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .map(|t| t.as_slice())
        .find(|t| t.first().map(String::as_str) == Some(name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

/// Whether `relay` (the `relay` tag) names this relay: ws or wss, one of
/// `relay_hosts`; a path or a query (the app key) does not matter.
pub fn names_this_relay(config: &Config, relay: &str) -> bool {
    let Ok(url) = url::Url::parse(relay) else {
        return false;
    };
    matches!(url.scheme(), "wss" | "ws") && url.host_str().is_some_and(|h| config.is_relay_host(h))
}

/// The AUTH event `event` against the challenges given (`known`), at `now`
/// (unix seconds).
pub fn verify(
    config: &Config,
    event: &Value,
    known: impl Fn(&str) -> bool,
    now: u64,
) -> Result<SignedIn, String> {
    let event: Event =
        serde_json::from_value(event.clone()).map_err(|e| format!("not an event: {e}"))?;
    if event.kind.as_u16() != KIND_AUTH {
        return Err(format!("an AUTH is of kind {KIND_AUTH}"));
    }
    event
        .verify()
        .map_err(|_| "the id or the signature does not check".to_string())?;
    let at = event.created_at.as_secs();
    if at.abs_diff(now) > config.limits.auth_skew_secs {
        return Err("created_at is too far from now".into());
    }
    let challenge = tag(&event, "challenge").ok_or("no challenge tag")?;
    if !known(challenge) {
        return Err("not the challenge of this connection".into());
    }
    let relay = tag(&event, "relay").ok_or("no relay tag")?;
    if !names_this_relay(config, relay) {
        return Err("the relay tag names another relay".into());
    }
    Ok(SignedIn {
        pubkey: event.pubkey.to_hex(),
        event_id: event.id.to_hex(),
        challenge: challenge.to_string(),
    })
}

/// A challenge of vguard's own: 16 random bytes, hex.
pub fn new_challenge() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("the system gives random bytes");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn config() -> Config {
        Config::parse("relay_hosts = [\"relay.example.org\", \"r.example.net\"]\n").unwrap()
    }

    pub(crate) fn auth_event(keys: &Keys, challenge: &str, relay: &str, at: u64) -> Value {
        let ev = EventBuilder::new(Kind::Authentication, "")
            .tags([
                Tag::parse(["challenge", challenge]).unwrap(),
                Tag::parse(["relay", relay]).unwrap(),
            ])
            .custom_created_at(Timestamp::from_secs(at))
            .finalize(keys)
            .unwrap();
        serde_json::to_value(&ev).unwrap()
    }

    #[test]
    fn a_good_auth_signs_in() {
        let keys = Keys::generate();
        let now = 1_800_000_000;
        let ev = auth_event(&keys, "c1", "wss://relay.example.org/?key=appkey", now);
        let s = verify(&config(), &ev, |c| c == "c1", now + 5).unwrap();
        assert_eq!(s.pubkey, keys.public_key().to_hex());
        assert_eq!(s.event_id, event_id_of(&ev));
        // An alias, upper case, no path.
        let ev = auth_event(&keys, "c1", "wss://R.EXAMPLE.NET", now);
        assert!(verify(&config(), &ev, |c| c == "c1", now).is_ok());
        // A phone whose clock is 2 days off, either way, still signs in.
        for at in [now - 2 * DAY, now + 2 * DAY] {
            let ev = auth_event(&keys, "c1", "wss://relay.example.org", at);
            assert!(verify(&config(), &ev, |c| c == "c1", now).is_ok());
        }
    }

    const DAY: u64 = 24 * 3600;

    #[test]
    fn what_does_not_sign_in() {
        let keys = Keys::generate();
        let now = 1_800_000_000;
        let cfg = config();
        let known = |c: &str| c == "c1";
        // Another challenge.
        assert!(verify(
            &cfg,
            &auth_event(&keys, "c2", "wss://relay.example.org", now),
            known,
            now
        )
        .is_err());
        // Another relay: the one that passed our challenge on.
        assert!(verify(
            &cfg,
            &auth_event(&keys, "c1", "wss://evil.example.com", now),
            known,
            now
        )
        .is_err());
        assert!(verify(
            &cfg,
            &auth_event(&keys, "c1", "wss://relay.example.org.evil.com", now),
            known,
            now
        )
        .is_err());
        assert!(verify(
            &cfg,
            &auth_event(&keys, "c1", "https://relay.example.org", now),
            known,
            now
        )
        .is_err());
        // A clock 4 days off, either way: too far.
        for at in [now - 4 * DAY, now + 4 * DAY] {
            assert!(verify(
                &cfg,
                &auth_event(&keys, "c1", "wss://relay.example.org", at),
                known,
                now
            )
            .is_err());
        }
        // Tampered: the id no longer checks.
        let mut ev = auth_event(&keys, "c1", "wss://relay.example.org", now);
        ev["content"] = "x".into();
        assert!(verify(&cfg, &ev, known, now).is_err());
        // Another kind.
        let note = EventBuilder::new(Kind::TextNote, "")
            .tags([
                Tag::parse(["challenge", "c1"]).unwrap(),
                Tag::parse(["relay", "wss://relay.example.org"]).unwrap(),
            ])
            .custom_created_at(Timestamp::from_secs(now))
            .finalize(&keys)
            .unwrap();
        assert!(verify(&cfg, &serde_json::to_value(&note).unwrap(), known, now).is_err());
        assert!(verify(&cfg, &serde_json::json!({"kind": 22242}), known, now).is_err());
    }

    #[test]
    fn challenges_differ() {
        let a = new_challenge();
        assert_eq!(a.len(), 32);
        assert_ne!(a, new_challenge());
    }
}
