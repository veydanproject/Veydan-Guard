//! Who may use the relay: the access mode of a server (spec/vguard.md,
//! "Access modes").
//!
//! - `open`: anybody with the app key, as before 0.7.0; nothing here acts.
//! - `team`: a company's server. Only its members read and write; a member
//!   gets in by an invite code (the access API, `api.rs`).
//! - `channel`: a blogger's server. Anybody reads what is public and may
//!   join and comment within `guest_kinds`, at `guest_events_per_minute`;
//!   everything else is written by the members (the authors) alone.
//!
//! There are no accounts: a member is a key in `members_file`, an admin a
//! key in `admins`, and the identity of a connection is the key it signed
//! in with (NIP-42), never the `pubkey` of an event (a gift wrap and the
//! events of a keeper are signed by keys of their own). The app key stays
//! the gate of nginx; it means nothing here.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use nostr::prelude::{FromBech32, PublicKey};
use serde_json::Value;
use veydan_denied::{KeyList, Refreshed};

use crate::config::AccessConfig;
use crate::policy::{self, Refusal};

/// The access mode of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Open,
    Team,
    Channel,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Mode::Open),
            "team" => Some(Mode::Team),
            "channel" => Some(Mode::Channel),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Open => "open",
            Mode::Team => "team",
            Mode::Channel => "channel",
        }
    }
}

/// A key as written by a person (npub, or 64 hex in any case) as the files
/// carry it: 64 lowercase hex. None when it is no key on the curve.
pub fn key_hex(s: &str) -> Option<String> {
    let s = s.trim();
    let key = if s.starts_with("npub1") {
        PublicKey::from_bech32(s).ok()?
    } else if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        PublicKey::from_hex(&s.to_ascii_lowercase()).ok()?
    } else {
        return None;
    };
    Some(key.to_hex())
}

/// Who a connection is, for the access mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Who {
    /// Not signed in.
    Anonymous,
    /// Signed in with a key that is neither a member nor an admin.
    Guest(String),
    /// Signed in as a member or an admin.
    Member(String),
}

impl Who {
    pub fn key(&self) -> Option<&str> {
        match self {
            Who::Anonymous => None,
            Who::Guest(k) | Who::Member(k) => Some(k),
        }
    }
}

/// Why an EVENT is refused by the access mode. The words are NIP-01's:
/// nostr-sdk signs in and sends the event again on `auth-required`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    AuthRequired(&'static str),
    Restricted(&'static str),
    RateLimited,
}

impl Refused {
    /// The text of the OK.
    pub fn message(&self) -> String {
        match self {
            Refused::AuthRequired(m) => format!("auth-required: {m}"),
            Refused::Restricted(m) => format!("restricted: {m}"),
            Refused::RateLimited => "rate-limited: slow down".into(),
        }
    }
}

/// The answers, one place.
pub const FOR_MEMBERS: &str = "this server is for its members";
pub const NOT_A_MEMBER_ASK: &str = "not a member of this server; ask its admin for an invite";
pub const NOT_A_MEMBER: &str = "not a member of this server";
pub const SIGN_IN_TO_WRITE: &str = "sign in to write on this server";
pub const AUTHORS_WRITE: &str = "on this server only its authors write";
pub const WRAPS_TO_AUTHORS: &str = "a guest writes to the authors of this server only";
pub const OWN_LISTS: &str = "a guest writes its own profile and relay lists only";

/// The kinds a guest may write only as itself: the profile and the relay
/// lists (of messages: 10050).
const OWN_KINDS: [u64; 3] = [0, 10002, 10050];

/// The events a guest may still write on one connection: `per_minute` at
/// once, refilled by `per_minute / 60` every second.
#[derive(Debug, Clone)]
pub struct Bucket {
    per_minute: f64,
    tokens: f64,
    at: Option<Instant>,
}

impl Bucket {
    pub fn new(per_minute: u32) -> Self {
        let per_minute = f64::from(per_minute.max(1));
        Self { per_minute, tokens: per_minute, at: None }
    }

    /// One event, at `now`: false when there is none left.
    pub fn take_at(&mut self, now: Instant) -> bool {
        if let Some(at) = self.at {
            let secs = now.saturating_duration_since(at).as_secs_f64();
            self.tokens = (self.tokens + secs * self.per_minute / 60.0).min(self.per_minute);
        }
        self.at = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn take(&mut self) -> bool {
        self.take_at(Instant::now())
    }
}

/// The access mode of this relay with its members and admins: shared by
/// every connection; the members are read again by the proxy.
pub struct Access {
    pub mode: Mode,
    /// `members_file`, read again when it changes and on SIGHUP.
    pub members: Arc<KeyList>,
    /// Hex.
    pub admins: HashSet<String>,
    pub guest_kinds: HashSet<u64>,
    pub guest_events_per_minute: u32,
}

impl Access {
    /// `open`: nothing acts.
    pub fn open() -> Self {
        Self::from_config(&AccessConfig::default())
    }

    pub fn from_config(c: &AccessConfig) -> Self {
        let members = match &c.members_file {
            Some(path) => KeyList::from_file(path),
            None => KeyList::none(),
        };
        Self {
            mode: c.mode(),
            members: Arc::new(members),
            admins: c.admins.iter().filter_map(|a| key_hex(a)).collect(),
            guest_kinds: c.guest_kinds.iter().map(|k| u64::from(*k)).collect(),
            guest_events_per_minute: c.guest_events_per_minute,
        }
    }

    /// A mode with fixed members and admins (hex), for tests.
    pub fn fixed(mode: Mode, members: &[&str], admins: &[&str]) -> Self {
        let mut c = AccessConfig { mode: mode.as_str().into(), ..AccessConfig::default() };
        c.admins = admins.iter().map(|a| a.to_string()).collect();
        let mut a = Self::from_config(&c);
        a.members = Arc::new(KeyList::of(members));
        a
    }

    pub fn is_open(&self) -> bool {
        self.mode == Mode::Open
    }

    pub fn is_admin(&self, key: &str) -> bool {
        self.admins.contains(&key.to_ascii_lowercase())
    }

    /// A member or an admin.
    pub fn admits(&self, key: &str) -> bool {
        self.is_admin(key) || self.members.contains(key)
    }

    pub fn who(&self, signed_in: Option<&str>) -> Who {
        match signed_in {
            None => Who::Anonymous,
            Some(k) if self.admits(k) => Who::Member(k.to_string()),
            Some(k) => Who::Guest(k.to_string()),
        }
    }

    /// The bucket of a new connection.
    pub fn bucket(&self) -> Bucket {
        Bucket::new(self.guest_events_per_minute)
    }

    /// A question (REQ, COUNT, NEG-OPEN), before its filters are looked at:
    /// a team's server answers its members only; the others ask as before.
    pub fn check_question(&self, who: &Who) -> Result<(), Refusal> {
        match (self.mode, who) {
            (Mode::Team, Who::Anonymous) => Err(Refusal::AuthRequired(FOR_MEMBERS.into())),
            (Mode::Team, Who::Guest(_)) => Err(Refusal::Restricted(NOT_A_MEMBER_ASK.into())),
            _ => Ok(()),
        }
    }

    /// An EVENT of `who` (the event itself, as sent).
    pub fn check_event(&self, who: &Who, event: &Value, bucket: &mut Bucket) -> Result<(), Refused> {
        let me = match (self.mode, who) {
            (Mode::Open, _) | (_, Who::Member(_)) => return Ok(()),
            (Mode::Team, Who::Anonymous) => return Err(Refused::AuthRequired(FOR_MEMBERS)),
            (Mode::Team, Who::Guest(_)) => return Err(Refused::Restricted(NOT_A_MEMBER)),
            (Mode::Channel, Who::Anonymous) => return Err(Refused::AuthRequired(SIGN_IN_TO_WRITE)),
            (Mode::Channel, Who::Guest(me)) => me,
        };
        let kind = event.get("kind").and_then(Value::as_u64);
        let Some(kind) = kind.filter(|k| self.guest_kinds.contains(k)) else {
            return Err(Refused::Restricted(AUTHORS_WRITE));
        };
        if policy::is_wrap_kind(kind) {
            // To the authors, every one of them: not from a guest to a guest.
            let p = policy::p_tags(event);
            if p.is_empty() || !p.iter().all(|k| self.admits(k)) {
                return Err(Refused::Restricted(WRAPS_TO_AUTHORS));
            }
        }
        if OWN_KINDS.contains(&kind) && !event.get("pubkey").and_then(Value::as_str).is_some_and(|k| k.eq_ignore_ascii_case(me)) {
            return Err(Refused::Restricted(OWN_LISTS));
        }
        if !bucket.take() {
            return Err(Refused::RateLimited);
        }
        Ok(())
    }

    /// One look at the members file: what the proxy does every minute and
    /// on SIGHUP.
    pub fn refresh(&self) -> Refreshed {
        self.members.refresh()
    }
}

/// The files of `[access]` read as the guard reads them (`vguard
/// check-config`): a members file or an invites file that is there must
/// read; the key of the invites must be there, at least 32 bytes, when the
/// mode is not open (one that is there is checked in any mode).
pub fn check_files(c: &AccessConfig) -> Result<(), String> {
    let mut problems = Vec::new();
    if let Some(path) = &c.members_file {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                if let Err(e) = veydan_denied::parse(&text) {
                    problems.push(format!("access.members_file: {}: {e}", path.display()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => problems.push(format!("access.members_file: {}: {e}", path.display())),
        }
    }
    if let Some(path) = &c.invites_file {
        if let Err(e) = crate::invites::read_file(path) {
            problems.push(format!("access.invites_file: {e}"));
        }
    }
    if let Some(path) = &c.secret_file {
        if c.mode() != Mode::Open || path.exists() {
            if let Err(e) = crate::invites::read_secret(path) {
                problems.push(format!("access.secret_file: {e}"));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn k(b: &str) -> String {
        // A key on the curve: the x of a key made from a fixed secret.
        let keys = nostr::prelude::Keys::parse(&b.repeat(32)).unwrap();
        keys.public_key().to_hex()
    }

    fn ev(kind: u64, pubkey: &str, p: &[&str]) -> Value {
        let tags: Vec<Value> = p.iter().map(|k| json!(["p", k])).collect();
        json!({"id": "ee".repeat(32), "pubkey": pubkey, "kind": kind, "tags": tags, "content": ""})
    }

    #[test]
    fn keys_are_read_as_npub_or_hex() {
        let hex = k("01");
        let npub = nostr::prelude::ToBech32::to_bech32(&PublicKey::from_hex(&hex).unwrap()).unwrap();
        assert_eq!(key_hex(&npub).as_deref(), Some(hex.as_str()));
        assert_eq!(key_hex(&hex.to_ascii_uppercase()).as_deref(), Some(hex.as_str()));
        assert_eq!(key_hex("npub1nope"), None);
        assert_eq!(key_hex(&"zz".repeat(32)), None);
        assert_eq!(key_hex("abc"), None);
        assert_eq!(Mode::parse("team"), Some(Mode::Team));
        assert_eq!(Mode::parse("Team"), None);
    }

    #[test]
    fn who_is_who() {
        let (m, a, g) = (k("01"), k("02"), k("03"));
        let access = Access::fixed(Mode::Team, &[&m], &[&a]);
        assert_eq!(access.who(None), Who::Anonymous);
        assert_eq!(access.who(Some(&m)), Who::Member(m.clone()));
        assert_eq!(access.who(Some(&a)), Who::Member(a.clone()), "an admin is admitted");
        assert!(access.is_admin(&a) && !access.is_admin(&m));
        assert_eq!(access.who(Some(&g)), Who::Guest(g.clone()));
    }

    #[test]
    fn open_lets_everything_through() {
        let access = Access::open();
        let mut b = access.bucket();
        for who in [Who::Anonymous, Who::Guest(k("03"))] {
            assert_eq!(access.check_question(&who), Ok(()));
            for _ in 0..100 {
                assert_eq!(access.check_event(&who, &ev(1, "x", &[]), &mut b), Ok(()));
            }
        }
    }

    #[test]
    fn a_team_admits_its_members_and_nobody_else() {
        let (m, a, g) = (k("01"), k("02"), k("03"));
        let access = Access::fixed(Mode::Team, &[&m], &[&a]);
        let mut b = access.bucket();
        assert_eq!(access.check_question(&Who::Anonymous), Err(Refusal::AuthRequired(FOR_MEMBERS.into())));
        assert_eq!(access.check_question(&access.who(Some(&g))), Err(Refusal::Restricted(NOT_A_MEMBER_ASK.into())));
        assert_eq!(access.check_question(&access.who(Some(&m))), Ok(()));
        assert_eq!(access.check_question(&access.who(Some(&a))), Ok(()));
        let e = ev(1, &g, &[]);
        assert_eq!(access.check_event(&Who::Anonymous, &e, &mut b), Err(Refused::AuthRequired(FOR_MEMBERS)));
        assert_eq!(access.check_event(&access.who(Some(&g)), &e, &mut b).unwrap_err().message(), "restricted: not a member of this server");
        // A member writes anything, by any key (a wrap is signed by its own).
        for _ in 0..100 {
            assert_eq!(access.check_event(&access.who(Some(&m)), &ev(1059, &g, &[&g]), &mut b), Ok(()));
        }
    }

    #[test]
    fn a_channel_reads_free_and_gates_writes() {
        let (m, a, g, s) = (k("01"), k("02"), k("03"), k("04"));
        let access = Access::fixed(Mode::Channel, &[&m], &[&a]);
        let guest = access.who(Some(&g));
        let mut b = access.bucket();
        assert_eq!(access.check_question(&Who::Anonymous), Ok(()));
        assert_eq!(access.check_question(&guest), Ok(()));
        assert_eq!(access.check_event(&Who::Anonymous, &ev(0, &g, &[]), &mut b), Err(Refused::AuthRequired(SIGN_IN_TO_WRITE)));
        // Outside the guest kinds.
        assert_eq!(access.check_event(&guest, &ev(1, &g, &[]), &mut b), Err(Refused::Restricted(AUTHORS_WRITE)));
        assert_eq!(access.check_event(&guest, &json!({"kind": "x"}), &mut b), Err(Refused::Restricted(AUTHORS_WRITE)));
        // Its own profile and lists only.
        assert_eq!(access.check_event(&guest, &ev(0, &g, &[]), &mut b), Ok(()));
        assert_eq!(access.check_event(&guest, &ev(10002, &g.to_ascii_uppercase(), &[]), &mut b), Ok(()));
        assert_eq!(access.check_event(&guest, &ev(10050, &s, &[]), &mut b), Err(Refused::Restricted(OWN_LISTS)));
        // Wraps to the authors, every one of them.
        assert_eq!(access.check_event(&guest, &ev(1059, &s, &[&a]), &mut b), Ok(()));
        assert_eq!(access.check_event(&guest, &ev(1059, &s, &[&m, &a]), &mut b), Ok(()));
        assert_eq!(access.check_event(&guest, &ev(1059, &s, &[&m, &s]), &mut b), Err(Refused::Restricted(WRAPS_TO_AUTHORS)));
        assert_eq!(access.check_event(&guest, &ev(1059, &s, &[]), &mut b), Err(Refused::Restricted(WRAPS_TO_AUTHORS)));
        // 21059 is not a guest kind by default.
        assert_eq!(access.check_event(&guest, &ev(21059, &s, &[&a]), &mut b), Err(Refused::Restricted(AUTHORS_WRITE)));
        // Joining a community.
        assert_eq!(access.check_event(&guest, &ev(1390, &g, &[]), &mut b), Ok(()));
        // A member writes anything.
        assert_eq!(access.check_event(&access.who(Some(&m)), &ev(1, &m, &[]), &mut b), Ok(()));
        // A read-only server.
        let mut ro = Access::fixed(Mode::Channel, &[&m], &[]);
        ro.guest_kinds.clear();
        assert_eq!(ro.check_event(&ro.who(Some(&g)), &ev(0, &g, &[]), &mut b), Err(Refused::Restricted(AUTHORS_WRITE)));
    }

    #[test]
    fn a_guest_is_slowed_down() {
        let g = k("03");
        let access = Access::fixed(Mode::Channel, &[], &[]);
        let guest = access.who(Some(&g));
        let mut b = access.bucket();
        for i in 0..30 {
            assert_eq!(access.check_event(&guest, &ev(0, &g, &[]), &mut b), Ok(()), "event {i}");
        }
        assert_eq!(access.check_event(&guest, &ev(0, &g, &[]), &mut b), Err(Refused::RateLimited));
        assert_eq!(Refused::RateLimited.message(), "rate-limited: slow down");
        // A refused kind costs nothing and is refused for what it is.
        assert_eq!(access.check_event(&guest, &ev(1, &g, &[]), &mut b), Err(Refused::Restricted(AUTHORS_WRITE)));

        // The refill: one every two seconds at 30 a minute.
        let t = Instant::now();
        let mut b = Bucket::new(30);
        for _ in 0..30 {
            assert!(b.take_at(t));
        }
        assert!(!b.take_at(t));
        assert!(!b.take_at(t + Duration::from_secs(1)));
        assert!(b.take_at(t + Duration::from_secs(2)));
        assert!(!b.take_at(t + Duration::from_secs(2)));
        // Never more than a minute's worth.
        let mut later = 0;
        while b.take_at(t + Duration::from_secs(3600)) {
            later += 1;
        }
        assert_eq!(later, 30);
    }
}
