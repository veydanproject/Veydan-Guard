//! One client connection as vguard sees it, without the sockets: what the
//! client sent, what goes on to strfry as it is, what vguard answers itself.
//!
//! The state is the challenges given, the key signed in with, and the open
//! subscriptions. A peer (router and sync of the other relays, VPush) has
//! no session: its frames pass untouched.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::access::{Access, Bucket, Refused, Who};
use crate::auth;
use crate::config::Config;
use crate::message::{self, parse_array, peek_verb};
use crate::metrics::{add, Metrics};
use crate::policy::{self, Refusal};
use veydan_denied::{DeniedGroups, DeniedKeys};

/// The longest subscription id taken (NIP-01 says 64 characters).
pub const MAX_SUB_ID: usize = 256;
/// Challenges kept per connection: strfry gives one, vguard at most one.
const MAX_CHALLENGES: usize = 4;
/// OKs of strfry vguard waits to drop: one per AUTH passed on.
const MAX_SWALLOW: usize = 8;

/// Who gave a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// strfry: an AUTH over it goes on to strfry too.
    Relay,
    /// vguard, when strfry gave none: the AUTH stays here.
    Guard,
}

/// What one frame of the client comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// To strfry, as it is.
    Upstream(String),
    /// To the client, vguard's own answer.
    Client(String),
}

/// What [`Session::on_client`] needs before it can answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    /// The question needs a signed-in key and no challenge has been given
    /// yet: wait for strfry's a moment, give one of vguard's own
    /// ([`Session::own_challenge`]) if none came, and ask again.
    Challenge,
    /// The question needs a signed-in key, a challenge is out and the
    /// client has not answered it yet: hold the question until its AUTH
    /// has been answered, or `auth_wait_ms` at most, then ask again with
    /// `waited`. Once a connection: a client that let the wait run out
    /// does not sign in, and its later questions are answered at once.
    Auth,
}

/// The verb of a message of the client, read as [`Session::on_client`]
/// reads it; None when the frame is no JSON array with a verb first.
fn verb_of(text: &str) -> Option<String> {
    match peek_verb(text) {
        Some(v) => Some(v.to_string()),
        None => parse_array(text)
            .ok()
            .map(|items| items[0].as_str().unwrap_or_default().to_string()),
    }
}

/// Whether a frame of the client is an AUTH: what a held question waits for.
pub fn is_auth(text: &str) -> bool {
    verb_of(text).as_deref() == Some("AUTH")
}

pub struct Session {
    config: Arc<Config>,
    metrics: Arc<Metrics>,
    /// The keys denied on every server (spec/vguard.md, "Denied keys"):
    /// shared by every connection, read again by the proxy.
    denied: Arc<DeniedKeys>,
    /// The groups closed on our relays (spec/vguard.md, "Denied groups"):
    /// shared and read again as the keys are.
    groups: Arc<DeniedGroups>,
    /// The access mode of the server (spec/vguard.md, "Access modes"),
    /// shared; `open` until given.
    access: Arc<Access>,
    /// What a guest of a channel may still write on this connection.
    bucket: Bucket,
    challenges: VecDeque<(String, Origin)>,
    signed_in: Option<String>,
    /// AUTH ids passed on to strfry, whose OK vguard has answered already.
    swallow: VecDeque<String>,
    subs: HashSet<String>,
    negs: HashSet<String>,
    /// A question of this connection has waited for the AUTH already
    /// ([`Pending::Auth`]).
    auth_waited: bool,
}

impl Session {
    pub fn new(config: Arc<Config>, metrics: Arc<Metrics>, denied: Arc<DeniedKeys>) -> Self {
        Self {
            config,
            metrics,
            denied,
            groups: Arc::new(DeniedGroups::none()),
            access: Arc::new(Access::open()),
            bucket: Bucket::new(1),
            challenges: VecDeque::new(),
            signed_in: None,
            swallow: VecDeque::new(),
            subs: HashSet::new(),
            negs: HashSet::new(),
            auth_waited: false,
        }
    }

    /// The closed groups this session refuses; none until given.
    pub fn with_denied_groups(mut self, groups: Arc<DeniedGroups>) -> Self {
        self.groups = groups;
        self
    }

    /// The access mode this session keeps; `open` until given.
    pub fn with_access(mut self, access: Arc<Access>) -> Self {
        self.bucket = access.bucket();
        self.access = access;
        self
    }

    /// Who this connection is for the access mode.
    fn who(&self) -> Who {
        self.access.who(self.signed_in.as_deref())
    }

    /// Whether an event must be looked into: somebody is denied or some
    /// group is closed. Both lists are empty nearly always, and then no
    /// event is parsed at all.
    fn denying(&self) -> bool {
        !self.denied.is_empty() || !self.groups.is_empty()
    }

    pub fn signed_in(&self) -> Option<&str> {
        self.signed_in.as_deref()
    }

    pub fn has_challenge(&self) -> bool {
        !self.challenges.is_empty()
    }

    /// The wait for the AUTH ([`Pending::Auth`]) is over: the AUTH was
    /// answered, the time ran out, or too much was held.
    pub fn auth_wait_over(&mut self) {
        self.auth_waited = true;
    }

    /// A challenge of vguard's own, when none is out and nobody signed in:
    /// strfry gave none in time.
    pub fn own_challenge(&mut self) -> Option<Out> {
        if self.has_challenge() || self.signed_in.is_some() {
            return None;
        }
        let c = auth::new_challenge();
        let out = Out::Client(message::auth_challenge(&c));
        self.remember_challenge(c, Origin::Guard);
        add(&self.metrics.challenges_own);
        Some(out)
    }

    fn remember_challenge(&mut self, c: String, origin: Origin) {
        if self.challenges.len() >= MAX_CHALLENGES {
            self.challenges.pop_front();
        }
        self.challenges.push_back((c, origin));
    }

    fn origin_of(&self, c: &str) -> Option<Origin> {
        self.challenges
            .iter()
            .find(|(x, _)| x == c)
            .map(|(_, o)| *o)
    }

    /// A frame of strfry: Some to pass on to the client, None to drop.
    /// strfry's challenge is noted; its OK to an AUTH vguard has answered
    /// is dropped; a subscription strfry closed is no longer open; an event
    /// of a denied key or of a closed group does not reach the client,
    /// whatever asked for it.
    pub fn on_upstream(&mut self, text: &str) -> Option<()> {
        let verb = match peek_verb(text) {
            Some(v) => v,
            None => return Some(()),
        };
        match verb {
            // Read only while somebody is denied: the stream of events is
            // most of what strfry sends, and the list is empty nearly always.
            "EVENT" if self.denying() => {
                if let Ok(items) = parse_array(text) {
                    if items.get(2).and_then(|e| e.get("pubkey")).and_then(Value::as_str).is_some_and(|k| self.denied.contains(k)) {
                        add(&self.metrics.denied_dropped);
                        return None;
                    }
                    if items.get(2).is_some_and(|e| policy::in_denied_group(e, &self.groups)) {
                        add(&self.metrics.groups_dropped);
                        return None;
                    }
                }
            }
            "AUTH" => {
                if let Ok(items) = parse_array(text) {
                    if let Some(c) = items.get(1).and_then(Value::as_str) {
                        self.remember_challenge(c.to_string(), Origin::Relay);
                    }
                }
            }
            "OK" if !self.swallow.is_empty() => {
                if let Ok(items) = parse_array(text) {
                    if let Some(id) = items.get(1).and_then(Value::as_str) {
                        if let Some(i) = self.swallow.iter().position(|x| x == id) {
                            self.swallow.remove(i);
                            return None;
                        }
                    }
                }
            }
            "CLOSED" => {
                if let Ok(items) = parse_array(text) {
                    if let Some(s) = items.get(1).and_then(Value::as_str) {
                        self.subs.remove(s);
                    }
                }
            }
            "NEG-ERR" => {
                if let Ok(items) = parse_array(text) {
                    if let Some(s) = items.get(1).and_then(Value::as_str) {
                        self.negs.remove(s);
                    }
                }
            }
            _ => {}
        }
        Some(())
    }

    /// A text frame of the client. `waited`: no more waiting, answer now
    /// (see [`Pending`]).
    pub fn on_client(&mut self, text: &str, now: u64, waited: bool) -> Result<Vec<Out>, Pending> {
        let Some(verb) = verb_of(text) else {
            return Ok(self.unreadable("a message is a JSON array with its verb first"));
        };
        match verb.as_str() {
            "REQ" | "COUNT" => self.question(&verb, text, waited),
            "NEG-OPEN" => self.neg_open(text, waited),
            "CLOSE" => Ok(self.close(text, false)),
            "NEG-CLOSE" => Ok(self.close(text, true)),
            "AUTH" => Ok(self.auth(text, now)),
            // Read only when it must be: in `open` with nobody denied an
            // EVENT goes on unread, as before 0.7.0.
            "EVENT" if !self.access.is_open() || self.denying() => self.event(text, waited),
            // EVENT, NEG-MSG and what strfry answers itself.
            _ => Ok(vec![Out::Upstream(text.to_string())]),
        }
    }

    /// An EVENT while somebody is denied: refused here when its `pubkey` is
    /// a denied key, so that no profile, follow list, media authorization
    /// or event of a group signed by it is stored. A gift wrap is signed by
    /// a key made for it and cannot be told apart. An EVENT vguard cannot
    /// read for certain does not pass while there is a key to look for.
    ///
    /// On a server that is not open the access mode decides next
    /// (spec/vguard.md, "Access modes"): an EVENT before the AUTH waits for
    /// it as a question does ([`Pending`]), then is refused `auth-required`
    /// if the connection still has not signed in; a guest writes what its
    /// mode lets it.
    fn event(&mut self, text: &str, waited: bool) -> Result<Vec<Out>, Pending> {
        let items = match parse_array(text) {
            Ok(items) => items,
            Err(e) => return Ok(self.unreadable(&e)),
        };
        let event = items.get(1);
        let id = event.and_then(|e| e.get("id")).and_then(Value::as_str).unwrap_or_default().to_string();
        if event.and_then(|e| e.get("pubkey")).and_then(Value::as_str).is_some_and(|k| self.denied.contains(k)) {
            add(&self.metrics.denied_events);
            return Ok(vec![Out::Client(message::ok(&id, false, "blocked: key denied"))]);
        }
        // An event of a closed group, by anybody: the group takes nothing
        // more on this relay.
        if event.is_some_and(|e| policy::in_denied_group(e, &self.groups)) {
            add(&self.metrics.groups_events);
            return Ok(vec![Out::Client(message::ok(&id, false, "blocked: group denied"))]);
        }
        if self.access.is_open() {
            return Ok(vec![Out::Upstream(text.to_string())]);
        }
        let mut out = Vec::new();
        let mut who = self.who();
        if who == Who::Anonymous {
            self.challenge_first(waited, &mut out)?;
            who = self.who();
        }
        let null = Value::Null;
        match self.access.check_event(&who, event.unwrap_or(&null), &mut self.bucket) {
            Ok(()) => {
                if matches!(who, Who::Guest(_)) {
                    add(&self.metrics.guest_events);
                }
                out.push(Out::Upstream(text.to_string()));
            }
            Err(r) => {
                add(match r {
                    Refused::AuthRequired(_) => &self.metrics.access_auth_required,
                    Refused::Restricted(_) => &self.metrics.access_restricted,
                    Refused::RateLimited => &self.metrics.guest_rate_limited,
                });
                out.push(Out::Client(message::ok(&id, false, &r.message())));
            }
        }
        Ok(out)
    }

    fn unreadable(&self, why: &str) -> Vec<Out> {
        add(&self.metrics.unreadable);
        vec![Out::Client(message::notice(&format!("invalid: {why}")))]
    }

    /// The subscription id of a message, or why not.
    fn sub_id(items: &[Value]) -> Result<String, &'static str> {
        match items.get(1).and_then(Value::as_str) {
            Some(s) if !s.is_empty() && s.len() <= MAX_SUB_ID => Ok(s.to_string()),
            _ => Err("a subscription id is a string of 1 to 256 bytes"),
        }
    }

    /// The access mode first, then the rules of the filters: `by_access`
    /// tells which refused.
    fn check_question(&self, check: impl FnOnce() -> Result<(), Refusal>) -> (Result<(), Refusal>, bool) {
        match self.access.check_question(&self.who()) {
            Err(r) => (Err(r), true),
            Ok(()) => (check(), false),
        }
    }

    fn count_refusal(&self, r: &Refusal, by_access: bool) {
        if by_access {
            add(match r {
                Refusal::AuthRequired(_) => &self.metrics.access_auth_required,
                _ => &self.metrics.access_restricted,
            });
            return;
        }
        add(match r {
            Refusal::AuthRequired(_) => &self.metrics.refused_auth_required,
            Refusal::Restricted(_) => &self.metrics.refused_restricted,
            Refusal::Invalid(_) => &self.metrics.refused_invalid,
        });
    }

    /// An AuthRequired: wait for a challenge, or for the AUTH over the one
    /// out; when there is no more waiting, refuse, with a challenge of our
    /// own if none is out, so that the client can sign in and ask again.
    fn challenge_first(&mut self, waited: bool, out: &mut Vec<Out>) -> Result<(), Pending> {
        if self.signed_in.is_some() {
            return Ok(());
        }
        if !waited {
            if !self.has_challenge() {
                return Err(Pending::Challenge);
            }
            if !self.auth_waited && self.config.limits.auth_wait_ms > 0 {
                return Err(Pending::Auth);
            }
            return Ok(());
        }
        out.extend(self.own_challenge());
        Ok(())
    }

    fn question(&mut self, verb: &str, text: &str, waited: bool) -> Result<Vec<Out>, Pending> {
        let items = match parse_array(text) {
            Ok(items) => items,
            Err(e) => return Ok(self.unreadable(&e)),
        };
        let sub = match Self::sub_id(&items) {
            Ok(s) => s,
            Err(e) => return Ok(self.unreadable(e)),
        };
        let req = verb == "REQ";
        let (checked, by_access) = self.check_question(|| {
            policy::check_filters(&items[2..], self.signed_in.as_deref(), self.config.limits.max_filters)
        });
        let mut out = Vec::new();
        // The closed groups out of the question; what is left goes on.
        let open = if checked.is_ok() { policy::without_denied_groups(&items[2..], &self.groups) } else { None };
        let filters = open.as_deref().unwrap_or(&items[2..]);
        match checked {
            // The events of denied keys or closed groups alone: nothing to
            // ask strfry, the answer is empty (and a REQ that replaced an
            // open one of the same id ends that one at strfry, as strfry
            // would have).
            Ok(()) if filters.is_empty() || policy::only_denied_authors(filters, &self.denied) => {
                add(if filters.is_empty() { &self.metrics.groups_answered } else { &self.metrics.denied_answered });
                if req {
                    if self.subs.remove(&sub) {
                        out.push(Out::Upstream(json!(["CLOSE", sub]).to_string()));
                    }
                    out.push(Out::Client(json!(["EOSE", sub]).to_string()));
                } else {
                    out.push(Out::Client(json!(["COUNT", sub, {"count": 0}]).to_string()));
                }
            }
            Ok(()) => {
                if req && !self.subs.contains(&sub) {
                    if self.subs.len() >= self.config.limits.max_subs {
                        add(&self.metrics.refused_too_many);
                        return Ok(vec![Out::Client(message::closed(
                            &sub,
                            "error: too many subscriptions on this connection",
                        ))]);
                    }
                    self.subs.insert(sub.clone());
                }
                add(&self.metrics.questions_passed);
                match &open {
                    Some(filters) => {
                        add(&self.metrics.groups_filtered);
                        let mut asked = vec![json!(verb), json!(sub)];
                        asked.extend(filters.iter().cloned());
                        out.push(Out::Upstream(Value::Array(asked).to_string()));
                    }
                    None => out.push(Out::Upstream(text.to_string())),
                }
            }
            Err(r) => {
                if matches!(r, Refusal::AuthRequired(_)) {
                    self.challenge_first(waited, &mut out)?;
                }
                self.count_refusal(&r, by_access);
                // The client asked to replace an open subscription: strfry
                // would have; the old one ends here too.
                if req && self.subs.remove(&sub) {
                    out.push(Out::Upstream(json!(["CLOSE", sub]).to_string()));
                }
                out.push(Out::Client(message::closed(&sub, &r.message())));
            }
        }
        Ok(out)
    }

    fn neg_open(&mut self, text: &str, waited: bool) -> Result<Vec<Out>, Pending> {
        let items = match parse_array(text) {
            Ok(items) => items,
            Err(e) => return Ok(self.unreadable(&e)),
        };
        let sub = match Self::sub_id(&items) {
            Ok(s) => s,
            Err(e) => return Ok(self.unreadable(e)),
        };
        let (checked, by_access) = if items.len() != 4 {
            (Err(Refusal::Invalid("NEG-OPEN is [\"NEG-OPEN\", <id>, <filter>, <message>]".into())), false)
        } else {
            self.check_question(|| policy::check_filter(&items[2], self.signed_in.as_deref()))
        };
        let mut out = Vec::new();
        // A sync of the closed groups alone is refused; of others besides,
        // it goes on without them (the client then asks by id what it lacks,
        // and an event of a closed group is dropped on its way back).
        let open = if checked.is_ok() { policy::without_denied_groups(&items[2..3], &self.groups) } else { None };
        let checked = match &open {
            Some(f) if f.is_empty() => {
                add(&self.metrics.groups_answered);
                Err(Refusal::Restricted("group denied".into()))
            }
            _ => checked,
        };
        match checked {
            Ok(()) => {
                if !self.negs.contains(&sub) {
                    if self.negs.len() >= self.config.limits.max_subs {
                        add(&self.metrics.refused_too_many);
                        return Ok(vec![Out::Client(message::neg_err(
                            &sub,
                            "error: too many syncs on this connection",
                        ))]);
                    }
                    self.negs.insert(sub.clone());
                }
                add(&self.metrics.questions_passed);
                match open {
                    Some(f) => {
                        add(&self.metrics.groups_filtered);
                        out.push(Out::Upstream(json!(["NEG-OPEN", sub, f[0], items[3]]).to_string()));
                    }
                    None => out.push(Out::Upstream(text.to_string())),
                }
            }
            Err(r) => {
                if matches!(r, Refusal::AuthRequired(_)) {
                    self.challenge_first(waited, &mut out)?;
                }
                self.count_refusal(&r, by_access);
                if self.negs.remove(&sub) {
                    out.push(Out::Upstream(json!(["NEG-CLOSE", sub]).to_string()));
                }
                out.push(Out::Client(message::neg_err(&sub, &r.message())));
            }
        }
        Ok(out)
    }

    fn close(&mut self, text: &str, neg: bool) -> Vec<Out> {
        if let Ok(items) = parse_array(text) {
            if let Some(s) = items.get(1).and_then(Value::as_str) {
                if neg {
                    self.negs.remove(s);
                } else {
                    self.subs.remove(s);
                }
            }
        }
        vec![Out::Upstream(text.to_string())]
    }

    fn auth(&mut self, text: &str, now: u64) -> Vec<Out> {
        let items = match parse_array(text) {
            Ok(items) => items,
            Err(e) => return self.unreadable(&e),
        };
        let Some(event) = items.get(1) else {
            return self.unreadable("AUTH carries an event");
        };
        let id = auth::event_id_of(event);
        let refuse = |s: &Self, why: String| {
            add(&s.metrics.auth_failed);
            vec![Out::Client(message::ok(
                &id,
                false,
                &format!("invalid: {why}"),
            ))]
        };
        let signed = match auth::verify(&self.config, event, |c| self.origin_of(c).is_some(), now) {
            Ok(s) => s,
            Err(why) => return refuse(self, why),
        };
        // A denied key does not sign in: so it reads no gift wrap of its
        // own, the one thing here that needs the key.
        if self.denied.contains(&signed.pubkey) {
            add(&self.metrics.denied_auth);
            return vec![Out::Client(message::ok(&signed.event_id, false, "restricted: key denied"))];
        }
        match &self.signed_in {
            Some(k) if *k != signed.pubkey => {
                add(&self.metrics.auth_failed);
                return vec![Out::Client(message::ok(
                    &id,
                    false,
                    "restricted: this connection is signed in with another key",
                ))];
            }
            _ => {}
        }
        self.signed_in = Some(signed.pubkey);
        add(&self.metrics.auth_ok);
        // A challenge signs in once: the same AUTH sent again on this
        // connection, or another event over the same challenge, is refused,
        // so that the wide window of auth_skew_secs opens no replay.
        let origin = self.origin_of(&signed.challenge);
        self.challenges.retain(|(c, _)| *c != signed.challenge);
        // vguard answers the AUTH: strfry's answer may differ for its own
        // reasons (it knows one name of the relay), and the client must
        // know it is signed in before it asks again.
        let mut out = vec![Out::Client(message::ok(&signed.event_id, true, ""))];
        if origin == Some(Origin::Relay) {
            if self.swallow.len() >= MAX_SWALLOW {
                self.swallow.pop_front();
            }
            self.swallow.push_back(signed.event_id);
            out.push(Out::Upstream(text.to_string()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{auth_event, config};
    use nostr::prelude::Keys;

    const NOW: u64 = 1_800_000_000;

    fn session() -> Session {
        Session::new(Arc::new(config()), Arc::new(Metrics::default()), Arc::new(DeniedKeys::none()))
    }

    fn client(s: &mut Session, v: Value) -> Vec<Out> {
        s.on_client(&v.to_string(), NOW, true).expect("no wait")
    }

    fn sign_in(s: &mut Session, keys: &Keys) -> Vec<Out> {
        s.on_upstream(&json!(["AUTH", "c1"]).to_string()).unwrap();
        client(
            s,
            json!([
                "AUTH",
                auth_event(keys, "c1", "wss://relay.example.org/?key=k", NOW)
            ]),
        )
    }

    fn passed(out: &[Out]) -> bool {
        matches!(out, [Out::Upstream(_)])
    }

    fn refused_with(out: &[Out], verb: &str, prefix: &str) -> bool {
        out.iter().any(|o| match o {
            Out::Client(t) => {
                let v: Value = serde_json::from_str(t).unwrap();
                v[0] == verb && v[2].as_str().unwrap_or_default().starts_with(prefix)
            }
            _ => false,
        }) && !out.iter().any(|o| matches!(o, Out::Upstream(t) if t.contains("\"REQ\"") || t.contains("\"NEG-OPEN\"") || t.contains("\"COUNT\"")))
    }

    #[test]
    fn auth_signs_in_and_goes_on_to_strfry_whose_ok_is_dropped() {
        let keys = Keys::generate();
        let mut s = session();
        let out = sign_in(&mut s, &keys);
        assert_eq!(s.signed_in(), Some(keys.public_key().to_hex().as_str()));
        let Out::Client(ok) = &out[0] else {
            panic!("{out:?}")
        };
        let ok: Value = serde_json::from_str(ok).unwrap();
        assert_eq!(ok[0], "OK");
        assert_eq!(ok[2], true);
        assert!(matches!(&out[1], Out::Upstream(t) if t.contains("\"AUTH\"")));
        // strfry's own OK to the same event: the client has one already.
        let id = ok[1].as_str().unwrap();
        assert!(s
            .on_upstream(&json!(["OK", id, false, "auth failed: relay tag"]).to_string())
            .is_none());
        // Another OK passes.
        assert!(s
            .on_upstream(&json!(["OK", "ee".repeat(32), true, ""]).to_string())
            .is_some());
    }

    #[test]
    fn a_bad_auth_is_answered_here_and_signs_nobody_in() {
        let keys = Keys::generate();
        let mut s = session();
        s.on_upstream(&json!(["AUTH", "c1"]).to_string());
        let out = client(
            &mut s,
            json!([
                "AUTH",
                auth_event(&keys, "c2", "wss://relay.example.org", NOW)
            ]),
        );
        assert!(matches!(&out[..], [Out::Client(t)] if t.contains("false")));
        let out = client(
            &mut s,
            json!([
                "AUTH",
                auth_event(&keys, "c1", "wss://elsewhere.example", NOW)
            ]),
        );
        assert!(matches!(&out[..], [Out::Client(t)] if t.contains("false")));
        assert_eq!(s.signed_in(), None);
        // A second key after the first: refused, the first stays.
        sign_in(&mut s, &keys);
        let other = Keys::generate();
        let out = client(
            &mut s,
            json!([
                "AUTH",
                auth_event(&other, "c1", "wss://relay.example.org", NOW)
            ]),
        );
        assert!(matches!(&out[..], [Out::Client(t)] if t.contains("false")));
        assert_eq!(s.signed_in(), Some(keys.public_key().to_hex().as_str()));
    }

    #[test]
    fn req_count_and_neg_open_keep_the_rules() {
        let keys = Keys::generate();
        let me = keys.public_key().to_hex();
        let other = Keys::generate().public_key().to_hex();
        let mut s = session();
        s.on_upstream(&json!(["AUTH", "c1"]).to_string());

        // Before signing in: auth-required, nothing to strfry.
        let out = client(&mut s, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}]));
        assert!(refused_with(&out, "CLOSED", "auth-required:"), "{out:?}");
        sign_in(&mut s, &keys);

        for verb in ["REQ", "COUNT"] {
            assert!(passed(&client(
                &mut s,
                json!([verb, "a", {"kinds": [1059], "#p": [me]}])
            )));
            assert!(refused_with(
                &client(&mut s, json!([verb, "b", {"kinds": [1059]}])),
                "CLOSED",
                "restricted:"
            ));
            assert!(refused_with(
                &client(&mut s, json!([verb, "c", {"kinds": [1059], "#p": [other]}])),
                "CLOSED",
                "restricted:"
            ));
            assert!(refused_with(
                &client(&mut s, json!([verb, "d", {"kinds": [9]}])),
                "CLOSED",
                "restricted:"
            ));
            assert!(passed(&client(
                &mut s,
                json!([verb, "e", {"kinds": [9], "#h": ["g"]}])
            )));
            assert!(refused_with(
                &client(&mut s, json!([verb, "f", {}])),
                "CLOSED",
                "restricted:"
            ));
            assert!(refused_with(
                &client(&mut s, json!([verb, "g"])),
                "CLOSED",
                "invalid:"
            ));
            assert!(passed(&client(
                &mut s,
                json!([verb, "h", {"kinds": [0], "authors": [other]}])
            )));
            assert!(passed(&client(&mut s, json!([verb, "i", {"kinds": [3]}]))));
            // One bad filter spoils the question.
            assert!(refused_with(
                &client(
                    &mut s,
                    json!([verb, "j", {"kinds": [0]}, {"kinds": [1059], "#p": [other]}])
                ),
                "CLOSED",
                "restricted:"
            ));
        }

        let neg = |f: Value| json!(["NEG-OPEN", "n", f, "6100"]);
        assert!(passed(&client(
            &mut s,
            neg(json!({"kinds": [1059], "#p": [me]}))
        )));
        assert!(refused_with(
            &client(&mut s, neg(json!({"kinds": [1059]}))),
            "NEG-ERR",
            "restricted:"
        ));
        assert!(refused_with(
            &client(&mut s, neg(json!({"kinds": [1059], "#p": [other]}))),
            "NEG-ERR",
            "restricted:"
        ));
        assert!(refused_with(
            &client(&mut s, neg(json!({}))),
            "NEG-ERR",
            "restricted:"
        ));
        assert!(refused_with(
            &client(&mut s, neg(json!({"kinds": [9]}))),
            "NEG-ERR",
            "restricted:"
        ));
        assert!(passed(&client(
            &mut s,
            neg(json!({"kinds": [9], "#h": ["g"]}))
        )));
        assert!(refused_with(
            &client(&mut s, json!(["NEG-OPEN", "n", {"kinds": [0]}])),
            "NEG-ERR",
            "invalid:"
        ));

        // A key twice in a filter: parsers disagree on it, so it goes nowhere.
        let out = s
            .on_client(
                &format!(r##"["REQ","x",{{"kinds":[1059],"#p":["{me}"],"#p":["{other}"]}}]"##),
                NOW,
                true,
            )
            .unwrap();
        assert!(
            matches!(&out[..], [Out::Client(t)] if t.contains("NOTICE")),
            "{out:?}"
        );
        // So does an escaped verb that is a REQ after all.
        let out = s
            .on_client(
                &format!(r#"["RE{}u0051","y",{{"kinds":[1059]}}]"#, char::from(92)),
                NOW,
                true,
            )
            .unwrap();
        assert!(refused_with(&out, "CLOSED", "restricted:"), "{out:?}");
        // What is not JSON at all.
        let out = s.on_client("REQ", NOW, true).unwrap();
        assert!(matches!(&out[..], [Out::Client(t)] if t.contains("NOTICE")));
        // EVENT and the rest pass as they are.
        let ev = json!(["EVENT", {"id": "x"}]).to_string();
        assert_eq!(
            s.on_client(&ev, NOW, true).unwrap(),
            vec![Out::Upstream(ev)]
        );
    }

    #[test]
    fn a_refused_replacement_closes_the_old_subscription_at_strfry() {
        let keys = Keys::generate();
        let me = keys.public_key().to_hex();
        let mut s = session();
        sign_in(&mut s, &keys);
        assert!(passed(&client(
            &mut s,
            json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])
        )));
        let out = client(&mut s, json!(["REQ", "dm", {"kinds": [1059]}]));
        assert!(
            out.contains(&Out::Upstream(json!(["CLOSE", "dm"]).to_string())),
            "{out:?}"
        );
        assert!(matches!(out.last(), Some(Out::Client(t)) if t.contains("CLOSED")));
        let out = client(
            &mut s,
            json!(["NEG-OPEN", "n", {"kinds": [1059], "#p": [me]}, "61"]),
        );
        assert!(passed(&out));
        let out = client(&mut s, json!(["NEG-OPEN", "n", {"kinds": [1059]}, "61"]));
        assert!(
            out.contains(&Out::Upstream(json!(["NEG-CLOSE", "n"]).to_string())),
            "{out:?}"
        );
    }

    #[test]
    fn subscriptions_are_counted_and_freed() {
        let mut cfg = config();
        cfg.limits.max_subs = 2;
        let mut s = Session::new(Arc::new(cfg), Arc::new(Metrics::default()), Arc::new(DeniedKeys::none()));
        let q = |id: &str| json!(["REQ", id, {"kinds": [0]}]);
        assert!(passed(&client(&mut s, q("a"))));
        assert!(passed(&client(&mut s, q("b"))));
        assert!(
            passed(&client(&mut s, q("a"))),
            "a replacement is no new subscription"
        );
        assert!(refused_with(&client(&mut s, q("c")), "CLOSED", "error:"));
        assert!(passed(&client(&mut s, json!(["CLOSE", "a"]))));
        assert!(passed(&client(&mut s, q("c"))));
        // strfry closed one itself.
        s.on_upstream(&json!(["CLOSED", "b", "error: x"]).to_string());
        assert!(passed(&client(&mut s, q("d"))));
        assert!(refused_with(&client(&mut s, q("e")), "CLOSED", "error:"));
        assert!(
            matches!(&client(&mut s, json!(["REQ", "", {"kinds": [0]}]))[..], [Out::Client(t)] if t.contains("NOTICE"))
        );
    }

    #[test]
    fn without_a_challenge_of_strfry_vguard_waits_then_gives_its_own() {
        let keys = Keys::generate();
        let me = keys.public_key().to_hex();
        let mut s = session();
        let q = json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}]).to_string();
        assert_eq!(s.on_client(&q, NOW, false), Err(Pending::Challenge));
        let out = s.on_client(&q, NOW, true).unwrap();
        let Out::Client(c) = &out[0] else {
            panic!("{out:?}")
        };
        let c: Value = serde_json::from_str(c).unwrap();
        assert_eq!(c[0], "AUTH");
        assert!(refused_with(&out, "CLOSED", "auth-required:"));
        // An AUTH over vguard's challenge stays here.
        let ev = auth_event(
            &keys,
            c[1].as_str().unwrap(),
            "wss://relay.example.org",
            NOW,
        );
        let out = client(&mut s, json!(["AUTH", ev]));
        assert!(
            matches!(&out[..], [Out::Client(t)] if t.contains("true")),
            "{out:?}"
        );
        assert!(passed(&s.on_client(&q, NOW, false).unwrap()));
        // The same AUTH again: its challenge has signed in once already.
        let out = client(&mut s, json!(["AUTH", ev]));
        assert!(
            matches!(&out[..], [Out::Client(t)] if t.contains("false") && t.contains("not the challenge")),
            "{out:?}"
        );
        assert!(s.signed_in().is_some(), "the connection stays signed in");
        // A public question never waits.
        let mut s = session();
        assert!(passed(
            &s.on_client(&json!(["REQ", "p", {"kinds": [0]}]).to_string(), NOW, false)
                .unwrap()
        ));
    }
    #[test]
    fn with_a_challenge_out_a_question_waits_for_the_auth_once() {
        let keys = Keys::generate();
        let me = keys.public_key().to_hex();
        let q = json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}]).to_string();
        let neg = json!(["NEG-OPEN", "n", {"kinds": [1059], "#p": [me]}, "61"]).to_string();
        let mut s = session();
        s.on_upstream(&json!(["AUTH", "c1"]).to_string()).unwrap();
        assert_eq!(s.on_client(&q, NOW, false), Err(Pending::Auth));
        assert_eq!(s.on_client(&neg, NOW, false), Err(Pending::Auth));
        // What needs no key does not wait.
        assert!(passed(&s.on_client(&json!(["REQ", "p", {"kinds": [0]}]).to_string(), NOW, false).unwrap()));
        // The AUTH came: the held question passes.
        sign_in(&mut s, &keys);
        assert!(passed(&s.on_client(&q, NOW, true).unwrap()));
        assert!(passed(&s.on_client(&neg, NOW, true).unwrap()));

        // The wait ran out without an AUTH: refused, with no challenge of
        // vguard's own (strfry's is out), and no second wait.
        let mut s = session();
        s.on_upstream(&json!(["AUTH", "c1"]).to_string()).unwrap();
        assert_eq!(s.on_client(&q, NOW, false), Err(Pending::Auth));
        s.auth_wait_over();
        let out = s.on_client(&q, NOW, true).unwrap();
        assert!(matches!(&out[..], [Out::Client(t)] if t.contains("auth-required:")), "{out:?}");
        let out = s.on_client(&q, NOW, false).unwrap();
        assert!(refused_with(&out, "CLOSED", "auth-required:"), "{out:?}");

        // auth_wait_ms = 0: never a wait.
        let mut cfg = config();
        cfg.limits.auth_wait_ms = 0;
        let mut s = Session::new(Arc::new(cfg), Arc::new(Metrics::default()), Arc::new(DeniedKeys::none()));
        s.on_upstream(&json!(["AUTH", "c1"]).to_string()).unwrap();
        assert!(refused_with(&s.on_client(&q, NOW, false).unwrap(), "CLOSED", "auth-required:"));
    }

    #[test]
    fn a_denied_key_signs_in_nowhere_and_its_events_go_nowhere() {
        let bad = Keys::generate();
        let good = Keys::generate();
        let (bad_hex, good_hex) = (bad.public_key().to_hex(), good.public_key().to_hex());
        let metrics = Arc::new(Metrics::default());
        let mut s = Session::new(Arc::new(config()), metrics.clone(), Arc::new(DeniedKeys::of(&[&bad_hex])));
        // AUTH: refused with its word, nobody signed in, nothing to strfry.
        s.on_upstream(&json!(["AUTH", "c1"]).to_string()).unwrap();
        let ev = auth_event(&bad, "c1", "wss://relay.example.org", NOW);
        let out = client(&mut s, json!(["AUTH", ev]));
        assert_eq!(out, vec![Out::Client(message::ok(ev["id"].as_str().unwrap(), false, "restricted: key denied"))]);
        assert_eq!(s.signed_in(), None);
        // So it reads no wrap of its own.
        let out = client(&mut s, json!(["REQ", "dm", {"kinds": [1059], "#p": [bad_hex]}]));
        assert!(refused_with(&out, "CLOSED", "auth-required:"), "{out:?}");
        // An EVENT it signed: refused here, whatever its kind.
        for kind in [0, 3, 9, 24242] {
            let event = json!({"id": "ee".repeat(32), "pubkey": bad_hex, "kind": kind, "created_at": NOW, "tags": [], "content": "", "sig": "00".repeat(64)});
            let out = client(&mut s, json!(["EVENT", event]));
            assert_eq!(out, vec![Out::Client(message::ok(&"ee".repeat(32), false, "blocked: key denied"))], "kind {kind}");
        }
        // Another's EVENT goes on as it is; one that does not read does not.
        let other = json!(["EVENT", {"id": "dd".repeat(32), "pubkey": good_hex, "kind": 1}]).to_string();
        assert_eq!(s.on_client(&other, NOW, true).unwrap(), vec![Out::Upstream(other.clone())]);
        let twice = format!(r#"["EVENT",{{"pubkey":"{good_hex}","pubkey":"{bad_hex}"}}]"#);
        assert!(matches!(&s.on_client(&twice, NOW, true).unwrap()[..], [Out::Client(t)] if t.contains("NOTICE")));
        // A REQ of the denied author alone is empty here; with another it passes.
        assert_eq!(client(&mut s, json!(["REQ", "p", {"kinds": [0], "authors": [bad_hex]}])), vec![Out::Client(json!(["EOSE", "p"]).to_string())]);
        assert_eq!(client(&mut s, json!(["COUNT", "c", {"kinds": [0, 3], "authors": [bad_hex]}])), vec![Out::Client(json!(["COUNT", "c", {"count": 0}]).to_string())]);
        assert!(passed(&client(&mut s, json!(["REQ", "q", {"kinds": [0], "authors": [bad_hex, good_hex]}]))));
        // A REQ that replaces an open one ends that one at strfry.
        let out = client(&mut s, json!(["REQ", "q", {"authors": [bad_hex], "kinds": [0]}]));
        assert_eq!(out, vec![Out::Upstream(json!(["CLOSE", "q"]).to_string()), Out::Client(json!(["EOSE", "q"]).to_string())]);
        // What strfry sends: the events of the denied key are dropped.
        let theirs = json!(["EVENT", "q", {"id": "aa".repeat(32), "pubkey": bad_hex, "kind": 0}]).to_string();
        let ours = json!(["EVENT", "q", {"id": "bb".repeat(32), "pubkey": good_hex, "kind": 0}]).to_string();
        assert!(s.on_upstream(&theirs).is_none());
        assert!(s.on_upstream(&ours).is_some());
        // The other key signs in as before.
        let ev = auth_event(&good, "c1", "wss://relay.example.org", NOW);
        assert!(matches!(&client(&mut s, json!(["AUTH", ev]))[0], Out::Client(t) if t.contains("true")));
        let counted = |name: &str| metrics.snapshot().into_iter().find(|(k, _)| *k == name).map(|(_, v)| v);
        assert_eq!((counted("denied_auth"), counted("denied_events"), counted("denied_answered"), counted("denied_dropped")), (Some(1), Some(4), Some(3), Some(1)));
    }

    #[test]
    fn a_closed_group_is_asked_for_nowhere_and_takes_no_event() {
        let metrics = Arc::new(Metrics::default());
        let groups = Arc::new(DeniedGroups::groups_of(&["bad"]));
        let mut s = Session::new(Arc::new(config()), metrics.clone(), Arc::new(DeniedKeys::none())).with_denied_groups(groups);
        // Of the closed group alone: empty, strfry never asked.
        assert_eq!(client(&mut s, json!(["REQ", "g", {"kinds": [9], "#h": ["bad"]}])), vec![Out::Client(json!(["EOSE", "g"]).to_string())]);
        assert_eq!(client(&mut s, json!(["COUNT", "c", {"kinds": [9], "#h": ["bad"]}])), vec![Out::Client(json!(["COUNT", "c", {"count": 0}]).to_string())]);
        // With others: the closed one taken out, the rest asked.
        let out = client(&mut s, json!(["REQ", "m", {"kinds": [9], "#h": ["good", "bad"], "since": 5}, {"kinds": [9], "#h": ["bad"]}]));
        assert_eq!(out, vec![Out::Upstream(json!(["REQ", "m", {"kinds": [9], "#h": ["good"], "since": 5}]).to_string())]);
        let other = json!(["REQ", "o", {"kinds": [9], "#h": ["good"]}]).to_string();
        assert_eq!(s.on_client(&other, NOW, true).unwrap(), vec![Out::Upstream(other.clone())], "untouched, byte for byte");
        // A sync of it alone: refused; with another: without it.
        let out = client(&mut s, json!(["NEG-OPEN", "n", {"kinds": [9], "#h": ["bad"]}, "61"]));
        assert!(refused_with(&out, "NEG-ERR", "restricted: group denied"), "{out:?}");
        let out = client(&mut s, json!(["NEG-OPEN", "n2", {"kinds": [9], "#h": ["bad", "good"]}, "61"]));
        assert_eq!(out, vec![Out::Upstream(json!(["NEG-OPEN", "n2", {"kinds": [9], "#h": ["good"]}, "61"]).to_string())]);
        // An event of it, by anybody: refused; of another group: on.
        let theirs = json!({"id": "aa".repeat(32), "pubkey": "cc".repeat(32), "kind": 9, "tags": [["h", "bad"]], "content": "", "sig": "00".repeat(64)});
        assert_eq!(client(&mut s, json!(["EVENT", theirs])), vec![Out::Client(message::ok(&"aa".repeat(32), false, "blocked: group denied"))]);
        let fine = json!(["EVENT", {"id": "bb".repeat(32), "pubkey": "cc".repeat(32), "kind": 9, "tags": [["h", "good"]]}]).to_string();
        assert_eq!(s.on_client(&fine, NOW, true).unwrap(), vec![Out::Upstream(fine.clone())]);
        // What strfry sends of it is dropped, whatever asked for it.
        assert!(s.on_upstream(&json!(["EVENT", "x", theirs]).to_string()).is_none());
        assert!(s.on_upstream(&json!(["EVENT", "x", {"id": "bb".repeat(32), "kind": 9, "tags": [["h", "good"]]}]).to_string()).is_some());
        let counted = |name: &str| metrics.snapshot().into_iter().find(|(k, _)| *k == name).map(|(_, v)| v);
        assert_eq!((counted("groups_answered"), counted("groups_filtered"), counted("groups_events"), counted("groups_dropped")), (Some(3), Some(2), Some(1), Some(1)));
    }

    fn with_mode(mode: crate::access::Mode, members: &[&str], admins: &[&str]) -> (Session, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::default());
        let access = Arc::new(Access::fixed(mode, members, admins));
        (Session::new(Arc::new(config()), metrics.clone(), Arc::new(DeniedKeys::none())).with_access(access), metrics)
    }

    fn event_of(keys: &Keys, kind: u16, p: &[&str]) -> Value {
        use nostr::prelude::*;
        let tags = p.iter().map(|k| nostr::prelude::Tag::parse(["p", k]).unwrap());
        let ev = nostr::prelude::EventBuilder::new(nostr::prelude::Kind::from(kind), "").tags(tags).finalize(keys).unwrap();
        serde_json::to_value(&ev).unwrap()
    }

    fn ok_false(out: &[Out], prefix: &str) -> bool {
        matches!(out, [Out::Client(t)] if {
            let v: Value = serde_json::from_str(t).unwrap();
            v[0] == "OK" && v[2] == false && v[3].as_str().unwrap_or_default().starts_with(prefix)
        })
    }

    #[test]
    fn a_team_waits_for_the_auth_then_admits_its_members_only() {
        use crate::access::Mode;
        let (member, guest) = (Keys::generate(), Keys::generate());
        let m = member.public_key().to_hex();
        let (mut s, metrics) = with_mode(Mode::Team, &[&m], &[]);
        // Anonymous: a public question and an EVENT wait for the AUTH as a
        // wrap question does, then are refused auth-required.
        let q = json!(["REQ", "p", {"kinds": [0]}]).to_string();
        let ev = json!(["EVENT", event_of(&member, 1, &[])]).to_string();
        assert_eq!(s.on_client(&q, NOW, false), Err(Pending::Challenge));
        assert_eq!(s.on_client(&ev, NOW, false), Err(Pending::Challenge));
        s.on_upstream(&json!(["AUTH", "c1"]).to_string()).unwrap();
        assert_eq!(s.on_client(&q, NOW, false), Err(Pending::Auth));
        assert_eq!(s.on_client(&ev, NOW, false), Err(Pending::Auth));
        s.auth_wait_over();
        let out = client(&mut s, json!(["REQ", "p", {"kinds": [0]}]));
        assert!(refused_with(&out, "CLOSED", "auth-required: this server is for its members"), "{out:?}");
        let out = s.on_client(&ev, NOW, true).unwrap();
        assert!(ok_false(&out, "auth-required: this server is for its members"), "{out:?}");
        let out = client(&mut s, json!(["NEG-OPEN", "n", {"kinds": [0]}, "61"]));
        assert!(refused_with(&out, "NEG-ERR", "auth-required:"), "{out:?}");

        // A guest signs in (OK true) and is refused everything.
        let out = sign_in(&mut s, &guest);
        assert!(matches!(&out[0], Out::Client(t) if t.contains("true")), "{out:?}");
        let out = client(&mut s, json!(["REQ", "p", {"kinds": [0]}]));
        assert!(refused_with(&out, "CLOSED", "restricted: not a member of this server; ask its admin for an invite"), "{out:?}");
        let out = client(&mut s, json!(["COUNT", "c", {"kinds": [0]}]));
        assert!(refused_with(&out, "CLOSED", "restricted: not a member"), "{out:?}");
        let out = client(&mut s, json!(["EVENT", event_of(&guest, 0, &[])]));
        assert!(ok_false(&out, "restricted: not a member of this server"), "{out:?}");

        // A member: as on an open server.
        let (mut s, _) = with_mode(Mode::Team, &[&m], &[]);
        sign_in(&mut s, &member);
        assert!(passed(&client(&mut s, json!(["REQ", "p", {"kinds": [0]}]))));
        assert!(passed(&client(&mut s, json!(["REQ", "dm", {"kinds": [1059], "#p": [m]}]))));
        let theirs = Keys::generate().public_key().to_hex();
        assert!(refused_with(&client(&mut s, json!(["REQ", "x", {"kinds": [1059], "#p": [theirs]}])), "CLOSED", "restricted: gift wraps"));
        assert!(passed(&client(&mut s, json!(["EVENT", event_of(&Keys::generate(), 1059, &[&theirs])]))), "a wrap is signed by a key of its own");
        let counted = |name: &str| metrics.snapshot().into_iter().find(|(k, _)| *k == name).map(|(_, v)| v).unwrap();
        assert_eq!((counted("access_auth_required"), counted("access_restricted")), (3, 3));
    }

    #[test]
    fn a_channel_reads_free_and_gates_writes() {
        use crate::access::Mode;
        let (author, guest, stranger) = (Keys::generate(), Keys::generate(), Keys::generate());
        let a = author.public_key().to_hex();
        let g = guest.public_key().to_hex();
        let (mut s, metrics) = with_mode(Mode::Channel, &[], &[&a]);
        // Anonymous reads what is public, at once; its wraps need a key.
        assert!(passed(&s.on_client(&json!(["REQ", "p", {"kinds": [0, 1]}]).to_string(), NOW, false).unwrap()));
        assert_eq!(s.on_client(&json!(["REQ", "dm", {"kinds": [1059], "#p": [g]}]).to_string(), NOW, false), Err(Pending::Challenge));
        // Anonymous writes nothing: after the wait, auth-required.
        let out = client(&mut s, json!(["EVENT", event_of(&guest, 0, &[])]));
        assert!(ok_false(&out[1..], "auth-required:"), "a challenge, then the refusal: {out:?}");
        sign_in(&mut s, &guest);
        assert!(passed(&client(&mut s, json!(["REQ", "dm", {"kinds": [1059], "#p": [g]}]))), "its own wraps: a community's issue");
        assert!(ok_false(&client(&mut s, json!(["EVENT", event_of(&guest, 1, &[])])), "restricted: on this server only its authors write"));
        assert!(passed(&client(&mut s, json!(["EVENT", event_of(&guest, 0, &[])]))));
        assert!(ok_false(&client(&mut s, json!(["EVENT", event_of(&stranger, 0, &[])])), "restricted: a guest writes its own"));
        assert!(passed(&client(&mut s, json!(["EVENT", event_of(&stranger, 1059, &[&a])]))));
        assert!(ok_false(&client(&mut s, json!(["EVENT", event_of(&stranger, 1059, &[&g])])), "restricted: a guest writes to the authors"));
        let counted = |name: &str| metrics.snapshot().into_iter().find(|(k, _)| *k == name).map(|(_, v)| v).unwrap();
        assert_eq!((counted("guest_events"), counted("access_restricted"), counted("access_auth_required")), (2, 3, 1));
        // The author writes anything.
        let (mut s, _) = with_mode(Mode::Channel, &[], &[&a]);
        sign_in(&mut s, &author);
        assert!(passed(&client(&mut s, json!(["EVENT", event_of(&author, 1, &[])]))));
    }

    #[test]
    fn open_reads_no_event_and_a_peer_is_not_a_session() {
        // Open, nobody denied: an EVENT is not even parsed (it is no JSON
        // here and still goes on).
        let mut s = session();
        assert_eq!(s.on_client("[\"EVENT\", not json", NOW, false).unwrap(), vec![Out::Upstream("[\"EVENT\", not json".into())]);
        let (mut s, _) = with_mode(crate::access::Mode::Channel, &[], &[]);
        assert!(matches!(&s.on_client("[\"EVENT\", not json", NOW, false).unwrap()[..], [Out::Client(t)] if t.contains("NOTICE")));
    }
}
