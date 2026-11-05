//! What a client may ask the relay (spec/vguard.md, "The rules").
//!
//! The relay holds gift wraps (kind 1059) addressed by `#p` and the events
//! of groups (kind 9) named by `#h`. Their contents are sealed, but who
//! gets wraps, when, and which groups talk is metadata, and the app key
//! that lets a client in is public. So a filter that can match a gift wrap
//! must name by `#p` the key the connection signed in with (NIP-42), and
//! nothing else; a filter that can match a group event must name groups by
//! `#h`. A filter without `kinds` can match both, so it must do both. A
//! filter of full event ids names its events itself and passes: an id is
//! a hash nobody guesses, and the push of a message carries one.
//!
//! Every other kind (profiles, follow lists, relay lists, presence, the
//! codes of a device link…) is public and asked as before.

use serde_json::{Map, Value};

/// A gift wrap (NIP-59).
pub const KIND_GIFT_WRAP: u64 = 1059;
/// The ephemeral wrap of a «typing» to a person: `p` names the receiver
/// as a gift wrap's does (crates/messenger/core/src/envelope.rs).
pub const KIND_TYPING_WRAP: u64 = 21059;
/// An event of a group on the relay (crates/messenger/groups/src/wire.rs).
pub const KIND_GROUP_EVENT: u64 = 9;
/// The ephemeral twin of a group event: a «typing» under the group's `h`.
pub const KIND_GROUP_TYPING: u64 = 20009;

/// Why a filter is not passed on. The words are NIP-01's machine-readable
/// prefixes: nostr-sdk signs in and asks again on `auth-required`, and
/// gives up on `restricted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The connection has not signed in yet.
    AuthRequired(String),
    /// Signed in, but this is not for that key; or not narrow enough.
    Restricted(String),
    /// Not a filter vguard can read for certain.
    Invalid(String),
}

impl Refusal {
    /// The text of CLOSED or NEG-ERR.
    pub fn message(&self) -> String {
        match self {
            Refusal::AuthRequired(m) => format!("auth-required: {m}"),
            Refusal::Restricted(m) => format!("restricted: {m}"),
            Refusal::Invalid(m) => format!("invalid: {m}"),
        }
    }

    /// The name of the counter.
    pub fn word(&self) -> &'static str {
        match self {
            Refusal::AuthRequired(_) => "auth_required",
            Refusal::Restricted(_) => "restricted",
            Refusal::Invalid(_) => "invalid",
        }
    }

    /// Of several refusals the one that tells the client most: an invalid
    /// filter stays invalid, a foreign key stays foreign after signing in.
    fn rank(&self) -> u8 {
        match self {
            Refusal::Invalid(_) => 2,
            Refusal::Restricted(_) => 1,
            Refusal::AuthRequired(_) => 0,
        }
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The strings of a list field: None when absent; an error when it is not
/// a list of strings.
fn strings<'a>(f: &'a Map<String, Value>, key: &str) -> Result<Option<Vec<&'a str>>, Refusal> {
    match f.get(key) {
        None => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().ok_or_else(|| {
                    Refusal::Invalid(format!("{key} holds a value that is not a string"))
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(Refusal::Invalid(format!("{key} is not a list"))),
    }
}

/// One filter, for a connection signed in as `authed` (hex) or not at all.
pub fn check_filter(filter: &Value, authed: Option<&str>) -> Result<(), Refusal> {
    let Value::Object(f) = filter else {
        return Err(Refusal::Invalid("a filter is an object".into()));
    };

    // Full ids name their events: nothing to enumerate.
    if let Some(ids) = strings(f, "ids")? {
        if !ids.is_empty() {
            if ids.iter().all(|id| is_hex64(id)) {
                return Ok(());
            }
            return Err(Refusal::Invalid("ids are full event ids, 64 hex".into()));
        }
    }

    // No kinds, or an empty list, matches every kind.
    let kinds: Option<Vec<u64>> = match f.get("kinds") {
        None => None,
        Some(Value::Array(items)) => {
            let ks = items
                .iter()
                .map(|v| v.as_u64().filter(|k| *k <= u16::MAX as u64))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| Refusal::Invalid("kinds are numbers 0..65535".into()))?;
            (!ks.is_empty()).then_some(ks)
        }
        Some(_) => return Err(Refusal::Invalid("kinds is not a list".into())),
    };
    let may = |kind: u64| kinds.as_ref().is_none_or(|ks| ks.contains(&kind));

    let mut refusals = Vec::new();
    // A «typing» to a person (21059) names its receiver as a gift wrap
    // does: who is written to, and when, is nobody else's to ask.
    if may(KIND_GIFT_WRAP) || may(KIND_TYPING_WRAP) {
        let p = strings(f, "#p")?.unwrap_or_default();
        if p.is_empty() {
            refusals.push(Refusal::Restricted(
                "gift wraps (kind 1059, 21059, or no kinds) are given by #p of the key you signed in with"
                    .into(),
            ));
        } else {
            match authed {
                None => refusals.push(Refusal::AuthRequired(
                    "gift wraps are given to the key that signed in".into(),
                )),
                Some(me) if p.iter().all(|k| *k == me) => {}
                Some(_) => refusals.push(Refusal::Restricted(
                    "gift wraps are given to their own key only".into(),
                )),
            }
        }
    }
    if may(KIND_GROUP_EVENT) || may(KIND_GROUP_TYPING) {
        let h = strings(f, "#h")?.unwrap_or_default();
        if h.is_empty() || h.iter().any(|g| g.is_empty()) {
            refusals.push(Refusal::Restricted(
                "events of groups (kind 9, 20009, or no kinds) are given by #h".into(),
            ));
        }
    }
    match refusals.into_iter().max_by_key(Refusal::rank) {
        None => Ok(()),
        Some(r) => Err(r),
    }
}

/// The filters of one REQ or COUNT: all of them pass, or the question does
/// not. None of them is a question too broad to answer.
pub fn check_filters(filters: &[Value], authed: Option<&str>, max: usize) -> Result<(), Refusal> {
    if filters.is_empty() {
        return Err(Refusal::Invalid("a question needs a filter".into()));
    }
    if filters.len() > max {
        return Err(Refusal::Invalid(format!(
            "at most {max} filters in one question"
        )));
    }
    let mut worst: Option<Refusal> = None;
    for f in filters {
        if let Err(r) = check_filter(f, authed) {
            if worst.as_ref().is_none_or(|w| r.rank() > w.rank()) {
                worst = Some(r);
            }
        }
    }
    match worst {
        None => Ok(()),
        Some(r) => Err(r),
    }
}

/// Whether a question asks for the events of denied keys and nothing else:
/// every filter names `authors`, and every one of them is denied. Such a
/// question is answered as empty here (`spec/vguard.md`, "Denied keys");
/// any other passes, and an event of a denied key that strfry sends back
/// is dropped on its way to the client.
pub fn only_denied_authors(filters: &[Value], denied: &veydan_denied::DeniedKeys) -> bool {
    !filters.is_empty()
        && filters.iter().all(|f| match f.get("authors") {
            Some(Value::Array(authors)) => {
                !authors.is_empty() && authors.iter().all(|a| a.as_str().is_some_and(|k| denied.contains(k)))
            }
            _ => false,
        })
}

/// The filters of a question with the closed groups taken out
/// (`spec/vguard.md`, "Denied groups"): every closed id out of each `#h`,
/// and a filter whose every `#h` was closed dropped, since it can match the
/// events of closed groups alone (`#h` is a condition every event it
/// matches meets). `None` when no filter named a closed group: the question
/// goes on as the client sent it, byte for byte. `Some` of an empty list:
/// nothing is left to ask, the answer is empty.
///
/// The ids are taken out rather than the question refused: the app asks
/// for all its groups in one filter, and one closed group must not cut it
/// off from the others.
pub fn without_denied_groups(filters: &[Value], groups: &veydan_denied::DeniedGroups) -> Option<Vec<Value>> {
    if groups.is_empty() {
        return None;
    }
    let names = |f: &Value| match f.get("#h") {
        Some(Value::Array(h)) => h.iter().any(|g| g.as_str().is_some_and(|g| groups.contains(g))),
        _ => false,
    };
    if !filters.iter().any(names) {
        return None;
    }
    let mut out = Vec::with_capacity(filters.len());
    for f in filters {
        let Some(Value::Array(h)) = f.get("#h") else {
            out.push(f.clone());
            continue;
        };
        let open: Vec<Value> = h.iter().filter(|g| !g.as_str().is_some_and(|g| groups.contains(g))).cloned().collect();
        if open.is_empty() {
            continue;
        }
        let mut f = f.clone();
        if let Some(map) = f.as_object_mut() {
            map.insert("#h".into(), Value::Array(open));
        }
        out.push(f);
    }
    Some(out)
}

/// Whether an event carries an `h` of a closed group: refused from a client,
/// dropped from strfry. Any `h` counts, not the first alone: an event in two
/// groups is in the closed one too.
pub fn in_denied_group(event: &Value, groups: &veydan_denied::DeniedGroups) -> bool {
    match event.get("tags") {
        Some(Value::Array(tags)) => tags.iter().any(|t| match t {
            Value::Array(t) => t.first().and_then(Value::as_str) == Some("h") && t.get(1).and_then(Value::as_str).is_some_and(|g| groups.contains(g)),
            _ => false,
        }),
        _ => false,
    }
}

/// Whether `kind` is a wrap addressed by its `p`: a gift wrap or the
/// ephemeral wrap of a «typing».
pub fn is_wrap_kind(kind: u64) -> bool {
    kind == KIND_GIFT_WRAP || kind == KIND_TYPING_WRAP
}

/// The values of the `p` tags of an event, in order; a tag that is not a
/// list of strings is skipped.
pub fn p_tags(event: &Value) -> Vec<&str> {
    match event.get("tags") {
        Some(Value::Array(tags)) => tags
            .iter()
            .filter_map(|t| match t {
                Value::Array(t) if t.first().and_then(Value::as_str) == Some("p") => t.get(1).and_then(Value::as_str),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_p_tags_of_an_event() {
        let e = json!({"tags": [["p", "a"], ["e", "x"], ["p", "b", "wss://r"], ["p"], "junk"]});
        assert_eq!(p_tags(&e), ["a", "b"]);
        assert!(p_tags(&json!({})).is_empty());
        assert!(is_wrap_kind(1059) && is_wrap_kind(21059) && !is_wrap_kind(9));
    }

    #[test]
    fn the_closed_groups_are_taken_out_of_a_question() {
        let groups = veydan_denied::DeniedGroups::groups_of(&["bad"]);
        let none = veydan_denied::DeniedGroups::none();
        let mixed = [json!({"kinds": [9], "#h": ["bad", "good"], "limit": 5}), json!({"kinds": [0], "authors": [ME]})];
        assert_eq!(without_denied_groups(&mixed, &none), None, "nobody closed: as it came");
        assert_eq!(without_denied_groups(&[json!({"kinds": [9], "#h": ["good"]})], &groups), None, "no closed group named");
        assert_eq!(without_denied_groups(&mixed, &groups), Some(vec![json!({"kinds": [9], "#h": ["good"], "limit": 5}), mixed[1].clone()]));
        assert_eq!(without_denied_groups(&[json!({"kinds": [9], "#h": ["bad"]}), mixed[1].clone()], &groups), Some(vec![mixed[1].clone()]), "a filter of the closed alone goes");
        assert_eq!(without_denied_groups(&[json!({"#h": ["bad"], "kinds": [9, 11]})], &groups), Some(vec![]), "nothing left to ask");
        let event = |tags: Value| json!({"id": "e", "kind": 9, "tags": tags});
        assert!(in_denied_group(&event(json!([["h", "bad"]])), &groups));
        assert!(in_denied_group(&event(json!([["h", "good"], ["h", "bad"]])), &groups), "any h");
        assert!(!in_denied_group(&event(json!([["h", "good"], ["p", "bad"]])), &groups));
        assert!(!in_denied_group(&event(json!("nope")), &groups) && !in_denied_group(&event(json!([["h", "bad"]])), &none));
    }

    #[test]
    fn a_question_of_denied_authors_alone_is_known() {
        let denied = veydan_denied::DeniedKeys::of(&[ME]);
        assert!(only_denied_authors(&[json!({"authors": [ME], "kinds": [0]})], &denied));
        assert!(only_denied_authors(&[json!({"authors": [ME]}), json!({"authors": [ME], "kinds": [3]})], &denied));
        assert!(!only_denied_authors(&[json!({"authors": [ME, OTHER]})], &denied), "another author is asked too");
        assert!(!only_denied_authors(&[json!({"authors": [ME]}), json!({"kinds": [0]})], &denied), "a filter without authors");
        assert!(!only_denied_authors(&[json!({"authors": []})], &denied));
        assert!(!only_denied_authors(&[], &denied));
        assert!(!only_denied_authors(&[json!({"authors": [ME]})], &veydan_denied::DeniedKeys::none()));
    }

    const ME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn word(r: Result<(), Refusal>) -> &'static str {
        match r {
            Ok(()) => "ok",
            Err(r) => r.word(),
        }
    }

    /// The table of the plan (S7-02): each filter, signed in or not, and
    /// what comes of it.
    #[test]
    fn the_table() {
        let rows: &[(Value, Option<&str>, &str)] = &[
            // Gift wraps.
            (json!({"kinds": [1059]}), Some(ME), "restricted"),
            (json!({"kinds": [1059]}), None, "restricted"),
            (
                json!({"kinds": [1059], "#p": [OTHER]}),
                Some(ME),
                "restricted",
            ),
            (
                json!({"kinds": [1059], "#p": [ME, OTHER]}),
                Some(ME),
                "restricted",
            ),
            (json!({"kinds": [1059], "#p": [ME]}), Some(ME), "ok"),
            (
                json!({"kinds": [1059], "#p": [ME, ME], "since": 1, "limit": 10}),
                Some(ME),
                "ok",
            ),
            (json!({"kinds": [1059], "#p": [ME]}), None, "auth_required"),
            // The ephemeral «typing» wrap names its receiver as a gift wrap does.
            (json!({"kinds": [21059], "#p": [ME]}), None, "auth_required"),
            (json!({"kinds": [21059], "#p": [OTHER]}), Some(ME), "restricted"),
            (json!({"kinds": [1059, 21059], "#p": [ME]}), Some(ME), "ok"),
            (json!({"kinds": [21059]}), Some(ME), "restricted"),
            // The ephemeral twin of a group event goes by `#h` like kind 9.
            (json!({"kinds": [20009]}), Some(ME), "restricted"),
            (json!({"kinds": [9, 20009], "#h": ["g1"]}), None, "ok"),
            (
                json!({"kinds": [1059], "#p": [ME.to_uppercase()]}),
                Some(ME),
                "restricted",
            ),
            (
                json!({"kinds": [1059], "authors": [OTHER]}),
                Some(ME),
                "restricted",
            ),
            (json!({"kinds": [0, 1059], "#p": [ME]}), Some(ME), "ok"),
            // Groups.
            (json!({"kinds": [9]}), Some(ME), "restricted"),
            (json!({"kinds": [9], "#h": []}), Some(ME), "restricted"),
            (json!({"kinds": [9], "#h": [""]}), Some(ME), "restricted"),
            (json!({"kinds": [9], "#h": ["g1", "g2"]}), None, "ok"),
            (
                json!({"kinds": [9], "#h": ["g1"], "since": 5}),
                Some(ME),
                "ok",
            ),
            (
                json!({"kinds": [9, 1059], "#h": ["g1"]}),
                Some(ME),
                "restricted",
            ),
            (
                json!({"kinds": [9, 1059], "#h": ["g1"], "#p": [ME]}),
                Some(ME),
                "ok",
            ),
            // No kinds: both rules.
            (json!({}), Some(ME), "restricted"),
            (json!({}), None, "restricted"),
            (json!({"limit": 100}), Some(ME), "restricted"),
            (json!({"kinds": []}), Some(ME), "restricted"),
            (json!({"#p": [ME]}), Some(ME), "restricted"),
            (json!({"#h": ["g1"]}), Some(ME), "restricted"),
            (json!({"#p": [ME], "#h": ["g1"]}), Some(ME), "ok"),
            (json!({"#p": [ME], "#h": ["g1"]}), None, "auth_required"),
            (json!({"authors": [OTHER]}), Some(ME), "restricted"),
            // Public kinds, as before.
            (json!({"kinds": [0], "authors": [OTHER]}), None, "ok"),
            (
                json!({"kinds": [3], "authors": [ME], "limit": 1}),
                None,
                "ok",
            ),
            (json!({"kinds": [10002]}), None, "ok"),
            (json!({"kinds": [10050], "authors": [OTHER]}), None, "ok"),
            (
                json!({"kinds": [30315], "authors": [OTHER], "#d": ["veydan"]}),
                None,
                "ok",
            ),
            (
                json!({"kinds": [30078], "#d": ["x"], "limit": 0}),
                None,
                "ok",
            ),
            // Full ids name their events.
            (json!({"ids": [OTHER]}), None, "ok"),
            (json!({"ids": [OTHER], "kinds": [1059]}), None, "ok"),
            (json!({"ids": ["bbbb"]}), None, "invalid"),
            (json!({"ids": []}), Some(ME), "restricted"),
            // What vguard cannot read for certain.
            (json!({"kinds": [1059.5], "#p": [ME]}), Some(ME), "invalid"),
            (json!({"kinds": ["1059"], "#p": [ME]}), Some(ME), "invalid"),
            (json!({"kinds": [70000]}), Some(ME), "invalid"),
            (json!({"kinds": 1059, "#p": [ME]}), Some(ME), "invalid"),
            (json!({"kinds": [1059], "#p": ME}), Some(ME), "invalid"),
            (json!({"kinds": [1059], "#p": [1]}), Some(ME), "invalid"),
            (json!([1059]), Some(ME), "invalid"),
        ];
        for (filter, authed, want) in rows {
            assert_eq!(
                word(check_filter(filter, *authed)),
                *want,
                "{filter} signed in as {authed:?}"
            );
        }
    }

    #[test]
    fn a_question_passes_only_whole() {
        let mine = json!({"kinds": [1059], "#p": [ME]});
        let theirs = json!({"kinds": [1059], "#p": [OTHER]});
        let profiles = json!({"kinds": [0], "authors": [OTHER]});
        assert!(check_filters(&[mine.clone(), profiles.clone()], Some(ME), 10).is_ok());
        assert_eq!(
            word(check_filters(&[mine.clone(), theirs.clone()], Some(ME), 10)),
            "restricted"
        );
        assert_eq!(word(check_filters(&[], Some(ME), 10)), "invalid");
        assert_eq!(
            word(check_filters(
                &[profiles.clone(), profiles.clone()],
                None,
                1
            )),
            "invalid"
        );
        // No #p at all: signing in would not help, restricted, not auth-required.
        assert_eq!(
            word(check_filters(
                &[mine.clone(), json!({"kinds": [1059]})],
                None,
                10
            )),
            "restricted"
        );
        assert_eq!(
            word(check_filters(&[mine.clone(), theirs], None, 10)),
            "auth_required",
            "whose key it is is known after signing in"
        );
        assert_eq!(word(check_filters(&[mine], None, 10)), "auth_required");
    }

    #[test]
    fn the_words_are_the_prefixes_of_nip01() {
        assert!(Refusal::AuthRequired("x".into())
            .message()
            .starts_with("auth-required: "));
        assert!(Refusal::Restricted("x".into())
            .message()
            .starts_with("restricted: "));
        assert!(Refusal::Invalid("x".into())
            .message()
            .starts_with("invalid: "));
    }
}
