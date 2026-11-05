//! The messages of NIP-01, NIP-42, NIP-45 and NIP-77 as vguard reads and
//! writes them.
//!
//! What vguard decides on, it reads the way strfry will: a message it
//! cannot read with certainty (a key twice in one object, which parsers
//! settle differently) is not passed on at all.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// The first element of a message, when it is a plain string: the cheap
/// way, without reading the rest (an EVENT may be 256 KiB). None when the
/// string has an escape in it or the text is not an array: the caller
/// reads the whole message then.
pub fn peek_verb(text: &str) -> Option<&str> {
    const WS: [char; 4] = [' ', '\t', '\n', '\r'];
    let t = text.trim_start_matches(WS).strip_prefix('[')?;
    let t = t.trim_start_matches(WS).strip_prefix('"')?;
    let end = t.find(['"', '\\'])?;
    (t.as_bytes()[end] == b'"').then(|| &t[..end])
}

/// The whole message, refused when an object in it has a key twice.
pub fn parse_strict(text: &str) -> Result<Value, String> {
    serde_json::from_str::<Strict>(text)
        .map(|s| s.0)
        .map_err(|e| e.to_string())
}

/// The message as an array with a string first, or why not.
pub fn parse_array(text: &str) -> Result<Vec<Value>, String> {
    match parse_strict(text)? {
        Value::Array(items) if items.first().is_some_and(Value::is_string) => Ok(items),
        _ => Err("a message is an array with its verb first".into()),
    }
}

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "the key {key:.40} twice in one object"
                )));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// `["CLOSED", <sub>, <why>]`
pub fn closed(sub: &str, why: &str) -> String {
    serde_json::json!(["CLOSED", sub, why]).to_string()
}

/// `["NEG-ERR", <sub>, <why>]`
pub fn neg_err(sub: &str, why: &str) -> String {
    serde_json::json!(["NEG-ERR", sub, why]).to_string()
}

/// `["NOTICE", <text>]`
pub fn notice(text: &str) -> String {
    serde_json::json!(["NOTICE", text]).to_string()
}

/// `["OK", <event id>, <taken>, <why>]`
pub fn ok(id: &str, taken: bool, why: &str) -> String {
    serde_json::json!(["OK", id, taken, why]).to_string()
}

/// `["AUTH", <challenge>]`
pub fn auth_challenge(challenge: &str) -> String {
    serde_json::json!(["AUTH", challenge]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verb_is_peeked_without_reading_the_rest() {
        assert_eq!(peek_verb(r#"["EVENT",{"id":"x"}]"#), Some("EVENT"));
        assert_eq!(peek_verb(" \n[ \"REQ\" ,\"s\",{}]"), Some("REQ"));
        let escaped = format!("[\"RE{}u0051\",\"s\",{{}}]", char::from(92));
        assert_eq!(peek_verb(&escaped), None, "an escape: read it whole");
        assert_eq!(peek_verb(r#"{"REQ":1}"#), None);
        assert_eq!(peek_verb("[1]"), None);
    }

    #[test]
    fn a_key_twice_is_refused_at_any_depth() {
        assert!(parse_strict(r##"["REQ","s",{"#p":["a"],"#p":["b"]}]"##).is_err());
        assert!(parse_strict(r#"["REQ","s",{"x":{"k":1,"k":2}}]"#).is_err());
        let v = parse_strict(&format!(
            r##"["RE{}u0051","s",{{"kinds":[1059],"#p":["a"]}}]"##,
            char::from(92)
        ))
        .unwrap();
        assert_eq!(v[0], "REQ");
        assert_eq!(v[2]["kinds"][0], 1059);
    }

    #[test]
    fn a_message_is_an_array_with_a_verb() {
        assert!(parse_array(r#"["REQ","s",{}]"#).is_ok());
        assert!(parse_array(r#"[1,"s"]"#).is_err());
        assert!(parse_array(r#"{"a":1}"#).is_err());
        assert!(parse_array("[]").is_err());
        assert!(parse_array("not json").is_err());
    }

    #[test]
    fn the_answers_are_json() {
        assert_eq!(
            closed("s", "restricted: x"),
            r#"["CLOSED","s","restricted: x"]"#
        );
        assert_eq!(
            neg_err("s", "auth-required: x"),
            r#"["NEG-ERR","s","auth-required: x"]"#
        );
        assert_eq!(ok("ab", true, ""), r#"["OK","ab",true,""]"#);
        assert_eq!(auth_challenge("c"), r#"["AUTH","c"]"#);
        assert_eq!(notice("n"), r#"["NOTICE","n"]"#);
    }
}
