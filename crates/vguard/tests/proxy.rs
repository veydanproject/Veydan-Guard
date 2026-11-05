//! vguard between a client and a relay, over real sockets: a fake strfry
//! that records what reaches it, and nostr-sdk's own relay with the
//! client the app is built on.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use vguard::config::Config;
use vguard::proxy::{self, Shared};
use nostr_sdk::prelude::ToBech32;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A strfry of a test: gives a challenge as the connection opens (when
/// `challenge`), answers REQ with EOSE, AUTH with a refusal of its own (as
/// strfry does for an alias), NEG-OPEN with a NEG-MSG; keeps every frame
/// and the X-Real-IP of each connection. A REQ is answered with the events
/// of `served` first, whatever it asked: what a filter would match is
/// strfry's business, what reaches the client is vguard's.
#[derive(Clone, Default)]
struct Fake {
    frames: Arc<Mutex<Vec<Value>>>,
    real_ips: Arc<Mutex<Vec<String>>>,
    served: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    async fn start(challenge: bool) -> (Self, SocketAddr) {
        let fake = Fake::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let f = fake.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let f = f.clone();
                tokio::spawn(async move {
                    let mut ip = None;
                    #[allow(clippy::result_large_err)]
                    let cb = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                        ip = req
                            .headers()
                            .get("x-real-ip")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        Ok(resp)
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, cb).await else {
                        return;
                    };
                    f.real_ips.lock().unwrap().push(ip.unwrap_or_default());
                    if challenge {
                        ws.send(Message::text(
                            json!(["AUTH", "strfry-challenge"]).to_string(),
                        ))
                        .await
                        .unwrap();
                    }
                    while let Some(Ok(m)) = ws.next().await {
                        let Message::Text(t) = m else { continue };
                        let v: Value = serde_json::from_str(t.as_str()).unwrap();
                        f.frames.lock().unwrap().push(v.clone());
                        if v[0] == "REQ" {
                            let served = f.served.lock().unwrap().clone();
                            for e in served {
                                if ws.send(Message::text(json!(["EVENT", v[1], e]).to_string())).await.is_err() {
                                    break;
                                }
                            }
                        }
                        let answer = match v[0].as_str() {
                            Some("REQ") => Some(json!(["EOSE", v[1]])),
                            Some("AUTH") => Some(json!([
                                "OK",
                                v[1]["id"],
                                false,
                                "auth failed: incorrect or missing relay tag"
                            ])),
                            Some("NEG-OPEN") => Some(json!(["NEG-MSG", v[1], "61"])),
                            Some("EVENT") => Some(json!(["OK", v[1]["id"], true, ""])),
                            _ => None,
                        };
                        if let Some(a) = answer {
                            if ws.send(Message::text(a.to_string())).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });
        (fake, addr)
    }

    fn verbs_with(&self, sub: &str) -> Vec<String> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v[1] == sub)
            .map(|v| v[0].as_str().unwrap().to_string())
            .collect()
    }

    /// Every frame strfry got, in order: the verb and, but for an AUTH, the
    /// subscription id (of an EVENT, its id).
    fn order(&self) -> Vec<String> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .map(|v| match (v[0].as_str().unwrap(), &v[1]) {
                ("AUTH", _) => "AUTH".to_string(),
                (verb, Value::String(s)) => format!("{verb} {s}"),
                (verb, e) => format!("{verb} {}", e["id"].as_str().unwrap_or_default()),
            })
            .collect()
    }

    fn saw(&self, verb: &str) -> usize {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v[0] == verb)
            .count()
    }
}

async fn guard(upstream: SocketAddr, extra: &str) -> (SocketAddr, Arc<Shared>) {
    let config = Config::parse(&format!(
        "upstream = \"{upstream}\"\nrelay_hosts = [\"relay.example.org\", \"127.0.0.1\"]\n{extra}"
    ))
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Shared::new(config);
    tokio::spawn(proxy::run(listener, shared.clone()));
    (addr, shared)
}

async fn connect(addr: SocketAddr, headers: &[(&'static str, &str)]) -> Ws {
    let mut req = format!("ws://{addr}/").into_client_request().unwrap();
    for (k, v) in headers {
        req.headers_mut()
            .insert(*k, HeaderValue::from_str(v).unwrap());
    }
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// The next text frame, within two seconds.
async fn recv(ws: &mut Ws) -> Value {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("an answer in time");
        match m.expect("the connection is open").expect("a frame") {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Close(_) => panic!("closed"),
            _ => continue,
        }
    }
}

fn auth_event(keys: &Keys, challenge: &str, relay: &str) -> Value {
    let ev = EventBuilder::new(Kind::Authentication, "")
        .tags([
            Tag::parse(["challenge", challenge]).unwrap(),
            Tag::parse(["relay", relay]).unwrap(),
        ])
        .finalize(keys)
        .unwrap();
    serde_json::to_value(&ev).unwrap()
}

#[tokio::test]
async fn a_client_signs_in_and_reads_its_own_wraps_only() {
    let (fake, up) = Fake::start(true).await;
    // No wait for the AUTH: a question before it is refused at once.
    let (addr, shared) = guard(up, "[limits]\nauth_wait_ms = 0\n").await;
    let keys = Keys::generate();
    let me = keys.public_key().to_hex();
    let other = Keys::generate().public_key().to_hex();
    let mut ws = connect(addr, &[("x-real-ip", "198.51.100.9")]).await;

    // strfry's challenge comes through.
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));

    // Before signing in: auth-required, and strfry never hears of it.
    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    let a = recv(&mut ws).await;
    assert_eq!(a[0], "CLOSED");
    assert!(a[2].as_str().unwrap().starts_with("auth-required:"), "{a}");

    // Signing in: vguard says OK, strfry gets the AUTH as it is, and its own
    // refusal does not reach the client.
    let ev = auth_event(
        &keys,
        "strfry-challenge",
        "wss://relay.example.org/?key=appkey",
    );
    send(&mut ws, json!(["AUTH", ev])).await;
    let ok = recv(&mut ws).await;
    assert_eq!(ok, json!(["OK", ev["id"], true, ""]));

    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    assert_eq!(
        recv(&mut ws).await,
        json!(["EOSE", "dm"]),
        "no second OK came before it"
    );
    assert_eq!(fake.saw("AUTH"), 1);

    for (sub, filter) in [
        ("theirs", json!({"kinds": [1059], "#p": [other]})),
        ("all-wraps", json!({"kinds": [1059]})),
        ("groups", json!({"kinds": [9]})),
        ("everything", json!({})),
    ] {
        send(&mut ws, json!(["REQ", sub, filter])).await;
        let a = recv(&mut ws).await;
        assert_eq!(a[0], "CLOSED", "{sub}: {a}");
        assert!(
            a[2].as_str().unwrap().starts_with("restricted:"),
            "{sub}: {a}"
        );
        assert!(fake.verbs_with(sub).is_empty(), "{sub} reached strfry");
    }
    send(&mut ws, json!(["COUNT", "count", {"kinds": [1059]}])).await;
    assert_eq!(recv(&mut ws).await[0], "CLOSED");
    send(&mut ws, json!(["NEG-OPEN", "neg", {"kinds": [1059]}, "61"])).await;
    let a = recv(&mut ws).await;
    assert_eq!(a[0], "NEG-ERR");
    assert!(fake.verbs_with("neg").is_empty());

    // What is allowed goes through.
    send(
        &mut ws,
        json!(["REQ", "group", {"kinds": [9], "#h": ["g1"]}]),
    )
    .await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "group"]));
    send(
        &mut ws,
        json!(["REQ", "profiles", {"kinds": [0], "authors": [other]}]),
    )
    .await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "profiles"]));
    send(
        &mut ws,
        json!(["NEG-OPEN", "sync", {"kinds": [1059], "#p": [me]}, "61"]),
    )
    .await;
    assert_eq!(recv(&mut ws).await, json!(["NEG-MSG", "sync", "61"]));
    send(
        &mut ws,
        json!(["REQ", "pushed", {"ids": ["ab".repeat(32)]}]),
    )
    .await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "pushed"]));

    // The address nginx named reaches strfry.
    assert_eq!(fake.real_ips.lock().unwrap().as_slice(), ["198.51.100.9"]);
    let m = shared.metrics.line();
    assert!(m.contains("refused_restricted=6"), "{m}");
    assert!(m.contains("auth_ok=1"), "{m}");
}

#[tokio::test]
async fn a_peer_named_by_nginx_reads_everything() {
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, "").await;
    let mut ws = connect(addr, &[("x-veydan-role", "peer")]).await;
    assert_eq!(recv(&mut ws).await[0], "AUTH");
    send(&mut ws, json!(["REQ", "mesh", {}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "mesh"]));
    send(&mut ws, json!(["NEG-OPEN", "sync", {}, "61"])).await;
    assert_eq!(recv(&mut ws).await, json!(["NEG-MSG", "sync", "61"]));
    send(&mut ws, json!(["REQ", "wraps", {"kinds": [1059]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "wraps"]));
    // Frames pass as they are, even what vguard would not read.
    ws.send(Message::text(r#"["REQ","dup",{"kinds":[0],"kinds":[1]}]"#))
        .await
        .unwrap();
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "dup"]));
    assert!(shared.metrics.line().contains("peers=1"));
    assert_eq!(fake.saw("REQ"), 3);
}

#[tokio::test]
async fn without_a_challenge_of_strfry_vguard_gives_its_own_and_keeps_the_auth() {
    let (fake, up) = Fake::start(false).await;
    let (addr, _) = guard(up, "[limits]\nchallenge_wait_ms = 100\n").await;
    let keys = Keys::generate();
    let me = keys.public_key().to_hex();
    let mut ws = connect(addr, &[]).await;
    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    let c = recv(&mut ws).await;
    assert_eq!(c[0], "AUTH");
    // The question waits for the AUTH over vguard's challenge, and is
    // answered after it.
    let ev = auth_event(&keys, c[1].as_str().unwrap(), "wss://relay.example.org");
    send(&mut ws, json!(["AUTH", ev])).await;
    assert_eq!(recv(&mut ws).await[2], true);
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "dm"]));
    send(&mut ws, json!(["REQ", "dm2", {"kinds": [1059], "#p": [me]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "dm2"]));
    assert_eq!(
        fake.saw("AUTH"),
        0,
        "strfry does not know vguard's challenge"
    );
}

/// The app asks for its history as the connection opens, before it has
/// signed in: with strfry's challenge out, the question waits for the
/// AUTH and is answered after it, not refused (the refusal sent the app
/// to a plain REQ, which strfry caps at its newest 500 events).
#[tokio::test]
async fn a_question_before_the_auth_is_answered_after_it() {
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, "").await;
    let keys = Keys::generate();
    let me = keys.public_key().to_hex();
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));

    send(&mut ws, json!(["NEG-OPEN", "history", {"kinds": [1059], "#p": [me]}, "61"])).await;
    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    // Nothing yet: neither an answer nor strfry hearing of it.
    let early = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(early.is_err(), "{early:?}");
    assert!(fake.verbs_with("history").is_empty() && fake.verbs_with("dm").is_empty());

    let ev = auth_event(&keys, "strfry-challenge", "wss://relay.example.org");
    send(&mut ws, json!(["AUTH", ev])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", ev["id"], true, ""]));
    assert_eq!(recv(&mut ws).await, json!(["NEG-MSG", "history", "61"]));
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "dm"]));
    // strfry got the AUTH first, then the questions as they were sent.
    assert_eq!(fake.order(), ["AUTH", "NEG-OPEN history", "REQ dm"]);
    let m = shared.metrics.line();
    assert!(m.contains("refused_auth_required=0") && m.contains("auth_waited=1"), "{m}");

    // The same AUTH again: its challenge has signed in once.
    send(&mut ws, json!(["AUTH", ev])).await;
    let again = recv(&mut ws).await;
    assert_eq!(again[2], false, "{again}");
    assert_eq!(fake.saw("AUTH"), 1);
}

/// Everything the client sends while a question waits keeps its place
/// behind it: a later REQ of the same id replaces the held one at strfry,
/// as it would have without the wait; only the AUTH goes ahead.
#[tokio::test]
async fn the_frames_behind_a_held_question_keep_their_order() {
    let (fake, up) = Fake::start(true).await;
    let (addr, _) = guard(up, "").await;
    let keys = Keys::generate();
    let me = keys.public_key().to_hex();
    let mut ws = connect(addr, &[]).await;
    recv(&mut ws).await;
    let note = serde_json::to_value(EventBuilder::new(Kind::Metadata, "{}").finalize(&keys).unwrap()).unwrap();
    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    send(&mut ws, json!(["EVENT", note])).await;
    send(&mut ws, json!(["REQ", "dm", {"kinds": [0], "authors": [me]}])).await;
    send(&mut ws, json!(["REQ", "pub", {"kinds": [0]}])).await;
    send(&mut ws, json!(["CLOSE", "pub"])).await;
    let ev = auth_event(&keys, "strfry-challenge", "wss://relay.example.org");
    send(&mut ws, json!(["AUTH", ev])).await;
    assert_eq!(recv(&mut ws).await[0], "OK");
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "dm"]));
    assert_eq!(recv(&mut ws).await, json!(["OK", note["id"], true, ""]));
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "dm"]));
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "pub"]));
    // The CLOSE has no answer: wait until strfry has it.
    for _ in 0..40 {
        if fake.order().len() == 6 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        fake.order(),
        ["AUTH", "REQ dm", &format!("EVENT {}", note["id"].as_str().unwrap()), "REQ dm", "REQ pub", "CLOSE pub"]
    );
}

/// A client that does not answer the challenge: its question is refused
/// after `auth_wait_ms`, as before, and the next one at once.
#[tokio::test]
async fn a_question_without_an_auth_is_refused_after_the_wait() {
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, "[limits]\nauth_wait_ms = 400\n").await;
    let me = Keys::generate().public_key().to_hex();
    let mut ws = connect(addr, &[]).await;
    recv(&mut ws).await;
    let t = std::time::Instant::now();
    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    let a = recv(&mut ws).await;
    assert_eq!(a[0], "CLOSED");
    assert!(a[2].as_str().unwrap().starts_with("auth-required:"), "{a}");
    assert!(t.elapsed() >= Duration::from_millis(350), "{:?}", t.elapsed());
    // The connection waited once: the next question is answered at once.
    let t = std::time::Instant::now();
    send(&mut ws, json!(["NEG-OPEN", "n", {"kinds": [1059], "#p": [me]}, "61"])).await;
    let a = recv(&mut ws).await;
    assert_eq!(a[0], "NEG-ERR");
    assert!(a[2].as_str().unwrap().starts_with("auth-required:"), "{a}");
    assert!(t.elapsed() < Duration::from_millis(300), "{:?}", t.elapsed());
    assert!(fake.verbs_with("dm").is_empty() && fake.verbs_with("n").is_empty());
    assert!(shared.metrics.line().contains("auth_wait_expired=1"), "{}", shared.metrics.line());
}

/// At most MAX_HELD frames wait: one more ends the wait at once, and the
/// held question is refused as without it.
#[tokio::test]
async fn a_client_that_sends_too_much_ends_the_wait() {
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, "").await;
    let me = Keys::generate().public_key().to_hex();
    let mut ws = connect(addr, &[]).await;
    recv(&mut ws).await;
    let t = std::time::Instant::now();
    send(&mut ws, json!(["REQ", "dm", {"kinds": [1059], "#p": [me]}])).await;
    // The question and 31 more fit; the 33rd frame does not.
    for i in 0..proxy::MAX_HELD {
        send(&mut ws, json!(["REQ", format!("p{i}"), {"kinds": [0]}])).await;
    }
    let a = recv(&mut ws).await;
    assert_eq!(a[0], "CLOSED");
    assert!(a[2].as_str().unwrap().starts_with("auth-required:"), "{a}");
    for i in 0..proxy::MAX_HELD {
        assert_eq!(recv(&mut ws).await, json!(["EOSE", format!("p{i}")]));
    }
    assert!(t.elapsed() < Duration::from_secs(3), "long before auth_wait_ms: {:?}", t.elapsed());
    assert_eq!(fake.saw("REQ"), proxy::MAX_HELD);
    assert!(shared.metrics.line().contains("auth_wait_overflow=1"), "{}", shared.metrics.line());
}

#[tokio::test]
async fn limits_hold() {
    let (_fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, "[limits]\nmax_frame = 4096\nmax_subs = 2\n").await;
    let mut ws = connect(addr, &[]).await;
    recv(&mut ws).await;
    for id in ["a", "b"] {
        send(&mut ws, json!(["REQ", id, {"kinds": [0]}])).await;
        assert_eq!(recv(&mut ws).await[0], "EOSE");
    }
    send(&mut ws, json!(["REQ", "c", {"kinds": [0]}])).await;
    let a = recv(&mut ws).await;
    assert_eq!(a[0], "CLOSED");
    assert!(a[2].as_str().unwrap().starts_with("error:"), "{a}");
    // A binary frame is no nostr message.
    ws.send(Message::binary(b"[\"REQ\",\"x\",{}]".to_vec()))
        .await
        .unwrap();
    assert_eq!(recv(&mut ws).await[0], "NOTICE");
    // A frame over the limit ends the connection.
    let big = json!(["EVENT", {"content": "x".repeat(8192)}]).to_string();
    ws.send(Message::text(big)).await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                _ => continue,
            }
        }
    })
    .await;
    assert!(end.is_ok(), "the connection ends");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        shared.metrics.line().contains("too_big=1"),
        "{}",
        shared.metrics.line()
    );
}

#[tokio::test]
async fn no_strfry_no_connection() {
    // A port nobody listens on.
    let free = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (addr, shared) = guard(free, "").await;
    let mut ws = connect(addr, &[]).await;
    let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap();
    assert!(
        matches!(m, None | Some(Ok(Message::Close(_))) | Some(Err(_))),
        "{m:?}"
    );
    assert!(shared.metrics.line().contains("upstream_down=1"));
}

/// The app's way: nostr-sdk with the key as its authenticator, the app key
/// in the query, a subscription to its gift wraps before it signed in.
/// nostr-sdk's relay gives no challenge (as a strfry without auth), so
/// vguard gives its own; nostr-sdk signs in and asks again by itself.
#[tokio::test]
async fn the_client_of_the_app_gets_its_wraps_and_no_one_elses() {
    let relay = LocalRelay::builder().build();
    relay.run().await.unwrap();
    let url = relay.url().await;
    let up: SocketAddr = url
        .as_str_without_trailing_slash()
        .trim_start_matches("ws://")
        .parse()
        .unwrap();
    let (addr, shared) = guard(up, "[limits]\nchallenge_wait_ms = 200\n").await;

    let me = Keys::generate();
    let other = Keys::generate();
    let sender = Keys::generate();
    let wrap_to = |to: &Keys, text: &str| {
        EventBuilder::new(Kind::GiftWrap, text)
            .tag(Tag::public_key(to.public_key()))
            .finalize(&sender)
            .unwrap()
    };
    // One to me and one to someone else, already on the relay.
    relay.add_event(wrap_to(&me, "old to me")).await.unwrap();
    relay
        .add_event(wrap_to(&other, "old to other"))
        .await
        .unwrap();

    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(me.clone()))
        .build();
    let guarded = format!("ws://{addr}/?key=appkey");
    client.add_relay(guarded.as_str()).await.unwrap();
    client.connect().await;
    let mut notes = client.notifications();
    client
        .subscribe(Filter::new().kind(Kind::GiftWrap).pubkey(me.public_key()))
        .await
        .unwrap();

    // A new one to me, and one to the other, sent past vguard.
    let direct = Client::default();
    direct.add_relay(url.as_str()).await.unwrap();
    direct.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    direct.send_event(&wrap_to(&me, "new to me")).await.unwrap();
    direct
        .send_event(&wrap_to(&other, "new to other"))
        .await
        .unwrap();

    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(n) = notes.next().await {
            if let ClientNotification::Event { event, .. } = n {
                got.push(event.content.clone());
                if got.len() == 2 {
                    break;
                }
            }
        }
    })
    .await;
    got.sort();
    assert_eq!(got, ["new to me", "old to me"], "{}", shared.metrics.line());

    // The same client asking for the other's wraps is refused.
    let theirs = client
        .fetch_events(
            Filter::new()
                .kind(Kind::GiftWrap)
                .pubkey(other.public_key()),
        )
        .timeout(Duration::from_secs(3))
        .await;
    assert!(
        theirs.as_ref().map(|e| e.is_empty()).unwrap_or(true),
        "{theirs:?}"
    );
    let m = shared.metrics.line();
    assert!(m.contains("auth_ok=1"), "{m}");
    assert!(m.contains("challenges_own=1"), "{m}");
    client.disconnect().await;
    direct.disconnect().await;
}

#[tokio::test]
async fn a_denied_key_is_refused_at_the_relay_and_the_file_is_read_again() {
    let dir = std::env::temp_dir().join(format!("vguard-denied-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("denied-keys.txt");
    let bad = Keys::generate();
    let good = Keys::generate();
    std::fs::write(&file, format!("{}\n", bad.public_key().to_hex())).unwrap();
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, &format!("denied_keys_file = \"{}\"", file.display())).await;
    assert_eq!(shared.denied.len(), 1, "read at the start");
    let mut ws = connect(addr, &[("x-real-ip", "198.51.100.9")]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));

    // AUTH of the denied key: refused here, strfry never hears of it.
    let ev = auth_event(&bad, "strfry-challenge", "wss://relay.example.org");
    send(&mut ws, json!(["AUTH", ev])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", ev["id"], false, "restricted: key denied"]));
    assert_eq!(fake.saw("AUTH"), 0);
    // Its profile: refused; another's goes on to strfry.
    let profile = serde_json::to_value(EventBuilder::new(Kind::Metadata, "{}").finalize(&bad).unwrap()).unwrap();
    send(&mut ws, json!(["EVENT", profile])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", profile["id"], false, "blocked: key denied"]));
    let theirs = serde_json::to_value(EventBuilder::new(Kind::Metadata, "{}").finalize(&good).unwrap()).unwrap();
    send(&mut ws, json!(["EVENT", theirs])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", theirs["id"], true, ""]));
    assert_eq!(fake.saw("EVENT"), 1);
    // Its events asked by author: empty, without strfry.
    send(&mut ws, json!(["REQ", "p", {"kinds": [0], "authors": [bad.public_key().to_hex()]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "p"]));
    assert!(fake.verbs_with("p").is_empty());

    // Lifted: the file without it, looked at again; its events pass.
    std::fs::write(&file, "").unwrap();
    assert_eq!(shared.denied.refresh(), veydan_denied::Refreshed::Loaded(0));
    let again = serde_json::to_value(EventBuilder::new(Kind::Metadata, "{\"name\":\"x\"}").finalize(&bad).unwrap()).unwrap();
    send(&mut ws, json!(["EVENT", again])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", again["id"], true, ""]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// An event of a group, as the app signs it: kind 9 with the `h` of the group.
fn group_event(keys: &Keys, group: &str) -> Value {
    let ev = EventBuilder::new(Kind::from(9u16), "sealed").tags([Tag::parse(["h", group]).unwrap()]).finalize(keys).unwrap();
    serde_json::to_value(&ev).unwrap()
}

#[tokio::test]
async fn a_closed_group_is_neither_given_nor_taken_and_the_file_is_read_again() {
    let dir = std::env::temp_dir().join(format!("vguard-groups-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("denied-groups.txt");
    let (bad, good) = ("9f".repeat(32), "0a".repeat(32));
    std::fs::write(&file, format!("# closed by vcloud\n{bad}\n")).unwrap();
    let (fake, up) = Fake::start(true).await;
    let member = Keys::generate();
    let (theirs, ours) = (group_event(&member, &bad), group_event(&member, &good));
    *fake.served.lock().unwrap() = vec![theirs.clone(), ours.clone()];
    let (addr, shared) = guard(up, &format!("denied_groups_file = \"{}\"", file.display())).await;
    assert_eq!(shared.denied_groups.len(), 1, "read at the start");
    let mut ws = connect(addr, &[("x-real-ip", "198.51.100.9")]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));

    // Of the closed group alone: empty, without strfry.
    send(&mut ws, json!(["REQ", "g", {"kinds": [9], "#h": [bad]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "g"]));
    assert!(fake.verbs_with("g").is_empty());
    // With the open one: strfry is asked for the open one alone, and what it
    // sends of the closed one does not come through.
    send(&mut ws, json!(["REQ", "both", {"kinds": [9], "#h": [bad, good]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EVENT", "both", ours]));
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "both"]));
    let asked = fake.frames.lock().unwrap().iter().find(|v| v[1] == "both").cloned().unwrap();
    assert_eq!(asked[2]["#h"], json!([good]));
    // An event of it, by a member: refused here; of the open one: stored.
    send(&mut ws, json!(["EVENT", theirs])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", theirs["id"], false, "blocked: group denied"]));
    send(&mut ws, json!(["EVENT", ours])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", ours["id"], true, ""]));
    assert_eq!(fake.saw("EVENT"), 1);

    // Opened again: the file without it, looked at again; its events pass.
    std::fs::write(&file, "").unwrap();
    assert_eq!(shared.denied_groups.refresh(), veydan_denied::Refreshed::Loaded(0));
    send(&mut ws, json!(["EVENT", theirs])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", theirs["id"], true, ""]));
    send(&mut ws, json!(["REQ", "again", {"kinds": [9], "#h": [bad]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EVENT", "again", theirs]));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Access modes (spec/vguard.md, "Access modes") ----

/// A folder of the files of `[access]`: a key of the invites and the
/// members given.
fn access_dir(name: &str, members: &[String]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vguard-access-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("access.key"), [42u8; 32]).unwrap();
    std::fs::write(dir.join("members.txt"), members.iter().map(|m| format!("{m}\n")).collect::<String>()).unwrap();
    dir
}

/// The `[access]` of a test, with a short wait for the AUTH before it.
fn access_toml(mode: &str, dir: &std::path::Path, admins: &[String]) -> String {
    let d = dir.display();
    let admins = admins.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(", ");
    format!(
        "[limits]\nauth_wait_ms = 300\nchallenge_wait_ms = 200\n[access]\nmode = \"{mode}\"\nmembers_file = \"{d}/members.txt\"\n\
         admins = [{admins}]\ninvites_file = \"{d}/invites.json\"\nsecret_file = \"{d}/access.key\"\n\
         listen_http = \"127.0.0.1:1\"\npublic_url = \"https://relay.example.org\"\n"
    )
}

/// Signs in over strfry's challenge; true when vguard said OK.
async fn sign_in(ws: &mut Ws, keys: &Keys) -> Value {
    let ev = auth_event(keys, "strfry-challenge", "wss://relay.example.org");
    send(ws, json!(["AUTH", ev])).await;
    recv(ws).await
}

fn event_json(keys: &Keys, kind: u16, p: &[String], content: &str) -> Value {
    let tags = p.iter().map(|k| Tag::parse(["p", k.as_str()]).unwrap());
    serde_json::to_value(EventBuilder::new(Kind::from(kind), content).tags(tags).finalize(keys).unwrap()).unwrap()
}

/// `["OK", id, false, <prefix>…]`.
fn ok_refused(v: &Value, prefix: &str) -> bool {
    v[0] == "OK" && v[2] == false && v[3].as_str().unwrap_or_default().starts_with(prefix)
}

#[tokio::test]
async fn team_mode_admits_members_and_nobody_else() {
    let (member, guest) = (Keys::generate(), Keys::generate());
    let dir = access_dir("team", &[member.public_key().to_hex()]);
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, &access_toml("team", &dir, &[])).await;
    assert_eq!(shared.access.members.len(), 1, "read at the start");

    // Anonymous: a public question waits for the AUTH, then is refused.
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    send(&mut ws, json!(["REQ", "anon", {"kinds": [0]}])).await;
    let a = recv(&mut ws).await;
    assert_eq!(a, json!(["CLOSED", "anon", "auth-required: this server is for its members"]));
    // A guest: signed in, admitted to nothing.
    let ok = sign_in(&mut ws, &guest).await;
    assert_eq!(ok[2], true, "{ok}");
    send(&mut ws, json!(["REQ", "guest", {"kinds": [0]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["CLOSED", "guest", "restricted: not a member of this server; ask its admin for an invite"]));
    send(&mut ws, json!(["NEG-OPEN", "gneg", {"kinds": [0]}, "61"])).await;
    assert_eq!(recv(&mut ws).await[0], "NEG-ERR");
    let ev = event_json(&guest, 1, &[], "hi");
    send(&mut ws, json!(["EVENT", ev])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", ev["id"], false, "restricted: not a member of this server"]));
    assert!(fake.verbs_with("anon").is_empty() && fake.verbs_with("guest").is_empty() && fake.verbs_with("gneg").is_empty());
    assert_eq!(fake.saw("EVENT"), 0);

    // A member reads and writes as on an open server.
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    assert_eq!(sign_in(&mut ws, &member).await[2], true);
    send(&mut ws, json!(["REQ", "member", {"kinds": [0]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "member"]));
    let ev = event_json(&member, 1, &[], "hello team");
    send(&mut ws, json!(["EVENT", ev])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", ev["id"], true, ""]));
    // The rules of the filters still hold for a member.
    send(&mut ws, json!(["REQ", "wraps", {"kinds": [1059]}])).await;
    assert!(recv(&mut ws).await[2].as_str().unwrap().starts_with("restricted: gift wraps"));
    let m = shared.metrics.line();
    assert!(m.contains("access_auth_required=1") && m.contains("access_restricted=3"), "{m}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn channel_mode_reads_free_and_gates_writes() {
    let (author, guest, stranger) = (Keys::generate(), Keys::generate(), Keys::generate());
    let dir = access_dir("channel", &[]);
    let (fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, &access_toml("channel", &dir, &[author.public_key().to_bech32().unwrap()])).await;
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));

    // Anonymous: a public question goes to strfry at once.
    send(&mut ws, json!(["REQ", "anon", {"kinds": [0, 1]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "anon"]));
    // Its EVENT waits for the AUTH, then auth-required.
    let ev = event_json(&guest, 0, &[], "{}");
    send(&mut ws, json!(["EVENT", ev])).await;
    assert!(ok_refused(&recv(&mut ws).await, "auth-required:"));

    assert_eq!(sign_in(&mut ws, &guest).await[2], true);
    let ev = event_json(&guest, 1, &[], "a note");
    send(&mut ws, json!(["EVENT", ev])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", ev["id"], false, "restricted: on this server only its authors write"]));
    let own = event_json(&guest, 0, &[], "{\"name\":\"g\"}");
    send(&mut ws, json!(["EVENT", own])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", own["id"], true, ""]));
    let theirs = event_json(&stranger, 0, &[], "{}");
    send(&mut ws, json!(["EVENT", theirs])).await;
    assert!(ok_refused(&recv(&mut ws).await, "restricted: a guest writes its own"));
    let to_author = event_json(&stranger, 1059, &[author.public_key().to_hex()], "sealed");
    send(&mut ws, json!(["EVENT", to_author])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", to_author["id"], true, ""]));
    let to_stranger = event_json(&stranger, 1059, &[stranger.public_key().to_hex()], "sealed");
    send(&mut ws, json!(["EVENT", to_stranger])).await;
    assert!(ok_refused(&recv(&mut ws).await, "restricted:"));

    // 30 a minute: 2 taken, 28 more, then the 31st is slowed down.
    for i in 0..28 {
        let e = event_json(&guest, 0, &[], &format!("{{\"n\":{i}}}"));
        send(&mut ws, json!(["EVENT", e])).await;
        assert_eq!(recv(&mut ws).await[2], true, "event {i}");
    }
    let e = event_json(&guest, 0, &[], "{\"n\":31}");
    send(&mut ws, json!(["EVENT", e])).await;
    assert_eq!(recv(&mut ws).await, json!(["OK", e["id"], false, "rate-limited: slow down"]));
    assert_eq!(fake.saw("EVENT"), 30);
    let m = shared.metrics.line();
    assert!(m.contains("guest_events=30") && m.contains("guest_rate_limited=1"), "{m}");

    // The author writes anything, without a limit.
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    assert_eq!(sign_in(&mut ws, &author).await[2], true);
    for i in 0..40 {
        let e = event_json(&author, 1, &[], &format!("post {i}"));
        send(&mut ws, json!(["EVENT", e])).await;
        assert_eq!(recv(&mut ws).await[2], true, "post {i}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_guest_wrap_reaches_authors_only() {
    let (author, admin, guest, other) = (Keys::generate(), Keys::generate(), Keys::generate(), Keys::generate());
    let hex = |k: &Keys| k.public_key().to_hex();
    let dir = access_dir("wraps", &[hex(&author)]);
    let (fake, up) = Fake::start(true).await;
    let (addr, _shared) = guard(up, &access_toml("channel", &dir, &[hex(&admin)])).await;
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    assert_eq!(sign_in(&mut ws, &guest).await[2], true);
    // A wrap is signed by a key of its own: the signer does not matter, the
    // receivers do.
    let wrapper = Keys::generate();
    for (p, passes) in [
        (vec![hex(&author)], true),
        (vec![hex(&author), hex(&admin)], true),
        (vec![hex(&author), hex(&other)], false),
        (vec![hex(&other)], false),
        (vec![hex(&guest)], false),
        (vec![], false),
    ] {
        let e = event_json(&wrapper, 1059, &p, "sealed");
        send(&mut ws, json!(["EVENT", e])).await;
        let a = recv(&mut ws).await;
        assert_eq!(a[2], passes, "{p:?}: {a}");
        if !passes {
            assert_eq!(a[3], "restricted: a guest writes to the authors of this server only");
        }
    }
    assert_eq!(fake.saw("EVENT"), 2);
    // Its own wraps it reads: what a community sends it.
    send(&mut ws, json!(["REQ", "mine", {"kinds": [1059], "#p": [hex(&guest)]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "mine"]));

    // An author writes a wrap to a guest.
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    assert_eq!(sign_in(&mut ws, &author).await[2], true);
    let e = event_json(&wrapper, 1059, &[hex(&guest)], "welcome");
    send(&mut ws, json!(["EVENT", e])).await;
    assert_eq!(recv(&mut ws).await[2], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_members_file_is_read_again_on_change() {
    let late = Keys::generate();
    let dir = access_dir("reread", &[]);
    let (_fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, &access_toml("team", &dir, &[])).await;
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    assert_eq!(sign_in(&mut ws, &late).await[2], true);
    send(&mut ws, json!(["REQ", "a", {"kinds": [0]}])).await;
    assert!(recv(&mut ws).await[2].as_str().unwrap().starts_with("restricted:"));

    // `vguard access members add` writes the file; the guard looks again
    // (every minute, or at once on SIGHUP): the same connection is in.
    std::fs::write(dir.join("members.txt"), format!("# the team\n{}\n", late.public_key().to_hex())).unwrap();
    shared.refresh_lists();
    assert_eq!(shared.access.members.len(), 1);
    send(&mut ws, json!(["REQ", "b", {"kinds": [0]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "b"]));
    // Taken off: out again.
    std::fs::write(dir.join("members.txt"), "").unwrap();
    assert_eq!(shared.access.refresh(), veydan_denied::Refreshed::Loaded(0));
    send(&mut ws, json!(["REQ", "c", {"kinds": [0]}])).await;
    assert!(recv(&mut ws).await[2].as_str().unwrap().starts_with("restricted:"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- The access API ----

const PUBLIC: &str = "https://relay.example.org";
const API: &str = "/.well-known/veydan-access/v1";

async fn api_up(shared: Arc<Shared>) -> SocketAddr {
    let api = vguard::api::Api::new(shared).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(vguard::api::serve(listener, api));
    addr
}

/// One request of HTTP/1.1: the status and the body as JSON (Null when
/// there is none).
async fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, String)], body: &[u8]) -> (u16, Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: relay.example.org\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text[9..12].parse().unwrap();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

/// `Authorization: Nostr …` of NIP-98 for `method path` with `body`.
fn nip98(keys: &Keys, method: &str, path: &str, body: &[u8]) -> (&'static str, String) {
    use base64::Engine as _;
    let url = format!("{PUBLIC}{path}");
    let mut tags = vec![Tag::parse(["u", url.as_str()]).unwrap(), Tag::parse(["method", method]).unwrap()];
    if !body.is_empty() {
        tags.push(Tag::parse(["payload", vguard::nip98::sha256_hex(body).as_str()]).unwrap());
    }
    // Two requests alike in one second would be one event, and a replay.
    tags.push(Tag::parse(["nonce", Keys::generate().public_key().to_hex().as_str()]).unwrap());
    let ev = EventBuilder::new(Kind::HttpAuth, "").tags(tags).finalize(keys).unwrap();
    ("Authorization", format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&ev).unwrap())))
}

async fn join(addr: SocketAddr, keys: &Keys, code: &str, ip: &str) -> (u16, Value) {
    let body = json!({"invite": code}).to_string();
    let path = format!("{API}/join");
    http(addr, "POST", &path, &[nip98(keys, "POST", &path, body.as_bytes()), ("X-Real-IP", ip.into())], body.as_bytes()).await
}

#[tokio::test]
async fn join_with_an_invite_then_read_as_member() {
    let (anna, boris) = (Keys::generate(), Keys::generate());
    let dir = access_dir("join", &[]);
    let (_fake, up) = Fake::start(true).await;
    let (addr, shared) = guard(up, &access_toml("team", &dir, &[])).await;
    let api = api_up(shared.clone()).await;

    let (status, info) = http(api, "GET", &format!("{API}/info"), &[], b"").await;
    assert_eq!((status, info.clone()), (200, json!({"v": 1, "mode": "team", "invite": true, "join": format!("{API}/join")})));

    // An invite for one, as `vguard access invite` makes it.
    let invites = vguard::invites::Invites::open(&shared.config.access).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let (code, _) = invites.create(1, 7, "Anna", now).unwrap();
    let (status, me) = http(api, "GET", &format!("{API}/me"), &[nip98(&anna, "GET", &format!("{API}/me"), b"")], b"").await;
    assert_eq!((status, me), (200, json!({"member": false, "admin": false, "mode": "team"})));

    assert_eq!(join(api, &anna, &code, "198.51.100.1").await, (200, json!({"member": true})));
    let file = std::fs::read_to_string(dir.join("members.txt")).unwrap();
    assert!(file.contains(&anna.public_key().to_hex()), "{file}");
    // The same key now reads, at once.
    let mut ws = connect(addr, &[]).await;
    assert_eq!(recv(&mut ws).await, json!(["AUTH", "strfry-challenge"]));
    assert_eq!(sign_in(&mut ws, &anna).await[2], true);
    send(&mut ws, json!(["REQ", "in", {"kinds": [0]}])).await;
    assert_eq!(recv(&mut ws).await, json!(["EOSE", "in"]));
    let (_, me) = http(api, "GET", &format!("{API}/me"), &[nip98(&anna, "GET", &format!("{API}/me"), b"")], b"").await;
    assert_eq!(me["member"], true);

    // A one-use code, used: invite_used; a bad mac: invite_invalid.
    assert_eq!(join(api, &boris, &code, "198.51.100.2").await, (401, json!({"error": "invite_used"})));
    let mut bad = code.clone();
    let last = bad.pop().unwrap();
    bad.push(if last == '0' { '1' } else { '0' });
    assert_eq!(join(api, &boris, &bad, "198.51.100.2").await, (401, json!({"error": "invite_invalid"})));
    // Expired: an invite whose time is past, laid by hand.
    let id = "00112233445566ff";
    std::fs::write(dir.join("invites.json"), json!([{"id": id, "label": "", "uses_left": 3, "expires_at": now - 1, "created_at": now - 100}]).to_string()).unwrap();
    assert_eq!(join(api, &boris, &invites.code_of(id), "198.51.100.2").await, (401, json!({"error": "invite_expired"})));
    // No signature, a replayed one, one for another address: auth_invalid.
    let body = json!({"invite": code}).to_string();
    let path = format!("{API}/join");
    assert_eq!(http(api, "POST", &path, &[], body.as_bytes()).await, (401, json!({"error": "auth_invalid"})));
    let h = nip98(&boris, "POST", &path, body.as_bytes());
    assert_eq!(http(api, "POST", &path, std::slice::from_ref(&h), body.as_bytes()).await.0, 401, "invite_used, the event used up");
    assert_eq!(http(api, "POST", &path, &[h], body.as_bytes()).await, (401, json!({"error": "auth_invalid"})), "a replay");
    let elsewhere = nip98(&boris, "POST", &format!("{API}/me"), body.as_bytes());
    assert_eq!(http(api, "POST", &path, &[elsewhere], body.as_bytes()).await, (401, json!({"error": "auth_invalid"})));
    // Ten joins a minute from one address.
    for _ in 0..10 {
        assert_eq!(join(api, &boris, &bad, "203.0.113.9").await.0, 401);
    }
    assert_eq!(join(api, &boris, &bad, "203.0.113.9").await, (429, json!({"error": "rate_limited"})));
    let m = shared.metrics.line();
    assert!(m.contains("joins=1"), "{m}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Blossom authorization (kind 24242), as the app signs one per upload.
fn blossom(keys: &Keys, expires_in: i64) -> (&'static str, String) {
    use base64::Engine as _;
    let exp = (Timestamp::now().as_secs() as i64 + expires_in).to_string();
    let ev = EventBuilder::new(Kind::from(24242u16), "Upload")
        .tags([Tag::parse(["t", "upload"]).unwrap(), Tag::parse(["expiration", exp.as_str()]).unwrap()])
        .finalize(keys)
        .unwrap();
    ("Authorization", format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&ev).unwrap())))
}

#[tokio::test]
async fn media_access_takes_a_member_upload() {
    let (member, admin, stranger) = (Keys::generate(), Keys::generate(), Keys::generate());
    let dir = access_dir("media", &[member.public_key().to_hex()]);
    let (_fake, up) = Fake::start(true).await;
    let (_addr, shared) = guard(up, &access_toml("team", &dir, &[admin.public_key().to_hex()])).await;
    let api = api_up(shared).await;
    assert_eq!(http(api, "GET", "/_access", &[blossom(&member, 300)], b"").await, (204, Value::Null));
    assert_eq!(http(api, "GET", "/_access", &[blossom(&admin, 300)], b"").await, (204, Value::Null));
    assert_eq!(http(api, "GET", "/_access", &[blossom(&member, 300)], b"").await.0, 204, "used again");
    assert_eq!(http(api, "GET", "/_access", &[blossom(&stranger, 300)], b"").await, (401, Value::Null));
    assert_eq!(http(api, "GET", "/_access", &[blossom(&member, -1)], b"").await, (401, Value::Null), "expired");
    assert_eq!(http(api, "GET", "/_access", &[], b"").await, (401, Value::Null));
    let path = "/_access";
    assert_eq!(http(api, "GET", path, &[nip98(&member, "GET", path, b"")], b"").await.0, 401, "not a Blossom authorization");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn admin_endpoints_need_an_admin_key() {
    let (admin, member, newcomer) = (Keys::generate(), Keys::generate(), Keys::generate());
    let dir = access_dir("admin", &[member.public_key().to_hex()]);
    let (_fake, up) = Fake::start(true).await;
    let (_addr, shared) = guard(up, &access_toml("team", &dir, &[admin.public_key().to_bech32().unwrap()])).await;
    let api = api_up(shared.clone()).await;
    let invites = format!("{API}/invites");
    let members = format!("{API}/members");
    let body = br#"{"uses":3,"days":2,"label":"designers"}"#;

    // Nobody, a member: refused.
    assert_eq!(http(api, "POST", &invites, &[], body).await, (401, json!({"error": "auth_invalid"})));
    assert_eq!(http(api, "POST", &invites, &[nip98(&member, "POST", &invites, body)], body).await, (403, json!({"error": "not_admin"})));
    assert_eq!(http(api, "GET", &invites, &[nip98(&member, "GET", &invites, b"")], b"").await.0, 403);

    // The admin: an invite, the list, the revoke.
    let (status, made) = http(api, "POST", &invites, &[nip98(&admin, "POST", &invites, body)], body).await;
    assert_eq!(status, 200, "{made}");
    assert!(made["code"].as_str().unwrap().starts_with("vi1."));
    let id = made["id"].as_str().unwrap().to_string();
    let (status, list) = http(api, "GET", &invites, &[nip98(&admin, "GET", &invites, b"")], b"").await;
    assert_eq!(status, 200);
    assert_eq!(list[0]["id"], id.as_str());
    assert_eq!((list[0]["uses_left"].clone(), list[0]["label"].clone(), list[0]["expires_at"].clone()), (json!(3), json!("designers"), made["expires_at"].clone()));
    let bad = br#"{"uses":0}"#;
    assert_eq!(http(api, "POST", &invites, &[nip98(&admin, "POST", &invites, bad)], bad).await.0, 400);
    let one = format!("{invites}/{id}");
    assert_eq!(http(api, "DELETE", &one, &[nip98(&admin, "DELETE", &one, b"")], b"").await, (200, json!({"revoked": id})));
    assert_eq!(http(api, "DELETE", &one, &[nip98(&admin, "DELETE", &one, b"")], b"").await, (404, json!({"error": "not_found"})));

    // Members: added by npub, taken off by hex.
    let add = json!({"pubkey": newcomer.public_key().to_bech32().unwrap()}).to_string();
    assert_eq!(http(api, "POST", &members, &[nip98(&member, "POST", &members, add.as_bytes())], add.as_bytes()).await.0, 403);
    let (status, added) = http(api, "POST", &members, &[nip98(&admin, "POST", &members, add.as_bytes())], add.as_bytes()).await;
    assert_eq!((status, added["member"].clone()), (200, json!(true)));
    assert!(shared.access.admits(&newcomer.public_key().to_hex()));
    let off = format!("{members}/{}", member.public_key().to_hex());
    assert_eq!(http(api, "DELETE", &off, &[nip98(&member, "DELETE", &off, b"")], b"").await.0, 403);
    assert_eq!(http(api, "DELETE", &off, &[nip98(&admin, "DELETE", &off, b"")], b"").await.0, 200);
    assert!(!shared.access.admits(&member.public_key().to_hex()));
    let file = std::fs::read_to_string(dir.join("members.txt")).unwrap();
    assert_eq!(file, format!("{}\n", newcomer.public_key().to_hex()));
    let junk = br#"{"pubkey":"npub1nope"}"#;
    assert_eq!(http(api, "POST", &members, &[nip98(&admin, "POST", &members, junk)], junk).await, (400, json!({"error": "bad_key"})));
    let (_, me) = http(api, "GET", &format!("{API}/me"), &[nip98(&admin, "GET", &format!("{API}/me"), b"")], b"").await;
    assert_eq!(me, json!({"member": true, "admin": true, "mode": "team"}));

    // An open server has no API to speak of (it is not bound): the code
    // path answers mode_open.
    let (_a, open) = guard(up, "").await;
    let api = api_up(open).await;
    let (_, info) = http(api, "GET", &format!("{API}/info"), &[], b"").await;
    assert_eq!(info["invite"], false);
    assert_eq!(join(api, &newcomer, "vi1.x.y", "198.51.100.3").await, (403, json!({"error": "mode_open"})));
    assert_eq!(http(api, "POST", &invites, &[nip98(&admin, "POST", &invites, body)], body).await, (403, json!({"error": "mode_open"})));
    let _ = std::fs::remove_dir_all(&dir);
}

/// What the client of the app does in a team: nostr-sdk sends an EVENT
/// before it signed in. With the wait for the AUTH (the default) the event
/// is held until the AUTH and passes; without it (`auth_wait_ms = 0`) it
/// is refused `auth-required` with a challenge, and nostr-sdk signs in and
/// sends it again by itself. A guest gets `restricted` and gives up.
#[tokio::test]
async fn the_client_of_the_app_signs_in_and_sends_again_in_a_team() {
    let member = Keys::generate();
    let guest = Keys::generate();
    for (name, wait) in [("held", 5000), ("resent", 0)] {
        let relay = LocalRelay::builder().build();
        relay.run().await.unwrap();
        let url = relay.url().await;
        let up: SocketAddr = url.as_str_without_trailing_slash().trim_start_matches("ws://").parse().unwrap();
        let dir = access_dir(&format!("sdk-{name}"), &[member.public_key().to_hex()]);
        let toml = access_toml("team", &dir, &[]).replace("auth_wait_ms = 300", &format!("auth_wait_ms = {wait}"));
        let (addr, shared) = guard(up, &toml).await;
        let guarded = format!("ws://{addr}/?key=appkey");

        let client = Client::builder().authenticator(SignerAuthenticator::new(member.clone())).build();
        client.add_relay(guarded.as_str()).await.unwrap();
        client.connect().await;
        let ev = EventBuilder::new(Kind::TextNote, "from a member").finalize(&member).unwrap();
        let out = client.send_event(&ev).await.unwrap();
        assert_eq!((out.success.len(), out.failed.len()), (1, 0), "{name}: {out:?} {}", shared.metrics.line());
        let m = shared.metrics.line();
        if wait == 0 {
            assert!(m.contains("access_auth_required=1"), "{name}: refused once, then sent again: {m}");
        } else {
            assert!(m.contains("access_auth_required=0") && m.contains("auth_waited=1"), "{name}: held until the AUTH: {m}");
        }
        client.disconnect().await;

        let client = Client::builder().authenticator(SignerAuthenticator::new(guest.clone())).build();
        client.add_relay(guarded.as_str()).await.unwrap();
        client.connect().await;
        let ev = EventBuilder::new(Kind::TextNote, "from a guest").finalize(&guest).unwrap();
        let out = client.send_event(&ev).await;
        let failed = match out {
            Ok(o) => o.failed.into_values().collect::<Vec<_>>().join(" "),
            Err(e) => e.to_string(),
        };
        assert!(failed.contains("restricted: not a member of this server"), "{name}: {failed}");
        client.disconnect().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
