//! The sockets: nginx on one side, strfry on the other, a session between.
//!
//! nginx names a peer of the mesh (the key of the peers: router and sync
//! of the other relays, VPush) by the header `X-Veydan-Role: peer`, set
//! by nginx itself and never passed on from a client. vguard believes the
//! header only on a connection from this machine.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use crate::access::Access;
use crate::config::Config;
use crate::metrics::{add, sub, Metrics};
use crate::session::{is_auth, Out, Pending, Session};
use veydan_denied::{DeniedGroups, DeniedKeys, Refreshed, RELOAD_EVERY};

/// The header nginx names a peer with.
pub const ROLE_HEADER: &str = "x-veydan-role";
/// The header nginx names the client's address with: strfry's realIpHeader.
pub const REAL_IP_HEADER: &str = "x-real-ip";
/// What strfry may send in one frame: it is ours, on this machine; an
/// answer of negentropy may be larger than what a client may send.
const UPSTREAM_MAX_MESSAGE: usize = 16 << 20;
/// Frames waiting for the client.
const TO_CLIENT_QUEUE: usize = 256;
/// Frames of a client held while a question waits for its AUTH, the
/// question among them: the app sends a handful before it signs in, and
/// a client that sends more ends the wait (its questions are refused as
/// without it) rather than the memory of the relay.
pub const MAX_HELD: usize = 32;
/// The bytes of those frames, for the same reason: an EVENT may be as
/// large as `max_frame`.
pub const MAX_HELD_BYTES: usize = 1 << 20;

/// Who is on the other side of nginx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An app: the read policy.
    Client,
    /// Another relay of the mesh or VPush, by the key of the peers: all.
    Peer,
}

/// The role of a connection from `peer` that carries `header`: a peer only
/// from this machine (nginx), and only with the word `peer`.
pub fn role_of(peer: IpAddr, header: Option<&str>) -> Role {
    if peer.is_loopback() && header.is_some_and(|h| h.trim().eq_ignore_ascii_case("peer")) {
        Role::Peer
    } else {
        Role::Client
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Shared {
    pub config: Arc<Config>,
    pub metrics: Arc<Metrics>,
    /// The keys denied on every server, from `denied_keys_file`.
    pub denied: Arc<DeniedKeys>,
    /// The groups closed on our relays, from `denied_groups_file`.
    pub denied_groups: Arc<DeniedGroups>,
    /// The access mode, with the members of `members_file`.
    pub access: Arc<Access>,
}

impl Shared {
    pub fn new(config: Config) -> Arc<Self> {
        let denied = match &config.denied_keys_file {
            Some(path) => DeniedKeys::from_file(path),
            None => DeniedKeys::none(),
        };
        let denied_groups = match &config.denied_groups_file {
            Some(path) => DeniedGroups::groups_from_file(path),
            None => DeniedGroups::none(),
        };
        let access = Access::from_config(&config.access);
        Arc::new(Self {
            config: Arc::new(config),
            metrics: Arc::new(Metrics::default()),
            denied: Arc::new(denied),
            denied_groups: Arc::new(denied_groups),
            access: Arc::new(access),
        })
    }

    /// Every list looked at once more, now: what SIGHUP does.
    pub fn refresh_lists(&self) {
        for (list, what) in self.lists() {
            if let Some(path) = list.path() {
                log_refresh(what, &path.display().to_string(), list.refresh());
            }
        }
    }

    /// The lists read from files, and what each is called in the journal.
    fn lists(&self) -> [(&Arc<DeniedKeys>, &'static str); 3] {
        [(&self.denied, "denied keys"), (&self.denied_groups, "closed groups"), (&self.access.members, "members")]
    }
}

/// Looks at the file of the denied keys every minute while the proxy runs
/// (`denied_keys_file`; without one there is nothing to look at). What
/// changed goes to the journal, the keys never.
pub async fn watch_denied(shared: Arc<Shared>) {
    watch_list(shared.denied.clone(), "denied keys").await
}

/// The same for the closed groups (`denied_groups_file`): their count to
/// the journal, never an id.
pub async fn watch_denied_groups(shared: Arc<Shared>) {
    watch_list(shared.denied_groups.clone(), "closed groups").await
}

/// The same for the members of a team or a channel (`[access]
/// members_file`): their count to the journal, never a key.
pub async fn watch_members(shared: Arc<Shared>) {
    watch_list(shared.access.members.clone(), "members").await
}

fn log_refresh(what: &str, path: &str, r: Refreshed) {
    match r {
        Refreshed::Same => {}
        Refreshed::Loaded(n) => tracing::info!("{what}: {n} from {path}"),
        Refreshed::Missing => tracing::info!("{what}: no {path}, none"),
        Refreshed::Refused(why) => tracing::warn!("{what}: {path} does not read ({why}); the list before stays"),
    }
}

async fn watch_list(list: Arc<DeniedKeys>, what: &str) {
    let Some(path) = list.path().map(|p| p.display().to_string()) else { return };
    tracing::info!("{what}: {} from {path}", list.len());
    let mut tick = tokio::time::interval(RELOAD_EVERY);
    tick.tick().await;
    loop {
        tick.tick().await;
        log_refresh(what, &path, list.refresh());
    }
}

/// Takes connections on `listener` until the task is dropped.
pub async fn run(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let m = shared.metrics.clone();
            if m.open.load(Ordering::Relaxed) as usize >= shared.config.limits.max_connections {
                add(&m.refused_connections);
                return;
            }
            add(&m.open);
            add(&m.connections);
            if let Err(e) = connection(stream, peer, &shared).await {
                tracing::debug!(error = %e, "connection");
            }
            sub(&m.open);
        });
    }
}

/// The counters to the log every `every`.
pub async fn report(shared: Arc<Shared>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    loop {
        tick.tick().await;
        tracing::info!(target: "vguard::metrics", "{}", shared.metrics.line());
    }
}

fn ws_config(max: usize) -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max))
}

type Ws = WebSocketStream<TcpStream>;

async fn connection(stream: TcpStream, peer: SocketAddr, shared: &Shared) -> anyhow::Result<()> {
    let limits = &shared.config.limits;
    let mut role_header: Option<String> = None;
    let mut real_ip: Option<String> = None;
    // The type of the error is tungstenite's.
    #[allow(clippy::result_large_err)]
    let callback = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let h = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        role_header = h(ROLE_HEADER);
        real_ip = h(REAL_IP_HEADER);
        Ok(resp)
    };
    let client = tokio::time::timeout(
        limits.handshake(),
        tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            callback,
            Some(ws_config(limits.max_frame)),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out"))??;
    let role = role_of(peer.ip(), role_header.as_deref());
    // The client's address as nginx saw it, for strfry's limits and log;
    // from anyone else, the address itself.
    let real_ip = match real_ip {
        Some(ip) if peer.ip().is_loopback() => ip,
        _ => peer.ip().to_string(),
    };

    let upstream = match open_upstream(shared, &real_ip).await {
        Ok(u) => u,
        Err(e) => {
            add(&shared.metrics.upstream_down);
            tracing::warn!(error = %e, "strfry is not reached");
            let mut client = client;
            let _ = client
                .close(Some(CloseFrame {
                    code: CloseCode::Error,
                    reason: "the relay is not reachable".into(),
                }))
                .await;
            return Ok(());
        }
    };
    if role == Role::Peer {
        add(&shared.metrics.peers);
    }
    pump(client, upstream, role, shared).await;
    Ok(())
}

async fn open_upstream(shared: &Shared, real_ip: &str) -> anyhow::Result<Ws> {
    let addr = shared.config.upstream;
    let mut req = format!("ws://{addr}/").into_client_request()?;
    if let Ok(v) = HeaderValue::from_str(real_ip) {
        req.headers_mut().insert(REAL_IP_HEADER, v);
    }
    let connect = async {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let (ws, _) = tokio_tungstenite::client_async_with_config(
            req,
            tcp,
            Some(ws_config(UPSTREAM_MAX_MESSAGE)),
        )
        .await?;
        anyhow::Ok(ws)
    };
    tokio::time::timeout(shared.config.limits.connect(), connect)
        .await
        .map_err(|_| anyhow::anyhow!("connect timed out"))?
}

/// Why a side stopped.
enum End {
    Closed,
    Idle,
    TooBig,
    Error,
}

fn ended(e: &WsError) -> End {
    match e {
        WsError::Capacity(_) => End::TooBig,
        _ => End::Error,
    }
}

async fn pump(client: Ws, upstream: Ws, role: Role, shared: &Shared) {
    let (client_sink, mut client_rx) = client.split();
    let (mut up_sink, mut up_rx) = upstream.split();
    let (to_client, queue) = mpsc::channel::<Message>(TO_CLIENT_QUEUE);
    let writer = tokio::spawn(write_client(client_sink, queue));
    let session = Arc::new(Mutex::new(
        Session::new(shared.config.clone(), shared.metrics.clone(), shared.denied.clone())
            .with_denied_groups(shared.denied_groups.clone())
            .with_access(shared.access.clone()),
    ));
    let (challenged, challenge_rx) = watch::channel(false);
    let idle = shared.config.limits.idle();

    let from_client = client_side(
        &mut client_rx,
        &mut up_sink,
        &to_client,
        role,
        &session,
        challenge_rx,
        shared,
    );
    let from_upstream = upstream_side(&mut up_rx, &to_client, role, &session, &challenged, idle);
    let end = tokio::select! {
        e = from_client => e,
        e = from_upstream => e,
    };
    match end {
        End::Idle => add(&shared.metrics.idle_closed),
        End::TooBig => add(&shared.metrics.too_big),
        End::Closed | End::Error => {}
    }
    let close = match end {
        End::TooBig => Some(CloseFrame {
            code: CloseCode::Size,
            reason: "frame too large".into(),
        }),
        _ => None,
    };
    let _ = to_client.send(Message::Close(close)).await;
    drop(to_client);
    let _ = tokio::time::timeout(Duration::from_secs(2), up_sink.close()).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
}

async fn write_client(mut sink: SplitSink<Ws, Message>, mut queue: mpsc::Receiver<Message>) {
    while let Some(m) = queue.recv().await {
        let last = matches!(m, Message::Close(_));
        if sink.send(m).await.is_err() || last {
            break;
        }
    }
    let _ = sink.close().await;
}

/// The frames of a client held while a question waits for the AUTH
/// ([`Pending::Auth`]): the question first, then everything the client
/// sent after it but its AUTH, so that nothing overtakes it (a later REQ of
/// the same subscription id, a CLOSE of it, an EVENT the client meant to
/// come after).
struct Held {
    frames: Vec<String>,
    bytes: usize,
    until: tokio::time::Instant,
}

impl Held {
    fn new(first: String, wait: Duration) -> Self {
        Self {
            bytes: first.len(),
            frames: vec![first],
            until: tokio::time::Instant::now() + wait,
        }
    }

    /// Whether `text` still fits; when not, the wait ends at once and the
    /// held questions are refused as without it.
    fn fits(&self, text: &str) -> bool {
        self.frames.len() < MAX_HELD && self.bytes + text.len() <= MAX_HELD_BYTES
    }

    fn push(&mut self, text: String) {
        self.bytes += text.len();
        self.frames.push(text);
    }
}

/// What a session answered, sent on: false when a side is gone.
async fn deliver(
    outs: Vec<Out>,
    up: &mut SplitSink<Ws, Message>,
    to_client: &mpsc::Sender<Message>,
) -> bool {
    for out in outs {
        let sent = match out {
            Out::Upstream(t) => up.send(Message::text(t)).await.is_ok(),
            Out::Client(t) => to_client.send(Message::text(t)).await.is_ok(),
        };
        if !sent {
            return false;
        }
    }
    true
}

/// The end of a wait for the AUTH: every held frame is answered now, in
/// the order the client sent them; a question passes if the AUTH signed
/// the connection in, and is refused as `auth-required` if not.
async fn release(
    held: Held,
    up: &mut SplitSink<Ws, Message>,
    to_client: &mpsc::Sender<Message>,
    session: &Mutex<Session>,
) -> bool {
    let outs: Vec<Out> = {
        let mut s = session.lock().unwrap_or_else(|e| e.into_inner());
        s.auth_wait_over();
        held.frames
            .iter()
            .flat_map(|f| s.on_client(f, now(), true).unwrap_or_default())
            .collect()
    };
    deliver(outs, up, to_client).await
}

/// Until `at`, or for ever when there is nothing to wait for.
async fn until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn client_side(
    rx: &mut SplitStream<Ws>,
    up: &mut SplitSink<Ws, Message>,
    to_client: &mpsc::Sender<Message>,
    role: Role,
    session: &Mutex<Session>,
    mut challenged: watch::Receiver<bool>,
    shared: &Shared,
) -> End {
    let idle = shared.config.limits.idle();
    let wait = shared.config.limits.challenge_wait();
    let auth_wait = shared.config.limits.auth_wait();
    let mut held: Option<Held> = None;
    loop {
        // A frame of the client, or the end of the wait for its AUTH. A
        // frame first when both are there: it may be the AUTH itself.
        let next = tokio::select! {
            biased;
            m = tokio::time::timeout(idle, rx.next()) => Some(m),
            () = until(held.as_ref().map(|h| h.until)) => None,
        };
        let msg = match next {
            None => {
                if let Some(h) = held.take() {
                    add(&shared.metrics.auth_wait_expired);
                    if !release(h, up, to_client, session).await {
                        return End::Error;
                    }
                }
                continue;
            }
            Some(Err(_)) => return End::Idle,
            Some(Ok(None)) => return End::Closed,
            Some(Ok(Some(Err(e)))) => return ended(&e),
            Some(Ok(Some(Ok(m)))) => m,
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Binary(b) if role == Role::Peer => {
                if up.send(Message::Binary(b)).await.is_err() {
                    return End::Error;
                }
                continue;
            }
            Message::Binary(_) => {
                // A nostr message is text; strfry would read these too.
                add(&shared.metrics.unreadable);
                let _ = to_client
                    .send(Message::text(crate::message::notice(
                        "invalid: binary frames are not taken",
                    )))
                    .await;
                continue;
            }
            // Answered by the WebSocket itself.
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Close(_) => return End::Closed,
        };
        if role == Role::Peer {
            if up.send(Message::Text(text)).await.is_err() {
                return End::Error;
            }
            continue;
        }

        if let Some(h) = held.as_mut() {
            if is_auth(text.as_str()) {
                // The AUTH goes ahead of what waits for it; then the held
                // frames, whatever its answer: a client refused does not
                // sign in by waiting longer.
                let outs = session
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .on_client(text.as_str(), now(), true)
                    .unwrap_or_default();
                let h = held.take().expect("held");
                add(&shared.metrics.auth_waited);
                if !deliver(outs, up, to_client).await || !release(h, up, to_client, session).await {
                    return End::Error;
                }
            } else if h.fits(text.as_str()) {
                h.push(text.to_string());
            } else {
                let mut h = held.take().expect("held");
                h.frames.push(text.to_string());
                add(&shared.metrics.auth_wait_overflow);
                if !release(h, up, to_client, session).await {
                    return End::Error;
                }
            }
            continue;
        }

        let first = session.lock().unwrap_or_else(|e| e.into_inner()).on_client(
            text.as_str(),
            now(),
            false,
        );
        let outs = match first {
            Ok(outs) => outs,
            Err(Pending::Challenge) => {
                // strfry gives its challenge as the connection opens; a
                // question faster than that waits for it a moment, and
                // without one gets vguard's own. Then it waits for the
                // AUTH as below.
                let _ = tokio::time::timeout(wait, challenged.wait_for(|c| *c)).await;
                let mut s = session.lock().unwrap_or_else(|e| e.into_inner());
                let mut outs: Vec<Out> = s.own_challenge().into_iter().collect();
                match s.on_client(text.as_str(), now(), false) {
                    Ok(more) => outs.extend(more),
                    Err(Pending::Auth) => held = Some(Held::new(text.to_string(), auth_wait)),
                    Err(Pending::Challenge) => {
                        outs.extend(s.on_client(text.as_str(), now(), true).unwrap_or_default())
                    }
                }
                outs
            }
            Err(Pending::Auth) => {
                held = Some(Held::new(text.to_string(), auth_wait));
                continue;
            }
        };
        if !deliver(outs, up, to_client).await {
            return End::Error;
        }
    }
}

async fn upstream_side(
    rx: &mut SplitStream<Ws>,
    to_client: &mpsc::Sender<Message>,
    role: Role,
    session: &Mutex<Session>,
    challenged: &watch::Sender<bool>,
    idle: Duration,
) -> End {
    loop {
        let msg = match tokio::time::timeout(idle, rx.next()).await {
            Err(_) => return End::Idle,
            Ok(None) => return End::Closed,
            Ok(Some(Err(e))) => return ended(&e),
            Ok(Some(Ok(m))) => m,
        };
        let msg = match msg {
            Message::Text(t) if role == Role::Client => {
                let pass = {
                    let mut s = session.lock().unwrap_or_else(|e| e.into_inner());
                    let pass = s.on_upstream(t.as_str()).is_some();
                    if s.has_challenge() {
                        challenged.send_replace(true);
                    }
                    pass
                };
                if !pass {
                    continue;
                }
                Message::Text(t)
            }
            // strfry's ping goes on, so nginx sees the client's socket
            // alive; the pong back to strfry is the WebSocket's own.
            Message::Ping(p) => Message::Ping(p),
            Message::Pong(_) | Message::Frame(_) => continue,
            Message::Close(_) => return End::Closed,
            m => m,
        };
        if to_client.send(msg).await.is_err() {
            return End::Error;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_is_named_by_nginx_on_this_machine_only() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let lo6: IpAddr = "::1".parse().unwrap();
        let far: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(role_of(lo, Some("peer")), Role::Peer);
        assert_eq!(role_of(lo6, Some(" Peer ")), Role::Peer);
        assert_eq!(role_of(far, Some("peer")), Role::Client);
        assert_eq!(role_of(lo, None), Role::Client);
        assert_eq!(role_of(lo, Some("")), Role::Client);
        assert_eq!(role_of(lo, Some("admin")), Role::Client);
    }
}
