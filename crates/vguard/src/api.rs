//! The access API (spec/vguard.md, "The access API", "Media access"): HTTP
//! on `listen_http`, bound only when the mode is not open; nginx puts it
//! under the relay's host as it is.
//!
//! - `GET  /.well-known/veydan-access/v1/info`: the mode, and whether a join is possible.
//! - `POST …/v1/join` `{"invite": "vi1.…"}`, NIP-98: the signer becomes a member.
//! - `GET  …/v1/me`, NIP-98: member, admin, mode.
//! - admins (NIP-98 by a key of `admins`): `POST …/v1/members`, `DELETE
//!   …/v1/members/<key>`, `POST …/v1/invites`, `GET …/v1/invites`,
//!   `DELETE …/v1/invites/<id>`.
//! - `GET /_access`: nginx's `auth_request` of the media host, by the
//!   Blossom authorization of the upload.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use veydan_denied::KeyList;

use crate::access::{key_hex, Access};
use crate::access_lock;
use crate::invites::{Invites, Redeem};
use crate::metrics::add;
use crate::nip98::{self, AuthError, Nip98};
use crate::proxy::{Shared, REAL_IP_HEADER};

/// Where the API lives under the relay's host.
pub const BASE: &str = "/.well-known/veydan-access/v1";
/// nginx's `auth_request` of the media host.
pub const MEDIA: &str = "/_access";
/// Joins per address per minute.
pub const JOINS_PER_MINUTE: u32 = 10;
const AUTH_PER_MINUTE: u32 = 60;
/// Addresses counted at once; past this many a join waits for room.
const MAX_ADDRESSES: usize = 100_000;
/// The largest body taken.
const MAX_BODY: usize = 16 * 1024;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The joins of each address in the minute that runs.
#[derive(Default)]
struct Joins {
    per_ip: HashMap<IpAddr, (Instant, u32)>,
}

#[derive(Default)]
struct AuthLimits {
    per_ip: HashMap<IpAddr, (Instant, u32)>,
    per_key: HashMap<String, (Instant, u32)>,
}

impl AuthLimits {
    fn allow(&mut self, ip: IpAddr, key: &str, at: Instant) -> bool {
        fn take<K: std::hash::Hash + Eq + Clone>(map: &mut HashMap<K, (Instant, u32)>, key: K, at: Instant) -> bool {
            let minute = Duration::from_secs(60);
            if map.len() >= MAX_ADDRESSES {
                map.retain(|_, (since, _)| at.saturating_duration_since(*since) < minute);
                if map.len() >= MAX_ADDRESSES && !map.contains_key(&key) {
                    return false;
                }
            }
            let (since, count) = map.entry(key).or_insert((at, 0));
            if at.saturating_duration_since(*since) >= minute {
                *since = at;
                *count = 0;
            }
            *count += 1;
            *count <= AUTH_PER_MINUTE
        }
        // Both budgets apply. A stream of new keys from one address cannot
        // fill the replay set or all key counters.
        take(&mut self.per_ip, ip, at) && take(&mut self.per_key, key.to_owned(), at)
    }
}

impl Joins {
    fn allow(&mut self, ip: IpAddr, at: Instant) -> bool {
        const MINUTE: Duration = Duration::from_secs(60);
        if self.per_ip.len() >= MAX_ADDRESSES {
            self.per_ip.retain(|_, (since, _)| at.saturating_duration_since(*since) < MINUTE);
            if self.per_ip.len() >= MAX_ADDRESSES {
                return false;
            }
        }
        let (since, n) = self.per_ip.entry(ip).or_insert((at, 0));
        if at.saturating_duration_since(*since) >= MINUTE {
            *since = at;
            *n = 0;
        }
        *n += 1;
        *n <= JOINS_PER_MINUTE
    }
}

pub struct Api {
    shared: Arc<Shared>,
    /// None on an open server: nothing to invite to.
    invites: Option<Invites>,
    nip98: Nip98,
    joins: Mutex<Joins>,
    auth_limits: Mutex<AuthLimits>,
}

fn error(status: StatusCode, word: &str) -> Response {
    (status, Json(json!({ "error": word }))).into_response()
}

fn ok(v: Value) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// A refusal of the API: its status and its word.
struct Refuse(StatusCode, &'static str);

impl IntoResponse for Refuse {
    fn into_response(self) -> Response {
        error(self.0, self.1)
    }
}

fn auth_failed(e: AuthError) -> Refuse {
    match e {
        AuthError::Busy => Refuse(StatusCode::TOO_MANY_REQUESTS, "busy"),
        _ => Refuse(StatusCode::UNAUTHORIZED, "auth_invalid"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinBody {
    invite: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberBody {
    pubkey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteBody {
    #[serde(default = "one")]
    uses: u32,
    #[serde(default = "seven")]
    days: u32,
    #[serde(default)]
    label: String,
}

fn one() -> u32 {
    1
}
fn seven() -> u32 {
    7
}

/// A body of JSON, or an empty one as `{}`.
fn body_of<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Refuse> {
    let body = if body.is_empty() { b"{}".as_slice() } else { body };
    serde_json::from_slice(body).map_err(|_| Refuse(StatusCode::BAD_REQUEST, "bad_request"))
}

impl Api {
    /// The API of `shared`'s access mode: on a server that is not open the
    /// key of the invites must read.
    pub fn new(shared: Arc<Shared>) -> Result<Arc<Self>, String> {
        let c = &shared.config.access;
        let invites = if shared.access.is_open() { None } else { Some(Invites::open(c)?) };
        let nip98 = Nip98::new(c.public_url.as_deref().unwrap_or_default());
        Ok(Arc::new(Self { shared, invites, nip98, joins: Mutex::default(), auth_limits: Mutex::default() }))
    }

    fn access(&self) -> &Access {
        &self.shared.access
    }

    /// The signer of a request of the API, or the answer that refuses it.
    fn verified(&self, headers: &HeaderMap, method: &Method, uri: &Uri, body: &[u8]) -> Result<nip98::Verified, Refuse> {
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or(uri.path());
        self.nip98
            .verify(header(headers, "authorization"), method.as_str(), path, body, now())
            .map_err(auth_failed)
    }

    fn limited(&self, peer: SocketAddr, headers: &HeaderMap, key: &str) -> Result<(), Refuse> {
        let ip = real_ip(peer, headers);
        if self.auth_limits.lock().unwrap_or_else(|e| e.into_inner()).allow(ip, key, Instant::now()) {
            Ok(())
        } else {
            Err(Refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited"))
        }
    }

    /// An admin's request: the mode is not open, the signer is an admin.
    fn admin(&self, peer: SocketAddr, headers: &HeaderMap, method: &Method, uri: &Uri, body: &[u8]) -> Result<&Invites, Refuse> {
        let Some(invites) = self.invites.as_ref().filter(|_| !self.access().is_open()) else {
            return Err(Refuse(StatusCode::FORBIDDEN, "mode_open"));
        };
        let verified = self.verified(headers, method, uri, body)?;
        self.limited(peer, headers, &verified.pubkey)?;
        if !self.access().is_admin(&verified.pubkey) {
            return Err(Refuse(StatusCode::FORBIDDEN, "not_admin"));
        }
        self.nip98.remember(verified.event).map_err(auth_failed)?;
        Ok(invites)
    }
}

fn real_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    match header(headers, REAL_IP_HEADER).and_then(|h| h.trim().parse::<IpAddr>().ok()) {
        Some(ip) if peer.ip().is_loopback() => ip,
        _ => peer.ip(),
    }
}

/// The router of the API.
pub fn router(api: Arc<Api>) -> Router {
    Router::new()
        .route(&format!("{BASE}/info"), get(info))
        .route(&format!("{BASE}/join"), post(join))
        .route(&format!("{BASE}/me"), get(me))
        .route(&format!("{BASE}/members"), post(add_member))
        .route(&format!("{BASE}/members/{{key}}"), delete(remove_member))
        .route(&format!("{BASE}/invites"), post(create_invite).get(list_invites))
        .route(&format!("{BASE}/invites/{{id}}"), delete(revoke_invite))
        .route(MEDIA, get(media))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(api)
}

/// Serves the API on `listener` until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, api: Arc<Api>) -> std::io::Result<()> {
    axum::serve(listener, router(api).into_make_service_with_connect_info::<SocketAddr>()).await
}

async fn info(State(api): State<Arc<Api>>) -> Response {
    let mode = api.access().mode;
    ok(json!({
        "v": 1,
        "mode": mode.as_str(),
        "invite": !api.access().is_open(),
        "join": format!("{BASE}/join"),
    }))
}

async fn join(
    State(api): State<Arc<Api>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let m = &api.shared.metrics;
    let refused = |r: Response| {
        add(&m.join_refused);
        r
    };
    let Some(invites) = api.invites.as_ref().filter(|_| !api.access().is_open()) else {
        return refused(error(StatusCode::FORBIDDEN, "mode_open"));
    };
    // The address nginx saw, from nginx on this machine; else the socket's.
    let ip = real_ip(peer, &headers);
    if !api.joins.lock().unwrap_or_else(|e| e.into_inner()).allow(ip, Instant::now()) {
        return refused(error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    let verified = match api.verified(&headers, &method, &uri, &body) {
        Ok(k) => k,
        Err(r) => return refused(r.into_response()),
    };
    let asked: JoinBody = match body_of(&body) {
        Ok(b) => b,
        Err(r) => return refused(r.into_response()),
    };
    let Some(path) = api.access().members.path() else {
        return refused(error(StatusCode::INTERNAL_SERVER_ERROR, "internal"));
    };
    let _file = match access_lock::lock(path) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!("access: the access lock is not available: {e}");
            return refused(error(StatusCode::INTERNAL_SERVER_ERROR, "internal"));
        }
    };
    let current_members = KeyList::from_file(path);
    // A member already: nothing to use up.
    if api.access().is_admin(&verified.pubkey) || current_members.contains(&verified.pubkey) {
        if let Err(e) = api.nip98.remember(verified.event) { return refused(auth_failed(e).into_response()); }
        return ok(json!({ "member": true }));
    }
    let id = match invites.redeem_with_locked(&asked.invite, now(), || api.nip98.remember(verified.event)) {
        Ok(id) => id,
        Err(Redeem::Io(why)) => {
            tracing::warn!("access: the invites do not read or write: {why}");
            return refused(error(StatusCode::INTERNAL_SERVER_ERROR, "internal"));
        }
        Err(Redeem::Auth(e)) => return refused(auth_failed(e).into_response()),
        Err(r) => return refused(error(StatusCode::UNAUTHORIZED, r.word())),
    };
    if let Err(e) = current_members.append(&verified.pubkey) {
        tracing::warn!("access: the members file is not written: {e}");
        return refused(error(StatusCode::INTERNAL_SERVER_ERROR, "internal"));
    }
    api.access().members.refresh();
    add(&m.joins);
    tracing::info!("access: a member joined by the invite {id}");
    ok(json!({ "member": true }))
}

async fn me(State(api): State<Arc<Api>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let verified = match api.verified(&headers, &method, &uri, b"") {
        Ok(k) => k,
        Err(r) => return r.into_response(),
    };
    if let Err(r) = api.limited(peer, &headers, &verified.pubkey) { return r.into_response(); }
    if let Err(e) = api.nip98.remember(verified.event) { return auth_failed(e).into_response(); }
    let a = api.access();
    ok(json!({
        "member": a.is_open() || a.admits(&verified.pubkey),
        "admin": a.is_admin(&verified.pubkey),
        "mode": a.mode.as_str(),
    }))
}

async fn add_member(State(api): State<Arc<Api>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = api.admin(peer, &headers, &method, &uri, &body) {
        return r.into_response();
    }
    let asked: MemberBody = match body_of(&body) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    let Some(key) = key_hex(&asked.pubkey) else {
        return error(StatusCode::BAD_REQUEST, "bad_key");
    };
    let members = &api.access().members;
    let Some(path) = members.path() else { return error(StatusCode::INTERNAL_SERVER_ERROR, "internal"); };
    let _file = match access_lock::lock(path) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!("access: the access lock is not available: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    };
    let current_members = KeyList::from_file(path);
    if !current_members.contains(&key) {
        if let Err(e) = current_members.append(&key) {
            tracing::warn!("access: the members file is not written: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    }
    members.refresh();
    ok(json!({ "pubkey": key, "member": true }))
}

async fn remove_member(
    State(api): State<Arc<Api>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = api.admin(peer, &headers, &method, &uri, b"") {
        return r.into_response();
    }
    let Some(key) = key_hex(&key) else {
        return error(StatusCode::BAD_REQUEST, "bad_key");
    };
    let members = &api.access().members;
    let Some(path) = members.path() else { return error(StatusCode::INTERNAL_SERVER_ERROR, "internal"); };
    let _file = match access_lock::lock(path) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!("access: the access lock is not available: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    };
    let current_members = KeyList::from_file(path);
    if current_members.contains(&key) {
        let rest: Vec<String> = current_members.items().into_iter().filter(|k| *k != key).collect();
        if let Err(e) = current_members.write_all(rest.iter().map(String::as_str)) {
            tracing::warn!("access: the members file is not written: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    }
    members.refresh();
    ok(json!({ "pubkey": key, "member": false }))
}

async fn create_invite(State(api): State<Arc<Api>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let invites = match api.admin(peer, &headers, &method, &uri, &body) {
        Ok(i) => i,
        Err(r) => return r.into_response(),
    };
    let asked: InviteBody = match body_of(&body) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    if let Err(why) = crate::invites::check_new(asked.uses, asked.days, &asked.label) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "bad_request", "why": why }))).into_response();
    }
    match invites.create(asked.uses, asked.days, &asked.label, now()) {
        Ok((code, i)) => ok(json!({ "code": code, "id": i.id, "expires_at": i.expires_at })),
        Err(why) => {
            tracing::warn!("access: the invites are not written: {why}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

async fn list_invites(State(api): State<Arc<Api>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let invites = match api.admin(peer, &headers, &method, &uri, b"") {
        Ok(i) => i,
        Err(r) => return r.into_response(),
    };
    match invites.list() {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(why) => {
            tracing::warn!("access: the invites do not read: {why}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

async fn revoke_invite(
    State(api): State<Arc<Api>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let invites = match api.admin(peer, &headers, &method, &uri, b"") {
        Ok(i) => i,
        Err(r) => return r.into_response(),
    };
    match invites.revoke(&id, now()) {
        Ok(true) => ok(json!({ "revoked": id })),
        Ok(false) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(why) => {
            tracing::warn!("access: the invites are not written: {why}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

/// nginx's `auth_request` of the media host: 204 for an upload signed by a
/// member or an admin (the Blossom authorization the app sends anyway),
/// 401 for anything else. No body either way.
async fn media(State(api): State<Arc<Api>>, headers: HeaderMap) -> StatusCode {
    match nip98::blossom_signer(header(&headers, "authorization"), now()) {
        Ok(key) if api.access().is_open() || api.access().admits(&key) => StatusCode::NO_CONTENT,
        _ => StatusCode::UNAUTHORIZED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_joins_a_minute_from_one_address() {
        let mut j = Joins::default();
        let (a, b): (IpAddr, IpAddr) = ("198.51.100.1".parse().unwrap(), "198.51.100.2".parse().unwrap());
        let t = Instant::now();
        for _ in 0..JOINS_PER_MINUTE {
            assert!(j.allow(a, t));
        }
        assert!(!j.allow(a, t));
        assert!(j.allow(b, t), "another address");
        assert!(j.allow(a, t + Duration::from_secs(60)), "the next minute");
    }

    #[test]
    fn fresh_keys_from_one_address_have_a_shared_limit() {
        let mut limits = AuthLimits::default();
        let at = Instant::now();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        for i in 0..AUTH_PER_MINUTE {
            assert!(limits.allow(a, &format!("key-{i}"), at));
        }
        assert!(!limits.allow(a, "one-more-key", at));
        assert!(limits.allow(b, "one-more-key", at));
        assert!(limits.allow(a, "one-more-key", at + Duration::from_secs(60)));
        let mut by_key = AuthLimits::default();
        for i in 0..AUTH_PER_MINUTE {
            let ip: IpAddr = format!("198.51.100.{}", i + 1).parse().unwrap();
            assert!(by_key.allow(ip, "same-key", at));
        }
        assert!(!by_key.allow("203.0.113.2".parse().unwrap(), "same-key", at));
    }
}
