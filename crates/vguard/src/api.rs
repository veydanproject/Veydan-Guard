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

use crate::access::{key_hex, Access};
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
        Ok(Arc::new(Self { shared, invites, nip98, joins: Mutex::default() }))
    }

    fn access(&self) -> &Access {
        &self.shared.access
    }

    /// The signer of a request of the API, or the answer that refuses it.
    fn signer(&self, headers: &HeaderMap, method: &Method, uri: &Uri, body: &[u8]) -> Result<String, Refuse> {
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or(uri.path());
        self.nip98
            .check(header(headers, "authorization"), method.as_str(), path, body, now())
            .map_err(auth_failed)
    }

    /// An admin's request: the mode is not open, the signer is an admin.
    fn admin(&self, headers: &HeaderMap, method: &Method, uri: &Uri, body: &[u8]) -> Result<&Invites, Refuse> {
        let Some(invites) = self.invites.as_ref().filter(|_| !self.access().is_open()) else {
            return Err(Refuse(StatusCode::FORBIDDEN, "mode_open"));
        };
        let key = self.signer(headers, method, uri, body)?;
        if !self.access().is_admin(&key) {
            return Err(Refuse(StatusCode::FORBIDDEN, "not_admin"));
        }
        Ok(invites)
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
    let ip = match header(&headers, REAL_IP_HEADER).and_then(|h| h.trim().parse::<IpAddr>().ok()) {
        Some(ip) if peer.ip().is_loopback() => ip,
        _ => peer.ip(),
    };
    if !api.joins.lock().unwrap_or_else(|e| e.into_inner()).allow(ip, Instant::now()) {
        return refused(error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    let key = match api.signer(&headers, &method, &uri, &body) {
        Ok(k) => k,
        Err(r) => return refused(r.into_response()),
    };
    let asked: JoinBody = match body_of(&body) {
        Ok(b) => b,
        Err(r) => return refused(r.into_response()),
    };
    // A member already: nothing to use up.
    if api.access().admits(&key) {
        return ok(json!({ "member": true }));
    }
    let id = match invites.redeem(&asked.invite, now()) {
        Ok(id) => id,
        Err(Redeem::Io(why)) => {
            tracing::warn!("access: the invites do not read or write: {why}");
            return refused(error(StatusCode::INTERNAL_SERVER_ERROR, "internal"));
        }
        Err(r) => return refused(error(StatusCode::UNAUTHORIZED, r.word())),
    };
    if let Err(e) = api.access().members.append(&key) {
        tracing::warn!("access: the members file is not written: {e}");
        return refused(error(StatusCode::INTERNAL_SERVER_ERROR, "internal"));
    }
    add(&m.joins);
    tracing::info!("access: a member joined by the invite {id}");
    ok(json!({ "member": true }))
}

async fn me(State(api): State<Arc<Api>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let key = match api.signer(&headers, &method, &uri, b"") {
        Ok(k) => k,
        Err(r) => return r.into_response(),
    };
    let a = api.access();
    ok(json!({
        "member": a.is_open() || a.admits(&key),
        "admin": a.is_admin(&key),
        "mode": a.mode.as_str(),
    }))
}

async fn add_member(State(api): State<Arc<Api>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = api.admin(&headers, &method, &uri, &body) {
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
    members.refresh();
    if !members.contains(&key) {
        if let Err(e) = members.append(&key) {
            tracing::warn!("access: the members file is not written: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    }
    ok(json!({ "pubkey": key, "member": true }))
}

async fn remove_member(
    State(api): State<Arc<Api>>,
    Path(key): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = api.admin(&headers, &method, &uri, b"") {
        return r.into_response();
    }
    let Some(key) = key_hex(&key) else {
        return error(StatusCode::BAD_REQUEST, "bad_key");
    };
    let members = &api.access().members;
    members.refresh();
    if members.contains(&key) {
        let rest: Vec<String> = members.items().into_iter().filter(|k| *k != key).collect();
        if let Err(e) = members.write_all(rest.iter().map(String::as_str)) {
            tracing::warn!("access: the members file is not written: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    }
    ok(json!({ "pubkey": key, "member": false }))
}

async fn create_invite(State(api): State<Arc<Api>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let invites = match api.admin(&headers, &method, &uri, &body) {
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

async fn list_invites(State(api): State<Arc<Api>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let invites = match api.admin(&headers, &method, &uri, b"") {
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
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let invites = match api.admin(&headers, &method, &uri, b"") {
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
}
