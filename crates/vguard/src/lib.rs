//! VGuard: the read policy of a Veydan relay.
//!
//! A WebSocket proxy between nginx and strfry. Every frame goes on as it
//! is, but a question (REQ, COUNT, NEG-OPEN) that could read gift wraps
//! of another key, or the events of groups it does not name, is answered
//! here with CLOSED or NEG-ERR and never reaches strfry. The rules are in
//! spec/vguard.md; the key a connection signed in with is NIP-42's.
//!
//! Since 0.7.0 a server has an access mode (`access`): open, team or
//! channel, with members, admins and invites, and an HTTP API for them
//! (`api`, `nip98`, `invites`).

pub mod access;
pub mod api;
pub mod auth;
pub mod config;
pub mod invites;
pub mod message;
pub mod metrics;
pub mod nip98;
pub mod policy;
pub mod proxy;
pub mod session;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
