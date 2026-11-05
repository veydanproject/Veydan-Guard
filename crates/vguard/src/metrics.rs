//! Counters, written to the log now and then. No addresses, no keys.

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Metrics {
            $(pub $name: AtomicU64,)*
        }

        impl Metrics {
            /// `name=value` pairs, in this order.
            pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
                vec![$((stringify!($name), self.$name.load(Ordering::Relaxed)),)*]
            }
        }
    };
}

counters!(
    open,
    connections,
    peers,
    refused_connections,
    upstream_down,
    questions_passed,
    refused_auth_required,
    refused_restricted,
    refused_invalid,
    refused_too_many,
    auth_ok,
    auth_failed,
    challenges_own,
    unreadable,
    too_big,
    idle_closed,
    denied_auth,
    denied_events,
    denied_answered,
    denied_dropped,
    groups_events,
    groups_answered,
    groups_filtered,
    groups_dropped,
    auth_waited,
    auth_wait_expired,
    auth_wait_overflow,
    access_auth_required,
    access_restricted,
    guest_events,
    guest_rate_limited,
    joins,
    join_refused,
);

pub fn add(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn sub(c: &AtomicU64) {
    c.fetch_sub(1, Ordering::Relaxed);
}

impl Metrics {
    /// One line: `open=3 connections=10 …`.
    pub fn line(&self) -> String {
        self.snapshot()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
