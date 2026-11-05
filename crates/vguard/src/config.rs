//! Configuration: one TOML file, `/opt/vguard/etc/vguard.toml` on a server
//! of the kit (services/server/templates/vguard.toml).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::access::{key_hex, Mode};

/// Where the config is looked for when `--config` is not given.
pub const DEFAULT_PATH: &str = "/opt/vguard/etc/vguard.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where nginx connects: `127.0.0.1:7778`.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// strfry: `127.0.0.1:7777`.
    #[serde(default = "default_upstream")]
    pub upstream: SocketAddr,
    /// The names the relay answers under (strfry's `serviceUrl` and the
    /// aliases): the `relay` tag of an AUTH must name one of them, or a
    /// relay elsewhere could pass on our challenge and sign in as its own
    /// user here.
    pub relay_hosts: Vec<String>,
    /// The keys denied on every server of the network, one a line, laid by
    /// the agent of vcloud (spec/vguard.md, "Denied keys"): read again when
    /// its mtime changes, at most once a minute. Not given, or no file:
    /// nobody is denied.
    #[serde(default)]
    pub denied_keys_file: Option<PathBuf>,
    /// The groups closed on our relays, one id a line, laid by the agent of
    /// vcloud beside the keys (spec/vguard.md, "Denied groups"); read again
    /// as the keys are. Not given, or no file: no group is closed.
    #[serde(default)]
    pub denied_groups_file: Option<PathBuf>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub log: LogConfig,
    /// Who may use the relay (spec/vguard.md, "Access modes"). Without the
    /// section: `open`, as before 0.7.0.
    #[serde(default)]
    pub access: AccessConfig,
}

/// The guest kinds of a channel by default: the profile, the relay lists,
/// gift wraps (to the authors), and the two kinds of joining a community.
pub const DEFAULT_GUEST_KINDS: [u16; 6] = [0, 10002, 10050, 1059, 1390, 21390];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AccessConfig {
    /// `open`, `team` or `channel`.
    pub mode: String,
    /// The members, one key a line (64 hex, `#` comments): the shape of
    /// `denied-keys.txt`. Read again on a change of its mtime and on SIGHUP.
    pub members_file: Option<PathBuf>,
    /// Always admitted; may call the admin endpoints. npub or 64 hex as
    /// written; 64 lowercase hex once loaded.
    pub admins: Vec<String>,
    /// The invites, JSON (spec/vguard.md, "Members, admins and invites").
    pub invites_file: Option<PathBuf>,
    /// At least 32 bytes of random: the HMAC key of the invite codes.
    pub secret_file: Option<PathBuf>,
    /// Where the access API listens; bound only when the mode is not open.
    pub listen_http: Option<SocketAddr>,
    /// The address NIP-98 requests are signed for, without a trailing
    /// slash: `https://relay.example.org`.
    pub public_url: Option<String>,
    /// What a guest of a channel may write; `[]`: nothing (a read-only
    /// server).
    pub guest_kinds: Vec<u16>,
    /// The events a guest of a channel may write per minute, per connection.
    pub guest_events_per_minute: u32,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            mode: "open".into(),
            members_file: None,
            admins: Vec::new(),
            invites_file: None,
            secret_file: None,
            listen_http: None,
            public_url: None,
            guest_kinds: DEFAULT_GUEST_KINDS.to_vec(),
            guest_events_per_minute: 30,
        }
    }
}

impl AccessConfig {
    /// The mode; `open` for a word that is none (refused by the check).
    pub fn mode(&self) -> Mode {
        Mode::parse(&self.mode).unwrap_or(Mode::Open)
    }

    /// Every problem of the section, added to `problems`.
    fn check(&self, problems: &mut Vec<String>) {
        let Some(mode) = Mode::parse(&self.mode) else {
            problems.push(format!("access.mode: {:?} is not open, team or channel", self.mode));
            return;
        };
        for (name, file) in [
            ("members_file", &self.members_file),
            ("invites_file", &self.invites_file),
            ("secret_file", &self.secret_file),
        ] {
            match file {
                Some(path) if !path.is_absolute() => {
                    problems.push(format!("access.{name}: {} is not an absolute path", path.display()))
                }
                None if mode != Mode::Open => problems.push(format!("access.{name}: needed when the mode is {}", mode.as_str())),
                _ => {}
            }
        }
        for a in &self.admins {
            if key_hex(a).is_none() {
                problems.push(format!("access.admins: {a:?} is not an npub or a key of 64 hex"));
            }
        }
        if self.listen_http.is_none() && mode != Mode::Open {
            problems.push(format!("access.listen_http: needed when the mode is {}", mode.as_str()));
        }
        match &self.public_url {
            Some(u) => {
                if let Err(why) = check_public_url(u) {
                    problems.push(format!("access.public_url: {u:?} {why}"));
                }
            }
            None if mode != Mode::Open => problems.push(format!("access.public_url: needed when the mode is {}", mode.as_str())),
            None => {}
        }
        if self.guest_events_per_minute == 0 {
            problems.push("access.guest_events_per_minute: must be above 0 (guest_kinds = [] makes a read-only server)".into());
        }
    }
}

/// `https://host[:port][/path]`, or `http://` to this machine (tests, a
/// server behind its own proxy); no trailing slash, no query.
fn check_public_url(u: &str) -> Result<(), &'static str> {
    let url = url::Url::parse(u).map_err(|_| "is not a URL")?;
    if u.ends_with('/') {
        return Err("ends with a slash; the paths are added to it");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("has a query or a fragment");
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if url.host_str().is_some_and(|h| h == "localhost" || h == "[::1]" || h.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())) => Ok(()),
        _ => Err("is not https (http only to this machine)"),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// The largest frame either way, bytes: strfry's `maxWebsocketPayloadSize`.
    pub max_frame: usize,
    /// Open subscriptions (REQ and NEG-OPEN) of one connection: strfry's
    /// `maxSubsPerConnection`.
    pub max_subs: usize,
    /// Filters in one REQ or COUNT: strfry's `maxReqFilterSize`.
    pub max_filters: usize,
    /// Connections at once.
    pub max_connections: usize,
    /// The WebSocket handshake of nginx, seconds.
    pub handshake_secs: u64,
    /// The connection to strfry, seconds.
    pub connect_secs: u64,
    /// No frame either way for this long closes the connection, seconds:
    /// nginx's `proxy_read_timeout`.
    pub idle_secs: u64,
    /// How far the `created_at` of an AUTH may be from now, seconds. Wide
    /// (3 days) because the clock of many a phone is off by hours, and a
    /// phone that cannot sign in gets no message at all. The window opens
    /// no replay: an AUTH is bound to a challenge this connection was
    /// given, which signs in once, and to the name of this relay.
    pub auth_skew_secs: u64,
    /// How long a question that needs a signed-in key waits for strfry's
    /// challenge before vguard sends one of its own, milliseconds.
    pub challenge_wait_ms: u64,
    /// How long a question that needs a signed-in key waits for the AUTH
    /// once a challenge is out, milliseconds. The app asks for its history
    /// as the connection opens, before it has signed in, and `auth-required`
    /// sends it to a fallback that gets only the newest events. 0: no
    /// wait, such a question is refused at once.
    pub auth_wait_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame: 262_144,
            max_subs: 200,
            max_filters: 200,
            max_connections: 20_000,
            handshake_secs: 10,
            connect_secs: 5,
            idle_secs: 300,
            auth_skew_secs: 259_200,
            challenge_wait_ms: 2_000,
            auth_wait_ms: 5_000,
        }
    }
}

impl Limits {
    pub fn handshake(&self) -> Duration {
        Duration::from_secs(self.handshake_secs)
    }
    pub fn connect(&self) -> Duration {
        Duration::from_secs(self.connect_secs)
    }
    pub fn idle(&self) -> Duration {
        Duration::from_secs(self.idle_secs)
    }
    pub fn challenge_wait(&self) -> Duration {
        Duration::from_millis(self.challenge_wait_ms)
    }
    pub fn auth_wait(&self) -> Duration {
        Duration::from_millis(self.auth_wait_ms)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// `error`, `warn`, `info`, `debug`, `trace`.
    pub level: String,
    /// How often the counters go to the log, seconds; 0: never.
    pub metrics_secs: u64,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            metrics_secs: 300,
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:7778".parse().expect("a socket address")
}

fn default_upstream() -> SocketAddr {
    "127.0.0.1:7777".parse().expect("a socket address")
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        config.check()?;
        // Checked above: every admin reads as a key.
        config.access.admins = config.access.admins.iter().filter_map(|a| key_hex(a)).collect();
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Every problem at once.
    fn check(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        for (name, file) in [("denied_keys_file", &self.denied_keys_file), ("denied_groups_file", &self.denied_groups_file)] {
            if let Some(path) = file {
                if !path.is_absolute() {
                    problems.push(format!("{name}: {} is not an absolute path", path.display()));
                }
            }
        }
        if self.relay_hosts.is_empty() {
            problems.push("relay_hosts: no name of the relay; nobody could sign in".to_string());
        }
        for h in &self.relay_hosts {
            if h.is_empty() || h.contains(['/', ':', ' ']) {
                problems.push(format!("relay_hosts: {h:?} is not a host name"));
            }
        }
        let l = &self.limits;
        for (name, v) in [
            ("max_frame", l.max_frame as u64),
            ("max_subs", l.max_subs as u64),
            ("max_filters", l.max_filters as u64),
            ("max_connections", l.max_connections as u64),
            ("handshake_secs", l.handshake_secs),
            ("connect_secs", l.connect_secs),
            ("idle_secs", l.idle_secs),
            ("auth_skew_secs", l.auth_skew_secs),
        ] {
            if v == 0 {
                problems.push(format!("limits.{name}: must be above 0"));
            }
        }
        if self.log.level.parse::<tracing::Level>().is_err() {
            problems.push(format!(
                "log.level: {:?} is not error, warn, info, debug or trace",
                self.log.level
            ));
        }
        if self.listen == self.upstream {
            problems.push("listen and upstream are the same address".into());
        }
        self.access.check(&mut problems);
        if let Some(http) = self.access.listen_http {
            if http == self.listen || http == self.upstream {
                problems.push("access.listen_http is the address of listen or upstream".into());
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Whether `host` is a name of this relay (ASCII, any case).
    pub fn is_relay_host(&self, host: &str) -> bool {
        self.relay_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_least_config_takes_the_defaults() {
        let c = Config::parse("relay_hosts = [\"relay.example.org\"]\n").unwrap();
        assert_eq!(c.listen.to_string(), "127.0.0.1:7778");
        assert_eq!(c.upstream.to_string(), "127.0.0.1:7777");
        assert_eq!(c.limits.max_frame, 262_144);
        assert_eq!(c.limits.max_subs, 200);
        assert_eq!(c.limits.auth_skew_secs, 3 * 24 * 3600, "a phone's clock may be off by days");
        assert_eq!(c.limits.auth_wait_ms, 5_000);
        assert!(c.is_relay_host("RELAY.example.org"));
        assert_eq!(c.denied_keys_file, None, "nobody denied unless a file is named");
        let c = Config::parse("relay_hosts = [\"r\"]\ndenied_keys_file = \"/opt/vguard/data/denied-keys.txt\"\n").unwrap();
        assert_eq!(c.denied_keys_file.as_deref(), Some(Path::new("/opt/vguard/data/denied-keys.txt")));
        assert!(Config::parse("relay_hosts = [\"r\"]\ndenied_keys_file = \"denied.txt\"\n").unwrap_err().contains("absolute"));
        assert_eq!(c.denied_groups_file, None, "no group closed unless a file is named");
        let g = Config::parse("relay_hosts = [\"r\"]\ndenied_groups_file = \"/opt/vguard/data/denied-groups.txt\"\n").unwrap();
        assert_eq!(g.denied_groups_file.as_deref(), Some(Path::new("/opt/vguard/data/denied-groups.txt")));
        assert!(Config::parse("relay_hosts = [\"r\"]\ndenied_groups_file = \"g.txt\"\n").unwrap_err().contains("denied_groups_file"));
        assert!(!c.is_relay_host("relay.example.org.evil"));
    }

    #[test]
    fn every_problem_is_told() {
        let e =
            Config::parse("relay_hosts = []\n[limits]\nmax_subs = 0\n[log]\nlevel = \"loud\"\n")
                .unwrap_err();
        assert!(e.contains("relay_hosts"), "{e}");
        assert!(e.contains("max_subs"), "{e}");
        assert!(e.contains("log.level"), "{e}");
        assert!(
            Config::parse("relay_hosts = [\"a\"]\nnope = 1\n").is_err(),
            "an unknown key is an error"
        );
        assert!(
            Config::parse("relay_hosts = [\"wss://a\"]\n").is_err(),
            "a host, not a URL"
        );
    }

    #[test]
    fn the_access_section() {
        // A config of 0.6.0, without it: open, as before.
        let c = Config::parse("relay_hosts = [\"r\"]\n").unwrap();
        assert_eq!(c.access.mode(), Mode::Open);
        assert_eq!(c.access.guest_kinds, DEFAULT_GUEST_KINDS);
        assert_eq!(c.access.guest_events_per_minute, 30);
        let hex = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap().public_key();
        let npub = nostr::prelude::ToBech32::to_bech32(&hex).unwrap();
        let full = format!(
            "relay_hosts = [\"r\"]\n[access]\nmode = \"team\"\nmembers_file = \"/opt/vguard/data/members.txt\"\n\
             admins = [\"{npub}\", \"{}\"]\ninvites_file = \"/opt/vguard/data/invites.json\"\n\
             secret_file = \"/opt/vguard/etc/access.key\"\nlisten_http = \"127.0.0.1:7779\"\n\
             public_url = \"https://relay.example.org\"\n",
            hex.to_hex().to_ascii_uppercase()
        );
        let c = Config::parse(&full).unwrap();
        assert_eq!(c.access.mode(), Mode::Team);
        assert_eq!(c.access.admins, [hex.to_hex(), hex.to_hex()], "both as hex");
        // A team without its files: each one named.
        let e = Config::parse("relay_hosts = [\"r\"]\n[access]\nmode = \"channel\"\n").unwrap_err();
        for name in ["members_file", "invites_file", "secret_file", "listen_http", "public_url"] {
            assert!(e.contains(name), "{name}: {e}");
        }
        let e = Config::parse("relay_hosts = [\"r\"]\n[access]\nmode = \"closed\"\n").unwrap_err();
        assert!(e.contains("open, team or channel"), "{e}");
        let bad = |line: &str| Config::parse(&full.replace("mode = \"team\"\n", &format!("mode = \"team\"\n{line}\n")));
        assert!(Config::parse(&full.replace("https://relay.example.org", "http://relay.example.org")).unwrap_err().contains("public_url"));
        assert!(Config::parse(&full.replace("https://relay.example.org", "http://127.0.0.1:9")).is_ok(), "http to this machine");
        assert!(Config::parse(&full.replace("https://relay.example.org", "https://relay.example.org/")).unwrap_err().contains("slash"));
        assert!(Config::parse(&full.replace("/opt/vguard/data/members.txt", "members.txt")).unwrap_err().contains("absolute"));
        assert!(Config::parse(&full.replace(&npub, "npub1nope")).unwrap_err().contains("access.admins"));
        assert!(Config::parse(&full.replace("127.0.0.1:7779", "127.0.0.1:7778")).unwrap_err().contains("listen_http"));
        assert!(bad("guest_events_per_minute = 0").unwrap_err().contains("guest_events_per_minute"));
        assert!(bad("nope = 1").is_err(), "an unknown key is an error");
        assert!(bad("guest_kinds = []").is_ok(), "a read-only channel");
    }
}
