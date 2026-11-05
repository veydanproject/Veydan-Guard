//! `vguard`: the read policy in front of a relay (see the library).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use vguard::config::{self, Config};
use vguard::access::{key_hex, Mode};
use vguard::api;
use vguard::invites::Invites;
use vguard::proxy::{self, Shared};
use veydan_denied::KeyList;

#[derive(Parser)]
#[command(name = "vguard", about = "Veydan relay guard: the read policy in front of strfry", version = vguard::VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct ConfigArg {
    /// Config file.
    #[arg(long, env = "VGUARD_CONFIG", default_value = config::DEFAULT_PATH)]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy.
    Serve(ConfigArg),
    /// Read the config and report every problem in it.
    CheckConfig(ConfigArg),
    /// Ask the running proxy one public question through to strfry: the
    /// health check of the kit.
    Probe {
        #[command(flatten)]
        config: ConfigArg,
        /// Seconds to wait for the answer.
        #[arg(long, default_value_t = 5)]
        wait: u64,
    },
    /// The members and the invites of a team or a channel, on their files
    /// (the running guard reads them again within a minute, or on SIGHUP).
    Access {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        what: AccessCmd,
    },
}

#[derive(Subcommand)]
enum AccessCmd {
    /// A new invite: its code on stdout, one line. `invite list`, `invite
    /// revoke <id>`: the invites.
    Invite(InviteCmd),
    /// The members: `list`, `add <npub|hex>`, `remove <npub|hex>`.
    Members {
        #[command(subcommand)]
        what: MembersCmd,
    },
}

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
struct InviteCmd {
    #[command(subcommand)]
    what: Option<InviteSub>,
    /// How many keys the code lets in.
    #[arg(long, default_value_t = 1)]
    uses: u32,
    /// How many days it is good for.
    #[arg(long, default_value_t = 7)]
    days: u32,
    /// A note for the admin: who it is for.
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Subcommand)]
enum InviteSub {
    /// One invite a line: id, uses left, expires at, made at (unix seconds), label; tab between.
    List,
    /// The code of the invite opens nothing more.
    Revoke { id: String },
}

#[derive(Subcommand)]
enum MembersCmd {
    /// One key a line, hex.
    List,
    /// Admit a key.
    Add { key: String },
    /// Take a key off the list.
    Remove { key: String },
}

fn load(arg: &ConfigArg) -> Result<Config, ExitCode> {
    Config::load(&arg.config).map_err(|e| {
        eprintln!("vguard: {e}");
        ExitCode::from(2)
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    match cli.command {
        Command::CheckConfig(arg) => match load(&arg) {
            // The files of [access] that are there must read too.
            Ok(c) => match vguard::access::check_files(&c.access) {
                Ok(()) => {
                    println!("{}: ok", arg.config.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("vguard: {}: {e}", arg.config.display());
                    ExitCode::from(2)
                }
            },
            Err(code) => code,
        },
        Command::Serve(arg) => {
            let config = match load(&arg) {
                Ok(c) => c,
                Err(code) => return code,
            };
            let level: tracing::Level = config.log.level.parse().unwrap_or(tracing::Level::INFO);
            tracing_subscriber::fmt()
                .with_max_level(level)
                .with_ansi(false)
                .with_target(false)
                .init();
            runtime.block_on(serve(config))
        }
        Command::Probe { config, wait } => {
            let config = match load(&config) {
                Ok(c) => c,
                Err(code) => return code,
            };
            runtime.block_on(probe(config, Duration::from_secs(wait)))
        }
        Command::Access { config, what } => match load(&config) {
            Ok(c) => access(&c, what),
            Err(code) => code,
        },
    }
}

async fn serve(config: Config) -> ExitCode {
    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vguard: listen on {}: {e}", config.listen);
            return ExitCode::from(1);
        }
    };
    tracing::info!(
        "vguard {} on {}, strfry at {}, relay {}, access {}",
        vguard::VERSION,
        config.listen,
        config.upstream,
        config.relay_hosts.join(" "),
        config.access.mode
    );
    let every = config.log.metrics_secs;
    let shared = Shared::new(config);
    // The access API, on a server that is not open.
    if !shared.access.is_open() {
        let api = match api::Api::new(shared.clone()) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("vguard: access: {e}");
                return ExitCode::from(1);
            }
        };
        let at = shared.config.access.listen_http.expect("checked: listen_http with a mode not open");
        let http = match tokio::net::TcpListener::bind(at).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("vguard: listen on {at}: {e}");
                return ExitCode::from(1);
            }
        };
        tracing::info!("access API on {at}, members {}, admins {}", shared.access.members.len(), shared.access.admins.len());
        tokio::spawn(async move {
            if let Err(e) = api::serve(http, api).await {
                tracing::error!("access API: {e}");
            }
        });
    }
    if every > 0 {
        tokio::spawn(proxy::report(shared.clone(), Duration::from_secs(every)));
    }
    tokio::spawn(proxy::watch_denied(shared.clone()));
    tokio::spawn(proxy::watch_denied_groups(shared.clone()));
    tokio::spawn(proxy::watch_members(shared.clone()));
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vguard: signals: {e}");
            return ExitCode::from(1);
        }
    };
    // SIGHUP: every list read again now (the members after `vguard access
    // members …`, the denied lists after the agent laid them).
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(mut hup) => {
            let shared = shared.clone();
            tokio::spawn(async move {
                while hup.recv().await.is_some() {
                    tracing::info!("SIGHUP: the lists are read again");
                    shared.refresh_lists();
                }
            });
        }
        Err(e) => {
            eprintln!("vguard: signals: {e}");
            return ExitCode::from(1);
        }
    }
    tokio::select! {
        _ = proxy::run(listener, shared.clone()) => {}
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("vguard stops: {}", shared.metrics.line());
    ExitCode::SUCCESS
}

/// `["REQ","vguard-probe",{"kinds":[0],"limit":0}]` until its EOSE.
async fn probe(config: Config, wait: Duration) -> ExitCode {
    let url = format!("ws://{}/", config.listen);
    let asked = async {
        let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str())
            .await
            .map_err(|e| e.to_string())?;
        ws.send(Message::text(
            r#"["REQ","vguard-probe",{"kinds":[0],"limit":0}]"#,
        ))
        .await
        .map_err(|e| e.to_string())?;
        while let Some(m) = ws.next().await {
            if let Message::Text(t) = m.map_err(|e| e.to_string())? {
                let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap_or_default();
                if v[1] == "vguard-probe" {
                    let _ = ws.close(None).await;
                    return match v[0].as_str() {
                        Some("EOSE") => Ok(()),
                        _ => Err(format!("the relay answered {t}")),
                    };
                }
            }
        }
        Err("the connection closed without an answer".to_string())
    };
    match tokio::time::timeout(wait, asked).await {
        Ok(Ok(())) => {
            println!("vguard on {}: strfry answers", config.listen);
            ExitCode::SUCCESS
        }
        Ok(Err(e)) => {
            eprintln!("vguard on {}: {e}", config.listen);
            ExitCode::from(1)
        }
        Err(_) => {
            eprintln!(
                "vguard on {}: no answer in {} s",
                config.listen,
                wait.as_secs()
            );
            ExitCode::from(1)
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `vguard access …`: on the files themselves; the running guard reads
/// the members again within a minute (or on SIGHUP), the invites on every
/// join. 0: done; 1: it did not work; 2: the config does not allow it.
fn access(config: &Config, what: AccessCmd) -> ExitCode {
    let c = &config.access;
    if c.mode() == Mode::Open {
        eprintln!(
            "vguard: access: this server is open ([access] mode = \"open\"): members and invites are for a team or a channel"
        );
        return ExitCode::from(2);
    }
    let fail = |e: String| {
        eprintln!("vguard: access: {e}");
        ExitCode::from(1)
    };
    match what {
        AccessCmd::Invite(cmd) => {
            let invites = match Invites::open(c) {
                Ok(i) => i,
                Err(e) => return fail(e),
            };
            match cmd.what {
                None => match invites.create(cmd.uses, cmd.days, &cmd.label, unix_now()) {
                    Ok((code, _)) => {
                        println!("{code}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(e),
                },
                Some(InviteSub::List) => match invites.list() {
                    Ok(list) => {
                        for i in list {
                            println!("{}\t{}\t{}\t{}\t{}", i.id, i.uses_left, i.expires_at, i.created_at, i.label);
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(e),
                },
                Some(InviteSub::Revoke { id }) => match invites.revoke(&id, unix_now()) {
                    Ok(true) => {
                        println!("revoked {id}");
                        ExitCode::SUCCESS
                    }
                    Ok(false) => fail(format!("no invite {id}")),
                    Err(e) => fail(e),
                },
            }
        }
        AccessCmd::Members { what } => {
            let path = c.members_file.as_deref().expect("checked: members_file with a mode not open");
            let members = KeyList::from_file(path);
            let key_of = |s: &str| key_hex(s).ok_or_else(|| format!("{s:?} is not an npub or a key of 64 hex"));
            match what {
                MembersCmd::List => {
                    for k in members.items() {
                        println!("{k}");
                    }
                    ExitCode::SUCCESS
                }
                MembersCmd::Add { key } => {
                    let key = match key_of(&key) {
                        Ok(k) => k,
                        Err(e) => return fail(e),
                    };
                    if !members.contains(&key) {
                        if let Err(e) = members.append(&key) {
                            return fail(format!("{}: {e}", path.display()));
                        }
                    }
                    println!("{key}");
                    ExitCode::SUCCESS
                }
                MembersCmd::Remove { key } => {
                    let key = match key_of(&key) {
                        Ok(k) => k,
                        Err(e) => return fail(e),
                    };
                    if !members.contains(&key) {
                        return fail(format!("{key} is not a member"));
                    }
                    let rest: Vec<String> = members.items().into_iter().filter(|k| *k != key).collect();
                    if let Err(e) = members.write_all(rest.iter().map(String::as_str)) {
                        return fail(format!("{}: {e}", path.display()));
                    }
                    println!("{key}");
                    ExitCode::SUCCESS
                }
            }
        }
    }
}
