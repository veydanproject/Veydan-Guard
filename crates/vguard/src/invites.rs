//! The invites of a team or a channel (spec/vguard.md, "Members, admins
//! and invites").
//!
//! A code is `vi1.<id>.<mac>`: `id` 16 hex of random, `mac` the first 16
//! hex of HMAC-SHA256(secret, "veydan.access.invite.v1\n" + id), the secret
//! being `secret_file`. The file of the invites (`invites_file`, JSON) lists
//! each id with what is left of it; a code is good when its mac checks, its
//! id is listed, uses are left and it has not expired. The file holds no
//! code: without the secret it opens nothing.
//!
//! The running guard reads the file on every join and `vguard access
//! invite …` writes it, both by a temporary file renamed over it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::config::AccessConfig;

/// The first word of a code.
pub const PREFIX: &str = "vi1";
/// What the mac is over, before the id.
const CONTEXT: &str = "veydan.access.invite.v1\n";
/// The shortest secret taken.
pub const MIN_SECRET: usize = 32;
/// How long an expired invite stays listed (and answers `invite_expired`)
/// before a write drops it.
const KEEP_EXPIRED_SECS: u64 = 30 * 24 * 3600;
/// The most uses of one invite, and its longest life.
pub const MAX_USES: u32 = 10_000;
pub const MAX_DAYS: u32 = 365;
/// The longest label.
pub const MAX_LABEL: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub uses_left: u32,
    /// Unix seconds.
    pub expires_at: u64,
    pub created_at: u64,
}

/// Why a code does not let a key in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redeem {
    /// Not a code of this server, or revoked.
    Invalid,
    Expired,
    /// Every use of it is taken.
    Used,
    /// The file does not read or cannot be written.
    Io(String),
}

impl Redeem {
    /// The word of the API.
    pub fn word(&self) -> &'static str {
        match self {
            Redeem::Invalid => "invite_invalid",
            Redeem::Expired => "invite_expired",
            Redeem::Used => "invite_used",
            Redeem::Io(_) => "internal",
        }
    }
}

/// The secret of the codes: the bytes of `path`, at least [`MIN_SECRET`].
pub fn read_secret(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() < MIN_SECRET {
        return Err(format!(
            "{}: {} bytes; the key of the invites is at least {MIN_SECRET} bytes of random",
            path.display(),
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// The invites of `path`; none when there is no file.
pub fn read_file(path: &Path) -> Result<Vec<Invite>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn is_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether a new invite of `uses`, `days` and `label` may be made.
pub fn check_new(uses: u32, days: u32, label: &str) -> Result<(), String> {
    if !(1..=MAX_USES).contains(&uses) {
        return Err(format!("uses: 1 to {MAX_USES}"));
    }
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(format!("days: 1 to {MAX_DAYS}"));
    }
    if label.chars().count() > MAX_LABEL || label.chars().any(char::is_control) {
        return Err(format!("label: at most {MAX_LABEL} characters, on one line"));
    }
    Ok(())
}

pub struct Invites {
    path: PathBuf,
    key: hmac::Key,
    /// One change at a time within this process.
    lock: Mutex<()>,
}

impl Invites {
    pub fn new(path: &Path, secret: &[u8]) -> Self {
        Self { path: path.to_path_buf(), key: hmac::Key::new(hmac::HMAC_SHA256, secret), lock: Mutex::new(()) }
    }

    /// The invites of the config's `invites_file`, by its `secret_file`.
    pub fn open(c: &AccessConfig) -> Result<Self, String> {
        let path = c.invites_file.as_deref().ok_or("access.invites_file is not set")?;
        let secret = c.secret_file.as_deref().ok_or("access.secret_file is not set")?;
        Ok(Self::new(path, &read_secret(secret)?))
    }

    fn mac(&self, id: &str) -> String {
        let tag = hmac::sign(&self.key, format!("{CONTEXT}{id}").as_bytes());
        hex(&tag.as_ref()[..8])
    }

    /// The code of the invite `id`.
    pub fn code_of(&self, id: &str) -> String {
        format!("{PREFIX}.{id}.{}", self.mac(id))
    }

    /// The id of a code whose mac checks; None for anything else.
    pub fn id_of(&self, code: &str) -> Option<String> {
        let mut parts = code.trim().split('.');
        let (Some(PREFIX), Some(id), Some(mac), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        let (id, mac) = (id.to_ascii_lowercase(), mac.to_ascii_lowercase());
        if !is_id(&id) || mac.len() != 16 {
            return None;
        }
        let want = self.mac(&id);
        // In constant time: the mac is what keeps a code from being guessed.
        let same = want.bytes().zip(mac.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
        same.then_some(id)
    }

    pub fn list(&self) -> Result<Vec<Invite>, String> {
        read_file(&self.path)
    }

    fn save(&self, invites: &[Invite], now: u64) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let kept: Vec<&Invite> = invites.iter().filter(|i| i.expires_at.saturating_add(KEEP_EXPIRED_SECS) > now).collect();
        let text = serde_json::to_vec_pretty(&kept).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension(format!("tmp.{}", std::process::id()));
        let written = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&text)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        written.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", self.path.display())
        })
    }

    /// A new invite: its code and its entry.
    pub fn create(&self, uses: u32, days: u32, label: &str, now: u64) -> Result<(String, Invite), String> {
        check_new(uses, days, label)?;
        let _one = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut invites = self.list()?;
        let id = loop {
            let id = crate::auth::new_challenge()[..16].to_string();
            if !invites.iter().any(|i| i.id == id) {
                break id;
            }
        };
        let invite = Invite {
            id: id.clone(),
            label: label.to_string(),
            uses_left: uses,
            expires_at: now + u64::from(days) * 86_400,
            created_at: now,
        };
        invites.push(invite.clone());
        self.save(&invites, now)?;
        Ok((self.code_of(&id), invite))
    }

    /// Takes the invite `id` off the list: its code opens nothing more.
    /// False when it was not listed.
    pub fn revoke(&self, id: &str, now: u64) -> Result<bool, String> {
        let _one = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut invites = self.list()?;
        let before = invites.len();
        invites.retain(|i| i.id != id);
        if invites.len() == before {
            return Ok(false);
        }
        self.save(&invites, now)?;
        Ok(true)
    }

    /// One use of `code`, at `now`: the id of its invite. A used-up invite
    /// stays listed until it expires, so that a second use is told
    /// `invite_used`.
    pub fn redeem(&self, code: &str, now: u64) -> Result<String, Redeem> {
        let id = self.id_of(code).ok_or(Redeem::Invalid)?;
        let _one = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut invites = self.list().map_err(Redeem::Io)?;
        let invite = invites.iter_mut().find(|i| i.id == id).ok_or(Redeem::Invalid)?;
        if invite.expires_at <= now {
            return Err(Redeem::Expired);
        }
        if invite.uses_left == 0 {
            return Err(Redeem::Used);
        }
        invite.uses_left -= 1;
        self.save(&invites, now).map_err(Redeem::Io)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vguard-invites-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_code_is_made_used_up_and_revoked() {
        let dir = temp("cycle");
        let inv = Invites::new(&dir.join("invites.json"), &[7u8; 32]);
        assert!(inv.list().unwrap().is_empty(), "no file, no invites");
        let (code, i) = inv.create(1, 7, "for Anna", NOW).unwrap();
        assert!(code.starts_with("vi1.") && code.len() == 4 + 16 + 1 + 16, "{code}");
        assert_eq!(i.expires_at, NOW + 7 * 86_400);
        assert_eq!(inv.id_of(&code).as_deref(), Some(i.id.as_str()));
        assert_eq!(inv.id_of(&code.to_ascii_uppercase().replacen("VI1", "vi1", 1)).as_deref(), Some(i.id.as_str()));
        assert_eq!(inv.redeem(&code, NOW + 1), Ok(i.id.clone()));
        assert_eq!(inv.redeem(&code, NOW + 2), Err(Redeem::Used), "a one-use code");
        assert_eq!(inv.list().unwrap()[0].uses_left, 0, "still listed");
        // A bad mac, another secret, a code of nothing.
        let mut bad = code.clone();
        bad.pop();
        bad.push(if code.ends_with('0') { '1' } else { '0' });
        assert_eq!(inv.redeem(&bad, NOW), Err(Redeem::Invalid));
        let other = Invites::new(&dir.join("invites.json"), &[8u8; 32]);
        assert_eq!(other.redeem(&code, NOW), Err(Redeem::Invalid));
        for junk in ["", "vi1", "vi1..", "vi2.0123456789abcdef.0123456789abcdef", &format!("{code}.x")] {
            assert_eq!(inv.redeem(junk, NOW), Err(Redeem::Invalid), "{junk}");
        }
        // Expired.
        let (code2, i2) = inv.create(5, 1, "", NOW).unwrap();
        assert_eq!(inv.redeem(&code2, NOW + 86_400), Err(Redeem::Expired));
        // Revoked.
        assert!(inv.revoke(&i2.id, NOW).unwrap());
        assert!(!inv.revoke(&i2.id, NOW).unwrap());
        assert_eq!(inv.redeem(&code2, NOW), Err(Redeem::Invalid));
        // Long expired ones are dropped by the next write.
        inv.create(1, 1, "", NOW + 40 * 86_400).unwrap();
        assert_eq!(inv.list().unwrap().len(), 1);
        // Bounds.
        assert!(inv.create(0, 7, "", NOW).is_err());
        assert!(inv.create(1, 0, "", NOW).is_err());
        assert!(inv.create(1, 7, "a\nb", NOW).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_secret_is_long_enough() {
        let dir = temp("secret");
        let p = dir.join("access.key");
        std::fs::write(&p, [1u8; 31]).unwrap();
        assert!(read_secret(&p).unwrap_err().contains("at least 32"));
        std::fs::write(&p, [1u8; 32]).unwrap();
        assert_eq!(read_secret(&p).unwrap().len(), 32);
        assert!(read_secret(&dir.join("none")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
