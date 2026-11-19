//! A single writer for the access files, shared by the daemon and CLI.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Keep the returned file alive until every read and write is finished.
/// The lock file is stable across atomic replacements of the data files.
pub fn lock(members_file: &Path) -> io::Result<File> {
    let path = members_file.with_file_name("access.lock");
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(path)?;
    file.lock()?;
    Ok(file)
}
