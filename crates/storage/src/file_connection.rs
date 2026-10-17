//! Use SQLite's locking long-path VFS for Windows deployment siblings.
//!
//! Rust filesystem calls already accept these paths. SQLite's default Windows
//! VFS instead caps its pathname buffer at MAX_PATH, even for an existing file.
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

pub(crate) fn open_file(path: &Path, flags: OpenFlags) -> rusqlite::Result<Connection> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use std::{
            ffi::OsString,
            path::{Component, PathBuf, Prefix},
        };

        // Preserve SQLite's explicit in-memory/temporary entry points. Disk
        // paths use the same VFS for create, reopen and read-only snapshot.
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Connection::open_with_flags(path, flags);
        }
        let absolute =
            std::path::absolute(path).map_err(|_| rusqlite::Error::InvalidPath(path.to_owned()))?;
        let extended = match absolute.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => absolute,
                Prefix::Disk(_) => {
                    let mut name = OsString::from(r"\\?\");
                    name.push(absolute.as_os_str());
                    PathBuf::from(name)
                }
                Prefix::UNC(_, _) => {
                    let mut name = OsString::from(r"\\?\UNC\");
                    let suffix: Vec<_> = absolute.as_os_str().encode_wide().skip(2).collect();
                    name.push(OsString::from_wide(&suffix));
                    PathBuf::from(name)
                }
                _ => return Err(rusqlite::Error::InvalidPath(path.to_owned())),
            },
            _ => return Err(rusqlite::Error::InvalidPath(path.to_owned())),
        };
        // This is the normal locking VFS, never win32-longpath-none. Keep all
        // caller flags, in particular READ_ONLY and NOFOLLOW, unchanged.
        Connection::open_with_flags_and_vfs(extended, flags, "win32-longpath")
    }
    #[cfg(not(windows))]
    {
        Connection::open_with_flags(path, flags)
    }
}
