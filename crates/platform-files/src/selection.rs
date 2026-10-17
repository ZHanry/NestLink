//! Native selectors report a local choice only. Opening a file/root and granting
//! access still require the caller's current session and explicit approval.
use std::{io, path::PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectionKind {
    File,
    Folder,
}

/// A bounded local pipe reply; never sent to a peer or included in diagnostics.
pub const MAX_SELECTION_PATH: usize = 3_072;

pub fn validate(path: &str) -> io::Result<PathBuf> {
    let path_buf = PathBuf::from(path);
    if path.is_empty()
        || path.len() > MAX_SELECTION_PATH
        || path.chars().any(char::is_control)
        || !path_buf.is_absolute()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the selected local path is invalid or exceeds its limit",
        ));
    }
    Ok(path_buf)
}

/// Run on a dedicated selector process so cancelling a modal OS dialog cannot
/// strand a UI thread or transfer its late result to a replacement session.
#[cfg(any(windows, target_os = "linux"))]
pub fn choose(kind: SelectionKind) -> io::Result<Option<PathBuf>> {
    #[cfg(windows)]
    let selected = windows::choose(kind)?;
    #[cfg(target_os = "linux")]
    let selected = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(linux::choose(kind))?;
    selected
        .map(|path| {
            let text = path.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the selected path is not UTF-8",
                )
            })?;
            validate(text)
        })
        .transpose()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn choose(_kind: SelectionKind) -> io::Result<Option<PathBuf>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native file selection is unavailable on this platform",
    ))
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_does_not_accept_relative_control_or_unbounded_paths() {
        assert!(validate("relative/path").is_err());
        assert!(validate("").is_err());
        let absolute = std::env::temp_dir();
        let base = absolute.to_string_lossy();
        assert!(validate(&base).is_ok());
        assert!(validate(&format!("{base}\nprivate")).is_err());
        assert!(validate(&format!("{base}{}", "x".repeat(MAX_SELECTION_PATH))).is_err());
    }
}
