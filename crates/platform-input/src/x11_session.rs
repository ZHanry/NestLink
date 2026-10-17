//! Shared read-only logind monitor; X11 input never owns a second session monitor.
pub(crate) use nestlink_platform_session::{
    LinuxDesktopSession as X11Session, LinuxSessionState as X11SessionState,
};
