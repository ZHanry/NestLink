//! Per-user desktop clipboard adapters. Wayland must supply a grant taken from
//! the original RemoteDesktop portal session; this module never opens a new one.
#[cfg(target_os = "linux")]
use nestlink_app_core::NativeClipboardBinding;
use nestlink_app_core::{CoreHandle, NativeClipboardPlatformFactory};
use nestlink_platform_clipboard::{
    ClipboardAuthority, ClipboardBinding, LocalClipboardApproval, NativeClipboard,
};
use std::{io, sync::Arc};

#[cfg(target_os = "linux")]
use nestlink_platform_input::portal::PortalControl;
#[cfg(target_os = "linux")]
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct InstalledClipboardFactory {
    #[cfg(target_os = "linux")]
    factory: Arc<DesktopClipboardFactory>,
}

impl InstalledClipboardFactory {
    /// Transfer the clipboard grant from the same portal session that owns the
    /// approved RemoteDesktop capture/input session. It is keyed by the full
    /// proved binding and remains reserved until that original owner closes.
    #[cfg(target_os = "linux")]
    pub fn provide_portal_grant(
        &self,
        binding: NativeClipboardBinding,
        grant: nestlink_platform_clipboard::portal::PortalClipboardGrant,
        control: PortalControl,
    ) -> io::Result<()> {
        let mut current = self
            .factory
            .portal_grant
            .lock()
            .map_err(|_| io::Error::other("clipboard portal grant state poisoned"))?;
        if let Some(previous) = current.as_ref() {
            if previous.binding == binding {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a Wayland clipboard grant is already registered for this Core session",
                ));
            }
            // Do not infer that cleanup completed from dropping the grant. A
            // later session can replace it only after the original
            // RemoteDesktop owner confirms its Close and D-Bus cleanup path.
            previous
                .control
                .wait_closed_until(Instant::now() + Duration::from_secs(2))?;
        }
        *current = Some(PortalGrantEntry {
            binding,
            grant: Some(grant),
            control,
        });
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct PortalGrantEntry {
    binding: NativeClipboardBinding,
    grant: Option<nestlink_platform_clipboard::portal::PortalClipboardGrant>,
    // Retained after the one-shot grant moves into PortalClipboard so a later
    // session cannot replace it until the original PortalInput owner closes.
    control: PortalControl,
}

pub fn install(
    core: &CoreHandle,
) -> Result<InstalledClipboardFactory, nestlink_app_core::NativeClipboardError> {
    let factory = Arc::new(DesktopClipboardFactory::new());
    core.install_native_clipboard_platform_factory(factory.clone())?;
    Ok(InstalledClipboardFactory {
        #[cfg(target_os = "linux")]
        factory,
    })
}

struct DesktopClipboardFactory {
    #[cfg(target_os = "linux")]
    desktop_pid: Option<u32>,
    #[cfg(target_os = "linux")]
    portal_grant: Mutex<Option<PortalGrantEntry>>,
}

impl DesktopClipboardFactory {
    fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            desktop_pid: std::env::var("NESTLINK_LOCAL_GUI_PID")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|pid| *pid != 0),
            #[cfg(target_os = "linux")]
            portal_grant: Mutex::new(None),
        }
    }
}

impl NativeClipboardPlatformFactory for DesktopClipboardFactory {
    fn open(
        &self,
        binding: ClipboardBinding,
        core_generation: u64,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<Box<dyn NativeClipboard>> {
        #[cfg(windows)]
        {
            let _ = core_generation;
            let clipboard =
                nestlink_platform_clipboard::WindowsClipboard::open(binding, approval, authority)?;
            Ok(Box::new(clipboard))
        }

        #[cfg(target_os = "linux")]
        {
            if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                let mut current = self
                    .portal_grant
                    .lock()
                    .map_err(|_| io::Error::other("clipboard portal grant state poisoned"))?;
                let entry = current
                    .as_mut()
                    .filter(|entry| {
                        entry.binding.request_id == binding.session_id
                            && entry.binding.connection_generation == binding.connection_generation
                            && entry.binding.core_generation == core_generation
                    })
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "no clipboard grant matches this request, connection and Core generation",
                        )
                    })?;
                let grant = entry.grant.take().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "the original Wayland clipboard grant was already consumed",
                    )
                })?;
                drop(current);
                let clipboard = nestlink_platform_clipboard::portal::PortalClipboard::open(
                    grant, binding, approval, authority,
                )?;
                return Ok(Box::new(clipboard));
            }

            let desktop_pid = self.desktop_pid.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the local GUI process identity is unavailable",
                )
            })?;
            let display = std::env::var("DISPLAY").map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the local X11 display is unavailable",
                )
            })?;
            let clipboard = nestlink_platform_clipboard::X11Clipboard::open_for_desktop(
                &display,
                desktop_pid,
                binding,
                approval,
                authority,
            )?;
            Ok(Box::new(clipboard))
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = core_generation;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native clipboard is unsupported on this desktop platform",
            ))
        }
    }
}
