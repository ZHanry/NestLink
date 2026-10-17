//! A normal-user, bounded tray entry. Its availability never grants remote
//! authority. The UI must remain visible whenever the OS host is unavailable.
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender},
    },
    time::Duration,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Open,
    Exit,
}
pub struct Icon {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}
impl Icon {
    fn validate(&self) -> io::Result<()> {
        if !(16..=64).contains(&self.width)
            || !(16..=64).contains(&self.height)
            || self.rgba.len() != self.width as usize * self.height as usize * 4
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tray icon exceeds its size budget",
            ));
        }
        Ok(())
    }
}
pub struct Labels {
    pub open: String,
    pub exit: String,
}
impl Labels {
    fn validate(&self) -> io::Result<()> {
        if [&self.open, &self.exit]
            .iter()
            .any(|label| label.is_empty() || label.len() > 128 || label.contains('\0'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tray labels invalid",
            ));
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Sink {
    actions: SyncSender<Action>,
    wake: Arc<dyn Fn() + Send + Sync>,
}
impl Sink {
    fn send(&self, action: Action) {
        if self.actions.try_send(action).is_ok() {
            (self.wake)();
        }
    }
}

pub struct Tray {
    available: Arc<AtomicBool>,
    actions: Receiver<Action>,
    #[cfg(windows)]
    worker: windows::Worker,
    #[cfg(target_os = "linux")]
    worker: linux::Worker,
}
impl Tray {
    pub fn create(
        icon: Icon,
        labels: Labels,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> io::Result<Self> {
        icon.validate()?;
        labels.validate()?;
        let (actions, incoming) = std::sync::mpsc::sync_channel(8);
        let sink = Sink { actions, wake };
        let available = Arc::new(AtomicBool::new(false));
        #[cfg(windows)]
        let worker = windows::Worker::start(icon, labels, sink, available.clone())?;
        #[cfg(target_os = "linux")]
        let worker = linux::Worker::start(icon, labels, sink, available.clone())?;
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tray host unavailable on this platform",
        ));
        #[cfg(any(windows, target_os = "linux"))]
        Ok(Self {
            available,
            actions: incoming,
            worker,
        })
    }
    pub fn available(&self) -> bool {
        #[cfg(windows)]
        if !self.worker.present() {
            return false;
        }
        self.available.load(Ordering::Acquire)
    }
    pub fn actions(&self) -> impl Iterator<Item = Action> + '_ {
        self.actions.try_iter()
    }
}
impl Drop for Tray {
    fn drop(&mut self) {
        self.available.store(false, Ordering::Release);
        self.worker.stop();
    }
}
const STARTUP: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn icon_and_labels_are_bounded_before_starting_any_os_worker() {
        for icon in [
            Icon {
                width: 0,
                height: 32,
                rgba: Vec::new(),
            },
            Icon {
                width: 65,
                height: 32,
                rgba: vec![0; 65 * 32 * 4],
            },
            Icon {
                width: 32,
                height: 32,
                rgba: vec![0; 4],
            },
        ] {
            assert!(icon.validate().is_err());
        }
        assert!(
            Labels {
                open: "Open\0hidden".into(),
                exit: "Exit".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            Labels {
                open: "Open".into(),
                exit: "x".repeat(129)
            }
            .validate()
            .is_err()
        );
    }
}
