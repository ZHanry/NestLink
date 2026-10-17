//! Android supplies synchronous ClipboardManager calls through a JNI bridge.
//! The existing worker owns every call and retains blocked platform work.
use crate::{
    Backend, ClipboardAuthority, ClipboardBinding, ClipboardDevice, ClipboardDirection, Context,
    LocalClipboardApproval, timed_out, validate_text,
};
use std::{io, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// This endpoint must check the original session and Android foreground access
/// immediately before and after a ClipboardManager call. It must never queue a
/// detached OS operation or include clipboard contents in errors or status.
pub trait AndroidClipboardBridge: Send + 'static {
    fn check(&mut self, until: Instant) -> io::Result<()>;
    fn read_text(&mut self, until: Instant) -> io::Result<Option<Zeroizing<Vec<u8>>>>;
    fn write_text(&mut self, text: &[u8], until: Instant) -> io::Result<()>;
    fn close(&mut self, until: Instant) -> io::Result<()>;
}

pub struct AndroidClipboard;
impl AndroidClipboard {
    pub fn open(
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
        bridge: Box<dyn AndroidClipboardBridge>,
    ) -> io::Result<ClipboardDevice> {
        ClipboardDevice::open(binding, approval, authority, move |_| {
            Ok(Box::new(AndroidBackend { bridge }))
        })
    }
}

struct AndroidBackend {
    bridge: Box<dyn AndroidClipboardBridge>,
}

fn within(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        return Err(timed_out("Android clipboard operation deadline exhausted"));
    }
    Ok(())
}

impl Backend for AndroidBackend {
    fn check(&mut self, until: Instant) -> io::Result<()> {
        within(until)?;
        self.bridge.check(until)?;
        within(until)
    }

    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>> {
        context.check(ClipboardDirection::Read, until)?;
        let bytes = self.bridge.read_text(until)?;
        context.check(ClipboardDirection::Read, until)?;
        let Some(bytes) = bytes else { return Ok(None) };
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Android clipboard text is not UTF-8",
            )
        })?;
        validate_text(text)?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    }

    fn write(&mut self, text: &str, context: &Context, until: Instant) -> io::Result<()> {
        validate_text(text)?;
        context.check(ClipboardDirection::Write, until)?;
        self.bridge.write_text(text.as_bytes(), until)?;
        context.check(ClipboardDirection::Write, until)
    }

    fn service(&mut self, _context: &Context, until: Instant) -> io::Result<()> {
        // Android owns its clipboard after setPrimaryClip; there is no local
        // text listener, selection service, retained previous value or restore.
        within(until)
    }

    fn close(&mut self, until: Instant) -> io::Result<()> {
        self.bridge.close(until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClipboardCleanup, NativeClipboard as _,
        tests::{authority, binding},
    };
    use std::{
        sync::{
            Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct Facts {
        reads: AtomicUsize,
        writes: AtomicUsize,
        closed: AtomicBool,
        entered: AtomicBool,
        gate: Mutex<bool>,
        wake: Condvar,
        block: bool,
    }

    struct Bridge(Arc<Facts>);
    struct Release(Arc<Facts>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Ok(mut gate) = self.0.gate.lock() {
                *gate = true;
            }
            self.0.wake.notify_all();
        }
    }
    impl AndroidClipboardBridge for Bridge {
        fn check(&mut self, _until: Instant) -> io::Result<()> {
            Ok(())
        }
        fn read_text(&mut self, _until: Instant) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            self.0.reads.fetch_add(1, Ordering::SeqCst);
            self.0.entered.store(true, Ordering::SeqCst);
            if self.0.block {
                let mut gate = self
                    .0
                    .gate
                    .lock()
                    .map_err(|_| io::Error::other("fixture gate"))?;
                while !*gate {
                    gate = self
                        .0
                        .wake
                        .wait(gate)
                        .map_err(|_| io::Error::other("fixture gate"))?;
                }
            }
            Ok(Some(Zeroizing::new("fixture 中文🙂".as_bytes().to_vec())))
        }
        fn write_text(&mut self, _text: &[u8], _until: Instant) -> io::Result<()> {
            self.0.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn close(&mut self, _until: Instant) -> io::Result<()> {
            self.0.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn open_and_health_checks_never_read_or_write_the_system_clipboard() -> io::Result<()> {
        let facts = Arc::new(Facts::default());
        let (approval, control) =
            LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
        let mut device = AndroidClipboard::open(
            binding(),
            approval,
            authority(),
            Box::new(Bridge(facts.clone())),
        )?;
        device.check()?;
        assert_eq!(facts.reads.load(Ordering::SeqCst), 0);
        assert_eq!(facts.writes.load(Ordering::SeqCst), 0);
        assert_eq!(device.read_text()?.as_deref(), Some("fixture 中文🙂"));
        device.write_text("explicit text")?;
        assert_eq!(facts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(facts.writes.load(Ordering::SeqCst), 1);
        control.revoke_all();
        device.close()?;
        assert!(facts.closed.load(Ordering::SeqCst));
        assert!(device.context.shared.worker_joined());
        Ok(())
    }

    #[test]
    fn revoked_direction_never_reaches_the_android_callback() -> io::Result<()> {
        let facts = Arc::new(Facts::default());
        let (approval, control) =
            LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
        let mut device = AndroidClipboard::open(
            binding(),
            approval,
            authority(),
            Box::new(Bridge(facts.clone())),
        )?;
        control.revoke_read();
        assert!(device.read_text().is_err());
        assert_eq!(facts.reads.load(Ordering::SeqCst), 0);
        device.write_text("separately approved write")?;
        assert_eq!(facts.writes.load(Ordering::SeqCst), 1);
        control.revoke_all();
        device.close()?;
        Ok(())
    }

    #[test]
    fn blocked_real_worker_remains_owned_after_timeout_and_revoke_until_same_join() -> io::Result<()>
    {
        let facts = Arc::new(Facts {
            block: true,
            ..Facts::default()
        });
        let _release = Release(facts.clone());
        let (approval, control) =
            LocalClipboardApproval::approve_from_local_user(binding(), true, false)?;
        let device = AndroidClipboard::open(
            binding(),
            approval,
            authority(),
            Box::new(Bridge(facts.clone())),
        )?;
        let caller = thread::spawn(move || {
            let mut device = device;
            let result = device.read_text();
            (device, result)
        });
        let until = Instant::now() + Duration::from_secs(3);
        while !facts.entered.load(Ordering::SeqCst) && Instant::now() < until {
            thread::yield_now();
        }
        // Always release the fixture gate on the error path as well.
        let entered = facts.entered.load(Ordering::SeqCst);
        control.revoke_all();
        if !entered {
            *facts
                .gate
                .lock()
                .map_err(|_| io::Error::other("fixture gate"))? = true;
            facts.wake.notify_all();
        }
        let (mut device, result) = caller
            .join()
            .map_err(|_| io::Error::other("fixture caller"))?;
        assert!(entered);
        assert!(result.is_err());
        assert!(device.close().is_err());
        assert!(!device.context.shared.worker_joined());
        assert!(!facts.closed.load(Ordering::SeqCst));
        assert!(matches!(
            device.monitor().status().cleanup,
            ClipboardCleanup::Failed(_)
        ));
        *facts
            .gate
            .lock()
            .map_err(|_| io::Error::other("fixture gate"))? = true;
        facts.wake.notify_all();
        let until = Instant::now() + Duration::from_secs(3);
        while !device.context.shared.worker_joined() && Instant::now() < until {
            device.monitor().status();
            thread::sleep(Duration::from_millis(1));
        }
        // Late completion does not erase the original cleanup timeout.
        assert!(device.close().is_err());
        assert!(device.context.shared.worker_joined());
        assert!(facts.closed.load(Ordering::SeqCst));
        assert!(matches!(
            device.monitor().status().cleanup,
            ClipboardCleanup::Failed(_)
        ));
        Ok(())
    }
}
