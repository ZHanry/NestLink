//! Original monitor/session and same-device NV12 capture for the HEVC worker.
//! Opening a source does not read desktop pixels. Capture begins only on an
//! explicit command of the caller's already-authorized live execution.
use super::*;
use nestlink_media_codec::{
    ExecutionDirection, HardwareHevcExecution, HevcExecutionTarget, HevcTextureSource,
};

struct HevcMonitorSource {
    capture: Option<GpuCapture>,
    observer: WindowsSessionObserver,
    invalidated: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    original: Arc<Context>,
    _dpi: DpiScope,
}
// SAFETY: only the execution worker constructs/uses/drops this !Send source.
// GpuCapture owns the original device and exact NV12 surface. The original
// monitor/session/DPI snapshot and sticky OS observer are checked around reads.
unsafe impl HevcTextureSource for HevcMonitorSource {
    fn device(&self) -> io::Result<*mut c_void> {
        self.check_current()?;
        self.capture
            .as_ref()
            .ok_or_else(|| denied("HEVC capture already closed"))?
            .device()
    }
    fn capture(&mut self, repeated: bool) -> io::Result<Option<NonNull<c_void>>> {
        self.check_current()?;
        let capture = self
            .capture
            .as_mut()
            .ok_or_else(|| denied("HEVC capture already closed"))?;
        let next = match capture.frame(false)? {
            Some(texture) => Some(texture),
            None if repeated => capture.frame(true)?,
            None => None,
        };
        self.check_current()?;
        Ok(next)
    }
    fn check_current(&self) -> io::Result<()> {
        self.observer.pump();
        if self.cancelled.load(Ordering::Acquire)
            || self.invalidated.load(Ordering::Acquire) || context()? != *self.original {
            return Err(denied("HEVC original desktop/session/monitor/DPI changed"));
        }
        Ok(())
    }
    fn close(mut self: Box<Self>) -> io::Result<()> {
        // Release capture after the native MF encoder has completed checked
        // close, before the observer and original thread DPI scope are dropped.
        self.capture.take();
        self.observer.close()
    }
}
impl WindowsCaptureSource {
    /// Exact approved source only: no source IDs from remote packets, implicit
    /// resizing, software fallback or synthetic replacement can enter this path.
    /// The returned worker remains owned until successful checked close and join.
    pub fn start_hevc_encode(
        &self,
        target: HevcExecutionTarget,
        authority: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
    ) -> io::Result<HardwareHevcExecution> {
        let config = target.contract().config();
        let display = self.display();
        if (config.width, config.height) != (display.logical.width, display.logical.height) {
            return Err(denied(
                "HEVC signed target differs from approved monitor geometry",
            ));
        }
        let selection = self.clone();
        HardwareHevcExecution::start(ExecutionDirection::Encode, target, authority, move || {
            let dpi = DpiScope::enter()?;
            let invalidated = Arc::new(AtomicBool::new(false));
            let mut observer = WindowsSessionObserver::open(invalidated.clone(), true)?;
            let result = (|| {
                observer.pump();
                if cancelled.load(Ordering::Acquire)
                    || invalidated.load(Ordering::Acquire) || context()? != *selection.original {
                    return Err(denied("HEVC approved capture selection is stale"));
                }
                let monitor = selection
                    .original
                    .monitors
                    .get(selection.index)
                    .ok_or_else(|| denied("HEVC approved monitor absent"))?;
                GpuCapture::open_target(monitor, config.width, config.height, config.fps)
            })();
            let capture = match result {
                Ok(capture) => capture,
                Err(error) => {
                    observer.close()?;
                    return Err(error);
                }
            };
            let owner = HevcMonitorSource {
                capture: Some(capture),
                observer,
                invalidated,
                cancelled,
                original: selection.original,
                _dpi: dpi,
            };
            owner.check_current()?;
            Ok(Box::new(owner) as Box<dyn HevcTextureSource>)
        })
    }
}
