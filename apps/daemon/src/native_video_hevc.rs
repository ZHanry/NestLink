//! Exact signed HEVC producer attached to the same View capture cleanup owner.
//! Approved opaque Windows sources are retained; no source is reconstructed
//! from a remote ID and no desktop pixels cross the hardware worker boundary.
use super::*;
use nestlink_media_codec::{
    HardwareHevcExecution, HevcExecutionOutput, HevcExecutionReceipt, HevcExecutionTarget,
    HevcOwnerOutput,
};
use nestlink_platform_capture::WindowsCaptureSource;
use nestlink_protocol::media_format::{Codec, FormatSet, VideoFormat};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

struct State {
    execution: Option<HardwareHevcExecution>,
    target: Option<(u32, HevcExecutionTarget)>,
}
#[derive(Clone)]
pub(super) struct Capture {
    sources: Arc<Vec<WindowsCaptureSource>>,
    stopped: Arc<AtomicBool>,
    authority: Arc<AtomicBool>,
    state: Arc<Mutex<State>>,
}
impl Capture {
    pub(super) fn new(sources: Vec<WindowsCaptureSource>) -> Self {
        Self {
            sources: Arc::new(sources),
            stopped: Arc::new(AtomicBool::new(false)),
            authority: Arc::new(AtomicBool::new(true)),
            state: Arc::new(Mutex::new(State {
                execution: None,
                target: None,
            })),
        }
    }
    fn configure(&self, source: u32, target: HevcExecutionTarget) -> io::Result<()> {
        if self.stopped.load(Ordering::Acquire) || !self.authority.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "HEVC original capture authorization retired",
            ));
        }
        let selected = self
            .sources
            .iter()
            .find(|s| s.display().source == source)
            .ok_or_else(|| {
                io::Error::other("HEVC source is outside locally approved capture set")
            })?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("HEVC capture owner poisoned"))?;
        if state.target == Some((source, target)) && state.execution.is_some() {
            return Ok(());
        }
        if let Some(mut old) = state.execution.take() {
            old.shutdown()?;
        }
        state.target = None;
        let mut owner =
            selected.start_hevc_encode(target, self.authority.clone(), self.stopped.clone())?;
        if self.stopped.load(Ordering::Acquire) || !self.authority.load(Ordering::Acquire) {
            owner.shutdown()?;
            return Err(io::Error::other(
                "HEVC capture retired during exact preparation",
            ));
        }
        state.execution = Some(owner);
        state.target = Some((source, target));
        Ok(())
    }
    fn capture(
        &self,
        pts: u64,
        repeated: bool,
    ) -> io::Result<Option<(HevcOwnerOutput, HevcExecutionReceipt)>> {
        if self.stopped.load(Ordering::Acquire) || !self.authority.load(Ordering::Acquire) {
            self.authority.store(false, Ordering::Release);
            return Err(io::Error::other(
                "HEVC capture authorization retired before submit",
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("HEVC capture owner poisoned"))?;
        let owner = state
            .execution
            .as_ref()
            .ok_or_else(|| io::Error::other("HEVC capture is not configured"))?;
        let mut ticket = owner.submit_capture(pts, repeated)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut accepted = false;
        loop {
            if self.stopped.load(Ordering::Acquire) || Instant::now() >= deadline {
                self.authority.store(false, Ordering::Release);
                return Err(io::Error::other(
                    "HEVC capture revoked or output deadline exhausted",
                ));
            }
            match ticket.try_poll()? {
                Some(HevcExecutionOutput::Encoded {
                    accepted: current,
                    output,
                }) => {
                    accepted |= current;
                    if output.is_some() || !accepted {
                        return Ok(output);
                    }
                    ticket = owner.poll_output()?;
                }
                Some(_) => {
                    return Err(io::Error::other(
                        "HEVC encoder returned wrong operation direction",
                    ));
                }
                None => {}
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}
impl CaptureDevice for Capture {
    fn check(&mut self) -> io::Result<()> {
        if self.stopped.load(Ordering::Acquire) || !self.authority.load(Ordering::Acquire) {
            Err(io::Error::other("HEVC original capture owner retired"))
        } else {
            Ok(())
        }
    }
    fn cancellation(&self) -> Option<Arc<AtomicBool>> {
        Some(self.stopped.clone())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.check()?;
        Ok(None)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.authority.store(false, Ordering::Release);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("HEVC capture owner poisoned"))?;
        state.target = None;
        if let Some(mut owner) = state.execution.take() {
            owner.shutdown()?;
        }
        Ok(())
    }
    fn reset_before(&mut self, deadline: Instant) -> io::Result<()> {
        self.reset()?;
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC capture checked join exceeded original cleanup deadline",
            ));
        }
        Ok(())
    }
}
fn select_target(formats: &FormatSet, binding: NativeVideoBinding) -> io::Result<VideoFormat> {
    formats
        .formats()
        .iter()
        .filter(|format| {
            format.codec == Codec::Hevc
                && (format.width, format.height) == (binding.width, binding.height)
                && nestlink_media_session::hevc_contract(**format).is_ok()
        })
        .max_by_key(|format| (format.frame_rate.numerator, format.max_kbps))
        .copied()
        .ok_or_else(|| {
            io::Error::other("approved monitor lacks an exact signed HEVC execution target")
        })
}
pub(super) fn stream<D: CaptureDevice>(
    core: &CoreHandle,
    identity: &SessionIdentity,
    controller: VideoController<D>,
    mut capture: Capture,
    runtime: tokio::runtime::Handle,
    stop: &watch::Receiver<bool>,
) -> (VideoController<D>, StreamExit) {
    let result = (|| -> io::Result<StreamExit> {
        let mut active = None;
        let mut first_deadline = Instant::now() + FIRST_FRAME_TIMEOUT;
        let mut output_seen = false;
        let mut previous_pts = 0;
        loop {
            if *stop.borrow() || !is_current_session(core, identity) {
                return Ok(StreamExit::SessionEnded);
            }
            if let Some(request) = core.native_display_switch_request(identity)? {
                runtime
                    .block_on(core.commit_native_display_switch(identity, &request))
                    .map_err(io::Error::other)?;
            }
            let state = core.native_displays(identity)?;
            if state.pending.is_some() || state.selected.is_none() {
                thread::sleep(CAPTURE_TICK);
                continue;
            }
            let selection = state
                .selected
                .as_ref()
                .ok_or_else(|| io::Error::other("HEVC display selection absent"))?;
            let display = state
                .displays
                .iter()
                .find(|d| d.source == selection.source)
                .ok_or_else(|| io::Error::other("HEVC approved selected monitor absent"))?;
            let binding = NativeVideoBinding {
                source: selection.source,
                width: display.width,
                height: display.height,
                layout_epoch: selection.layout_epoch,
            };
            let formats = core
                .native_video_formats(identity)?
                .ok_or_else(|| io::Error::other("HEVC has no exact signed scope"))?;
            let format = select_target(&formats, binding)?;
            if core.native_video_encoder_backend(identity)?.as_deref() != Some("gpu-hevc-encoder") {
                return Err(io::Error::other(
                    "HEVC lacks its independently proved encoder backend",
                ));
            }
            let hardware = core
                .native_video_encoder_hardware_target(identity)?
                .ok_or_else(|| io::Error::other("HEVC original encoder platform absent"))?;
            let target = nestlink_media_session::hevc_execution_target(
                format,
                hardware.adapter_luid,
                hardware.driver_version,
            )?.with_encoder(core.native_video_hevc_encoder_selection(identity)?);
            if active != Some((binding, target)) {
                capture.configure(binding.source, target)?;
                active = Some((binding, target));
                output_seen = false;
                first_deadline = Instant::now() + FIRST_FRAME_TIMEOUT;
            }
            let started = Instant::now();
            let pts = core
                .native_video_capture_pts(identity, started)
                .map_err(io::Error::other)?
                .max(previous_pts + 1)
                .max(1);
            previous_pts = pts;
            let repeated = runtime
                .block_on(core.native_video_keyframe_needed(identity, binding))
                .map_err(io::Error::other)?;
            if let Some((mut packet, receipt)) = capture.capture(pts, repeated)? {
                if packet.pts_90khz != pts {
                    return Err(io::Error::other(
                        "HEVC hardware output differs from its original accepted capture",
                    ));
                }
                receipt.check_encoded(packet.pts_90khz, &packet.data)?;
                nestlink_media_session::hevc_execution_receipt_matches(&receipt, format)?;
                runtime
                    .block_on(core.register_native_video_execution(identity, receipt.clone()))?;
                output_seen = true;
                if runtime.block_on(core.propose_native_video_format(identity, format))? {
                    runtime
                        .block_on(core.send_native_hevc_execution_frame(
                            identity,
                            binding,
                            packet.pts_90khz,
                            repeated,
                            std::mem::take(&mut *packet.data),
                            receipt,
                        ))
                        .map_err(io::Error::other)?;
                }
            } else if !output_seen && Instant::now() >= first_deadline {
                return Err(io::Error::other(
                    "HEVC original capture produced no accepted output",
                ));
            }
            let cadence =
                Duration::from_nanos(1_000_000_000 / u64::from(target.contract().config().fps));
            thread::sleep(cadence.saturating_sub(started.elapsed()).min(cadence));
        }
    })();
    let cleanup = capture.reset();
    let exit = match (result, cleanup) {
        (Ok(exit), Ok(())) => exit,
        (Err(error), _) | (_, Err(error)) => {
            eprintln!(
                "native HEVC original capture failed: {:?}; {error}",
                error.kind()
            );
            StreamExit::CaptureFailed
        }
    };
    (controller, exit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::media_format::FrameRate;
    #[test]
    fn signed_hevc_selection_never_scales_an_unapproved_monitor_or_uses_a_legacy_codec()
    -> io::Result<()> {
        let mut ptl = [0; 12];
        ptl[0] = 1;
        ptl[11] = 120;
        let format = VideoFormat::hevc_main8_observed(
            ptl,
            640,
            480,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            4000,
        )
        .map_err(io::Error::other)?;
        let signed = FormatSet::new(vec![format]).map_err(io::Error::other)?;
        let binding = NativeVideoBinding {
            source: 7,
            width: 640,
            height: 480,
            layout_epoch: 3,
        };
        assert_eq!(select_target(&signed, binding)?, format);
        assert!(
            select_target(
                &signed,
                NativeVideoBinding {
                    width: 1280,
                    ..binding
                }
            )
            .is_err()
        );
        let h264 = VideoFormat::legacy_h264(
            31,
            640,
            480,
            FrameRate::new(30, 1).map_err(io::Error::other)?,
            4000,
        )
        .map_err(io::Error::other)?;
        assert!(
            select_target(
                &FormatSet::new(vec![h264]).map_err(io::Error::other)?,
                binding
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn original_capture_cancel_latch_denies_submit_and_cannot_revive_after_checked_reset()
    -> io::Result<()> {
        let mut capture = Capture::new(Vec::new());
        let latch = capture
            .cancellation()
            .ok_or_else(|| io::Error::other("capture cancellation absent"))?;
        latch.store(true, Ordering::Release);
        assert!(capture.capture(1, false).is_err());
        assert!(capture.check().is_err());
        capture.reset()?;
        // Clearing a stale external copy cannot restore an authority generation.
        latch.store(false, Ordering::Release);
        assert!(capture.check().is_err());
        assert!(capture.capture(2, true).is_err());
        assert!(
            capture
                .state
                .lock()
                .map_err(|_| io::Error::other("fixture owner poisoned"))?
                .execution
                .is_none()
        );
        Ok(())
    }
}
