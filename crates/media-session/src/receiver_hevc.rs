//! Actual hardware HEVC readback consumer on the original receiver worker.
//! Desktop GPU handoff remains a distinct owner and cannot borrow this UUID.
use super::*;
use nestlink_media_codec::{HardwareHevcExecution, HevcExecutionOutput, HevcExecutionTicket};
use nestlink_protocol::{
    media_authority::MediaDirection,
    media_format::{Codec, FormatSet},
};

pub(super) fn prepare(
    decoder: &mut Decoder,
    layout: VideoLayout,
    revision: u64,
    formats: &FormatSet,
    selected: Option<&nestlink_protocol::native_media_format::FormatSelection>,
    lease: &LeaseControl,
    output: &Output,
) -> io::Result<()> {
    if formats.formats().iter().any(|f| f.codec != Codec::Hevc)
        || lease
            .local_media_backend(MediaDirection::Decode)
            .map_err(io::Error::other)?
            .as_deref()
            != Some("gpu-hevc-decoder")
    {
        return Err(io::Error::other(
            "HEVC decoder lacks its independent exact local scope",
        ));
    }
    if output
        .external
        .lock()
        .map_err(|_| io::Error::other("external sink poisoned"))?
        .is_some()
    {
        return Err(io::Error::other(
            "HEVC original readback owner cannot replace an external owner",
        ));
    }
    let format = if let Some(selected) = selected {
        if !formats.contains(&selected.format) {
            return Err(io::Error::other(
                "HEVC selected format is outside signed scope",
            ));
        }
        selected.format
    } else {
        formats
            .formats()
            .iter()
            .filter(|f| (f.width, f.height) == (layout.width, layout.height))
            .filter(|f| crate::hevc_contract(**f).is_ok())
            .max_by_key(|f| (f.frame_rate.numerator, f.max_kbps))
            .copied()
            .ok_or_else(|| io::Error::other("approved display lacks an exact signed HEVC target"))?
    };
    let config = crate::hevc_contract(format)?.config();
    if (config.width, config.height) != (layout.width, layout.height) {
        return Err(io::Error::other(
            "HEVC original display and execution geometry differ",
        ));
    }
    let hardware = lease
        .local_media_hardware_target(MediaDirection::Decode)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("HEVC original decoder hardware target absent"))?;
    let target =
        crate::hevc_execution_target(format, hardware.adapter_luid, hardware.driver_version)?;
    lease
        .check_media_binding(Channel::Video, layout.epoch.connection)
        .map_err(io::Error::other)?;
    let mut owner = HardwareHevcExecution::start_decode(
        target,
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
    )?;
    let execution = owner.current()?;
    crate::hevc_execution_receipt_matches(&execution, format)?;
    let mut state = output
        .state
        .lock()
        .map_err(|_| io::Error::other("media output poisoned"))?;
    if state.selected != Some(layout)
        || state.catalog.as_ref().map(|(key, _)| key.revision) != Some(revision)
        || state.closed
        || lease
            .check_media_binding(Channel::Video, layout.epoch.connection)
            .is_err()
    {
        owner.shutdown()?;
        return Err(io::Error::other(
            "HEVC display or lease changed during actual decoder preparation",
        ));
    }
    decoder.stream.codec = config;
    decoder.hevc = Some(owner);
    state.execution = Some(execution.into());
    output
        .prepared
        .send_replace(DecoderReadiness::Display(layout, revision));
    Ok(())
}
fn wait(mut ticket: HevcExecutionTicket, deadline: Instant) -> io::Result<HevcExecutionOutput> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC original receiver operation deadline",
            ));
        }
        if let Some(output) = ticket.try_poll()? {
            return Ok(output);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
impl Decoder {
    pub(super) fn decode_hevc(
        &mut self,
        packet: NativeVideo,
        payload: Zeroizing<Vec<u8>>,
        epoch: VideoEpoch,
        now: Instant,
    ) -> io::Result<Option<(DecodedVideo, bool)>> {
        let format = self
            .format
            .as_ref()
            .ok_or_else(|| io::Error::other("HEVC bytes preceded exact format ACK"))?
            .format;
        let owner = self
            .hevc
            .as_ref()
            .ok_or_else(|| io::Error::other("HEVC original decoder generation is absent"))?;
        crate::hevc_execution_receipt_matches(&owner.current()?, format)?;
        if !packet.keyframe || self.pending.len() >= 8 || self.hevc_ready.len() >= 8 {
            return Err(io::Error::other(
                "HEVC exact IDR or bounded receiver ledger violated",
            ));
        }
        let deadline = now + Duration::from_millis(500);
        let mut accepted = false;
        while !accepted || self.hevc_ready.is_empty() {
            let submitting = !accepted;
            let ticket = if submitting {
                owner.submit_decode(payload.to_vec(), packet.pts_90khz)?
            } else {
                owner.poll_output()?
            };
            let output = wait(ticket, deadline)?;
            let HevcExecutionOutput::Decoded {
                accepted: input_accepted,
                output,
            } = output
            else {
                return Err(io::Error::other(
                    "HEVC receive worker returned a different operation",
                ));
            };
            if submitting && input_accepted {
                accepted = true;
                self.pending
                    .insert(packet.pts_90khz, (packet.sequence, packet.repeated_source));
            }
            if let Some((mut picture, receipt)) = output {
                receipt.check_decoded(picture.pts_90khz, &picture.bgra)?;
                crate::hevc_execution_receipt_matches(&receipt, format)?;
                let (sequence, repeated_source) =
                    self.pending.remove(&picture.pts_90khz).ok_or_else(|| {
                        io::Error::other("HEVC actual output has no accepted input identity")
                    })?;
                self.hevc_ready.push_back(DecodedVideo {
                    execution: Some(receipt.into()),
                    shared: picture.shared.take(),
                    source_color: format.color,
                    codec: crate::hevc_wire_codec(format)? as u8,
                    hardware_decode: true,
                    epoch,
                    source: packet.source,
                    sequence,
                    pts_90khz: picture.pts_90khz,
                    width: packet.width,
                    height: packet.height,
                    pixels: std::mem::take(&mut *picture.bgra),
                    repeated_source,
                });
            }
            if !accepted || self.hevc_ready.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.awaiting_keyframe = false;
        self.deadline(Instant::now())?;
        let frame = self.hevc_ready.pop_front();
        let recovered = frame.is_some() && self.recovery.take().is_some();
        Ok(frame.map(|frame| (frame, recovered)))
    }
}
