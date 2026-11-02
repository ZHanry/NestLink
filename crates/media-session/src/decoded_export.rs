//! Finite original-decoder export authority. Completion means transferred bytes,
//! never a GPU submission, shared texture, decoder handoff or Presented receipt.
use crate::{DecodedVideo, LiveExecutionIdentity, LiveExecutionReceipt};
use std::{
    io,
    time::{Duration, Instant},
};

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExportIdentity {
    connection: u64,
    layout: u64,
    source: u32,
    width: u32,
    height: u32,
    codec: u8,
    hardware_decode: bool,
    execution: Option<LiveExecutionIdentity>,
    format_sha256: Option<[u8; 32]>,
}

/// One original consumer stream, one in-flight frame, bounded bytes and age.
/// A new layout/format/execution requires closing this consumer and opening a
/// fresh authenticated stream. This type cannot mint or deserialize an owner.
#[derive(Default)]
pub struct DecodedExportLedger {
    identity: Option<ExportIdentity>,
    last_sequence: u64,
    last_pts: u64,
    issued: u64,
    pending: bool,
    retired: bool,
}
impl DecodedExportLedger {
    pub fn begin(&mut self, frame: &DecodedVideo) -> io::Result<DecodedFrameExport<'_>> {
        self.begin_at(frame, Instant::now())
    }
    fn begin_at(
        &mut self,
        frame: &DecodedVideo,
        now: Instant,
    ) -> io::Result<DecodedFrameExport<'_>> {
        if self.retired || self.pending {
            return Err(io::Error::other(
                "decoded export consumer retired or occupied",
            ));
        }
        let expected_bytes = (frame.width as usize)
            .checked_mul(frame.height as usize)
            .and_then(|pixels| pixels.checked_mul(4));
        if frame.width == 0
            || frame.height == 0
            || frame.width > 8192
            || frame.height > 8192
            || !frame.width.is_multiple_of(2)
            || !frame.height.is_multiple_of(2)
            || frame.pixels.len() > MAX_BYTES
            || expected_bytes != Some(frame.pixels.len())
            || frame.epoch.connection == 0
            || frame.epoch.connection > i64::MAX as u64
            || frame.epoch.layout == 0
            || frame.epoch.layout > i64::MAX as u64
            || frame.sequence == 0
            || frame.sequence > i64::MAX as u64
            || frame.sequence <= self.last_sequence
            || frame.pts_90khz > i64::MAX as u64
            || (self.last_sequence > 0 && frame.pts_90khz <= self.last_pts)
        {
            return Err(io::Error::other(
                "decoded export frame identity or budget invalid",
            ));
        }
        // This checks actual pixel hash, direction, codec and exact geometry
        // once. Subsequent chunk checks retain this same unforgeable fence.
        let execution = frame.export_execution()?;
        let identity = ExportIdentity {
            connection: frame.epoch.connection,
            layout: frame.epoch.layout,
            source: frame.source,
            width: frame.width,
            height: frame.height,
            codec: frame.codec,
            hardware_decode: frame.hardware_decode,
            execution: execution
                .as_ref()
                .map(LiveExecutionReceipt::identity)
                .transpose()?,
            format_sha256: execution
                .as_ref()
                .map(|value| value.target().format_digest()),
        };
        if self.identity.is_some_and(|original| original != identity) {
            self.retired = true;
            return Err(io::Error::other(
                "decoded export original owner or context changed",
            ));
        }
        self.issued = self
            .issued
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("decoded export sequence exhausted"))?;
        self.identity = Some(identity);
        self.pending = true;
        Ok(DecodedFrameExport {
            ledger: self,
            execution,
            sequence: frame.sequence,
            pts: frame.pts_90khz,
            bytes: frame.pixels.len(),
            transferred: 0,
            deadline: now + MAX_AGE,
            complete: false,
        })
    }
}

/// Held only by the original sender. It is deliberately not Clone, serde data
/// or a public constructor from an IPC owner UUID or client acknowledgement.
pub struct DecodedFrameExport<'a> {
    ledger: &'a mut DecodedExportLedger,
    execution: Option<LiveExecutionReceipt>,
    sequence: u64,
    pts: u64,
    bytes: usize,
    transferred: usize,
    deadline: Instant,
    complete: bool,
}
impl DecodedFrameExport<'_> {
    pub fn check_current(&self) -> io::Result<()> {
        self.check_at(Instant::now())
    }
    fn check_at(&self, now: Instant) -> io::Result<()> {
        if self.complete || self.ledger.retired || !self.ledger.pending || now >= self.deadline {
            return Err(io::Error::other(
                "decoded export authority retired or expired",
            ));
        }
        if let Some(execution) = &self.execution {
            execution.check_current()?;
        }
        Ok(())
    }
    /// Call only after the original authenticated stream accepted these bytes.
    /// It records transfer progress, not remote decoding or GPU consumption.
    pub fn transferred(&mut self, bytes: usize) -> io::Result<()> {
        self.check_current()?;
        let Some(total) = self
            .transferred
            .checked_add(bytes)
            .filter(|value| bytes > 0 && *value <= self.bytes)
        else {
            self.ledger.retired = true;
            return Err(io::Error::other(
                "decoded export transfer exceeds admitted output",
            ));
        };
        self.transferred = total;
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<()> {
        self.check_current()?;
        if self.transferred != self.bytes {
            return Err(io::Error::other("decoded export transfer is incomplete"));
        }
        self.ledger.last_sequence = self.sequence;
        self.ledger.last_pts = self.pts;
        self.ledger.pending = false;
        self.complete = true;
        Ok(())
    }
}
impl Drop for DecodedFrameExport<'_> {
    fn drop(&mut self) {
        self.ledger.pending = false;
        if !self.complete {
            // An interrupted stream cannot reuse an uncertain partial transfer.
            // This retires only its export, not the independent decoder owner.
            self.ledger.retired = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::media_format::Color;
    use nestlink_remote::video::VideoEpoch;

    fn frame(sequence: u64, pts: u64) -> DecodedVideo {
        DecodedVideo {
            execution: None,
            source_color: Color::LEGACY_VP8_BT601,
            codec: 0,
            hardware_decode: false,
            epoch: VideoEpoch {
                connection: 1,
                layout: 1,
            },
            source: 1,
            sequence,
            pts_90khz: pts,
            width: 2,
            height: 2,
            pixels: vec![0; 16],
            repeated_source: false,
        }
    }
    #[test]
    fn bounded_transfer_is_not_a_decode_or_presentation_acknowledgement() -> io::Result<()> {
        let mut ledger = DecodedExportLedger::default();
        let mut export = ledger.begin(&frame(1, 0))?;
        export.transferred(8)?;
        export.transferred(8)?;
        export.finish()?;
        assert!(!ledger.pending);
        assert!(!ledger.retired);
        assert_eq!(ledger.last_sequence, 1);
        assert!(
            ledger
                .identity
                .is_some_and(|identity| identity.execution.is_none())
        );
        assert!(ledger.begin(&frame(1, 1)).is_err());
        assert!(ledger.begin(&frame(2, 0)).is_err());
        ledger.begin(&frame(2, 1))?.transferred(16)?;
        // Dropping without finish retires the stream even if all bytes moved.
        assert!(ledger.retired);
        Ok(())
    }
    #[test]
    fn incomplete_overflow_expiry_and_context_change_retire_export() -> io::Result<()> {
        let mut incomplete = DecodedExportLedger::default();
        assert!(incomplete.begin(&frame(1, 0))?.finish().is_err());
        assert!(incomplete.retired);
        let mut ledger = DecodedExportLedger::default();
        let mut export = ledger.begin(&frame(1, 0))?;
        assert!(export.transferred(17).is_err());
        assert!(export.transferred(16).is_err());
        drop(export);
        assert!(ledger.begin(&frame(2, 1)).is_err());
        let mut expired = DecodedExportLedger::default();
        let export = expired.begin(&frame(1, 0))?;
        assert!(
            export
                .check_at(export.deadline - Duration::from_nanos(1))
                .is_ok()
        );
        assert!(export.check_at(export.deadline).is_err());
        drop(export);
        assert!(expired.retired);
        let mut ledger = DecodedExportLedger::default();
        let mut export = ledger.begin(&frame(1, 0))?;
        export.transferred(16)?;
        export.finish()?;
        let mut different = frame(2, 1);
        different.epoch.layout = 2;
        assert!(ledger.begin(&different).is_err());
        assert!(ledger.retired);
        Ok(())
    }
    #[test]
    fn hevc_metadata_without_original_sealed_output_cannot_open_export() {
        let mut ledger = DecodedExportLedger::default();
        let mut hevc = frame(1, 0);
        hevc.codec = nestlink_protocol::NativeVideoCodec::HevcMain8 as u8;
        hevc.hardware_decode = true;
        assert!(ledger.begin(&hevc).is_err());
        assert!(!ledger.pending);
    }
}
