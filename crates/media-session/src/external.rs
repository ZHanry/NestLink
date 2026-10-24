//! Bounded compressed-reference handoff. Transfer acceptance is deliberately
//! distinct from real decoder output: only the latter refunds a reference.
use crate::legacy_format::LegacyPrepare;
use nestlink_media_codec::VideoCodec;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const EXTERNAL_MAX_UNITS: usize = 8;
pub const EXTERNAL_MAX_BYTES: usize = 32 * 1024 * 1024;
pub const EXTERNAL_MAX_AGE: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoSinkContext {
    pub connection_generation: u64,
    pub source: u32,
    pub stream_id: [u8; 16],
    pub stream_epoch: u64,
    pub catalog_revision: u64,
    pub selection_sequence: u64,
    pub layout_epoch: u64,
    pub decode_epoch: u64,
    pub configuration_id: u64,
}
pub struct ExternalAccessUnit {
    pub context: VideoSinkContext,
    pub delivery_sequence: u64,
    pub native_sequence: u64,
    pub pts_90khz: u64,
    pub keyframe: bool,
    pub repeated_source: bool,
    pub due: Instant,
    pub payload: Zeroizing<Vec<u8>>,
}
#[derive(Clone, Debug)]
pub enum VideoSinkFeedback {
    Prepared,
    Fence,
    Accepted {
        delivery_sequence: u64,
    },
    Decoded {
        delivery_sequence: u64,
        native_sequence: u64,
        pts_90khz: u64,
    },
    NeedKeyframe,
    Stopped {
        joined: bool,
    },
}
struct Pending {
    issued: bool,
    admitted_at: Instant,
    sequence: u64,
    pts: u64,
    bytes: usize,
    idr: bool,
}
pub(crate) struct ExternalSink {
    pub context: VideoSinkContext,
    pub width: u32,
    pub height: u32,
    pub prepared: bool,
    pub stopped: bool,
    fenced: bool,
    pub recover: bool,
    pub completed: VecDeque<(u64, u64, bool)>,
    prepare: LegacyPrepare,
    delivery: u64,
    bytes: usize,
    queued: VecDeque<(Instant, ExternalAccessUnit)>,
    pending: BTreeMap<u64, Pending>,
}
impl ExternalSink {
    pub fn new(context: VideoSinkContext, width: u32, height: u32) -> io::Result<Self> {
        Ok(Self {
            context,
            width,
            height,
            prepared: false,
            stopped: false,
            fenced: false,
            recover: true,
            completed: VecDeque::new(),
            prepare: LegacyPrepare::new(VideoCodec::H264Baseline, width, height)?,
            delivery: 0,
            bytes: 0,
            queued: VecDeque::new(),
            pending: BTreeMap::new(),
        })
    }
    pub fn surface(&self) -> crate::LegacySurface {
        self.prepare.surface()
    }
    // Keep wire identity, scheduling and admission time explicit at this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        sequence: u64,
        pts: u64,
        keyframe: bool,
        repeated_source: bool,
        due: Instant,
        payload: Zeroizing<Vec<u8>>,
        now: Instant,
    ) -> io::Result<bool> {
        if self.stopped || self.fenced || !self.prepared {
            return Ok(false);
        }
        if self
            .queued
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > EXTERNAL_MAX_AGE)
            || self.pending.len() >= EXTERNAL_MAX_UNITS
            || self.bytes.saturating_add(payload.len()) > EXTERNAL_MAX_BYTES
        {
            self.reset()?;
            return Ok(false);
        }
        if self.recover && !keyframe {
            return Ok(false);
        }
        self.prepare.validate(&payload, keyframe)?;
        self.delivery = self
            .delivery
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("external delivery exhausted"))?;
        self.bytes += payload.len();
        self.pending.insert(
            self.delivery,
            Pending {
                issued: false,
                admitted_at: now,
                sequence,
                pts,
                bytes: payload.len(),
                idr: keyframe,
            },
        );
        self.queued.push_back((
            now,
            ExternalAccessUnit {
                context: self.context.clone(),
                delivery_sequence: self.delivery,
                native_sequence: sequence,
                pts_90khz: pts,
                keyframe,
                repeated_source,
                due,
                payload,
            },
        ));
        // References may follow the admitted IDR before it produces output.
        self.recover = false;
        Ok(true)
    }
    pub fn pop(&mut self) -> Option<ExternalAccessUnit> {
        let (_, unit) = self.queued.pop_front()?;
        if let Some(pending) = self.pending.get_mut(&unit.delivery_sequence) {
            pending.issued = true;
        }
        Some(unit)
    }
    pub fn check_pressure(&mut self, now: Instant) -> io::Result<bool> {
        if self
            .pending
            .first_key_value()
            .is_some_and(|(_, p)| now.saturating_duration_since(p.admitted_at) > EXTERNAL_MAX_AGE)
        {
            self.reset()?;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn reset(&mut self) -> io::Result<()> {
        self.context.decode_epoch = self
            .context
            .decode_epoch
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("decode epoch exhausted"))?;
        self.queued.clear();
        self.pending.clear();
        self.completed.clear();
        self.bytes = 0;
        self.prepare = LegacyPrepare::new(VideoCodec::H264Baseline, self.width, self.height)?;
        self.prepared = false;
        self.recover = true;
        Ok(())
    }
    pub fn feedback(
        &mut self,
        context: &VideoSinkContext,
        feedback: VideoSinkFeedback,
    ) -> io::Result<()> {
        if context != &self.context || self.stopped {
            return Err(io::Error::other("stale external feedback"));
        }
        match feedback {
            VideoSinkFeedback::Prepared => {
                if self.fenced {
                    return Err(io::Error::other("external sink fenced"));
                }
                self.prepared = true;
            }
            VideoSinkFeedback::Fence => {
                self.fenced = true;
                self.prepared = false;
                self.queued.clear();
                self.pending.clear();
                self.completed.clear();
                self.bytes = 0;
            }
            VideoSinkFeedback::Accepted { delivery_sequence } => {
                if !self
                    .pending
                    .get(&delivery_sequence)
                    .is_some_and(|p| p.issued)
                {
                    return Err(io::Error::other("unknown external acceptance"));
                }
            }
            VideoSinkFeedback::Decoded {
                delivery_sequence,
                native_sequence,
                pts_90khz,
            } => {
                if self.completed.len() >= EXTERNAL_MAX_UNITS {
                    return Err(io::Error::other("external completion queue full"));
                }
                let Some((&first, pending)) = self.pending.first_key_value() else {
                    return Err(io::Error::other("unknown external output"));
                };
                if !pending.issued
                    || first != delivery_sequence
                    || pending.sequence != native_sequence
                    || pending.pts != pts_90khz
                {
                    return Err(io::Error::other("external output reordered or relabelled"));
                }
                let pending = self
                    .pending
                    .remove(&delivery_sequence)
                    .ok_or_else(|| io::Error::other("missing external output"))?;
                self.bytes -= pending.bytes;
                self.completed
                    .push_back((native_sequence, pts_90khz, pending.idr));
            }
            VideoSinkFeedback::NeedKeyframe => self.reset()?,
            VideoSinkFeedback::Stopped { joined } => {
                if !joined {
                    return Err(io::Error::other("external owner has not joined"));
                }
                self.stopped = true;
                self.queued.clear();
                self.pending.clear();
                self.bytes = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sink() -> io::Result<ExternalSink> {
        ExternalSink::new(
            VideoSinkContext {
                connection_generation: 1,
                source: 1,
                stream_id: [1; 16],
                stream_epoch: 1,
                catalog_revision: 1,
                selection_sequence: 1,
                layout_epoch: 1,
                decode_epoch: 1,
                configuration_id: 1,
            },
            320,
            240,
        )
    }
    #[test]
    fn prepared_legacy_surface_rejects_bad_au_before_issuing_credit() -> io::Result<()> {
        let mut s = sink()?;
        assert_eq!(
            s.surface().color,
            nestlink_protocol::media_format::Color::SDR_BT709_LIMITED
        );
        let context = s.context.clone();
        s.feedback(&context, VideoSinkFeedback::Prepared)?;
        let now = Instant::now();
        assert!(
            s.push(1, 90, true, false, now, Zeroizing::new(vec![1, 2, 3]), now)
                .is_err()
        );
        assert_eq!(s.delivery, 0);
        assert_eq!(s.bytes, 0);
        assert!(s.pending.is_empty());
        assert!(s.queued.is_empty());
        Ok(())
    }
    #[test]
    fn queued_unissued_unit_cannot_refund_credit() -> io::Result<()> {
        let mut s = sink()?;
        s.pending.insert(
            1,
            Pending {
                issued: false,
                admitted_at: Instant::now(),
                sequence: 10,
                pts: 90,
                bytes: 8,
                idr: true,
            },
        );
        s.bytes = 8;
        let c = s.context.clone();
        assert!(
            s.feedback(
                &c,
                VideoSinkFeedback::Accepted {
                    delivery_sequence: 1
                }
            )
            .is_err()
        );
        assert!(
            s.feedback(
                &c,
                VideoSinkFeedback::Decoded {
                    delivery_sequence: 1,
                    native_sequence: 10,
                    pts_90khz: 90,
                }
            )
            .is_err()
        );
        assert_eq!(s.bytes, 8);
        assert_eq!(s.pending.len(), 1);
        Ok(())
    }
    #[test]
    fn only_exact_actual_output_refunds_credit() -> io::Result<()> {
        let mut s = sink()?;
        s.pending.insert(
            1,
            Pending {
                issued: true,
                admitted_at: Instant::now(),
                sequence: 10,
                pts: 90,
                bytes: 8,
                idr: true,
            },
        );
        s.bytes = 8;
        let c = s.context.clone();
        s.feedback(
            &c,
            VideoSinkFeedback::Accepted {
                delivery_sequence: 1,
            },
        )?;
        assert_eq!(s.bytes, 8);
        assert!(
            s.feedback(
                &c,
                VideoSinkFeedback::Decoded {
                    delivery_sequence: 1,
                    native_sequence: 11,
                    pts_90khz: 90
                }
            )
            .is_err()
        );
        assert_eq!(s.bytes, 8);
        s.feedback(
            &c,
            VideoSinkFeedback::Decoded {
                delivery_sequence: 1,
                native_sequence: 10,
                pts_90khz: 90,
            },
        )?;
        assert_eq!(s.bytes, 0);
        assert!(
            s.feedback(
                &c,
                VideoSinkFeedback::Decoded {
                    delivery_sequence: 1,
                    native_sequence: 10,
                    pts_90khz: 90
                }
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn reset_fences_old_feedback_and_requires_preparation() -> io::Result<()> {
        let mut s = sink()?;
        let c = s.context.clone();
        s.prepared = true;
        s.reset()?;
        assert!(!s.prepared);
        assert!(s.feedback(&c, VideoSinkFeedback::Prepared).is_err());
        let c = s.context.clone();
        assert!(
            s.feedback(&c, VideoSinkFeedback::Stopped { joined: false })
                .is_err()
        );
        assert!(!s.stopped);
        Ok(())
    }
    #[test]
    fn stalled_reference_fences_epoch_without_refunding_a_replay() -> io::Result<()> {
        let mut s = sink()?;
        let now = Instant::now();
        let old = s.context.clone();
        s.pending.insert(
            1,
            Pending {
                issued: true,
                admitted_at: now,
                sequence: 1,
                pts: 0,
                bytes: 8,
                idr: true,
            },
        );
        s.bytes = 8;
        s.prepared = true;
        assert!(s.check_pressure(now + EXTERNAL_MAX_AGE + Duration::from_millis(1))?);
        assert_eq!(s.context.decode_epoch, old.decode_epoch + 1);
        assert_eq!(s.bytes, 0);
        assert!(!s.prepared);
        assert!(
            s.feedback(
                &old,
                VideoSinkFeedback::Decoded {
                    delivery_sequence: 1,
                    native_sequence: 1,
                    pts_90khz: 0
                }
            )
            .is_err()
        );
        Ok(())
    }
}
