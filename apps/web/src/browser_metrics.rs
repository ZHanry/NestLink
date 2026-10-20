//! Sanitized WebRTC receiver counters. No SDP, candidate addresses, credentials
//! or clipboard/file contents enter this model or its diagnostic export.
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct MediaSample {
    pub sampled_at_ms: f64,
    pub bytes: Option<f64>,
    pub frames: Option<f64>,
    pub packets: Option<f64>,
    pub lost: Option<f64>,
    pub dropped: Option<f64>,
    pub decode_seconds: Option<f64>,
    pub buffer_seconds: Option<f64>,
    pub buffer_count: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub codec: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct MediaStatistics {
    pub sample: MediaSample,
    pub fps: Option<f64>,
    pub kbps: Option<f64>,
    pub loss_percent: Option<f64>,
    pub decode_ms: Option<f64>,
    pub jitter_buffer_ms: Option<f64>,
}
fn difference(now: Option<f64>, before: Option<f64>) -> Option<f64> {
    let difference = now? - before?;
    (difference.is_finite() && difference >= 0.0).then_some(difference)
}
impl MediaStatistics {
    pub fn between(sample: MediaSample, previous: Option<&MediaSample>) -> Self {
        let mut stats = Self {
            sample,
            ..Self::default()
        };
        let Some(before) = previous else {
            return stats;
        };
        if stats.sample.codec != before.codec
            || stats.sample.width != before.width
            || stats.sample.height != before.height
        {
            return stats;
        }
        let milliseconds = stats.sample.sampled_at_ms - before.sampled_at_ms;
        if !(250.0..=10_000.0).contains(&milliseconds) {
            return stats;
        }
        let frames = difference(stats.sample.frames, before.frames);
        stats.fps = frames.map(|value| value * 1000.0 / milliseconds);
        stats.kbps =
            difference(stats.sample.bytes, before.bytes).map(|value| value * 8.0 / milliseconds);
        stats.loss_percent = difference(stats.sample.packets, before.packets)
            .zip(difference(stats.sample.lost, before.lost))
            .and_then(|(packets, lost)| {
                (packets + lost > 0.0).then_some(lost * 100.0 / (packets + lost))
            });
        stats.decode_ms = difference(stats.sample.decode_seconds, before.decode_seconds)
            .zip(frames)
            .and_then(|(time, frames)| (frames > 0.0).then_some(time * 1000.0 / frames));
        stats.jitter_buffer_ms = difference(stats.sample.buffer_seconds, before.buffer_seconds)
            .zip(difference(stats.sample.buffer_count, before.buffer_count))
            .and_then(|(time, frames)| (frames > 0.0).then_some(time * 1000.0 / frames));
        stats
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn from_report(report: &web_sys::RtcStatsReport, sampled_at_ms: f64) -> MediaSample {
    use wasm_bindgen::JsValue;
    let property = |value: &JsValue, name: &str| js_sys::Reflect::get(value, &name.into()).ok();
    let string =
        |value: &JsValue, name: &str| property(value, name).and_then(|value| value.as_string());
    let number = |value: &JsValue, name: &str| {
        property(value, name)
            .and_then(|value| value.as_f64())
            .filter(|value| value.is_finite() && *value >= 0.0 && *value <= 9_007_199_254_740_991.0)
    };
    let mut sample = MediaSample {
        sampled_at_ms,
        ..MediaSample::default()
    };
    let transports = report.values();
    let mut selected_pair = None;
    for _ in 0..1024 {
        let Ok(entry) = transports.next() else {
            break;
        };
        if entry.done() {
            break;
        }
        let value = entry.value();
        if string(&value, "type").as_deref() == Some("transport")
            && let Some(id) = string(&value, "selectedCandidatePairId")
        {
            selected_pair = Some(id);
            break;
        }
    }
    let iterator = report.values();
    // The product has one video transceiver. Bound iteration even if a browser
    // implementation supplies unrelated or malformed statistics.
    for _ in 0..1024 {
        let Ok(entry) = iterator.next() else {
            break;
        };
        if entry.done() {
            break;
        }
        let value = entry.value();
        match string(&value, "type").as_deref() {
            Some("candidate-pair")
                if selected_pair
                    .as_ref()
                    .is_some_and(|id| string(&value, "id").as_ref() == Some(id))
                    || (selected_pair.is_none()
                        && (property(&value, "selected").and_then(|value| value.as_bool())
                            == Some(true)
                            || (property(&value, "nominated")
                                .and_then(|value| value.as_bool())
                                == Some(true)
                                && string(&value, "state").as_deref() == Some("succeeded")))) =>
            {
                sample.rtt_ms = number(&value, "currentRoundTripTime").map(|value| value * 1000.0);
            }
            Some("inbound-rtp")
                if string(&value, "kind")
                    .or_else(|| string(&value, "mediaType"))
                    .as_deref()
                    == Some("video") =>
            {
                sample.bytes = number(&value, "bytesReceived");
                sample.frames = number(&value, "framesDecoded");
                sample.packets = number(&value, "packetsReceived");
                sample.lost = number(&value, "packetsLost");
                sample.dropped = number(&value, "framesDropped");
                sample.decode_seconds = number(&value, "totalDecodeTime");
                sample.buffer_seconds = number(&value, "jitterBufferDelay");
                sample.buffer_count = number(&value, "jitterBufferEmittedCount");
                sample.width = number(&value, "frameWidth");
                sample.height = number(&value, "frameHeight");
                sample.codec = string(&value, "codecId")
                    .and_then(|id| report.get(&id))
                    .and_then(|codec| string(&codec, "mimeType"))
                    .filter(|codec| {
                        matches!(
                            codec.to_ascii_lowercase().as_str(),
                            "video/vp8" | "video/h264" | "video/h265" | "video/av1" | "video/vp9"
                        )
                    });
            }
            _ => {}
        }
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_use_counter_deltas_and_resets_remain_unknown() {
        let before = MediaSample {
            sampled_at_ms: 1000.0,
            bytes: Some(100_000.0),
            frames: Some(20.0),
            packets: Some(100.0),
            lost: Some(1.0),
            decode_seconds: Some(0.04),
            ..MediaSample::default()
        };
        let now = MediaSample {
            sampled_at_ms: 2000.0,
            bytes: Some(200_000.0),
            frames: Some(80.0),
            packets: Some(199.0),
            lost: Some(2.0),
            decode_seconds: Some(0.16),
            ..MediaSample::default()
        };
        let stats = MediaStatistics::between(now, Some(&before));
        assert_eq!(stats.fps, Some(60.0));
        assert_eq!(stats.kbps, Some(800.0));
        assert_eq!(stats.loss_percent, Some(1.0));
        assert_eq!(stats.decode_ms, Some(2.0));
        assert!(stats.jitter_buffer_ms.is_none());
        let reset = MediaStatistics::between(
            MediaSample {
                sampled_at_ms: 2000.0,
                bytes: Some(0.0),
                frames: Some(0.0),
                ..MediaSample::default()
            },
            Some(&before),
        );
        assert!(reset.fps.is_none() && reset.kbps.is_none());
        assert!(MediaStatistics::between(before, None).fps.is_none());
    }
}
