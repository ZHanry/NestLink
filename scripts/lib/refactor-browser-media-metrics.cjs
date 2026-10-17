// Inspect receiver counters independently of the HTML media clock. A playing
// video element alone cannot prove that new RTP frames continue to decode.
function videoInterval(previous, current, profile) {
  const seconds = (current.monotonic_ms - previous.monotonic_ms) / 1000;
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 20) {
    throw new Error('Video observation interval is invalid or exceeded 20 seconds');
  }
  if (current.video_width !== profile.width || current.video_height !== profile.height) {
    throw new Error('Decoded native video geometry changed');
  }
  if (!current.peer_states.includes('connected')) throw new Error('Real native WebRTC peer disconnected');
  if (!Number.isFinite(current.video_time) || !Number.isFinite(previous.video_time) ||
      current.video_time - previous.video_time < seconds * 0.6) {
    throw new Error('Decoded native video media clock stopped advancing');
  }
  const before = new Map(previous.inbound.map(item => [item.id, item]));
  if (current.inbound.length !== 1) throw new Error('Expected exactly one native inbound video stream');
  const stream = current.inbound[0];
  const original = before.get(stream.id);
  if (!original || stream.codec?.toLowerCase() !== 'video/vp8') {
    throw new Error('Inbound video identity or VP8 codec changed');
  }
  if (![stream.framesDecoded, original.framesDecoded, stream.bytesReceived, original.bytesReceived]
    .every(value => Number.isSafeInteger(value) && value >= 0)) {
    throw new Error('Browser did not expose valid decoded-frame and byte counters');
  }
  const frames = stream.framesDecoded - original.framesDecoded;
  const bytes = stream.bytesReceived - original.bytesReceived;
  if (!Number.isSafeInteger(frames) || frames <= 0 || !Number.isSafeInteger(bytes) || bytes <= 0) {
    throw new Error('Browser lacks advancing decoded inbound RTP video counters');
  }
  const fps = frames / seconds;
  if (fps < profile.minimum_decoded_fps) {
    throw new Error(`Decoded video fell below ${profile.minimum_decoded_fps} fps: ${fps.toFixed(2)}`);
  }
  if (current.pixel?.length !== 4 || Math.abs(current.pixel[0] - 210) > 12 ||
      Math.abs(current.pixel[2] - 40) > 12 || current.pixel[3] !== 255) {
    throw new Error('Decoded native video does not contain the owned synthetic capture pixels');
  }
  return { seconds, decoded_frames: frames, received_bytes: bytes, decoded_fps: fps };
}

function audioInterval(previous, current) {
  const seconds = (current.monotonic_ms - previous.monotonic_ms) / 1000;
  if (!(seconds > 0 && seconds <= 20) || previous.audio?.length !== 1 || current.audio?.length !== 1) {
    throw new Error('Expected one continuously observed native audio stream');
  }
  const original = previous.audio[0], stream = current.audio[0];
  if (stream.id !== original.id || stream.codec?.toLowerCase() !== 'audio/opus' ||
      ![stream.totalSamplesReceived, original.totalSamplesReceived, stream.packetsReceived, original.packetsReceived]
        .every(value => Number.isSafeInteger(value) && value >= 0)) {
    throw new Error('Inbound Opus identity or decoded-sample counters changed');
  }
  const samples = stream.totalSamplesReceived - original.totalSamplesReceived;
  const packets = stream.packetsReceived - original.packetsReceived;
  if (samples / seconds < 48_000 * 0.9 || packets / seconds < 45) {
    throw new Error('Native Opus reception or decoded samples stopped advancing at the requested rate');
  }
  return { seconds, decoded_samples: samples, received_packets: packets,
    sample_rate: samples / seconds, packets_per_second: packets / seconds };
}

module.exports = { videoInterval, audioInterval };
