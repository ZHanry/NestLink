const test = require('node:test');
const assert = require('node:assert/strict');
const { videoInterval, audioInterval } = require('../../scripts/lib/refactor-browser-media-metrics.cjs');

const profile = { width: 1920, height: 1080, fps: 30, minimum_decoded_fps: 27 };
const sample = (seconds, frames) => ({ monotonic_ms: seconds * 1000,
  video_width: 1920, video_height: 1080, peer_states: ['connected'], video_time: seconds,
  inbound: [{ id: 'owned-video', codec: 'video/VP8', framesDecoded: frames, bytesReceived: frames * 1000 }],
  pixel: [210, 100, 40, 255] });

test('measures actual receiver frames over a full observation interval', () => {
  const result = videoInterval(sample(2, 60), sample(14, 420), profile);
  assert.equal(result.decoded_fps, 30);
  assert.equal(result.decoded_frames, 360);
});
test('rejects a moving media clock when decoding has stopped', () => {
  assert.throws(() => videoInterval(sample(2, 60), sample(14, 60), profile), /advancing/);
});
test('reports insufficient decoded frame rate independently of media time', () => {
  assert.throws(() => videoInterval(sample(2, 60), sample(14, 300), profile), /below 27 fps: 20.00/);
});
test('rejects counter resets, missing stats and a changed stream identity', () => {
  for (const change of [item => { item.framesDecoded = 0; }, item => { item.framesDecoded = null; },
    item => { item.id = 'replacement'; }, item => { item.codec = 'video/H264'; }]) {
    const current = sample(14, 420);
    change(current.inbound[0]);
    assert.throws(() => videoInterval(sample(2, 60), current, profile));
  }
});
test('rejects long sampling gaps, wrong geometry and unowned pixels', () => {
  for (const change of [value => { value.monotonic_ms = 25000; }, value => { value.video_width = 320; },
    value => { value.pixel = [0, 0, 0, 255]; }, value => { value.peer_states = ['disconnected']; },
    value => { value.video_time = Number.NaN; }]) {
    const current = sample(14, 420);
    change(current);
    assert.throws(() => videoInterval(sample(2, 60), current, profile));
  }
});

test('measures Opus decoded samples independently of video playback', () => {
  const before = { monotonic_ms: 0, audio: [{ id: 'owned-audio', codec: 'audio/opus', totalSamplesReceived: 960, packetsReceived: 1 }] };
  const after = { monotonic_ms: 12000, audio: [{ id: 'owned-audio', codec: 'audio/opus', totalSamplesReceived: 576960, packetsReceived: 601 }] };
  assert.equal(audioInterval(before, after).sample_rate, 48000);
  for (const change of [item => { item.totalSamplesReceived = 960; }, item => { item.packetsReceived = 1; },
    item => { item.codec = 'audio/AAC'; }, item => { item.totalSamplesReceived = null; }]) {
    const changed = structuredClone(after);
    change(changed.audio[0]);
    assert.throws(() => audioInterval(before, changed));
  }
});
