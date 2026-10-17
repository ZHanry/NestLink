const test = require('node:test');
const assert = require('node:assert/strict');
const { prepareNetworkDamage, exerciseNetworkDamage, observedDamage, assertStableSignaling } = require('../../scripts/lib/refactor-browser-network-damage.cjs');

const observation = (changes = {}) => ({ signaling_states: ['stable'], inbound: [{ id: 'owned-video', codec: 'video/VP8',
  framesDecoded: 100, bytesReceived: 5000, packetsReceived: 120, packetsLost: 0,
  nackCount: 0, pliCount: 0, ...changes }] });

test('page-scoped throughput changes cannot trigger SDP renegotiation', () => {
  assert.doesNotThrow(() => assertStableSignaling(observation()));
  assert.throws(() => assertStableSignaling({ ...observation(), signaling_states: ['have-local-offer'] }),
    /unexpectedly initiated WebRTC renegotiation/);
  assert.throws(() => assertStableSignaling({ ...observation(), signaling_states: ['closed'] }),
    /unexpectedly initiated WebRTC renegotiation/);
});

test('observed transient loss remains evidence after successful retransmission', () => {
  const result = observedDamage(observation(), observation({ framesDecoded: 180,
    bytesReceived: 8000, packetsReceived: 201, packetsLost: -1, nackCount: 3 }),
  [observation({ packetsLost: 4, nackCount: 2 })]);
  assert.equal(result.packetsLost, -1);
  assert.equal(result.peak_packets_lost_delta, 4);
  assert.equal(result.nackCount, 3);
});

test('a successful browser emulation command cannot substitute for receiver evidence', () => {
  assert.throws(() => observedDamage(observation(), observation({ framesDecoded: 180,
    bytesReceived: 8000, packetsReceived: 200 })), /did not prove/);
  assert.throws(() => observedDamage(observation(), observation({ packetsLost: 4 })), /did not prove/);
  assert.throws(() => observedDamage(observation(), observation({ nackCount: 4 })), /did not prove/);
});

test('new RTP identities and reset counters cannot be counted as recovery', () => {
  assert.throws(() => observedDamage(observation(), observation({ id: 'replacement',
    packetsLost: 4, nackCount: 1 })), /identity/);
  assert.throws(() => observedDamage(observation(), observation({ packetsLost: 4,
    nackCount: 1 }), [observation({ id: 'replacement' })]), /identity/);
  assert.throws(() => observedDamage(observation(), observation({ framesDecoded: 99,
    packetsLost: 4, nackCount: 1 })), /reset/);
});

test('unavailable feedback counters cannot be silently treated as zero', () => {
  for (const missing of ['nackCount', 'pliCount', 'packetsLost']) {
    assert.throws(() => observedDamage(observation(), observation({ packetsLost: 4,
      nackCount: 1, [missing]: null })), /requires an available/);
  }
});

test('an intermediate counter reset cannot be hidden by larger final counters', () => {
  assert.throws(() => observedDamage(observation({ nackCount: 2 }),
    observation({ framesDecoded: 180, bytesReceived: 8000, packetsReceived: 201,
      packetsLost: 4, nackCount: 3 }),
    [observation({ packetsLost: 4, nackCount: 1 })]), /reset/);
});

function ownedPage({ failSend, failDetach, url = 'about:blank', owned = true } = {}) {
  const calls = [];
  const session = {
    async send(method, params) {
      calls.push({ method, params });
      const error = failSend?.(method, params);
      if (error) throw error;
      return {};
    },
    async detach() {
      calls.push({ method: 'detach' });
      if (failDetach) throw failDetach;
    },
  };
  const page = { url: () => url, evaluate: async () => owned,
    async createCDPSession() { calls.push({ method: 'createCDPSession' }); return session; } };
  return { page, calls };
}

const origin = 'https://127.0.0.1:43817';
const conditions = calls => calls.filter(call => call.method === 'Network.emulateNetworkConditions').map(call => call.params);
const neutral = value => value.latency === 0 && value.packetLoss === 0 && value.offline === false &&
  value.downloadThroughput === -1 && value.uploadThroughput === -1 && value.packetQueueLength === 0 && value.packetReordering === false;

test('the fresh-page owner installs a live P2P session before RTC and explicitly restores/detaches', async () => {
  const { page, calls } = ownedPage();
  const facts = {};
  const owner = await prepareNetworkDamage({ page, origin, facts });
  assert.deepEqual(calls.map(item => item.method), ['createCDPSession', 'Network.enable', 'Network.emulateNetworkConditions']);
  assert.equal(conditions(calls)[0].latency, 1);
  assert.equal(conditions(calls)[0].packetLoss, 0);
  assert.equal(facts.prepared_before_rtc, true);
  assert.equal(facts.session_detached, false);
  await owner.close();
  assert.equal(neutral(conditions(calls).at(-1)), true);
  assert.deepEqual(calls.slice(-2).map(item => item.method), ['Network.disable', 'detach']);
  assert.equal(facts.conditions_restored, true);
  assert.equal(facts.session_detached, true);
  assert.equal(facts.network_disabled, true);
  assert.equal(facts.passed, false); // Command acknowledgement is not RTP evidence.
});

test('preparation rejects a loaded page or another origin before acquiring CDP resources', async () => {
  for (const destination of ['http://127.0.0.1:43817', 'https://example.com:43817', 'https://127.0.0.1', origin + '/elsewhere']) {
    const { page, calls } = ownedPage();
    await assert.rejects(prepareNetworkDamage({ page, origin: destination, facts: {} }), /owned HTTPS loopback/);
    assert.equal(calls.length, 0);
  }
  const { page, calls } = ownedPage({ url: origin });
  await assert.rejects(prepareNetworkDamage({ page, origin, facts: {} }), /before navigation and RTC creation/);
  assert.equal(calls.length, 0);
});

test('partial enable and interceptor setup failures each clear conditions and detach the owner', async () => {
  for (const operation of ['enable', 'interceptor']) {
    const initial = new Error('initial ' + operation + ' failed');
    const { page, calls } = ownedPage({ failSend: (method, params) =>
      (operation === 'enable' && method === 'Network.enable') ||
      (operation === 'interceptor' && method === 'Network.emulateNetworkConditions' && params.latency === 1) ? initial : null });
    const facts = {};
    await assert.rejects(prepareNetworkDamage({ page, origin, facts }), error => error === initial);
    assert.equal(neutral(conditions(calls).at(-1)), true);
    assert.equal(facts.conditions_restored, true);
    assert.equal(facts.session_detached, true);
    assert.equal(facts.passed, false);
    assert.equal(facts.error, initial.message);
    assert.deepEqual(facts.cleanup_errors, []);
  }
});

test('a restore error still disables and detaches, retains the failure and cannot become a pass', async () => {
  const { page, calls } = ownedPage({ failSend: (method, params) =>
    method === 'Network.emulateNetworkConditions' && params.latency === 0 ? new Error('restore rejected') : null });
  const facts = {};
  const owner = await prepareNetworkDamage({ page, origin, facts });
  await assert.rejects(owner.close(), /cleanup failed/);
  const count = calls.length;
  await assert.rejects(owner.close(), /cleanup failed/);
  assert.equal(calls.length, count);
  assert.equal(facts.conditions_restored, false);
  assert.equal(facts.network_disabled, true);
  assert.equal(facts.session_detached, true);
  assert.equal(facts.cleanup_errors[0].operation, 'restore');
  assert.equal(facts.passed, false);
});

test('disable and detach failures remain observable and do not suppress the other cleanup steps', async () => {
  for (const operation of ['disable', 'detach']) {
    const failure = new Error(operation + ' rejected');
    const { page, calls } = ownedPage({
      failSend: method => operation === 'disable' && method === 'Network.disable' ? failure : null,
      failDetach: operation === 'detach' ? failure : null,
    });
    const facts = {};
    const owner = await prepareNetworkDamage({ page, origin, facts });
    await assert.rejects(owner.close(), /cleanup failed/);
    assert.equal(facts.conditions_restored, true);
    assert.equal(calls.at(-1).method, 'detach');
    assert.equal(facts.session_detached, operation !== 'detach');
    assert.equal(facts.cleanup_errors[0].operation, operation);
    assert.equal(facts.passed, false);
  }
});

test('concurrent owner close requests share one cleanup and never reacquire a session', async () => {
  const { page, calls } = ownedPage();
  const owner = await prepareNetworkDamage({ page, origin, facts: {} });
  await Promise.all([owner.close(), owner.close(), owner.close()]);
  for (const method of ['createCDPSession', 'Network.disable', 'detach']) {
    assert.equal(calls.filter(call => call.method === method).length, 1);
  }
  assert.equal(conditions(calls).filter(neutral).length, 1);
});

test('a setup or capture failure before damage restores the persistent baseline session', async () => {
  const { page, calls } = ownedPage();
  const facts = {};
  const owner = await prepareNetworkDamage({ page, origin, facts });
  const initial = new Error('actual receiver capture failed');
  await assert.rejects(exerciseNetworkDamage({ owner, capture: async () => { throw initial; }, profile: {}, retain() {} }),
    error => error === initial);
  assert.equal(facts.error, initial.message);
  assert.equal(facts.conditions_restored, true);
  assert.equal(facts.session_detached, true);
  assert.equal(facts.passed, false);
  assert.equal(conditions(calls).some(value => value.packetLoss > 0), false);
});

test('a secondary cleanup error cannot replace the original receiver error', async () => {
  const { page } = ownedPage({ failDetach: new Error('secondary detach rejected') });
  const facts = {};
  const owner = await prepareNetworkDamage({ page, origin, facts });
  const initial = new Error('primary receiver error');
  await assert.rejects(exerciseNetworkDamage({ owner, capture: async () => { throw initial; }, profile: {}, retain() {} }),
    error => error === initial);
  assert.equal(facts.error, initial.message);
  assert.equal(facts.cleanup_errors[0].operation, 'detach');
  assert.equal(facts.session_detached, false);
  assert.equal(facts.passed, false);
});

test('diagnostic samples are retained before malformed-counter rejection and origin changes are refused', async () => {
  for (const changedOrigin of [false, true]) {
    const { page } = ownedPage({ owned: !changedOrigin });
    const facts = {};
    const retained = [];
    const owner = await prepareNetworkDamage({ page, origin, facts });
    await assert.rejects(exerciseNetworkDamage({ owner,
      capture: async () => observation({ packetsLost: null }), profile: {}, retain: entry => retained.push(entry) }),
    changedOrigin ? /navigated away/ : /available receiver counter/);
    assert.equal(retained.length, changedOrigin ? 0 : 1);
    assert.equal(facts.samples.length, retained.length);
    assert.equal(facts.conditions_restored, true);
    assert.equal(facts.session_detached, true);
    assert.equal(facts.passed, false);
  }
});

test('mock lifecycle completion preserves damage and 27-fps/ten-second recovery gates', { timeout: 30000 }, async () => {
  // These deterministic receiver samples test lifecycle orchestration only.
  // A separate real browser/native run must provide the actual RTP evidence.
  const { page, calls } = ownedPage();
  const facts = {};
  const owner = await prepareNetworkDamage({ page, origin, facts });
  let count = 0;
  const capture = async () => {
    const index = count++;
    return { ...observation({ framesDecoded: 100 + index * 30,
      bytesReceived: 5000 + index * 3000, packetsReceived: 120 + index * 50,
      packetsLost: index ? 4 : 0, nackCount: index ? 2 : 0 }),
    monotonic_ms: index * 1000, video_width: 1920, video_height: 1080,
    video_time: 10 + index, peer_states: [index === 1 ? 'disconnected' : 'connected'], pixel: [210, 0, 40, 255] };
  };
  await exerciseNetworkDamage({ owner, capture,
    profile: { width: 1920, height: 1080, minimum_decoded_fps: 27, with_audio: false }, retain() {} });
  assert.equal(facts.receiver_damage.peak_packets_lost_delta, 4);
  assert.equal(facts.receiver_damage.nackCount, 2);
  assert.equal(facts.configuration.blackout_ms, 800);
  assert.equal(facts.configuration.impaired_ms, 6000);
  assert.equal(facts.configuration.recovery_budget_ms, 10000);
  assert.equal(facts.recovery_intervals.length, 3);
  assert.ok(facts.recovery_intervals.every(item => item.video.decoded_fps >= 27));
  assert.ok(facts.recovery_elapsed_ms <= 10000);
  assert.equal(facts.passed, false); // Final observer drain/cleanup is still owed.
  assert.equal(facts.session_detached, false);
  assert.equal(calls.some(call => call.method === 'Network.disable'), false);
  assert.equal(neutral(conditions(calls).at(-1)), true);
  await owner.close();
  assert.equal(facts.passed, true);
  assert.equal(facts.session_detached, true);
  assert.equal(neutral(conditions(calls).at(-1)), true);
  assert.equal(calls.some(call => call.method === 'Network.emulateNetworkConditionsByRule'), false);
  const countAfterClose = calls.length;
  await owner.close();
  assert.equal(calls.length, countAfterClose);
});
