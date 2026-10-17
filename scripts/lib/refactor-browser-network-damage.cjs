// Owned Chromium page only. Register the P2P interceptor before RTC creation;
// a successful CDP command alone never proves real receiver packet damage.
const { performance } = require('node:perf_hooks');
const { videoInterval, audioInterval } = require('./refactor-browser-media-metrics.cjs');
const { createPermitResponseObserver } = require('./refactor-browser-response-observer.cjs');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const configuration = Object.freeze({
  blackout_ms: 800,
  impaired_ms: 6000,
  packet_loss_percent: 8,
  latency_ms: 80,
  bytes_per_second: 4096,
  packet_queue_length: 8,
  recovery_budget_ms: 10000,
});

function stream(sample) {
  const video = sample.inbound;
  if (!Array.isArray(video) || video.length !== 1 || video[0].codec?.toLowerCase() !== 'video/vp8') {
    throw new Error('Network damage requires one actual VP8 receiver');
  }
  for (const field of ['framesDecoded', 'bytesReceived', 'packetsReceived', 'packetsLost', 'nackCount', 'pliCount']) {
    // packetsLost is signed and can fall as late/retransmitted packets arrive.
    if (!Number.isSafeInteger(video[0][field]) || (field !== 'packetsLost' && video[0][field] < 0)) {
      throw new Error('Network damage requires an available receiver counter: ' + field);
    }
  }
  return video[0];
}

function assertStableSignaling(sample) {
  if (!Array.isArray(sample.signaling_states) || sample.signaling_states.length === 0) {
    throw new Error('Network damage requires an observed peer signaling state');
  }
  const unstable = sample.signaling_states.filter(state => state !== 'stable');
  if (unstable.length) {
    throw new Error('Page-scoped throughput impairment unexpectedly initiated WebRTC renegotiation: ' +
      unstable.join(', '));
  }
}

function observedDamage(before, after, observations = []) {
  const first = stream(before), last = stream(after);
  if (first.id !== last.id) throw new Error('Network damage changed the actual RTP receiver identity');
  let previous = first;
  let peakLost = first.packetsLost;
  for (const sample of [...observations, after]) {
    const value = stream(sample);
    if (value.id !== first.id) throw new Error('Network damage changed the actual RTP receiver identity');
    for (const field of ['framesDecoded', 'bytesReceived', 'packetsReceived', 'nackCount', 'pliCount']) {
      if (value[field] < previous[field]) throw new Error('Receiver counters reset during network damage');
    }
    peakLost = Math.max(peakLost, value.packetsLost);
    previous = value;
  }
  const result = {};
  for (const field of ['framesDecoded', 'bytesReceived', 'packetsReceived', 'packetsLost', 'nackCount', 'pliCount']) {
    result[field] = last[field] - first[field];
    if (field !== 'packetsLost' && result[field] < 0) throw new Error('Receiver counters reset during network damage');
  }
  result.peak_packets_lost_delta = peakLost - first.packetsLost;
  if (!(result.peak_packets_lost_delta > 0 && (result.nackCount > 0 || result.pliCount > 0))) {
    throw new Error('The receiver did not prove packet loss and fresh NACK/PLI feedback');
  }
  return result;
}

const owners = new WeakMap();
const neutralConditions = Object.freeze({ offline: false, latency: 0, downloadThroughput: -1,
  uploadThroughput: -1, packetLoss: 0, packetQueueLength: 0, packetReordering: false });

function event(state, phase) {
  state.facts.lifecycle.push({ phase, monotonic_ms: performance.now() });
}

async function setConditions(state, conditions) {
  if (!state.session || state.closed) throw new Error('Owned network damage session is unavailable');
  // A rejected command may have partially taken effect. Clear this flag before
  // sending it so failure cleanup still sends the full neutral configuration.
  state.dirty = true;
  state.facts.conditions_restored = false;
  await state.session.send('Network.emulateNetworkConditions', { ...neutralConditions, ...conditions });
}

async function restoreConditions(state) {
  if (!state.dirty) return;
  await state.session.send('Network.emulateNetworkConditions', { ...neutralConditions });
  state.dirty = false;
  state.facts.conditions_restored = true;
  event(state, 'conditions-restored');
}

function closeOwner(state) {
  if (state.closePromise) return state.closePromise;
  state.closePromise = (async () => {
    event(state, 'closing');
    const errors = [];
    const attempt = async (name, operation) => {
      try { await operation(); }
      catch (error) {
        errors.push(error);
        state.facts.cleanup_errors.push({ operation: name, message: String(error.message).slice(0, 500) });
      }
    };
    if (state.session) {
      // Drain while the same page session still owns the HTTP response bodies.
      // Always continue restoring and detaching after an observation failure.
      if (state.responseObserver) await attempt('response-observer', () => state.responseObserver.close());
      await attempt('restore', () => restoreConditions(state));
      await attempt('disable', async () => {
        await state.session.send('Network.disable');
        state.facts.network_disabled = true;
        event(state, 'network-disabled');
      });
      // A restore/disable error must never prevent detach from being attempted.
      await attempt('detach', async () => {
        await state.session.detach();
        state.facts.session_detached = true;
        event(state, 'session-detached');
      });
    }
    state.closed = true;
    event(state, 'closed');
    state.facts.passed = state.recoveryProven && !state.failed && errors.length === 0 &&
      state.facts.conditions_restored && state.facts.network_disabled && state.facts.session_detached &&
      (!state.observerFacts || state.observerFacts.passed === true);
    if (errors.length) throw new AggregateError(errors, 'Owned network damage cleanup failed');
  })();
  return state.closePromise;
}

async function prepareNetworkDamage({ page, origin, facts, responseObserver }) {
  const destination = new URL(origin);
  if (destination.protocol !== 'https:' || destination.hostname !== '127.0.0.1' ||
      !destination.port || destination.origin !== origin || !facts || typeof facts !== 'object') {
    throw new Error('Network damage is restricted to this owned HTTPS loopback origin');
  }
  if (page.url() !== 'about:blank') {
    throw new Error('Network damage must be prepared on the fresh owned page before navigation and RTC creation');
  }
  Object.assign(facts, {
    scope: 'Owned Chromium CDP page WebRTC packet/queue/throughput impairment; no OS network change',
    configuration, protocol_command: 'Network.emulateNetworkConditions', registration_latency_ms: 1,
    lifecycle: [], samples: [], recovery_intervals: [], cleanup_errors: [],
    session_created: false, prepared_before_rtc: false, conditions_restored: false,
    network_disabled: false, session_detached: false, passed: false,
  });
  const state = { page, origin, facts, session: null, dirty: false, closed: false,
    closePromise: null, started: false, recoveryProven: false, failed: false,
    responseObserver: null, observerFacts: responseObserver?.facts };
  const owner = Object.freeze({ close: () => closeOwner(state) });
  owners.set(owner, state);
  event(state, 'preparing-before-navigation');
  try {
    state.session = await page.createCDPSession();
    facts.session_created = true;
    if (responseObserver) state.responseObserver = createPermitResponseObserver({ ...responseObserver,
      session: state.session, origin });
    state.dirty = true;
    await state.session.send('Network.enable');
    // A nonzero neutral latency installs Chromium's P2P socket interceptor.
    // Keep this same session alive across navigation, RTC setup and damage.
    await setConditions(state, { latency: 1 });
    facts.prepared_before_rtc = true;
    event(state, 'prepared-before-rtc');
    return owner;
  } catch (error) {
    state.failed = true;
    facts.error = String(error.message).slice(0, 1000);
    try { await owner.close(); } catch { /* Retained cleanup_errors preserve the secondary failure. */ }
    throw error;
  }
}

async function exerciseNetworkDamage({ owner, capture, profile, retain }) {
  const state = owners.get(owner);
  if (!state) throw new Error('Network damage requires its prepared owned CDP session');
  const { page, facts } = state;
  const take = async phase => {
    const sample = await capture(page);
    const entry = { phase, observation: sample };
    facts.samples.push(entry);
    retain(entry);
    // Retain damaged samples before validating them. Temporary path/connection
    // disruption is permitted during impairment and the original recovery budget.
    stream(sample);
    assertStableSignaling(sample);
    if (phase === 'before' && !sample.peer_states?.includes('connected')) {
      throw new Error('Network damage requires the real connected baseline peer');
    }
    return sample;
  };
  let failure;
  try {
    if (state.closed || state.started || !facts.prepared_before_rtc ||
        typeof capture !== 'function' || typeof retain !== 'function') {
      throw new Error('Network damage needs one prepared owner and retained owned-page observations');
    }
    state.started = true;
    const owned = await page.evaluate(expected => isSecureContext && location.origin === expected, state.origin);
    if (!owned) throw new Error('Owned page navigated away from the prepared HTTPS loopback origin');
    event(state, 'exercise-started');
    const before = await take('before');
    await setConditions(state, { latency: 1, packetLoss: 100 });
    facts.blackout_applied = true;
    await sleep(configuration.blackout_ms);
    await take('blackout');
    await setConditions(state, { latency: configuration.latency_ms,
      downloadThroughput: configuration.bytes_per_second, uploadThroughput: configuration.bytes_per_second,
      packetLoss: configuration.packet_loss_percent, packetQueueLength: configuration.packet_queue_length });
    facts.impairment_applied = true;
    const until = performance.now() + configuration.impaired_ms;
    do {
      await sleep(Math.max(1, Math.min(1000, until - performance.now())));
      await take('impaired');
    } while (performance.now() < until);
    await restoreConditions(state);
    facts.restored_at_monotonic_ms = performance.now();
    const after = await take('restored');
    facts.receiver_damage = observedDamage(before, after, facts.samples.map(item => item.observation));
    let previous = after;
    let successive = 0;
    while (performance.now() - facts.restored_at_monotonic_ms < configuration.recovery_budget_ms) {
      await sleep(1000);
      const current = await take('recovery');
      try {
        const video = videoInterval(previous, current, profile);
        const audio = profile.with_audio ? audioInterval(previous, current) : null;
        successive += 1;
        facts.last_recovery_interval = { video, audio };
        facts.recovery_intervals.push({ video, audio, elapsed_ms: performance.now() - facts.restored_at_monotonic_ms });
      } catch (error) {
        facts.last_recovery_observation_error = String(error.message).slice(0, 500);
        successive = 0;
      }
      previous = current;
      const elapsed = performance.now() - facts.restored_at_monotonic_ms;
      if (successive >= 3 && elapsed <= configuration.recovery_budget_ms) {
        facts.recovery_elapsed_ms = elapsed;
        state.recoveryProven = true;
        break;
      }
    }
    if (!state.recoveryProven) throw new Error('RTP decoding did not recover for three intervals within the original ten-second budget');
    // Retain the neutral session for subsequent actual management renewals.
    // The outer probe owns the final drain/disable/detach and final pass flag.
    event(state, 'recovered-session-retained');
  } catch (error) {
    state.failed = true;
    facts.passed = false;
    facts.error = String(error.message).slice(0, 1000);
    failure = error;
  } finally {
    if (failure) {
      try { await owner.close(); }
      catch { /* Keep the primary receiver error; close retains cleanup_errors. */ }
    }
  }
  if (failure) throw failure;
}

module.exports = { prepareNetworkDamage, exerciseNetworkDamage, observedDamage, assertStableSignaling };
