// Exercise the production Web UI against the ephemeral native Core fixture.
// Puppeteer uses a fresh profile and trusted input. RTC diagnostics retain real
// browser objects; no signaling, clocks, permissions or codec behavior is faked.
// An optional synthetic online event asks the UI to perform a real ICE restart;
// that test does not claim an operating-system network change.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { videoInterval, audioInterval } = require('./lib/refactor-browser-media-metrics.cjs');
const { prepareNetworkDamage, exerciseNetworkDamage } = require('./lib/refactor-browser-network-damage.cjs');
const { preparePermitResponseObservation } = require('./lib/refactor-browser-response-observer.cjs');
const ownedData = require('./lib/refactor-browser-owned-data.cjs');
const workspaceUi = require('./lib/refactor-browser-workspace-ui.cjs');
const edgeNamespaceUi = require('./lib/refactor-browser-edge-namespace.cjs');
const networkMembershipUi = require('./lib/refactor-browser-network-membership.cjs');
const relayAttributesUi = require('./lib/refactor-browser-relay-attributes.cjs');
const spacesUi = require('./lib/refactor-browser-spaces.cjs');

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
const required = ['ready', 'report', 'tools', 'executable', 'engine', 'tls'];
if (required.some(key => !args[key]) || !['chrome', 'firefox'].includes(args.engine)) throw new Error('Missing native-browser probe arguments');
if (args['exercise-network-damage'] === 'true' && args.engine !== 'chrome') throw new Error('Page-scoped network damage requires Chromium CDP');
const ready = JSON.parse(fs.readFileSync(args.ready, 'utf8'));
const profile = ready.capture_profile ?? { name: 'smoke', width: 320, height: 180, fps: 10, duration_seconds: 36 };
if (!['smoke', '1080p30'].includes(profile.name) || !Number.isInteger(profile.duration_seconds) ||
    profile.duration_seconds < 36 || profile.duration_seconds > 1800 ||
    profile.width !== (profile.name === 'smoke' ? 320 : 1920) ||
    profile.height !== (profile.name === 'smoke' ? 180 : 1080) ||
    profile.fps !== (profile.name === 'smoke' ? 10 : 30)) throw new Error('Invalid owned capture profile');
profile.minimum_decoded_fps = profile.fps * 0.9;
const origin = new URL(ready.origin);
if (origin.protocol !== 'https:' || origin.hostname !== '127.0.0.1' || !origin.port || !ready.scope.startsWith('Ephemeral local development fixture')) throw new Error('Only the owned HTTPS loopback fixture is allowed');
const tls = JSON.parse(fs.readFileSync(args.tls, 'utf8'));
if (tls.origin !== ready.origin || tls.global_trust_modified !== false || !/^[A-Za-z0-9+/]{43}=$/.test(tls.leaf_spki_sha256_base64)) throw new Error('An isolated temporary certificate trust setup is required');
if (fs.existsSync(args.report)) throw new Error('Preserve the previous browser report');
const toolsPromise = import(require('node:url').pathToFileURL(path.join(path.resolve(args.tools), 'lib', 'puppeteer', 'puppeteer-core.js')).href);
if (require(path.join(path.resolve(args.tools), 'package.json')).version !== '25.14.0') throw new Error('Use the reviewed pinned Puppeteer runtime');
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const report = { schema_version: 1, scope: 'Production Web UI to native Core, real local WebRTC/VP8 and management renewal; owned synthetic capture, not installed-platform acceptance',
  started_at_utc: new Date().toISOString(), passed: false, engine: args.engine, executable_sha256: digest(args.executable),
  browser_product: args['browser-product'] || args.engine, browser_product_verified: false,
  probe_sha256: digest(__filename), initial_permits: [], renewals: [], successful_revocations: [], samples: [], page_errors: [], api_failures: [], response_inspection_errors: [], cleanup_requested: false, error: null };
report.capture_profile = profile;
report.intervals = [];
report.audio_intervals = [];
report.metrics_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-media-metrics.cjs'));
report.network_damage_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-network-damage.cjs'));
report.response_observer_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-response-observer.cjs'));
report.workspace_ui_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-workspace-ui.cjs'));
report.edge_namespace_ui_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-edge-namespace.cjs'));
report.network_membership_ui_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-network-membership.cjs'));
report.relay_attributes_ui_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-relay-attributes.cjs'));
report.spaces_ui_helper_sha256 = digest(path.join(__dirname, 'lib/refactor-browser-spaces.cjs'));
const progressPath = args.report.replace(/\.json$/, '') + '-progress.jsonl';
const progress = fs.openSync(progressPath, 'wx');
const retainSample = value => {
  report.samples.push(value);
  fs.writeSync(progress, JSON.stringify(value) + '\n');
  fs.fsyncSync(progress);
};
report.tls = { origin: tls.origin, leaf_sha256: tls.leaf_sha256, global_trust_modified: false,
  browser_trust: args.engine === 'firefox' ? 'Temporary CA in this fresh profile only' : 'Exact temporary leaf SPKI in this fresh process only' };

function check(value, message) { if (!value) throw new Error(message); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function sample(page) {
  return page.evaluate(async profile => {
    const video = document.querySelector('#remote-view-video');
    const peers = window.__nativeProbePeers || [];
    const inbound = [];
    const audio = [];
    let pixel = null;
    if (video?.readyState >= 2 && video.videoWidth === profile.width && video.videoHeight === profile.height) {
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = 1;
      const context = canvas.getContext('2d', { willReadFrequently: true });
      context.drawImage(video, Math.floor(profile.width / 2), Math.floor(profile.height / 2), 1, 1, 0, 0, 1, 1);
      pixel = Array.from(context.getImageData(0, 0, 1, 1).data);
    }
    for (const peer of peers) {
      const stats = await peer.getStats();
      for (const item of stats.values()) if (item.type === 'inbound-rtp' && (item.kind === 'video' || item.mediaType === 'video')) {
        inbound.push({ id: item.id, codec: stats.get(item.codecId)?.mimeType ?? null,
          framesDecoded: item.framesDecoded ?? null, bytesReceived: item.bytesReceived ?? null,
          packetsReceived: item.packetsReceived ?? null, packetsLost: item.packetsLost ?? null,
          framesDropped: item.framesDropped ?? null, jitter: item.jitter ?? null,
          nackCount: item.nackCount ?? null, pliCount: item.pliCount ?? null, firCount: item.firCount ?? null,
          totalDecodeTime: item.totalDecodeTime ?? null });
      } else if (item.type === 'inbound-rtp' && (item.kind === 'audio' || item.mediaType === 'audio')) {
        audio.push({ id: item.id, codec: stats.get(item.codecId)?.mimeType ?? null,
          totalSamplesReceived: item.totalSamplesReceived ?? null,
          packetsReceived: item.packetsReceived ?? null, bytesReceived: item.bytesReceived ?? null,
          concealedSamples: item.concealedSamples ?? null, totalAudioEnergy: item.totalAudioEnergy ?? null,
          jitter: item.jitter ?? null, packetsLost: item.packetsLost ?? null });
      }
    }
    return { monotonic_ms: performance.now(), video_width: video?.videoWidth ?? 0, video_height: video?.videoHeight ?? 0,
      video_time: video?.currentTime ?? 0, video_ready: video?.readyState ?? 0,
      peer_states: peers.map(peer => peer.connectionState),
      signaling_states: peers.map(peer => peer.signalingState),
      ice_states: peers.map(peer => peer.iceConnectionState),
      descriptions: peers.map(peer => ({ local: peer.localDescription?.type ?? null, remote: peer.remoteDescription?.type ?? null })), pixel, inbound, audio };
  }, profile);
}

async function main() {
  let browser, page;
  let networkDamage;
  let responseOwner;
  let responseHandler;
  let observationsClosed = false;
  const pendingResponses = new Set();
  try {
    const { default: tools, CDPSessionEvent } = await toolsPromise;
    browser = await tools.launch({ executablePath: args.executable, browser: args.engine, headless: true,
      userDataDir: tls.profile, acceptInsecureCerts: false,
      args: args.engine === 'chrome' ? ['--no-first-run', '--no-default-browser-check', '--ignore-certificate-errors-spki-list=' + tls.leaf_spki_sha256_base64] : [], timeout: 30000 });
    report.browser_version = await browser.version();
    const userAgent = await browser.userAgent();
    check(['chrome', 'edge', 'firefox'].includes(report.browser_product), 'Unknown requested browser product');
    const isEdge = /\bEdg\/\d+\./.test(userAgent);
    const productMatches = report.browser_product === 'firefox' ? /\bFirefox\/\d+\./.test(userAgent)
      : report.browser_product === 'edge' ? isEdge : /\b(?:Headless)?Chrome\/\d+\./.test(userAgent) && !isEdge;
    check(productMatches,
      'Actual browser product differs from the requested qualification');
    report.browser_product_verified = true;
    page = await ownedData.createPage(browser, ready, args, tls);
    const observationOptions = { disconnectedEvent: CDPSessionEvent.Disconnected,
      onClaims: (operation, claims) => {
        (operation === 'permit' ? report.initial_permits : report.renewals).push(claims);
      },
      onError: diagnostic => {
        report.response_inspection_errors.push(diagnostic);
        report.error ??= 'Could not inspect an actual successful permit or renewal response';
      } };
    if (args['exercise-network-damage'] === 'true') {
      report.network_damage = {};
      report.permit_response_observer = {};
      networkDamage = await prepareNetworkDamage({ page, origin: ready.origin, facts: report.network_damage,
        responseObserver: { ...observationOptions, facts: report.permit_response_observer } });
    } else if (args.engine === 'chrome') {
      report.permit_response_observer = {};
      responseOwner = await preparePermitResponseObservation({ ...observationOptions, page,
        origin: ready.origin, facts: report.permit_response_observer });
    }
    await ownedData.install(page, ready, args);
    page.setDefaultTimeout(30000);
    page.on('pageerror', error => report.page_errors.push(String(error.message).slice(0, 500)));
    responseHandler = response => {
      const observedMonotonic = performance.now();
      const observedUnix = Date.now();
      if (response.status() >= 400 && new URL(response.url()).pathname.startsWith('/api/')
          && !edgeNamespaceUi.expectedFailure(response) && !networkMembershipUi.expectedFailure(response)
          && !relayAttributesUi.expectedFailure(response) && !spacesUi.expectedFailure(response)) {
        report.api_failures.push({ path: new URL(response.url()).pathname, status: response.status() });
      }
      const operation = new URL(response.url()).pathname;
      if (response.request().method() === 'DELETE' && response.status() === 204 &&
          /^\/api\/v3\/(remote|devices)\/[^/]+$/.test(operation)) {
        report.successful_revocations.push({ path: operation, status: response.status(),
          observed_monotonic_ms: observedMonotonic, observed_unix_ms: observedUnix });
      }
      // The owned early CDP session observes these exact response streams. Do
      // not issue a competing default-session body read; this handler still
      // retains API failures and revocations. Firefox keeps its native observer.
      if (networkDamage || responseOwner) return;
      const initialPermit = operation.endsWith('/permit') && response.request().method() === 'POST';
      if ((!operation.endsWith('/renew') && !initialPermit) || response.status() !== 200) return;
      let inspectionStage = 'response-json';
      const inspection = (async () => {
        const body = await response.json();
        if (observationsClosed) return;
        inspectionStage = 'permit-claims';
        const destination = initialPermit ? report.initial_permits : report.renewals;
        destination.push({ lease_sequence: body.claims.lease_sequence, connection_generation: body.claims.connection_generation,
          session_id: body.claims.session_id, controller_device_id: body.claims.controller_device_id,
          issued_at_unix_ms: body.claims.issued_at_unix_ms, expires_at_unix_ms: body.claims.expires_at_unix_ms,
          observed_monotonic_ms: observedMonotonic, observed_unix_ms: observedUnix });
      })().catch(error => {
        if (!observationsClosed) {
          report.response_inspection_errors.push({ path: operation, status: response.status(),
            stage: inspectionStage, error_type: error.name,
            // A JSON parse error can quote response bytes; never retain tokens.
            message: error.name === 'SyntaxError' ? 'Response body was not valid JSON' : String(error.message).slice(0, 500) });
          report.error ??= 'Could not inspect an actual successful permit or renewal response';
        }
      });
      pendingResponses.add(inspection);
      inspection.then(() => pendingResponses.delete(inspection));
    };
    page.on('response', responseHandler);
    await page.evaluateOnNewDocument(profile => {
      const NativePeer = window.RTCPeerConnection;
      window.__nativeProbePeers = [];
      window.__nativeProbeDiagnostics = [];
      window.__nativeProbeNetworkEvents = [];
      window.__nativeProbeControls = [];
      const observeControl = (direction, data, sendMethod = null) => {
        if (window.__nativeProbeControls.length >= 512) return;
        try {
          const bytes = typeof data === 'string' ? null :
            data instanceof ArrayBuffer ? new Uint8Array(data) :
            ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : null;
          if (bytes && bytes.length >= 47 && bytes[0] === 0x4e && bytes[1] === 0x4c &&
              bytes[2] === 0x44 && bytes[3] === 0x42) {
            const kinds = { 1: 'catalog_begin', 2: 'catalog_entry', 3: 'catalog_commit',
              4: 'catalog_ack', 5: 'select', 6: 'selected', 7: 'selection_ack' };
            window.__nativeProbeControls.push({ monotonic_ms: performance.now(), direction,
              binary: 'native_display', message_kind: kinds[bytes[46]] ?? 'unknown',
              byte_length: bytes.length, send_method: sendMethod });
            return;
          }
          const message = JSON.parse(typeof data === 'string' ? data : new TextDecoder().decode(data));
          window.__nativeProbeControls.push({ monotonic_ms: performance.now(), direction,
            kind: message.kind, lease_sequence: message.lease_sequence,
            connection_generation: message.connection_generation, sequence: message.sequence,
            input_epoch: message.input_epoch, layout_epoch: message.layout_epoch,
            action_kind: message.action?.kind, x: message.action?.x, y: message.action?.y });
        } catch { window.__nativeProbeControls.push({ monotonic_ms: performance.now(), direction, unavailable: true }); }
      };
      const networkEvent = event => {
        const connection = navigator.connection;
        if (window.__nativeProbeNetworkEvents.length < 32) window.__nativeProbeNetworkEvents.push({
          monotonic_ms: performance.now(), event: event.type, trusted: event.isTrusted,
          online: navigator.onLine, type: connection?.type ?? null,
          effective_type: connection?.effectiveType ?? null });
      };
      window.addEventListener('online', networkEvent);
      window.addEventListener('offline', networkEvent);
      navigator.connection?.addEventListener('change', networkEvent);
      const descriptionFacts = description => {
        const candidates = (description?.sdp || '').split(/\r?\n/).filter(line => line.startsWith('a=candidate:'));
        return { type: description?.type ?? null, candidates: candidates.map(line => {
          const fields = line.slice(2).split(/\s+/);
          const typeIndex = fields.indexOf('typ');
          return { protocol: fields[2]?.toLowerCase() ?? null,
            address_kind: fields[4]?.endsWith('.local') ? 'mdns' : fields[4]?.includes(':') ? 'ipv6' : 'ipv4',
            type: typeIndex < 0 ? null : fields[typeIndex + 1] };
        }) };
      };
      window.RTCPeerConnection = class extends NativePeer {
        constructor(...configuration) {
          super(...configuration);
          window.__nativeProbePeers.push(this);
          const diagnostic = { transitions: [], observations: [] };
          window.__nativeProbeDiagnostics.push(diagnostic);
          const transition = event => {
            if (diagnostic.transitions.length < 512) diagnostic.transitions.push({ monotonic_ms: performance.now(), event: event?.type ?? 'created',
              connection: this.connectionState, ice: this.iceConnectionState, gathering: this.iceGatheringState,
              signaling: this.signalingState });
          };
          for (const event of ['connectionstatechange', 'iceconnectionstatechange', 'icegatheringstatechange', 'signalingstatechange']) {
            this.addEventListener(event, transition);
          }
          transition();
          const timer = setInterval(async () => {
            // Firefox's description getters throw after close. Stop this
            // diagnostic owner before reading SDP from a closed peer.
            if (this.connectionState === 'closed' || diagnostic.observations.length >= 2000) {
              clearInterval(timer); return;
            }
            const observation = { monotonic_ms: performance.now(), connection: this.connectionState,
              ice: this.iceConnectionState, local: descriptionFacts(this.localDescription), remote: descriptionFacts(this.remoteDescription),
              candidates: [], pairs: [], transports: [] };
            try {
              const stats = await this.getStats();
              for (const item of stats.values()) {
                if (item.type === 'local-candidate' || item.type === 'remote-candidate') {
                  observation.candidates.push({ side: item.type, type: item.candidateType, protocol: item.protocol,
                    network_type: item.networkType ?? null });
                } else if (item.type === 'candidate-pair') {
                  observation.pairs.push({ state: item.state, nominated: item.nominated ?? false,
                    requests_sent: item.requestsSent ?? null, requests_received: item.requestsReceived ?? null,
                    responses_sent: item.responsesSent ?? null, responses_received: item.responsesReceived ?? null,
                    bytes_sent: item.bytesSent ?? null, bytes_received: item.bytesReceived ?? null });
                } else if (item.type === 'transport') {
                  observation.transports.push({ dtls: item.dtlsState, ice: item.iceState ?? null,
                    selected_pair: !!item.selectedCandidatePairId });
                }
              }
            } catch { observation.stats_unavailable = true; }
            diagnostic.observations.push(observation);
            if (this.connectionState === 'closed') clearInterval(timer);
          }, profile.duration_seconds > 120 ? 1000 : 250);
        }
        createDataChannel(...configuration) {
          const channel = super.createDataChannel(...configuration);
          if (channel.label === 'nestlink-control-v1') {
            for (const method of ['send', 'sendWithArrayBuffer', 'sendWithArrayBufferView',
              'sendWithBlob', 'sendWithString', 'sendWithU8Array']) {
              const send = channel[method];
              if (typeof send !== 'function') continue;
              channel[method] = function(...args) {
                const result = Reflect.apply(send, this, args);
                observeControl('sent', args[0], method);
                return result;
              };
            }
            channel.addEventListener('message', event => observeControl('received', event.data));
          }
          return channel;
        }
      };
    }, profile);
    await page.goto(ready.origin, { waitUntil: 'networkidle0' });
    check(await page.evaluate(() => isSecureContext && location.protocol === 'https:'), 'Production page must run in an HTTPS secure context');
    // The production entry screen discovers its deployment over this HTTPS
    // origin; it no longer exposes manual issuer/deployment input fields.
    await page.locator('.entry-panel button.primary').click();
    await page.waitForSelector('#username', { visible: true });
    await page.locator('#username').fill(ready.username);
    await page.locator('#password').fill(ready.password);
    await page.locator('.entry-panel button.primary').click();
    await page.waitForSelector('button.record', { visible: true });
    // A second page shares browser cookies but owns a different SDK login.
    // Its logout must not replace or revoke this page's bearer session, nor
    // the native host's login. The first page must still establish and renew
    // the real media session below after the shared cookies are cleared.
    const sibling = await page.browserContext().newPage();
    try {
      check(sibling.browserContext() === page.browserContext(),
        'Concurrent sign-in must use the actual controller browser context');
      await sibling.goto(ready.origin, { waitUntil: 'networkidle0' });
      await sibling.locator('.entry-panel button.primary').click();
      await sibling.waitForSelector('#username', { visible: true });
      await sibling.locator('#username').fill(ready.username);
      await sibling.locator('#password').fill(ready.password);
      await sibling.locator('.entry-panel button.primary').click();
      await sibling.waitForSelector('button.record', { visible: true });
      await sibling.locator('::-p-xpath(//button[contains(.,"退出登录") or contains(.,"Sign out")])').click();
      await sibling.waitForFunction(() => document.querySelector('.entry-panel button.primary')?.disabled === false && !document.querySelector('#username'));
      report.concurrent_login = { same_account: true, shared_browser_context: true, second_page_signed_out: true };
    } finally {
      await sibling.close();
    }
    await edgeNamespaceUi.run(page, ready, report);
    await networkMembershipUi.run(page, ready, report, { engine: args.engine, disconnectedEvent: CDPSessionEvent.Disconnected });
    await relayAttributesUi.run(page, ready, report, { engine: args.engine, disconnectedEvent: CDPSessionEvent.Disconnected });
    await spacesUi.run(page, ready, report, { engine: args.engine, disconnectedEvent: CDPSessionEvent.Disconnected });
    await workspaceUi.workspaces(page, args, report);
    check(await page.$$eval('button.record', nodes => nodes.length) === 1, 'Fixture must initially expose only its own native host');
    await page.locator('button.record').click();
    await page.locator('.detail-pane button.primary').click();
    if (profile.with_audio) {
      await page.locator('.remote-permissions label:first-of-type input').click();
      check(await page.$eval('.remote-permissions label:first-of-type input', element => element.checked),
        'Synthetic audio must be explicitly requested through the actual permission control');
    }
    await ownedData.request(page, ready, args);
    await workspaceUi.permissions(page, report);
    const requestStarted = performance.now();
    await page.locator('.remote-footer button.primary').click();
    await workspaceUi.requestStarted(page, report);
    await page.waitForFunction(() => {
      return [...document.querySelectorAll('.remote-actions button.secondary')].some(button =>
        ['播放画面与声音', 'Play video and audio'].some(label => button.textContent.includes(label)) && !button.disabled);
    });
    // Decode the owned tone without disturbing the user's speakers. This
    // verifies receiver samples, not audible playback or output-device delay.
    await page.$eval('#remote-view-video', video => { video.volume = 0; });
    report.audio_output_muted = true;
    await page.locator('::-p-xpath(//div[contains(@class,"remote-actions")]/button[contains(.,"播放画面与声音") or contains(.,"Play video and audio")])').click();
    await page.waitForFunction(profile => {
      const video = document.querySelector('#remote-view-video');
      return video?.videoWidth === profile.width && video.videoHeight === profile.height && video.currentTime > 0 && video.readyState >= 2;
    }, { timeout: 35000 }, profile);
    // The HTML video can render its first frame before getStats publishes its
    // inbound stream. Start the measured interval only with a real RTP baseline.
    await page.waitForFunction(async () => {
      const streams = [];
      for (const peer of window.__nativeProbePeers) {
        const stats = await peer.getStats();
        for (const item of stats.values()) if (item.type === 'inbound-rtp' &&
          (item.kind === 'video' || item.mediaType === 'video')) {
          streams.push(item.framesDecoded > 0 && item.bytesReceived > 0 &&
            stats.get(item.codecId)?.mimeType?.toLowerCase() === 'video/vp8');
        }
      }
      return streams.length === 1 && streams[0];
    }, { timeout: 10000 });
    if (profile.with_audio) await page.waitForFunction(async () => {
      for (const peer of window.__nativeProbePeers) {
        const stats = await peer.getStats();
        for (const item of stats.values()) if (item.type === 'inbound-rtp' &&
          (item.kind === 'audio' || item.mediaType === 'audio') && item.totalSamplesReceived > 0) return true;
      }
      return false;
    }, { timeout: 10000 });
    await ownedData.exercise(page, ready, args, report);
    if (args['exercise-network-damage'] === 'true') {
      await exerciseNetworkDamage({ owner: networkDamage, capture: sample, profile,
        retain: entry => {
          fs.writeSync(progress, JSON.stringify({ network_damage: entry }) + '\n');
          fs.fsyncSync(progress);
        } });
    }
    const gate = JSON.parse(fs.readFileSync(path.join(path.dirname(path.resolve(args.ready)), 'host-start-gate.json'), 'utf8'));
    check(Number.isSafeInteger(profile.lifetime_seconds) && Number.isSafeInteger(gate.elapsed_ms) && gate.elapsed_ms >= 0,
      'Native fixture lifetime observations are unavailable');
    // The native gate happens after the UI request. Adding the whole elapsed
    // request phase overestimates elapsed native time, giving a conservative
    // lower bound without comparing clocks in different processes.
    const remaining = profile.lifetime_seconds * 1000 - gate.elapsed_ms - (performance.now() - requestStarted);
    report.native_lifetime_budget = { lifetime_seconds: profile.lifetime_seconds,
      management_rate_window_seconds: profile.management_rate_window_seconds,
      gate_elapsed_ms: gate.elapsed_ms, conservative_remaining_ms: remaining,
      requested_steady_ms: profile.duration_seconds * 1000, cleanup_reserve_ms: 15000 };
    check(remaining >= profile.duration_seconds * 1000 + 15000,
      'Insufficient original native fixture lifetime remains for the full steady interval and cleanup');
    report.steady_renewal_start_count = report.renewals.length;
    retainSample(await sample(page));
    const decodedStarted = performance.now();
    report.steady_observation_started_monotonic_ms = decodedStarted;
    await workspaceUi.activeLayouts(page, args, report);
    if (args['exercise-ice-restart'] === 'true') {
      report.ice_restart = { trigger: 'Synthetic online event; real signed offer/answer and ICE negotiation',
        requested: true, observed_offer_count: null };
      await page.evaluate(() => window.dispatchEvent(new Event('online')));
    }
    const intervalCount = Math.ceil(profile.duration_seconds / 12);
    for (let index = 0; index < intervalCount; index++) {
      await sleep(Math.max(1, decodedStarted + (index + 1) * profile.duration_seconds * 1000 / intervalCount - performance.now()));
      const current = await sample(page);
      const previous = report.samples[report.samples.length - 1];
      retainSample(current);
      report.intervals.push(videoInterval(previous, current, profile));
      if (profile.with_audio) report.audio_intervals.push(audioInterval(previous, current));
      await workspaceUi.sampleActive(page, report);
    }
    report.decoded_elapsed_seconds = (report.samples.at(-1).monotonic_ms - report.samples[0].monotonic_ms) / 1000;
    report.steady_observation_finished_monotonic_ms = performance.now();
    report.average_decoded_fps = report.intervals.reduce((sum, item) => sum + item.decoded_frames, 0) / report.decoded_elapsed_seconds;
    check(report.decoded_elapsed_seconds >= profile.duration_seconds, 'Decoded observation did not cover the requested duration');
    report.steady_renewals = report.renewals.filter(renewal =>
      renewal.observed_monotonic_ms >= decodedStarted &&
      renewal.observed_monotonic_ms <= report.steady_observation_finished_monotonic_ms);
    check(report.steady_renewals.length >= 4, 'The UI did not complete four actual signed management renewals during steady decoding');
    check(report.renewals.every((renewal, index, all) => renewal.lease_sequence === index + 2 && (!index || renewal.connection_generation === all[0].connection_generation)), 'Renewal sequence or connection generation changed unexpectedly');
    check(report.page_errors.length === 0, 'Production page raised an unhandled error');
    check(report.error === null, report.error);
    if (report.ice_restart) {
      report.ice_restart.observed_offer_count = await page.evaluate(() =>
        window.__nativeProbeDiagnostics.flatMap(peer => peer.transitions).filter(event =>
          event.event === 'signalingstatechange' && event.signaling === 'have-local-offer').length);
      check(report.ice_restart.observed_offer_count >= 2, 'The UI did not publish a new real ICE restart offer');
    }
    const video = await page.$('#remote-view-video');
    if (video) await video.screenshot({ path: args.report.replace(/\.json$/, '-video.png') });
    check(report.initial_permits.length === 1, 'Expected the one actual initial permit for this owned session');
    const initial = report.initial_permits[0];
    check([initial.session_id, initial.controller_device_id].every(value =>
      typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)),
      'Actual initial permit lacks exact session and persistent-controller identifiers');
    await ownedData.holdTerminalKey(page, ready, args, report);
    report.disconnect_requested_monotonic_ms = performance.now();
    if (!await ownedData.disconnect(page, ready, args, report)) await page.locator('.remote-actions button.danger').click();
    await page.waitForFunction(() => window.__nativeProbePeers.every(peer => peer.connectionState === 'closed') &&
      document.querySelector('.remote-actions button.danger')?.disabled === true, { timeout: 10000 });
    report.browser_peers_closed = true;
    check(await page.$$eval('.error-message', nodes => nodes.every(node => !node.textContent.trim())),
      'The UI reported a connection or cleanup failure');
    check(await page.$$eval('.remote-actions button', nodes => nodes.every(node =>
      !['重试清理', 'Retry cleanup'].some(label => node.textContent.includes(label)))),
      'The UI retained an unfinished cleanup operation');
    report.cleanup_revocations = report.successful_revocations.filter(item =>
      item.observed_monotonic_ms >= report.disconnect_requested_monotonic_ms);
    check(report.cleanup_revocations.filter(item => item.path === `/api/v3/remote/${initial.session_id}`).length === 1,
      'The server did not confirm this exact session revocation');
    check(!report.successful_revocations.some(item => item.path === `/api/v3/devices/${initial.controller_device_id}`),
      'Stopping a session must preserve the enrolled persistent browser identity');
    report.persistent_controller_preserved = true;
    report.ui_cleanup_complete = true;
    await workspaceUi.close(page, report);
    report.passed = true;
  } catch (error) {
    report.main_failure = String(error.message).slice(0, 1000);
    report.error ??= String(error.message).slice(0, 1000);
    if (page) {
      try { report.failure_sample = await sample(page); }
      catch { report.failure_sample = { unavailable: true }; }
      try { report.ui_errors = await page.$$eval('.error-message', nodes => nodes.map(node => node.textContent.slice(0, 500))); }
      catch { report.ui_errors = ['Page unavailable during failure diagnosis']; }
      try { report.failure_diagnostics = await page.evaluate(() => ({
        viewport: { width: innerWidth, height: innerHeight },
        layout: Object.fromEntries(['.remote-session', '.remote-toolbar', '.remote-display-selector', '.remote-stage', '.remote-data-panel', '.remote-data-panel > summary', '.remote-footer', '.remote-permissions'].map(selector => {
          const element = document.querySelector(selector);
          if (!element) return [selector, null];
          const rect = element.getBoundingClientRect();
          return [selector, { x: rect.x, y: rect.y, width: rect.width, height: rect.height,
            scroll_height: element.scrollHeight, client_height: element.clientHeight,
            position: getComputedStyle(element).position, z_index: getComputedStyle(element).zIndex }];
        })),
        data_panel_open: document.querySelector('.remote-data-panel')?.open ?? null,
        data_state: document.querySelector('.remote-data-state')?.textContent ?? null,
        data_content: document.querySelector('.remote-data-content')?.textContent?.slice(0, 2000) ?? null,
        approvals: Array.from(document.querySelectorAll('.remote-data-approvals input')).map(input => ({ checked: input.checked, disabled: input.disabled })),
        read_options: Array.from(document.querySelectorAll('section[aria-labelledby="remote-files-title"] select option')).map(option => ({ text: option.textContent, value: option.value })),
        write_options: Array.from(document.querySelectorAll('section[aria-labelledby="remote-upload-title"] select option')).map(option => ({ text: option.textContent, value: option.value })),
        data_actions: Array.from(document.querySelectorAll('.remote-data-panel button')).map(button => ({ text: button.textContent, disabled: button.disabled }))
      })); } catch { report.failure_diagnostics = { unavailable: true }; }
      try { await page.screenshot({ path: args.report.replace(/\.json$/, '-failure.png'), fullPage: true }); }
      catch { report.failure_screenshot_unavailable = true; }
    }
    process.exitCode = 1;
  } finally {
    if (page) {
      try {
        report.connection_diagnostics = await page.evaluate(() => window.__nativeProbeDiagnostics || []);
        report.control_diagnostics = await page.evaluate(() => window.__nativeProbeControls || []);
        report.network_events = await page.evaluate(() => window.__nativeProbeNetworkEvents || []);
      }
      catch { report.connection_diagnostics_unavailable = true; }
    }
    const cleanupErrors = [];
    if (networkDamage) {
      // Also covers UI/setup failures before the impairment exercise begins.
      try { await networkDamage.close(); }
      catch (error) { cleanupErrors.push('Owned network damage close: ' + String(error.message).slice(0, 300)); }
    }
    if (responseOwner) {
      try { await responseOwner.close(); }
      catch (error) { cleanupErrors.push('Owned response observer close: ' + String(error.message).slice(0, 300)); }
    }
    if (browser) {
      try { await browser.close(); report.browser_closed = true; }
      catch (error) { cleanupErrors.push('Browser close: ' + String(error.message).slice(0, 300)); }
    }
    if (page && responseHandler) page.off('response', responseHandler);
    let observationTimeout;
    try {
      if (pendingResponses.size) await Promise.race([
        Promise.allSettled([...pendingResponses]),
        new Promise((_, reject) => {
          observationTimeout = setTimeout(() => reject(new Error('Pending permit/renewal observations exceeded five seconds')), 5000);
        }),
      ]);
    } catch (error) {
      report.error ??= String(error.message).slice(0, 1000);
      cleanupErrors.push('Response observation completion: ' + String(error.message).slice(0, 300));
    } finally {
      clearTimeout(observationTimeout);
      observationsClosed = true;
      report.pending_response_observations_after_close = pendingResponses.size;
    }
    if (report.browser_closed) {
      try { await ownedData.cleanupAfterBrowser(ready, args, report); }
      catch (error) {
        if (report.owned_data) report.owned_data.passed = false;
        cleanupErrors.push('Owned saved-file cleanup: ' + String(error.message).slice(0, 300));
      }
    }
    try {
      const stop = path.join(path.dirname(path.resolve(args.ready)), 'stop.request');
      try { fs.writeFileSync(stop, 'Owned browser probe finished\n', { flag: 'wx' }); }
      catch (error) {
        if (error.code !== 'EEXIST' || !fs.lstatSync(stop).isFile() || fs.lstatSync(stop).isSymbolicLink()) throw error;
        report.existing_stop_request_preserved = true;
      }
      report.cleanup_requested = true;
    } catch (error) { cleanupErrors.push('Host stop request: ' + String(error.message).slice(0, 300)); }
    if (cleanupErrors.length) {
      report.passed = false;
      report.cleanup_errors = cleanupErrors;
      process.exitCode = 1;
    }
    // Screenshot, disconnect and browser shutdown can still expose a page
    // failure or finish an already observed permit/renewal response.
    report.renewal_sequence_valid = report.renewals.every((renewal, index, all) =>
      renewal.lease_sequence === index + 2 && (!index || renewal.connection_generation === all[0].connection_generation));
    if (report.error !== null || report.page_errors.length !== 0 || report.api_failures.length !== 0 || !report.renewal_sequence_valid ||
        (args.engine === 'chrome' && report.permit_response_observer?.passed !== true) ||
        (responseOwner && report.permit_response_observer?.session_owner?.passed !== true) ||
        (args['exercise-network-damage'] === 'true' && report.network_damage?.passed !== true)) {
      report.passed = false;
      process.exitCode = 1;
    }
    report.finished_at_utc = new Date().toISOString();
    fs.closeSync(progress);
    report.progress_sha256 = digest(progressPath);
    fs.writeFileSync(args.report, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    process.stdout.write(JSON.stringify({ passed: report.passed, renewals: report.renewals.length, samples: report.samples.length, error: report.error }) + '\n');
  }
}
main().catch(error => { process.stderr.write(String(error.message) + '\n'); process.exitCode = 1; });
