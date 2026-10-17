// Exercise the feature-gated browser verification binary against real browser
// engines and a separately built production page. Both servers must be local
// loopback origins; this script never reads credentials or sends clipboard text
// to Node, logs, or the report.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const timeoutMs = 30_000;
const expectedPlaywrightVersion = '1.64.1';
const fixtureText = 'nestlink browser local clipboard fixture';
let activeCase = 'setup';
let activeDiagnostics = null;
let activeCompletedCases = null;
const caseGroup = process.env.NESTLINK_WEB_BROWSER_CASES || 'all';

function markCasePassed(name) {
  if (activeCompletedCases) activeCompletedCases.push({ case: name, status: 'passed' });
}

function markCaseNotApplicable(name, reasonCode) {
  if (activeCompletedCases) activeCompletedCases.push({ case: name, status: 'not-applicable', reason_code: reasonCode });
}

function markCaseNotCovered(name, reasonCode) {
  if (activeCompletedCases) activeCompletedCases.push({ case: name, status: 'not-covered', reason_code: reasonCode });
}

function clipboardPermissionFailureCode(error) {
  const message = typeof error?.message === 'string' ? error.message : '';
  if (/(?:^|:\s*)Unknown permission: clipboard-read$/.test(message)) return 'unknown-permission-clipboard-read';
  if (/(?:^|:\s*)Unknown permission: clipboard-write$/.test(message)) return 'unknown-permission-clipboard-write';
  if (/^Protocol error \(Emulation\.grantPermissions\):/.test(message)) return 'firefox-permission-protocol-rejected';
  return 'clipboard-permission-grant-failed';
}

const diagnosticInitScript = `(() => {
  const peers = [];
  Object.defineProperty(window, '__nestlinkRtcDiagnostics', {
    configurable: false,
    value: peers,
  });
  const NativePeerConnection = window.RTCPeerConnection;
  if (!NativePeerConnection) return;
  window.RTCPeerConnection = new Proxy(NativePeerConnection, {
    construct(target, args, newTarget) {
      const peer = Reflect.construct(target, args, newTarget);
      const sendCounts = new WeakMap();
      const record = {
        peer,
        channels: [],
        sentCount: channel => sendCounts.get(channel)?.() || 0,
      };
      peers.push(record);
      const track = channel => {
        if (record.channels.includes(channel)) return;
        record.channels.push(channel);
        let count = 0;
        const send = channel.send.bind(channel);
        channel.send = (...sendArgs) => {
          count += 1;
          return send(...sendArgs);
        };
        sendCounts.set(channel, () => count);
      };
      const createDataChannel = peer.createDataChannel.bind(peer);
      peer.createDataChannel = (...channelArgs) => {
        const channel = createDataChannel(...channelArgs);
        track(channel);
        return channel;
      };
      peer.addEventListener('datachannel', event => track(event.channel));
      return peer;
    },
  });
})();`;

function attachPageDiagnostics(page) {
  activeDiagnostics = { page_errors: [], console_errors: [], rtc: [] };
  page.on('pageerror', error => {
    activeDiagnostics.page_errors.push(error.name || 'Error');
  });
  page.on('console', message => {
    if (message.type() === 'error') activeDiagnostics.console_errors.push(message.type());
  });
}

async function capturePageDiagnostics(page) {
  if (!activeDiagnostics) return;
  try {
    const pageState = await page.evaluate(() => {
      const ids = ['fixture', 'receive', 'copy', 'send'];
      const buttons = Object.fromEntries(ids.map(id => {
        const element = document.getElementById(id);
        return [id, element ? { state: element.dataset.state, error_name: element.dataset.errorName || null } : null];
      }));
      const rtc = (window.__nestlinkRtcDiagnostics || []).map(record => {
        const { peer, channels } = record;
        return {
          signaling_state: peer.signalingState,
          ice_connection_state: peer.iceConnectionState,
          connection_state: peer.connectionState,
          ice_gathering_state: peer.iceGatheringState,
          local_description_type: peer.localDescription?.type || null,
          remote_description_type: peer.remoteDescription?.type || null,
          channels: channels.map(channel => ({
            label: channel.label,
            ready_state: channel.readyState,
            buffered_amount: channel.bufferedAmount,
            messages_sent: record.sentCount(channel),
          })),
        };
      });
      return { buttons, rtc };
    });
    activeDiagnostics.snapshot = pageState;
  } catch (error) {
    activeDiagnostics.snapshot_error = error.name || 'Error';
  }
}

function check(condition, message, failureCode) {
  if (condition) return;
  const error = new Error(message);
  if (failureCode) error.failureCode = failureCode;
  throw error;
}

function localUrl(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch (_) {
    throw new Error(`${name} must be an explicit local URL`);
  }
  check(!url.username && !url.password && !url.search && !url.hash, `${name} must not contain credentials, query, or fragment`);
  check(url.protocol === 'http:' || url.protocol === 'https:', `${name} must use HTTP(S)`);
  check(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), `${name} must use a loopback host`);
  return url;
}

function reportPath() {
  const requested = process.env.NESTLINK_WEB_BROWSER_REPORT;
  const stamp = new Date().toISOString().replace(/[-:.]/g, '').replace('T', '-').replace('Z', '');
  const file = path.resolve(requested || path.join(root, 'artifacts', 'core-verification', `web-browser-${stamp}-${process.pid}.json`));
  for (const site of [path.join(root, 'apps', 'web', 'dist'), path.join(root, 'docs', 'site')]) {
    check(file !== site && !file.startsWith(`${site}${path.sep}`), 'Report path cannot be inside a published site');
  }
  check(!fs.existsSync(file), 'Report path already exists; choose a new unique output');
  return file;
}

function resolvePlaywright() {
  const name = process.env.PLAYWRIGHT_PACKAGE || 'playwright-core';
  try {
    const entry = require.resolve(name);
    let directory = path.dirname(entry);
    let version;
    for (let depth = 0; depth < 5; depth++) {
      const manifestPath = path.join(directory, 'package.json');
      if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        if (manifest.name === 'playwright-core') {
          version = manifest.version;
          break;
        }
      }
      directory = path.dirname(directory);
    }
    check(version === expectedPlaywrightVersion, `playwright-core ${expectedPlaywrightVersion} is required`);
    return { api: require(name), version };
  } catch (_) {
    throw new Error(`Set PLAYWRIGHT_PACKAGE to playwright-core ${expectedPlaywrightVersion}`);
  }
}

function browserSpecs(playwright) {
  const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
  const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  return {
    chrome: {
      engine: playwright.chromium,
      executable: process.env.PLAYWRIGHT_CHROME_EXECUTABLE || path.join(programFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      clipboardPermissions: ['clipboard-read', 'clipboard-write'],
    },
    edge: {
      engine: playwright.chromium,
      executable: process.env.PLAYWRIGHT_EDGE_EXECUTABLE || path.join(programFilesX86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      clipboardPermissions: ['clipboard-read', 'clipboard-write'],
    },
    firefox: {
      engine: playwright.firefox,
      executable: process.env.PLAYWRIGHT_FIREFOX_EXECUTABLE || path.join(programFiles, 'Mozilla Firefox', 'firefox.exe'),
      // Firefox's Playwright permission map has no clipboard permission entry.
      // Do not change browser preferences; exercise clipboard APIs only from
      // the trusted click handlers below.
      clipboardPermissions: [],
    },
    'firefox-stable': {
      engine: require('./refactor-firefox-bidi.cjs'),
      executable: process.env.NESTLINK_FIREFOX_STABLE_EXECUTABLE,
      clipboardPermissions: [],
      automationTransport: 'WebDriver BiDi; puppeteer-core 25.14.0',
      contextEmulation: 'none; stock locale/theme/motion settings',
    },
  };
}

function selectedBrowsers() {
  const value = process.env.NESTLINK_WEB_BROWSERS || process.argv.slice(2).find(arg => !arg.startsWith('--'));
  check(value, 'Set NESTLINK_WEB_BROWSERS or pass chrome,edge,firefox explicitly');
  const names = value.split(',').map(name => name.trim().toLowerCase()).filter(Boolean);
  check(names.length > 0 && new Set(names).size === names.length, 'Browser selection is empty or contains duplicates');
  return names;
}

function digestFile(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex');
}

function sourceRevision() {
  return execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}

async function waitForHook(page) {
  await page.waitForFunction(() => {
    const api = window.nestlinkBrowserVerification;
    return api && typeof api.storageHold === 'function' && typeof api.clipboardFixtureStart === 'function'
      && typeof api.identityLoad === 'function'
      && typeof api.clipboardLifecycleFixtureStart === 'function';
  }, null, { timeout: timeoutMs });
}

async function storageCall(page, name, ...args) {
  return page.evaluate(async ([hookName, hookArgs]) => {
    return await window.nestlinkBrowserVerification[hookName](...hookArgs);
  }, [name, args]);
}

async function waitButton(page, statusId, state) {
  await page.waitForFunction(([id, expected]) => {
    const element = document.getElementById(id);
    return element && element.dataset.state === expected;
  }, [statusId, state], { timeout: timeoutMs });
}

async function rtcMessageCount(page, peerCount = 2) {
  return page.evaluate(count => {
    const peers = (window.__nestlinkRtcDiagnostics || []).slice(-count);
    return peers.reduce((total, record) => total + record.channels.reduce((sent, channel) => sent + record.sentCount(channel), 0), 0);
  }, peerCount);
}

async function beginClipboardLifecycleWait(page, hookName) {
  const started = await page.evaluate(name => {
    try {
      window.__nestlinkClipboardLifecycleWaiter = window.nestlinkBrowserVerification[name]();
      return true;
    } catch (_) {
      return false;
    }
  }, hookName);
  check(started, `Clipboard lifecycle operation ${hookName} did not start`);
}

async function finishClipboardLifecycleWait(page, deadlineMs = 5_000) {
  return page.evaluate(async timeout => {
    let timer;
    const result = await Promise.race([
      Promise.resolve(window.__nestlinkClipboardLifecycleWaiter).then(
        () => ({ status: 'fulfilled' }),
        error => ({ status: 'rejected', message: typeof error?.message === 'string' ? error.message : '' }),
      ),
      new Promise(resolve => { timer = window.setTimeout(() => resolve({ status: 'pending' }), timeout); }),
    ]);
    window.clearTimeout(timer);
    delete window.__nestlinkClipboardLifecycleWaiter;
    return result;
  }, deadlineMs);
}

async function revokeReapproveAndResolve(page, hookName, resolveHookName) {
  return page.evaluate(({ hookName, resolveHookName }) => {
    const api = window.nestlinkBrowserVerification;
    const startedAt = performance.now();
    let waiter;
    try {
      waiter = api[hookName]();
    } catch (error) {
      return {
        status: 'start-failed',
        message: typeof error?.message === 'string' ? error.message : '',
      };
    }
    api.clipboardLifecycleSetConsent(false);
    return Promise.resolve(waiter).then(
      () => ({ status: 'fulfilled', elapsed_ms: performance.now() - startedAt }),
      error => {
        const elapsedMs = performance.now() - startedAt;
        const stateAtInterrupt = api.clipboardLifecycleState();
        // Reapprove and settle the original browser Promise in the same
        // rejection callback, before its original short verification deadline.
        api.clipboardLifecycleSetConsent(true);
        api[resolveHookName]();
        return {
          status: 'rejected',
          message: typeof error?.message === 'string' ? error.message : '',
          elapsed_ms: elapsedMs,
          state_at_interrupt: stateAtInterrupt,
        };
      },
    );
  }, { hookName, resolveHookName });
}

async function revokeReapproveResolveSameTurn(page, hookName, resolveHookName) {
  return page.evaluate(({ hookName, resolveHookName }) => {
    const api = window.nestlinkBrowserVerification;
    const startedAt = performance.now();
    let waiter;
    try {
      waiter = api[hookName]();
    } catch (error) {
      return {
        status: 'start-failed',
        message: typeof error?.message === 'string' ? error.message : '',
      };
    }
    const stateWhilePending = api.clipboardLifecycleState();
    api.clipboardLifecycleSetConsent(false);
    api.clipboardLifecycleSetConsent(true);
    api[resolveHookName]();
    const sameTurnElapsedMs = performance.now() - startedAt;
    return Promise.resolve(waiter).then(
      () => ({ status: 'fulfilled', same_turn_elapsed_ms: sameTurnElapsedMs }),
      error => ({
        status: 'rejected',
        message: typeof error?.message === 'string' ? error.message : '',
        same_turn_elapsed_ms: sameTurnElapsedMs,
        state_while_pending: stateWhilePending,
      }),
    );
  }, { hookName, resolveHookName });
}

async function clipboardLifecycleState(page) {
  return page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleState());
}

async function waitForClipboardLifecycleIdle(page) {
  await page.waitForFunction(() => !window.nestlinkBrowserVerification.clipboardLifecycleState().operation_pending, null,
    { timeout: timeoutMs });
}

async function clipboardLifecycleAcceptance(page) {
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleFixtureStart());

  activeCase = 'clipboard-api-deadline-retains-owner';
  const beforeReadTimeout = await rtcMessageCount(page);
  await beginClipboardLifecycleWait(page, 'clipboardLifecycleStartRead');
  const readTimeout = await finishClipboardLifecycleWait(page);
  check(readTimeout.status === 'rejected' && readTimeout.message.includes('读取本机剪贴板超时'),
    'A pending local clipboard read did not report its deadline');
  let state = await clipboardLifecycleState(page);
  check(state.operation_pending && state.replacement_blocked && state.read_calls === 1,
    'A timed-out read released the owned clipboard operation or allowed replacement');
  const retryWhileReadPending = await page.evaluate(() => {
    try {
      window.nestlinkBrowserVerification.clipboardLifecycleStartRead();
      return { started: true, message: '' };
    } catch (error) {
      return { started: false, message: typeof error?.message === 'string' ? error.message : '' };
    }
  });
  check(!retryWhileReadPending.started && retryWhileReadPending.message.includes('正在执行'),
    'A second clipboard operation started while the native read Promise was unresolved');
  state = await clipboardLifecycleState(page);
  check(state.read_calls === 1, 'Retrying while the read Promise was unresolved invoked readText again');
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleResolveRead());
  await waitForClipboardLifecycleIdle(page);
  check(await rtcMessageCount(page) === beforeReadTimeout,
    'A read result that arrived after its deadline sent a WebRTC clipboard RPC');
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && !state.replacement_blocked && state.read_calls === 1,
    'The clipboard owner did not become replaceable after the original Promise settled');
  markCasePassed('clipboard-api-deadline-retains-owner');

  activeCase = 'clipboard-api-revocation-before-read-settles';
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleSetConsent(true));
  const beforeReadRevocation = await rtcMessageCount(page);
  const readRevoked = await revokeReapproveAndResolve(
    page,
    'clipboardLifecycleStartRead',
    'clipboardLifecycleResolveRead',
  );
  check(readRevoked.status === 'rejected' && readRevoked.message.includes('批准已撤销'),
    'Revoking consent did not settle the local-read UI waiter');
  check(readRevoked.elapsed_ms < readRevoked.state_at_interrupt.api_timeout_ms,
    'The reapproval did not happen before the original controlled clipboard deadline');
  check(readRevoked.state_at_interrupt.operation_pending
    && readRevoked.state_at_interrupt.replacement_blocked
    && readRevoked.state_at_interrupt.read_calls === 2,
    'Revoking consent released a still-pending native read owner');
  await waitForClipboardLifecycleIdle(page);
  check(await rtcMessageCount(page) === beforeReadRevocation,
    'A read that settled after consent was restored sent a WebRTC clipboard RPC');
  check(readRevoked.status === 'rejected' && readRevoked.message.includes('批准已撤销'),
    'Settling the old read upgraded its terminal revocation result');
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && state.read_calls === 2,
    'The revoked read did not release its owner after the browser Promise settled');
  markCasePassed('clipboard-api-revocation-before-read-settles');

  activeCase = 'clipboard-read-rejection-classified';
  const beforeReadRejection = await rtcMessageCount(page);
  await beginClipboardLifecycleWait(page, 'clipboardLifecycleStartRead');
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleRejectRead());
  const readRejected = await finishClipboardLifecycleWait(page);
  check(readRejected.status === 'rejected'
    && readRejected.message.includes('无法读取本机剪贴板')
    && !readRejected.message.includes('无法读写文件'),
  'A rejected clipboard read was reported as a file storage failure');
  await waitForClipboardLifecycleIdle(page);
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && state.read_calls === 3 && await rtcMessageCount(page) === beforeReadRejection,
    'A rejected clipboard read retained its owner or sent a WebRTC RPC');
  markCasePassed('clipboard-read-rejection-classified');

  activeCase = 'clipboard-approval-token-survives-same-turn-regrant';
  const beforeSameTurnRegrant = await rtcMessageCount(page);
  const sameTurnRegrant = await revokeReapproveResolveSameTurn(
    page,
    'clipboardLifecycleStartRead',
    'clipboardLifecycleResolveRead',
  );
  check(sameTurnRegrant.status === 'rejected'
    && sameTurnRegrant.message.includes('批准已撤销'),
  'Revoking and regranting in the same JavaScript turn revived an old clipboard consent');
  check(sameTurnRegrant.state_while_pending.operation_pending
    && sameTurnRegrant.state_while_pending.read_calls === 4
    && sameTurnRegrant.same_turn_elapsed_ms < sameTurnRegrant.state_while_pending.api_timeout_ms,
  'The same-turn approval-token fixture did not settle the original read before its deadline');
  await waitForClipboardLifecycleIdle(page);
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && await rtcMessageCount(page) === beforeSameTurnRegrant,
    'An old clipboard read sent an RPC or retained its owner after same-turn regrant');
  markCasePassed('clipboard-approval-token-survives-same-turn-regrant');

  activeCase = 'clipboard-write-timeout-is-unconfirmed';
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleSetConsent(true));
  await page.evaluate(async () => window.nestlinkBrowserVerification.clipboardLifecycleStageRemote());
  check((await clipboardLifecycleState(page)).staged_clipboard,
    'The lifecycle fixture could not stage text for a controlled local write');
  const beforeWriteTimeout = await rtcMessageCount(page);
  await beginClipboardLifecycleWait(page, 'clipboardLifecycleStartWrite');
  const writeTimeout = await finishClipboardLifecycleWait(page);
  check(writeTimeout.status === 'rejected' && writeTimeout.message.includes('本机剪贴板写入结果未确认')
    && writeTimeout.message.includes('可能已经改变'),
  'A pending local write did not report its possible clipboard effect');
  state = await clipboardLifecycleState(page);
  check(state.operation_pending && state.replacement_blocked && !state.staged_clipboard && state.write_calls === 1,
    'A timed-out local write released its owner, retained stale text, or invoked the API more than once');
  const retryWhileWritePending = await page.evaluate(() => {
    try {
      window.nestlinkBrowserVerification.clipboardLifecycleStartWrite();
      return { started: true, message: '' };
    } catch (error) {
      return { started: false, message: typeof error?.message === 'string' ? error.message : '' };
    }
  });
  check(!retryWhileWritePending.started && retryWhileWritePending.message.includes('正在执行'),
    'A second local write started while the original write Promise was unresolved');
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleResolveWrite());
  await waitForClipboardLifecycleIdle(page);
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && state.write_calls === 1 && await rtcMessageCount(page) === beforeWriteTimeout,
    'The timed-out local write was retried or produced a WebRTC RPC after it settled');
  markCasePassed('clipboard-write-timeout-is-unconfirmed');

  activeCase = 'clipboard-write-revocation-is-unconfirmed';
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleSetConsent(true));
  await page.evaluate(async () => window.nestlinkBrowserVerification.clipboardLifecycleStageRemote());
  const beforeWriteRevocation = await rtcMessageCount(page);
  const writeRevoked = await revokeReapproveAndResolve(
    page,
    'clipboardLifecycleStartWrite',
    'clipboardLifecycleResolveWrite',
  );
  check(writeRevoked.status === 'rejected' && writeRevoked.message.includes('本机剪贴板写入结果未确认')
    && writeRevoked.message.includes('可能已经改变'),
  'Revoking consent during a local write did not report an unknown clipboard effect');
  check(writeRevoked.elapsed_ms < writeRevoked.state_at_interrupt.api_timeout_ms,
    'The reapproval did not happen before the original controlled clipboard deadline');
  check(writeRevoked.state_at_interrupt.operation_pending
    && writeRevoked.state_at_interrupt.replacement_blocked
    && writeRevoked.state_at_interrupt.write_calls === 2,
    'Revoking consent released a still-pending local write owner');
  await waitForClipboardLifecycleIdle(page);
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && state.write_calls === 2 && await rtcMessageCount(page) === beforeWriteRevocation,
    'A revoked local write was repeated or sent over WebRTC after its Promise settled');
  check(writeRevoked.status === 'rejected'
    && writeRevoked.message.includes('本机剪贴板写入结果未确认'),
  'Settling the old clipboard write upgraded its terminal unconfirmed result');
  markCasePassed('clipboard-write-revocation-is-unconfirmed');

  activeCase = 'clipboard-write-rejection-is-unconfirmed';
  await page.evaluate(async () => window.nestlinkBrowserVerification.clipboardLifecycleStageRemote());
  const beforeWriteRejection = await rtcMessageCount(page);
  await beginClipboardLifecycleWait(page, 'clipboardLifecycleStartWrite');
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardLifecycleRejectWrite());
  const writeRejected = await finishClipboardLifecycleWait(page);
  check(writeRejected.status === 'rejected'
    && writeRejected.message.includes('本机剪贴板写入结果未确认')
    && writeRejected.message.includes('可能已经改变')
    && !writeRejected.message.includes('没有改变'),
  'A rejected clipboard write claimed that the clipboard was unchanged');
  await waitForClipboardLifecycleIdle(page);
  state = await clipboardLifecycleState(page);
  check(!state.operation_pending && !state.staged_clipboard && state.write_calls === 3
    && await rtcMessageCount(page) === beforeWriteRejection,
  'A rejected clipboard write retained its owner, stale text or sent an RPC');
  markCasePassed('clipboard-write-rejection-is-unconfirmed');
}

async function acquireAfterRelease(page) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (await storageCall(page, 'storageHold')) return true;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  return false;
}

async function productionSmoke(browser, productionUrl) {
  activeCase = 'production-ui-smoke';
  const context = await browser.newContext({ locale: 'zh-CN', colorScheme: 'light', reducedMotion: 'reduce' });
  try {
    const page = await context.newPage();
    const response = await page.goto(productionUrl.href, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    check(response && response.ok(), 'Production URL did not return a successful response');
    await page.waitForSelector('#trust-title', { state: 'visible', timeout: timeoutMs });
    check((await page.locator('#deployment').count()) === 1, 'Production trust form is missing deployment input');
    check((await page.locator('#issuer').count()) === 1, 'Production trust form is missing issuer input');
    check(await page.evaluate(() => window.nestlinkBrowserVerification === undefined), 'Production page exposed the test-only API');
    return { status: 'passed', title: await page.title(), trust_screen: true, verification_api_absent: true };
  } finally {
    await context.close();
  }
}

async function storageAcceptance(context, verificationUrl) {
  activeCase = 'web-lock-contention';
  const owner = await context.newPage();
  const contender = await context.newPage();
  await Promise.all([owner.goto(verificationUrl.href), contender.goto(verificationUrl.href)]);
  await Promise.all([waitForHook(owner), waitForHook(contender)]);
  check(await storageCall(owner, 'storageHold') === true, 'First page could not acquire the production Web Lock');
  check(await storageCall(contender, 'storageHold') === false, 'A second page acquired an already-held Web Lock');
  check(await storageCall(owner, 'storageRelease') === true, 'The owning page did not confirm lock release');
  markCasePassed('web-lock-contention');

  activeCase = 'opfs-failure-releases-lock';
  const failureReleased = await contender.evaluate(async () => {
    const originalStorage = Object.getOwnPropertyDescriptor(navigator, 'storage');
    let failed = false;
    try {
      Object.defineProperty(navigator, 'storage', {
        configurable: true,
        value: { getDirectory: () => Promise.reject(new DOMException('verification failure', 'SecurityError')) },
      });
      try {
        await window.nestlinkBrowserVerification.storageHold();
      } catch (_) {
        failed = true;
      }
    } finally {
      if (originalStorage) Object.defineProperty(navigator, 'storage', originalStorage);
      else delete navigator.storage;
    }
    return failed;
  });
  check(failureReleased, 'The simulated OPFS API failure was not surfaced');
  check(await storageCall(owner, 'storageHold') === true, 'A failed OPFS open retained its Web Lock');
  check(await storageCall(owner, 'storageRelease') === true, 'The post-failure lock could not be released');
  markCasePassed('opfs-failure-releases-lock');

  activeCase = 'opfs-page-close-recovery';
  check(await storageCall(owner, 'storageHold') === true, 'Could not reacquire the storage owner before recovery setup');
  const orphanNames = Array.from({ length: 65 }, () => crypto.randomUUID());
  const retainedDirectory = `nestlink-verification-keep-${crypto.randomUUID()}`;
  const staleVersionOne = '00000000-0000-1000-8000-000000000001';
  await owner.evaluate(async ({ orphanNames, retainedDirectory }) => {
    const root = await navigator.storage.getDirectory();
    const parent = await root.getDirectoryHandle('nestlink-private-v15', { create: true });
    for (const name of orphanNames) {
      const directory = await parent.getDirectoryHandle(name, { create: true });
      await directory.getFileHandle('fixture.bin', { create: true });
    }
    await parent.getDirectoryHandle(retainedDirectory, { create: true });
    await parent.getDirectoryHandle('00000000-0000-1000-8000-000000000001', { create: true });
    await parent.getFileHandle('nestlink-verification-keep-file.txt', { create: true });
  }, { orphanNames, retainedDirectory });

  // Closing the page destroys the actual execution context that owns the
  // pending navigator.locks callback; no test-only release runs here.
  await owner.close();
  check(await acquireAfterRelease(contender), 'Closing the old page did not release its browser Web Lock');
  const passes = await storageCall(contender, 'storageRecoverClose', 8);
  check(Number.isInteger(passes) && passes >= 2, 'Recovery did not cross its bounded 64-entry pass');
  const result = await contender.evaluate(async ({ orphanNames, retainedDirectory, staleVersionOne }) => {
    const root = await navigator.storage.getDirectory();
    const parent = await root.getDirectoryHandle('nestlink-private-v15');
    const exists = async name => {
      try {
        await parent.getDirectoryHandle(name);
        return true;
      } catch (error) {
        if (error && error.name === 'NotFoundError') return false;
        throw error;
      }
    };
    const orphanCount = (await Promise.all(orphanNames.map(exists))).filter(Boolean).length;
    const retained = await exists(retainedDirectory);
    const versionOneRetained = await exists(staleVersionOne);
    const keepFile = await parent.getFileHandle('nestlink-verification-keep-file.txt').then(() => true);
    await parent.removeEntry(retainedDirectory, { recursive: true });
    await parent.removeEntry(staleVersionOne, { recursive: true });
    await parent.removeEntry('nestlink-verification-keep-file.txt');
    return { orphanCount, retained, versionOneRetained, keepFile };
  }, { orphanNames, retainedDirectory, staleVersionOne });
  check(result.orphanCount === 0, 'Recovery left one or more canonical UUIDv4 directories');
  check(result.retained && result.versionOneRetained && result.keepFile, 'Recovery removed an entry it did not own');
  await contender.close();
  markCasePassed('opfs-page-close-recovery');
  return {
    lock_contention: 'passed',
    opfs_failure_releases_lock: 'passed',
    page_close_recovery: 'passed',
    bounded_recovery_passes: passes,
    canonical_orphans_removed: orphanNames.length,
    unrelated_directory_file_and_uuidv1_preserved: true,
  };
}

async function browserIdentityAcceptance(context, verificationUrl) {
  activeCase = 'browser-controller-identity-persistence';
  const page = await context.newPage();
  let otherPage;
  try {
    await page.goto(verificationUrl.href);
    await waitForHook(page);
    const scope = `verification:${crypto.randomUUID()}`;
    const first = await storageCall(page, 'identityLoad', scope);
    check(typeof first === 'string' && first.includes(':'), 'Browser identity creation returned no stable key identity');
    await page.reload();
    await waitForHook(page);
    const second = await storageCall(page, 'identityLoad', scope);
    check(second === first, 'Reload changed the browser controller device ID or public key');
    const stored = await page.evaluate(async scope => {
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('nestlink-control-identity-v1');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      try {
        const record = await new Promise((resolve, reject) => {
          const request = db.transaction('identities', 'readonly').objectStore('identities').get(scope);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
        return {
          version: record.version,
          scope: record.scope,
          extractable: record.key.extractable,
          algorithm: record.key.algorithm.name,
          key_bits: record.key.algorithm.length,
          usages: [...record.key.usages].sort(),
          iv_bytes: record.iv.byteLength,
          ciphertext_bytes: record.ciphertext.byteLength,
        };
      } finally {
        db.close();
      }
    }, scope);
    check(stored.version === 1 && stored.scope === scope && stored.extractable === false
      && stored.algorithm === 'AES-GCM' && stored.key_bits === 256
      && stored.usages.join(',') === 'decrypt,encrypt'
      && stored.iv_bytes === 12 && stored.ciphertext_bytes === 48,
    'Browser identity was not stored as a seed ciphertext protected by a non-extractable AES-GCM key');
    otherPage = await context.newPage();
    await otherPage.goto(verificationUrl.href);
    await waitForHook(otherPage);
    const concurrentScope = `verification:${crypto.randomUUID()}`;
    const concurrent = await Promise.all([
      storageCall(page, 'identityLoad', concurrentScope),
      storageCall(otherPage, 'identityLoad', concurrentScope),
    ]);
    check(concurrent[0] === concurrent[1], 'Concurrent tabs enrolled different controller identities');
    check(concurrent[0] !== first, 'Different account scopes shared a browser identity');

    const replacementId = crypto.randomUUID();
    await page.evaluate(async ({ scope, replacementId }) => {
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('nestlink-control-identity-v1');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      try {
        await new Promise((resolve, reject) => {
          const tx = db.transaction('identities', 'readwrite');
          tx.oncomplete = resolve;
          tx.onerror = tx.onabort = () => reject(tx.error);
          const store = tx.objectStore('identities');
          const request = store.get(scope);
          request.onsuccess = () => {
            const record = request.result;
            record.device_id = replacementId;
            store.put(record, scope);
          };
        });
      } finally { db.close(); }
    }, { scope, replacementId });
    let corruptRejected = false;
    try { await storageCall(page, 'identityLoad', scope); }
    catch (_) { corruptRejected = true; }
    check(corruptRejected, 'Tampered device binding was accepted');
    const preservedId = await page.evaluate(async scope => {
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('nestlink-control-identity-v1');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      try {
        return await new Promise((resolve, reject) => {
          const request = db.transaction('identities').objectStore('identities').get(scope);
          request.onsuccess = () => resolve(request.result.device_id);
          request.onerror = () => reject(request.error);
        });
      } finally { db.close(); }
    }, scope);
    check(preservedId === replacementId, 'Corrupt identity was silently replaced');
    markCasePassed('browser-controller-identity-persistence');
    return { status: 'passed', reload_preserved_identity: true, key_extractable: stored.extractable,
      encrypted_seed_bytes: stored.ciphertext_bytes, concurrent_tabs_share_identity: true,
      account_scopes_separated: true, tampered_binding_rejected_without_replacement: true };
  } finally {
    if (otherPage) await otherPage.close();
    await page.close();
  }
}

async function clipboardAcceptance(context, verificationUrl, permissions, browser) {
  activeCase = 'clipboard-permissions';
  if (permissions.length > 0) {
    try {
      await context.grantPermissions(permissions, { origin: verificationUrl.origin });
    } catch (error) {
      // Preserve only a fixed diagnostic category. Protocol errors can include
      // browser-supplied details; do not put those strings in reports or logs.
      const failure = new Error('Clipboard permission setup failed');
      failure.name = 'ClipboardPermissionError';
      failure.failureCode = clipboardPermissionFailureCode(error);
      throw failure;
    }
  }
  const page = await context.newPage();
  attachPageDiagnostics(page);
  await page.addInitScript({ content: diagnosticInitScript });
  await page.goto(verificationUrl.href);
  await waitForHook(page);
  if (permissions.length > 0) markCasePassed('clipboard-permissions');
  else markCaseNotApplicable('clipboard-permissions', 'browser-permission-map-does-not-support-clipboard');
  await page.evaluate(() => {
    const api = window.nestlinkBrowserVerification;
    const start = api.clipboardFixtureStart;
    api.clipboardFixtureStart = () => start().catch(error => {
      const status = document.getElementById('fixture');
      // Do not retain exception text: a failed RTC operation may include SDP,
      // which contains ephemeral ICE credentials.
      status.dataset.errorName = error?.name || 'Error';
      throw error;
    });
  });

  activeCase = 'real-webrtc-clipboard-rpc';
  await page.locator('#clipboard-fixture-start').click();
  await page.waitForFunction(() => {
    const state = document.getElementById('fixture')?.dataset.state;
    return state === 'fulfilled' || state === 'rejected';
  }, null, { timeout: timeoutMs });
  const fixtureState = await page.locator('#fixture').getAttribute('data-state');
  if (fixtureState !== 'fulfilled') {
    await capturePageDiagnostics(page);
    throw new Error(`WebRTC fixture start ${fixtureState}; see browser diagnostics`);
  }

  // Each clipboard operation is invoked directly in a trusted click handler.
  await page.locator('#clipboard-receive').click();
  await waitButton(page, 'receive', 'fulfilled');
  check(await page.evaluate(() => window.nestlinkBrowserVerification.clipboardHasPending()), 'Remote clipboard reply was not staged');

  await page.locator('#clipboard-copy').click();
  await waitButton(page, 'copy', 'fulfilled');
  await page.locator('#clipboard-check-remote').click();
  await waitButton(page, 'check-remote', 'match');

  await page.locator('#clipboard-seed').click();
  await waitButton(page, 'seed', 'fulfilled');
  await page.locator('#clipboard-check-local').click();
  await waitButton(page, 'check-local', 'match');

  await page.locator('#clipboard-send').click();
  await waitButton(page, 'send', 'fulfilled');
  check(await page.evaluate(expected => window.nestlinkBrowserVerification.clipboardLastHostWrite() === expected, fixtureText),
    'The real WebRTC clipboard write did not reach the local peer');
  markCasePassed('real-webrtc-clipboard-rpc');

  await clipboardLifecycleAcceptance(page);

  let denialResult;
  if (permissions.length > 0) {
    activeCase = 'clipboard-api-failure';
    await context.clearPermissions();
    await page.locator('#clipboard-send').click();
    try {
      await waitButton(page, 'send', 'rejected');
    } catch (error) {
      await capturePageDiagnostics(page);
      throw error;
    }
    check(await page.evaluate(expected => window.nestlinkBrowserVerification.clipboardLastHostWrite() === expected, fixtureText),
      'A denied clipboard read unexpectedly sent data to the WebRTC peer');
    markCasePassed('clipboard-api-failure');
    denialResult = { denied_clipboard_read_sends_no_rpc: 'passed' };
  } else {
    activeCase = 'clipboard-api-no-user-activation';
    // Firefox does not expose clipboard permissions through Playwright. Use a
    // fresh context with no grants or clicks. Firefox may keep its native
    // permission Promise pending; the production actor must still reject its
    // UI waiter at its original 30-second deadline without sending an RPC.
    const denialContext = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: false });
    denialContext.setDefaultTimeout(timeoutMs);
    try {
      const denialPage = await denialContext.newPage();
      attachPageDiagnostics(denialPage);
      await denialPage.addInitScript({ content: diagnosticInitScript });
      await denialPage.goto(verificationUrl.href);
      await waitForHook(denialPage);
      const fixtureStarted = await denialPage.evaluate(async () => {
        try {
          await window.nestlinkBrowserVerification.clipboardFixtureStart();
          return true;
        } catch (_) {
          return false;
        }
      });
      check(fixtureStarted, 'The fresh clipboard denial fixture could not start', 'denial-fixture-start-failed');
      const fixtureSendCount = await rtcMessageCount(denialPage);
      check(fixtureSendCount === 0, 'The fresh fixture sent data before the clipboard read', 'denial-fixture-sent-before-read');
      check(await denialPage.evaluate(() => window.nestlinkBrowserVerification.clipboardLastHostWrite()) === '',
        'The fresh fixture retained a prior clipboard write', 'denial-fixture-retained-prior-write');
      const deniedRead = await denialPage.evaluate(timeout => new Promise(resolve => {
        const timer = window.setTimeout(() => resolve('pending'), timeout);
        try {
          Promise.resolve(window.nestlinkBrowserVerification.clipboardSendLocal()).then(
            () => { window.clearTimeout(timer); resolve('fulfilled'); },
            () => { window.clearTimeout(timer); resolve('rejected'); },
          );
        } catch (_) {
          window.clearTimeout(timer);
          resolve('rejected');
        }
      }), 35_000);
      if (deniedRead === 'pending') {
        markCaseNotCovered('clipboard-api-no-user-activation', 'clipboard-read-without-activation-pending');
        denialResult = { denied_clipboard_read_without_user_activation_sends_no_rpc: 'not-covered' };
      } else {
        check(deniedRead === 'rejected', 'Clipboard read without user activation did not reject',
          'clipboard-read-without-activation-allowed');
        const fixtureSendCountAfterRead = await rtcMessageCount(denialPage);
        check(fixtureSendCountAfterRead === fixtureSendCount,
          'Clipboard read without user activation sent data to the WebRTC peer', 'clipboard-read-without-activation-sent-rpc');
        check(await denialPage.evaluate(() => window.nestlinkBrowserVerification.clipboardLastHostWrite()) === '',
          'Clipboard read without user activation changed the host clipboard fixture', 'clipboard-read-without-activation-changed-write');
        markCasePassed('clipboard-api-no-user-activation');
        denialResult = { denied_clipboard_read_without_user_activation_sends_no_rpc: 'passed' };
      }
      await denialPage.close();
    } finally {
      await denialContext.close();
    }
    attachPageDiagnostics(page);
  }

  activeCase = 'invalid-webrtc-reply-closes-peer';
  await page.evaluate(() => window.nestlinkBrowserVerification.clipboardUseBadReplySequence());
  await page.locator('#clipboard-receive').click();
  await waitButton(page, 'receive', 'rejected');
  await page.waitForFunction(() => {
    const states = Array.from(window.nestlinkBrowserVerification.clipboardPeerStates());
    return states.length === 2 && states.every(state => state === 'closed');
  }, null, { timeout: timeoutMs });
  markCasePassed('invalid-webrtc-reply-closes-peer');
  await page.close();
  return {
    local_sctp_clipboard_read_write: 'passed',
    trusted_click_clipboard_copy_and_read: 'passed',
    ...denialResult,
    invalid_reply_sequence_closes_both_peers: 'passed',
  };
}

async function runBrowser(name, spec, verificationUrl, productionUrl) {
  activeDiagnostics = null;
  activeCompletedCases = [];
  const headless = process.env.NESTLINK_WEB_HEADLESS !== 'false';
  const result = { browser: name, status: 'passed', headless, completed_cases: activeCompletedCases };
  if (spec?.automationTransport) {
    result.automation_transport = spec.automationTransport;
    result.context_emulation = spec.contextEmulation;
  }
  let browser;
  let failure = null;
  activeCase = `${name}-launch`;
  try {
    check(spec?.engine, `Playwright has no engine for ${name}`);
    check(fs.existsSync(spec.executable), `Configured ${name} executable is missing`);
    browser = await spec.engine.launch({ headless, executablePath: spec.executable });
    result.version = browser.version();
    result.production_ui_smoke = await productionSmoke(browser, productionUrl);
    markCasePassed('production-ui-smoke');
    activeCase = `${name}-verification-context`;
    const context = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: false });
    context.setDefaultTimeout(timeoutMs);
    try {
      result.browser_identity = await browserIdentityAcceptance(context, verificationUrl);
      if (caseGroup === 'all') {
        result.storage = await storageAcceptance(context, verificationUrl);
        result.clipboard = await clipboardAcceptance(context, verificationUrl, spec.clipboardPermissions, browser);
      }
    } finally {
      await context.close();
    }
  } catch (error) {
    failure = error;
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch (error) {
        if (!failure) {
          activeCase = `${name}-close`;
          failure = error;
        }
      }
    }
  }
  if (failure) {
    result.status = 'failed';
    result.failed_case = activeCase;
    result.failure_name = typeof failure?.name === 'string' ? failure.name : 'Error';
    if (typeof failure?.failureCode === 'string') result.failure_code = failure.failureCode;
    if (activeDiagnostics) result.diagnostics = activeDiagnostics;
  } else {
    const notCovered = activeCompletedCases.filter(item => item.status === 'not-covered');
    if (notCovered.length > 0) {
      result.status = 'incomplete';
      result.not_covered_cases = notCovered.map(item => ({ case: item.case, reason_code: item.reason_code }));
    }
  }
  return result;
}

async function main() {
  check(['all', 'identity'].includes(caseGroup), 'Unknown browser case group');
  const verificationUrl = localUrl(process.env.NESTLINK_WEB_VERIFY_URL, 'NESTLINK_WEB_VERIFY_URL');
  const productionUrl = localUrl(process.env.NESTLINK_WEB_PRODUCTION_URL, 'NESTLINK_WEB_PRODUCTION_URL');
  const selected = selectedBrowsers();
  const playwright = resolvePlaywright();
  const specs = browserSpecs(playwright.api);
  const report = {
    schema_version: 1,
    scope: caseGroup === 'identity'
      ? 'local browser identity persistence, concurrent tabs, tamper rejection and production trust-screen smoke'
      : 'local browser identity/Web Lock/OPFS, real browser SCTP clipboard RPC and production trust-screen smoke',
    selected_case_group: caseGroup,
    captured_at: new Date().toISOString(),
    source_revision: sourceRevision(),
    playwright_core: playwright.version,
    source_sha256: {
      'apps/web/index.html': digestFile('apps/web/index.html'),
      'apps/web/browser-verification.html': digestFile('apps/web/browser-verification.html'),
      'apps/web/src/browser_peer.rs': digestFile('apps/web/src/browser_peer.rs'),
      'apps/web/src/browser_sdp.rs': digestFile('apps/web/src/browser_sdp.rs'),
      'apps/web/src/browser_verification.rs': digestFile('apps/web/src/browser_verification.rs'),
      'apps/web/src/browser_identity.rs': digestFile('apps/web/src/browser_identity.rs'),
      'scripts/refactor-web-browser-check.cjs': digestFile('scripts/refactor-web-browser-check.cjs'),
      'scripts/refactor-firefox-bidi.cjs': digestFile('scripts/refactor-firefox-bidi.cjs'),
    },
    endpoints: { verification_origin: verificationUrl.origin, production_origin: productionUrl.origin },
    runs: [],
    passed: false,
    incomplete: false,
  };
  let failure = false;
  let incomplete = false;
  for (const name of selected) {
    const run = await runBrowser(name, specs[name], verificationUrl, productionUrl);
    report.runs.push(run);
    if (run.status === 'failed') failure = true;
    if (run.status === 'incomplete') incomplete = true;
  }
  report.incomplete = incomplete && !failure && report.runs.length === selected.length;
  report.passed = !failure && !incomplete && report.runs.length === selected.length;
  const target = reportPath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  if (!report.passed) {
    if (failure) {
      const failedCase = report.runs.find(run => run.status === 'failed')?.failed_case || activeCase;
      console.error(`Browser verification failed in ${failedCase}; redacted report: ${path.relative(root, target)}`);
    } else {
      const gap = report.runs.flatMap(run => run.not_covered_cases || [])[0];
      console.error(`Browser verification incomplete in ${gap?.case || activeCase}; redacted report: ${path.relative(root, target)}`);
    }
    process.exitCode = 1;
    return;
  }
  console.log(`Browser verification passed for ${selected.join(', ')}; report: ${path.relative(root, target)}`);
}

main().catch(() => {
  console.error(`Browser verification could not start in ${activeCase}. Check the local origins, browser executable and Playwright package.`);
  process.exitCode = 1;
});
