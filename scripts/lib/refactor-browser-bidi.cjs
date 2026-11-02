// Thin Firefox adaptation over the existing pinned Puppeteer BiDi transport.
// No HTTP re-fetch, request interception, response substitution or permission grant.
'use strict';
const { performance } = require('node:perf_hooks');
const { TextDecoder } = require('node:util');
const { projectPermitClaims } = require('./refactor-browser-response-observer.cjs');

const permitRoute = /^\/api\/v3\/remote\/([0-9a-fA-F-]{36})\/(permit|renew)$/;
const limits = Object.freeze({ requests: 128, pending: 32, body: 262144, requestMs: 15000, bodyMs: 3000, drainMs: 5000 });

async function requestJson(response) {
  try {
    const request = response.request();
    const firefox = request.frame()?.page().browser().cdpSupported === false;
    // Preserve Chromium's original cached postData behavior. Firefox exposes
    // the same actual request bytes through Puppeteer's BiDi network.getData.
    const text = firefox ? await request.fetchPostData() : request.postData();
    if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > limits.body) throw new Error('body-bound');
    return JSON.parse(text);
  } catch { throw new Error('Actual bounded browser request JSON was unavailable'); }
}

function preparePermitResponseObservation({ page, origin, facts, onClaims, onError }) {
  const destination = new URL(origin);
  if (destination.origin !== origin || destination.protocol !== 'https:' || destination.hostname !== '127.0.0.1'
      || !destination.port || page?.url() !== 'about:blank' || page.browser().cdpSupported !== false
      || typeof page.on !== 'function' || typeof page.off !== 'function'
      || !facts || typeof onClaims !== 'function' || typeof onError !== 'function') {
    throw new Error('BiDi observation requires the fresh owned Firefox HTTPS loopback page');
  }
  Object.assign(facts, { schema_version: 1, transport: 'webDriverBiDi',
    source: 'Puppeteer 25.14.0 BiDi network data collector; actual requestfinished response content, no re-fetch',
    requests_tracked: 0, successful_responses: 0, claims_observed: 0, pending: 0, peak_pending: 0,
    errors: [], closed: false, listeners_removed: false, passed: false });
  const lifecycle = facts.bidi_owner = { prepared_before_navigation: true,
    request_listeners_removed: false, closed: false, passed: false, cleanup_errors: [] };
  const pending = new Map();
  let accepting = true, closing = false, closePromise, drained;
  const finish = entry => {
    if (!pending.delete(entry.request)) return;
    clearTimeout(entry.timer);
    facts.pending = pending.size;
    if (!pending.size) drained?.();
  };
  const failure = (entry, stage) => {
    // Browser/protocol/JSON errors may quote secrets. Retain fixed categories only.
    const diagnostic = { path: entry?.path ?? null, stage,
      message: 'Owned Firefox permit response observation failed' };
    facts.errors.push(diagnostic);
    if (entry) finish(entry);
    try { onError(diagnostic); } catch { /* Original fixed diagnostic remains. */ }
  };
  const requestHandler = request => {
    if (!accepting) return;
    let url, found;
    try {
      url = new URL(request.url());
      found = permitRoute.exec(url.pathname);
      if (url.origin !== origin || url.search || url.hash || url.username || url.password
          || !found || request.method() !== 'POST') return;
    } catch { return; }
    if (pending.has(request)) { failure(pending.get(request), 'duplicate-request'); return; }
    if (facts.requests_tracked >= limits.requests || pending.size >= limits.pending) {
      accepting = false;
      failure(null, 'request-bound');
      return;
    }
    const entry = { request, path: url.pathname, operation: found[2], sessionId: found[1].toLowerCase(),
      observedMonotonic: null, observedUnix: null, reading: false };
    entry.timer = setTimeout(() => failure(entry, 'request-timeout'), limits.requestMs);
    pending.set(request, entry);
    facts.requests_tracked++;
    facts.pending = pending.size;
    facts.peak_pending = Math.max(facts.peak_pending, pending.size);
  };
  const responseHandler = response => {
    const entry = pending.get(response.request());
    if (entry) {
      entry.observedMonotonic = performance.now();
      entry.observedUnix = Date.now();
    }
  };
  const finishedHandler = request => {
    const entry = pending.get(request);
    if (!entry) return;
    if (entry.reading) { failure(entry, 'duplicate-completion'); return; }
    entry.reading = true;
    const response = request.response();
    if (!response || response.url() !== origin + entry.path || response.status() !== 200 || entry.observedMonotonic === null) {
      failure(entry, 'response-status'); return;
    }
    const length = response.headers()['content-length'];
    if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > limits.body)) {
      failure(entry, 'body-bound'); return;
    }
    facts.successful_responses++;
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => failure(entry, 'body-timeout'), limits.bodyMs);
    void (async () => {
      let bytes;
      try {
        // Puppeteer uses Firefox's native bounded BiDi data collector. Read the
        // original request only after its actual completion event, never a GET.
        bytes = await response.content();
        if (!pending.has(request)) return;
        if (!(bytes instanceof Uint8Array) || bytes.length > limits.body) {
          failure(entry, 'body-bound'); return;
        }
        const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        const claims = projectPermitClaims(body, entry);
        onClaims(entry.operation, claims);
        facts.claims_observed++;
        finish(entry);
      } catch { if (pending.has(request)) failure(entry, 'response-body'); }
      finally { if (bytes instanceof Uint8Array) bytes.fill(0); }
    })();
  };
  const failedHandler = request => {
    const entry = pending.get(request);
    if (entry) failure(entry, 'request-failed');
  };
  const pageClosedHandler = () => {
    if (!closing) {
      failure(null, 'page-closed');
      for (const entry of [...pending.values()]) finish(entry);
    }
  };
  const handlers = { request: requestHandler, response: responseHandler,
    requestfinished: finishedHandler, requestfailed: failedHandler, close: pageClosedHandler };
  for (const [event, handler] of Object.entries(handlers)) page.on(event, handler);
  return Object.freeze({ close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      accepting = false;
      closing = true;
      let timeout;
      try {
        if (pending.size) await Promise.race([
          new Promise(resolve => { drained = resolve; }),
          new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('BiDi drain timeout')), limits.drainMs); }),
        ]);
      } catch {
        lifecycle.cleanup_errors.push('response-drain');
        for (const entry of [...pending.values()]) failure(entry, 'close-timeout');
      } finally {
        clearTimeout(timeout);
        for (const [event, handler] of Object.entries(handlers)) page.off(event, handler);
        facts.listeners_removed = lifecycle.request_listeners_removed = true;
        facts.closed = lifecycle.closed = true;
        facts.passed = facts.errors.length === 0 && pending.size === 0
          && facts.claims_observed > 0 && facts.claims_observed === facts.requests_tracked;
        lifecycle.passed = facts.passed && lifecycle.cleanup_errors.length === 0;
      }
      if (!lifecycle.passed) throw new Error('Owned Firefox permit response observation did not complete');
    })();
    return closePromise;
  } });
}

// Pinned Puppeteer exposes the real BiDi connection and frame context identifier.
// Only subscribe/unsubscribe to standard download events; no extra protocol
// session, network interception or setPermission command is created here.
function observeDownload(browser, page, origin) {
  const connection = browser.connection;
  const context = page.mainFrame().browsingContext?.id;
  if (browser.cdpSupported !== false || !connection?.on || !connection?.off || typeof context !== 'string') {
    throw new Error('Pinned Firefox BiDi download event surface is unavailable');
  }
  const observer = { started: [], progress: new Map(), errors: [], closed: false };
  const failure = category => { if (observer.errors.length < 8) observer.errors.push(category); };
  const begin = event => {
    if (event.context !== context) return;
    if (typeof event.url !== 'string' || !event.url.startsWith('blob:' + origin + '/')
        || typeof event.navigation !== 'string' || event.navigation.length === 0 || event.navigation.length > 128
        || event.suggestedFilename !== 'owned-download.bin'
        || observer.started.length >= 4) { failure('unexpected-download'); return; }
    observer.started.push({ guid: event.navigation, filename: event.suggestedFilename });
  };
  const end = event => {
    if (event.context !== context) return;
    if (!observer.started.some(item => item.guid === event.navigation)
        || !['complete', 'canceled'].includes(event.status)) { failure('unmatched-download-end'); return; }
    observer.progress.set(event.navigation, { state: event.status === 'complete' ? 'completed' : 'canceled' });
  };
  connection.on('browsingContext.downloadWillBegin', begin);
  connection.on('browsingContext.downloadEnd', end);
  observer.close = () => {
    connection.off('browsingContext.downloadWillBegin', begin);
    connection.off('browsingContext.downloadEnd', end);
    observer.closed = true;
  };
  return observer;
}

module.exports = { preparePermitResponseObservation, observeDownload, requestJson };
