'use strict';
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { preparePermitResponseObservation, observeDownload, requestJson } = require('../../scripts/lib/refactor-browser-bidi.cjs');

const origin = 'https://127.0.0.1:45678';
const session = '12345678-1234-4234-8234-123456789abc';
const controller = '12345678-1234-4234-8234-123456789def';
const endpoint = origin + '/api/v3/remote/' + session + '/permit';
const tick = () => new Promise(resolve => setImmediate(resolve));
const payload = () => ({ permit: 'privateSignedPermit', claims: { session_id: session, controller_device_id: controller,
  lease_sequence: 1, connection_generation: 1, issued_at_unix_ms: 1000, expires_at_unix_ms: 2000 } });

test('request JSON uses actual BiDi bytes only on Firefox and preserves Chromium cached postData', async () => {
  for (const firefox of [true, false]) {
    const request = { frame: () => ({ page: () => ({ browser: () => firefox ? { cdpSupported: false } : {} }) }),
      fetchPostData: async () => { assert.equal(firefox, true); return '{"expected_revision":17}'; },
      postData: () => { assert.equal(firefox, false); return '{"expected_revision":17}'; } };
    assert.deepEqual(await requestJson({ request: () => request }), { expected_revision: 17 });
  }
  await assert.rejects(requestJson({ request: () => { throw new Error('private-body'); } }),
    /^Error: Actual bounded browser request JSON was unavailable$/);
});

function fixture() {
  const page = new EventEmitter();
  page.url = () => 'about:blank';
  page.browser = () => ({ cdpSupported: false });
  const facts = {}, claims = [], errors = [];
  const owner = preparePermitResponseObservation({ page, origin, facts,
    onClaims: (operation, value) => claims.push({ operation, value }), onError: value => errors.push(value) });
  function request({ url = endpoint, body = payload(), status = 200, headers = {}, content } = {}) {
    const bytes = Buffer.from(JSON.stringify(body));
    let reads = 0;
    const req = { url: () => url, method: () => 'POST', response: () => res };
    const res = { request: () => req, url: () => url, status: () => status, headers: () => headers,
      content: async () => { reads++; return content ? await content() : bytes; } };
    return { req, res, bytes, reads: () => reads };
  }
  return { page, facts, claims, errors, owner, request };
}

test('BiDi observes the exact original completed response, ignores foreign origins and clears secret bytes', async () => {
  const f = fixture();
  const foreign = f.request({ url: 'https://other.invalid/api/v3/remote/' + session + '/permit' });
  f.page.emit('request', foreign.req); f.page.emit('response', foreign.res); f.page.emit('requestfinished', foreign.req);
  assert.equal(foreign.reads(), 0);
  const actual = f.request();
  f.page.emit('request', actual.req); f.page.emit('response', actual.res);
  await tick();
  assert.equal(actual.reads(), 0, 'a response header cannot substitute for actual load completion');
  f.page.emit('requestfinished', actual.req);
  await tick();
  assert.equal(actual.reads(), 1);
  assert.equal(f.claims.length, 1);
  assert.equal(f.claims[0].value.session_id, session);
  assert.equal(actual.bytes.every(value => value === 0), true);
  await f.owner.close(); await f.owner.close();
  assert.equal(f.facts.passed, true);
  assert.equal(f.facts.bidi_owner.request_listeners_removed, true);
  assert.equal(f.page.eventNames().length, 0);
  assert.equal(JSON.stringify(f.facts).includes('privateSignedPermit'), false);
});

test('wrong session proof, oversized bodies and unavailable original response remain failures without leaking exception text', async () => {
  for (const input of [
    { body: { ...payload(), claims: { ...payload().claims, session_id: controller } } },
    { headers: { 'content-length': '262145' } },
    { content: async () => Buffer.alloc(262145) },
    { content: async () => { throw new Error('privateSignedPermit private-body'); } },
  ]) {
    const f = fixture();
    const actual = f.request(input);
    f.page.emit('request', actual.req); f.page.emit('response', actual.res); f.page.emit('requestfinished', actual.req);
    await tick();
    await assert.rejects(f.owner.close(), /did not complete/);
    assert.equal(f.facts.passed, false);
    assert.equal(f.claims.length, 0);
    assert.equal(f.page.eventNames().length, 0);
    assert.equal(JSON.stringify(f.facts).includes('privateSignedPermit'), false);
    assert.equal(JSON.stringify(f.facts).includes('private-body'), false);
  }
});

test('a failed request or closed page cannot leave a successful response owner', async () => {
  for (const event of ['requestfailed', 'close']) {
    const f = fixture();
    const actual = f.request();
    f.page.emit('request', actual.req); f.page.emit('response', actual.res);
    f.page.emit(event, actual.req);
    await assert.rejects(f.owner.close(), /did not complete/);
    assert.equal(f.facts.pending, 0);
    assert.equal(f.page.eventNames().length, 0);
    assert.equal(actual.reads(), 0);
  }
});

test('finite pending admission refuses the thirty-third request and closes every owned listener', async () => {
  const f = fixture();
  const requests = Array.from({ length: 33 }, () => f.request());
  for (const { req } of requests) f.page.emit('request', req);
  assert.equal(f.facts.requests_tracked, 32);
  assert.equal(f.facts.peak_pending, 32);
  assert.equal(f.errors[0].stage, 'request-bound');
  for (const { req } of requests) f.page.emit('requestfailed', req);
  await assert.rejects(f.owner.close(), /did not complete/);
  assert.equal(f.facts.pending, 0);
  assert.equal(f.page.eventNames().length, 0);
});

test('actual BiDi download completion correlates the exact owned page, blob origin, navigation and filename', () => {
  const connection = new EventEmitter();
  const browser = { cdpSupported: false, connection };
  const page = { mainFrame: () => ({ browsingContext: { id: 'owned-context' } }) };
  const observer = observeDownload(browser, page, origin);
  connection.emit('browsingContext.downloadWillBegin', { context: 'foreign-context', url: 'blob:' + origin + '/id', navigation: 'ignored', suggestedFilename: 'owned-download.bin' });
  assert.equal(observer.started.length, 0);
  connection.emit('browsingContext.downloadWillBegin', { context: 'owned-context', url: 'blob:' + origin + '/id', navigation: 'owned-navigation', suggestedFilename: 'owned-download.bin' });
  assert.equal(observer.progress.size, 0);
  connection.emit('browsingContext.downloadEnd', { context: 'owned-context', navigation: 'owned-navigation', status: 'complete', filepath: '/private/never-publish' });
  assert.equal(observer.started[0].filename, 'owned-download.bin');
  assert.equal(observer.progress.get('owned-navigation').state, 'completed');
  assert.equal(JSON.stringify([...observer.progress.values()]).includes('/private/'), false);
  observer.close();
  assert.equal(observer.closed, true);
  assert.equal(connection.eventNames().length, 0);
});

test('unexpected download origins and unmatched completions are refused rather than inferred as complete', () => {
  const connection = new EventEmitter();
  const observer = observeDownload({ cdpSupported: false, connection },
    { mainFrame: () => ({ browsingContext: { id: 'owned-context' } }) }, origin);
  connection.emit('browsingContext.downloadWillBegin', { context: 'owned-context', url: 'blob:https://other.invalid/id', navigation: 'wrong', suggestedFilename: 'owned-download.bin' });
  connection.emit('browsingContext.downloadEnd', { context: 'owned-context', navigation: 'wrong', status: 'complete' });
  assert.equal(observer.started.length, 0);
  assert.equal(observer.progress.size, 0);
  assert.equal(observer.errors.length, 2);
  observer.close();
});
