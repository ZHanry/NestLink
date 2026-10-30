const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createPermitResponseObserver, preparePermitResponseObservation,
  createManagementResponseObserver, prepareManagementResponseObservation } = require('../../scripts/lib/refactor-browser-response-observer.cjs');
const { prepareNetworkDamage } = require('../../scripts/lib/refactor-browser-network-damage.cjs');

const origin = 'https://127.0.0.1:43817';
const sessionId = '1b270a31-41d1-4916-89dd-33d1bb275b8f';
const controllerId = 'd0c524d8-63dd-4b64-a6a8-4072dc470e60';
const disconnected = Symbol('public-CDPSession.Disconnected');
const permitUrl = origin + '/api/v3/remote/' + sessionId + '/permit';
const renewUrl = origin + '/api/v3/remote/' + sessionId + '/renew';
const privateToken = 'PRIVATE_TOKEN_MUST_NOT_BE_RETAINED';
const body = (changes = {}) => ({ permit: privateToken,
  claims: { lease_sequence: 1, connection_generation: 1, session_id: sessionId,
    controller_device_id: controllerId, issued_at_unix_ms: 1800000000000,
    expires_at_unix_ms: 1800000010000, secret_extra: privateToken, ...changes }, secret_extra: privateToken });
const turn = () => new Promise(resolve => setImmediate(resolve));

test('management CAS evidence uses an early bounded stream on its own session, including actual HTTP 201', async () => {
  const session = new EventEmitter(), facts = {}, received = [], errors = [], calls = [];
  const value = { revision: 7, membership_epoch: 4, secret_extra: privateToken };
  session.send = async (method, params) => {
    calls.push({ method, params });
    assert.equal(method, 'Network.streamResourceContent');
    return { bufferedData: Buffer.from(JSON.stringify(value)).toString('base64') };
  };
  const observer = createManagementResponseObserver({ session, origin, disconnectedEvent: disconnected, facts,
    routes: [{ method: 'PUT', path: /^\/api\/v3\/network\/spaces\/fixture\/authority$/ }],
    onResponse: (operation, response, requestId) => received.push({ operation, response, requestId }),
    onError: error => errors.push(error) });
  const url = origin + '/api/v3/network/spaces/fixture/authority';
  for (const [requestId, requestUrl, method] of [['unowned-origin', url.replace('127.0.0.1', 'localhost'), 'PUT'],
    ['unowned-method', url, 'GET'], ['unowned-query', url + '?token=private', 'PUT'], ['1', url, 'PUT']]) {
    session.emit('Network.requestWillBeSent', { requestId, request: { url: requestUrl, method } });
    session.emit('Network.responseReceived', { requestId, response: { url: requestUrl, status: 201 } });
    session.emit('Network.loadingFinished', { requestId, encodedDataLength: 128 });
  }
  await observer.close();
  assert.equal(calls.length, 1);
  assert.deepEqual(received, [{ operation: 'PUT /api/v3/network/spaces/fixture/authority',
    response: { status: 201, body: value }, requestId: '1' }]);
  assert.equal(errors.length, 0);
  assert.equal(facts.claims_observed, 0);
  assert.equal(facts.json_responses_observed, 1);
  assert.equal(facts.observations[0].status, 201);
  assert.equal(facts.observations[0].stream.raw_buffers_cleared, true);
  assert.equal(facts.passed, true);
  assert.equal(session.eventNames().length, 0);
  noPrivateOutput(facts);
});

test('management observer prepares the existing primary page before relevant requests and cleans its exact session', async () => {
  const session = new EventEmitter(), calls = [], facts = {};
  session.send = async method => {
    calls.push(method);
    return method === 'Network.streamResourceContent' ? { bufferedData: Buffer.from('[{"revision":1}]').toString('base64') } : {};
  };
  session.detach = async () => { calls.push('detach'); };
  const owner = await prepareManagementResponseObservation({ origin, facts, disconnectedEvent: disconnected,
    page: { url: () => origin, createCDPSession: async () => session },
    routes: [{ method: 'GET', path: /^\/api\/v3\/network\/spaces\/fixture\/policy$/ }],
    onResponse() {}, onError() {} });
  const url = origin + '/api/v3/network/spaces/fixture/policy';
  const expected = owner.expect('GET /api/v3/network/spaces/fixture/policy');
  assert.throws(() => owner.expect('GET /api/v3/network/spaces/fixture/policy'), /overlapping/);
  session.emit('Network.requestWillBeSent', { requestId: '1', request: { url, method: 'GET' } });
  session.emit('Network.responseReceived', { requestId: '1', response: { url, status: 200 } });
  session.emit('Network.loadingFinished', { requestId: '1', encodedDataLength: 16 });
  assert.deepEqual(await expected.promise, [{ revision: 1 }]);
  expected.cancel();
  await owner.close();
  assert.throws(() => owner.expect('GET /api/v3/network/spaces/fixture/policy'), /Invalid/);
  assert.deepEqual(calls, ['Network.enable', 'Network.streamResourceContent', 'Network.disable', 'detach']);
  assert.equal(facts.session_owner.prepared_before_navigation, false);
  assert.equal(facts.session_owner.prepared_before_relevant_requests, true);
  assert.equal(facts.session_owner.passed, true);
  assert.equal(session.eventNames().length, 0);
});

test('missing management stream and completed body fail closed and remove every listener', async () => {
  const session = new EventEmitter(), facts = {}, received = [], errors = [];
  session.send = async () => { throw new Error('resource no longer available'); };
  const observer = createManagementResponseObserver({ session, origin, disconnectedEvent: disconnected, facts,
    routes: [{ method: 'GET', path: /^\/api\/v3\/network\/spaces\/fixture\/policy$/ }],
    onResponse: value => received.push(value), onError: value => errors.push(value) });
  const url = origin + '/api/v3/network/spaces/fixture/policy';
  session.emit('Network.requestWillBeSent', { requestId: '1', request: { url, method: 'GET' } });
  session.emit('Network.responseReceived', { requestId: '1', response: { url, status: 200 } });
  session.emit('Network.loadingFinished', { requestId: '1', encodedDataLength: 16 });
  await assert.rejects(observer.close(), /observation failed/);
  assert.equal(received.length, 0);
  assert.equal(errors.length, 1);
  assert.equal(facts.passed, false);
  assert.equal(facts.pending, 0);
  assert.equal(session.eventNames().length, 0);
});

function owned({ send, limits = {} } = {}) {
  const session = new EventEmitter();
  const calls = [];
  session.send = async (method, params) => {
    calls.push({ method, params });
    return send ? send(method, params) : { bufferedData: Buffer.from(JSON.stringify(body())).toString('base64') };
  };
  const facts = {}, claims = [], errors = [];
  const observer = createPermitResponseObserver({ session, origin, disconnectedEvent: disconnected,
    facts, onClaims: (operation, value) => claims.push({ operation, value }), onError: error => errors.push(error), limits });
  const request = (requestId = '1', url = permitUrl, method = 'POST', metadata = {}) => session.emit('Network.requestWillBeSent',
    { ...metadata, requestId, request: { url, method } });
  const response = (requestId = '1', url = permitUrl, status = 200, metadata = {}, details = {}) => session.emit('Network.responseReceived',
    { ...metadata, requestId, response: { ...details, url, status } });
  const finished = (requestId = '1', encodedDataLength = 1024) => session.emit('Network.loadingFinished',
    { requestId, encodedDataLength });
  const data = (requestId, bytes, metadata = {}) => session.emit('Network.dataReceived',
    { requestId, dataLength: bytes.length, encodedDataLength: bytes.length, data: bytes.toString('base64'), ...metadata });
  const failed = (requestId = '1', metadata = {}) => session.emit('Network.loadingFailed',
    { requestId, errorText: 'net::ERR_ABORTED', canceled: true, ...metadata });
  return { session, calls, facts, claims, errors, observer, request, response, finished, data, failed };
}

function noPrivateOutput(value) {
  assert.equal(JSON.stringify(value).includes(privateToken), false);
}

test('the existing session starts the exact POST content stream on response headers and emits allowlisted claims only after a terminal', async () => {
  const ownedValue = owned();
  const { request, response, finished, calls, facts, claims, observer } = ownedValue;
  request(); response();
  await turn();
  assert.equal(calls.length, 1);
  assert.equal(claims.length, 0);
  finished();
  await turn();
  assert.deepEqual(calls, [{ method: 'Network.streamResourceContent', params: { requestId: '1' } }]);
  assert.equal(claims[0].operation, 'permit');
  assert.deepEqual(Object.keys(claims[0].value).sort(), ['lease_sequence', 'connection_generation',
    'session_id', 'controller_device_id', 'issued_at_unix_ms', 'expires_at_unix_ms',
    'observed_monotonic_ms', 'observed_unix_ms'].sort());
  assert.ok(claims[0].value.observed_monotonic_ms > 0);
  assert.ok(claims[0].value.observed_unix_ms > 0);
  await observer.close();
  assert.equal(facts.claims_observed, 1);
  assert.equal(facts.schema_version, 3);
  assert.equal(facts.network_all_completed_normally, true);
  assert.equal(facts.normal_loads, 1);
  assert.equal(facts.failed_loads, 0);
  assert.equal(facts.observations[0].stream.raw_buffers_cleared, true);
  assert.equal(facts.passed, true);
  assert.equal(facts.pending, 0);
  assert.equal(facts.listeners_removed, true);
  assert.equal(ownedValue.session.eventNames().length, 0);
  noPrivateOutput({ facts, claims });
});

test('base64 renewal bodies are decoded in memory and matched to the original request identifier', async () => {
  const value = owned({ send: async () => ({ bufferedData: Buffer.from(JSON.stringify(body({ lease_sequence: 2 }))).toString('base64') }) });
  value.request('renewal', renewUrl);
  value.response('unowned', renewUrl);
  value.finished('unowned');
  assert.equal(value.calls.length, 0);
  value.response('renewal', renewUrl);
  value.finished('renewal');
  await value.observer.close();
  assert.equal(value.claims.length, 1);
  assert.equal(value.claims[0].operation, 'renew');
  assert.equal(value.claims[0].value.lease_sequence, 2);
  noPrivateOutput(value.facts);
});

test('another origin, port, method, credentials, route, query or fragment cannot supply permit evidence', async () => {
  const value = owned();
  const cases = [[permitUrl.replace('127.0.0.1', 'localhost'), 'POST'], [permitUrl.replace('43817', '43818'), 'POST'],
    [permitUrl.replace('https://', 'http://'), 'POST'], [permitUrl, 'GET'], [permitUrl + '?token=private', 'POST'],
    [permitUrl + '#suffix', 'POST'], [permitUrl.replace('127.0.0.1', 'user@127.0.0.1'), 'POST'],
    [permitUrl.replace(sessionId, 'not-a-uuid'), 'POST'], [permitUrl + '/extra', 'POST'],
    [permitUrl.replace('/api/', '/API/'), 'POST'], [permitUrl.replace('/permit', '/Permit'), 'POST']];
  for (const [index, [url, method]] of cases.entries()) {
    value.request(String(index), url, method); value.response(String(index), url); value.finished(String(index));
  }
  await value.observer.close();
  assert.equal(value.calls.length, 0);
  assert.equal(value.facts.requests_tracked, 0);
  assert.equal(value.facts.passed, false);
});

test('HTTP failures cannot become successful response evidence or body reads', async () => {
  const value = owned();
  value.request(); value.response('1', permitUrl, 403); value.finished();
  await value.observer.close();
  assert.equal(value.calls.length, 0);
  assert.equal(value.facts.pending, 0);
  assert.equal(value.facts.successful_responses, 0);
  assert.equal(value.facts.passed, false);
});

test('redirected or reused request identifiers fail without reading a different response', async () => {
  for (const redirect of [false, true]) {
    const value = owned();
    value.request();
    if (redirect) value.request('1', renewUrl);
    else value.response('1', renewUrl);
    value.finished();
    await assert.rejects(value.observer.close(), /observation failed/);
    assert.equal(value.calls.length, 0);
    assert.equal(value.errors[0].error_type, redirect ? 'RedirectError' : 'ResponseIdentityError');
    assert.equal(value.facts.pending, 0);
  }
});

test('loadingFinished cannot substitute for the actual successful HTTP response', async () => {
  const value = owned();
  value.request(); value.finished();
  await assert.rejects(value.observer.close(), /observation failed/);
  assert.equal(value.errors[0].error_type, 'ResponseIdentityError');
  assert.equal(value.calls.length, 0);
});

test('missing terminal fails at the bounded request deadline even with a full available prefix', async () => {
  const value = owned({ limits: { requestTimeoutMs: 20, drainTimeoutMs: 100 } });
  value.request(); value.response();
  await new Promise(resolve => setTimeout(resolve, 35));
  await assert.rejects(value.observer.close(), /observation failed/);
  assert.equal(value.errors[0].stage, 'loading-terminal');
  assert.equal(value.errors[0].error_type, 'TimeoutError');
  assert.equal(value.calls.length, 1);
  assert.equal(value.facts.pending, 0);
});

test('bounded close drains an existing request before removing its response listeners', async () => {
  const value = owned();
  value.request(); value.response();
  const close = value.observer.close();
  assert.equal(value.session.listenerCount('Network.requestWillBeSent'), 0);
  assert.equal(value.session.listenerCount('Network.loadingFinished'), 1);
  value.finished();
  await close;
  assert.equal(value.facts.passed, true);
  assert.equal(value.session.eventNames().length, 0);
});

test('a shutdown deadline reports unfinished responses and removes every listener and pending item', async () => {
  const value = owned({ limits: { drainTimeoutMs: 20 } });
  value.request(); value.response();
  const first = value.observer.close();
  assert.equal(first, value.observer.close());
  await assert.rejects(first, /observation failed/);
  assert.equal(value.errors[0].stage, 'drain');
  assert.equal(value.facts.pending, 0);
  assert.equal(value.facts.closed, true);
  assert.equal(value.facts.listeners_removed, true);
  assert.equal(value.session.eventNames().length, 0);
  assert.equal(value.facts.passed, false);
});

test('a failed load retains its fixed message and redacts arbitrary CDP error text', async () => {
  const value = owned();
  value.request(); value.response();
  value.session.emit('Network.loadingFailed', { requestId: '1', errorText: privateToken });
  await assert.rejects(value.observer.close(), /observation failed/);
  assert.equal(value.errors[0].stage, 'loading-failed');
  assert.equal(value.errors[0].network.loading_failed.error_text, null);
  assert.equal(value.errors[0].network.loading_failed.error_text_redacted, true);
  assert.equal(value.facts.pending, 0);
  noPrivateOutput({ facts: value.facts, errors: value.errors });
});

test('a matching 200 followed by loadingFailed retains raw Chromium metadata from the same owned session and request', async () => {
  const value = owned();
  const requestId = '29176.47';
  const loader = 'A123456789ABCDEF0123456789ABCDEF';
  const frame = 'B123456789ABCDEF0123456789ABCDEF';
  value.request(requestId, permitUrl, 'POST', { loaderId: loader, frameId: frame,
    type: 'Fetch', timestamp: 4200.1, wallTime: 1800000000.25 });
  value.response(requestId, permitUrl, 200, { loaderId: loader, frameId: frame, type: 'Fetch', timestamp: 4200.2 },
    { protocol: 'h2', connectionId: 27, connectionReused: true, fromDiskCache: false,
      fromServiceWorker: false, fromPrefetchCache: false });
  const unrelated = new EventEmitter();
  unrelated.emit('Network.loadingFailed', { requestId, errorText: 'net::ERR_FAILED', canceled: false });
  value.session.emit('Network.loadingFailed', { requestId: '29176.48', errorText: 'net::ERR_FAILED', canceled: false });
  assert.equal(value.errors.length, 0);
  assert.equal(value.facts.pending, 1);
  value.session.emit('Network.loadingFailed', { requestId, errorText: 'net::ERR_ABORTED', canceled: true,
    blockedReason: 'inspector', type: 'Fetch', timestamp: 4200.3 });
  await assert.rejects(value.observer.close(), /observation failed/);
  const failure = value.errors[0];
  assert.equal(failure.status, 200);
  assert.equal(failure.stage, 'loading-failed');
  assert.equal(failure.network.request_id, requestId);
  assert.equal(failure.network.request_ordinal, 1);
  assert.deepEqual(failure.network.request, { loader_id: loader, loader_id_redacted: false,
    frame_id: frame, frame_id_redacted: false, resource_type: 'Fetch', resource_type_redacted: false,
    timestamp: 4200.1, wall_time: 1800000000.25 });
  assert.deepEqual(failure.network.response, { loader_id: loader, loader_id_redacted: false,
    frame_id: frame, frame_id_redacted: false, resource_type: 'Fetch', resource_type_redacted: false,
    timestamp: 4200.2, protocol: 'h2', protocol_redacted: false, connection_id: 27,
    connection_reused: true, from_disk_cache: false, from_service_worker: false, from_prefetch_cache: false });
  const failed = failure.network.loading_failed;
  assert.equal(failed.error_text, 'net::ERR_ABORTED');
  assert.equal(failed.error_text_redacted, false);
  assert.equal(failed.canceled, true);
  assert.equal(failed.blocked_reason, 'inspector');
  assert.equal(failed.blocked_reason_redacted, false);
  assert.equal(failed.resource_type, 'Fetch');
  assert.equal(failed.timestamp, 4200.3);
  assert.ok(failed.observed_monotonic_ms > 0);
  assert.ok(failed.observed_unix_ms > 0);
  assert.equal(value.facts.schema_version, 3);
  assert.equal(value.facts.successful_responses, 1);
  assert.equal(value.facts.claims_observed, 0);
  assert.equal(value.facts.pending, 0);
  assert.equal(value.calls.length, 1);
  noPrivateOutput({ facts: value.facts, errors: value.errors });
});

test('concurrent owned request failures keep their original request and response metadata separate', async () => {
  const value = owned();
  value.request('29176.47');
  value.request('29176.48', renewUrl);
  value.response('29176.48', renewUrl, 200, { timestamp: 22 }, { protocol: 'http/1.1' });
  value.response('29176.47', permitUrl, 200, { timestamp: 11 }, { protocol: 'h2' });
  value.session.emit('Network.loadingFailed', { requestId: '29176.48', timestamp: 23,
    errorText: 'net::ERR_CONNECTION_RESET', canceled: false });
  value.session.emit('Network.loadingFailed', { requestId: '29176.47', timestamp: 12,
    errorText: 'net::ERR_HTTP2_PROTOCOL_ERROR', canceled: false });
  await assert.rejects(value.observer.close(), /observation failed/);
  assert.deepEqual(value.errors.map(error => [error.path, error.network.request_id, error.network.request_ordinal,
    error.network.response.protocol, error.network.response.timestamp, error.network.loading_failed.error_text,
    error.network.loading_failed.timestamp]), [
    [new URL(renewUrl).pathname, '29176.48', 2, 'http/1.1', 22, 'net::ERR_CONNECTION_RESET', 23],
    [new URL(permitUrl).pathname, '29176.47', 1, 'h2', 11, 'net::ERR_HTTP2_PROTOCOL_ERROR', 12],
  ]);
  assert.equal(value.facts.pending, 0);
  assert.equal(value.claims.length, 0);
  assert.equal(value.calls.length, 2);
});

test('absent CDP diagnostics stay unknown instead of implying cancellation, a protocol or a blocked reason', async () => {
  const value = owned();
  value.request(); value.response();
  value.session.emit('Network.loadingFailed', { requestId: '1' });
  await assert.rejects(value.observer.close(), /observation failed/);
  const network = value.errors[0].network;
  assert.equal(network.request_id, '1');
  assert.equal(network.request.timestamp, null);
  assert.equal(network.request.wall_time, null);
  assert.equal(network.response.protocol, null);
  assert.equal(network.response.protocol_redacted, false);
  assert.equal(network.response.connection_reused, null);
  assert.equal(network.loading_failed.error_text, null);
  assert.equal(network.loading_failed.error_text_redacted, false);
  assert.equal(network.loading_failed.canceled, null);
  assert.equal(network.loading_failed.blocked_reason, null);
  assert.equal(network.loading_failed.blocked_reason_redacted, false);
  assert.equal(network.loading_failed.timestamp, null);
  assert.equal(network.loading_failed.cors_error, null);
  assert.equal(network.loading_failed.cors_error_redacted, false);
});

test('diagnostic metadata is bounded and cannot retain headers, arbitrary identifiers, enums or failed CORS parameters', async () => {
  const value = owned();
  value.request(privateToken, permitUrl, 'POST', { loaderId: privateToken, frameId: privateToken,
    type: privateToken, timestamp: Infinity, wallTime: -1, initiator: { secret: privateToken } });
  value.response(privateToken, permitUrl, 200, { loaderId: privateToken, frameId: privateToken,
    type: privateToken, timestamp: Number.MAX_SAFE_INTEGER + 1 }, { protocol: privateToken,
    connectionId: -1, connectionReused: privateToken, fromDiskCache: privateToken,
    fromServiceWorker: privateToken, fromPrefetchCache: privateToken,
    headers: { authorization: privateToken }, timing: { secret: privateToken } });
  value.session.emit('Network.loadingFailed', { requestId: privateToken, errorText: 'net::ERR_' + 'A'.repeat(81),
    canceled: privateToken, blockedReason: privateToken, type: privateToken, timestamp: privateToken,
    corsErrorStatus: { corsError: 'MissingAllowOriginHeader', failedParameter: privateToken }, extra: privateToken });
  await assert.rejects(value.observer.close(), /observation failed/);
  const network = value.errors[0].network;
  assert.equal(network.request_id, null);
  assert.equal(network.request_id_redacted, true);
  assert.equal(network.request_ordinal, 1);
  assert.equal(network.request.loader_id_redacted, true);
  assert.equal(network.request.frame_id_redacted, true);
  assert.equal(network.request.resource_type_redacted, true);
  assert.equal(network.request.timestamp, null);
  assert.equal(network.request.wall_time, null);
  assert.equal(network.response.protocol_redacted, true);
  assert.equal(network.response.timestamp, null);
  assert.equal(network.response.connection_id, null);
  assert.equal(network.response.connection_reused, null);
  assert.equal(network.loading_failed.error_text_redacted, true);
  assert.equal(network.loading_failed.blocked_reason_redacted, true);
  assert.equal(network.loading_failed.canceled, null);
  assert.equal(network.loading_failed.cors_error, 'MissingAllowOriginHeader');
  assert.equal(network.loading_failed.cors_failed_parameter_present, true);
  assert.equal(JSON.stringify(network).includes('A'.repeat(81)), false);
  noPrivateOutput({ facts: value.facts, errors: value.errors });
});

test('unknown CORS enums are redacted and a failure before response headers retains no invented response', async () => {
  const value = owned();
  value.request();
  value.session.emit('Network.loadingFailed', { requestId: '1', errorText: 'net::ERR_FAILED', canceled: false,
    corsErrorStatus: { corsError: privateToken, failedParameter: privateToken } });
  await assert.rejects(value.observer.close(), /observation failed/);
  const failure = value.errors[0];
  assert.equal(failure.status, null);
  assert.equal(failure.network.response, null);
  assert.equal(failure.network.loading_failed.cors_error, null);
  assert.equal(failure.network.loading_failed.cors_error_redacted, true);
  assert.equal(value.facts.successful_responses, 0);
  noPrivateOutput({ facts: value.facts, errors: value.errors });
});

test('target loss uses the public CDPSession event symbol and fails even without pending requests', async () => {
  for (const pending of [false, true]) {
    const value = owned();
    if (pending) { value.request(); value.response(); }
    value.session.emit(disconnected);
    await assert.rejects(value.observer.close(), /observation failed/);
    assert.equal(value.facts.session_lost, true);
    assert.equal(value.errors[0].error_type, 'TargetCloseError');
    assert.equal(value.facts.pending, 0);
    assert.equal(value.session.eventNames().length, 0);
  }
  assert.throws(() => createPermitResponseObserver({ session: new EventEmitter(), origin,
    disconnectedEvent: 'Disconnected', facts: {}, onClaims() {}, onError() {} }), /public disconnected-event symbol/);
});

test('unavailable streaming reads the same owned response only after normal loadingFinished', async () => {
  const bytes = Buffer.from(JSON.stringify(body()));
  const methods = [];
  const value = owned({ send: async method => {
    methods.push(method);
    if (method === 'Network.streamResourceContent') {
      const error = new Error(privateToken); error.name = 'ProtocolError'; throw error;
    }
    return { body: bytes.toString('utf8'), base64Encoded: false };
  } });
  value.request(); value.response();
  await turn();
  assert.deepEqual(methods, ['Network.streamResourceContent']);
  assert.equal(value.claims.length, 0);
  value.finished();
  await value.observer.close();
  assert.deepEqual(methods, ['Network.streamResourceContent', 'Network.getResponseBody']);
  assert.equal(value.claims.length, 1);
  assert.equal(value.facts.observations[0].stream.enabled, false);
  assert.equal(value.facts.observations[0].stream.fallback_used, true);
  assert.equal(value.facts.observations[0].stream.retrieval_method, 'Network.getResponseBody');
  assert.equal(value.facts.observations[0].stream.complete_json, true);
  assert.equal(value.facts.observations[0].stream.raw_buffers_cleared, true);
  assert.equal(value.facts.network_all_completed_normally, true);
  assert.equal(value.facts.passed, true);
  noPrivateOutput({ facts: value.facts, claims: value.claims });
});

test('failed or canceled loads never use the completed-response body fallback', async () => {
  const methods = [];
  const value = owned({ send: async method => {
    methods.push(method);
    if (method === 'Network.streamResourceContent') throw new Error(privateToken);
    return { body: JSON.stringify(body()), base64Encoded: false };
  } });
  value.request(); value.response(); value.failed();
  await assert.rejects(value.observer.close(), /observation failed/);
  assert.deepEqual(methods, ['Network.streamResourceContent']);
  assert.equal(value.errors[0].stage, 'response-stream');
  assert.equal(value.errors[0].error_type, 'ProtocolError');
  assert.equal(value.facts.pending, 0);
  noPrivateOutput({ facts: value.facts, errors: value.errors });
});

test('completed-response fallback enforces the existing body bound and JSON validation', async () => {
  const oversized = owned({ limits: { maxBodyBytes: 256 }, send: async method => {
    if (method === 'Network.streamResourceContent') throw new Error(privateToken);
    return { body: 'x'.repeat(257), base64Encoded: false };
  } });
  oversized.request(); oversized.response(); oversized.finished('1', 128);
  await assert.rejects(oversized.observer.close(), /observation failed/);
  assert.equal(oversized.errors[0].stage, 'response-body');
  assert.equal(oversized.errors[0].error_type, 'BodyLimitError');
  noPrivateOutput({ facts: oversized.facts, errors: oversized.errors });

  const malformed = owned({ send: async method => {
    if (method === 'Network.streamResourceContent') throw new Error(privateToken);
    return { body: privateToken, base64Encoded: false };
  } });
  malformed.request(); malformed.response(); malformed.finished();
  await assert.rejects(malformed.observer.close(), /observation failed/);
  assert.equal(malformed.errors[0].stage, 'response-json');
  assert.equal(malformed.errors[0].error_type, 'SyntaxError');
  assert.equal(malformed.facts.observations[0].stream.raw_buffers_cleared, true);
  noPrivateOutput({ facts: malformed.facts, errors: malformed.errors });
});

test('a never-settling body read has a retrieval deadline and also responds to target loss', async () => {
  for (const targetLoss of [false, true]) {
    const value = owned({ send: () => new Promise(() => {}), limits: { bodyTimeoutMs: 20, drainTimeoutMs: 200 } });
    value.request(); value.response(); value.finished();
    if (targetLoss) value.session.emit(disconnected);
    await assert.rejects(value.observer.close(), /observation failed/);
    assert.equal(value.errors[0].error_type, targetLoss ? 'TargetCloseError' : 'TimeoutError');
    assert.equal(value.facts.pending, 0);
    assert.equal(value.facts.closed, true);
    assert.equal(value.session.eventNames().length, 0);
  }
});

test('invalid JSON and invalid claims fail with fixed messages that cannot quote private response data', async () => {
  const variants = [privateToken, JSON.stringify(body({ lease_sequence: '1' })),
    JSON.stringify(body({ controller_device_id: null })), JSON.stringify(body({ session_id: controllerId })),
    JSON.stringify(body({ expires_at_unix_ms: 1800000000000 })), JSON.stringify(body({ issued_at_unix_ms: Number.MAX_SAFE_INTEGER + 1 }))];
  for (const [index, json] of variants.entries()) {
    const value = owned({ send: async () => ({ bufferedData: Buffer.from(json).toString('base64') }) });
    value.request(); value.response(); value.finished();
    await assert.rejects(value.observer.close(), /observation failed/);
    assert.equal(value.errors[0].error_type, index === 0 ? 'SyntaxError' : 'ClaimsError');
    assert.equal(value.claims.length, 0);
    noPrivateOutput({ facts: value.facts, errors: value.errors });
  }
});

test('pending, transfer and decoded-body byte bounds cannot be exceeded silently', async () => {
  const pendingValue = owned({ limits: { maxPending: 1, drainTimeoutMs: 20 } });
  pendingValue.request(); pendingValue.request('2');
  assert.equal(pendingValue.facts.peak_pending, 1);
  await assert.rejects(pendingValue.observer.close(), /observation failed/);
  assert.equal(pendingValue.errors[0].error_type, 'PendingLimitError');
  for (const transfer of [false, true]) {
    const value = owned({ send: async () => ({ bufferedData: Buffer.from('x'.repeat(2000)).toString('base64') }), limits: { maxBodyBytes: 1200 } });
    value.request(); value.response(); value.finished('1', transfer ? 2000 : 1024);
    await assert.rejects(value.observer.close(), /observation failed/);
    assert.equal(value.errors[0].error_type, 'BodyLimitError');
    assert.equal(value.calls.length, 1);
    assert.equal(value.facts.pending, 0);
  }
});

test('late body completion and post-close events cannot mutate retained observations', async () => {
  let resolveBody;
  const value = owned({ send: () => new Promise(resolve => { resolveBody = resolve; }), limits: { drainTimeoutMs: 20 } });
  value.request(); value.response(); value.finished();
  await assert.rejects(value.observer.close(), /observation failed/);
  const frozen = JSON.stringify({ facts: value.facts, claims: value.claims, errors: value.errors });
  const lateReply = { bufferedData: Buffer.from(JSON.stringify(body())).toString('base64') };
  resolveBody(lateReply);
  value.request('late'); value.response('late'); value.finished('late'); value.session.emit(disconnected);
  await turn();
  assert.equal(lateReply.bufferedData, null);
  assert.equal(JSON.stringify({ facts: value.facts, claims: value.claims, errors: value.errors }), frozen);
});

test('owner cleanup drains observations before disabling/detaching the one existing page session', async () => {
  const session = new EventEmitter();
  const calls = [];
  session.send = async method => {
    calls.push(method);
    return method === 'Network.streamResourceContent' ? { bufferedData: Buffer.from(JSON.stringify(body())).toString('base64') } : {};
  };
  session.detach = async () => { calls.push('detach'); session.emit(disconnected); };
  const page = { url: () => 'about:blank', createCDPSession: async () => { calls.push('createCDPSession'); return session; } };
  const facts = {}, observationFacts = {};
  const owner = await prepareNetworkDamage({ page, origin, facts,
    responseObserver: { disconnectedEvent: disconnected, facts: observationFacts, onClaims() {}, onError() {} } });
  session.emit('Network.requestWillBeSent', { requestId: '1', request: { method: 'POST', url: permitUrl } });
  session.emit('Network.responseReceived', { requestId: '1', response: { status: 200, url: permitUrl } });
  const close = owner.close();
  assert.equal(calls.includes('Network.disable'), false);
  session.emit('Network.loadingFinished', { requestId: '1', encodedDataLength: 1024 });
  await close;
  assert.equal(calls.filter(method => method === 'createCDPSession').length, 1);
  assert.equal(calls.filter(method => method === 'Network.enable').length, 1);
  assert.ok(calls.indexOf('Network.streamResourceContent') < calls.indexOf('Network.disable'));
  assert.equal(calls.includes('Network.getResponseBody'), false);
  assert.equal(observationFacts.passed, true);
  assert.equal(observationFacts.session_lost, false);
  assert.equal(facts.conditions_restored, true);
  assert.equal(facts.session_detached, true);
  assert.equal(facts.passed, false); // No actual RTP exercise was performed.
});

test('observation failure never prevents the network owner from restoring/disabling/detaching', async () => {
  const session = new EventEmitter();
  const calls = [];
  session.send = async method => { calls.push(method); return {}; };
  session.detach = async () => { calls.push('detach'); session.emit(disconnected); };
  const facts = {}, observationFacts = {};
  const owner = await prepareNetworkDamage({ origin, facts,
    page: { url: () => 'about:blank', createCDPSession: async () => session },
    responseObserver: { disconnectedEvent: disconnected, facts: observationFacts, onClaims() {}, onError() {} } });
  session.emit(disconnected);
  await assert.rejects(owner.close(), /cleanup failed/);
  assert.equal(facts.cleanup_errors[0].operation, 'response-observer');
  assert.equal(facts.conditions_restored, true);
  assert.equal(facts.network_disabled, true);
  assert.equal(facts.session_detached, true);
  assert.equal(facts.passed, false);
  assert.equal(observationFacts.listeners_removed, true);
});

async function rejectedStream(value, type, stage) {
  await assert.rejects(value.observer.close(), /observation failed/);
  assert.equal(value.errors[0].error_type, type);
  if (stage) assert.equal(value.errors[0].stage, stage);
  assert.equal(value.facts.pending, 0);
  assert.equal(value.facts.passed, false);
  assert.equal(value.session.eventNames().length, 0);
  assert.ok(value.facts.observations.every(item => item.stream.raw_buffers_cleared));
  noPrivateOutput({ facts: value.facts, claims: value.claims, errors: value.errors });
}

test('the buffered prefix precedes all data-bearing events even when chunks and terminal precede its reply', async () => {
  const full = Buffer.from(JSON.stringify(body()));
  let resolveStream;
  const value = owned({ send: () => new Promise(resolve => { resolveStream = resolve; }) });
  value.request(); value.response();
  value.data('1', full.subarray(0, 99), { data: undefined });
  value.data('1', full.subarray(99, 180)); value.data('1', full.subarray(180)); value.finished();
  assert.equal(value.claims.length, 0);
  const close = value.observer.close();
  resolveStream({ bufferedData: full.subarray(0, 99).toString('base64') });
  await close;
  assert.equal(value.claims.length, 1);
  assert.equal(value.facts.observations[0].stream.buffered_bytes, 99);
  assert.equal(value.facts.observations[0].stream.decoded_bytes, full.length);
  assert.equal(value.facts.observations[0].stream.pre_stream_data_events, 1);
  assert.equal(value.facts.observations[0].stream.data_chunks, 2);
  assert.equal(value.facts.observations[0].stream.raw_buffers_cleared, true);
  noPrivateOutput(value.facts);
});

test('a canceled terminal arriving before stream reply waits for that reply and queued chunk data', async () => {
  const full = Buffer.from(JSON.stringify(body()));
  let resolveStream;
  const value = owned({ send: () => new Promise(resolve => { resolveStream = resolve; }) });
  value.request(); value.response(); value.failed();
  const close = value.observer.close();
  value.data('1', full.subarray(99));
  await turn();
  assert.equal(value.claims.length, 0);
  resolveStream({ bufferedData: full.subarray(0, 99).toString('base64') });
  await close;
  assert.equal(value.claims.length, 1);
  assert.equal(value.facts.passed, true); // Content observation, never normal load completion.
  assert.equal(value.facts.normal_loads, 0);
  assert.equal(value.facts.failed_loads, 1);
  assert.equal(value.facts.canceled_loads, 1);
  assert.equal(value.facts.network_all_completed_normally, false);
  const observation = value.facts.observations[0];
  assert.equal(observation.network_completion, 'canceled');
  assert.equal(observation.network.loading_finished, null);
  assert.equal(observation.network.loading_failed.error_text, 'net::ERR_ABORTED');
  assert.equal(observation.network.loading_failed.canceled, true);
  assert.equal(observation.stream.complete_json, true);
  noPrivateOutput({ facts: value.facts, claims: value.claims });
});

test('post-reply chunks remain ordered and UTF-8 may span base64 chunk boundaries', async () => {
  const full = Buffer.from(JSON.stringify({ ...body(), ignored: '汉字' }));
  const cut = full.indexOf(Buffer.from('汉')) + 1;
  const value = owned({ send: async () => ({ bufferedData: full.subarray(0, cut).toString('base64') }) });
  value.request(); value.response(); await turn();
  value.data('1', full.subarray(cut, cut + 1)); value.data('1', full.subarray(cut + 1)); value.finished();
  await value.observer.close();
  assert.equal(value.facts.passed, true);
  assert.equal(value.facts.observations[0].stream.decoded_bytes, full.length);
  assert.equal(value.facts.observations[0].stream.raw_buffers_cleared, true);
});

test('concurrent successful and canceled request streams never mix body chunks or terminal facts', async () => {
  const contents = new Map([['29176.47', Buffer.from(JSON.stringify(body()))],
    ['29176.48', Buffer.from(JSON.stringify(body({ lease_sequence: 2 })))] ]);
  const value = owned({ send: async (_method, params) => ({ bufferedData: contents.get(params.requestId).subarray(0, 99).toString('base64') }) });
  value.request('29176.47'); value.request('29176.48', renewUrl);
  value.response('29176.48', renewUrl); value.response('29176.47');
  value.data('29176.47', contents.get('29176.47').subarray(99));
  value.data('29176.48', contents.get('29176.48').subarray(99));
  value.failed('29176.48'); value.finished('29176.47');
  await value.observer.close();
  assert.equal(value.claims.length, 2);
  assert.equal(value.claims.find(item => item.operation === 'renew').value.lease_sequence, 2);
  assert.equal(value.facts.observations[0].network_completion, 'finished');
  assert.equal(value.facts.observations[1].network_completion, 'canceled');
});

test('cancellation never substitutes for complete JSON or a successful streaming command', async () => {
  for (const send of [async () => ({ bufferedData: Buffer.from(JSON.stringify(body()).slice(0, -1)).toString('base64') }),
    async () => { throw new Error(privateToken); }]) {
    const value = owned({ send });
    value.request(); value.response(); value.failed();
    await assert.rejects(value.observer.close(), /observation failed/);
    assert.equal(value.claims.length, 0);
    assert.equal(value.facts.canceled_loads, 1);
    assert.equal(value.errors[0].network.loading_failed.error_text, 'net::ERR_ABORTED');
    assert.equal(value.errors[0].network.loading_finished, null);
    noPrivateOutput(value.facts);
  }
});

test('noncancel failures, blocked requests, CORS errors and unknown diagnostics still fail closed with a full body', async () => {
  const variants = [{ errorText: 'net::ERR_CONNECTION_RESET', canceled: false }, { canceled: false },
    { errorText: 'net::ERR_FAILED' }, { blockedReason: 'inspector' }, { blockedReason: privateToken },
    { corsErrorStatus: { corsError: 'MissingAllowOriginHeader', failedParameter: privateToken } },
    { corsErrorStatus: { corsError: privateToken } }, { errorText: privateToken }];
  for (const metadata of variants) {
    const value = owned();
    value.request(); value.response(); value.failed('1', metadata);
    await rejectedStream(value, 'NetworkError', 'loading-failed');
    assert.equal(value.claims.length, 0);
  }
});

test('malformed UTF-8, truncated JSON, multiple documents, trailing bytes and BOM fail with fixed safe diagnostics', async () => {
  const json = JSON.stringify(body());
  const variants = [Buffer.from(json.slice(0, -1)), Buffer.from(json + '{}'), Buffer.from(json + 'x'),
    Buffer.from('\ufeff' + json), Buffer.from(json + '\0'),
    Buffer.concat([Buffer.from(json), Buffer.from([0xc0, 0xaf])]),
    Buffer.concat([Buffer.from(json), Buffer.from([0xe6, 0xb1])])];
  for (const [index, bytes] of variants.entries()) {
    const value = owned({ send: async () => ({ bufferedData: bytes.toString('base64') }) });
    value.request(); value.response(); value.finished();
    await rejectedStream(value, index >= 5 ? 'EncodingError' : 'SyntaxError');
    assert.equal(value.claims.length, 0);
  }
});

test('coercible UUID arrays, invalid root/claims types, permit strings and unsafe lease values are rejected', async () => {
  const variants = [body({ session_id: [sessionId] }), body({ controller_device_id: [controllerId] }),
    body({ connection_generation: 0 }), body({ lease_sequence: 1.5 }),
    { ...body(), permit: privateToken + '=' }, { ...body(), claims: [] }, []];
  for (const candidate of variants) {
    const value = owned({ send: async () => ({ bufferedData: Buffer.from(JSON.stringify(candidate)).toString('base64') }) });
    value.request(); value.response(); value.finished();
    await rejectedStream(value, 'ClaimsError', 'permit-claims');
  }
});

test('claims callbacks only receive safe fields and their private exceptions never become retained diagnostics', async () => {
  const value = owned();
  // The factory callback is separate from the retained test callback.
  await value.observer.close();
  const session = new EventEmitter(), facts = {}, errors = [];
  session.send = async () => ({ bufferedData: Buffer.from(JSON.stringify(body())).toString('base64') });
  const observer = createPermitResponseObserver({ session, origin, disconnectedEvent: disconnected, facts,
    onClaims: () => { throw new Error(privateToken); }, onError: error => errors.push(error) });
  session.emit('Network.requestWillBeSent', { requestId: '1', request: { method: 'POST', url: permitUrl } });
  session.emit('Network.responseReceived', { requestId: '1', response: { status: 200, url: permitUrl } });
  session.emit('Network.loadingFinished', { requestId: '1', encodedDataLength: 1024 });
  await assert.rejects(observer.close(), /observation failed/);
  assert.equal(errors[0].error_type, 'CallbackError');
  assert.equal(facts.claims_observed, 0);
  assert.equal(facts.observations[0].stream.raw_buffers_cleared, true);
  noPrivateOutput({ facts, errors });
});

test('the stream command has a separate fixed deadline even when a terminal has already arrived', async () => {
  const value = owned({ send: () => new Promise(() => {}), limits: { bodyTimeoutMs: 10, drainTimeoutMs: 100 } });
  value.request(); value.response(); value.failed();
  await rejectedStream(value, 'TimeoutError', 'response-stream');
});

test('total request and data-event bounds cannot grow retained facts indefinitely', async () => {
  const total = owned({ limits: { maxRequests: 2 } });
  for (const id of ['1', '2', '3', '4']) { total.request(id); total.response(id, permitUrl, 403); }
  await rejectedStream(total, 'RequestLimitError');
  assert.equal(total.facts.observations.length, 2);
  assert.equal(total.errors.length, 1);
  const events = owned({ limits: { maxDataEvents: 2 } });
  events.request(); events.response();
  events.data('1', Buffer.alloc(0)); events.data('1', Buffer.alloc(0)); events.data('1', Buffer.alloc(0));
  await rejectedStream(events, 'EventLimitError');
});

test('body bytes and encoded/decoded data-event lengths are bounded before allocation or parsing', async () => {
  for (const metadata of [{ dataLength: -1 }, { dataLength: 1.5 }, { dataLength: Infinity },
    { dataLength: 1201 }, { encodedDataLength: -1 }, { encodedDataLength: 1201 }]) {
    const value = owned({ limits: { maxBodyBytes: 1200 } });
    value.request(); value.response(); value.data('1', Buffer.alloc(0), metadata);
    await rejectedStream(value, 'BodyLimitError');
  }
  for (const key of ['dataLength', 'encodedDataLength']) {
    const value = owned({ send: () => new Promise(() => {}), limits: { maxBodyBytes: 1200 } });
    value.request(); value.response();
    value.data('1', Buffer.alloc(0), { data: undefined, [key]: 800 });
    value.data('1', Buffer.alloc(0), { data: undefined, [key]: 800 });
    await rejectedStream(value, 'BodyLimitError');
  }
  const full = Buffer.from(JSON.stringify(body()));
  const value = owned({ send: async () => ({ bufferedData: full.subarray(0, 50).toString('base64') }), limits: { maxBodyBytes: full.length } });
  value.request(); value.response(); await turn(); value.data('1', full);
  await rejectedStream(value, 'BodyLimitError');
});

test('terminal transfer lengths must also be bounded nonnegative integers', async () => {
  for (const length of [-1, 0.5, Infinity, 1201]) {
    const value = owned({ limits: { maxBodyBytes: 1200 } });
    value.request(); value.response(); value.finished('1', length);
    await rejectedStream(value, 'BodyLimitError', 'loading-finished');
  }
});

test('invalid, unpadded, URL-safe and noncanonical base64 cannot use permissive Buffer decoding', async () => {
  for (const encoded of ['!!!!', 'YQ', 'YQ=', 'Zh==', 'Y Q==', '____', 'YQ===']) {
    for (const mode of ['prefix', 'chunk']) {
      const value = owned({ send: async () => ({ bufferedData: mode === 'prefix' ? encoded : '' }) });
      value.request(); value.response();
      if (mode === 'chunk') value.data('1', Buffer.alloc(1), { data: encoded });
      else value.finished();
      await rejectedStream(value, 'Base64Error');
    }
  }
});

test('missing or oversized stream reply payloads fail closed', async () => {
  for (const reply of [null, undefined, {}, { bufferedData: null }, { bufferedData: privateToken.repeat(30000) }]) {
    const value = owned({ send: async () => reply });
    value.request(); value.response(); value.finished();
    await rejectedStream(value, 'BodyLimitError');
  }
});

test('streamed chunks must match their declared decoded lengths', async () => {
  const value = owned();
  value.request(); value.response(); value.data('1', Buffer.from('abc'), { dataLength: 4 });
  await rejectedStream(value, 'ChunkLengthError');
});

test('missing chunks after enable or between data-bearing events cannot be filled by bufferedData', async () => {
  for (const afterReply of [false, true]) {
    const value = owned({ send: afterReply ? undefined : () => new Promise(() => {}) });
    value.request(); value.response();
    if (afterReply) await turn();
    else value.data('1', Buffer.from('{'));
    value.data('1', Buffer.from('abc'), { data: undefined });
    await rejectedStream(value, 'MissingChunkError');
  }
});

test('the command prefix cannot omit bytes already reported before streaming started', async () => {
  let resolveStream;
  const value = owned({ send: () => new Promise(resolve => { resolveStream = resolve; }) });
  value.request(); value.response(); value.data('1', Buffer.alloc(10), { data: undefined }); value.finished();
  resolveStream({ bufferedData: Buffer.from('{}').toString('base64') });
  await rejectedStream(value, 'MissingChunkError');
});

test('conflicting terminal events cannot rewrite canceled to finished or finished to canceled', async () => {
  for (const first of ['failed', 'finished']) {
    const value = owned();
    value.request(); value.response(); value[first](); value[first === 'failed' ? 'finished' : 'failed']();
    await rejectedStream(value, 'TerminalIdentityError', 'loading-terminal');
    assert.equal(value.claims.length, 0);
  }
});

test('stream bounds can only tighten known fixed positive integer defaults', () => {
  for (const limits of [{ maxRequests: 129 }, { maxBodyBytes: 262145 }, { maxDataEvents: 0 },
    { bodyTimeoutMs: 1.5 }, { extra: 1 }]) assert.throws(() => owned({ limits }), /only tighten/);
});

test('an exactly bounded large valid body is decoded without relaxing the allocation cap', async () => {
  const candidate = { ...body(), ignored: '' };
  const size = 262144;
  candidate.ignored = 'x'.repeat(size - Buffer.byteLength(JSON.stringify(candidate)));
  const bytes = Buffer.from(JSON.stringify(candidate));
  assert.equal(bytes.length, size);
  const value = owned({ send: async () => ({ bufferedData: bytes.toString('base64') }) });
  value.request(); value.response(); value.finished('1', size);
  await value.observer.close();
  assert.equal(value.facts.passed, true);
  assert.equal(value.facts.observations[0].stream.decoded_bytes, size);
  assert.equal(value.facts.observations[0].stream.raw_buffers_cleared, true);
  noPrivateOutput(value.facts);
});

test('raw buffers are released before either a claims or safe error callback is invoked', async () => {
  for (const valid of [false, true]) {
    const session = new EventEmitter(), facts = {};
    session.send = async () => ({ bufferedData: Buffer.from(valid ? JSON.stringify(body()) : privateToken).toString('base64') });
    let callbacks = 0;
    const callback = () => {
      callbacks += 1;
      assert.equal(facts.observations[0].stream.raw_buffers_cleared, true);
    };
    const observer = createPermitResponseObserver({ session, origin, disconnectedEvent: disconnected,
      facts, onClaims: callback, onError: callback });
    session.emit('Network.requestWillBeSent', { requestId: '1', request: { method: 'POST', url: permitUrl } });
    session.emit('Network.responseReceived', { requestId: '1', response: { status: 200, url: permitUrl } });
    session.emit('Network.loadingFinished', { requestId: '1', encodedDataLength: 1024 });
    if (valid) await observer.close();
    else await assert.rejects(observer.close(), /observation failed/);
    assert.equal(callbacks, 1);
    noPrivateOutput(facts);
  }
});

function steadyPage({ send, detach } = {}) {
  const session = new EventEmitter(), calls = [], facts = {}, claims = [], errors = [];
  session.send = async (method, params) => {
    calls.push({ method, params });
    return send ? send(method, params, session) : {};
  };
  session.detach = async () => { calls.push({ method: 'detach' }); if (detach) await detach(); };
  const page = { url: () => 'about:blank', createCDPSession: async () => session };
  const prepare = () => preparePermitResponseObservation({ page, origin, facts,
    disconnectedEvent: disconnected, onClaims: (operation, value) => claims.push({ operation, value }),
    onError: error => errors.push(error) });
  return { session, calls, facts, claims, errors, page, prepare };
}

function steadyRequest(session, terminal = 'finished') {
  session.emit('Network.requestWillBeSent', { requestId: '17.9', request: { url: permitUrl, method: 'POST' } });
  session.emit('Network.responseReceived', { requestId: '17.9', response: { url: permitUrl, status: 200 } });
  if (terminal === 'finished') session.emit('Network.loadingFinished', { requestId: '17.9', encodedDataLength: 1024 });
  if (terminal === 'canceled') session.emit('Network.loadingFailed', { requestId: '17.9', errorText: 'net::ERR_ABORTED', canceled: true });
}

test('steady Chromium registers its observer before bounded Network.enable and never changes network conditions', async () => {
  const value = steadyPage({ send: async (method, params, session) => {
    if (method === 'Network.enable') {
      assert.deepEqual(params, { maxTotalBufferSize: 8 * 1024 * 1024, maxResourceBufferSize: 256 * 1024,
        maxPostDataSize: 0, enableDurableMessages: true });
      assert.equal(session.listenerCount('Network.requestWillBeSent'), 1);
      steadyRequest(session, 'canceled');
    } else if (method === 'Network.streamResourceContent') {
      assert.deepEqual(params, { requestId: '17.9' });
      return { bufferedData: Buffer.from(JSON.stringify(body())).toString('base64') };
    } else if (method !== 'Network.disable') throw new Error('Unexpected command, including late default body reads');
    return {};
  } });
  const owner = await value.prepare();
  await owner.close();
  assert.equal(value.facts.passed, true);
  assert.equal(value.facts.session_owner.passed, true);
  assert.equal(value.facts.session_owner.prepared_before_navigation, true);
  assert.equal(value.facts.canceled_loads, 1);
  assert.equal(value.facts.normal_loads, 0);
  assert.equal(value.facts.network_all_completed_normally, false);
  assert.equal(value.claims.length, 1);
  assert.deepEqual(value.calls.map(call => call.method), ['Network.enable', 'Network.streamResourceContent', 'Network.disable', 'detach']);
  assert.equal(value.session.eventNames().length, 0);
  noPrivateOutput(value.facts);
});

test('steady completed-response fallback reads the exact request in the same session without manufacturing a terminal', async () => {
  const value = steadyPage({ send: async (method, params) => {
    if (method === 'Network.streamResourceContent') throw new Error('stream-unavailable');
    if (method === 'Network.getResponseBody') {
      assert.deepEqual(params, { requestId: '17.9' });
      return { body: JSON.stringify(body()), base64Encoded: false };
    }
    return {};
  } });
  const owner = await value.prepare();
  steadyRequest(value.session);
  await owner.close();
  assert.equal(value.facts.session_owner.passed, true);
  assert.equal(value.facts.normal_loads, 1);
  assert.equal(value.facts.failed_loads, 0);
  assert.equal(value.facts.observations[0].stream.fallback_used, true);
  assert.equal(value.facts.observations[0].stream.raw_buffers_cleared, true);
  noPrivateOutput(value.facts);
});

test('steady shutdown drains pending same-session streams before disable and is idempotent', async () => {
  let resolveStream;
  const value = steadyPage({ send: (method) => method === 'Network.streamResourceContent'
    ? new Promise(resolve => { resolveStream = resolve; }) : Promise.resolve({}) });
  const owner = await value.prepare();
  steadyRequest(value.session);
  const close = owner.close();
  assert.equal(owner.close(), close);
  assert.equal(value.calls.some(call => call.method === 'Network.disable'), false);
  resolveStream({ bufferedData: Buffer.from(JSON.stringify(body())).toString('base64') });
  await close;
  assert.equal(value.facts.session_owner.passed, true);
  assert.equal(value.facts.pending, 0);
  assert.deepEqual(value.calls.slice(-2).map(call => call.method), ['Network.disable', 'detach']);
});

test('steady setup and drain failures still release the owned session without retaining private exceptions', async () => {
  const setup = steadyPage({ send: async method => { if (method === 'Network.enable') throw new Error(privateToken); return {}; } });
  await assert.rejects(setup.prepare(), /Could not prepare owned/);
  assert.deepEqual(setup.calls.map(call => call.method), ['Network.enable', 'Network.disable', 'detach']);
  assert.equal(setup.facts.session_owner.closed, true);
  assert.equal(setup.facts.session_owner.passed, false);
  assert.equal(setup.session.eventNames().length, 0);
  noPrivateOutput(setup.facts);
  const drain = steadyPage({ send: async method => {
    if (method === 'Network.streamResourceContent' || method === 'Network.disable') throw new Error(privateToken);
    return {};
  } });
  const owner = await drain.prepare();
  steadyRequest(drain.session, 'canceled');
  await assert.rejects(owner.close(), /cleanup failed/);
  assert.equal(drain.facts.passed, false);
  assert.equal(drain.facts.session_owner.passed, false);
  assert.equal(drain.facts.session_owner.session_detached, true);
  assert.equal(drain.session.eventNames().length, 0);
  assert.deepEqual(drain.facts.session_owner.cleanup_errors, ['response-observer', 'network-disable']);
  noPrivateOutput(drain.facts);
});

test('steady observation rejects previously navigated or unowned pages before creating a session', async () => {
  const value = steadyPage();
  value.page.url = () => origin;
  await assert.rejects(value.prepare(), /fresh owned HTTPS loopback page/);
  assert.equal(value.calls.length, 0);
  for (const other of ['http://127.0.0.1:43817', 'https://example.com:43817', origin + '/path']) {
    await assert.rejects(preparePermitResponseObservation({ page: { ...value.page, url: () => 'about:blank' },
      origin: other, facts: {} }), /fresh owned HTTPS loopback page/);
  }
  assert.equal(value.calls.length, 0);
});
