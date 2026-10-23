// Observe only permit/renew responses owned by the already-enabled page CDP
// session. No token/body is retained in facts, diagnostics or callback output.
const { performance } = require('node:perf_hooks');
const { TextDecoder } = require('node:util');

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const route = /^\/api\/v3\/remote\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/(permit|renew)$/;
const defaults = Object.freeze({ maxPending: 32, maxRequests: 128, maxDataEvents: 1024, maxBodyBytes: 262144,
  requestTimeoutMs: 15000, bodyTimeoutMs: 3000, drainTimeoutMs: 5000 });
const resourceTypes = new Set(['Document', 'Stylesheet', 'Image', 'Media', 'Font', 'Script', 'TextTrack',
  'XHR', 'Fetch', 'Prefetch', 'EventSource', 'WebSocket', 'Manifest', 'SignedExchange', 'Ping', 'CSPViolationReport',
  'Preflight', 'FedCM', 'Other']);
const blockedReasons = new Set(['other', 'csp', 'mixed-content', 'origin', 'inspector', 'integrity', 'subresource-filter',
  'content-type', 'coep-frame-resource-needs-coep-header', 'coop-sandboxed-iframe-cannot-navigate-to-coop-page',
  'corp-not-same-origin', 'corp-not-same-origin-after-defaulted-to-same-origin-by-coep',
  'corp-not-same-origin-after-defaulted-to-same-origin-by-dip', 'corp-not-same-origin-after-defaulted-to-same-origin-by-coep-and-dip',
  'corp-not-same-site', 'sri-message-signature-mismatch']);
const responseProtocols = new Set(['http/0.9', 'http/1.0', 'http/1.1', 'h2', 'h3', 'quic']);
const corsErrors = new Set(['DisallowedByMode', 'InvalidResponse', 'WildcardOriginNotAllowed', 'MissingAllowOriginHeader',
  'MultipleAllowOriginValues', 'InvalidAllowOriginValue', 'AllowOriginMismatch', 'InvalidAllowCredentials', 'CorsDisabledScheme',
  'PreflightInvalidStatus', 'PreflightDisallowedRedirect', 'PreflightWildcardOriginNotAllowed',
  'PreflightMissingAllowOriginHeader', 'PreflightMultipleAllowOriginValues', 'PreflightInvalidAllowOriginValue',
  'PreflightAllowOriginMismatch', 'PreflightInvalidAllowCredentials', 'PreflightMissingAllowExternal',
  'PreflightInvalidAllowExternal', 'PreflightMissingAllowPrivateNetwork', 'PreflightInvalidAllowPrivateNetwork',
  'InvalidAllowMethodsPreflightResponse', 'InvalidAllowHeadersPreflightResponse', 'MethodDisallowedByPreflightResponse',
  'HeaderDisallowedByPreflightResponse', 'RedirectContainsCredentials', 'InsecurePrivateNetwork', 'InvalidPrivateNetworkAccess',
  'UnexpectedPrivateNetworkAccess', 'NoCorsRedirectModeNotFollow', 'PreflightMissingPrivateNetworkAccessId',
  'PreflightMissingPrivateNetworkAccessName', 'PrivateNetworkAccessPermissionUnavailable',
  'PrivateNetworkAccessPermissionDenied', 'LocalNetworkAccessPermissionDenied']);
const safeField = (value, accepts) => ({ value: accepts(value) ? value : null,
  redacted: value !== undefined && value !== null && !accepts(value) });
const numeric = value => Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
const boolean = value => typeof value === 'boolean';
// CDP identifiers are public correlation metadata. Never retain an arbitrary
// string supplied in place of an identifier, protocol enum or network error.
const requestIdentifier = value => typeof value === 'string' &&
  /^(?:[0-9]{1,20}(?:\.[0-9]{1,20})?|[0-9a-fA-F]{32})$/.test(value);
const targetIdentifier = value => typeof value === 'string' && /^[0-9a-fA-F]{32}$/.test(value);
const networkError = value => typeof value === 'string' && /^net::ERR_[A-Z0-9_]{1,80}$/.test(value);

function eventMetadata(event) {
  const loader = safeField(event.loaderId, targetIdentifier);
  const frame = safeField(event.frameId, targetIdentifier);
  const type = safeField(event.type, value => resourceTypes.has(value));
  return { timestamp: numeric(event.timestamp) ? event.timestamp : null,
    loader_id: loader.value, loader_id_redacted: loader.redacted,
    frame_id: frame.value, frame_id_redacted: frame.redacted,
    resource_type: type.value, resource_type_redacted: type.redacted };
}

function responseMetadata(event) {
  const response = event.response;
  const protocol = safeField(response.protocol, value => responseProtocols.has(value));
  return { ...eventMetadata(event), protocol: protocol.value, protocol_redacted: protocol.redacted,
    connection_id: numeric(response.connectionId) ? response.connectionId : null,
    connection_reused: boolean(response.connectionReused) ? response.connectionReused : null,
    from_disk_cache: boolean(response.fromDiskCache) ? response.fromDiskCache : null,
    from_service_worker: boolean(response.fromServiceWorker) ? response.fromServiceWorker : null,
    from_prefetch_cache: boolean(response.fromPrefetchCache) ? response.fromPrefetchCache : null };
}

function failedMetadata(event) {
  const error = safeField(event.errorText, networkError);
  const blocked = safeField(event.blockedReason, value => blockedReasons.has(value));
  const cors = safeField(event.corsErrorStatus?.corsError, value => corsErrors.has(value));
  return { ...eventMetadata(event), error_text: error.value, error_text_redacted: error.redacted,
    canceled: boolean(event.canceled) ? event.canceled : null,
    blocked_reason: blocked.value, blocked_reason_redacted: blocked.redacted,
    cors_error: cors.value, cors_error_redacted: cors.redacted,
    cors_failed_parameter_present: typeof event.corsErrorStatus?.failedParameter === 'string' &&
      event.corsErrorStatus.failedParameter.length > 0,
    observed_monotonic_ms: performance.now(), observed_unix_ms: Date.now() };
}

function createPermitResponseObserver({ session, origin, disconnectedEvent, facts, onClaims, onError, limits = {} }) {
  const destination = new URL(origin);
  if (destination.origin !== origin || destination.protocol !== 'https:' || destination.hostname !== '127.0.0.1' ||
      !destination.port || !session?.on || !session?.off || !session?.send ||
      typeof disconnectedEvent !== 'symbol' || !facts || typeof onClaims !== 'function' || typeof onError !== 'function') {
    throw new Error('Response observation requires the owned page session and its public disconnected-event symbol');
  }
  const bounds = { ...defaults, ...limits };
  for (const key of Object.keys(bounds)) {
    if (!Object.hasOwn(defaults, key) || !Number.isSafeInteger(bounds[key]) || bounds[key] <= 0 || bounds[key] > defaults[key]) {
      throw new Error('Response observation bounds may only tighten the fixed defaults');
    }
  }
  Object.assign(facts, { schema_version: 3, source: 'Bounded Network.streamResourceContent with same-session completed-response fallback on exact owned-origin POST permit/renew requestId',
    requests_tracked: 0, successful_responses: 0, claims_observed: 0, peak_pending: 0,
    pending: 0, observations: [], normal_loads: 0, canceled_loads: 0, failed_loads: 0,
    network_all_completed_normally: false, errors: [], session_lost: false,
    closed: false, listeners_removed: false, passed: false });
  const pending = new Map();
  let accepting = true, closed = false, closePromise, drained;

  const match = value => {
    try {
      const url = new URL(value);
      const found = route.exec(url.pathname);
      if (url.origin === origin && !url.search && !url.hash && !url.username && !url.password && found) {
        return { path: url.pathname, operation: found[2].toLowerCase(), sessionId: found[1].toLowerCase(), url: url.href };
      }
    } catch { /* Unrelated/malformed URLs never become an owned response. */ }
    return null;
  };
  const clearRaw = entry => {
    entry.prefix?.fill(0);
    for (const chunk of entry.chunks ?? []) chunk.fill(0);
    entry.prefix = null;
    entry.chunks = [];
    if (entry.observation) entry.observation.stream.raw_buffers_cleared = true;
  };
  const finish = entry => {
    if (entry.finished) return;
    entry.finished = true;
    clearTimeout(entry.deadline);
    if (entry.settleImmediate) clearImmediate(entry.settleImmediate);
    entry.cancel?.();
    clearRaw(entry);
    pending.delete(entry.requestId);
    facts.pending = pending.size;
    if (!pending.size) drained?.();
  };
  const networkFacts = entry => {
    const identifier = safeField(entry?.requestId, requestIdentifier);
    return { request_id: identifier.value, request_id_redacted: identifier.redacted,
      request_ordinal: entry?.ordinal ?? null, request: entry?.requestMetadata ?? null,
      response: entry?.responseMetadata ?? null, loading_finished: entry?.loadingFinished ?? null,
      loading_failed: entry?.loadingFailed ?? null };
  };
  const failure = (entry, stage, type, message) => {
    const diagnostic = { path: entry?.path ?? null, status: entry?.status ?? null, stage,
      error_type: type, message, network: networkFacts(entry) };
    // All messages are fixed literals. CDP/JSON exceptions can quote private
    // response bytes, so neither exception.message nor response bodies escape.
    facts.errors.push(diagnostic);
    facts.passed = false;
    if (entry?.observation) entry.observation.observation_error = true;
    if (entry) finish(entry);
    try { onError(diagnostic); } catch { /* Facts still retain the original safe failure. */ }
  };
  const observedClaims = (value, entry) => {
    const claims = value?.claims;
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        !claims || typeof claims !== 'object' || Array.isArray(claims) ||
        typeof value.permit !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value.permit) ||
        typeof claims.session_id !== 'string' || !uuid.test(claims.session_id) ||
        claims.session_id.toLowerCase() !== entry.sessionId ||
        typeof claims.controller_device_id !== 'string' || !uuid.test(claims.controller_device_id)) throw new Error('invalid-claims');
    for (const key of ['lease_sequence', 'connection_generation', 'issued_at_unix_ms', 'expires_at_unix_ms']) {
      if (!Number.isSafeInteger(claims[key]) || claims[key] <= 0) throw new Error('invalid-claims');
    }
    if (claims.expires_at_unix_ms <= claims.issued_at_unix_ms) throw new Error('invalid-claims');
    return { lease_sequence: claims.lease_sequence, connection_generation: claims.connection_generation,
      session_id: claims.session_id, controller_device_id: claims.controller_device_id,
      issued_at_unix_ms: claims.issued_at_unix_ms, expires_at_unix_ms: claims.expires_at_unix_ms,
      observed_monotonic_ms: entry.observedMonotonic, observed_unix_ms: entry.observedUnix };
  };
  const decodeChunk = (encoded, remaining) => {
    if (typeof encoded !== 'string' || encoded.length > Math.ceil(remaining / 3) * 4) {
      throw new Error('body-limit');
    }
    // Buffer.from(base64) silently ignores malformed input. Require canonical
    // CDP binary data, including padding and pad bits, before trusting bytes.
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
      throw new Error('invalid-base64');
    }
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.length > remaining || bytes.toString('base64') !== encoded) {
      bytes.fill(0);
      throw new Error(bytes.length > remaining ? 'body-limit' : 'invalid-base64');
    }
    return bytes;
  };
  const chunkFailure = (entry, error) => failure(entry, 'response-stream',
    error?.message === 'body-limit' ? 'BodyLimitError' : 'Base64Error',
    error?.message === 'body-limit' ? 'Owned response stream exceeded the fixed decoded byte bound' :
      'Owned response stream did not contain canonical bounded base64 data');
  const fallbackFailure = (entry, stage, type, message) => failure(entry, stage, type, message);
  const startFallback = entry => {
    if (entry.finished || closed || entry.fallbackStarted || entry.status !== 200 || entry.terminal !== 'finished' ||
        !entry.loadingFinished || entry.loadingFailed) return;
    entry.fallbackStarted = true;
    entry.observation.stream.fallback_used = true;
    entry.observation.stream.retrieval_method = 'Network.getResponseBody';
    // The complete finished response supersedes any partial stream bookkeeping.
    entry.prefix?.fill(0);
    entry.prefix = null;
    for (const chunk of entry.chunks) chunk.fill(0);
    entry.chunks = [];
    entry.byteCount = 0;
    entry.encodedBytes = 0;
    entry.decodedEventBytes = 0;
    entry.preStreamBytes = 0;
    let timeout, reply = null;
    const canceled = new Promise(resolve => { entry.cancel = () => resolve(null); });
    const command = Promise.resolve().then(() => session.send('Network.getResponseBody', { requestId: entry.requestId }))
      .then(result => {
        if (entry.finished || closed) {
          if (result && typeof result === 'object') result.body = null;
          return null;
        }
        return result;
      });
    void Promise.race([command, canceled,
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('body-timeout')), bounds.bodyTimeoutMs); })])
      .then(result => {
        if (entry.finished || closed || result === null) return;
        let bytes = null;
        try {
          if (typeof result?.body !== 'string' || typeof result.base64Encoded !== 'boolean') {
            throw new Error('body-limit');
          }
          if (result.base64Encoded) {
            bytes = decodeChunk(result.body, bounds.maxBodyBytes);
          } else {
            const length = Buffer.byteLength(result.body, 'utf8');
            if (length > bounds.maxBodyBytes) throw new Error('body-limit');
            bytes = Buffer.from(result.body, 'utf8');
            if (bytes.toString('utf8') !== result.body) throw new Error('invalid-utf8');
          }
          if (entry.finished || closed) return;
          entry.prefix = bytes;
          bytes = null;
          entry.byteCount = entry.prefix.length;
          entry.observation.stream.buffered_bytes = entry.prefix.length;
          entry.observation.stream.decoded_bytes = entry.byteCount;
          entry.streamReady = true;
          settle(entry);
        } catch (error) {
          if (entry.finished || closed) return;
          const type = error?.message === 'body-limit' ? 'BodyLimitError' :
            error?.message === 'invalid-base64' ? 'Base64Error' : 'EncodingError';
          const message = type === 'BodyLimitError' ? 'Owned completed response body exceeded the fixed byte bound' :
            type === 'Base64Error' ? 'Owned completed response body did not contain canonical bounded base64 data' :
              'Owned completed response body was not valid UTF-8';
          fallbackFailure(entry, 'response-body', type, message);
        } finally {
          bytes?.fill(0);
          if (result && typeof result === 'object') result.body = null;
          result = null;
        }
      }, error => {
        if (entry.finished || closed) return;
        const timedOut = error?.message === 'body-timeout';
        fallbackFailure(entry, 'response-body', timedOut ? 'TimeoutError' : 'ProtocolError',
          timedOut ? 'Owned CDP completed response body exceeded the fixed retrieval deadline' :
            'Owned CDP completed response body was unavailable');
      })
      .finally(() => clearTimeout(timeout));
  };
  const inspectBody = entry => {
    if (entry.finished || closed || !entry.streamReady || !entry.terminal) return;
    let stage = 'response-utf8', bytes = null, text = null, value = null, claims;
    try {
      bytes = Buffer.concat([entry.prefix, ...entry.chunks], entry.byteCount);
      // Preserve a possible BOM so JSON.parse rejects it. Invalid or truncated
      // UTF-8 is rejected instead of silently substituting replacement bytes.
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      stage = 'response-json';
      value = JSON.parse(text); // Exactly one complete document; no trailing data.
      entry.observation.stream.complete_json = true;
      stage = 'permit-claims';
      claims = observedClaims(value, entry);
      // Release raw data before any callback or persisted diagnostic. JS strings
      // cannot be overwritten; their references are dropped, never retained.
      bytes.fill(0); bytes = null; text = null; value = null;
      clearRaw(entry);
      stage = 'claims-callback';
      onClaims(entry.operation, claims);
      facts.claims_observed += 1;
      entry.observation.claims_observed = true;
      finish(entry);
    } catch {
      if (entry.finished || closed) return;
      const type = stage === 'response-utf8' ? 'EncodingError' : stage === 'response-json' ? 'SyntaxError' :
        stage === 'permit-claims' ? 'ClaimsError' : 'CallbackError';
      const message = stage === 'response-utf8' ? 'Owned response stream was not complete valid UTF-8' :
        stage === 'response-json' ? 'Owned response stream was not exactly one complete JSON document' :
        stage === 'permit-claims' ? 'Owned response did not contain the required bounded permit claims' :
        'Owned permit claims callback failed';
      bytes?.fill(0); bytes = null; text = null; value = null;
      clearRaw(entry);
      failure(entry, stage, type, message);
    } finally { bytes?.fill(0); bytes = null; text = null; value = null; clearRaw(entry); }
  };
  const settle = entry => {
    if (entry.finished || closed || !entry.streamReady || !entry.terminal || entry.settleImmediate) return;
    // A terminal can precede the command reply. The prefix always comes first,
    // followed by data-bearing events in arrival order, even when those events
    // arrived before the reply. Drain already queued callbacks before parsing.
    entry.settleImmediate = setImmediate(() => {
      entry.settleImmediate = null;
      inspectBody(entry);
    });
  };
  const enableStream = async entry => {
    let timeout, reply = null;
    try {
      const canceled = new Promise(resolve => { entry.cancel = () => resolve(null); });
      const command = Promise.resolve(session.send('Network.streamResourceContent', { requestId: entry.requestId }))
        .then(result => {
          if (entry.finished || closed) {
            if (result && typeof result === 'object') result.bufferedData = null;
            return null;
          }
          return result;
        });
      reply = await Promise.race([command, canceled,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('stream-timeout')), bounds.bodyTimeoutMs); })]);
      if (entry.finished || closed) return;
      entry.prefix = decodeChunk(reply?.bufferedData, bounds.maxBodyBytes - entry.byteCount);
      if (entry.prefix.length < entry.preStreamBytes) {
        failure(entry, 'response-stream', 'MissingChunkError', 'Owned response stream prefix omitted previously reported decoded bytes');
        return;
      }
      entry.byteCount += entry.prefix.length;
      entry.observation.stream.buffered_bytes = entry.prefix.length;
      entry.observation.stream.decoded_bytes = entry.byteCount;
      entry.observation.stream.retrieval_method = 'Network.streamResourceContent';
      entry.streamReady = entry.observation.stream.enabled = true;
      settle(entry);
    } catch (error) {
      if (entry.finished || closed) return;
      if (error?.message === 'body-limit' || error?.message === 'invalid-base64') chunkFailure(entry, error);
      else if (error?.message === 'stream-timeout') {
        failure(entry, 'response-stream', 'TimeoutError', 'Owned CDP stream enable exceeded the fixed retrieval deadline');
      } else {
        entry.streamUnavailable = true;
        if (entry.terminal === 'finished') startFallback(entry);
        else if (entry.terminal === 'failed') failure(entry, 'response-stream', 'ProtocolError',
          'Owned CDP response content stream was unavailable after a failed network load');
      }
    } finally {
      clearTimeout(timeout);
      if (reply && typeof reply === 'object') reply.bufferedData = null;
      reply = null;
    }
  };
  const onRequest = event => {
    if (!accepting || closed) return;
    const existing = pending.get(event.requestId);
    if (existing) {
      failure(existing, 'request', 'RedirectError', 'Owned permit request identifier was redirected or reused before completion');
      return;
    }
    const owned = event.request?.method === 'POST' ? match(event.request.url) : null;
    if (!owned || typeof event.requestId !== 'string' || !event.requestId || event.requestId.length > 256) return;
    if (facts.requests_tracked >= bounds.maxRequests) {
      accepting = false;
      failure(owned, 'request', 'RequestLimitError', 'Owned response observation exceeded the fixed total-request bound');
      return;
    }
    if (pending.size >= bounds.maxPending) {
      accepting = false;
      failure(owned, 'request', 'PendingLimitError', 'Owned response observation exceeded the fixed pending-request bound');
      return;
    }
    const entry = { ...owned, requestId: event.requestId, status: null, finished: false,
      prefix: null, chunks: [], byteCount: 0, encodedBytes: 0, decodedEventBytes: 0, preStreamBytes: 0, dataEvents: 0,
      streamReady: false, streamUnavailable: false, fallbackStarted: false, terminal: null,
      ordinal: facts.requests_tracked + 1, requestMetadata: { ...eventMetadata(event),
        wall_time: numeric(event.wallTime) ? event.wallTime : null } };
    entry.observation = { path: entry.path, operation: entry.operation, status: null,
      network: networkFacts(entry), network_completion: 'pending', claims_observed: false, observation_error: false,
      stream: { requested: false, enabled: false, fallback_used: false, retrieval_method: null, buffered_bytes: 0, decoded_bytes: 0,
        data_events: 0, data_chunks: 0, pre_stream_data_events: 0, complete_json: false, raw_buffers_cleared: false } };
    facts.observations.push(entry.observation);
    pending.set(entry.requestId, entry);
    facts.requests_tracked += 1;
    facts.pending = pending.size;
    facts.peak_pending = Math.max(facts.peak_pending, pending.size);
    entry.deadline = setTimeout(() => failure(entry, entry.status === 200 ? 'loading-terminal' : 'response-received',
      'TimeoutError', 'Owned permit response did not complete before the fixed request deadline'), bounds.requestTimeoutMs);
  };
  const onResponse = event => {
    const entry = pending.get(event.requestId);
    if (!entry || closed) return;
    if (event.response?.status !== 200) {
      entry.observation.status = numeric(event.response?.status) ? event.response.status : null;
      entry.observation.network_completion = 'http-failure';
      finish(entry);
      return;
    }
    if (event.response.url !== entry.url || entry.status !== null) {
      failure(entry, 'response-received', 'ResponseIdentityError', 'Owned permit response did not match its exact original request');
      return;
    }
    entry.status = 200;
    entry.responseMetadata = responseMetadata(event);
    entry.observedMonotonic = performance.now();
    entry.observedUnix = Date.now();
    entry.observation.status = 200;
    entry.observation.network.response = entry.responseMetadata;
    entry.observation.stream.requested = true;
    facts.successful_responses += 1;
    void enableStream(entry);
  };
  const onData = event => {
    const entry = pending.get(event.requestId);
    if (!entry || closed) return;
    if (entry.status !== 200) {
      failure(entry, 'response-stream', 'ResponseIdentityError', 'Owned response data arrived without matching successful response headers');
      return;
    }
    entry.dataEvents += 1;
    entry.observation.stream.data_events = entry.dataEvents;
    if (entry.dataEvents > bounds.maxDataEvents) {
      failure(entry, 'response-stream', 'EventLimitError', 'Owned response stream exceeded the fixed data-event bound');
      return;
    }
    if (!Number.isSafeInteger(event.dataLength) || event.dataLength < 0 || event.dataLength > bounds.maxBodyBytes - entry.decodedEventBytes ||
        !Number.isSafeInteger(event.encodedDataLength) || event.encodedDataLength < 0 ||
        event.encodedDataLength > bounds.maxBodyBytes - entry.encodedBytes) {
      failure(entry, 'response-stream', 'BodyLimitError', 'Owned response data lengths were unavailable or exceeded the fixed byte bound');
      return;
    }
    entry.encodedBytes += event.encodedDataLength;
    entry.decodedEventBytes += event.dataLength;
    if (event.data === undefined) {
      // Before the method's reply, old events lack data and the command's
      // bufferedData owns their prefix. After streaming starts, a missing
      // payload or a hole between data-bearing events cannot be reconstructed.
      if (entry.streamReady || entry.chunks.length) {
        failure(entry, 'response-stream', 'MissingChunkError', 'Owned response stream omitted a data chunk after streaming began');
      } else {
        entry.preStreamBytes += event.dataLength;
        entry.observation.stream.pre_stream_data_events += 1;
      }
      return;
    }
    let chunk;
    try {
      chunk = decodeChunk(event.data, bounds.maxBodyBytes - entry.byteCount);
      if (chunk.length !== event.dataLength) {
        chunk.fill(0);
        failure(entry, 'response-stream', 'ChunkLengthError', 'Owned response stream chunk did not match its declared decoded byte length');
        return;
      }
      entry.chunks.push(chunk);
      entry.byteCount += chunk.length;
      entry.observation.stream.data_chunks += 1;
      entry.observation.stream.decoded_bytes = entry.byteCount;
    } catch (error) { chunk?.fill(0); chunkFailure(entry, error); }
  };
  const onFinished = event => {
    const entry = pending.get(event.requestId);
    if (!entry || closed) return;
    if (entry.terminal) {
      failure(entry, 'loading-terminal', 'TerminalIdentityError', 'Owned response reported more than one terminal network event');
      return;
    }
    if (entry.status !== 200) {
      failure(entry, 'loading-finished', 'ResponseIdentityError', 'Owned request finished without an observed matching successful response');
      return;
    }
    if (!Number.isSafeInteger(event.encodedDataLength) || event.encodedDataLength < 0 || event.encodedDataLength > bounds.maxBodyBytes) {
      failure(entry, 'loading-finished', 'BodyLimitError', 'Owned response transfer length was unavailable or exceeded the fixed byte bound');
      return;
    }
    entry.terminal = 'finished';
    entry.loadingFinished = { timestamp: numeric(event.timestamp) ? event.timestamp : null,
      encoded_data_length: event.encodedDataLength };
    entry.observation.network.loading_finished = entry.loadingFinished;
    entry.observation.network_completion = 'finished';
    facts.normal_loads += 1;
    if (entry.streamUnavailable) startFallback(entry);
    else settle(entry);
  };
  const onFailed = event => {
    const entry = pending.get(event.requestId);
    if (!entry || closed) return;
    if (entry.terminal) {
      failure(entry, 'loading-terminal', 'TerminalIdentityError', 'Owned response reported more than one terminal network event');
      return;
    }
    entry.terminal = 'failed';
    entry.loadingFailed = failedMetadata(event);
    entry.observation.network.loading_failed = entry.loadingFailed;
    entry.observation.network_completion = entry.loadingFailed.canceled === true ? 'canceled' : 'failed';
    facts.failed_loads += 1;
    if (entry.loadingFailed.canceled === true) facts.canceled_loads += 1;
    // A complete streamed body can be observed despite Chromium cancellation.
    // This exception is deliberately narrow and never creates loadingFinished.
    // Other failures, blocked requests or CORS errors still fail closed.
    if (entry.status !== 200 || entry.loadingFailed.error_text !== 'net::ERR_ABORTED' ||
        entry.loadingFailed.canceled !== true || entry.loadingFailed.blocked_reason !== null ||
        entry.loadingFailed.blocked_reason_redacted || entry.loadingFailed.cors_error !== null ||
        entry.loadingFailed.cors_error_redacted) {
      failure(entry, 'loading-failed', 'NetworkError', 'Owned permit request reported a CDP loading failure');
      return;
    }
    if (entry.streamUnavailable) {
      failure(entry, 'response-stream', 'ProtocolError', 'Owned CDP response content stream was unavailable after a canceled network load');
      return;
    }
    settle(entry);
  };
  const onDisconnected = () => {
    if (closed || facts.session_lost) return;
    accepting = false;
    facts.session_lost = true;
    if (!pending.size) failure(null, 'session', 'TargetCloseError', 'Owned page CDP session disconnected before observer shutdown');
    for (const entry of [...pending.values()]) {
      failure(entry, 'session', 'TargetCloseError', 'Owned page CDP session disconnected before response observation completed');
    }
  };
  const listeners = [['Network.requestWillBeSent', onRequest], ['Network.responseReceived', onResponse], ['Network.dataReceived', onData],
    ['Network.loadingFinished', onFinished], ['Network.loadingFailed', onFailed], [disconnectedEvent, onDisconnected]];
  for (const [name, listener] of listeners) session.on(name, listener);

  return Object.freeze({ close() {
    if (closePromise) return closePromise;
    accepting = false;
    session.off('Network.requestWillBeSent', onRequest);
    closePromise = (async () => {
      let timeout;
      try {
        if (pending.size) await Promise.race([
          new Promise(resolve => { drained = resolve; }),
          new Promise(resolve => { timeout = setTimeout(() => {
            for (const entry of [...pending.values()]) failure(entry, 'drain', 'TimeoutError',
              'Owned response did not finish before the fixed observer shutdown deadline');
            resolve();
          }, bounds.drainTimeoutMs); }),
        ]);
      } finally {
        clearTimeout(timeout);
        drained = undefined;
        closed = true;
        for (const [name, listener] of listeners) session.off(name, listener);
        facts.closed = facts.listeners_removed = true;
        facts.pending = pending.size;
        facts.network_all_completed_normally = facts.successful_responses > 0 &&
          facts.normal_loads === facts.successful_responses && facts.failed_loads === 0;
        facts.passed = facts.errors.length === 0 && facts.claims_observed > 0 && pending.size === 0;
      }
      if (facts.errors.length) throw new Error('Owned permit/renewal response observation failed');
    })();
    return closePromise;
  } });
}

// Steady Chromium runs need the same early, owned CDP observation as impairment
// runs. Puppeteer's default-session response.json() can lose a Fetch body after
// the application consumes/drops it; a later getResponseBody is not evidence.
// This owner observes header-time streams and completed-response fallback on one
// session, with bounded durable buffers, without changing network conditions.
async function preparePermitResponseObservation({ page, origin, facts, ...options }) {
  const destination = new URL(origin);
  if (destination.origin !== origin || destination.protocol !== 'https:' || destination.hostname !== '127.0.0.1' ||
      !destination.port || !page?.createCDPSession || page.url() !== 'about:blank' || !facts || typeof facts !== 'object') {
    throw new Error('Permit response observation requires a fresh owned HTTPS loopback page');
  }
  const parameters = Object.freeze({ maxTotalBufferSize: defaults.maxBodyBytes * defaults.maxPending,
    maxResourceBufferSize: defaults.maxBodyBytes, maxPostDataSize: 0, enableDurableMessages: true });
  const lifecycle = facts.session_owner = {
    source: 'Dedicated steady-run CDP session; no network emulation or request interception',
    network_enable_parameters: parameters, session_created: false, prepared_before_navigation: false,
    network_disabled: false, session_detached: false, cleanup_errors: [], closed: false, passed: false,
  };
  let session = null, observer = null, closePromise;
  const owner = Object.freeze({ close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      const errors = [];
      const attempt = async (operation, task) => {
        try { await task(); }
        catch { errors.push(operation); lifecycle.cleanup_errors.push(operation); }
      };
      // A partial setup or failed drain must still disable and detach its exact
      // owned session. Never disable Puppeteer's own session or any other page.
      if (observer) await attempt('response-observer', () => observer.close());
      if (session) {
        await attempt('network-disable', async () => {
          await session.send('Network.disable');
          lifecycle.network_disabled = true;
        });
        await attempt('session-detach', async () => {
          await session.detach();
          lifecycle.session_detached = true;
        });
      }
      lifecycle.closed = true;
      lifecycle.passed = errors.length === 0 && facts.passed === true && lifecycle.prepared_before_navigation &&
        lifecycle.network_disabled && lifecycle.session_detached;
      if (errors.length) throw new Error('Owned permit response observation cleanup failed');
    })();
    return closePromise;
  } });
  try {
    session = await page.createCDPSession();
    lifecycle.session_created = true;
    observer = createPermitResponseObserver({ ...options, session, origin, facts });
    // The observer must own listeners before Network.enable/navigation can
    // deliver the first request. Body reads use only this same session.
    await session.send('Network.enable', parameters);
    lifecycle.prepared_before_navigation = true;
    return owner;
  } catch {
    try { await owner.close(); } catch { /* Fixed cleanup categories remain in facts. */ }
    throw new Error('Could not prepare owned permit response observation');
  }
}

module.exports = { createPermitResponseObserver, preparePermitResponseObservation };
