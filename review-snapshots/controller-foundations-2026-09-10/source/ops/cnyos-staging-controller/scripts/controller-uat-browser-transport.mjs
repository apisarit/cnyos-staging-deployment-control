// Dedicated CDP connection only: never share its target manager with Playwright
// or a user's browser. cdp.terminate() MUST kill only this exclusively-owned
// runtime and confirm exit before disconnecting its CDP transport. A socket
// close/dispose is NOT equivalent: Chromium can release intercepted requests.
// This component is not an OS-level egress sandbox, a UAT
// receipt, target authorization or an activation path for the protected CLI.
import { Buffer } from 'node:buffer';

const DEFAULTS = Object.freeze({ maxRequests: 512, maxTotalBytes: 32 * 1024 * 1024,
  maxResponseBytes: 4 * 1024 * 1024, maxRequestBytes: 16 * 1024,
  maxPendingRequests: 128, maxConcurrentStreams: 8, maxScreenshotBytes: 2 * 1024 * 1024,
  maxScreenshots: 8, operationTimeoutMs: 5000, totalTimeoutMs: 120000 });
const KINDS = new Set(['document', 'script', 'style', 'json', 'image', 'font', 'empty']);
const SAFE_HEADERS = new Set(['content-type', 'cache-control', 'etag', 'last-modified',
  'content-security-policy', 'content-security-policy-report-only', 'x-content-type-options',
  'x-frame-options', 'referrer-policy', 'permissions-policy', 'cross-origin-resource-policy',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'vary', 'content-range',
  'access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers',
  'access-control-allow-credentials', 'access-control-expose-headers', 'access-control-max-age']);
const safeErrors = new WeakSet();
const makeError = code => { const error = new Error(`CNYOS_UAT_BROWSER_${code}`); safeErrors.add(error); return error; };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const id = value => typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,160}$/.test(value);
const bytes = value => Buffer.byteLength(value, 'utf8');

function optionsOf(input = {}) {
  if (!record(input) || Object.keys(input).some(key => !(key in DEFAULTS))) throw makeError('LIMITS');
  const limits = { ...DEFAULTS, ...input };
  for (const key of Object.keys(DEFAULTS)) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 1 || limits[key] > DEFAULTS[key]) throw makeError('LIMITS');
  }
  return Object.freeze(limits);
}
function descriptorOf(event, maxRequestBytes) {
  if (!record(event.request) || typeof event.request.url !== 'string' || bytes(event.request.url) > 4096 ||
    typeof event.request.method !== 'string' || !/^[A-Z]{1,16}$/.test(event.request.method) ||
    typeof event.resourceType !== 'string' || event.resourceType.length > 32) throw makeError('REQUEST_SCHEMA');
  const url = new URL(event.request.url);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw makeError('REQUEST_URL');
  const postData = event.request.postData ?? '';
  if (typeof postData !== 'string' || bytes(postData) > maxRequestBytes ||
    (event.request.hasPostData === true && event.request.postData === undefined)) throw makeError('REQUEST_BODY');
  let accessControlRequestMethod = '', accessControlRequestHeaders = [];
  if (event.request.method === 'OPTIONS') {
    if (!record(event.request.headers)) throw makeError('REQUEST_HEADERS');
    const named = name => Object.entries(event.request.headers).filter(([key]) => key.toLowerCase() === name);
    const method = named('access-control-request-method'), headers = named('access-control-request-headers');
    if (method.length !== 1 || headers.length !== 1 || typeof method[0][1] !== 'string' ||
      !/^[A-Z]{1,16}$/.test(method[0][1]) || typeof headers[0][1] !== 'string' || bytes(headers[0][1]) > 1024) {
      throw makeError('PREFLIGHT_SCHEMA');
    }
    accessControlRequestMethod = method[0][1];
    accessControlRequestHeaders = headers[0][1].split(',').map(name => name.trim().toLowerCase()).sort();
    if (accessControlRequestHeaders.length > 20 || new Set(accessControlRequestHeaders).size !== accessControlRequestHeaders.length ||
      accessControlRequestHeaders.some(name => !/^[a-z][a-z0-9-]{0,99}$/.test(name))) throw makeError('PREFLIGHT_SCHEMA');
  }
  return Object.freeze({ url: event.request.url, method: event.request.method, resourceType: event.resourceType, postData,
    accessControlRequestMethod, accessControlRequestHeaders: Object.freeze(accessControlRequestHeaders) });
}
function decisionOf(classify, descriptor, limits) {
  const value = classify(descriptor);
  if (!record(value) || !Object.isFrozen(value)) throw makeError('POLICY_SCHEMA');
  if (Object.keys(value).sort().join(',') === 'allowed' && value.allowed === false) throw makeError('REQUEST_DENIED');
  if (Object.keys(value).sort().join(',') !== 'allowed,maxResponseBytes,responseKind' || value.allowed !== true ||
    !KINDS.has(value.responseKind) || !Number.isSafeInteger(value.maxResponseBytes) || value.maxResponseBytes < 1 ||
    value.maxResponseBytes > limits.maxResponseBytes) throw makeError('POLICY_SCHEMA');
  if (value.responseKind === 'empty' && (descriptor.method !== 'OPTIONS' ||
    !['Preflight', 'XHR', 'Fetch'].includes(descriptor.resourceType) ||
    !descriptor.accessControlRequestMethod || descriptor.accessControlRequestHeaders.length === 0)) {
    throw makeError('POLICY_SCHEMA');
  }
  return Object.freeze({ ...value });
}
function headersOf(value) {
  if (!Array.isArray(value) || value.length > 100) throw makeError('RESPONSE_HEADERS');
  let size = 0;
  const headers = value.map(item => {
    if (!record(item) || typeof item.name !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/.test(item.name) ||
      typeof item.value !== 'string' || /[\r\n\0]/.test(item.value)) throw makeError('RESPONSE_HEADERS');
    size += bytes(item.name) + bytes(item.value);
    if (size > 32768) throw makeError('RESPONSE_HEADERS');
    return { name: item.name.toLowerCase(), value: item.value };
  });
  for (const singleton of ['content-type', 'content-encoding', 'content-length', 'content-disposition']) {
    if (headers.filter(header => header.name === singleton).length > 1) throw makeError('RESPONSE_HEADERS');
  }
  return headers;
}
function mimeAllowed(kind, value) {
  const mime = value.split(';')[0].trim().toLowerCase();
  return kind === 'empty' ? value === '' : kind === 'document' ? mime === 'text/html' :
    kind === 'script' ? ['text/javascript', 'application/javascript', 'application/x-javascript'].includes(mime) :
    kind === 'style' ? mime === 'text/css' : kind === 'json' ? mime === 'application/json' :
    kind === 'image' ? ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/x-icon'].includes(mime) :
    ['font/woff', 'font/woff2', 'application/font-woff'].includes(mime);
}

function topFrame(value) {
  const tree = value.frameTree, frame = tree?.frame;
  if (!record(tree) || !record(frame) || !id(frame.id) || !id(frame.loaderId) ||
    frame.parentId !== undefined || typeof frame.url !== 'string' || bytes(frame.url) > 4096 ||
    (tree.childFrames !== undefined && (!Array.isArray(tree.childFrames) || tree.childFrames.length))) {
    throw makeError('NAVIGATION_FRAME');
  }
  return { frameId: frame.id, loaderId: frame.loaderId, url: frame.url };
}
function screenshotOf(value, limit) {
  if (typeof value.data !== 'string' || value.data.length > Math.ceil(limit / 3) * 4 ||
    value.data.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(value.data)) {
    throw makeError('SCREENSHOT_BASE64');
  }
  const png = Buffer.from(value.data, 'base64');
  if (png.length > limit || png.toString('base64') !== value.data || png.length < 57 ||
    !png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ||
    png.readUInt32BE(8) !== 13 || png.toString('ascii', 12, 16) !== 'IHDR' ||
    png.readUInt32BE(16) !== 390 || png.readUInt32BE(20) !== 844 ||
    png[24] !== 8 || ![2, 6].includes(png[25]) || png[26] !== 0 || png[27] !== 0 || png[28] !== 0) {
    throw makeError('SCREENSHOT_PNG');
  }
  // Bound and validate the PNG container, not a general-purpose image decoder.
  let offset = 8, chunks = 0, imageData = false, ended = false;
  while (offset < png.length) {
    if (++chunks > 4096 || offset + 12 > png.length) throw makeError('SCREENSHOT_PNG');
    const length = png.readUInt32BE(offset), type = png.toString('ascii', offset + 4, offset + 8);
    if (!/^[A-Za-z]{4}$/.test(type) || length > png.length - offset - 12 ||
      (offset !== 8 && type === 'IHDR')) throw makeError('SCREENSHOT_PNG');
    if (type === 'IDAT' && length > 0) imageData = true;
    offset += length + 12;
    if (type === 'IEND') {
      if (length !== 0 || offset !== png.length || !imageData) throw makeError('SCREENSHOT_PNG');
      ended = true;
    }
  }
  if (!ended) throw makeError('SCREENSHOT_PNG');
  return Object.freeze({ format: 'png', dataBase64: value.data, width: 390, height: 844, byteLength: png.length });
}

export async function createControllerUatBrowserTransport({ cdp, classifyRequest, limits: inputLimits } = {}) {
  if (!record(cdp) || typeof cdp.send !== 'function' || typeof cdp.onEvent !== 'function' ||
    typeof cdp.terminate !== 'function' || typeof classifyRequest !== 'function') throw makeError('OPTIONS');
  const limits = optionsOf(inputLimits);
  let contextId, targetId, sessionId, failure, closePromise, unsubscribe, totalTimer;
  let stopping = false, initialized = false, navigated = false, requestCount = 0, totalBytes = 0, aggregateBytes = 0, activeStreams = 0;
  const pending = new Map(), streams = new Map(), tasks = new Set(), heldAttachments = [], idleWaiters = new Set();
  const paused = new Map(), cancellations = new Set();
  let abortUncertain = false, shutdownPauses = 0, cleanupConfirmed = false;
  let navigation, navigating = false, screenshots = 0, screenshotBusy = false, exceptionCount = 0, consoleErrorCount = 0;
  const pulse = () => { for (const wake of idleWaiters) wake(); idleWaiters.clear(); };
  let resolveAttached;
  const attached = new Promise(resolve => { resolveAttached = resolve; });
  const healthy = () => { if (failure) throw failure; if (stopping) throw makeError('CLOSED'); };
  const deadline = async (promise, code) => {
    let timer;
    try {
      return await Promise.race([promise, new Promise((_, reject) => {
        timer = setTimeout(() => reject(makeError(code)), limits.operationTimeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  };
  const command = async (method, params = {}, sid, beforeDispatch) => {
    healthy();
    const value = await deadline(Promise.resolve().then(() => {
      healthy(); beforeDispatch?.(); return cdp.send(method, params, sid);
    }), 'OPERATION_TIMEOUT');
    healthy();
    if (!record(value)) throw makeError('PROTOCOL_SCHEMA');
    return value;
  };
  function latch(error) {
    if (!failure) failure = safeErrors.has(error) ? error : makeError('FAILED');
    if (!stopping) void cleanup().catch(() => {});
  }
  function forgetPause(entry) {
    if (paused.get(entry.key) === entry) paused.delete(entry.key);
  }
  function cancelPause(entry) {
    if (entry.canceling || ['stream-opening', 'streaming'].includes(entry.stage)) return;
    entry.canceling = true;
    const cancellation = deadline(Promise.resolve().then(() => cdp.send('Fetch.failRequest', {
      requestId: entry.requestId, errorReason: 'BlockedByClient'
    }, entry.sessionId)), 'CANCEL_TIMEOUT').then(value => {
      if (!record(value)) abortUncertain = true;
    }).catch(() => { abortUncertain = true; }).finally(() => {
      forgetPause(entry); cancellations.delete(cancellation);
    });
    cancellations.add(cancellation);
  }
  function registerPause(event) {
    if (!record(event.params) || !id(event.params.requestId) || !id(event.sessionId)) {
      abortUncertain = true; latch(makeError('REQUEST_SESSION')); return null;
    }
    const key = `${event.sessionId}:${event.params.requestId}`;
    const previous = paused.get(key);
    if (previous && ['stream-opening', 'streaming'].includes(previous.stage)) {
      latch(makeError('RESPONSE_BINDING')); return null;
    }
    if (stopping && ++shutdownPauses > limits.maxPendingRequests) { abortUncertain = true; return null; }
    const entry = { key, requestId: event.params.requestId, sessionId: event.sessionId,
      stage: event.params.responseStatusCode === undefined ? 'request' : 'response', canceling: false };
    paused.set(key, entry);
    // Bound a synchronous protocol burst before async handlers can run. Retain
    // the first overflow ID so cleanup can explicitly abort it as well.
    if (!stopping && paused.size > limits.maxPendingRequests) { latch(makeError('PENDING_LIMIT')); return null; }
    return entry;
  }
  async function cleanup() {
    if (closePromise) return closePromise;
    stopping = true;
    clearTimeout(totalTimer);
    pulse();
    closePromise = (async () => {
      let uncertain = false;
      // Fail known non-streaming pauses before shutdown; denied requests are
      // registered BEFORE policy evaluation. Never fail/continue active or
      // opening streams (the protocol defines conflicting operations as unsafe).
      for (const entry of paused.values()) cancelPause(entry);
      try { await deadline(Promise.allSettled([...cancellations]), 'CLEANUP_TIMEOUT'); } catch { uncertain = true; }
      // ALWAYS terminate, never dispose/detach: new pauses can arrive after the
      // snapshot and detachment itself can release an unapproved request.
      try { await deadline(cdp.terminate(), 'CLEANUP_TIMEOUT'); } catch { uncertain = true; }
      try { await deadline(Promise.allSettled([...cancellations]), 'CLEANUP_TIMEOUT'); } catch { uncertain = true; }
      try { await deadline(Promise.allSettled([...tasks]), 'CLEANUP_TIMEOUT'); } catch { uncertain = true; }
      try { unsubscribe?.(); } catch { uncertain = true; }
      pending.clear(); streams.clear(); paused.clear();
      // A confirmed shutdown can still rethrow an earlier policy/application
      // failure. Callers must use this status, not parse its error message, to
      // distinguish that outcome from unconfirmed owned-runtime teardown.
      cleanupConfirmed = !uncertain && !abortUncertain;
      if (uncertain || abortUncertain) failure = makeError('CLEANUP_UNCONFIRMED');
      if (failure) throw failure;
      return Object.freeze({ closed: true, requestCount, responseBytes: totalBytes,
        authorization: false, authenticatedUatComplete: false, osEgressIsolationVerified: false });
    })();
    return closePromise;
  }
  function startTask(action) {
    if (stopping) return;
    const task = Promise.resolve().then(action).catch(latch);
    tasks.add(task);
    void task.finally(() => { tasks.delete(task); pulse(); });
  }
  function navigationEvent(event) {
    if (!navigation?.armed || event.sessionId !== sessionId) return;
    let observation;
    if (event.method === 'Page.frameNavigated') {
      const frame = event.params.frame;
      if (!record(frame) || !id(frame.id) || !id(frame.loaderId) || typeof frame.url !== 'string' || bytes(frame.url) > 4096) {
        throw makeError('NAVIGATION_EVENT');
      }
      if (frame.id !== navigation.frameId || frame.parentId !== undefined) return;
      observation = { kind: 'frame', loaderId: frame.loaderId, url: frame.url };
    } else if (event.method === 'Page.lifecycleEvent' && event.params.name === 'load') {
      if (!id(event.params.frameId) || !id(event.params.loaderId) || !Number.isFinite(event.params.timestamp)) {
        throw makeError('NAVIGATION_EVENT');
      }
      if (event.params.frameId !== navigation.frameId) return;
      observation = { kind: 'load', loaderId: event.params.loaderId };
    } else return;
    if (observation.loaderId === navigation.previousLoaderId) return;
    if (navigation.events.length >= 32) throw makeError('NAVIGATION_EVENT_LIMIT');
    navigation.events.push(observation);
    navigation.wake?.();
  }
  async function initialize(event) {
    if (initialized || sessionId || event.params.targetInfo.type !== 'page' ||
      event.params.targetInfo.targetId !== targetId || event.params.targetInfo.browserContextId !== contextId ||
      event.params.waitingForDebugger !== true || !id(event.params.sessionId)) throw makeError('TARGET_DENIED');
    sessionId = event.params.sessionId;
    const autoAttach = { autoAttach: true, waitForDebuggerOnStart: true, flatten: true,
      filter: [{ type: 'browser', exclude: true }, { type: 'tab', exclude: true }, {}] };
    await command('Target.setAutoAttach', autoAttach, sessionId);
    await command('Network.enable', {}, sessionId);
    await command('Network.setBypassServiceWorker', { bypass: true }, sessionId);
    await command('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
    await command('Network.setBlockedURLs', { urls: ['ws://*', 'wss://*'] }, sessionId);
    await command('Fetch.enable', { handleAuthRequests: true, patterns: [
      { urlPattern: '*', requestStage: 'Request' }, { urlPattern: '*', requestStage: 'Response' }
    ] }, sessionId);
    await command('Page.enable', {}, sessionId);
    await command('Page.setLifecycleEventsEnabled', { enabled: true }, sessionId);
    await command('Runtime.enable', {}, sessionId);
    await command('Emulation.setTimezoneOverride', { timezoneId: 'Asia/Bangkok' }, sessionId);
    await command('Emulation.setLocaleOverride', { locale: 'th-TH' }, sessionId);
    await command('Emulation.setDeviceMetricsOverride', {
      width: 390, height: 844, deviceScaleFactor: 1, mobile: false
    }, sessionId);
    healthy();
    await command('Runtime.runIfWaitingForDebugger', {}, sessionId);
    initialized = true;
    resolveAttached();
  }
  async function requestPaused(event, entry) {
    if (!initialized || event.sessionId !== sessionId || !id(event.params.requestId)) throw makeError('REQUEST_SESSION');
    const p = event.params;
    const descriptor = descriptorOf(p, limits.maxRequestBytes);
    const decision = decisionOf(classifyRequest, descriptor, limits);
    if (p.responseErrorReason !== undefined) throw makeError('RESPONSE_ERROR');
    if (p.responseStatusCode === undefined) {
      if (pending.has(p.requestId) || ++requestCount > limits.maxRequests) throw makeError('REQUEST_LIMIT');
      if (pending.size >= limits.maxPendingRequests) throw makeError('PENDING_LIMIT');
      const requestHeaders = p.request.headers;
      if (!record(requestHeaders) || Object.keys(requestHeaders).length > 100) throw makeError('REQUEST_HEADERS');
      let headerBytes = 0;
      const headers = [];
      for (const [name, value] of Object.entries(requestHeaders)) {
        if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/.test(name) || typeof value !== 'string' || /[\r\n\0]/.test(value)) {
          throw makeError('REQUEST_HEADERS');
        }
        headerBytes += bytes(name) + bytes(value);
        if (headerBytes > 32768) throw makeError('REQUEST_HEADERS');
        if (name.toLowerCase() !== 'accept-encoding') headers.push({ name, value });
      }
      headers.push({ name: 'Accept-Encoding', value: 'identity' });
      aggregateBytes += bytes(descriptor.url) + bytes(descriptor.postData) + headerBytes;
      if (aggregateBytes > limits.maxTotalBytes) throw makeError('AGGREGATE_SIZE');
      pending.set(p.requestId, { descriptor, decision });
      await command('Fetch.continueRequest', { requestId: p.requestId, headers }, sessionId, () => forgetPause(entry));
      return;
    }
    const original = pending.get(p.requestId);
    if (!original || JSON.stringify(original.descriptor) !== JSON.stringify(descriptor) ||
      JSON.stringify(original.decision) !== JSON.stringify(decision)) throw makeError('RESPONSE_BINDING');
    const status = p.responseStatusCode;
    if (!Number.isInteger(status) || status < 200 || status > 299) throw makeError('RESPONSE_STATUS');
    const headers = headersOf(p.responseHeaders);
    aggregateBytes += headers.reduce((sum, item) => sum + bytes(item.name) + bytes(item.value), 0);
    if (aggregateBytes > limits.maxTotalBytes) throw makeError('AGGREGATE_SIZE');
    const header = name => headers.find(value => value.name === name)?.value ?? '';
    if (header('content-disposition') || (header('content-encoding') && header('content-encoding').toLowerCase() !== 'identity')) {
      throw makeError('RESPONSE_ENCODING_OR_DOWNLOAD');
    }
    if (!mimeAllowed(decision.responseKind, header('content-type'))) throw makeError('RESPONSE_MIME');
    const length = header('content-length');
    if (length && (!/^(0|[1-9][0-9]{0,9})$/.test(length) || Number(length) > decision.maxResponseBytes)) throw makeError('RESPONSE_SIZE');
    const chunks = [];
    let count = 0;
    if (status === 204) {
      if (decision.responseKind !== 'empty' || (length && length !== '0')) throw makeError('RESPONSE_SIZE');
    } else {
    while (activeStreams >= limits.maxConcurrentStreams) {
      let wake;
      try { await deadline(new Promise(resolve => { wake = resolve; idleWaiters.add(wake); }), 'STREAM_WAIT_TIMEOUT'); }
      finally { idleWaiters.delete(wake); }
      healthy();
    }
    activeStreams++;
    const { stream } = await command('Fetch.takeResponseBodyAsStream', { requestId: p.requestId }, sessionId,
      () => { entry.stage = 'stream-opening'; });
    if (!id(stream)) throw makeError('STREAM_SCHEMA');
    entry.stage = 'streaming';
    streams.set(stream, sessionId);
    while (true) {
      const size = Math.min(65536, decision.maxResponseBytes - count + 1, limits.maxTotalBytes - aggregateBytes + 1);
      if (size < 1) throw makeError('RESPONSE_SIZE');
      const chunk = await command('IO.read', { handle: stream, size }, sessionId);
      if (typeof chunk.data !== 'string' || typeof chunk.eof !== 'boolean' ||
        (chunk.base64Encoded !== undefined && typeof chunk.base64Encoded !== 'boolean')) throw makeError('STREAM_SCHEMA');
      if (chunk.data.length > Math.ceil(size / 3) * 4 + 4) throw makeError('STREAM_CHUNK');
      let data;
      if (chunk.base64Encoded === true) {
        if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(chunk.data)) throw makeError('STREAM_BASE64');
        data = Buffer.from(chunk.data, 'base64');
        if (data.toString('base64') !== chunk.data) throw makeError('STREAM_BASE64');
      } else data = Buffer.from(chunk.data, 'utf8');
      if (data.length > size || (!chunk.eof && data.length === 0)) throw makeError('STREAM_CHUNK');
      count += data.length; totalBytes += data.length; aggregateBytes += data.length;
      if (count > decision.maxResponseBytes || aggregateBytes > limits.maxTotalBytes) throw makeError('RESPONSE_SIZE');
      chunks.push(data);
      if (chunk.eof) break;
    }
    await command('IO.close', { handle: stream }, sessionId);
    entry.stage = 'response';
    streams.delete(stream); activeStreams--;
    pulse();
    }
    if ((length && Number(length) !== count) || (decision.responseKind === 'empty' && count !== 0)) throw makeError('RESPONSE_SIZE');
    const sanitized = headers.filter(value => SAFE_HEADERS.has(value.name));
    // Add a restrictive policy alongside (never replacing) the application's CSP.
    // This is a UAT transport overlay, not a published-artifact equivalence claim.
    if (decision.responseKind === 'document') sanitized.push({ name: 'content-security-policy',
      value: "worker-src 'none'; child-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'" });
    sanitized.push({ name: 'content-length', value: String(count) });
    await command('Fetch.fulfillRequest', { requestId: p.requestId, responseCode: status,
      responseHeaders: sanitized, body: Buffer.concat(chunks).toString('base64') }, sessionId, () => forgetPause(entry));
    pending.delete(p.requestId);
  }
  try {
    unsubscribe = cdp.onEvent(event => {
      if (stopping) {
        if (record(event) && event.method === 'Fetch.requestPaused') {
          const entry = registerPause(event);
          if (entry) cancelPause(entry);
        }
        return;
      }
      pulse();
      if (!record(event) || typeof event.method !== 'string' || !record(event.params)) { latch(makeError('EVENT_SCHEMA')); return; }
      try {
        navigationEvent(event);
        if (event.sessionId === sessionId && sessionId) {
          if (event.method === 'Runtime.exceptionThrown' && ++exceptionCount > 1024) throw makeError('DIAGNOSTIC_LIMIT');
          if (event.method === 'Runtime.consoleAPICalled' && event.params.type === 'error' && ++consoleErrorCount > 1024) {
            throw makeError('DIAGNOSTIC_LIMIT');
          }
        }
      } catch (error) { latch(error); return; }
      if (event.method === 'Target.attachedToTarget') {
        if (!record(event.params.targetInfo)) { latch(makeError('TARGET_SCHEMA')); return; }
        if (!targetId) {
          if (heldAttachments.length > 1) latch(makeError('TARGET_DENIED'));
          else heldAttachments.push(event);
        } else startTask(() => initialize(event));
      } else if (event.method === 'Fetch.requestPaused') {
        const entry = registerPause(event);
        if (entry) startTask(() => requestPaused(event, entry));
      }
      else if (event.method === 'Fetch.authRequired' || event.method === 'Network.webSocketCreated' ||
        event.method === 'Browser.downloadWillBegin' || event.method === 'Target.targetCrashed' ||
        (event.method === 'Target.detachedFromTarget' && event.params.sessionId === sessionId)) latch(makeError('UNSUPPORTED_ACTIVITY'));
    });
    if (typeof unsubscribe !== 'function') throw makeError('OPTIONS');
    totalTimer = setTimeout(() => latch(makeError('GLOBAL_TIMEOUT')), limits.totalTimeoutMs);
    const inventory = await command('Target.getTargets');
    if (!Array.isArray(inventory.targetInfos) || inventory.targetInfos.length !== 0) throw makeError('EXISTING_TARGETS');
    const created = await command('Target.createBrowserContext', { disposeOnDetach: true });
    if (!id(created.browserContextId)) throw makeError('CONTEXT_SCHEMA');
    contextId = created.browserContextId;
    await command('Browser.setDownloadBehavior', { behavior: 'deny', browserContextId: contextId, eventsEnabled: true });
    await command('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true,
      filter: [{ type: 'browser', exclude: true }, { type: 'tab', exclude: true }, {}] });
    const page = await command('Target.createTarget', { url: 'about:blank', browserContextId: contextId });
    if (!id(page.targetId)) throw makeError('TARGET_SCHEMA');
    targetId = page.targetId;
    for (const event of heldAttachments.splice(0)) startTask(() => initialize(event));
    await deadline(attached, 'ATTACH_TIMEOUT');
    healthy();
    return Object.freeze({ targetId, sessionId,
      assertHealthy: healthy,
      getClosureStatus() { return Object.freeze({ cleanupConfirmed }); },
      async addInitScript(source) {
        healthy();
        if (navigated || typeof source !== 'string' || bytes(source) > 65536) throw makeError('INIT_SCRIPT');
        try { await command('Page.addScriptToEvaluateOnNewDocument', { source }, sessionId); }
        catch (error) { latch(error); await cleanup(); }
      },
      async navigate(url) {
        try {
          healthy();
          if (navigating || screenshotBusy) throw makeError('PAGE_OPERATION_BUSY');
          navigating = true;
          decisionOf(classifyRequest, descriptorOf({ request: { url, method: 'GET' }, resourceType: 'Document' }, limits.maxRequestBytes), limits);
          navigated = true;
          const result = await command('Page.navigate', { url }, sessionId);
          if (result.errorText) throw makeError('NAVIGATION');
        } catch (error) { latch(error); await cleanup(); }
        finally { navigating = false; }
      },
      async navigateAndWait(url) {
        let current;
        try {
          healthy();
          if (navigating || screenshotBusy) throw makeError('PAGE_OPERATION_BUSY');
          navigating = true;
          const decision = decisionOf(classifyRequest, descriptorOf({ request: { url, method: 'GET' }, resourceType: 'Document' }, limits.maxRequestBytes), limits);
          if (decision.responseKind !== 'document') throw makeError('NAVIGATION');
          const previous = topFrame(await command('Page.getFrameTree', {}, sessionId));
          current = { frameId: previous.frameId, previousLoaderId: previous.loaderId, events: [], armed: false };
          navigation = current;
          navigated = true;
          await deadline((async () => {
            const result = await command('Page.navigate', { url, frameId: previous.frameId }, sessionId,
              () => { current.armed = true; });
            if (result.errorText !== undefined || result.isDownload === true || result.frameId !== previous.frameId ||
              !id(result.loaderId) || result.loaderId === previous.loaderId) throw makeError('NAVIGATION');
            while (true) {
              healthy();
              const matching = current.events.filter(event => event.loaderId === result.loaderId);
              if (matching.some(event => event.kind === 'frame' && event.url !== url)) throw makeError('NAVIGATION_BINDING');
              if (matching.some(event => event.kind === 'frame') && matching.some(event => event.kind === 'load')) break;
              await new Promise(resolve => { current.wake = resolve; idleWaiters.add(resolve); });
              idleWaiters.delete(current.wake); current.wake = undefined;
            }
            const final = topFrame(await command('Page.getFrameTree', {}, sessionId));
            if (final.frameId !== result.frameId || final.loaderId !== result.loaderId || final.url !== url) throw makeError('NAVIGATION_BINDING');
            current.result = Object.freeze({ ...final, loaded: true });
          })(), 'NAVIGATION_TIMEOUT');
          healthy();
          return current.result;
        } catch (error) { latch(error); await cleanup(); }
        finally {
          if (current?.wake) { idleWaiters.delete(current.wake); current.wake(); }
          if (navigation === current) navigation = undefined;
          navigating = false;
        }
      },
      getPageDiagnostics() { healthy(); return Object.freeze({ exceptionCount, consoleErrorCount }); },
      async captureScreenshot() {
        try {
          healthy();
          if (navigating || screenshotBusy) throw makeError('PAGE_OPERATION_BUSY');
          screenshotBusy = true;
          if (++screenshots > limits.maxScreenshots) throw makeError('SCREENSHOT_LIMIT');
          const value = await command('Page.captureScreenshot', { format: 'png', fromSurface: true,
            captureBeyondViewport: false, clip: { x: 0, y: 0, width: 390, height: 844, scale: 1 } }, sessionId);
          const screenshot = screenshotOf(value, limits.maxScreenshotBytes);
          aggregateBytes += screenshot.byteLength;
          if (aggregateBytes > limits.maxTotalBytes) throw makeError('AGGREGATE_SIZE');
          return screenshot;
        } catch (error) { latch(error); await cleanup(); }
        finally { screenshotBusy = false; }
      },
      async evaluate(expression) {
        try {
          healthy();
          if (typeof expression !== 'string' || bytes(expression) > 65536) throw makeError('EVALUATION');
          const value = await command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
          if (value.exceptionDetails || !record(value.result) || bytes(JSON.stringify(value.result)) > 1024 * 1024) throw makeError('EVALUATION');
          return value.result.value;
        } catch (error) { latch(error); await cleanup(); }
      },
      async waitForIdle() {
        try {
          healthy();
          while (tasks.size || pending.size || streams.size) {
            let wake;
            try { await deadline(new Promise(resolve => { wake = resolve; idleWaiters.add(wake); }), 'IDLE_TIMEOUT'); }
            finally { idleWaiters.delete(wake); }
            healthy();
          }
        } catch (error) { latch(error); await cleanup(); }
      },
      close: cleanup
    });
  } catch (error) {
    latch(error);
    await cleanup();
    throw failure;
  }
}
