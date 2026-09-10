import assert from 'node:assert/strict';
import { createControllerUatBrowserTransport } from '../scripts/controller-uat-browser-transport.mjs';
import { createUatBrowserReadPolicy } from '../scripts/controller-uat-browser-read-policy.mjs';

// In-memory CDP protocol peer, not a Chromium/network/authentication test.
const origin = 'https://fixture.invalid';
const marker = 'PRIVATE_SESSION_SENTINEL';
const tick = () => new Promise(resolve => setImmediate(resolve));
const allow = (responseKind = 'json', maxResponseBytes = 4096) => Object.freeze({ allowed: true, responseKind, maxResponseBytes });
function policy(request) {
  if (request.url === `${origin}/` && request.method === 'GET') return allow('document');
  if (/^https:\/\/fixture\.invalid\/data[0-9]*$/.test(request.url) && request.method === 'GET') return allow();
  return Object.freeze({ allowed: false });
}
function peer(overrides = {}) {
  const calls = [], responses = new Map(), streams = new Map(), browserPauses = new Map(), released = [];
  let listener, closed = false, active = 0, maxActive = 0;
  const emit = (method, params, sessionId) => {
    if (method === 'Fetch.requestPaused') browserPauses.set(params.requestId, params);
    listener?.({ method, params, sessionId });
  };
  const cdp = {
    onEvent(callback) { listener = callback; return () => { listener = undefined; if (overrides.unsubscribeFails) throw new Error(marker); }; },
    async terminate() {
      calls.push({ method: 'terminate' });
      if (overrides.closeFails) throw new Error(marker);
      overrides.onTerminate?.({ emit, calls });
      // Force termination does not detach/resume a live renderer.
      closed = true; browserPauses.clear();
    },
    async send(method, params = {}, sessionId) {
      calls.push({ method, params, sessionId });
      const override = overrides.send?.(method, params, sessionId, { emit, calls });
      if (override !== undefined) return override;
      if (method === 'Target.getTargets') return { targetInfos: overrides.existing ? [{ targetId: 'old-page' }] : [] };
      if (method === 'Target.disposeBrowserContext' || method === 'Target.detachFromTarget') {
        // Model the real Chromium escape: graceful detach releases pauses.
        released.push(...browserPauses.values()); browserPauses.clear();
      }
      if (method === 'Fetch.failRequest') {
        assert.equal(params.errorReason, 'BlockedByClient');
        browserPauses.delete(params.requestId);
      }
      if (method === 'Target.createBrowserContext') return { browserContextId: 'context-1' };
      if (method === 'Target.createTarget') {
        queueMicrotask(() => emit('Target.attachedToTarget', { sessionId: 'session-1', waitingForDebugger: true,
          targetInfo: { targetId: 'target-1', type: 'page', browserContextId: 'context-1' } }));
        return { targetId: 'target-1' };
      }
      if (method === 'Fetch.continueRequest') {
        browserPauses.delete(params.requestId);
        const response = responses.get(params.requestId);
        if (response) queueMicrotask(() => emit('Fetch.requestPaused', response, 'session-1'));
      }
      if (method === 'Fetch.takeResponseBodyAsStream') {
        const key = `stream-${params.requestId}`;
        const response = responses.get(params.requestId);
        streams.set(key, { data: Buffer.from(response.fixtureBody ?? '{}'), cursor: 0 });
        active++; maxActive = Math.max(maxActive, active);
        return { stream: key };
      }
      if (method === 'IO.read') {
        await tick();
        const stream = streams.get(params.handle);
        const data = stream.data.subarray(stream.cursor, stream.cursor + Math.min(params.size, 7));
        stream.cursor += data.length;
        return { data: data.toString('base64'), base64Encoded: true, eof: stream.cursor === stream.data.length };
      }
      if (method === 'IO.close') { streams.delete(params.handle); active--; }
      if (method === 'Fetch.fulfillRequest') browserPauses.delete(params.requestId);
      if (method === 'Runtime.evaluate') return { result: { value: { fixture: true } } };
      return {};
    }
  };
  function request(requestId = 'request-1', change = {}) {
    const event = { requestId, resourceType: 'Fetch', request: { url: `${origin}/data`, method: 'GET',
      headers: { Authorization: marker, 'Accept-Encoding': 'gzip' } }, ...change };
    const { response: responseChange, ...requestEvent } = event;
    responses.set(requestId, { ...requestEvent, responseStatusCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], ...responseChange });
    emit('Fetch.requestPaused', requestEvent, 'session-1');
  }
  return { cdp, calls, emit, request, released, get closed() { return closed; }, get maxActive() { return maxActive; } };
}
async function setup(overrides = {}, classifyRequest = policy, limits = {}) {
  const fixture = peer(overrides);
  const boundary = await createControllerUatBrowserTransport({ cdp: fixture.cdp, classifyRequest,
    limits: { operationTimeoutMs: 200, totalTimeoutMs: 4000, ...limits } });
  return { fixture, boundary };
}
async function denied(change, code, options = {}) {
  const { fixture, boundary } = await setup(options.overrides, options.policy ?? policy, options.limits);
  change(fixture, boundary);
  await assert.rejects(boundary.waitForIdle(), error => {
    assert.equal(error.message, `CNYOS_UAT_BROWSER_${code}`);
    assert.ok(!error.message.includes(marker)); return true;
  });
  await assert.rejects(boundary.close(), { message: `CNYOS_UAT_BROWSER_${code}` });
  assert.equal(fixture.closed, true);
  assert.deepEqual(fixture.released, []);
  assert.ok(!fixture.calls.some(call => ['Target.disposeBrowserContext', 'Target.detachFromTarget'].includes(call.method)));
  assert.equal(fixture.calls.filter(call => call.method === 'Fetch.fulfillRequest').length, 0);
  return fixture;
}

const { fixture, boundary } = await setup();
const commands = fixture.calls.map(call => call.method);
const resumed = commands.indexOf('Runtime.runIfWaitingForDebugger');
for (const method of ['Browser.setDownloadBehavior', 'Target.setAutoAttach', 'Network.setBlockedURLs',
  'Network.setBypassServiceWorker', 'Fetch.enable', 'Page.enable', 'Runtime.enable', 'Emulation.setTimezoneOverride',
  'Emulation.setLocaleOverride', 'Emulation.setDeviceMetricsOverride']) {
  assert.ok(commands.indexOf(method) >= 0 && commands.indexOf(method) < resumed, method);
}
assert.deepEqual(fixture.calls.find(call => call.method === 'Network.setBlockedURLs').params.urls, ['ws://*', 'wss://*']);
assert.equal(fixture.calls.find(call => call.method === 'Emulation.setTimezoneOverride').params.timezoneId, 'Asia/Bangkok');
assert.deepEqual(fixture.calls.find(call => call.method === 'Emulation.setLocaleOverride').params, { locale: 'th-TH' });
assert.deepEqual(fixture.calls.find(call => call.method === 'Emulation.setDeviceMetricsOverride').params,
  { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
assert.deepEqual(fixture.calls.find(call => call.method === 'Target.createTarget').params,
  { url: 'about:blank', browserContextId: 'context-1' });
await boundary.addInitScript('globalThis.fixture = true');
await boundary.navigate(`${origin}/`);
assert.deepEqual(await boundary.evaluate('({fixture:true})'), { fixture: true });
fixture.request();
await boundary.waitForIdle();
assert.equal(fixture.calls.filter(call => call.method === 'IO.close').length, 1);
assert.equal(Buffer.from(fixture.calls.find(call => call.method === 'Fetch.fulfillRequest').params.body, 'base64').toString(), '{}');
assert.deepEqual(fixture.calls.find(call => call.method === 'Fetch.continueRequest').params.headers,
  [{ name: 'Authorization', value: marker }, { name: 'Accept-Encoding', value: 'identity' }]);
assert.deepEqual(await boundary.close(), { closed: true, requestCount: 1, responseBytes: 2,
  authorization: false, authenticatedUatComplete: false, osEgressIsolationVerified: false });
assert.equal(fixture.closed, true);

const burst = await setup({}, policy, { maxConcurrentStreams: 2 });
for (let i = 0; i < 24; i++) burst.fixture.request(`burst-${i}`);
await burst.boundary.waitForIdle();
assert.equal(burst.fixture.maxActive, 2);
assert.equal(burst.fixture.calls.filter(call => call.method === 'Fetch.fulfillRequest').length, 24);
await burst.boundary.close();

// Exercise the actual source-derived policy with a sanitized preflight descriptor.
const realPolicy = createUatBrowserReadPolicy({ siteOrigin: 'https://uat-staging.invalid',
  supabaseOrigin: 'https://fixture-db.supabase.co', sessionUserId: '11111111-1111-4111-8111-111111111111',
  workspace: 'operations', role: 'viewer', bootInstant: '2026-09-10T00:00:00.000Z' });
for (const resourceType of ['Preflight', 'XHR', 'Fetch']) {
const preflight = await setup({}, realPolicy);
preflight.fixture.request('preflight', { request: {
  url: 'https://fixture-db.supabase.co/rest/v1/rpc/current_access_context', method: 'OPTIONS',
  headers: { 'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'x-client-info, content-type, authorization, apikey' }
}, resourceType, response: { responseStatusCode: 204, responseHeaders: [{ name: 'Access-Control-Allow-Origin', value: 'https://uat-staging.invalid' }] } });
await preflight.boundary.waitForIdle();
assert.equal(preflight.fixture.calls.filter(call => call.method === 'Fetch.takeResponseBodyAsStream').length, 0);
assert.equal(preflight.fixture.calls.find(call => call.method === 'Fetch.fulfillRequest').params.responseCode, 204);
await preflight.boundary.close();
}
await denied(f => f.request('empty-not-preflight'), 'POLICY_SCHEMA', { policy: () => allow('empty', 1) });
await denied(f => f.request('preflight-missing-metadata', { resourceType: 'XHR', request: {
  url: `${origin}/data`, method: 'OPTIONS', headers: {}
} }), 'PREFLIGHT_SCHEMA', { policy: () => allow('empty', 1) });

const requestDenial = await denied(f => f.request('denied', { request: { url: 'https://unreviewed.invalid/', method: 'GET', headers: {} } }), 'REQUEST_DENIED');
assert.equal(requestDenial.calls.find(call => call.method === 'Fetch.failRequest').params.requestId, 'denied');
assert.ok(requestDenial.calls.findIndex(call => call.method === 'Fetch.failRequest') < requestDenial.calls.findIndex(call => call.method === 'terminate'));
const redirectDenial = await denied(f => f.request('redirect', { response: { responseStatusCode: 302,
  responseHeaders: [{ name: 'Location', value: `https://unreviewed.invalid/${marker}` }] } }), 'RESPONSE_STATUS');
assert.equal(redirectDenial.calls.find(call => call.method === 'Fetch.failRequest').params.requestId, 'redirect');
await denied(f => f.request('compressed', { response: { responseHeaders: [
  { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Encoding', value: 'gzip' }] } }), 'RESPONSE_ENCODING_OR_DOWNLOAD');
await denied(f => f.request('attachment', { response: { responseHeaders: [
  { name: 'Content-Type', value: 'application/json' }, { name: 'Content-Disposition', value: 'attachment' }] } }), 'RESPONSE_ENCODING_OR_DOWNLOAD');
await denied(f => f.request('mime', { response: { responseHeaders: [{ name: 'Content-Type', value: 'text/html' }] } }), 'RESPONSE_MIME');
await denied(f => f.request('large'), 'RESPONSE_SIZE', { policy: () => allow('json', 1) });
await denied(f => f.request('bad-base64'), 'STREAM_BASE64', {
  overrides: { send: method => method === 'IO.read' ? Promise.resolve({ data: 'AB==', base64Encoded: true, eof: true }) : undefined }
});
await denied(f => f.request('bad-eof'), 'STREAM_SCHEMA', {
  overrides: { send: method => method === 'IO.read' ? Promise.resolve({ data: '', eof: 'true' }) : undefined }
});
await denied(f => f.request('empty-progress'), 'STREAM_CHUNK', {
  overrides: { send: method => method === 'IO.read' ? Promise.resolve({ data: '', eof: false }) : undefined }
});
await denied(f => f.request('policy'), 'POLICY_SCHEMA', { policy: () => ({ allowed: true, responseKind: 'json', maxResponseBytes: 100 }) });
await denied(f => f.request('body', { request: { url: `${origin}/data`, method: 'GET', hasPostData: true, headers: {} } }), 'REQUEST_BODY');
await denied(f => { f.request('one'); f.request('two'); }, 'PENDING_LIMIT', { limits: { maxPendingRequests: 1 } });
await denied(f => f.request(), 'AGGREGATE_SIZE', { limits: { maxTotalBytes: 1 } });
for (const type of ['worker', 'shared_worker', 'service_worker', 'iframe', 'page', 'unknown']) {
  const failed = await denied(f => f.emit('Target.attachedToTarget', { sessionId: 'other-session', waitingForDebugger: true,
    targetInfo: { targetId: 'other-target', browserContextId: 'context-1', type } }, 'session-1'), 'TARGET_DENIED');
  assert.equal(failed.calls.filter(call => call.method === 'Runtime.runIfWaitingForDebugger').length, 1);
}
for (const method of ['Fetch.authRequired', 'Network.webSocketCreated', 'Browser.downloadWillBegin']) {
  await denied(f => f.emit(method, {}, 'session-1'), 'UNSUPPORTED_ACTIVITY');
}
const existing = peer({ existing: true });
await assert.rejects(createControllerUatBrowserTransport({ cdp: existing.cdp, classifyRequest: policy }), /CNYOS_UAT_BROWSER_EXISTING_TARGETS/);
assert.ok(existing.closed);
assert.ok(!existing.calls.some(call => call.method === 'Target.createBrowserContext'));

// A microtask may latch shutdown after command() is scheduled but before send().
const race = await setup();
queueMicrotask(() => race.fixture.emit('Network.webSocketCreated', {}, 'session-1'));
await assert.rejects(race.boundary.evaluate('1'), /CNYOS_UAT_BROWSER_UNSUPPORTED_ACTIVITY/);
assert.ok(!race.fixture.calls.some(call => call.method === 'Runtime.evaluate'));

let releaseRead;
const stalled = await setup({ send: method => method === 'IO.read' ? new Promise(resolve => { releaseRead = resolve; }) : undefined }, policy,
  { operationTimeoutMs: 30 });
stalled.fixture.request();
while (!releaseRead) await tick();
await new Promise(resolve => setTimeout(resolve, 50));
await assert.rejects(stalled.boundary.close(), /CNYOS_UAT_BROWSER_OPERATION_TIMEOUT/);
releaseRead({ data: 'e30=', base64Encoded: true, eof: true });
await tick();
assert.ok(stalled.fixture.closed);
assert.ok(!stalled.fixture.calls.some(call => ['Fetch.fulfillRequest', 'Fetch.failRequest'].includes(call.method)));

for (const overrides of [{ closeFails: true }, { unsubscribeFails: true }]) {
  const uncertain = await setup(overrides);
  uncertain.fixture.emit('Network.webSocketCreated', {}, 'session-1');
  await assert.rejects(uncertain.boundary.close(), { message: 'CNYOS_UAT_BROWSER_CLEANUP_UNCONFIRMED' });
}
const cancelFailure = await setup({ send: method => method === 'Fetch.failRequest' ? Promise.reject(new Error(marker)) : undefined });
cancelFailure.fixture.request('blocked', { request: { url: 'https://unreviewed.invalid/', method: 'GET', headers: {} } });
await assert.rejects(cancelFailure.boundary.waitForIdle(), /CNYOS_UAT_BROWSER_CLEANUP_UNCONFIRMED/);
assert.ok(cancelFailure.fixture.closed);
assert.ok(!cancelFailure.fixture.calls.some(call => call.method === 'Target.disposeBrowserContext'));

const cancelStall = await setup({ send: method => method === 'Fetch.failRequest' ? new Promise(() => {}) : undefined }, policy,
  { operationTimeoutMs: 30 });
cancelStall.fixture.request('blocked', { request: { url: 'https://unreviewed.invalid/', method: 'GET', headers: {} } });
await assert.rejects(cancelStall.boundary.waitForIdle(), /CNYOS_UAT_BROWSER_CLEANUP_UNCONFIRMED/);
assert.ok(cancelStall.fixture.closed);
assert.ok(!cancelStall.fixture.calls.some(call => call.method === 'Target.disposeBrowserContext'));

const overflow = await setup({}, policy, { maxPendingRequests: 2 });
for (let i = 0; i < 256; i++) overflow.fixture.request(`overflow-${i}`);
await assert.rejects(overflow.boundary.waitForIdle(), /CNYOS_UAT_BROWSER_CLEANUP_UNCONFIRMED/);
assert.ok(overflow.fixture.closed);
assert.ok(overflow.fixture.calls.filter(call => call.method === 'Fetch.failRequest').length <= 5);
assert.ok(!overflow.fixture.calls.some(call => ['Fetch.continueRequest', 'Fetch.fulfillRequest'].includes(call.method)));
assert.deepEqual(overflow.fixture.released, []);

const simultaneous = await setup();
simultaneous.fixture.request('denied-first', { request: { url: 'https://unreviewed.invalid/', method: 'GET', headers: {} } });
simultaneous.fixture.request('allowed-paused');
await assert.rejects(simultaneous.boundary.waitForIdle(), /CNYOS_UAT_BROWSER_REQUEST_DENIED/);
assert.deepEqual(simultaneous.fixture.calls.filter(call => call.method === 'Fetch.failRequest').map(call => call.params.requestId).sort(),
  ['allowed-paused', 'denied-first']);
assert.deepEqual(simultaneous.fixture.released, []);

const late = await setup({ onTerminate: ({ emit }) => emit('Fetch.requestPaused', { requestId: 'late-denied',
  resourceType: 'Fetch', request: { url: 'https://unreviewed.invalid/', method: 'GET', headers: {} } }, 'session-1') });
late.fixture.request('denied-first', { request: { url: 'https://unreviewed.invalid/', method: 'GET', headers: {} } });
await assert.rejects(late.boundary.waitForIdle(), /CNYOS_UAT_BROWSER_REQUEST_DENIED/);
assert.ok(late.fixture.calls.some(call => call.method === 'Fetch.failRequest' && call.params.requestId === 'late-denied'));
assert.deepEqual(late.fixture.released, []);
await assert.rejects(createControllerUatBrowserTransport({ cdp: { send() {}, onEvent() {}, close() {} }, classifyRequest: policy }),
  /CNYOS_UAT_BROWSER_OPTIONS/);
console.log('CNYOS UAT browser transport contract: passed');
