import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';
import { performance } from 'node:perf_hooks';
import { POLICY } from '../scripts/policy.mjs';
import { UAT_ACCESS_ROLES } from '../scripts/controller-uat-access-observations.mjs';
import { UAT_BROWSER_WORKSPACE_PATHS } from '../scripts/controller-uat-browser-read-policy.mjs';
import { createControllerUatBrowserTransport } from '../scripts/controller-uat-browser-transport.mjs';
import { runControllerBrowserMatrix, expectedUatNavigation, UAT_EXPECTED_WORKSPACES,
  UAT_NORMAL_BOOT_TEXT, UAT_DENIAL_BOOT_TEXT } from '../scripts/controller-uat-browser-matrix.mjs';
import { PLATFORM_FEATURES, resolvePlatformFeatures } from '../test-support/candidate-source/platform-config.js';

// Pure orchestration + VM source-bound DOM fixture. No browser, connection,
// genuine JWT, identity validation, database, filesystem retention or live UAT.
const root = new URL('../test-support/candidate-source/', import.meta.url);
const runtime = await fs.readFile(new URL('chananya-runtime.js', root), 'utf8');
const shell = await fs.readFile(new URL('app-shell.js', root), 'utf8');
const scriptNames = { operations: 'app', checkin: 'check-in', clinical: 'clinical-v3' };
const htmlByWorkspace = {};
for (const [workspace, route] of Object.entries(UAT_BROWSER_WORKSPACE_PATHS)) {
  const html = await fs.readFile(new URL(route === '/' ? 'index.html' : route.slice(1), root), 'utf8');
  htmlByWorkspace[workspace] = html;
  assert.equal(html.match(/<body data-page="([^"]+)"/)[1], workspace);
  assert.equal(html.match(/id="boot-error">([^<]*)</)[1], UAT_NORMAL_BOOT_TEXT[workspace]);
  if (workspace !== 'operations') {
    const source = await fs.readFile(new URL(`${scriptNames[workspace] || workspace}.js`, root), 'utf8');
    assert.ok(source.includes(`throw new Error('${UAT_DENIAL_BOOT_TEXT[workspace]}')`), workspace);
  }
}
// Exercise dependency closure/canonical order against the actual platform
// resolver, not only a mirrored fixture. Missing dependencies fail closed.
for (const feature of PLATFORM_FEATURES) {
  const resolved = resolvePlatformFeatures([feature.id]);
  assert.doesNotThrow(() => expectedUatNavigation('super_admin', resolved));
}
for (const invalid of [undefined, [], ['clinical'], ['core', 'clinical'], ['core', 'core'], ['unknown'], ['knowledge', 'core']]) {
  assert.throws(() => expectedUatNavigation('viewer', invalid), /MATRIX_FEATURES/);
}
assert.deepEqual(expectedUatNavigation('viewer', null), ['/', '/luopan.html']);
assert.deepEqual(expectedUatNavigation('viewer', ['core']), ['/']);

const sentinel = 'PRIVATE_MATRIX_SENTINEL';
function leases() {
  return Object.fromEntries(UAT_ACCESS_ROLES.map((role, index) => {
    const id = `11111111-1111-4111-8111-${String(index + 1).padStart(12, '0')}`;
    const expires_at = Math.ceil(Date.now() / 1000) + 3600;
    const claims = { iss: `${POLICY.target.supabaseOrigin}/auth/v1`, sub: id, aud: 'authenticated', role: 'authenticated', exp: expires_at };
    // Deliberately unsigned fake inputs only. Matrix outputs must not claim the
    // structural consistency check authenticated these fixtures.
    const access_token = `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.ZmFrZQ`;
    return [role, { access_token, refresh_token: `fake_${sentinel}_${index}`, expires_at, expires_in: 3600, token_type: 'bearer',
      user: { id, email: `${sentinel}@example.invalid`, user_metadata: { role: 'super_admin', sentinel }, app_metadata: { sentinel } } }];
  }));
}
function element(textContent = '', hidden = false) {
  const classes = new Set(hidden ? ['hidden'] : []);
  const value = { textContent, dataset: {}, hidden: false, links: [], attributes: {},
    classList: { contains: key => classes.has(key), add: key => classes.add(key), remove: key => classes.delete(key) },
    getClientRects: () => classes.has('hidden') ? [] : [{}],
    addEventListener() {}, setAttribute(key, next) { this.attributes[key] = next; },
    getAttribute(key) { return this.attributes[key] ?? null; },
    querySelectorAll(selector) { assert.equal(selector, 'a'); return this.links; } };
  Object.defineProperty(value, 'innerHTML', { set(markup) {
    this.links = [...markup.matchAll(/<a href="([^"]+)"/g)].map(match => {
      const link = element(); link.attributes.href = match[1]; return link;
    });
  } });
  return value;
}
function page(role, workspace, features) {
  const nodes = { '#app': element('', true), '#boot': element(), '#boot-error': element(UAT_NORMAL_BOOT_TEXT[workspace]),
    '#role': element('viewer'), '#global-nav': element(), '#identity': element() };
  const config = { deploymentId: POLICY.target.deploymentId, database: { url: POLICY.target.supabaseOrigin },
    tenant: { expectedClinicId: POLICY.target.clinicId, expectedClinicCode: POLICY.target.clinicCode },
    auth: { redirectOrigin: POLICY.target.netlifyOrigin }, safety: { previewLocked: false }, ...(features === null ? {} : { features }) };
  const body = element(); body.dataset.page = workspace;
  const document = { body, readyState: 'complete', addEventListener() {},
    querySelector: selector => nodes[selector] ?? null,
    querySelectorAll: selector => nodes[selector] ? [nodes[selector]] : [] };
  const storage = new Map();
  const context = vm.createContext({ window: { CLINICAL_OS_CONFIG: config, dispatchEvent() {} }, document,
    location: { origin: POLICY.target.netlifyOrigin, href: `${POLICY.target.netlifyOrigin}${UAT_BROWSER_WORKSPACE_PATHS[workspace]}` },
    localStorage: { setItem(key, value) { storage.set(key, value); } },
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; } },
    getComputedStyle: value => ({ display: value.classList.contains('hidden') ? 'none' : 'block', visibility: 'visible' }) });
  context.window.top = context.window;
  vm.runInContext(runtime, context);
  vm.runInContext(shell, context);
  const profile = { clinic_role: ['admin', 'super_admin'].includes(role) ? 'viewer' : role,
    system_role: role === 'super_admin' ? 'super_admin' : role === 'admin' ? 'admin' : 'staff', access_context_ready: true };
  const route = context.window.ChananyaShell.routes.find(route => route.key === workspace);
  const allowed = !route.capability || context.window.ChananyaRuntime.can(profile, route.capability);
  assert.equal(allowed, UAT_EXPECTED_WORKSPACES[role].includes(workspace));
  if (allowed) {
    context.window.ChananyaShell.mount({ profile, session: { user: {} }, active: workspace });
    nodes['#app'].classList.remove('hidden'); nodes['#boot'].classList.add('hidden');
    assert.deepEqual(nodes['#global-nav'].links.map(link => link.getAttribute('href')), [...expectedUatNavigation(role, features)]);
  } else nodes['#boot-error'].textContent = UAT_DENIAL_BOOT_TEXT[workspace];
  return { nodes, context, storage, allowed };
}
function fixture(changes = {}) {
  const created = [], retained = [];
  const features = changes.features === undefined ? null : changes.features;
  let active = 0, maxActive = 0;
  const options = { sessionLeasesByRole: leases(), expectedFeatures: features,
    async createOwnedTransport({ role, workspace, classifyRequest }) {
      if (changes.setupFails) throw new Error(sentinel);
      assert.equal(active, 0, 'a new role must not overlap a prior owned browser');
      const state = { role, workspace, ...page(role, workspace, features), closed: false, evaluations: 0, idle: 0,
        diagnostics: { exceptionCount: 0, consoleErrorCount: UAT_EXPECTED_WORKSPACES[role].includes(workspace) ? 0 : 1 } };
      const url = `${POLICY.target.netlifyOrigin}${UAT_BROWSER_WORKSPACE_PATHS[workspace]}`;
      assert.equal(classifyRequest({ url, method: 'GET', resourceType: 'Document' }).allowed, true);
      for (const request of [
        { url: `${POLICY.productionDenylist.netlifyOrigin}/`, method: 'GET', resourceType: 'Document' },
        { url: `${POLICY.target.netlifyOrigin}/api/account-access`, method: 'POST', resourceType: 'Fetch', postData: '{"action":"status"}' },
        { url: `${POLICY.target.supabaseOrigin}/auth/v1/token?grant_type=refresh_token`, method: 'POST', resourceType: 'Fetch', postData: '{}' }
      ]) assert.equal(classifyRequest(request).allowed, false);
      active++; maxActive = Math.max(maxActive, active); created.push(state);
      const transport = {
        async addInitScript(source) {
          // Exact origin and top-frame restrictions are executed, not regex-only.
          const originalOrigin = state.context.location.origin;
          state.context.location.origin = POLICY.productionDenylist.netlifyOrigin;
          vm.runInContext(source, state.context); assert.equal(state.storage.size, 0);
          state.context.location.origin = originalOrigin;
          state.context.window.top = {};
          vm.runInContext(source, state.context); assert.equal(state.storage.size, 0);
          state.context.window.top = state.context.window;
          vm.runInContext(source, state.context); assert.equal(state.storage.size, 1);
          const key = `sb-${POLICY.target.supabaseProjectRef}-auth-token`;
          const stored = JSON.parse(state.storage.get(key));
          assert.deepEqual(Object.keys(stored.user), ['id']);
          assert.equal(stored.user.id, options.sessionLeasesByRole[role].user.id);
          assert.deepEqual(Object.keys(stored).sort(), ['access_token', 'expires_at', 'expires_in', 'refresh_token', 'token_type', 'user']);
        },
        async navigateAndWait(actual) {
          assert.equal(actual, url);
          if (changes.navigationFails) throw new Error(sentinel);
          return { loaded: true, url: changes.wrongNavigation ? `${url}?wrong=1` : url, frameId: 'frame', loaderId: 'loader' };
        },
        assertHealthy() { if (changes.terminated) throw new Error(sentinel); },
        async waitForIdle() { state.idle++; if (changes.idleFails) throw new Error(sentinel); },
        async evaluate(source) {
          state.evaluations++;
          changes.mutate?.(state);
          if (changes.rawResult) return sentinel;
          return vm.runInContext(source, state.context);
        },
        getPageDiagnostics() { return { ...state.diagnostics }; },
        async captureScreenshot() {
          state.captured = true; assert.equal(state.closed, false);
          if (changes.screenshotFails) throw new Error(sentinel);
          // Inert bytes: PNG validity is tested by the real transport contract,
          // not by pretending this dependency fixture is an image decoder.
          const bytes = Buffer.from('inert fixture');
          return { format: 'png', width: 390, height: 844, dataBase64: bytes.toString('base64'), byteLength: bytes.length };
        },
        async close() { state.closed = true; active--; if (changes.closeThrows) throw new Error(sentinel); return { closed: true }; },
        getClosureStatus() { return { cleanupConfirmed: state.closed && !changes.cleanupUncertain }; }
      };
      return transport;
    },
    async retainFailureScreenshot(value) {
      assert.equal(active, 0, 'retention must run only after confirmed browser closure');
      retained.push(value);
      if (changes.retentionHangs) return new Promise(() => {});
      if (changes.retentionFails) throw new Error(sentinel);
      return { stored: true, sha256: changes.retentionMismatch ? '0'.repeat(64) : value.sha256 };
    } };
  return { options, created, retained, get active() { return active; }, get maxActive() { return maxActive; } };
}
function safeResult(result) {
  assert.equal(result.authorization, false); assert.equal(result.authenticatedIdentityVerified, false);
  assert.equal(result.crossTenantDenialsVerified, false); assert.equal(result.uatComplete, false); assert.equal(result.deploymentAllowed, false);
  assert.ok(!JSON.stringify(result).includes(sentinel));
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.observations));
}
for (const features of [null, ['core'], resolvePlatformFeatures(['quality', 'outcomes', 'u-synthesise', 'appointments'])]) {
  const run = fixture({ features });
  const result = await runControllerBrowserMatrix(run.options);
  safeResult(result);
  assert.equal(result.allExpectedUiStatesObserved, true);
  assert.equal(result.observedCount, 110); assert.equal(run.created.length, 110);
  assert.equal(result.observations.filter(value => value.expected === 'allow').length, 40);
  assert.equal(result.observations.filter(value => value.expected === 'deny').length, 70);
  assert.equal(new Set(result.observations.map(value => `${value.role}/${value.workspace}`)).size, 110);
  assert.ok(run.created.every(value => value.closed && value.evaluations === 3 && value.idle === 3));
  assert.equal(run.active, 0); assert.equal(run.maxActive, 1); assert.equal(run.retained.length, 0);
}
for (const [change, expectedCode] of [
  [{ mutate: state => { state.nodes['#boot-error'].textContent = sentinel; } }, 'BOOT_ERROR'],
  [{ mutate: state => { state.context.location.href += '?wrong=1'; } }, 'DOCUMENT_MISMATCH'],
  [{ mutate: state => { state.context.document.body.dataset.page = 'other'; } }, 'DOCUMENT_MISMATCH'],
  [{ mutate: state => { state.context.window.CLINICAL_OS_CONFIG.database.url = POLICY.productionDenylist.supabaseOrigin; } }, 'CONFIG_MISMATCH'],
  [{ mutate: state => { state.context.window.CLINICAL_OS_CONFIG.features = []; } }, 'CONFIG_MISMATCH'],
  [{ mutate: state => { state.nodes['#role'].textContent = 'admin'; } }, 'ROLE_MISMATCH'],
  [{ mutate: state => { state.nodes['#global-nav'].links.pop(); } }, 'NAVIGATION_MISMATCH'],
  [{ mutate: state => { state.nodes['#app'].hidden = true; } }, 'VISIBILITY_MISMATCH'],
  [{ mutate: state => { state.diagnostics.exceptionCount = 1; } }, 'PAGE_DIAGNOSTICS'],
  [{ mutate: state => { state.diagnostics.consoleErrorCount = 1; } }, 'PAGE_DIAGNOSTICS'],
  [{ mutate: state => { if (state.evaluations === 3) state.nodes['#boot-error'].textContent = sentinel; } }, 'FINAL_STATE_CHANGED'],
  [{ mutate: state => { if (state.evaluations === 3) state.diagnostics.consoleErrorCount = 1; } }, 'PAGE_DIAGNOSTICS'],
  [{ rawResult: true }, 'PROBE_RESPONSE'], [{ navigationFails: true }, 'TRANSPORT_FAILURE'],
  [{ wrongNavigation: true }, 'TRANSPORT_FAILURE'], [{ idleFails: true }, 'TRANSPORT_FAILURE']
]) {
  const run = fixture(change); const result = await runControllerBrowserMatrix(run.options);
  safeResult(result); assert.equal(result.allExpectedUiStatesObserved, false); assert.equal(result.observedCount, 1);
  assert.equal(result.observations[0].code, expectedCode); assert.equal(result.observations[0].screenshotState, 'retained');
  assert.match(result.observations[0].failureScreenshot, /^practitioner\/operations\/[0-9a-f]{64}\.png$/);
  assert.equal(run.retained.length, 1); assert.equal(run.active, 0);
}
// A pending boot cannot become ready solely because no request is pending.
const pending = fixture({ mutate: state => { state.nodes['#app'].classList.add('hidden'); state.nodes['#boot'].classList.remove('hidden'); } });
const pendingResult = await runControllerBrowserMatrix(pending.options);
assert.equal(pendingResult.observations[0].code, 'BOOT_TIMEOUT'); assert.equal(pending.created[0].evaluations, 100);
// Exact expected denial is insufficient if the app shell mounted or extra
// errors occurred. Exercise a denied cell, not only the first allowed cell.
for (const mutate of [state => { state.nodes['#role'].dataset.effectiveRole = 'viewer'; },
  state => { state.nodes['#boot-error'].textContent = 'another denial'; }, state => { state.diagnostics.consoleErrorCount = 2; }]) {
  const run = fixture({ mutate: state => { if (!state.allowed) mutate(state); } });
  const result = await runControllerBrowserMatrix(run.options);
  assert.equal(result.allExpectedUiStatesObserved, false);
  assert.equal(result.observations.at(-1).expected, 'deny'); assert.notEqual(result.observations.at(-1).code, 'MATCH');
  assert.ok(run.created.every(state => state.closed)); safeResult(result);
}
for (const change of [{ screenshotFails: true }, { retentionFails: true }, { retentionMismatch: true }, { terminated: true }]) {
  const run = fixture({ navigationFails: true, ...change });
  const result = await runControllerBrowserMatrix(run.options);
  assert.equal(result.observations[0].screenshotState, 'unavailable'); assert.equal(result.observations[0].failureScreenshot, null);
  assert.equal(run.active, 0); safeResult(result);
}
// An error rethrown by close is not uncertain if the transport confirms closure.
const refused = fixture({ navigationFails: true, terminated: true, closeThrows: true });
assert.equal((await runControllerBrowserMatrix(refused.options)).observations[0].code, 'TRANSPORT_FAILURE');
// A refusal arriving after successful DOM observations is still a failed cell,
// even when cleanup itself succeeded. Never erase it with closure confirmation.
const lateRefusal = fixture({ closeThrows: true });
const lateResult = await runControllerBrowserMatrix(lateRefusal.options);
assert.equal(lateResult.allExpectedUiStatesObserved, false); assert.equal(lateResult.observedCount, 1);
assert.equal(lateResult.observations[0].code, 'TRANSPORT_FAILURE');
assert.equal(lateResult.observations[0].screenshotState, 'unavailable'); assert.equal(lateRefusal.active, 0);
for (const change of [{ cleanupUncertain: true }, { cleanupUncertain: true, closeThrows: true }]) {
  const run = fixture({ navigationFails: true, ...change });
  await assert.rejects(runControllerBrowserMatrix(run.options), { message: 'CNYOS_UAT_BROWSER_MATRIX_CLEANUP' });
  assert.equal(run.created.length, 1); assert.equal(run.retained.length, 0);
}
const hung = fixture({ navigationFails: true, retentionHangs: true });
const before = performance.now();
const timedOut = await runControllerBrowserMatrix(hung.options);
assert.ok(performance.now() - before >= 4900 && performance.now() - before < 10000);
assert.equal(timedOut.observations[0].screenshotState, 'unavailable'); assert.equal(hung.active, 0);

for (const mutate of [options => { delete options.sessionLeasesByRole.viewer; },
  options => { options.sessionLeasesByRole.viewer = options.sessionLeasesByRole.doctor; },
  options => { options.sessionLeasesByRole.viewer.expires_at = 1; },
  options => { options.sessionLeasesByRole.viewer.access_token = sentinel; },
  options => { options.expectedFeatures = ['core', 'clinical']; },
  options => { options.siteOrigin = POLICY.productionDenylist.netlifyOrigin; },
  options => { options.createOwnedTransport = undefined; },
  options => { const session = options.sessionLeasesByRole.viewer; const claims = JSON.parse(Buffer.from(session.access_token.split('.')[1], 'base64url')); claims.role = 'service_role'; session.access_token = `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.ZmFrZQ`; }
]) {
  const run = fixture(); mutate(run.options);
  await assert.rejects(runControllerBrowserMatrix(run.options), error => {
    assert.match(error.message, /^CNYOS_UAT_BROWSER_MATRIX_[A-Z_]+$/); assert.ok(!error.message.includes(sentinel)); return true;
  });
  assert.equal(run.created.length, 0);
}
const setup = fixture({ setupFails: true });
await assert.rejects(runControllerBrowserMatrix(setup.options), { message: 'CNYOS_UAT_BROWSER_MATRIX_SETUP' });

// Integrate the ACTUAL transport's refusal and closure semantics with the
// matrix. This protocol peer has no socket/server and cannot dispatch a request.
for (const uncertain of [false, true]) {
  const run = fixture();
  let listener, owned, stopped = false;
  const calls = [];
  const emit = (method, params, sessionId) => listener?.({ method, params, sessionId });
  const cdp = {
    onEvent(callback) { listener = callback; return () => { listener = undefined; }; },
    async terminate() { stopped = true; if (uncertain) throw new Error(sentinel); },
    async send(method, params = {}, sessionId) {
      calls.push(method);
      if (method === 'Target.getTargets') return { targetInfos: [] };
      if (method === 'Target.createBrowserContext') return { browserContextId: 'owned-context' };
      if (method === 'Target.createTarget') {
        queueMicrotask(() => emit('Target.attachedToTarget', { sessionId: 'owned-session', waitingForDebugger: true,
          targetInfo: { targetId: 'owned-target', type: 'page', browserContextId: 'owned-context' } }));
        return { targetId: 'owned-target' };
      }
      if (method === 'Page.getFrameTree') return { frameTree: { frame: { id: 'owned-frame', loaderId: 'old-loader', url: 'about:blank' } } };
      if (method === 'Page.navigate') {
        assert.equal(sessionId, 'owned-session');
        queueMicrotask(() => emit('Fetch.requestPaused', { requestId: 'forbidden-request', resourceType: 'Fetch',
          request: { url: `${POLICY.target.netlifyOrigin}/api/account-access`, method: 'POST', postData: '{"action":"status"}' } }, 'owned-session'));
        return { frameId: 'owned-frame', loaderId: 'new-loader' };
      }
      return {};
    }
  };
  run.options.createOwnedTransport = async ({ classifyRequest }) => {
    owned = await createControllerUatBrowserTransport({ cdp, classifyRequest, limits: { operationTimeoutMs: 100, totalTimeoutMs: 4000 } });
    return owned;
  };
  if (uncertain) await assert.rejects(runControllerBrowserMatrix(run.options), { message: 'CNYOS_UAT_BROWSER_MATRIX_CLEANUP' });
  else {
    const result = await runControllerBrowserMatrix(run.options);
    safeResult(result); assert.equal(result.observations[0].code, 'TRANSPORT_FAILURE');
    assert.equal(result.observations[0].screenshotState, 'unavailable');
  }
  assert.equal(stopped, true); assert.equal(owned.getClosureStatus().cleanupConfirmed, !uncertain);
  assert.ok(calls.includes('Fetch.failRequest')); assert.ok(!calls.includes('Fetch.continueRequest'));
  assert.ok(!calls.includes('Page.captureScreenshot')); assert.equal(run.retained.length, 0);
}
console.log('CNYOS UAT browser matrix contract: passed');
