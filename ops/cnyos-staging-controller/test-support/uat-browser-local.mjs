// Optional, explicit LOCAL fixture. This is not a protected-runtime launcher,
// authenticated UAT, an egress-isolation attestation or a browser-version pin.
// It never opens the user's profile, connects to a running browser or supplies
// credentials. Only an owned loopback HTTP recorder is used as page content.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createControllerUatBrowserTransport } from '../scripts/controller-uat-browser-transport.mjs';
import { publishUatEvidenceBytes } from '../scripts/controller-uat-evidence-publication.mjs';

const args = process.argv.slice(2);
assert.ok(args.length === 2 || args.length === 4,
  'explicit --chrome-binary ABSOLUTE_PATH [--evidence-directory ABSOLUTE_DIR] is required');
assert.equal(args[0], '--chrome-binary');
assert.ok(path.isAbsolute(args[1]), 'browser binary path must be absolute');
if (args.length === 4) {
  assert.equal(args[2], '--evidence-directory');
  assert.ok(path.isAbsolute(args[3]), 'evidence directory path must be absolute');
}
const binary = await fs.realpath(args[1]);
assert.ok((await fs.stat(binary)).isFile(), 'browser binary must be a regular file');
const executableMode = await fs.stat(binary);
assert.ok(executableMode.mode & 0o111, 'browser binary must be executable');
const evidenceDirectory = args.length === 4 ? path.resolve(args[3]) : null;
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const opdWorkflowPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'candidate-source/opd-workflow.js');
// Capture the reviewed component exactly once, before starting any browser or
// fixture server. The local page serves these bytes only; it never exposes a
// general filesystem route.
const opdWorkflowBytes = await fs.readFile(opdWorkflowPath);
const opdWorkflowSourceSha256 = createHash('sha256').update(opdWorkflowBytes).digest('hex');
if (evidenceDirectory) {
  assert.equal(evidenceDirectory, args[3], 'evidence directory must be canonical');
  assert.notEqual(evidenceDirectory, repositoryRoot,
    'evidence directory must be outside the repository operational inputs');
  assert.ok(!evidenceDirectory.startsWith(`${repositoryRoot}${path.sep}`),
    'evidence directory must be outside the repository operational inputs');
  const evidenceStat = await fs.lstat(evidenceDirectory);
  assert.ok(evidenceStat.isDirectory() && evidenceStat.uid === process.getuid() &&
    (evidenceStat.mode & 0o7777) === 0o700 && await fs.realpath(evidenceDirectory) === evidenceDirectory,
  'evidence directory must be an owned canonical 0700 directory');
  await assert.rejects(fs.lstat(path.join(evidenceDirectory, 'uat.json')), { code: 'ENOENT' });
}
async function sha256File(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
const browserBinarySha256 = await sha256File(binary);

async function dedicatedPipe() {
  const profile = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'cnyos-browser-fixture-'));
  let child;
  let closed = false;
  let closePromise;
  let nextId = 0;
  let buffered = Buffer.alloc(0);
  const pending = new Map();
  const listeners = new Set();
  let fatal;
  const rejectPending = code => {
    fatal ||= new Error(code);
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(fatal); }
    pending.clear();
  };
  const cdp = {
    send(method, params = {}, sessionId) {
      if (closed || fatal) return Promise.reject(fatal || new Error('LOCAL_CDP_CLOSED'));
      if (pending.size >= 128) return Promise.reject(new Error('LOCAL_CDP_PENDING_LIMIT'));
      const id = ++nextId;
      const data = JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) });
      if (Buffer.byteLength(data) > 4 * 1024 * 1024) return Promise.reject(new Error('LOCAL_CDP_SEND_LIMIT'));
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error('LOCAL_CDP_OPERATION_TIMEOUT'));
        }, 5000);
        pending.set(id, { resolve, reject, timer });
        child.stdio[3].write(`${data}\0`, error => {
          if (error) rejectPending('LOCAL_CDP_WRITE_FAILED');
        });
      });
    },
    onEvent(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    close() { return cdp.terminate(); },
    terminate() {
      closePromise ||= (async () => {
        closed = true;
        rejectPending('LOCAL_CDP_CLOSED');
        if (child?.pid && child.exitCode === null && child.signalCode === null) {
          const exited = once(child, 'exit');
          // detached:true creates this fixture's own process group. Never match
          // names or signal an existing user browser process/group.
          // Graceful disconnect/shutdown can resume a paused request. Never
          // detach CDP or send SIGTERM first; kill only this disposable group.
          try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
          await Promise.race([
            exited,
            new Promise((_, reject) => {
              const timer = setTimeout(() => reject(new Error('LOCAL_BROWSER_EXIT_TIMEOUT')), 6000);
              exited.finally(() => clearTimeout(timer)).catch(() => {});
            })
          ]);
        }
        if (child?.pid && child.exitCode === null && child.signalCode === null) {
          throw new Error('LOCAL_BROWSER_EXIT_UNCONFIRMED');
        }
        if (child?.pid) {
          let absent = false;
          for (let attempt = 0; attempt < 50; attempt += 1) {
            // Managed macOS can reject signal-zero after the group was killed.
            // Require a successful bounded numeric-only process table query;
            // a failed query is uncertainty, never evidence of absence.
            const groups = spawnSync('/bin/ps', ['-axo', 'pgid='], {
              env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, encoding: 'utf8',
              timeout: 1000, maxBuffer: 256 * 1024
            });
            if (groups.error || groups.status !== 0 || !groups.stdout.trim() ||
              groups.stdout.trim().split(/\s+/).some(value => !/^[0-9]+$/.test(value))) {
              throw new Error('LOCAL_BROWSER_GROUP_EXIT_UNCONFIRMED');
            }
            if (!groups.stdout.trim().split(/\s+/).includes(String(child.pid))) { absent = true; break; }
            await delay(100);
          }
          if (!absent) throw new Error('LOCAL_BROWSER_GROUP_EXIT_UNCONFIRMED');
        }
        listeners.clear();
        // Exact mkdtemp-owned disposable profile only, after confirmed process exit.
        await fs.rm(profile, { recursive: true, force: true });
      })();
      return closePromise;
    }
  };
  try {
    child = spawn(binary, [
      '--headless=new', '--remote-debugging-pipe', '--no-startup-window',
      `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
      '--disable-background-networking', '--disable-component-update', '--disable-sync',
      '--disable-default-apps', '--disable-extensions', '--disable-client-side-phishing-detection',
      '--disable-component-extensions-with-background-pages',
      '--disable-breakpad', '--disable-domain-reliability', '--disable-quic',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1',
      '--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication'
    ], {
      env: { PATH: '/usr/bin:/bin', TMPDIR: profile },
      detached: true,
      stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe']
    });
    child.on('error', () => rejectPending('LOCAL_BROWSER_LAUNCH_FAILED'));
    child.on('exit', () => rejectPending('LOCAL_BROWSER_EXITED'));
    child.stdio[3].on('error', () => rejectPending('LOCAL_CDP_PIPE_FAILED'));
    child.stdio[4].on('error', () => rejectPending('LOCAL_CDP_PIPE_FAILED'));
    child.stdio[4].on('data', chunk => {
      if (closed || fatal) return;
      if (buffered.length + chunk.length > 8 * 1024 * 1024) {
        rejectPending('LOCAL_CDP_RECEIVE_LIMIT'); return;
      }
      buffered = Buffer.concat([buffered, chunk]);
      let end;
      while ((end = buffered.indexOf(0)) >= 0) {
        const raw = buffered.subarray(0, end);
        buffered = buffered.subarray(end + 1);
        let message;
        try { message = JSON.parse(raw.toString('utf8')); }
        catch { rejectPending('LOCAL_CDP_INVALID_JSON'); return; }
        if (message.id !== undefined) {
          const item = pending.get(message.id);
          if (!item) continue;
          clearTimeout(item.timer); pending.delete(message.id);
          if (message.error) {
            item.reject(new Error('LOCAL_CDP_COMMAND_FAILED'));
          }
          else item.resolve(message.result);
        } else {
          for (const listener of listeners) {
            try { listener(message); }
            catch { rejectPending('LOCAL_CDP_EVENT_FAILED'); }
          }
        }
      }
    });
    const version = await cdp.send('Browser.getVersion');
    return { cdp, version: version.product };
  } catch (error) { await cdp.close(); throw error; }
}

const received = [];
const crossReceived = [];
const sockets = new Set();
let opdFixtureNavigationCount = 0;
const server = http.createServer((request, response) => {
  received.push(request.url);
  if (request.url === '/redirect') {
    response.writeHead(302, { location: '/denied-redirect' }); response.end(); return;
  }
  if (request.url === '/attachment') {
    response.writeHead(200, { 'content-type': 'text/plain', 'content-disposition': 'attachment; filename="fixture.txt"' });
    response.end('inert fixture'); return;
  }
  if (request.url === '/oversize') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify('x'.repeat(64 * 1024))); return;
  }
  if (request.url === '/chunked-oversize') {
    response.writeHead(200, { 'content-type': 'application/json', 'transfer-encoding': 'chunked' });
    response.flushHeaders(); response.end(JSON.stringify('x'.repeat(64 * 1024))); return;
  }
  if (request.url === '/stalled') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.flushHeaders(); response.write('{'); return;
  }
  if (request.url === '/data') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"fixture":true}'); return;
  }
  if (request.url === '/workflow') {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,"><title>Owned local synthetic workflow</title>
      <main><form id="synthetic-workflow"><label>Label <input id="label" name="label"></label>
      <button id="complete" type="submit">Complete</button></form><output id="phase">initial</output></main>
      <script>
        const form = document.querySelector('#synthetic-workflow');
        const input = document.querySelector('#label');
        const phase = document.querySelector('#phase');
        input.addEventListener('input', () => { phase.textContent = input.value ? 'draft' : 'initial'; });
        form.addEventListener('submit', event => { event.preventDefault(); phase.textContent = 'completed'; });
      </script>`); return;
  }
  if (request.url === '/opd-workflow.js') {
    response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' });
    response.end(opdWorkflowBytes); return;
  }
  if (request.url === '/opd-workflow-fixture') {
    opdFixtureNavigationCount += 1;
    const committedSession = opdFixtureNavigationCount > 1 ? [{
      session_no: 1, treated_at: '2026-09-11T00:00:00.000Z',
      treatment_modalities: ['massage'], treatment_detail: 'synthetic committed session',
      pain_before: 3, pain_after: 1, outcome_summary: 'synthetic complete'
    }] : [];
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(`<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,"><title>Owned local mocked OPD component</title>
      <main id="app"><select id="encounter"><option value="">เลือก Encounter</option><option value="enc-A">A</option><option value="enc-B">B</option></select>
      <form id="opd-history-form"><input id="opd-accident"><input id="opd-surgery"><input id="opd-chronic"><input id="opd-family"><input id="opd-personal"><input id="opd-food"><input id="opd-water"><input id="opd-coffee"><input id="opd-smoking"><input id="opd-alcohol"><input id="opd-urination"><input id="opd-bowel"><input id="opd-sleep"><input id="opd-posture"><input id="opd-emotion"><input id="opd-allergy"><input id="opd-menstruation"><input id="opd-meds"><input id="opd-physical"><button id="history-save" type="submit">save history</button></form>
      <output id="opd-history-status">เลือก Encounter ก่อน</output>
      <form id="opd-session-form"><input name="opd-modality" type="checkbox" value="massage"><input id="opd-pain-before"><input id="opd-pain-after"><textarea id="opd-treatment-detail"></textarea><input id="opd-procedure-referral" type="checkbox"><input id="opd-procedure-detail"><input id="opd-precautions"><input id="opd-outcome"><input id="opd-advice"><button id="session-save" type="submit">save session</button></form>
      <output id="opd-session-list"></output><output id="opd-session-status">เลือก Encounter ก่อน</output>
      <script>window.__opdFixtureCommittedSessions = ${JSON.stringify(committedSession)};</script>
      <script src="/opd-workflow.js"></script></main>`); return;
  }
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end('<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,"><title>Owned local fixture</title><main id="ready">ready</main>');
});
server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
server.on('upgrade', (request, socket) => { received.push(`UPGRADE:${request.url}`); socket.destroy(); });
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = `http://127.0.0.1:${server.address().port}`;
const crossServer = http.createServer((request, response) => {
  crossReceived.push({ method: request.method, path: request.url,
    preflightMethod: request.headers['access-control-request-method'],
    preflightHeaders: request.headers['access-control-request-headers'] });
  const headers = { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'GET, POST',
    'access-control-allow-headers': 'x-fixture, content-type' };
  if (request.method === 'OPTIONS') {
    response.writeHead(204, headers); response.end(); return;
  }
  response.writeHead(200, { ...headers, 'content-type': 'application/json' });
  response.end('{"crossFixture":true}');
});
crossServer.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
crossServer.listen(0, '127.0.0.1');
await once(crossServer, 'listening');
const crossOrigin = `http://127.0.0.1:${crossServer.address().port}`;

const classifyRequest = request => {
  const parsed = new URL(request.url);
  if (parsed.origin === crossOrigin && parsed.pathname === '/cross-data' && !parsed.search && !parsed.hash) {
    if (request.method === 'OPTIONS' && ['Preflight', 'XHR', 'Fetch'].includes(request.resourceType) &&
      request.accessControlRequestMethod === 'POST' &&
      JSON.stringify(request.accessControlRequestHeaders) === '["content-type","x-fixture"]' && !request.postData) {
      return Object.freeze({ allowed: true, responseKind: 'empty', maxResponseBytes: 1 });
    }
    if (request.method === 'POST' && ['Fetch', 'XHR'].includes(request.resourceType) && request.postData === '{"inert":true}') {
      return Object.freeze({ allowed: true, responseKind: 'json', maxResponseBytes: 16384 });
    }
    return Object.freeze({ allowed: false });
  }
  const allowed = parsed.origin === origin && request.method === 'GET' && !request.postData &&
    !parsed.search && !parsed.hash && ['/page', '/workflow', '/opd-workflow-fixture', '/opd-workflow.js', '/data', '/redirect', '/attachment', '/oversize', '/chunked-oversize', '/stalled'].includes(parsed.pathname);
  return Object.freeze(allowed ? {
    allowed: true,
    responseKind: parsed.pathname === '/opd-workflow.js' ? 'script' : ['/page', '/workflow', '/opd-workflow-fixture'].includes(parsed.pathname) ? 'document' : 'json',
    maxResponseBytes: parsed.pathname === '/opd-workflow.js' ? 256 * 1024 : 16384
  } : { allowed: false });
};

let observedVersion;
let cases = 0;
const confirmedRefusal = /^(?:CNYOS_UAT_BROWSER_(?:REQUEST_DENIED|RESPONSE_STATUS|RESPONSE_ENCODING_OR_DOWNLOAD|RESPONSE_SIZE|OPERATION_TIMEOUT|GLOBAL_TIMEOUT|TARGET_DENIED|UNSUPPORTED_ACTIVITY)|LOCAL_CDP_CLOSED)$/;
async function navigateReady(transport) {
  const navigation = await transport.navigateAndWait(`${origin}/page`);
  assert.equal(navigation.loaded, true);
  assert.equal(navigation.url, `${origin}/page`);
  await transport.waitForIdle();
  assert.equal(await transport.evaluate('document.getElementById("ready")?.textContent'), 'ready');
  transport.assertHealthy();
}
async function localCase(operation, expectedRefusal = false) {
  received.length = 0;
  crossReceived.length = 0;
  const { cdp, version } = await dedicatedPipe();
  observedVersion ||= version;
  assert.equal(version, observedVersion);
  let transport;
  let outcome;
  try {
    transport = await createControllerUatBrowserTransport({ cdp, classifyRequest,
      limits: { operationTimeoutMs: 3000, totalTimeoutMs: 20000 } });
    assert.deepEqual(transport.getClosureStatus(), { cleanupConfirmed: false });
    outcome = await operation(transport, cdp);
    cases += 1;
  } finally {
    try {
      if (transport) {
        try { await transport.close(); }
        catch (error) { if (!expectedRefusal || !confirmedRefusal.test(error.message)) throw error; }
        assert.deepEqual(transport.getClosureStatus(), { cleanupConfirmed: true });
      }
    }
    finally { await cdp.close(); }
    for (const socket of sockets) socket.destroy();
  }
  return outcome;
}

// Runtime/database adapter for the checked-in OPD component. It is installed
// before document scripts run, and exposes only in-memory queues/counters to
// the test page. It has no credentials, network implementation, or provider.
const opdFixtureInitScript = `(() => {
  const state = { reads: [], writes: [], pendingWrites: [], events: [], next: 0, sessionCalls: 0 };
  const pending = (kind, table, encounter) => {
    const id = ++state.next;
    let resolve;
    const promise = new Promise(yes => { resolve = yes; });
    state.reads.push({ id, kind, table, encounter, resolve });
    return promise;
  };
  const query = table => {
    let encounter = null;
    const chain = {
      select() { return chain; },
      eq(column, value) { if (column === 'encounter_id') encounter = value; return chain; },
      order() { return pending('read', table, encounter).then(data => ({ data, error: null })); },
      maybeSingle() { return pending('read', table, encounter).then(data => ({ data, error: null })); },
      upsert(payload) { state.writes.push({ kind: 'upsert', table, payload }); let resolve; const promise = new Promise(yes => { resolve = yes; }); state.pendingWrites.push({ resolve, result: { data: payload, error: null } }); return promise; }
    };
    return chain;
  };
  const db = { from: query, rpc(name, args) {
    state.writes.push({ kind: 'rpc', name, args });
    if (name === 'create_clinical_treatment_session') {
      let resolve; const promise = new Promise(yes => { resolve = yes; });
      state.pendingWrites.push({ resolve, result: { data: null, error: null } }); return promise;
    }
    return Promise.resolve({ data: null, error: null });
  }, auth: {} };
  const session = { user: { id: '00000000-0000-4000-8000-000000000001' } };
  window.__opdFixture = Object.assign(state, {
    resolveRead(id, data) { const item = state.reads.find(x => x.id === id); if (!item) throw new Error('unknown read'); item.resolve(data); },
    resolveWrite(index = 0) { const item = state.pendingWrites.splice(index, 1)[0]; if (!item) throw new Error('unknown write'); item.resolve(item.result); },
  });
  window.addEventListener('chananya:clinical-data-changed', event => state.events.push({ name: 'chananya:clinical-data-changed', detail: event.detail }));
  window.ChananyaRuntime = { getDb: () => db, getSession: async () => { state.sessionCalls += 1; return session; } };
})()`;
async function navigateOpd(transport) {
  await transport.addInitScript(opdFixtureInitScript);
  const navigation = await transport.navigateAndWait(`${origin}/opd-workflow-fixture`);
  assert.equal(navigation.loaded, true);
  assert.equal(navigation.url, `${origin}/opd-workflow-fixture`);
  await transport.waitForIdle();
  transport.assertHealthy();
}
async function waitForOpdReads(transport, count) {
  for (let i = 0; i < 60; i += 1) {
    if (await transport.evaluate(`window.__opdFixture.reads.length >= ${count}`)) return;
    await delay(25);
  }
  throw new Error('LOCAL_OPD_FIXTURE_READ_TIMEOUT');
}

let syntheticWorkflowEvidence;
let opdComponentEvidence = null;
const opdComponentObservations = [];
try {
  syntheticWorkflowEvidence = await localCase(async transport => {
    const navigation = await transport.navigateAndWait(`${origin}/workflow`);
    assert.equal(navigation.loaded, true);
    assert.equal(navigation.url, `${origin}/workflow`);
    assert.equal(typeof navigation.frameId, 'string');
    assert.equal(typeof navigation.loaderId, 'string');
    await transport.waitForIdle();
    const initial = await transport.evaluate(`({ phase: document.querySelector('#phase')?.textContent,
      value: document.querySelector('#label')?.value, button: document.querySelector('#complete')?.textContent })`);
    assert.deepEqual(initial, { phase: 'initial', value: '', button: 'Complete' });
    const draft = await transport.evaluate(`(() => {
      const input = document.querySelector('#label');
      input.value = 'local-synthetic';
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return { phase: document.querySelector('#phase')?.textContent, value: input.value };
    })()`);
    assert.deepEqual(draft, { phase: 'draft', value: 'local-synthetic' });
    const completed = await transport.evaluate(`(() => {
      document.querySelector('#complete').click();
      return { phase: document.querySelector('#phase')?.textContent,
        value: document.querySelector('#label')?.value };
    })()`);
    assert.deepEqual(completed, { phase: 'completed', value: 'local-synthetic' });
    await transport.waitForIdle();
    transport.assertHealthy();
    assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 0 });
    assert.deepEqual(received, ['/workflow']);
    assert.deepEqual(crossReceived, []);
    const screenshot = await transport.captureScreenshot();
    assert.equal(screenshot.format, 'png');
    assert.equal(screenshot.width, 390); assert.equal(screenshot.height, 844);
    assert.ok(screenshot.byteLength > 57 && screenshot.byteLength <= 2 * 1024 * 1024);
    assert.equal(Buffer.from(screenshot.dataBase64, 'base64').length, screenshot.byteLength);
    return Object.freeze({ initial, draft, completed, screenshot, diagnostics: transport.getPageDiagnostics() });
  });
  opdComponentEvidence = await localCase(async transport => {
    await navigateOpd(transport);
    const select = async encounter => transport.evaluate(`(() => { const e = document.querySelector('#encounter'); e.value = ${JSON.stringify(encounter)}; e.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
    const reads = () => transport.evaluate('window.__opdFixture.reads.map(({id,table,encounter}) => ({id,table,encounter}))');
    await select('enc-A'); await waitForOpdReads(transport, 2);
    const aReads = await reads();
    await select('enc-B'); await waitForOpdReads(transport, 4);
    const allReads = await reads();
    const bReads = allReads.slice(-2);
    for (const item of bReads) await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${item.table === 'ttm_opd_histories' ? JSON.stringify({ chronic_diseases: 'B-draft', water_glasses_per_day: 4 }) : '[]'})`);
    for (const item of aReads) await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${item.table === 'ttm_opd_histories' ? JSON.stringify({ chronic_diseases: 'A-stale', water_glasses_per_day: 1 }) : '[]'})`);
    await transport.waitForIdle();
    assert.deepEqual(await transport.evaluate('({ encounter: document.querySelector("#encounter").value, chronic: document.querySelector("#opd-chronic").value, water: document.querySelector("#opd-water").value })'), { encounter: 'enc-B', chronic: 'B-draft', water: '4' });
    assert.equal(await transport.evaluate('window.__opdFixture.writes.length'), 0);
    transport.assertHealthy();
    const screenshot = await transport.captureScreenshot();
    assert.equal(screenshot.format, 'png');
    assert.deepEqual(received, ['/opd-workflow-fixture', '/opd-workflow.js']);
    assert.deepEqual(crossReceived, []);
    assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 0 });
    return Object.freeze({ scenario: 'out_of_order_history_read', reads: allReads.length, writes: 0,
      displayed: await transport.evaluate('({ encounter: document.querySelector("#encounter").value, chronic: document.querySelector("#opd-chronic").value, water: document.querySelector("#opd-water").value })'), screenshot,
      diagnostics: transport.getPageDiagnostics() });
  });
  opdComponentObservations.push(opdComponentEvidence);
  opdComponentObservations.push(await localCase(async transport => {
    await navigateOpd(transport);
    await transport.evaluate(`(() => { const e = document.querySelector('#encounter'); e.value = 'enc-A'; e.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await waitForOpdReads(transport, 2);
    for (const item of await transport.evaluate('window.__opdFixture.reads.map(({id,table}) => ({id,table}))')) await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${item.table === 'ttm_opd_histories' ? '{}' : '[]'})`);
    await transport.evaluate(`(() => { for (const [id, value] of [['opd-chronic', 'synthetic chronic'], ['opd-water', '2']]) { const input = document.querySelector('#' + id); input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true })); } document.querySelector('#opd-history-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); document.querySelector('#opd-history-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); })()`);
    await waitForOpdReads(transport, 3);
    await transport.evaluate('window.__opdFixture.resolveRead(3, {})');
    for (let i = 0; i < 60; i += 1) { if (await transport.evaluate('window.__opdFixture.pendingWrites.length === 1')) break; await delay(25); }
    assert.equal(await transport.evaluate('window.__opdFixture.writes.filter(x => x.kind === "upsert").length'), 1);
    const payload = await transport.evaluate('window.__opdFixture.writes[0].payload');
    assert.equal(payload.encounter_id, 'enc-A'); assert.equal(payload.chronic_diseases, 'synthetic chronic'); assert.equal(payload.water_glasses_per_day, 2);
    await transport.evaluate('window.__opdFixture.resolveWrite(0)'); await transport.waitForIdle();
    assert.match(await transport.evaluate('document.querySelector("#opd-history-status").textContent'), /บันทึก OPD History/);
    assert.deepEqual(await transport.evaluate('window.__opdFixture.events.filter(x => x.name === "chananya:clinical-data-changed")[0].detail'), { encounterId: 'enc-A', source: 'opd-history' });
    transport.assertHealthy();
    const screenshot = await transport.captureScreenshot();
    assert.deepEqual(received, ['/opd-workflow-fixture', '/opd-workflow.js']);
    assert.deepEqual(crossReceived, []); assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 0 });
    return Object.freeze({ scenario: 'history_duplicate_submit_and_payload', writes: 1,
      reads: await transport.evaluate('window.__opdFixture.reads.length'),
      payload: { encounter_id: payload.encounter_id, chronic_diseases: payload.chronic_diseases, water_glasses_per_day: payload.water_glasses_per_day },
      event: await transport.evaluate('window.__opdFixture.events.filter(x => x.name === "chananya:clinical-data-changed")[0].detail'), screenshot,
      diagnostics: transport.getPageDiagnostics() });
  }));
  opdComponentObservations.push(await localCase(async transport => {
    await navigateOpd(transport);
    const select = async encounter => transport.evaluate(`(() => { const e = document.querySelector('#encounter'); e.value = ${JSON.stringify(encounter)}; e.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await select('enc-A'); await waitForOpdReads(transport, 2);
    for (const item of await transport.evaluate('window.__opdFixture.reads.map(({id,table}) => ({id,table}))')) {
      await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${item.table === 'ttm_opd_histories' ? '{}' : '[]'})`);
    }
    await transport.evaluate(`(() => { const input = document.querySelector('#opd-treatment-detail'); input.value = 'synthetic pending session'; input.dispatchEvent(new Event('input', { bubbles: true })); document.querySelector('#opd-session-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); })()`);
    for (let i = 0; i < 60; i += 1) { if (await transport.evaluate('window.__opdFixture.pendingWrites.length === 1')) break; await delay(25); }
    const before = await transport.evaluate(`({
      marker: window.sessionStorage.getItem('chananya.opd.v1.session.uncertain'),
      markerKey: 'chananya.opd.v1.session.uncertain',
      markerIsUuid: /^[-0-9a-f]{36}$/i.test(window.sessionStorage.getItem('chananya.opd.v1.session.uncertain') || ''),
      storageKeys: Object.keys(window.sessionStorage),
      storageLength: window.sessionStorage.length,
      rpcDispatches: window.__opdFixture.writes.filter(x => x.kind === 'rpc').length,
      draft: document.querySelector('#opd-treatment-detail').value
    })`);
    assert.equal(before.markerIsUuid, true);
    assert.deepEqual(before.storageKeys, [before.markerKey]);
    assert.equal(before.storageLength, 1);
    assert.equal(before.rpcDispatches, 1);
    const reload = await transport.navigateAndWait(`${origin}/opd-workflow-fixture`);
    assert.equal(reload.loaded, true);
    assert.equal(reload.url, `${origin}/opd-workflow-fixture`);
    await transport.waitForIdle();
    await select('enc-A'); await waitForOpdReads(transport, 2);
    for (const item of await transport.evaluate('window.__opdFixture.reads.map(({id,table}) => ({id,table}))')) {
      const value = item.table === 'ttm_opd_histories' ? '{}' : 'window.__opdFixtureCommittedSessions';
      await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${value})`);
    }
    await transport.waitForIdle();
    const afterReads = await transport.evaluate(`({
      marker: window.sessionStorage.getItem('chananya.opd.v1.session.uncertain'),
      markerIsUuid: /^[-0-9a-f]{36}$/i.test(window.sessionStorage.getItem('chananya.opd.v1.session.uncertain') || ''),
      storageKeys: Object.keys(window.sessionStorage),
      storageLength: window.sessionStorage.length,
      encounter: document.querySelector('#encounter').value,
      list: document.querySelector('#opd-session-list').textContent,
      draft: document.querySelector('#opd-treatment-detail').value,
      status: document.querySelector('#opd-session-status').textContent,
      rpcDispatches: window.__opdFixture.writes.filter(x => x.kind === 'rpc').length
    })`);
    assert.equal(afterReads.marker, before.marker);
    assert.equal(afterReads.markerIsUuid, true);
    assert.deepEqual(afterReads.storageKeys, [before.markerKey]);
    assert.equal(afterReads.storageLength, 1);
    assert.equal(afterReads.encounter, 'enc-A');
    assert.match(afterReads.list, /synthetic committed session/);
    assert.equal(afterReads.draft, '');
    assert.match(afterReads.status, /ระงับ/);
    assert.match(afterReads.status, /ไม่แน่ชัด/);
    assert.equal(afterReads.rpcDispatches, 0);
    await transport.evaluate(`(() => { const input = document.querySelector('#opd-treatment-detail'); input.value = 'new draft after reload'; input.dispatchEvent(new Event('input', { bubbles: true })); document.querySelector('#opd-session-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); })()`);
    await transport.waitForIdle();
    const afterSubmit = await transport.evaluate(`({
      marker: window.sessionStorage.getItem('chananya.opd.v1.session.uncertain'),
      markerIsUuid: /^[-0-9a-f]{36}$/i.test(window.sessionStorage.getItem('chananya.opd.v1.session.uncertain') || ''),
      storageKeys: Object.keys(window.sessionStorage),
      storageLength: window.sessionStorage.length,
      draft: document.querySelector('#opd-treatment-detail').value,
      status: document.querySelector('#opd-session-status').textContent,
      rpcDispatches: window.__opdFixture.writes.filter(x => x.kind === 'rpc').length
    })`);
    assert.equal(afterSubmit.marker, before.marker);
    assert.equal(afterSubmit.markerIsUuid, true);
    assert.deepEqual(afterSubmit.storageKeys, [before.markerKey]);
    assert.equal(afterSubmit.storageLength, 1);
    assert.equal(afterSubmit.draft, 'new draft after reload');
    assert.match(afterSubmit.status, /ระงับ/);
    assert.match(afterSubmit.status, /ไม่แน่ชัด/);
    assert.equal(afterSubmit.rpcDispatches, 0);
    transport.assertHealthy();
    assert.deepEqual(received, ['/opd-workflow-fixture', '/opd-workflow.js', '/opd-workflow-fixture', '/opd-workflow.js']);
    assert.deepEqual(crossReceived, []);
    assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 0 });
    const screenshot = await transport.captureScreenshot();
    return Object.freeze({ scenario: 'reload_preserves_uncertain_session_marker_without_replay',
      before: { markerKey: before.markerKey, markerIsUuid: before.markerIsUuid, rpcDispatches: before.rpcDispatches },
      afterReads: { markerPreserved: afterReads.marker === before.marker, encounter: afterReads.encounter,
        committedSessionVisible: /synthetic committed session/.test(afterReads.list), draftRestored: afterReads.draft !== '', rpcDispatches: afterReads.rpcDispatches },
      afterSubmit: { markerPreserved: afterSubmit.marker === before.marker, draftRetained: afterSubmit.draft === 'new draft after reload', warning: /ระงับ/.test(afterSubmit.status) && /ไม่แน่ชัด/.test(afterSubmit.status), rpcDispatches: afterSubmit.rpcDispatches },
      navigations: 2, fixedAssetReads: received.filter(item => item === '/opd-workflow-fixture' || item === '/opd-workflow.js').length,
      screenshot, diagnostics: transport.getPageDiagnostics() });
  }));
  opdComponentObservations.push(await localCase(async transport => {
    await navigateOpd(transport);
    const select = async encounter => transport.evaluate(`(() => { const e = document.querySelector('#encounter'); e.value = ${JSON.stringify(encounter)}; e.dispatchEvent(new Event('change', { bubbles: true })); })()`);
    await select('enc-A'); await waitForOpdReads(transport, 2);
    for (const item of await transport.evaluate('window.__opdFixture.reads.map(({id,table}) => ({id,table}))')) await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${item.table === 'ttm_opd_histories' ? '{}' : '[]'})`);
    await transport.evaluate(`(() => { const input = document.querySelector('#opd-treatment-detail'); input.value = 'A pending session'; input.dispatchEvent(new Event('input', { bubbles: true })); document.querySelector('#opd-session-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); })()`);
    for (let i = 0; i < 60; i += 1) { if (await transport.evaluate('window.__opdFixture.pendingWrites.length === 1')) break; await delay(25); }
    await select('enc-B'); await waitForOpdReads(transport, 4);
    for (const item of await transport.evaluate('window.__opdFixture.reads.slice(-2).map(({id,table}) => ({id,table}))')) await transport.evaluate(`window.__opdFixture.resolveRead(${item.id}, ${item.table === 'ttm_opd_histories' ? '{}' : '[]'})`);
    await transport.evaluate(`(() => { const input = document.querySelector('#opd-treatment-detail'); input.value = 'B draft must survive'; input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    await transport.evaluate('window.__opdFixture.resolveWrite(0)'); await transport.waitForIdle();
    assert.deepEqual(await transport.evaluate('({ encounter: document.querySelector("#encounter").value, draft: document.querySelector("#opd-treatment-detail").value })'), { encounter: 'enc-B', draft: 'B draft must survive' });
    assert.equal(await transport.evaluate('window.__opdFixture.writes.filter(x => x.kind === "rpc").length'), 1);
    transport.assertHealthy();
    const screenshot = await transport.captureScreenshot();
    assert.deepEqual(received, ['/opd-workflow-fixture', '/opd-workflow.js']);
    assert.deepEqual(crossReceived, []); assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 0 });
    return Object.freeze({ scenario: 'pending_session_does_not_erase_new_encounter_draft', writes: 1,
      reads: await transport.evaluate('window.__opdFixture.reads.length'),
      displayed: await transport.evaluate('({ encounter: document.querySelector("#encounter").value, draft: document.querySelector("#opd-treatment-detail").value })'), screenshot,
      diagnostics: transport.getPageDiagnostics() });
  }));
  await localCase(async (transport, cdp) => {
    await navigateReady(transport, cdp);
    assert.equal(await transport.evaluate('fetch("/data").then(r => r.json()).then(v => v.fixture)'), true);
    assert.equal(await transport.evaluate(`fetch(${JSON.stringify(`${crossOrigin}/cross-data`)}, {
      method:"POST", headers:{"content-type":"application/json","x-fixture":"inert"}, body:'{"inert":true}'
    }).then(r => r.json()).then(v => v.crossFixture)`), true);
    await transport.waitForIdle();
    transport.assertHealthy();
    assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 0 });
    // A caught application error is counted without retaining its raw payload;
    // the healthy transport can capture the failure page before owned shutdown.
    await transport.evaluate('console.error("INERT_LOCAL_ERROR_PAYLOAD"); true');
    assert.deepEqual(transport.getPageDiagnostics(), { exceptionCount: 0, consoleErrorCount: 1 });
    const screenshot = await transport.captureScreenshot();
    assert.equal(screenshot.format, 'png');
    assert.equal(screenshot.width, 390); assert.equal(screenshot.height, 844);
    assert.ok(screenshot.byteLength > 57 && screenshot.byteLength <= 2 * 1024 * 1024);
    assert.equal(Buffer.from(screenshot.dataBase64, 'base64').length, screenshot.byteLength);
    assert.deepEqual(received, ['/page', '/data']);
    assert.deepEqual(crossReceived, [
      { method: 'OPTIONS', path: '/cross-data', preflightMethod: 'POST', preflightHeaders: 'content-type,x-fixture' },
      { method: 'POST', path: '/cross-data', preflightMethod: undefined, preflightHeaders: undefined }
    ]);
  });
  for (const requestPath of ['/denied', '/redirect', '/attachment', '/oversize', '/chunked-oversize', '/stalled']) {
    await localCase(async (transport, cdp) => {
      await navigateReady(transport, cdp);
      await assert.rejects(async () => {
        await transport.evaluate(`fetch(${JSON.stringify(requestPath)}).then(r => r.text())`);
        await transport.waitForIdle();
        transport.assertHealthy();
      }, error => confirmedRefusal.test(error.message));
      try { await transport.close(); }
      catch (error) { assert.match(error.message, confirmedRefusal); }
      assert.deepEqual(received, requestPath === '/denied' ? ['/page'] : ['/page', requestPath]);
      return true;
    }, true);
  }
  for (const { expression, directive } of [
    { expression: 'window.open("/denied-popup")' },
    { expression: 'new Worker("/denied-worker")', directive: 'worker-src' },
    { expression: 'await navigator.serviceWorker.register("/denied-service-worker")', directive: 'worker-src' },
    { expression: 'new WebSocket(location.origin.replace("http:", "ws:") + "/denied-websocket")' },
    { expression: 'document.body.appendChild(Object.assign(document.createElement("iframe"), {src:"/denied-frame"}))', directive: 'frame-src' }
  ]) {
    await localCase(async (transport, cdp) => {
      await navigateReady(transport, cdp);
      try {
        const observed = await transport.evaluate(`(async () => {
          const violations = [];
          document.addEventListener('securitypolicyviolation', event => violations.push(event.effectiveDirective));
          let outcome = 'constructed';
          try { ${expression}; }
          catch (error) { if (error.name !== 'SecurityError') throw error; outcome = 'SecurityError'; }
          await new Promise(resolve => setTimeout(resolve, 100));
          return { attempted: true, outcome, violations };
        })()`);
        await transport.waitForIdle();
        transport.assertHealthy();
        assert.ok(directive, 'popup and WebSocket must trigger transport refusal');
        assert.equal(observed.attempted, true);
        assert.ok(['constructed', 'SecurityError'].includes(observed.outcome));
        assert.ok(observed.violations.includes(directive), 'CSP overlay denial must be observed, not inferred');
      } catch (error) { assert.match(error.message, confirmedRefusal); }
      // Close first so late dispatch cannot evade the local recorder assertion.
      try { await transport.close(); }
      catch (error) { assert.match(error.message, confirmedRefusal); }
      assert.deepEqual(received, ['/page']);
      return true;
    }, true);
  }
} finally {
  for (const socket of sockets) socket.destroy();
  const closedServers = [once(server, 'close'), once(crossServer, 'close')];
  server.close();
  crossServer.close();
  await Promise.all(closedServers);
}

let publishedEvidence = null;
if (evidenceDirectory && syntheticWorkflowEvidence) {
    const evidence = Buffer.from(JSON.stringify({
      evidenceType: 'local_synthetic_browser_workflow',
      browser: observedVersion, browserBinarySha256,
      checkedInApplicationTested: false, credentialFree: true, localLoopbackOnlyContent: true,
      authenticatedUatComplete: false, independentSecurityApproval: false,
      productionAuthorization: false, operatingSystemEgressIsolationVerified: false,
      pinnedRuntimeVerified: false, workflow: {
        observations: [syntheticWorkflowEvidence.initial, syntheticWorkflowEvidence.draft,
          syntheticWorkflowEvidence.completed],
        diagnostics: syntheticWorkflowEvidence.diagnostics,
        screenshot: syntheticWorkflowEvidence.screenshot
      }, opdComponent: opdComponentEvidence ? {
        evidenceType: 'local_mocked_opd_component', component: 'opd-workflow.js',
        sourcePath: 'opd-workflow.js', sourceSha256: opdWorkflowSourceSha256,
        fixture: 'inline synthetic OPD DOM + in-memory mocked runtime/database',
        checkedInComponentTested: true, appIntegrationComplete: false,
        credentialFree: true, providerCalls: false,
        observations: opdComponentObservations, diagnostics: opdComponentEvidence.diagnostics,
        screenshot: opdComponentEvidence.screenshot
      } : null
    }) + '\n');
    publishedEvidence = await publishUatEvidenceBytes({ directory: evidenceDirectory, bytes: evidence,
      expectedSha256: createHash('sha256').update(evidence).digest('hex') });
}
const result = {
  kind: 'cnyos_local_browser_transport_fixture', cases, browser: observedVersion,
  credentialFree: true, localLoopbackOnlyContent: true,
  pinnedRuntimeVerified: false, operatingSystemEgressIsolationVerified: false,
  authenticatedUatComplete: false, independentSecurityApproval: false,
  productionAuthorization: false
};
if (publishedEvidence) Object.assign(result, {
  evidenceType: 'local_synthetic_browser_workflow', checkedInApplicationTested: false,
  ...(opdComponentEvidence ? { checkedInComponentTested: true, component: 'opd-workflow.js',
    componentSourceSha256: opdWorkflowSourceSha256, appIntegrationComplete: false } : {}),
  publicationPath: publishedEvidence.path, publicationSha256: publishedEvidence.sha256
});
console.log(JSON.stringify(result));
