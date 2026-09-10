// Optional, explicit LOCAL fixture. This is not a protected-runtime launcher,
// authenticated UAT, an egress-isolation attestation or a browser-version pin.
// It never opens the user's profile, connects to a running browser or supplies
// credentials. Only an owned loopback HTTP recorder is used as page content.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createControllerUatBrowserTransport } from '../scripts/controller-uat-browser-transport.mjs';

const args = process.argv.slice(2);
assert.equal(args.length, 2, 'explicit --chrome-binary ABSOLUTE_PATH is required');
assert.equal(args[0], '--chrome-binary');
assert.ok(path.isAbsolute(args[1]), 'browser binary path must be absolute');
const binary = await fs.realpath(args[1]);
assert.ok((await fs.stat(binary)).isFile(), 'browser binary must be a regular file');
const executableMode = await fs.stat(binary);
assert.ok(executableMode.mode & 0o111, 'browser binary must be executable');

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
    !parsed.search && !parsed.hash && ['/page', '/data', '/redirect', '/attachment', '/oversize', '/chunked-oversize', '/stalled'].includes(parsed.pathname);
  return Object.freeze(allowed ? {
    allowed: true,
    responseKind: parsed.pathname === '/page' ? 'document' : 'json',
    maxResponseBytes: 16384
  } : { allowed: false });
};

let observedVersion;
let cases = 0;
const confirmedRefusal = /^(?:CNYOS_UAT_BROWSER_(?:REQUEST_DENIED|RESPONSE_STATUS|RESPONSE_ENCODING_OR_DOWNLOAD|RESPONSE_SIZE|OPERATION_TIMEOUT|GLOBAL_TIMEOUT|TARGET_DENIED|UNSUPPORTED_ACTIVITY)|LOCAL_CDP_CLOSED)$/;
async function navigateReady(transport, cdp) {
  // navigate() dispatches only. Pending-request idle is not a DOM-ready signal.
  // Bind a real frame navigation to this exact local URL, then its load event.
  let resolveLoaded, timer, committed = false;
  const loaded = new Promise((resolve, reject) => {
    resolveLoaded = resolve;
    timer = setTimeout(() => reject(new Error('LOCAL_PAGE_LOAD_TIMEOUT')), 3000);
  });
  loaded.catch(() => {});
  const unsubscribe = cdp.onEvent(event => {
    if (event.sessionId !== transport.sessionId) return;
    if (event.method === 'Page.frameNavigated' && event.params.frame.url === `${origin}/page`) committed = true;
    if (committed && event.method === 'Page.loadEventFired') resolveLoaded();
  });
  try {
    await transport.navigate(`${origin}/page`);
    await loaded;
    await transport.waitForIdle();
    assert.equal(await transport.evaluate('document.getElementById("ready")?.textContent'), 'ready');
    transport.assertHealthy();
  } finally { clearTimeout(timer); unsubscribe(); }
}
async function localCase(operation, expectedRefusal = false) {
  received.length = 0;
  crossReceived.length = 0;
  const { cdp, version } = await dedicatedPipe();
  observedVersion ||= version;
  assert.equal(version, observedVersion);
  let transport;
  try {
    transport = await createControllerUatBrowserTransport({ cdp, classifyRequest,
      limits: { operationTimeoutMs: 3000, totalTimeoutMs: 20000 } });
    await operation(transport, cdp);
    cases += 1;
  } finally {
    try {
      if (transport) {
        try { await transport.close(); }
        catch (error) { if (!expectedRefusal || !confirmedRefusal.test(error.message)) throw error; }
      }
    }
    finally { await cdp.close(); }
    for (const socket of sockets) socket.destroy();
  }
}

try {
  await localCase(async (transport, cdp) => {
    await navigateReady(transport, cdp);
    assert.equal(await transport.evaluate('fetch("/data").then(r => r.json()).then(v => v.fixture)'), true);
    assert.equal(await transport.evaluate(`fetch(${JSON.stringify(`${crossOrigin}/cross-data`)}, {
      method:"POST", headers:{"content-type":"application/json","x-fixture":"inert"}, body:'{"inert":true}'
    }).then(r => r.json()).then(v => v.crossFixture)`), true);
    await transport.waitForIdle();
    transport.assertHealthy();
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
  console.log(JSON.stringify({
    kind: 'cnyos_local_browser_transport_fixture', cases, browser: observedVersion,
    credentialFree: true, localLoopbackOnlyContent: true,
    pinnedRuntimeVerified: false, operatingSystemEgressIsolationVerified: false,
    authenticatedUatComplete: false, independentSecurityApproval: false,
    productionAuthorization: false
  }));
} finally {
  for (const socket of sockets) socket.destroy();
  const closedServers = [once(server, 'close'), once(crossServer, 'close')];
  server.close();
  crossServer.close();
  await Promise.all(closedServers);
}
