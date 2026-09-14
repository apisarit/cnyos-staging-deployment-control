import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { spawn } from 'node:child_process';
import path from 'node:path';

export const LIMITS = Object.freeze({
  bodyBytes: 16 * 1024,
  tokenBytes: 16 * 1024,
  adapterTimeoutMs: 30_000,
  journalLockMs: 2_000,
});

const ISSUER = 'https://token.actions.githubusercontent.com';
const JWKS_URL = `${ISSUER}/.well-known/jwks`;
const AUDIENCE = 'cnyos-vps-staging-broker';
const CONTROLLER_REPOSITORY = 'apisarit/cnyos-staging-deployment-control';
const CONTROLLER_REPOSITORY_ID = 1362863285;
const CONTROLLER_ACTOR = 'apisarit';
const CONTROLLER_ACTOR_ID = 216305243;
const CONTROLLER_REF = 'refs/heads/main';
const CONTROLLER_WORKFLOW = 'Admit VPS staging release';
const CONTROLLER_WORKFLOW_FILE = 'admit-vps-staging-release.yml';
const PRODUCER_REPOSITORY = 'apisarit/chananya-clinical-wellness-os';
const PRODUCER_REF = 'refs/heads/main';
const PRODUCER_WORKFLOW = 'deploy-vps-staging.yml';

export class BrokerError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function base64urlDecode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new BrokerError('OIDC_TOKEN_INVALID');
  return Buffer.from(value, 'base64url');
}

function parseJson(value, code) {
  try { return JSON.parse(value); } catch { throw new BrokerError(code); }
}

function exactString(value, pattern, code) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new BrokerError(code);
  return value;
}

function positiveInt(value, code) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new BrokerError(code);
  return value;
}

function exactKeys(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) throw new BrokerError(code);
  return value;
}

function sha256(value) { return /^[0-9a-f]{64}$/.test(value); }

export function validateAdmissionRequest(body, headerRequestId) {
  exactKeys(body, ['schema_version', 'request_id', 'environment', 'controller', 'producer', 'candidate'], 'REQUEST_INVALID');
  if (body.schema_version !== 1 || body.environment !== 'staging') throw new BrokerError('REQUEST_SCOPE_INVALID');
  const requestId = exactString(body.request_id, /^[1-9][0-9]*\.[1-9][0-9]*\.[0-9a-f]{40}$/, 'REQUEST_ID_INVALID');
  if (headerRequestId !== requestId) throw new BrokerError('REQUEST_ID_MISMATCH');
  const c = exactKeys(body.controller, ['repository', 'repository_id', 'ref', 'ref_protected', 'workflow', 'workflow_ref', 'workflow_sha', 'run_id', 'run_attempt', 'actor', 'actor_id', 'triggering_actor'], 'CONTROLLER_BINDING_INVALID');
  if (c.repository !== CONTROLLER_REPOSITORY || c.ref !== CONTROLLER_REF ||
      c.workflow !== CONTROLLER_WORKFLOW) throw new BrokerError('CONTROLLER_BINDING_INVALID');
  if (c.repository_id !== CONTROLLER_REPOSITORY_ID || c.ref_protected !== true ||
      c.workflow_ref !== `${CONTROLLER_REPOSITORY}/.github/workflows/${CONTROLLER_WORKFLOW_FILE}@${CONTROLLER_REF}` ||
      !/^[0-9a-f]{40}$/.test(c.workflow_sha)) throw new BrokerError('CONTROLLER_IMMUTABLE_IDENTITY_INVALID');
  positiveInt(c.run_id, 'CONTROLLER_RUN_INVALID');
  positiveInt(c.run_attempt, 'CONTROLLER_ATTEMPT_INVALID');
  if (c.actor !== CONTROLLER_ACTOR || c.actor_id !== CONTROLLER_ACTOR_ID ||
      c.triggering_actor !== CONTROLLER_ACTOR) throw new BrokerError('CONTROLLER_ACTOR_INVALID');
  const p = exactKeys(body.producer, ['repository', 'ref', 'workflow_file'], 'PRODUCER_BINDING_INVALID');
  if (p.repository !== PRODUCER_REPOSITORY || p.ref !== PRODUCER_REF ||
      p.workflow_file !== PRODUCER_WORKFLOW) throw new BrokerError('PRODUCER_BINDING_INVALID');
  const candidate = exactKeys(body.candidate, ['source_commit', 'artifact_id', 'producer_run_id', 'archive_sha256', 'release_request_sha256'], 'CANDIDATE_INVALID');
  exactString(candidate.source_commit, /^[0-9a-f]{40}$/, 'CANDIDATE_COMMIT_INVALID');
  positiveInt(candidate.artifact_id, 'CANDIDATE_ARTIFACT_INVALID');
  positiveInt(candidate.producer_run_id, 'CANDIDATE_RUN_INVALID');
  if (!sha256(candidate.archive_sha256) || !sha256(candidate.release_request_sha256)) {
    throw new BrokerError('CANDIDATE_DIGEST_INVALID');
  }
  return body;
}

function claimString(claims, name, expected) {
  if (claims[name] !== expected) throw new BrokerError(`OIDC_${name.toUpperCase()}_INVALID`, 401);
}

function claimRun(claims, body) {
  if (String(claims.run_id) !== String(body.controller.run_id) ||
      String(claims.run_attempt) !== String(body.controller.run_attempt) ||
      claims.actor !== body.controller.actor) throw new BrokerError('OIDC_RUN_BINDING_INVALID', 401);
}

export function expectedOidcClaims(body) {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: `repo:${CONTROLLER_REPOSITORY}:environment:staging`,
    repository: CONTROLLER_REPOSITORY,
    repository_id: String(CONTROLLER_REPOSITORY_ID),
    repository_visibility: 'private',
    ref: CONTROLLER_REF,
    workflow: CONTROLLER_WORKFLOW,
    workflow_ref: `${CONTROLLER_REPOSITORY}/.github/workflows/${CONTROLLER_WORKFLOW_FILE}@${CONTROLLER_REF}`,
    workflow_sha: body.controller.workflow_sha,
    environment: 'staging',
    runner_environment: 'self-hosted',
    event_name: 'workflow_dispatch',
    run_id: body.controller.run_id,
    run_attempt: body.controller.run_attempt,
    actor: body.controller.actor,
    actor_id: String(CONTROLLER_ACTOR_ID),
  };
}

function keyFromJwk(jwk) {
  if (!jwk || jwk.kty !== 'RSA' || jwk.alg !== 'RS256' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
    throw new BrokerError('OIDC_KEY_INVALID', 401);
  }
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

async function fetchJsonHttps(url, maxBytes = 256 * 1024) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'token.actions.githubusercontent.com' || parsed.pathname !== '/.well-known/jwks') {
    throw new BrokerError('OIDC_JWKS_URL_INVALID', 503);
  }
  return new Promise((resolve, reject) => {
    const req = https.get({ hostname: parsed.hostname, port: 443, path: parsed.pathname, servername: parsed.hostname,
      headers: { accept: 'application/json' }, timeout: 5_000 }, response => {
      if (response.statusCode !== 200) { response.resume(); reject(new BrokerError('OIDC_JWKS_UNAVAILABLE', 503)); return; }
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > maxBytes) { req.destroy(new BrokerError('OIDC_JWKS_TOO_LARGE', 503)); return; } chunks.push(chunk); });
      response.on('end', () => { try { resolve(parseJson(Buffer.concat(chunks).toString('utf8'), 'OIDC_JWKS_INVALID')); } catch (error) { reject(error); } });
    });
    req.on('timeout', () => req.destroy(new BrokerError('OIDC_JWKS_TIMEOUT', 503)));
    req.on('error', reject);
  });
}

export async function verifyOidcToken(token, body, { jwks = null, now = Math.floor(Date.now() / 1000) } = {}) {
  if (typeof token !== 'string' || Buffer.byteLength(token) > LIMITS.tokenBytes) throw new BrokerError('OIDC_TOKEN_INVALID', 401);
  const parts = token.split('.');
  if (parts.length !== 3) throw new BrokerError('OIDC_TOKEN_INVALID', 401);
  const header = parseJson(base64urlDecode(parts[0]).toString('utf8'), 'OIDC_TOKEN_INVALID');
  const claims = parseJson(base64urlDecode(parts[1]).toString('utf8'), 'OIDC_TOKEN_INVALID');
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || typeof header.kid !== 'string' || !header.kid ||
      typeof claims.iss !== 'string' || claims.iss !== ISSUER ||
      claims.aud !== AUDIENCE || typeof claims.exp !== 'number' || typeof claims.nbf !== 'number' ||
      typeof claims.iat !== 'number' || typeof claims.jti !== 'string' || claims.jti.length < 16 ||
      claims.exp <= now || claims.exp > now + 600 || claims.nbf > now + 30 ||
      claims.iat > now + 30 || claims.iat < now - 600) throw new BrokerError('OIDC_CLAIMS_INVALID', 401);
  const keys = jwks ?? await fetchJsonHttps(JWKS_URL);
  if (!keys || !Array.isArray(keys.keys)) throw new BrokerError('OIDC_JWKS_INVALID', 503);
  const jwk = keys.keys.find(item => item.kid === header.kid);
  if (!jwk) throw new BrokerError('OIDC_KEY_NOT_FOUND', 401);
  const verified = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), keyFromJwk(jwk), base64urlDecode(parts[2]));
  if (!verified) throw new BrokerError('OIDC_SIGNATURE_INVALID', 401);
  const expected = expectedOidcClaims(body);
  for (const [name, value] of Object.entries(expected)) {
    if (name === 'run_id' || name === 'run_attempt') { if (String(claims[name]) !== String(value)) throw new BrokerError('OIDC_RUN_BINDING_INVALID', 401); }
    else claimString(claims, name, value);
  }
  claimRun(claims, body);
  return claims;
}

async function withJournalLock(lockPath, operation) {
  const started = Date.now();
  while (true) {
    try { await fs.mkdir(lockPath); break; } catch (error) {
      if (error.code !== 'EEXIST' || Date.now() - started > LIMITS.journalLockMs) throw new BrokerError('JOURNAL_BUSY', 503);
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }
  try { return await operation(); } finally { await fs.rm(lockPath, { recursive: true, force: true }); }
}

async function appendDurably(filePath, line) {
  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW;
  const handle = await fs.open(filePath, flags, 0o600);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new BrokerError('JOURNAL_PERMISSION_INVALID', 503);
    await handle.writeFile(line, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export function createJournal(directory) {
  const journalPath = path.join(directory, 'admissions.jsonl');
  const lockPath = `${journalPath}.lock`;
  return {
    async reserve(requestId, metadata) {
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
      return withJournalLock(lockPath, async () => {
        let contents = '';
        try { contents = await fs.readFile(journalPath, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
        const entries = contents.split('\n').filter(Boolean).map(line => JSON.parse(line));
        if (entries.some(entry => entry.request_id === requestId && entry.state !== 'released')) throw new BrokerError('REQUEST_REPLAY', 409);
        await appendDurably(journalPath, `${JSON.stringify({ request_id: requestId, state: 'reserved', at: new Date().toISOString(), ...metadata })}\n`);
      });
    },
    async finish(requestId, state) {
      return withJournalLock(lockPath, async () => {
        await appendDurably(journalPath, `${JSON.stringify({ request_id: requestId, state, at: new Date().toISOString() })}\n`);
      });
    },
    path: journalPath,
  };
}

function executableAdapter(command, { timeoutMs = LIMITS.adapterTimeoutMs } = {}) {
  return async payload => new Promise((resolve, reject) => {
    const child = spawn(command, [], { stdio: ['pipe', 'pipe', 'ignore'], shell: false, detached: true });
    const output = []; let bytes = 0;
    const terminateTree = () => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* already exited */ } }
    };
    const timer = setTimeout(() => { terminateTree(); reject(new BrokerError('ADAPTER_TIMEOUT', 503)); }, timeoutMs);
    child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 64 * 1024) { child.kill('SIGKILL'); reject(new BrokerError('ADAPTER_OUTPUT_TOO_LARGE', 503)); } else output.push(chunk); });
    child.on('error', () => { clearTimeout(timer); reject(new BrokerError('ADAPTER_UNAVAILABLE', 503)); });
    child.on('close', code => { clearTimeout(timer); if (code !== 0) { reject(new BrokerError('ADAPTER_REJECTED', 502)); return; } try { const result = JSON.parse(Buffer.concat(output).toString('utf8')); if (result.ok !== true) throw new Error(); resolve(result); } catch { reject(new BrokerError('ADAPTER_INVALID', 502)); } });
    child.stdin.end(JSON.stringify(payload));
  });
}

export function createProductionAdapters({ verifierCommand, artifactFetcherCommand, deployerCommand } = {}) {
  if (![verifierCommand, artifactFetcherCommand, deployerCommand].every(value => typeof value === 'string' && path.isAbsolute(value))) throw new BrokerError('ADAPTERS_NOT_CONFIGURED', 503);
  return {
    candidateVerifier: executableAdapter(verifierCommand),
    artifactFetcher: executableAdapter(artifactFetcherCommand),
    deployer: executableAdapter(deployerCommand, { timeoutMs: 15 * 60_000 }),
  };
}

export function checkRootOwnedPath(filePath, { executable = false, privateFile = false } = {}) {
  return fs.stat(filePath).then(stat => stat.uid === 0 &&
    (stat.mode & (privateFile ? 0o077 : 0o022)) === 0 &&
    (!executable || (stat.mode & 0o111) !== 0)).catch(() => false);
}

export async function productionReadiness({ tlsCert, tlsKey, caPem, stateDir, credentialFile, verifierCommand, artifactFetcherCommand, deployerCommand }) {
  const checks = await Promise.all([
    checkRootOwnedPath(tlsCert), checkRootOwnedPath(tlsKey, { privateFile: true }), checkRootOwnedPath(caPem),
    checkRootOwnedPath(credentialFile, { privateFile: true }), checkRootOwnedPath(verifierCommand, { executable: true }),
    checkRootOwnedPath(artifactFetcherCommand, { executable: true }), checkRootOwnedPath(deployerCommand, { executable: true }),
    fs.stat(stateDir).then(stat => stat.uid === 0 && (stat.mode & 0o077) === 0).catch(() => false),
  ]);
  return checks.every(Boolean);
}

export function createBroker({ journal, jwks, candidateVerifier, artifactFetcher, deployer, readiness = async () => true }) {
  if (!journal || typeof candidateVerifier !== 'function' || typeof artifactFetcher !== 'function' || typeof deployer !== 'function') throw new BrokerError('BROKER_NOT_CONFIGURED', 503);
  async function handle(req, res) {
    const fail = (error) => { const status = error instanceof BrokerError ? error.status : 503; res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify({ error: error instanceof BrokerError ? error.code : 'BROKER_UNAVAILABLE' })); };
    try {
      if (req.method !== 'POST' || req.url !== '/v1/staging/releases') throw new BrokerError('NOT_FOUND', 404);
      if (req.headers['content-type'] !== 'application/json') throw new BrokerError('CONTENT_TYPE_REQUIRED', 415);
      const rawLength = req.headers['content-length'];
      if (typeof rawLength !== 'string' || !/^[1-9][0-9]{0,5}$/.test(rawLength)) throw new BrokerError('BODY_LIMIT', 413);
      const length = Number(rawLength);
      if (!Number.isSafeInteger(length) || length < 2 || length > LIMITS.bodyBytes) throw new BrokerError('BODY_LIMIT', 413);
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > LIMITS.bodyBytes) throw new BrokerError('BODY_LIMIT', 413); chunks.push(chunk); }
      if (size !== length) throw new BrokerError('BODY_LENGTH_INVALID', 400);
      const body = validateAdmissionRequest(parseJson(Buffer.concat(chunks).toString('utf8'), 'REQUEST_INVALID'), req.headers['x-cnyos-request-id']);
      const auth = req.headers.authorization;
      if (typeof auth !== 'string' || !/^Bearer [^\s]+$/.test(auth)) throw new BrokerError('OIDC_REQUIRED', 401);
      await verifyOidcToken(auth.slice(7), body, { jwks });
      if (!(await readiness())) throw new BrokerError('BROKER_NOT_READY', 503);
      if (!(await candidateVerifier(body))) throw new BrokerError('CANDIDATE_NOT_VERIFIED', 403);
      await journal.reserve(body.request_id, { commit: body.candidate.source_commit, artifact_id: body.candidate.artifact_id });
      try {
        const artifact = await artifactFetcher(body);
        await deployer({ ...body, artifact });
        await journal.finish(body.request_id, 'completed');
      } catch (error) {
        try { await journal.finish(body.request_id, 'failed'); } catch { /* preserve original fail-closed response */ }
        throw error;
      }
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ schema_version: 1, request_id: body.request_id, status: 'accepted' }));
    } catch (error) { fail(error); }
  }
  return { handle };
}

export async function createProductionServer({ env = process.env } = {}) {
  const config = {
    tlsCert: env.CNYOS_BROKER_TLS_CERT || '/etc/cnyos-broker/tls/server.crt',
    tlsKey: env.CNYOS_BROKER_TLS_KEY || '/etc/cnyos-broker/tls/server.key',
    caPem: env.CNYOS_BROKER_CA_PEM || '/etc/cnyos-broker/ca.pem',
    stateDir: env.CNYOS_BROKER_STATE_DIR || '/var/lib/cnyos-broker',
    credentialFile: env.CNYOS_BROKER_CREDENTIAL_FILE || '/etc/cnyos-broker/github-token',
    verifierCommand: env.CNYOS_BROKER_CANDIDATE_VERIFIER || '/usr/local/libexec/cnyos-staging-candidate-verifier',
    artifactFetcherCommand: env.CNYOS_BROKER_ARTIFACT_FETCHER || '/usr/local/libexec/cnyos-staging-artifact-fetcher',
    deployerCommand: env.CNYOS_BROKER_DEPLOYER || '/usr/local/libexec/cnyos-staging-deployer',
  };
  const ready = () => productionReadiness(config);
  const adapters = createProductionAdapters(config);
  const journal = createJournal(config.stateDir);
  const broker = createBroker({ journal, ...adapters, readiness: ready });
  const cert = await fs.readFile(config.tlsCert); const key = await fs.readFile(config.tlsKey);
  const server = https.createServer({ cert, key, minVersion: 'TLSv1.3' });
  server.on('request', (req, res) => {
    if (req.url === '/healthz' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      res.end('ok\n');
      return;
    }
    if (req.url === '/readyz' && req.method === 'GET') {
      ready().then(ok => {
        res.writeHead(ok ? 200 : 503, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
        res.end(ok ? 'ready\n' : 'not_ready\n');
      }).catch(() => { res.writeHead(503); res.end('not_ready\n'); });
      return;
    }
    broker.handle(req, res);
  });
  return { server, ready };
}
