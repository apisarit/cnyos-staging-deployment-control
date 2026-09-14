import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createBroker, createJournal, validateAdmissionRequest, verifyOidcToken, BrokerError } from '../broker/core.mjs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'offline-test', alg: 'RS256', use: 'sig', kty: 'RSA' };
const now = Math.floor(Date.now() / 1000);
const baseBody = (suffix = 'a'.repeat(40)) => ({
  schema_version: 1,
  request_id: `9001.1.${suffix}`,
  environment: 'staging',
  controller: { repository: 'apisarit/cnyos-staging-deployment-control', repository_id: 1362863285, ref: 'refs/heads/main', ref_protected: true, workflow: 'Admit VPS staging release', workflow_ref: 'apisarit/cnyos-staging-deployment-control/.github/workflows/admit-vps-staging-release.yml@refs/heads/main', workflow_sha: '9'.repeat(40), run_id: 9001, run_attempt: 1, actor: 'apisarit', actor_id: 216305243, triggering_actor: 'apisarit' },
  producer: { repository: 'apisarit/chananya-clinical-wellness-os', ref: 'refs/heads/main', workflow_file: 'deploy-vps-staging.yml' },
  candidate: { source_commit: 'b'.repeat(40), artifact_id: 7001, producer_run_id: 8001, archive_sha256: 'c'.repeat(64), release_request_sha256: 'd'.repeat(64) },
});
function tokenFor(body, changes = {}) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'offline-test' })).toString('base64url');
  const claims = { iss: 'https://token.actions.githubusercontent.com', aud: 'cnyos-vps-staging-broker', sub: 'repo:apisarit/cnyos-staging-deployment-control:environment:staging', repository: 'apisarit/cnyos-staging-deployment-control', repository_id: String(body.controller.repository_id), repository_visibility: 'private', ref: 'refs/heads/main', workflow: 'Admit VPS staging release', workflow_ref: body.controller.workflow_ref, workflow_sha: body.controller.workflow_sha, environment: 'staging', runner_environment: 'self-hosted', event_name: 'workflow_dispatch', run_id: body.controller.run_id, run_attempt: body.controller.run_attempt, actor: body.controller.actor, actor_id: String(body.controller.actor_id), jti: 'offline-test-jti-0001', iat: now - 2, nbf: now - 2, exp: now + 300, ...changes };
  const encoded = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${encoded}`), privateKey).toString('base64url');
  return `${header}.${encoded}.${signature}`;
}
function request(server, body, token = tokenFor(body), headers = {}) {
  const serialized = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const address = server.address();
    const req = http.request({ host: address.address, port: address.port, method: 'POST', path: '/v1/staging/releases', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(serialized), authorization: `Bearer ${token}`, 'x-cnyos-request-id': body.request_id, ...headers } }, response => { const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() })); });
    req.on('error', reject); req.end(serialized);
  });
}

assert.doesNotThrow(() => validateAdmissionRequest(baseBody(), baseBody().request_id));
assert.throws(() => validateAdmissionRequest({ ...baseBody(), unexpected: true }, baseBody().request_id), /REQUEST_INVALID/);
for (const [name, changes] of [['audience', { aud: 'wrong' }], ['issuer', { iss: 'https://evil.example' }], ['repository ID', { repository_id: '987654321' }], ['visibility', { repository_visibility: 'public' }], ['runner', { runner_environment: 'github-hosted' }], ['workflow', { workflow_ref: 'apisarit/cnyos-staging-deployment-control/.github/workflows/other.yml@refs/heads/main' }], ['workflow SHA', { workflow_sha: '8'.repeat(40) }]]) {
  const body = baseBody(name === 'issuer' ? 'e'.repeat(40) : 'a'.repeat(40));
  await assert.rejects(() => verifyOidcToken(tokenFor(body, changes), body, { jwks: { keys: [jwk] }, now }), BrokerError, name);
}
{
  const body = baseBody('f'.repeat(40));
  const token = tokenFor(body).split('.'); token[2] = `${token[2].slice(0, -2)}xx`;
  await assert.rejects(() => verifyOidcToken(token.join('.'), body, { jwks: { keys: [jwk] }, now }), /OIDC_SIGNATURE_INVALID/);
}

const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-broker-'));
const journal = createJournal(temp);
let verified = 0; let fetched = 0; let deployed = 0;
const broker = createBroker({ journal, jwks: { keys: [jwk] }, candidateVerifier: async () => { verified += 1; return true; }, artifactFetcher: async candidate => { fetched += 1; return { ok: true, digest: candidate.archive_sha256 }; }, deployer: async () => { deployed += 1; } });
const server = http.createServer(broker.handle);
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const body = baseBody('1'.repeat(40));
let result = await request(server, body);
assert.equal(result.status, 200); assert.deepEqual(JSON.parse(result.body), { schema_version: 1, request_id: body.request_id, status: 'accepted' });
assert.equal(verified, 1); assert.equal(fetched, 1); assert.equal(deployed, 1);
result = await request(server, body);
assert.equal(result.status, 409); assert.match(result.body, /REQUEST_REPLAY/);
assert.equal(deployed, 1);
result = await request(server, body, tokenFor(body), { 'content-type': 'application/json; charset=utf-8' });
assert.equal(result.status, 415);
result = await request(server, body, tokenFor(body), { 'x-cnyos-request-id': 'wrong' });
assert.equal(result.status, 400);
await new Promise(resolve => server.close(resolve));

const failedJournal = createJournal(path.join(temp, 'failed'));
const failedBroker = createBroker({ journal: failedJournal, jwks: { keys: [jwk] }, candidateVerifier: async () => true, artifactFetcher: async () => { throw new BrokerError('ADAPTER_REJECTED', 502); }, deployer: async () => {} });
const failedServer = http.createServer(failedBroker.handle);
await new Promise(resolve => failedServer.listen(0, '127.0.0.1', resolve));
const failedBody = baseBody('2'.repeat(40));
result = await request(failedServer, failedBody);
assert.equal(result.status, 502); assert.match(result.body, /ADAPTER_REJECTED/);
result = await request(failedServer, failedBody);
assert.equal(result.status, 409); assert.match(result.body, /REQUEST_REPLAY/);
await new Promise(resolve => failedServer.close(resolve));

const oversized = baseBody('3'.repeat(40)); oversized.padding = 'x'.repeat(20_000);
const sizeServer = http.createServer(broker.handle);
await new Promise(resolve => sizeServer.listen(0, '127.0.0.1', resolve));
result = await request(sizeServer, oversized);
assert.equal(result.status, 413);
await new Promise(resolve => sizeServer.close(resolve));

process.stdout.write('CNYOS OIDC broker offline contract: passed (invalid OIDC, body limits, replay, adapter failure)\n');
