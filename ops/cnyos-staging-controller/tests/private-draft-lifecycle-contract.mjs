import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY, EXPECTED_FUNCTION_NAMES, sha256 } from '../scripts/policy.mjs';
import {
  PRIVATE_DRAFT_CUSTOM_FUNCTION_PATHS, privateDraftProbeInventory,
  probeAnonymousPrivateDraft, validatePrivateDraftContentChain, verifyPrivateDraftLifecycle
} from '../scripts/verify-private-draft-lifecycle.mjs';
import { DRAFT_PUBLISHER_FORBIDDEN_ENVIRONMENT_NAMES } from '../scripts/create-netlify-draft-with-durable-intent.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const deployed = '2'.repeat(24);
const origin = `https://${deployed}--cnyos.netlify.app`;
const bundle = { manifest: { files: [
  { path: 'payload/dist/index.html' }, { path: 'payload/dist/deploy-manifest.json' },
  { path: 'payload/dist/_headers' }, { path: 'payload/dist/_redirects' },
  { path: 'payload/netlify/functions/database-backup.zip' }
] } };
const probes = privateDraftProbeInventory(bundle);
assert.equal(Object.isFrozen(probes), true);
assert.equal(probes.length, 3 + 2 * (EXPECTED_FUNCTION_NAMES.length + PRIVATE_DRAFT_CUSTOM_FUNCTION_PATHS.length));
assert.equal(new Set(probes.map(p => `${p.method}:${p.pathname}`)).size, probes.length);
assert.equal(probes.some(p => /_headers|_redirects|\.zip$/.test(p.pathname)), false);
for (const name of EXPECTED_FUNCTION_NAMES) for (const method of ['GET', 'POST']) {
  assert.equal(probes.some(p => p.pathname === `/.netlify/functions/${name}` && p.method === method), true);
}
for (const pathname of PRIVATE_DRAFT_CUSTOM_FUNCTION_PATHS) {
  assert.equal(probes.filter(p => p.pathname === pathname).length, 2);
}
function response(url, { status = 403, type = 'text/html; charset=utf-8',
  body = '<html><title>Access denied</title></html>', redirected = false } = {}) {
  const r = new Response(body, { status, headers: { 'Content-Type': type } });
  Object.defineProperties(r, { url: { value: String(url) }, redirected: { value: redirected } });
  return r;
}
const requests = [];
const observations = [];
for (const probe of probes) {
  observations.push(await probeAnonymousPrivateDraft(async (url, init) => {
    requests.push({ url: String(url), init });
    assert.equal(url.origin, origin);
    assert.equal(init.credentials, 'omit'); assert.equal(init.redirect, 'error');
    assert.equal(init.referrerPolicy, 'no-referrer'); assert.equal(init.cache, 'no-store');
    assert.equal(Object.hasOwn(init.headers, 'Authorization'), false);
    assert.equal(Object.hasOwn(init.headers, 'Cookie'), false);
    assert.equal(init.body, probe.method === 'POST' ? '{' : undefined);
    assert.equal(init.signal instanceof AbortSignal, true);
    return response(url);
  }, origin, probe));
}
assert.equal(requests.length, probes.length);
for (const observation of observations) {
  assert.equal(observation.status, 403);
  assert.equal(observation.bodySha256, sha256('<html><title>Access denied</title></html>'));
  assert.equal(observation.credentialsSent, false);
  assert.equal(observation.redirectsFollowed, false);
  assert.equal(Object.hasOwn(observation, 'body'), false);
}
const probe = { pathname: '/.netlify/functions/database-backup-background', method: 'POST', kind: 'function' };
for (const options of [
  { status: 200 }, { status: 202 }, { status: 404 }, { status: 302 }, { redirected: true },
  { type: 'application/json', body: '{"ok":false,"code":"UNAUTHORIZED"}' },
  { type: 'text/html', body: '{"ok":true,"enabled":false}' }, { type: '', body: 'denied' },
  { body: '' }, { body: 'x'.repeat(65537) }
]) await assert.rejects(probeAnonymousPrivateDraft(async url => response(url, options), origin, probe), /CNYOS_PRIVATE_DRAFT_/);
await assert.rejects(probeAnonymousPrivateDraft(async url => response(`${url.origin}/different`), origin, probe), /NOT_DENIED/);
await assert.rejects(probeAnonymousPrivateDraft(async () => { throw new Error('timeout'); }, origin, probe), /NOT_DENIED/);
for (const [badOrigin, badProbe] of [
  ['https://chananya.netlify.app', probe], ['http://' + origin.slice(8), probe],
  [origin, { ...probe, pathname: '//other.example.invalid/' }],
  [origin, { ...probe, pathname: '/api/../other' }],
  [origin, { ...probe, pathname: '/api/x?token=not-allowed' }],
  [origin, { ...probe, method: 'DELETE' }]
]) {
  let invoked = 0;
  await assert.rejects(probeAnonymousPrivateDraft(() => { invoked++; }, badOrigin, badProbe), /PROBE_TARGET_INVALID/);
  assert.equal(invoked, 0);
}
for (const name of DRAFT_PUBLISHER_FORBIDDEN_ENVIRONMENT_NAMES) {
  let invoked = 0;
  await assert.rejects(verifyPrivateDraftLifecycle({ env: { [name]: '' },
    contextLoader: () => { invoked++; }, fetchImpl: () => { invoked++; } }), /CREDENTIAL_ISOLATION_INVALID/);
  assert.equal(invoked, 0);
}
let forbiddenCalls = 0;
await assert.rejects(verifyPrivateDraftLifecycle({ env: {}, fetchImpl: () => { forbiddenCalls++; },
  contextLoader: () => { forbiddenCalls++; } }), /POLICY_INVALID|ORIGIN_INVALID/);
assert.equal(forbiddenCalls, 0, 'unreviewed boundary policy must stop before inputs or network');

// No public-response result is accepted directly as a content/ownership chain.
const context = { runtime: { repository: POLICY.controller.repository, ref: POLICY.controller.protectedRef,
  commit: 'a'.repeat(40), runId: '123' }, bundle,
  preflight: { sha256: 'a'.repeat(64), value: { previousPublishedDeploy: { id: '1'.repeat(24) } } },
  gate: { sha256: 'b'.repeat(64) } };
assert.throws(() => validatePrivateDraftContentChain({ context,
  receipt: { value: { draftDeployId: deployed } }, observedAt: new Date() }), /RECEIPT_INVALID/);
assert.throws(() => validatePrivateDraftContentChain({ context,
  receipt: { value: { draftDeployId: '1'.repeat(24) } }, observedAt: new Date() }), /RECEIPT_INVALID/);

// Contract composition remains controller-owned and fail-closed, not a probe-only receipt.
const source = await fs.readFile(path.join(root, 'scripts/verify-private-draft-lifecycle.mjs'), 'utf8');
for (const name of ['validateStoredDraftIntent', 'assertDraftAccessBoundaryEvidence',
  'assertDraftMetadataPromotionChain', 'validateNetlifyControlBehaviorEvidence',
  'exactSiteInventory', 'assertFreshPreflight']) assert.equal(source.includes(name), true);
assert.match(source, /await checkProvider\(\);[\s\S]+for \(const probe[\s\S]+await checkProvider\(\)/);
assert.match(source, /canonicalIsoTimestamp\(deploy\.value\.created_at/);
assert.match(source, /intentBindingScope: 'signed_intent_and_provider_ownership_marker'/);
assert.match(source, /cleanupOnPrePromotionFailureArmed:\s*intent\.verified\.result\.cleanupOnPrePromotionFailureArmed/);
process.stdout.write('CNYOS activation contract private-draft-lifecycle: passed\n');
