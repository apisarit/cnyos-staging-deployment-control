import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { randomBytes } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  MAX_FILE_BYTES,
  POLICY,
  POLICY_SHA256,
  assertExactKeys,
  assertControllerRuntime,
  assertPolicyTarget,
  canonicalIsoTimestamp,
  exactDeployId,
  exactSha256,
  fail,
  isPlainObject,
  parseJsonObject,
  readRegularFileStable,
  recentCanonicalTimestamp,
  required,
  safeOrigin,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';

const BOUNDARY_PATH = '/v1/read-netlify-draft-file';
const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
const MAX_OUTER_RESPONSE_BYTES = 256 * 1024;
const MAX_REDIRECT_PROBE_BODY_BYTES = 1024 * 1024;
const MAX_BOUNDARY_AGE_MS = 10 * 60 * 1000;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

export const PROBED_HEADER_NAMES = Object.freeze([
  'cache-control',
  'content-type',
  'location',
  'permissions-policy',
  'referrer-policy',
  'x-content-type-options',
  'x-frame-options',
  'x-robots-tag'
]);

const FORBIDDEN_AUTHORITY_ENVIRONMENT = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'SUPABASE_ACCESS_TOKEN',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'SUPABASE_DB_PASSWORD',
  'POSTGRES_PASSWORD',
  'PGPASSWORD',
  'DATABASE_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN'
]);

const NO_STORE = 'no-store, no-cache, must-revalidate, max-age=0';

const CONTROL_BEHAVIOR_EVIDENCE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'authorization',
  'promotionAuthorization', 'scope', 'productionAuthorization', 'verifiedAt',
  'controllerRepository', 'controllerRef', 'controllerCommit', 'controllerRunId',
  'dispatchNonce', 'policySha256', 'source', 'artifact', 'target',
  'currentPublishedDeployId', 'draftDeployId', 'exactDeployOrigin',
  'headersBehaviorVerified', 'redirectsBehaviorVerified',
  'boundaryCredentialConsumedOnlyAtBoundary', 'boundaryCredentialForwardedUpstream',
  'boundaryRedirectsFollowed', 'headerRuleCount', 'redirectRuleCount',
  'headerProbes', 'redirectProbes', 'preflightEvidenceSha256',
  'draftReceiptEvidenceSha256', 'draftAccessBoundaryEvidenceSha256',
  'draftVerificationEvidenceSha256', 'secretValuesSerialized'
]);
const CONTROL_BEHAVIOR_HEADER_PROBE_KEYS = Object.freeze([
  'path', 'routeKind', 'method', 'expectedStatus', 'upstreamStatus',
  'expectedHeadersSha256', 'observedHeadersSha256'
]);
const CONTROL_BEHAVIOR_REDIRECT_PROBE_KEYS = Object.freeze([
  'from', 'to', 'expectedStatus', 'force', 'upstreamStatus', 'upstreamLocation',
  'upstreamBodySize', 'upstreamBodySha256'
]);

function strictDraftAccessToken(value) {
  if (typeof value !== 'string' || value.length < 32 || value.length > 2048 ||
    !/^[A-Za-z0-9\-._~+/]+={0,2}$/.test(value)) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_INVALID');
  }
  return value;
}

export const REQUIRED_NETLIFY_HEADER_RULES = Object.freeze([
  Object.freeze({ path: '/', headers: Object.freeze({ 'cache-control': NO_STORE }) }),
  Object.freeze({ path: '/login-v3.html', headers: Object.freeze({ 'cache-control': NO_STORE }) }),
  Object.freeze({ path: '/auth.html', headers: Object.freeze({ 'cache-control': NO_STORE }) }),
  Object.freeze({ path: '/index.html', headers: Object.freeze({ 'cache-control': NO_STORE }) }),
  Object.freeze({
    path: '/ui-review.html',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-robots-tag': 'noindex, nofollow'
    })
  }),
  Object.freeze({
    path: '/identity-review.html',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-robots-tag': 'noindex, nofollow, noarchive',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    })
  }),
  Object.freeze({
    path: '/owner-control.html',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-robots-tag': 'noindex, nofollow, noarchive',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    })
  }),
  Object.freeze({
    path: '/api/owner-subscription',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    })
  }),
  Object.freeze({
    path: '/patient-card.html',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-robots-tag': 'noindex, nofollow, noarchive',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()'
    })
  }),
  Object.freeze({
    path: '/check-in.html',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-robots-tag': 'noindex, nofollow, noarchive',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'camera=(self), microphone=(), geolocation=()'
    })
  }),
  Object.freeze({
    path: '/api/patient-identity',
    headers: Object.freeze({
      'cache-control': NO_STORE,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    })
  })
]);

export const REQUIRED_NETLIFY_REDIRECT_RULES = Object.freeze([
  Object.freeze({ from: '/app.html', to: '/', status: 301, force: true }),
  Object.freeze({ from: '/check-in', to: '/check-in.html', status: 301, force: true }),
  Object.freeze({ from: '/patient-card', to: '/patient-card.html', status: 301, force: true }),
  Object.freeze({ from: '/identity-review', to: '/identity-review.html', status: 301, force: true }),
  Object.freeze({ from: '/owner-control', to: '/owner-control.html', status: 301, force: true }),
  Object.freeze({ from: '/luopan', to: '/luopan.html', status: 301, force: true }),
  Object.freeze({ from: '/', to: '/index.html', status: 200, force: false })
]);

function exactText(bytes, code) {
  if (!Buffer.isBuffer(bytes) ||
    (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)) fail(code);
  let text;
  try { text = UTF8.decode(bytes); }
  catch { fail(code); }
  if (text.includes('\0') || text.startsWith('\ufeff') || /\r(?!\n)/.test(text)) fail(code);
  return text.replaceAll('\r\n', '\n');
}

function exactControlPath(value, code) {
  const candidate = String(value || '');
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]*$/.test(candidate) ||
    candidate.includes('//') || candidate.split('/').some(item => item === '.' || item === '..')) fail(code);
  return candidate;
}

function exactHeaderValue(value, code) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 ||
    value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) fail(code);
  return value;
}

export function parseNetlifyHeaders(bytes) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_HEADERS_CONTROL_FILE_INVALID';
  const lines = exactText(bytes, code).split('\n');
  const rules = [];
  const paths = new Set();
  let current = null;
  for (const line of lines) {
    if (line === '' || /^\s*#/.test(line)) continue;
    if (!/^[ \t]/.test(line)) {
      const rulePath = exactControlPath(line, code);
      if (paths.has(rulePath)) fail(code);
      paths.add(rulePath);
      current = { path: rulePath, headers: {} };
      rules.push(current);
      continue;
    }
    if (!current) fail(code);
    const match = line.match(/^  ([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]+(.+)$/);
    if (!match) fail(code);
    const name = match[1].toLowerCase();
    if (match[1] !== name && match[1] !== match[1].split('-')
      .map(item => item ? item[0].toUpperCase() + item.slice(1).toLowerCase() : item).join('-')) fail(code);
    if (!PROBED_HEADER_NAMES.includes(name) || name === 'location' ||
      Object.hasOwn(current.headers, name)) fail(code);
    current.headers[name] = exactHeaderValue(match[2], code);
  }
  if (!rules.length || rules.some(rule => Object.keys(rule.headers).length < 1)) fail(code);
  return Object.freeze(rules.map(rule => Object.freeze({
    path: rule.path,
    headers: Object.freeze({ ...rule.headers })
  })));
}

export function parseNetlifyRedirects(bytes) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_REDIRECTS_CONTROL_FILE_INVALID';
  const rules = [];
  const sources = new Set();
  for (const line of exactText(bytes, code).split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (line !== trimmed || /\t/.test(line)) fail(code);
    const tokens = line.split(/ +/);
    if (tokens.length !== 3) fail(code);
    const [rawFrom, rawTo, rawStatus] = tokens;
    const from = exactControlPath(rawFrom, code);
    const to = exactControlPath(rawTo, code);
    const match = rawStatus.match(/^(200|301|302|303|307|308)(!)?$/);
    if (!match || sources.has(from)) fail(code);
    sources.add(from);
    rules.push(Object.freeze({
      from,
      to,
      status: Number(match[1]),
      force: match[2] === '!'
    }));
  }
  if (!rules.length) fail(code);
  return Object.freeze(rules);
}

export function assertRequiredNetlifyControlInventory(headerRules, redirectRules) {
  if (JSON.stringify(headerRules) !== JSON.stringify(REQUIRED_NETLIFY_HEADER_RULES)) {
    fail('CNYOS_CONTROLLER_NETLIFY_HEADERS_REQUIRED_INVENTORY_MISMATCH');
  }
  if (JSON.stringify(redirectRules) !== JSON.stringify(REQUIRED_NETLIFY_REDIRECT_RULES)) {
    fail('CNYOS_CONTROLLER_NETLIFY_REDIRECTS_REQUIRED_INVENTORY_MISMATCH');
  }
}

async function responseBytes(response, maximum, code) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel().catch(() => {});
        fail(code);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

function canonicalJsonObject(bytes, code) {
  let value;
  try { value = JSON.parse(UTF8.decode(bytes)); }
  catch { fail(code); }
  if (!isPlainObject(value) || !Buffer.from(JSON.stringify(value)).equals(bytes)) fail(code);
  return value;
}

function safeHeaderValue(value, code) {
  if (value === null) return null;
  if (typeof value !== 'string' || value.length > 8192 || /[\r\n\u0000]/.test(value)) fail(code);
  return value;
}

function exactProbePath(value, code) {
  return exactControlPath(value, code);
}

function assertNoSecretSerialization(value, token, code) {
  if (String(value).includes(token)) fail(code);
}

function freshRequestNonce(randomBytesImpl, code) {
  if (typeof randomBytesImpl !== 'function') fail(code);
  let bytes;
  try { bytes = randomBytesImpl(32); }
  catch { fail(code); }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) fail(code);
  return Buffer.from(bytes).toString('base64url');
}

export async function probeExactDraftRequest(fetchImpl, {
  boundaryOrigin,
  boundaryToken,
  boundaryPolicyId,
  boundaryPolicySha256,
  controllerRunId,
  netlifySiteId,
  netlifyDeployId,
  exactDraftDeployOrigin,
  method,
  path: requestPath,
  expectedStatus,
  maximumBodyBytes,
  now = () => new Date(),
  randomBytesImpl = randomBytes
}) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_RESPONSE_INVALID';
  const origin = safeOrigin(boundaryOrigin,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID');
  const token = strictDraftAccessToken(boundaryToken);
  const policyId = required(boundaryPolicyId,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID', 200);
  const policySha256 = exactSha256(boundaryPolicySha256,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  const runId = required(controllerRunId, 'CNYOS_CONTROLLER_RUN_ID_INVALID', 32);
  if (!/^\d+$/.test(runId)) fail('CNYOS_CONTROLLER_RUN_ID_INVALID');
  if (netlifySiteId !== POLICY.target.netlifySiteId) fail(code);
  const deployId = exactDeployId(netlifyDeployId, code);
  const deployOrigin = safeOrigin(exactDraftDeployOrigin, code);
  if (deployOrigin !== `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app` ||
    deployOrigin === origin || deployOrigin === POLICY.target.netlifyOrigin) fail(code);
  if (!['GET', 'HEAD'].includes(method)) fail(code);
  const safePath = exactProbePath(requestPath, code);
  if (expectedStatus !== null &&
    (!Number.isSafeInteger(expectedStatus) || expectedStatus < 100 || expectedStatus > 599)) fail(code);
  if (!Number.isSafeInteger(maximumBodyBytes) || maximumBodyBytes < 0 ||
    maximumBodyBytes > MAX_FILE_BYTES) fail(code);
  const requestNonce = freshRequestNonce(randomBytesImpl, code);
  const requestValue = {
    schemaVersion: 1,
    operation: 'probe_exact_netlify_draft_request',
    controllerRunId: runId,
    netlifySiteId,
    netlifyDeployId: deployId,
    exactDraftDeployOrigin: deployOrigin,
    requestNonce,
    method,
    path: safePath,
    expectedStatus,
    maximumBodyBytes
  };
  const requestStartedAt = now();
  if (!(requestStartedAt instanceof Date) || Number.isNaN(requestStartedAt.getTime())) fail(code);
  let response;
  try {
    response = await fetchImpl(`${origin}${BOUNDARY_PATH}`, {
      method: 'POST',
      redirect: 'error',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        'Content-Type': 'application/json',
        'X-CNYOS-Boundary-Policy-Id': policyId,
        'X-CNYOS-Boundary-Policy-SHA256': policySha256
      },
      body: JSON.stringify(requestValue),
      signal: AbortSignal.timeout(20_000)
    });
  } catch {
    fail('CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_REQUEST_FAILED');
  }
  if (response.status !== 200 || response.redirected === true ||
    response.headers.get('content-type') !== 'application/json; charset=utf-8' ||
    response.headers.get('cache-control') !== 'no-store' ||
    response.headers.get('x-content-type-options') !== 'nosniff' ||
    response.headers.get('x-cnyos-boundary-policy-id') !== policyId ||
    response.headers.get('x-cnyos-boundary-policy-sha256') !== policySha256 ||
    response.headers.get('x-cnyos-upstream-authorization-forwarded') !== 'false' ||
    response.headers.get('x-cnyos-upstream-cookies-forwarded') !== 'false' ||
    response.headers.get('x-cnyos-upstream-redirect-followed') !== 'false') fail(code);
  for (const [name, value] of response.headers) {
    assertNoSecretSerialization(name, token, code);
    assertNoSecretSerialization(value, token, code);
  }
  const bytes = await responseBytes(response, MAX_OUTER_RESPONSE_BYTES, code);
  assertNoSecretSerialization(bytes.toString('utf8'), token, code);
  const value = canonicalJsonObject(bytes, code);
  assertExactKeys(value, [
    'schemaVersion', 'operation', 'controllerRunId', 'netlifySiteId',
    'netlifyDeployId', 'exactDraftDeployOrigin', 'method', 'path',
    'expectedStatus', 'upstreamStatus', 'upstreamLocation', 'upstreamHeaders',
    'upstreamBodySize', 'upstreamBodySha256', 'canary'
  ], code);
  assertExactKeys(value.upstreamHeaders, PROBED_HEADER_NAMES, code);
  assertExactKeys(value.canary, [
    'verifiedAt', 'requestNonce', 'candidateFunctionReached', 'boundaryCredentialObserved',
    'authorizationHeaderObserved', 'cookiesObserved', 'responseReflectedCredential'
  ], code);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime()) ||
    observedAt < requestStartedAt) fail(code);
  const canaryVerifiedAt = recentCanonicalTimestamp(
    value.canary.verifiedAt,
    observedAt,
    MAX_BOUNDARY_AGE_MS,
    code
  );
  for (const header of PROBED_HEADER_NAMES) safeHeaderValue(value.upstreamHeaders[header], code);
  const upstreamLocation = safeHeaderValue(value.upstreamLocation, code);
  if (value.schemaVersion !== 1 ||
    value.operation !== requestValue.operation ||
    value.controllerRunId !== runId || value.netlifySiteId !== netlifySiteId ||
    value.netlifyDeployId !== deployId || value.exactDraftDeployOrigin !== deployOrigin ||
    value.canary.requestNonce !== requestNonce || canaryVerifiedAt < requestStartedAt ||
    value.method !== method || value.path !== safePath ||
    value.expectedStatus !== expectedStatus ||
    !Number.isSafeInteger(value.upstreamStatus) || value.upstreamStatus < 100 ||
    value.upstreamStatus > 599 ||
    (expectedStatus !== null && value.upstreamStatus !== expectedStatus) ||
    value.upstreamHeaders.location !== upstreamLocation ||
    !Number.isSafeInteger(value.upstreamBodySize) || value.upstreamBodySize < 0 ||
    value.upstreamBodySize > maximumBodyBytes ||
    !/^[0-9a-f]{64}$/.test(String(value.upstreamBodySha256 || '')) ||
    value.canary.candidateFunctionReached !== true ||
    value.canary.boundaryCredentialObserved !== false ||
    value.canary.authorizationHeaderObserved !== false ||
    value.canary.cookiesObserved !== false ||
    value.canary.responseReflectedCredential !== false) fail(code);
  assertNoSecretSerialization(JSON.stringify(value), token, code);
  return Object.freeze(value);
}

async function loadEvidence(filename, expectedSha256, code) {
  const bytes = await readRegularFileStable(
    required(filename, `${code}_PATH_REQUIRED`, 4096),
    MAX_EVIDENCE_BYTES,
    code,
    2
  );
  const digest = sha256(bytes);
  if (digest !== exactSha256(expectedSha256, code)) fail(code);
  return Object.freeze({ value: parseJsonObject(bytes.toString('utf8'), code), sha256: digest });
}

function assertEvidenceChain({
  runtime,
  bundle,
  preflight,
  receipt,
  boundary,
  verification,
  reviewedBoundary,
  observedAt
}) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_CONTROL_EVIDENCE_CHAIN_INVALID';
  assertExactKeys(boundary.value, [
    'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
    'verifiedAt', 'controllerRepository', 'controllerRef', 'controllerCommit',
    'controllerRunId', 'source', 'artifact', 'target', 'preflightEvidenceSha256',
    'draftReceiptEvidenceSha256', 'currentPublishedDeployId', 'draftDeployId',
    'exactDraftDeployOrigin', 'boundary', 'canary'
  ], code);
  assertExactKeys(boundary.value.source, ['repository', 'commit', 'tree'], code);
  assertExactKeys(boundary.value.artifact, ['artifactSha256'], code);
  assertExactKeys(boundary.value.target, ['netlifySiteId', 'netlifyOrigin'], code);
  assertExactKeys(boundary.value.boundary, [
    'origin', 'policyId', 'policySha256', 'endpointPath', 'requestMethod',
    'authorizationHeaderConsumedAtBoundary', 'authorizationHeaderForwardedUpstream',
    'cookiesForwardedUpstream', 'redirectsFollowed', 'fixedTargetSiteId',
    'fixedTargetDeployId', 'exactDeployOriginRequired',
    'candidateRoutingCanChangeUpstreamTarget',
    'readOperationReturnsOnlyHashBoundUpstreamBytes',
    'probeOperationReturnsOnlySanitizedMetadata', 'secretSerializationPrevented'
  ], code);
  assertExactKeys(boundary.value.canary, [
    'verifiedAt', 'requestNonce', 'candidateFunctionReached', 'boundaryCredentialObserved',
    'authorizationHeaderObserved', 'cookiesObserved', 'responseReflectedCredential'
  ], code);
  const previousDeployId = exactDeployId(preflight.value.previousPublishedDeploy?.id, code);
  const deployId = exactDeployId(receipt.value.draftDeployId, code);
  const deployOrigin = `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`;
  const capturedAt = recentCanonicalTimestamp(
    preflight.value.capturedAt,
    observedAt,
    POLICY.authorization.maximumLifetimeMinutes * 60 * 1000,
    code
  );
  const receiptAt = recentCanonicalTimestamp(
    receipt.value.recordedAt,
    observedAt,
    MAX_BOUNDARY_AGE_MS,
    code
  );
  const boundaryAt = recentCanonicalTimestamp(
    boundary.value.verifiedAt,
    observedAt,
    MAX_BOUNDARY_AGE_MS,
    code
  );
  const boundaryCanaryAt = recentCanonicalTimestamp(
    boundary.value.canary.verifiedAt,
    observedAt,
    MAX_BOUNDARY_AGE_MS,
    code
  );
  const verificationAt = recentCanonicalTimestamp(
    verification.value.verifiedAt,
    observedAt,
    MAX_BOUNDARY_AGE_MS,
    code
  );
  for (const name of [
    'authorizationExpiresAt',
    'deploymentControlBoundaryExpiresAt',
    'principalProofExpiresAt',
    'liveNetlifyAuthorityBoundaryExpiresAt'
  ]) {
    if (canonicalIsoTimestamp(preflight.value[name], code) <= observedAt) fail(code);
  }
  const common = value => value?.controllerRepository === runtime.repository &&
    value?.controllerRef === runtime.ref && value?.controllerCommit === runtime.commit &&
    value?.controllerRunId === runtime.runId &&
    value?.source?.repository === bundle.manifest.sourceRepository &&
    value?.source?.commit === bundle.manifest.candidateCommit &&
    value?.source?.tree === bundle.manifest.candidateTree &&
    value?.artifact?.artifactSha256 === bundle.manifest.artifactSha256 &&
    value?.target?.netlifySiteId === POLICY.target.netlifySiteId &&
    value?.target?.netlifyOrigin === POLICY.target.netlifyOrigin &&
    value?.productionAuthorization === false;
  if (preflight.value.evidenceType !== 'cnyos_staging_controller_preflight' ||
    preflight.value.authorization !== false || !common(preflight.value) ||
    receipt.value.evidenceType !== 'cnyos_staging_controller_draft_deploy_receipt' ||
    receipt.value.authorization !== false || receipt.value.promotionAuthorization !== false ||
    !common(receipt.value) || receipt.value.previousDeployId !== previousDeployId ||
    receipt.value.currentPublishedDeployId !== previousDeployId ||
    receipt.value.exactDeployOrigin !== deployOrigin ||
    receipt.value.preflightEvidenceSha256 !== preflight.sha256 ||
    boundary.value.schemaVersion !== 1 ||
    boundary.value.evidenceType !== 'cnyos_staging_controller_private_draft_access_boundary' ||
    boundary.value.status !== 'passed' || boundary.value.scope !== 'cnyos_staging_only' ||
    !common(boundary.value) ||
    boundary.value.preflightEvidenceSha256 !== preflight.sha256 ||
    boundary.value.draftReceiptEvidenceSha256 !== receipt.sha256 ||
    boundary.value.currentPublishedDeployId !== previousDeployId ||
    boundary.value.draftDeployId !== deployId ||
    boundary.value.exactDraftDeployOrigin !== deployOrigin ||
    boundary.value.boundary?.origin !== reviewedBoundary.origin ||
    boundary.value.boundary?.policyId !== reviewedBoundary.policyId ||
    boundary.value.boundary?.policySha256 !== reviewedBoundary.policySha256 ||
    boundary.value.boundary?.endpointPath !== BOUNDARY_PATH ||
    boundary.value.boundary?.requestMethod !== 'POST' ||
    boundary.value.boundary?.authorizationHeaderConsumedAtBoundary !== true ||
    boundary.value.boundary?.authorizationHeaderForwardedUpstream !== false ||
    boundary.value.boundary?.cookiesForwardedUpstream !== false ||
    boundary.value.boundary?.redirectsFollowed !== false ||
    boundary.value.boundary?.fixedTargetSiteId !== true ||
    boundary.value.boundary?.fixedTargetDeployId !== true ||
    boundary.value.boundary?.exactDeployOriginRequired !== true ||
    boundary.value.boundary?.candidateRoutingCanChangeUpstreamTarget !== false ||
    boundary.value.boundary?.readOperationReturnsOnlyHashBoundUpstreamBytes !== true ||
    boundary.value.boundary?.probeOperationReturnsOnlySanitizedMetadata !== true ||
    boundary.value.boundary?.secretSerializationPrevented !== true ||
    !/^[A-Za-z0-9_-]{43}$/.test(String(boundary.value.canary?.requestNonce || '')) ||
    boundary.value.canary?.candidateFunctionReached !== true ||
    boundary.value.canary?.boundaryCredentialObserved !== false ||
    boundary.value.canary?.authorizationHeaderObserved !== false ||
    boundary.value.canary?.cookiesObserved !== false ||
    boundary.value.canary?.responseReflectedCredential !== false ||
    verification.value.evidenceType !== 'cnyos_staging_controller_draft_verification' ||
    verification.value.status !== 'passed' || verification.value.authorization !== false ||
    verification.value.promotionAuthorization !== false || !common(verification.value) ||
    verification.value.previousDeployId !== previousDeployId ||
    verification.value.currentPublishedDeployId !== previousDeployId ||
    verification.value.draftDeployId !== deployId ||
    verification.value.exactDraftDeployOrigin !== deployOrigin ||
    verification.value.privateDraftAccessBoundaryEvidenceSha256 !== boundary.sha256 ||
    verification.value.draftReceiptEvidenceSha256 !== receipt.sha256 ||
    verification.value.draftAccessCredentialConsumedOnlyAtBoundary !== true ||
    verification.value.draftAccessCredentialForwardedToCandidateOrigin !== false ||
    receiptAt < capturedAt || boundaryCanaryAt < receiptAt || boundaryCanaryAt > boundaryAt ||
    boundaryAt < receiptAt || verificationAt < boundaryAt) fail(code);
  return Object.freeze({ previousDeployId, deployId, deployOrigin, verificationAt });
}

function controlFileEntry(bundle, name) {
  const expectedPath = `payload/dist/${name}`;
  const entries = bundle.manifest.files.filter(item => item.path === expectedPath);
  if (entries.length !== 1) fail('CNYOS_CONTROLLER_NETLIFY_CONTROL_FILE_MANIFEST_INVALID');
  return entries[0];
}

async function readControlFile(bundle, name) {
  const entry = controlFileEntry(bundle, name);
  const bytes = await readRegularFileStable(
    path.join(bundle.bundleDirectory, 'payload', 'dist', name),
    Math.min(MAX_FILE_BYTES, 1024 * 1024),
    'CNYOS_CONTROLLER_NETLIFY_CONTROL_FILE_INVALID',
    1
  );
  if (bytes.byteLength !== entry.size || sha256(bytes) !== entry.sha256) {
    fail('CNYOS_CONTROLLER_NETLIFY_CONTROL_FILE_DIGEST_MISMATCH');
  }
  return Object.freeze({ bytes, entry });
}

function expectedStaticTarget(bundle, target) {
  const relative = target.slice(1) || 'index.html';
  const entry = bundle.manifest.files.find(item => item.path === `payload/dist/${relative}`);
  if (!entry) fail('CNYOS_CONTROLLER_NETLIFY_REWRITE_TARGET_NOT_IN_BUNDLE');
  return entry;
}

function redirectLocationMatches(observed, expectedPath, origin) {
  if (typeof observed !== 'string' || !observed) return false;
  let url;
  try { url = new URL(observed, origin); }
  catch { return false; }
  return url.username === '' && url.password === '' &&
    url.origin === origin && `${url.pathname}${url.search}${url.hash}` === expectedPath;
}

function reviewedBoundaryForExecution(env, override) {
  if (override !== null &&
    (env.CNYOS_CONTROLLER_ACTIVATION_CONTRACT !== 'true' ||
      env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE !== 'false')) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_TEST_OVERRIDE_FORBIDDEN');
  }
  const boundary = override === null ? POLICY.privateDraftAccessBoundary : override;
  if (!isPlainObject(boundary)) fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  assertExactKeys(boundary, ['origin', 'policyId', 'policySha256'],
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  const origin = safeOrigin(boundary.origin,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  const policyId = required(boundary.policyId,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID', 200);
  const policySha256 = exactSha256(boundary.policySha256,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  if (origin === POLICY.target.netlifyOrigin || /__|BLOCKED_UNTIL/.test(policyId)) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  }
  return Object.freeze({ origin, policyId, policySha256 });
}

function headerProbeDescriptor(bundle, rule) {
  if (rule.path === '/api/owner-subscription') {
    return Object.freeze({
      routeKind: 'dynamic_function_response_contract',
      method: 'GET',
      expectedStatus: 403,
      maximumBodyBytes: 64 * 1024
    });
  }
  if (rule.path === '/api/patient-identity') {
    return Object.freeze({
      routeKind: 'dynamic_function_response_contract',
      method: 'GET',
      expectedStatus: 200,
      maximumBodyBytes: 64 * 1024
    });
  }
  expectedStaticTarget(bundle, rule.path);
  return Object.freeze({
    routeKind: 'netlify_static_headers_control',
    method: 'HEAD',
    expectedStatus: 200,
    maximumBodyBytes: 0
  });
}

export function validateNetlifyControlBehaviorEvidence(value, {
  runtime,
  bundle,
  previousDeployId,
  deployId,
  preflightEvidenceSha256,
  draftReceiptEvidenceSha256,
  draftAccessBoundaryEvidenceSha256,
  draftVerificationEvidenceSha256,
  observedAt,
  notBefore,
  notAfter = observedAt,
  maximumAgeMilliseconds = MAX_BOUNDARY_AGE_MS
}) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_CONTROL_BEHAVIOR_EVIDENCE_INVALID';
  if (!isPlainObject(bundle) || !isPlainObject(bundle.manifest) ||
    typeof bundle.manifestSha256 !== 'string' || !Array.isArray(bundle.manifest.files) ||
    !(observedAt instanceof Date) || Number.isNaN(observedAt.getTime()) ||
    !(notBefore instanceof Date) || Number.isNaN(notBefore.getTime()) ||
    !(notAfter instanceof Date) || Number.isNaN(notAfter.getTime()) ||
    notAfter > observedAt || notAfter < notBefore ||
    !Number.isSafeInteger(maximumAgeMilliseconds) || maximumAgeMilliseconds < 0) fail(code);
  const expectedPreviousDeployId = exactDeployId(previousDeployId, code);
  const expectedDeployId = exactDeployId(deployId, code);
  const expectedDeployOrigin =
    `https://${expectedDeployId}--${POLICY.target.netlifySiteName}.netlify.app`;
  const expectedPreflightSha256 = exactSha256(preflightEvidenceSha256, code);
  const expectedDraftReceiptSha256 = exactSha256(draftReceiptEvidenceSha256, code);
  const expectedDraftAccessBoundarySha256 =
    exactSha256(draftAccessBoundaryEvidenceSha256, code);
  const expectedDraftVerificationSha256 = exactSha256(draftVerificationEvidenceSha256, code);
  const headersEntry = controlFileEntry(bundle, '_headers');
  const redirectsEntry = controlFileEntry(bundle, '_redirects');

  assertExactKeys(value, CONTROL_BEHAVIOR_EVIDENCE_KEYS, code);
  assertExactKeys(value.source, ['repository', 'commit', 'tree'], code);
  assertExactKeys(value.artifact, [
    'producerManifestSha256', 'artifactSha256', 'headersSha256', 'redirectsSha256'
  ], code);
  assertExactKeys(value.target, Object.keys(POLICY.target), code);
  const verifiedAt = recentCanonicalTimestamp(
    value.verifiedAt,
    observedAt,
    maximumAgeMilliseconds,
    code
  );
  if (verifiedAt < notBefore || verifiedAt > notAfter || value.schemaVersion !== 1 ||
    value.evidenceType !== 'cnyos_staging_controller_netlify_control_behavior_verification' ||
    value.status !== 'passed' || value.authorization !== false ||
    value.promotionAuthorization !== false || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false ||
    value.controllerRepository !== runtime?.repository || value.controllerRef !== runtime?.ref ||
    value.controllerCommit !== runtime?.commit || value.controllerRunId !== runtime?.runId ||
    value.dispatchNonce !== bundle.manifest.dispatchNonce || value.policySha256 !== POLICY_SHA256 ||
    value.source.repository !== bundle.manifest.sourceRepository ||
    value.source.commit !== bundle.manifest.candidateCommit ||
    value.source.tree !== bundle.manifest.candidateTree ||
    value.artifact.producerManifestSha256 !== exactSha256(bundle.manifestSha256, code) ||
    value.artifact.artifactSha256 !== bundle.manifest.artifactSha256 ||
    value.artifact.headersSha256 !== headersEntry.sha256 ||
    value.artifact.redirectsSha256 !== redirectsEntry.sha256 ||
    value.currentPublishedDeployId !== expectedPreviousDeployId ||
    value.draftDeployId !== expectedDeployId || value.exactDeployOrigin !== expectedDeployOrigin ||
    value.headersBehaviorVerified !== true || value.redirectsBehaviorVerified !== true ||
    value.boundaryCredentialConsumedOnlyAtBoundary !== true ||
    value.boundaryCredentialForwardedUpstream !== false ||
    value.boundaryRedirectsFollowed !== false ||
    value.headerRuleCount !== REQUIRED_NETLIFY_HEADER_RULES.length ||
    value.redirectRuleCount !== REQUIRED_NETLIFY_REDIRECT_RULES.length ||
    value.preflightEvidenceSha256 !== expectedPreflightSha256 ||
    value.draftReceiptEvidenceSha256 !== expectedDraftReceiptSha256 ||
    value.draftAccessBoundaryEvidenceSha256 !== expectedDraftAccessBoundarySha256 ||
    value.draftVerificationEvidenceSha256 !== expectedDraftVerificationSha256 ||
    value.secretValuesSerialized !== false) fail(code);
  assertPolicyTarget(value.target, code);

  if (!Array.isArray(value.headerProbes) ||
    value.headerProbes.length !== REQUIRED_NETLIFY_HEADER_RULES.length) fail(code);
  value.headerProbes.forEach((probe, index) => {
    assertExactKeys(probe, CONTROL_BEHAVIOR_HEADER_PROBE_KEYS, code);
    const rule = REQUIRED_NETLIFY_HEADER_RULES[index];
    const descriptor = headerProbeDescriptor(bundle, rule);
    const expectedHeadersSha256 = sha256(JSON.stringify(rule.headers));
    if (probe.path !== rule.path || probe.routeKind !== descriptor.routeKind ||
      probe.method !== descriptor.method || probe.expectedStatus !== descriptor.expectedStatus ||
      probe.upstreamStatus !== descriptor.expectedStatus ||
      probe.expectedHeadersSha256 !== expectedHeadersSha256 ||
      probe.observedHeadersSha256 !== expectedHeadersSha256) fail(code);
  });

  if (!Array.isArray(value.redirectProbes) ||
    value.redirectProbes.length !== REQUIRED_NETLIFY_REDIRECT_RULES.length) fail(code);
  value.redirectProbes.forEach((probe, index) => {
    const rule = REQUIRED_NETLIFY_REDIRECT_RULES[index];
    const target = rule.status === 200 ? expectedStaticTarget(bundle, rule.to) : null;
    assertExactKeys(probe, target ?
      [...CONTROL_BEHAVIOR_REDIRECT_PROBE_KEYS, 'rewriteTargetSha256'] :
      CONTROL_BEHAVIOR_REDIRECT_PROBE_KEYS, code);
    if (probe.from !== rule.from || probe.to !== rule.to ||
      probe.expectedStatus !== rule.status || probe.force !== rule.force ||
      probe.upstreamStatus !== rule.status ||
      !Number.isSafeInteger(probe.upstreamBodySize) || probe.upstreamBodySize < 0 ||
      (!target && probe.upstreamBodySize > MAX_REDIRECT_PROBE_BODY_BYTES) ||
      probe.upstreamBodySha256 !== exactSha256(probe.upstreamBodySha256, code)) fail(code);
    if (target) {
      if (probe.upstreamLocation !== null || probe.upstreamBodySize !== target.size ||
        probe.upstreamBodySha256 !== target.sha256 || probe.rewriteTargetSha256 !== target.sha256) {
        fail(code);
      }
    } else if (!redirectLocationMatches(probe.upstreamLocation, rule.to, expectedDeployOrigin)) {
      fail(code);
    }
  });
  return verifiedAt;
}

export async function verifyNetlifyControlFileBehavior({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date(),
  verifyProducerBundleImpl = verifyProducerBundle,
  reviewedBoundaryOverride = null
} = {}) {
  for (const name of FORBIDDEN_AUTHORITY_ENVIRONMENT) {
    if (Object.hasOwn(env, name)) fail('CNYOS_CONTROLLER_NETLIFY_CONTROL_AUTHORITY_CORESIDENCY_FORBIDDEN');
  }
  const runtime = assertControllerRuntime(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_NETLIFY_CONTROL_TIME_INVALID');
  }
  const reviewedBoundary = reviewedBoundaryForExecution(env, reviewedBoundaryOverride);
  if (safeOrigin(env.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID') !== reviewedBoundary.origin) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID');
  }
  const bundle = await verifyProducerBundleImpl({ env });
  const preflight = await loadEvidence(
    env.CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_NETLIFY_CONTROL_PREFLIGHT_EVIDENCE_INVALID'
  );
  const receipt = await loadEvidence(
    env.CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_NETLIFY_CONTROL_DRAFT_RECEIPT_EVIDENCE_INVALID'
  );
  const boundary = await loadEvidence(
    env.CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_EVIDENCE_INVALID'
  );
  const verification = await loadEvidence(
    env.CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_DRAFT_VERIFICATION_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_NETLIFY_CONTROL_DRAFT_VERIFICATION_EVIDENCE_INVALID'
  );
  const chain = assertEvidenceChain({
    runtime,
    bundle,
    preflight,
    receipt,
    boundary,
    verification,
    reviewedBoundary,
    observedAt
  });
  const token = strictDraftAccessToken(env.CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN);
  const headersFile = await readControlFile(bundle, '_headers');
  const redirectsFile = await readControlFile(bundle, '_redirects');
  const headerRules = parseNetlifyHeaders(headersFile.bytes);
  const redirectRules = parseNetlifyRedirects(redirectsFile.bytes);
  assertRequiredNetlifyControlInventory(headerRules, redirectRules);
  const requestBase = Object.freeze({
    boundaryOrigin: reviewedBoundary.origin,
    boundaryToken: token,
    boundaryPolicyId: reviewedBoundary.policyId,
    boundaryPolicySha256: reviewedBoundary.policySha256,
    controllerRunId: runtime.runId,
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyDeployId: chain.deployId,
    exactDraftDeployOrigin: chain.deployOrigin,
    now
  });
  const headerProbes = [];
  for (const rule of headerRules) {
    const descriptor = headerProbeDescriptor(bundle, rule);
    const probe = await probeExactDraftRequest(fetchImpl, {
      ...requestBase,
      method: descriptor.method,
      path: rule.path,
      expectedStatus: descriptor.expectedStatus,
      maximumBodyBytes: descriptor.maximumBodyBytes
    });
    for (const [name, expectedValue] of Object.entries(rule.headers)) {
      if (probe.upstreamHeaders[name] !== expectedValue) {
        fail('CNYOS_CONTROLLER_NETLIFY_HEADERS_BEHAVIOR_MISMATCH');
      }
    }
    headerProbes.push(Object.freeze({
      path: rule.path,
      routeKind: descriptor.routeKind,
      method: descriptor.method,
      expectedStatus: descriptor.expectedStatus,
      upstreamStatus: probe.upstreamStatus,
      expectedHeadersSha256: sha256(JSON.stringify(rule.headers)),
      observedHeadersSha256: sha256(JSON.stringify(Object.fromEntries(
        Object.keys(rule.headers).map(name => [name, probe.upstreamHeaders[name]])
      )))
    }));
  }
  const redirectProbes = [];
  for (const rule of redirectRules) {
    const target = rule.status === 200 ? expectedStaticTarget(bundle, rule.to) : null;
    const probe = await probeExactDraftRequest(fetchImpl, {
      ...requestBase,
      method: 'GET',
      path: rule.from,
      expectedStatus: rule.status,
      maximumBodyBytes: target ? target.size : MAX_REDIRECT_PROBE_BODY_BYTES
    });
    if (target) {
      if (probe.upstreamLocation !== null || probe.upstreamBodySize !== target.size ||
        probe.upstreamBodySha256 !== target.sha256) {
        fail('CNYOS_CONTROLLER_NETLIFY_REWRITE_BEHAVIOR_MISMATCH');
      }
    } else if (!redirectLocationMatches(probe.upstreamLocation, rule.to, chain.deployOrigin)) {
      fail('CNYOS_CONTROLLER_NETLIFY_REDIRECT_BEHAVIOR_MISMATCH');
    }
    redirectProbes.push(Object.freeze({
      from: rule.from,
      to: rule.to,
      expectedStatus: rule.status,
      force: rule.force,
      upstreamStatus: probe.upstreamStatus,
      upstreamLocation: probe.upstreamLocation,
      upstreamBodySize: probe.upstreamBodySize,
      upstreamBodySha256: probe.upstreamBodySha256,
      ...(target ? { rewriteTargetSha256: target.sha256 } : {})
    }));
  }
  const verifiedAt = now();
  if (!(verifiedAt instanceof Date) || Number.isNaN(verifiedAt.getTime()) ||
    verifiedAt < observedAt || verifiedAt < chain.verificationAt) {
    fail('CNYOS_CONTROLLER_NETLIFY_CONTROL_TIME_INVALID');
  }
  assertEvidenceChain({
    runtime,
    bundle,
    preflight,
    receipt,
    boundary,
    verification,
    reviewedBoundary,
    observedAt: verifiedAt
  });
  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_netlify_control_behavior_verification',
    status: 'passed',
    authorization: false,
    promotionAuthorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: verifiedAt.toISOString(),
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerRunId: runtime.runId,
    dispatchNonce: bundle.manifest.dispatchNonce,
    policySha256: POLICY_SHA256,
    source: Object.freeze({
      repository: bundle.manifest.sourceRepository,
      commit: bundle.manifest.candidateCommit,
      tree: bundle.manifest.candidateTree
    }),
    artifact: Object.freeze({
      producerManifestSha256: bundle.manifestSha256,
      artifactSha256: bundle.manifest.artifactSha256,
      headersSha256: headersFile.entry.sha256,
      redirectsSha256: redirectsFile.entry.sha256
    }),
    target: POLICY.target,
    currentPublishedDeployId: chain.previousDeployId,
    draftDeployId: chain.deployId,
    exactDeployOrigin: chain.deployOrigin,
    headersBehaviorVerified: true,
    redirectsBehaviorVerified: true,
    boundaryCredentialConsumedOnlyAtBoundary: true,
    boundaryCredentialForwardedUpstream: false,
    boundaryRedirectsFollowed: false,
    headerRuleCount: headerRules.length,
    redirectRuleCount: redirectRules.length,
    headerProbes: Object.freeze(headerProbes),
    redirectProbes: Object.freeze(redirectProbes),
    preflightEvidenceSha256: preflight.sha256,
    draftReceiptEvidenceSha256: receipt.sha256,
    draftAccessBoundaryEvidenceSha256: boundary.sha256,
    draftVerificationEvidenceSha256: verification.sha256,
    secretValuesSerialized: false
  });
  validateNetlifyControlBehaviorEvidence(evidence, {
    runtime,
    bundle,
    previousDeployId: chain.previousDeployId,
    deployId: chain.deployId,
    preflightEvidenceSha256: preflight.sha256,
    draftReceiptEvidenceSha256: receipt.sha256,
    draftAccessBoundaryEvidenceSha256: boundary.sha256,
    draftVerificationEvidenceSha256: verification.sha256,
    observedAt: verifiedAt,
    notBefore: chain.verificationAt,
    notAfter: verifiedAt
  });
  assertNoSecretSerialization(JSON.stringify(evidence), token,
    'CNYOS_CONTROLLER_NETLIFY_CONTROL_SECRET_SERIALIZED');
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_CONTROL_BEHAVIOR_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_CONTROL_BEHAVIOR_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({ evidence, evidencePath });
}

async function main() {
  const result = await verifyNetlifyControlFileBehavior();
  const bytes = await fs.readFile(result.evidencePath);
  process.stdout.write(`${JSON.stringify({
    evidencePath: result.evidencePath,
    evidenceSha256: sha256(bytes),
    draftDeployId: result.evidence.draftDeployId
  })}\n`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch(error => {
    process.stderr.write(`${String(error?.message ||
      'CNYOS_CONTROLLER_NETLIFY_CONTROL_BEHAVIOR_FAILED')}\n`);
    process.exitCode = 1;
  });
}
