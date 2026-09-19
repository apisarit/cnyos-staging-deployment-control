import path from 'node:path';
import process from 'node:process';
import { randomBytes } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  MAX_FILE_BYTES,
  POLICY,
  assertControllerRuntime,
  assertExactKeys,
  assertPolicyTarget,
  canonicalIsoTimestamp,
  deploymentMarker,
  exactDeployId,
  exactSha256,
  fail,
  isPlainObject,
  readFileBounded,
  recentCanonicalTimestamp,
  required,
  safeOrigin,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';

export const DRAFT_ACCESS_BOUNDARY_PATH = '/v1/read-netlify-draft-file';
export const DRAFT_ACCESS_BOUNDARY_MAXIMUM_AGE_MS = 10 * 60 * 1000;
export const DRAFT_ACCESS_PROBE_MAXIMUM_JSON_BYTES = 64 * 1024;

export const DRAFT_ACCESS_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
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

export const PROBE_RESPONSE_KEYS = Object.freeze([
  'schemaVersion',
  'operation',
  'controllerRunId',
  'netlifySiteId',
  'netlifyDeployId',
  'exactDraftDeployOrigin',
  'method',
  'path',
  'expectedStatus',
  'upstreamStatus',
  'upstreamLocation',
  'upstreamHeaders',
  'upstreamBodySize',
  'upstreamBodySha256',
  'canary'
]);

export const PROBE_UPSTREAM_HEADER_KEYS = Object.freeze([
  'cache-control',
  'content-type',
  'location',
  'permissions-policy',
  'referrer-policy',
  'x-content-type-options',
  'x-frame-options',
  'x-robots-tag'
]);

const PROBE_REQUEST_KEYS = Object.freeze([
  'schemaVersion',
  'operation',
  'controllerRunId',
  'netlifySiteId',
  'netlifyDeployId',
  'exactDraftDeployOrigin',
  'requestNonce',
  'method',
  'path',
  'expectedStatus',
  'maximumBodyBytes'
]);

const CANARY_KEYS = Object.freeze([
  'verifiedAt',
  'requestNonce',
  'candidateFunctionReached',
  'boundaryCredentialObserved',
  'authorizationHeaderObserved',
  'cookiesObserved',
  'responseReflectedCredential'
]);

const PROOF_HEADERS = Object.freeze({
  policyId: 'x-cnyos-boundary-policy-id',
  policySha256: 'x-cnyos-boundary-policy-sha256',
  authorizationForwarded: 'x-cnyos-upstream-authorization-forwarded',
  cookiesForwarded: 'x-cnyos-upstream-cookies-forwarded',
  redirectFollowed: 'x-cnyos-upstream-redirect-followed'
});

const INVALID_BEARER_PREFIX = 'cnyos-invalid-boundary-bearer-';
const MAX_UNAUTHORIZED_RESPONSE_BYTES = 4 * 1024;

function exactKeyOrder(value, expected, code) {
  assertExactKeys(value, expected, code);
  const actual = Object.keys(value);
  if (actual.some((key, index) => key !== expected[index])) fail(code);
}

function strictUtf8(bytes, code) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(code);
  }
}

function exactRequestPath(value, code) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048 ||
    !value.startsWith('/') || value.startsWith('//') || /[?#\\\u0000-\u0020\u007f]/.test(value) ||
    /%(?![0-9A-F]{2})/.test(value) || /%(?:2F|5C|00)/i.test(value)) fail(code);
  let parsed;
  try { parsed = new URL(value, 'https://cnyos.invalid'); }
  catch { fail(code); }
  if (parsed.pathname !== value || parsed.search || parsed.hash ||
    value.split('/').some(part => part === '.' || part === '..' || /%(?:2E)/i.test(part))) fail(code);
  return value;
}

function exactProbeMethod(value) {
  if (value !== 'GET' && value !== 'HEAD') fail('CNYOS_CONTROLLER_DRAFT_PROBE_METHOD_INVALID');
  return value;
}

function exactExpectedStatus(value) {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || value < 100 || value > 599) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_EXPECTED_STATUS_INVALID');
  }
  return value;
}

function exactMaximumBodyBytes(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_FILE_BYTES) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_BODY_LIMIT_INVALID');
  }
  return value;
}

function exactRequestNonce(value, code = 'CNYOS_CONTROLLER_DRAFT_PROBE_NONCE_INVALID') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) fail(code);
  return value;
}

function freshRequestNonce(randomBytesImpl) {
  if (typeof randomBytesImpl !== 'function') {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_NONCE_INVALID');
  }
  let bytes;
  try { bytes = randomBytesImpl(32); }
  catch { fail('CNYOS_CONTROLLER_DRAFT_PROBE_NONCE_INVALID'); }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_NONCE_INVALID');
  }
  return Buffer.from(bytes).toString('base64url');
}

function strictDraftAccessToken(value) {
  if (typeof value !== 'string' || value.length < 32 || value.length > 2048 ||
    !/^[A-Za-z0-9\-._~+/]+={0,2}$/.test(value)) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_INVALID');
  }
  return value;
}

function exactDraftOrigin(deployId) {
  const siteName = required(
    POLICY.target?.netlifySiteName,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID',
    63
  );
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(siteName)) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID');
  }
  return `https://${deployId}--${siteName}.netlify.app`;
}

export function reviewedPrivateDraftAccessBoundary() {
  const boundary = POLICY.privateDraftAccessBoundary;
  const code = 'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID';
  assertExactKeys(boundary, ['origin', 'policyId', 'policySha256'], code);
  const origin = safeOrigin(boundary.origin, code);
  const policyId = required(boundary.policyId, code, 200);
  const policySha256 = exactSha256(boundary.policySha256, code);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(policyId) ||
    origin !== boundary.origin || origin === POLICY.target.netlifyOrigin ||
    /__|BLOCKED_UNTIL/i.test(`${origin}\n${policyId}\n${policySha256}`)) fail(code);
  return Object.freeze({ origin, policyId, policySha256 });
}

function assertReviewedBoundaryDescriptor(value) {
  const code = 'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID';
  assertExactKeys(value, ['origin', 'policyId', 'policySha256'], code);
  const reviewed = reviewedPrivateDraftAccessBoundary();
  if (value.origin !== reviewed.origin || value.policyId !== reviewed.policyId ||
    value.policySha256 !== reviewed.policySha256) fail(code);
  return reviewed;
}

export function assertDraftAccessCredentialIsolation(env) {
  for (const name of DRAFT_ACCESS_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) {
      fail('CNYOS_CONTROLLER_DRAFT_ACCESS_CREDENTIAL_CORESIDENCY_FORBIDDEN');
    }
  }
}

async function responseBytes(response, maximum, code) {
  if (!response || !response.headers || !Number.isSafeInteger(response.status)) fail(code);
  const declaredLength = String(response.headers.get('content-length') || '').trim();
  if (declaredLength && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximum)) fail(code);
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) fail(code);
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel().catch(() => {});
        fail(code);
      }
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error?.message === code) throw error;
    fail(code);
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

function assertSecretAbsentFromResponse(response, body, token, code) {
  if (body.includes(Buffer.from(token, 'utf8'))) fail(code);
  try {
    for (const [name, value] of response.headers) {
      if (`${name}:${value}`.includes(token)) fail(code);
    }
  } catch {
    fail(code);
  }
}

function assertBoundaryProofHeaders(response, boundary, code) {
  if (response.redirected === true ||
    response.headers.get(PROOF_HEADERS.policyId) !== boundary.policyId ||
    response.headers.get(PROOF_HEADERS.policySha256) !== boundary.policySha256 ||
    response.headers.get(PROOF_HEADERS.authorizationForwarded) !== 'false' ||
    response.headers.get(PROOF_HEADERS.cookiesForwarded) !== 'false' ||
    response.headers.get(PROOF_HEADERS.redirectFollowed) !== 'false') fail(code);
}

function assertSafeOuterHeaders(response, expectedContentType, code) {
  if (String(response.headers.get('content-type') || '').toLowerCase() !== expectedContentType ||
    response.headers.get('cache-control') !== 'no-store' ||
    String(response.headers.get('x-content-type-options') || '').toLowerCase() !== 'nosniff') {
    fail(code);
  }
}

function requestOptions(body, boundary, authorization = null, accept = 'application/json') {
  return Object.freeze({
    method: 'POST',
    redirect: 'error',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
    headers: Object.freeze({
      ...(authorization ? { Authorization: `Bearer ${authorization}` } : {}),
      Accept: accept,
      'Accept-Encoding': 'identity',
      'Content-Type': 'application/json',
      'X-CNYOS-Boundary-Policy-Id': boundary.policyId,
      'X-CNYOS-Boundary-Policy-SHA256': boundary.policySha256
    }),
    body,
    signal: AbortSignal.timeout(20_000)
  });
}

function validateProbeDescriptor({
  controllerRunId,
  netlifySiteId,
  netlifyDeployId,
  exactDraftDeployOrigin,
  requestNonce,
  method,
  path: requestPath,
  expectedStatus,
  maximumBodyBytes
}) {
  const runId = required(controllerRunId, 'CNYOS_CONTROLLER_RUN_ID_REQUIRED', 32);
  if (controllerRunId !== runId || !/^\d+$/.test(runId)) {
    fail('CNYOS_CONTROLLER_RUN_ID_INVALID');
  }
  if (netlifySiteId !== POLICY.target.netlifySiteId) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_SITE_INVALID');
  }
  const deployId = exactDeployId(
    netlifyDeployId,
    'CNYOS_CONTROLLER_DRAFT_PROBE_DEPLOY_INVALID'
  );
  const deployOrigin = safeOrigin(
    exactDraftDeployOrigin,
    'CNYOS_CONTROLLER_DRAFT_PROBE_ORIGIN_INVALID'
  );
  if (netlifyDeployId !== deployId || exactDraftDeployOrigin !== deployOrigin ||
    deployOrigin !== exactDraftOrigin(deployId)) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_ORIGIN_INVALID');
  }
  return Object.freeze({
    schemaVersion: 1,
    operation: 'probe_exact_netlify_draft_request',
    controllerRunId: runId,
    netlifySiteId,
    netlifyDeployId: deployId,
    exactDraftDeployOrigin: deployOrigin,
    requestNonce: exactRequestNonce(requestNonce),
    method: exactProbeMethod(method),
    path: exactRequestPath(requestPath, 'CNYOS_CONTROLLER_DRAFT_PROBE_PATH_INVALID'),
    expectedStatus: exactExpectedStatus(expectedStatus),
    maximumBodyBytes: exactMaximumBodyBytes(maximumBodyBytes)
  });
}

function exactCanonicalRequest(value) {
  exactKeyOrder(value, PROBE_REQUEST_KEYS, 'CNYOS_CONTROLLER_DRAFT_PROBE_REQUEST_INVALID');
  return JSON.stringify(value);
}

function validateSanitizedHeaderMap(headers, code) {
  exactKeyOrder(headers, PROBE_UPSTREAM_HEADER_KEYS, code);
  for (const value of Object.values(headers)) {
    if (value !== null && (typeof value !== 'string' || value.length > 8192 ||
      value !== value.trim() || /[\r\n\u0000]/.test(value))) fail(code);
  }
  return headers;
}

function assertCanary(canary, requestNonce, requestStartedAt, observedAt, code) {
  exactKeyOrder(canary, CANARY_KEYS, code);
  if (!(requestStartedAt instanceof Date) || Number.isNaN(requestStartedAt.getTime()) ||
    !(observedAt instanceof Date) || Number.isNaN(observedAt.getTime()) ||
    requestStartedAt > observedAt) fail(code);
  const verifiedAt = recentCanonicalTimestamp(
    canary.verifiedAt,
    observedAt,
    DRAFT_ACCESS_BOUNDARY_MAXIMUM_AGE_MS,
    code
  );
  if (verifiedAt < requestStartedAt ||
    canary.requestNonce !== exactRequestNonce(requestNonce, code) ||
    canary.candidateFunctionReached !== true ||
    canary.boundaryCredentialObserved !== false ||
    canary.authorizationHeaderObserved !== false ||
    canary.cookiesObserved !== false ||
    canary.responseReflectedCredential !== false) fail(code);
  return canary;
}

export function validateExactDraftProbeEnvelope(
  value,
  descriptor,
  observedAt,
  requestStartedAt = observedAt
) {
  const code = 'CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID';
  exactKeyOrder(value, PROBE_RESPONSE_KEYS, code);
  const headers = validateSanitizedHeaderMap(value.upstreamHeaders, code);
  if (value.schemaVersion !== 1 ||
    value.operation !== descriptor.operation ||
    value.controllerRunId !== descriptor.controllerRunId ||
    value.netlifySiteId !== descriptor.netlifySiteId ||
    value.netlifyDeployId !== descriptor.netlifyDeployId ||
    value.exactDraftDeployOrigin !== descriptor.exactDraftDeployOrigin ||
    value.method !== descriptor.method || value.path !== descriptor.path ||
    value.expectedStatus !== descriptor.expectedStatus ||
    !Number.isSafeInteger(value.upstreamStatus) ||
    value.upstreamStatus < 100 || value.upstreamStatus > 599 ||
    (descriptor.expectedStatus !== null && value.upstreamStatus !== descriptor.expectedStatus) ||
    !Number.isSafeInteger(value.upstreamBodySize) || value.upstreamBodySize < 0 ||
    value.upstreamBodySize > descriptor.maximumBodyBytes ||
    value.upstreamBodySha256 !== exactSha256(value.upstreamBodySha256, code) ||
    (value.upstreamLocation !== null && (typeof value.upstreamLocation !== 'string' ||
      value.upstreamLocation.length > 4096 || value.upstreamLocation !== value.upstreamLocation.trim() ||
      /[\r\n\u0000]/.test(value.upstreamLocation))) ||
    value.upstreamLocation !== headers.location) fail(code);
  assertCanary(value.canary, descriptor.requestNonce, requestStartedAt, observedAt, code);
  return Object.freeze({ ...value, upstreamHeaders: Object.freeze({ ...headers }) });
}

export async function probeExactNetlifyDraftRequest({
  fetchImpl = fetch,
  boundary,
  accessToken,
  now = () => new Date(),
  ...request
}) {
  if (typeof fetchImpl !== 'function' || typeof now !== 'function') {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_ARGUMENT_INVALID');
  }
  boundary = assertReviewedBoundaryDescriptor(boundary);
  const descriptor = validateProbeDescriptor(request);
  if (boundary.origin === descriptor.exactDraftDeployOrigin) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID');
  }
  const body = exactCanonicalRequest(descriptor);
  const requestStartedAt = now();
  if (!(requestStartedAt instanceof Date) || Number.isNaN(requestStartedAt.getTime())) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_ARGUMENT_INVALID');
  }
  let response;
  try {
    response = await fetchImpl(`${boundary.origin}${DRAFT_ACCESS_BOUNDARY_PATH}`,
      requestOptions(body, boundary, strictDraftAccessToken(accessToken)));
  } catch {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_REQUEST_FAILED');
  }
  const responseBody = await responseBytes(
    response,
    DRAFT_ACCESS_PROBE_MAXIMUM_JSON_BYTES,
    'CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_TOO_LARGE'
  );
  assertSecretAbsentFromResponse(
    response,
    responseBody,
    accessToken,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_REFLECTED'
  );
  assertBoundaryProofHeaders(response, boundary, 'CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID');
  assertSafeOuterHeaders(
    response,
    'application/json; charset=utf-8',
    'CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID'
  );
  if (response.status !== 200) fail('CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID');
  const text = strictUtf8(responseBody, 'CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID');
  let value;
  try { value = JSON.parse(text); }
  catch { fail('CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID'); }
  if (!isPlainObject(value) || text !== JSON.stringify(value)) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_NONCANONICAL');
  }
  const responseObservedAt = now();
  if (!(responseObservedAt instanceof Date) || Number.isNaN(responseObservedAt.getTime())) {
    fail('CNYOS_CONTROLLER_DRAFT_PROBE_ARGUMENT_INVALID');
  }
  return validateExactDraftProbeEnvelope(
    value,
    descriptor,
    responseObservedAt,
    requestStartedAt
  );
}

async function assertBearerRequired({
  fetchImpl,
  boundary,
  descriptor,
  invalidBearer = null,
  secretTokens = []
}) {
  const requestBody = exactCanonicalRequest(descriptor);
  let response;
  try {
    response = await fetchImpl(
      `${boundary.origin}${DRAFT_ACCESS_BOUNDARY_PATH}`,
      requestOptions(requestBody, boundary, invalidBearer)
    );
  } catch {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_PROBE_FAILED');
  }
  const body = await responseBytes(
    response,
    MAX_UNAUTHORIZED_RESPONSE_BYTES,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_RESPONSE_INVALID'
  );
  for (const token of secretTokens) {
    assertSecretAbsentFromResponse(
      response,
      body,
      token,
      'CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_REFLECTED'
    );
  }
  assertBoundaryProofHeaders(
    response,
    boundary,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_RESPONSE_INVALID'
  );
  assertSafeOuterHeaders(
    response,
    'application/json; charset=utf-8',
    'CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_RESPONSE_INVALID'
  );
  if (response.status !== 401 || response.redirected === true ||
    response.headers.get('location') !== null ||
    !/^Bearer(?:\s|$)/i.test(String(response.headers.get('www-authenticate') || '')) ||
    strictUtf8(body, 'CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_RESPONSE_INVALID') !==
      '{"schemaVersion":1,"error":"unauthorized"}') {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_RESPONSE_INVALID');
  }
}

export async function readExactNetlifyDraftFile({
  fetchImpl = fetch,
  boundary,
  accessToken,
  controllerRunId,
  netlifySiteId,
  netlifyDeployId,
  exactDraftDeployOrigin,
  path: requestPath,
  expectedSize,
  expectedSha256
}) {
  boundary = assertReviewedBoundaryDescriptor(boundary);
  const descriptor = validateProbeDescriptor({
    controllerRunId,
    netlifySiteId,
    netlifyDeployId,
    exactDraftDeployOrigin,
    requestNonce: freshRequestNonce(randomBytes),
    method: 'GET',
    path: requestPath,
    expectedStatus: 200,
    maximumBodyBytes: expectedSize
  });
  if (boundary.origin === descriptor.exactDraftDeployOrigin) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID');
  }
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 1 || expectedSize > MAX_FILE_BYTES) {
    fail('CNYOS_CONTROLLER_DRAFT_FILE_EXPECTATION_INVALID');
  }
  const expectedDigest = exactSha256(
    expectedSha256,
    'CNYOS_CONTROLLER_DRAFT_FILE_EXPECTATION_INVALID'
  );
  const requestValue = Object.freeze({
    schemaVersion: 1,
    operation: 'read_exact_netlify_draft_file',
    controllerRunId: descriptor.controllerRunId,
    netlifySiteId: descriptor.netlifySiteId,
    netlifyDeployId: descriptor.netlifyDeployId,
    exactDraftDeployOrigin: descriptor.exactDraftDeployOrigin,
    path: descriptor.path,
    expectedSize,
    expectedSha256: expectedDigest
  });
  const requestBody = JSON.stringify(requestValue);
  let response;
  try {
    response = await fetchImpl(
      `${boundary.origin}${DRAFT_ACCESS_BOUNDARY_PATH}`,
      requestOptions(requestBody, boundary, strictDraftAccessToken(accessToken),
        'application/octet-stream')
    );
  } catch {
    fail('CNYOS_CONTROLLER_DRAFT_FILE_REQUEST_FAILED');
  }
  const body = await responseBytes(
    response,
    expectedSize,
    'CNYOS_CONTROLLER_DRAFT_FILE_TOO_LARGE'
  );
  assertSecretAbsentFromResponse(
    response,
    body,
    accessToken,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_REFLECTED'
  );
  assertBoundaryProofHeaders(response, boundary, 'CNYOS_CONTROLLER_DRAFT_FILE_RESPONSE_INVALID');
  assertSafeOuterHeaders(
    response,
    'application/octet-stream',
    'CNYOS_CONTROLLER_DRAFT_FILE_RESPONSE_INVALID'
  );
  if (response.status !== 200 || body.byteLength !== expectedSize || sha256(body) !== expectedDigest) {
    fail('CNYOS_CONTROLLER_DRAFT_FILE_BYTES_MISMATCH');
  }
  return Object.freeze({ size: body.byteLength, sha256: sha256(body) });
}

async function loadCanonicalEvidence(filename, expectedSha256, code) {
  const bytes = await readFileBounded(filename, 4 * 1024 * 1024, code);
  if (sha256(bytes) !== exactSha256(expectedSha256, `${code}_DIGEST_INVALID`)) {
    fail(`${code}_DIGEST_MISMATCH`);
  }
  const text = strictUtf8(bytes, code);
  let value;
  try { value = JSON.parse(text); }
  catch { fail(code); }
  if (!isPlainObject(value) || text !== `${JSON.stringify(value, null, 2)}\n`) fail(code);
  return Object.freeze({ bytes, value, sha256: sha256(bytes) });
}

function assertSourceAndArtifact(value, bundle, code) {
  if (!isPlainObject(value.source) || !isPlainObject(value.artifact) ||
    value.source.repository !== bundle.manifest.sourceRepository ||
    value.source.commit !== bundle.manifest.candidateCommit ||
    value.source.tree !== bundle.manifest.candidateTree ||
    value.source.functionSourceTree !== bundle.manifest.functionSourceTree ||
    value.artifact.producerManifestSha256 !== bundle.manifestSha256 ||
    value.artifact.artifactSha256 !== bundle.manifest.artifactSha256) fail(code);
}

function controllerEvidenceMaximumAgeMilliseconds(code) {
  const minutes = POLICY.authorization?.maximumLifetimeMinutes;
  if (!Number.isSafeInteger(minutes) || minutes < 1 || minutes > 60) fail(code);
  return minutes * 60 * 1000;
}

function assertFreshPreflight(preflight, runtime, bundle, observedAt) {
  const code = 'CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_INVALID';
  if (preflight.schemaVersion !== 1 ||
    preflight.evidenceType !== 'cnyos_staging_controller_preflight' ||
    preflight.authorization !== false || preflight.scope !== 'cnyos_staging_only' ||
    preflight.productionAuthorization !== false ||
    preflight.controllerRepository !== runtime.repository ||
    preflight.controllerRef !== runtime.ref || preflight.controllerCommit !== runtime.commit ||
    preflight.controllerRunId !== runtime.runId ||
    preflight.dispatchNonce !== bundle.manifest.dispatchNonce) fail(code);
  assertSourceAndArtifact(preflight, bundle, code);
  assertPolicyTarget(preflight.target, code);
  const exclusion = preflight.targetSiteAndPublisherExclusion;
  if (!isPlainObject(exclusion) ||
    exclusion.productionNetlifySiteId !== POLICY.productionDenylist.netlifySiteId ||
    exclusion.productionNetlifyOrigin !== POLICY.productionDenylist.netlifyOrigin) fail(code);
  for (const field of [
    'authorizationExpiresAt',
    'deploymentControlBoundaryExpiresAt',
    'principalProofExpiresAt',
    'liveNetlifyAuthorityBoundaryExpiresAt'
  ]) {
    if (canonicalIsoTimestamp(preflight[field], code) <= observedAt) fail(code);
  }
  recentCanonicalTimestamp(
    preflight.capturedAt,
    observedAt,
    controllerEvidenceMaximumAgeMilliseconds(code),
    code
  );
  return exactDeployId(
    preflight.previousPublishedDeploy?.id,
    'CNYOS_CONTROLLER_ROLLBACK_DEPLOY_ID_INVALID'
  );
}

function assertDraftReceipt(receipt, runtime, bundle, preflight, previousDeployId, observedAt) {
  const code = 'CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID';
  if (receipt.schemaVersion !== 1 ||
    receipt.evidenceType !== 'cnyos_staging_controller_draft_deploy_receipt' ||
    receipt.authorization !== false || receipt.promotionAuthorization !== false ||
    receipt.scope !== 'cnyos_staging_only' || receipt.productionAuthorization !== false ||
    receipt.controllerRepository !== runtime.repository || receipt.controllerRef !== runtime.ref ||
    receipt.controllerCommit !== runtime.commit || receipt.controllerRunId !== runtime.runId ||
    receipt.dispatchNonce !== bundle.manifest.dispatchNonce ||
    receipt.preflightEvidenceSha256 !== preflight.sha256 ||
    receipt.previousDeployId !== previousDeployId ||
    receipt.currentPublishedDeployId !== previousDeployId ||
    receipt.netlifyCliVersion !== POLICY.publishing.netlifyCliVersion) fail(code);
  assertSourceAndArtifact(receipt, bundle, code);
  assertPolicyTarget(receipt.target, code);
  const recordedAt = recentCanonicalTimestamp(
    receipt.recordedAt,
    observedAt,
    controllerEvidenceMaximumAgeMilliseconds(code),
    code
  );
  if (recordedAt < canonicalIsoTimestamp(preflight.value.capturedAt, code)) fail(code);
  const deployId = exactDeployId(receipt.draftDeployId, code);
  const origin = safeOrigin(receipt.exactDeployOrigin, code);
  if (deployId === previousDeployId || receipt.draftDeployId !== deployId ||
    receipt.exactDeployOrigin !== origin || origin !== exactDraftOrigin(deployId) ||
    !isPlainObject(receipt.deploy) || receipt.deploy.id !== deployId ||
    receipt.deploy.siteId !== POLICY.target.netlifySiteId || receipt.deploy.state !== 'ready' ||
    receipt.deploy.context !== 'production' || receipt.deploy.exactDeployOrigin !== origin ||
    receipt.deploy.commitRef !== bundle.manifest.candidateCommit ||
    receipt.deploy.title !== deploymentMarker(
      runtime.runId,
      bundle.manifest.dispatchNonce,
      bundle.manifest.candidateCommit
    ) ||
    receipt.deploy.publishedAt !== null ||
    !isPlainObject(receipt.sanitizedCliReceipt) ||
    receipt.sanitizedCliReceipt.deployId !== deployId ||
    receipt.sanitizedCliReceipt.exactDeployOrigin !== origin ||
    receipt.sanitizedCliReceipt.siteId !== POLICY.target.netlifySiteId ||
    receipt.sanitizedCliReceipt.siteName !== POLICY.target.netlifySiteName) fail(code);
  return Object.freeze({ deployId, origin });
}

function exactCommaSeparatedSet(value, expected, code) {
  if (typeof value !== 'string') fail(code);
  const actual = value.split(',').map(item => item.trim().toLowerCase()).filter(Boolean).sort();
  const wanted = [...expected].map(item => item.toLowerCase()).sort();
  if (actual.length !== wanted.length || actual.some((item, index) => item !== wanted[index])) fail(code);
}

function assertIndexSecurityHeaders(headers) {
  const code = 'CNYOS_CONTROLLER_DRAFT_SECURITY_HEADERS_INVALID';
  exactCommaSeparatedSet(
    headers['cache-control'],
    ['no-store', 'no-cache', 'must-revalidate', 'max-age=0'],
    code
  );
  exactCommaSeparatedSet(headers['x-robots-tag'], ['noindex', 'nofollow', 'noarchive'], code);
  exactCommaSeparatedSet(
    headers['permissions-policy'],
    ['camera=(self)', 'geolocation=()', 'microphone=()'],
    code
  );
  const contentType = String(headers['content-type'] || '').toLowerCase();
  if (contentType !== 'text/html; charset=utf-8' || headers.location !== null ||
    String(headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff' ||
    String(headers['x-frame-options'] || '').toUpperCase() !== 'SAMEORIGIN' ||
    String(headers['referrer-policy'] || '').toLowerCase() !== 'no-referrer') fail(code);
}

export async function verifyPrivateDraftAccessBoundary({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
  verifyProducerBundleImpl = verifyProducerBundle
} = {}) {
  assertDraftAccessCredentialIsolation(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_TIME_INVALID');
  }
  const runtime = assertControllerRuntime(env);
  const boundary = reviewedPrivateDraftAccessBoundary();
  const configuredBoundaryOrigin = safeOrigin(
    env.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL,
    'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID'
  );
  if (env.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL !== configuredBoundaryOrigin ||
    configuredBoundaryOrigin !== boundary.origin) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID');
  }
  const bundle = await verifyProducerBundleImpl({ env });
  if (!bundle || !isPlainObject(bundle.manifest) ||
    !/^[0-9a-f]{64}$/.test(String(bundle.manifestSha256 || ''))) {
    fail('CNYOS_CONTROLLER_PRODUCER_BUNDLE_INVALID');
  }
  const preflight = await loadCanonicalEvidence(
    required(env.CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_INVALID'
  );
  const previousDeployId = assertFreshPreflight(
    preflight.value,
    runtime,
    bundle,
    observedAt
  );
  const receipt = await loadCanonicalEvidence(
    required(env.CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID'
  );
  const { deployId, origin } = assertDraftReceipt(
    receipt.value,
    runtime,
    bundle,
    preflight,
    previousDeployId,
    observedAt
  );
  if (boundary.origin === origin) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID');
  }
  const indexEntries = bundle.manifest.files.filter(item => item?.path === 'payload/dist/index.html');
  if (indexEntries.length !== 1 || !Number.isSafeInteger(indexEntries[0].size) ||
    indexEntries[0].size < 1 || indexEntries[0].size > MAX_FILE_BYTES ||
    !/^[0-9a-f]{64}$/.test(String(indexEntries[0].sha256 || ''))) {
    fail('CNYOS_CONTROLLER_DRAFT_INDEX_EXPECTATION_INVALID');
  }
  const indexEntry = indexEntries[0];
  const accessToken = strictDraftAccessToken(env.CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN);
  const descriptorFields = Object.freeze({
    controllerRunId: runtime.runId,
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyDeployId: deployId,
    exactDraftDeployOrigin: origin,
    method: 'GET',
    path: '/index.html',
    expectedStatus: 200,
    maximumBodyBytes: indexEntry.size
  });
  const invalidBearer = `${INVALID_BEARER_PREFIX}${sha256(JSON.stringify({
    controllerRunId: runtime.runId,
    netlifyDeployId: deployId
  }))}`;
  if (invalidBearer === accessToken) fail('CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_INVALID');
  await assertBearerRequired({
    fetchImpl,
    boundary,
    descriptor: validateProbeDescriptor({
      ...descriptorFields,
      requestNonce: freshRequestNonce(randomBytesImpl)
    }),
    secretTokens: [accessToken]
  });
  await assertBearerRequired({
    fetchImpl,
    boundary,
    descriptor: validateProbeDescriptor({
      ...descriptorFields,
      requestNonce: freshRequestNonce(randomBytesImpl)
    }),
    invalidBearer,
    secretTokens: [accessToken, invalidBearer]
  });
  const descriptor = validateProbeDescriptor({
    ...descriptorFields,
    requestNonce: freshRequestNonce(randomBytesImpl)
  });
  const probe = await probeExactNetlifyDraftRequest({
    fetchImpl,
    boundary,
    accessToken,
    now,
    ...descriptor
  });
  if (probe.upstreamStatus !== 200 || probe.upstreamBodySize !== indexEntry.size ||
    probe.upstreamBodySha256 !== indexEntry.sha256) {
    fail('CNYOS_CONTROLLER_DRAFT_INDEX_CONTENT_MISMATCH');
  }
  assertIndexSecurityHeaders(probe.upstreamHeaders);
  await readExactNetlifyDraftFile({
    fetchImpl,
    boundary,
    accessToken,
    controllerRunId: runtime.runId,
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyDeployId: deployId,
    exactDraftDeployOrigin: origin,
    path: '/index.html',
    expectedSize: indexEntry.size,
    expectedSha256: indexEntry.sha256
  });
  const completedAt = now();
  if (!(completedAt instanceof Date) || Number.isNaN(completedAt.getTime()) ||
    completedAt < observedAt) fail('CNYOS_CONTROLLER_TIME_INVALID');
  assertFreshPreflight(preflight.value, runtime, bundle, completedAt);
  assertDraftReceipt(
    receipt.value,
    runtime,
    bundle,
    preflight,
    previousDeployId,
    completedAt
  );
  assertCanary(
    probe.canary,
    descriptor.requestNonce,
    observedAt,
    completedAt,
    'CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID'
  );
  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_private_draft_access_boundary',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: completedAt.toISOString(),
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerRunId: runtime.runId,
    source: Object.freeze({
      repository: bundle.manifest.sourceRepository,
      commit: bundle.manifest.candidateCommit,
      tree: bundle.manifest.candidateTree
    }),
    artifact: Object.freeze({ artifactSha256: bundle.manifest.artifactSha256 }),
    target: Object.freeze({
      netlifySiteId: POLICY.target.netlifySiteId,
      netlifyOrigin: POLICY.target.netlifyOrigin
    }),
    preflightEvidenceSha256: preflight.sha256,
    draftReceiptEvidenceSha256: receipt.sha256,
    currentPublishedDeployId: previousDeployId,
    draftDeployId: deployId,
    exactDraftDeployOrigin: origin,
    boundary: Object.freeze({
      origin: boundary.origin,
      policyId: boundary.policyId,
      policySha256: boundary.policySha256,
      endpointPath: DRAFT_ACCESS_BOUNDARY_PATH,
      requestMethod: 'POST',
      authorizationHeaderConsumedAtBoundary: true,
      authorizationHeaderForwardedUpstream: false,
      cookiesForwardedUpstream: false,
      redirectsFollowed: false,
      fixedTargetSiteId: true,
      fixedTargetDeployId: true,
      exactDeployOriginRequired: true,
      candidateRoutingCanChangeUpstreamTarget: false,
      readOperationReturnsOnlyHashBoundUpstreamBytes: true,
      probeOperationReturnsOnlySanitizedMetadata: true,
      secretSerializationPrevented: true
    }),
    canary: Object.freeze({ ...probe.canary })
  });
  if (JSON.stringify(evidence).includes(accessToken)) {
    fail('CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_SERIALIZED');
  }
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({ evidence, evidencePath });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  verifyPrivateDraftAccessBoundary().then(result => {
    process.stdout.write(`${JSON.stringify({
      evidencePath: result.evidencePath,
      draftDeployId: result.evidence.draftDeployId,
      exactDraftDeployOrigin: result.evidence.exactDraftDeployOrigin,
      boundaryPolicyId: result.evidence.boundary.policyId
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message ||
      'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_VERIFICATION_FAILED')}\n`);
    process.exitCode = 1;
  });
}
