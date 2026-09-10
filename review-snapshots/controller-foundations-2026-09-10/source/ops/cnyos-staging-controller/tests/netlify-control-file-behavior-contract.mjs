import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PROBED_HEADER_NAMES,
  REQUIRED_NETLIFY_HEADER_RULES,
  REQUIRED_NETLIFY_REDIRECT_RULES,
  assertRequiredNetlifyControlInventory,
  parseNetlifyHeaders,
  parseNetlifyRedirects,
  probeExactDraftRequest,
  validateNetlifyControlBehaviorEvidence,
  verifyNetlifyControlFileBehavior
} from '../scripts/verify-netlify-control-file-behavior.mjs';
import { POLICY, sha256 } from '../scripts/policy.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = await fs.readFile(
  path.join(packageRoot, 'scripts', 'verify-netlify-control-file-behavior.mjs'),
  'utf8'
);

const headers = parseNetlifyHeaders(Buffer.from([
  '/',
  '  Cache-Control: no-store, no-cache, must-revalidate, max-age=0',
  '',
  '/identity-review.html',
  '  X-Robots-Tag: noindex, nofollow, noarchive',
  '  X-Frame-Options: SAMEORIGIN',
  '  X-Content-Type-Options: nosniff',
  '  Referrer-Policy: no-referrer',
  '',
  '/check-in.html',
  '  Permissions-Policy: camera=(self), microphone=(), geolocation=()',
  ''
].join('\n')));
assert.deepEqual(headers, [
  {
    path: '/',
    headers: { 'cache-control': 'no-store, no-cache, must-revalidate, max-age=0' }
  },
  {
    path: '/identity-review.html',
    headers: {
      'x-robots-tag': 'noindex, nofollow, noarchive',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    }
  },
  {
    path: '/check-in.html',
    headers: { 'permissions-policy': 'camera=(self), microphone=(), geolocation=()' }
  }
]);

for (const invalid of [
  '/*\n  Cache-Control: no-store\n',
  '/a\n  Set-Cookie: bad=true\n',
  '/a\n  Authorization: secret\n',
  '/a\n Cache-Control: no-store\n',
  '/a\n  Cache-Control: no-store\n/a\n  Cache-Control: public\n',
  '/a\n  Cache-Control: no-store\rbroken\n',
  '\ufeff/a\n  Cache-Control: no-store\n'
]) {
  assert.throws(() => parseNetlifyHeaders(Buffer.from(invalid)),
    /CNYOS_CONTROLLER_NETLIFY_HEADERS_CONTROL_FILE_INVALID/);
}

const redirects = parseNetlifyRedirects(Buffer.from([
  '/app.html / 301!',
  '/check-in /check-in.html 301!',
  '/ /index.html 200',
  ''
].join('\n')));
assert.deepEqual(redirects, [
  { from: '/app.html', to: '/', status: 301, force: true },
  { from: '/check-in', to: '/check-in.html', status: 301, force: true },
  { from: '/', to: '/index.html', status: 200, force: false }
]);
assert.doesNotThrow(() => assertRequiredNetlifyControlInventory(
  REQUIRED_NETLIFY_HEADER_RULES,
  REQUIRED_NETLIFY_REDIRECT_RULES
));
assert.throws(() => assertRequiredNetlifyControlInventory(
  REQUIRED_NETLIFY_HEADER_RULES.slice(1),
  REQUIRED_NETLIFY_REDIRECT_RULES
), /CNYOS_CONTROLLER_NETLIFY_HEADERS_REQUIRED_INVENTORY_MISMATCH/);
assert.throws(() => assertRequiredNetlifyControlInventory(
  REQUIRED_NETLIFY_HEADER_RULES,
  REQUIRED_NETLIFY_REDIRECT_RULES.slice(0, -1)
), /CNYOS_CONTROLLER_NETLIFY_REDIRECTS_REQUIRED_INVENTORY_MISMATCH/);

for (const invalid of [
  '/a https://attacker.example/ 301!\n',
  '/* /index.html 200\n',
  '/a /b 404\n',
  '/a /b 301 extra\n',
  '/a /b 301\n/a /c 302\n',
  ' /a /b 301\n',
  '/a\t/b\t301\n'
]) {
  assert.throws(() => parseNetlifyRedirects(Buffer.from(invalid)),
    /CNYOS_CONTROLLER_NETLIFY_REDIRECTS_CONTROL_FILE_INVALID/);
}

const boundaryOrigin = 'https://boundary.reviewed.example';
const boundaryToken = 'B'.repeat(48);
const boundaryPolicyId = 'cnyos-private-draft-access-v1';
const boundaryPolicySha256 = 'd'.repeat(64);
const deployId = 'a'.repeat(24);
const deployOrigin = `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`;
const now = new Date('2026-09-09T03:00:00.000Z');
const requestNonce = Buffer.alloc(32, 0x6e).toString('base64url');
const canary = Object.freeze({
  verifiedAt: now.toISOString(),
  requestNonce,
  candidateFunctionReached: true,
  boundaryCredentialObserved: false,
  authorizationHeaderObserved: false,
  cookiesObserved: false,
  responseReflectedCredential: false
});

function upstreamHeaders(overrides = {}) {
  return Object.fromEntries(PROBED_HEADER_NAMES.map(name => [name, overrides[name] ?? null]));
}

function validValue(overrides = {}) {
  const headersValue = overrides.upstreamHeaders || upstreamHeaders({
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  return {
    schemaVersion: 1,
    operation: 'probe_exact_netlify_draft_request',
    controllerRunId: '123456',
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyDeployId: deployId,
    exactDraftDeployOrigin: deployOrigin,
    method: 'HEAD',
    path: '/index.html',
    expectedStatus: null,
    upstreamStatus: 200,
    upstreamLocation: headersValue.location,
    upstreamHeaders: headersValue,
    upstreamBodySize: 0,
    upstreamBodySha256: sha256(Buffer.alloc(0)),
    canary,
    ...overrides
  };
}

function outerResponse(value, overrides = {}) {
  return new Response(JSON.stringify(value), {
    status: overrides.status ?? 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-cnyos-boundary-policy-id': boundaryPolicyId,
      'x-cnyos-boundary-policy-sha256': boundaryPolicySha256,
      'x-cnyos-upstream-authorization-forwarded': 'false',
      'x-cnyos-upstream-cookies-forwarded': 'false',
      'x-cnyos-upstream-redirect-followed': 'false',
      ...(overrides.headers || {})
    }
  });
}

const commonRequest = Object.freeze({
  boundaryOrigin,
  boundaryToken,
  boundaryPolicyId,
  boundaryPolicySha256,
  controllerRunId: '123456',
  netlifySiteId: POLICY.target.netlifySiteId,
  netlifyDeployId: deployId,
  exactDraftDeployOrigin: deployOrigin,
  method: 'HEAD',
  path: '/index.html',
  expectedStatus: null,
  maximumBodyBytes: 0,
  now: () => now,
  randomBytesImpl: size => Buffer.alloc(size, 0x6e)
});

let observed = null;
const valid = await probeExactDraftRequest(async (url, options) => {
  observed = { url, options };
  return outerResponse(validValue());
}, commonRequest);
assert.equal(valid.upstreamStatus, 200);
assert.equal(observed.url, `${boundaryOrigin}/v1/read-netlify-draft-file`);
assert.equal(observed.options.method, 'POST');
assert.equal(observed.options.redirect, 'error');
assert.equal(observed.options.credentials, 'omit');
assert.equal(observed.options.referrerPolicy, 'no-referrer');
assert.equal(observed.options.cache, 'no-store');
assert.equal(observed.options.headers.Authorization, `Bearer ${boundaryToken}`);
assert.equal(observed.options.headers['Accept-Encoding'], 'identity');
const requestBody = JSON.parse(observed.options.body);
assert.deepEqual(requestBody, {
  schemaVersion: 1,
  operation: 'probe_exact_netlify_draft_request',
  controllerRunId: '123456',
  netlifySiteId: POLICY.target.netlifySiteId,
  netlifyDeployId: deployId,
  exactDraftDeployOrigin: deployOrigin,
  requestNonce,
  method: 'HEAD',
  path: '/index.html',
  expectedStatus: null,
  maximumBodyBytes: 0
});
assert.equal(observed.options.body.includes(boundaryToken), false);
assert.equal(JSON.stringify(valid).includes(boundaryToken), false);

const redirectHeaders = upstreamHeaders({ location: '/check-in.html' });
const redirect = await probeExactDraftRequest(
  async () => outerResponse(validValue({
    method: 'GET',
    path: '/check-in',
    expectedStatus: 301,
    upstreamStatus: 301,
    upstreamLocation: '/check-in.html',
    upstreamHeaders: redirectHeaders,
    upstreamBodySize: 24,
    upstreamBodySha256: 'e'.repeat(64)
  })),
  {
    ...commonRequest,
    method: 'GET',
    path: '/check-in',
    expectedStatus: 301,
    maximumBodyBytes: 1024
  }
);
assert.equal(redirect.upstreamHeaders.location, '/check-in.html');

let invalidOriginCalls = 0;
await assert.rejects(
  probeExactDraftRequest(async () => {
    invalidOriginCalls += 1;
    return outerResponse(validValue());
  }, { ...commonRequest, exactDraftDeployOrigin: POLICY.target.netlifyOrigin }),
  /CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_RESPONSE_INVALID/
);
assert.equal(invalidOriginCalls, 0);

const invalidResponses = [
  outerResponse({ ...validValue(), extra: true }),
  outerResponse(validValue({ upstreamStatus: 700 })),
  outerResponse(validValue({ upstreamBodySize: 1 })),
  outerResponse(validValue({ canary: { ...canary, verifiedAt: '2026-09-09T02:40:00.000Z' } })),
  outerResponse(validValue({
    canary: { ...canary, verifiedAt: '2026-09-09T02:59:59.999Z' }
  })),
  outerResponse(validValue({ canary: { ...canary, requestNonce: 'z'.repeat(43) } })),
  outerResponse(validValue({ canary: { ...canary, authorizationHeaderObserved: true } })),
  outerResponse(validValue(), {
    headers: { 'x-cnyos-upstream-authorization-forwarded': 'true' }
  }),
  outerResponse(validValue(), { headers: { 'x-boundary-debug': boundaryToken } }),
  outerResponse(validValue({ upstreamHeaders: { ...upstreamHeaders(), extra: null } }))
];
for (const response of invalidResponses) {
  await assert.rejects(
    probeExactDraftRequest(async () => response.clone(), commonRequest),
    /CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_RESPONSE_INVALID/
  );
}

const mismatchedExpected = validValue({ expectedStatus: 301, upstreamStatus: 302 });
await assert.rejects(
  probeExactDraftRequest(async () => outerResponse(mismatchedExpected), {
    ...commonRequest,
    expectedStatus: 301
  }),
  /CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_RESPONSE_INVALID/
);

const CONTROLLER_COMMIT = 'c'.repeat(40);
const SOURCE_COMMIT = 'a'.repeat(40);
const SOURCE_TREE = 'b'.repeat(40);
const PREVIOUS_DEPLOY_ID = '9'.repeat(24);
const RUN_ID = '987654321';
const DISPATCH_NONCE = Buffer.alloc(32, 9).toString('base64url');
const CONTROL_NOW = new Date('2026-09-09T03:00:00.000Z');
const reviewedBoundary = Object.freeze({
  origin: boundaryOrigin,
  policyId: boundaryPolicyId,
  policySha256: boundaryPolicySha256
});

function fixtureDigest(label) {
  return crypto.createHash('sha256').update(`control-fixture:${label}`).digest('hex');
}

function pretty(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function headerFile(rules) {
  return `${rules.map(rule => [
    rule.path,
    ...Object.entries(rule.headers).map(([name, value]) =>
      `  ${name.split('-').map(part => part[0].toUpperCase() + part.slice(1)).join('-')}: ${value}`)
  ].join('\n')).join('\n\n')}\n`;
}

function redirectFile(rules) {
  return `${rules.map(rule =>
    `${rule.from}  ${rule.to}  ${rule.status}${rule.force ? '!' : ''}`).join('\n')}\n`;
}

async function writeFixtureEvidence(root, name, value) {
  const filename = path.join(root, name);
  const bytes = Buffer.from(pretty(value));
  await fs.writeFile(filename, bytes, { mode: 0o600 });
  return Object.freeze({ filename, sha256: sha256(bytes) });
}

function controllerSource() {
  return {
    repository: POLICY.sourceRepository,
    commit: SOURCE_COMMIT,
    tree: SOURCE_TREE
  };
}

function commonEvidence() {
  return {
    productionAuthorization: false,
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: CONTROLLER_COMMIT,
    controllerRunId: RUN_ID,
    source: controllerSource(),
    artifact: { artifactSha256: fixtureDigest('artifact') },
    target: { ...POLICY.target }
  };
}

async function createControlFixture({
  headerRules = REQUIRED_NETLIFY_HEADER_RULES,
  redirectRules = REQUIRED_NETLIFY_REDIRECT_RULES,
  mutateBoundary = null
} = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-control-behavior-'));
  const bundleDirectory = path.join(root, 'producer');
  const dist = path.join(bundleDirectory, 'payload', 'dist');
  await fs.mkdir(dist, { recursive: true });
  const headersBytes = Buffer.from(headerFile(headerRules));
  const redirectsBytes = Buffer.from(redirectFile(redirectRules));
  await fs.writeFile(path.join(dist, '_headers'), headersBytes, { mode: 0o600 });
  await fs.writeFile(path.join(dist, '_redirects'), redirectsBytes, { mode: 0o600 });
  const staticPaths = new Set(['index.html']);
  for (const rule of headerRules) {
    if (rule.path !== '/' && !rule.path.startsWith('/api/')) staticPaths.add(rule.path.slice(1));
  }
  for (const rule of redirectRules) {
    if (rule.status === 200) staticPaths.add(rule.to.slice(1) || 'index.html');
  }
  const staticBytes = new Map([...staticPaths].map(name => [
    name,
    Buffer.from(`<fixture path="/${name}">safe</fixture>`)
  ]));
  const files = [
    { path: 'payload/dist/_headers', size: headersBytes.byteLength, sha256: sha256(headersBytes) },
    { path: 'payload/dist/_redirects', size: redirectsBytes.byteLength, sha256: sha256(redirectsBytes) },
    ...[...staticBytes].map(([name, bytes]) => ({
      path: `payload/dist/${name}`,
      size: bytes.byteLength,
      sha256: sha256(bytes)
    }))
  ].sort((left, right) => left.path.localeCompare(right.path));
  const manifestSha256 = fixtureDigest('producer-manifest');
  const manifest = {
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: CONTROLLER_COMMIT,
    controllerRunId: RUN_ID,
    dispatchNonce: DISPATCH_NONCE,
    sourceRepository: POLICY.sourceRepository,
    candidateCommit: SOURCE_COMMIT,
    candidateTree: SOURCE_TREE,
    artifactSha256: fixtureDigest('artifact'),
    files
  };
  const preflight = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_preflight',
    authorization: false,
    scope: 'cnyos_staging_only',
    capturedAt: '2026-09-09T02:55:00.000Z',
    dispatchNonce: DISPATCH_NONCE,
    ...commonEvidence(),
    authorizationExpiresAt: '2026-09-09T03:20:00.000Z',
    deploymentControlBoundaryExpiresAt: '2026-09-09T03:20:00.000Z',
    principalProofExpiresAt: '2026-09-09T03:20:00.000Z',
    liveNetlifyAuthorityBoundaryExpiresAt: '2026-09-09T03:20:00.000Z',
    previousPublishedDeploy: { id: PREVIOUS_DEPLOY_ID }
  };
  const preflightFile = await writeFixtureEvidence(root, 'preflight.json', preflight);
  const receipt = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_draft_deploy_receipt',
    authorization: false,
    promotionAuthorization: false,
    scope: 'cnyos_staging_only',
    recordedAt: '2026-09-09T02:56:00.000Z',
    dispatchNonce: DISPATCH_NONCE,
    ...commonEvidence(),
    previousDeployId: PREVIOUS_DEPLOY_ID,
    currentPublishedDeployId: PREVIOUS_DEPLOY_ID,
    draftDeployId: deployId,
    exactDeployOrigin: deployOrigin,
    preflightEvidenceSha256: preflightFile.sha256
  };
  const receiptFile = await writeFixtureEvidence(root, 'receipt.json', receipt);
  const boundary = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_private_draft_access_boundary',
    status: 'passed',
    scope: 'cnyos_staging_only',
    verifiedAt: '2026-09-09T02:57:00.000Z',
    ...commonEvidence(),
    target: {
      netlifySiteId: POLICY.target.netlifySiteId,
      netlifyOrigin: POLICY.target.netlifyOrigin
    },
    preflightEvidenceSha256: preflightFile.sha256,
    draftReceiptEvidenceSha256: receiptFile.sha256,
    currentPublishedDeployId: PREVIOUS_DEPLOY_ID,
    draftDeployId: deployId,
    exactDraftDeployOrigin: deployOrigin,
    boundary: {
      ...reviewedBoundary,
      endpointPath: '/v1/read-netlify-draft-file',
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
    },
    canary: {
      verifiedAt: '2026-09-09T02:56:30.000Z',
      requestNonce: Buffer.alloc(32, 0x6e).toString('base64url'),
      candidateFunctionReached: true,
      boundaryCredentialObserved: false,
      authorizationHeaderObserved: false,
      cookiesObserved: false,
      responseReflectedCredential: false
    }
  };
  if (mutateBoundary) mutateBoundary(boundary);
  const boundaryFile = await writeFixtureEvidence(root, 'boundary.json', boundary);
  const verification = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_draft_verification',
    status: 'passed',
    authorization: false,
    promotionAuthorization: false,
    scope: 'cnyos_staging_only',
    verifiedAt: '2026-09-09T02:58:00.000Z',
    dispatchNonce: DISPATCH_NONCE,
    ...commonEvidence(),
    previousDeployId: PREVIOUS_DEPLOY_ID,
    currentPublishedDeployId: PREVIOUS_DEPLOY_ID,
    draftDeployId: deployId,
    exactDraftDeployOrigin: deployOrigin,
    privateDraftAccessBoundaryEvidenceSha256: boundaryFile.sha256,
    draftReceiptEvidenceSha256: receiptFile.sha256,
    draftAccessCredentialConsumedOnlyAtBoundary: true,
    draftAccessCredentialForwardedToCandidateOrigin: false
  };
  const verificationFile = await writeFixtureEvidence(root, 'verification.json', verification);
  const output = path.join(root, 'control-behavior.json');
  const workflowPath = POLICY.controller.releaseWorkflowPath;
  const env = {
    CNYOS_CONTROLLER_ACTIVATION_CONTRACT: 'true',
    CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE: 'false',
    GITHUB_REPOSITORY: POLICY.controller.repository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: RUN_ID,
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: POLICY.controller.protectedRef,
    CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: CONTROLLER_COMMIT,
    CNYOS_CONTROLLER_WORKFLOW_PATH: workflowPath,
    GITHUB_WORKFLOW_REF:
      `${POLICY.controller.repository}/${workflowPath}@${POLICY.controller.protectedRef}`,
    GITHUB_ACTOR: 'apisarit',
    GITHUB_TRIGGERING_ACTOR: 'apisarit',
    CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL: boundaryOrigin,
    CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: boundaryToken,
    CNYOS_PRODUCER_BUNDLE_DIRECTORY: bundleDirectory,
    CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: manifestSha256,
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.filename,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.sha256,
    CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH: receiptFile.filename,
    CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256: receiptFile.sha256,
    CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH: boundaryFile.filename,
    CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256: boundaryFile.sha256,
    CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH: verificationFile.filename,
    CNYOS_EXPECTED_DRAFT_VERIFICATION_EVIDENCE_SHA256: verificationFile.sha256,
    CNYOS_CONTROLLER_CONTROL_BEHAVIOR_EVIDENCE_PATH: output
  };
  return {
    root,
    env,
    output,
    staticBytes,
    bundle: { bundleDirectory, manifestSha256, manifest },
    evidenceFiles: { preflightFile, receiptFile, boundaryFile, verificationFile }
  };
}

function controlFetch(fixture, {
  staticHeaderStatus = 200,
  redirectLocationOverride = null
} = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const request = JSON.parse(init.body);
    calls.push({ url, init, request });
    const headerRule = REQUIRED_NETLIFY_HEADER_RULES.find(rule => rule.path === request.path);
    const redirectRule = REQUIRED_NETLIFY_REDIRECT_RULES.find(rule =>
      rule.from === request.path && request.method === 'GET');
    let status;
    let location = null;
    let body = Buffer.alloc(0);
    let observedHeaders = upstreamHeaders();
    if (request.method === 'HEAD') {
      status = staticHeaderStatus;
      observedHeaders = upstreamHeaders(headerRule?.headers || {});
    } else if (headerRule && request.path.startsWith('/api/')) {
      status = request.path === '/api/owner-subscription' ? 403 : 200;
      body = Buffer.from('{"safe":true}');
      observedHeaders = upstreamHeaders({
        ...headerRule.headers,
        'content-type': 'application/json; charset=utf-8'
      });
    } else if (redirectRule) {
      status = redirectRule.status;
      if (status === 200) {
        body = fixture.staticBytes.get(redirectRule.to.slice(1) || 'index.html');
      } else {
        location = redirectLocationOverride ?? redirectRule.to;
      }
      observedHeaders = upstreamHeaders({ location });
    } else {
      throw new Error('unexpected control probe');
    }
    const value = {
      schemaVersion: 1,
      operation: request.operation,
      controllerRunId: request.controllerRunId,
      netlifySiteId: request.netlifySiteId,
      netlifyDeployId: request.netlifyDeployId,
      exactDraftDeployOrigin: request.exactDraftDeployOrigin,
      method: request.method,
      path: request.path,
      expectedStatus: request.expectedStatus,
      upstreamStatus: status,
      upstreamLocation: location,
      upstreamHeaders: observedHeaders,
      upstreamBodySize: body.byteLength,
      upstreamBodySha256: sha256(body),
      canary: {
        verifiedAt: CONTROL_NOW.toISOString(),
        requestNonce: request.requestNonce,
        candidateFunctionReached: true,
        boundaryCredentialObserved: false,
        authorizationHeaderObserved: false,
        cookiesObserved: false,
        responseReflectedCredential: false
      }
    };
    return outerResponse(value);
  };
  return Object.freeze({ calls, fetchImpl });
}

async function runControlFixture(fixture, fetchFixture, now = () => new Date(CONTROL_NOW)) {
  return verifyNetlifyControlFileBehavior({
    env: fixture.env,
    fetchImpl: fetchFixture.fetchImpl,
    now,
    verifyProducerBundleImpl: async () => fixture.bundle,
    reviewedBoundaryOverride: reviewedBoundary
  });
}

{
  const fixture = await createControlFixture();
  try {
    const fetchFixture = controlFetch(fixture);
    let clockReads = 0;
    await assert.rejects(runControlFixture(fixture, fetchFixture, () => {
      const value = clockReads >=
        1 + 2 * (REQUIRED_NETLIFY_HEADER_RULES.length +
          REQUIRED_NETLIFY_REDIRECT_RULES.length)
        ? new Date('2026-09-09T03:11:00.000Z')
        : new Date(CONTROL_NOW);
      clockReads += 1;
      return value;
    }), /CNYOS_CONTROLLER_NETLIFY_CONTROL_EVIDENCE_CHAIN_INVALID/);
    assert.equal(clockReads,
      2 + 2 * (REQUIRED_NETLIFY_HEADER_RULES.length +
        REQUIRED_NETLIFY_REDIRECT_RULES.length),
      'the completed verifier must re-observe time after every sequential probe');
  } finally {
    await disposeControlFixture(fixture);
  }
}

async function disposeControlFixture(fixture) {
  await fs.rm(fixture.root, { recursive: true, force: true });
}

{
  const fixture = await createControlFixture();
  try {
    const fetchFixture = controlFetch(fixture);
    const result = await runControlFixture(fixture, fetchFixture);
    assert.equal(fetchFixture.calls.length,
      REQUIRED_NETLIFY_HEADER_RULES.length + REQUIRED_NETLIFY_REDIRECT_RULES.length);
    assert.equal(result.evidence.headersBehaviorVerified, true);
    assert.equal(result.evidence.redirectsBehaviorVerified, true);
    assert.equal(result.evidence.headerRuleCount, REQUIRED_NETLIFY_HEADER_RULES.length);
    assert.equal(result.evidence.redirectRuleCount, REQUIRED_NETLIFY_REDIRECT_RULES.length);
    assert.equal(result.evidence.headerProbes.filter(item =>
      item.routeKind === 'dynamic_function_response_contract').length, 2);
    assert.equal(result.evidence.headerProbes.filter(item =>
      item.routeKind === 'netlify_static_headers_control').every(item =>
      item.expectedStatus === 200 && item.upstreamStatus === 200), true);
    const validationOptions = {
      runtime: {
        repository: POLICY.controller.repository,
        ref: POLICY.controller.protectedRef,
        commit: CONTROLLER_COMMIT,
        runId: RUN_ID
      },
      bundle: fixture.bundle,
      previousDeployId: PREVIOUS_DEPLOY_ID,
      deployId,
      preflightEvidenceSha256: fixture.evidenceFiles.preflightFile.sha256,
      draftReceiptEvidenceSha256: fixture.evidenceFiles.receiptFile.sha256,
      draftAccessBoundaryEvidenceSha256: fixture.evidenceFiles.boundaryFile.sha256,
      draftVerificationEvidenceSha256: fixture.evidenceFiles.verificationFile.sha256,
      observedAt: new Date(CONTROL_NOW),
      notBefore: new Date('2026-09-09T02:58:00.000Z')
    };
    assert.equal(
      validateNetlifyControlBehaviorEvidence(result.evidence, validationOptions).toISOString(),
      CONTROL_NOW.toISOString()
    );
    for (const [label, mutate] of [
      ['extra top-level field', value => { value.unreviewed = true; }],
      ['wrong policy digest', value => { value.policySha256 = fixtureDigest('other-policy'); }],
      ['wrong manifest digest', value => {
        value.artifact.producerManifestSha256 = fixtureDigest('other-manifest');
      }],
      ['wrong headers digest', value => { value.artifact.headersSha256 = fixtureDigest('headers'); }],
      ['wrong header count', value => { value.headerRuleCount -= 1; }],
      ['missing header probe', value => { value.headerProbes.pop(); }],
      ['reordered header probes', value => { value.headerProbes.reverse(); }],
      ['wrong observed header digest', value => {
        value.headerProbes[0].observedHeadersSha256 = fixtureDigest('observed-headers');
      }],
      ['extra header probe field', value => { value.headerProbes[0].unreviewed = true; }],
      ['wrong redirect count', value => { value.redirectRuleCount += 1; }],
      ['reordered redirect probes', value => { value.redirectProbes.reverse(); }],
      ['credential-bearing redirect location', value => {
        const probe = value.redirectProbes.find(item => item.expectedStatus !== 200);
        const url = new URL(probe.to, deployOrigin);
        url.username = 'boundary-user';
        url.password = 'boundary-password';
        probe.upstreamLocation = url.href;
      }],
      ['wrong rewrite bytes digest', value => {
        value.redirectProbes.at(-1).upstreamBodySha256 = fixtureDigest('rewrite');
      }],
      ['extra redirect probe field', value => { value.redirectProbes[0].unreviewed = true; }],
      ['credential not boundary-only', value => {
        value.boundaryCredentialConsumedOnlyAtBoundary = false;
      }],
      ['credential forwarded', value => { value.boundaryCredentialForwardedUpstream = true; }],
      ['redirect followed', value => { value.boundaryRedirectsFollowed = true; }],
      ['wrong receipt pointer', value => {
        value.draftReceiptEvidenceSha256 = fixtureDigest('other-receipt');
      }],
      ['verified before draft verification', value => {
        value.verifiedAt = '2026-09-09T02:57:59.999Z';
      }]
    ]) {
      const candidate = structuredClone(result.evidence);
      mutate(candidate);
      assert.throws(
        () => validateNetlifyControlBehaviorEvidence(candidate, validationOptions),
        /CNYOS_CONTROLLER_NETLIFY_CONTROL_BEHAVIOR_EVIDENCE_INVALID/,
        label
      );
    }
    for (const call of fetchFixture.calls) {
      assert.equal(call.url, `${boundaryOrigin}/v1/read-netlify-draft-file`);
      assert.equal(call.init.redirect, 'error');
      assert.equal(call.init.credentials, 'omit');
      assert.equal(call.init.referrerPolicy, 'no-referrer');
      assert.equal(call.init.cache, 'no-store');
      assert.equal(call.init.body.includes(boundaryToken), false);
    }
    const status = await fs.lstat(fixture.output);
    assert.equal(status.isFile(), true);
    assert.equal(status.isSymbolicLink(), false);
    assert.equal(status.mode & 0o777, 0o600);
    const output = await fs.readFile(fixture.output, 'utf8');
    assert.equal(output, pretty(JSON.parse(output)));
    assert.equal(output.includes(boundaryToken), false);
  } finally {
    await disposeControlFixture(fixture);
  }
}

{
  const fixture = await createControlFixture();
  try {
    const firstRedirect = REQUIRED_NETLIFY_REDIRECT_RULES.find(rule => rule.status !== 200);
    assert.ok(firstRedirect);
    const credentialLocation = new URL(firstRedirect.to, deployOrigin);
    credentialLocation.username = 'boundary-user';
    credentialLocation.password = 'boundary-password';
    assert.equal(credentialLocation.origin, deployOrigin);
    assert.equal(credentialLocation.username, 'boundary-user');
    assert.equal(credentialLocation.password, 'boundary-password');
    assert.equal(
      `${credentialLocation.pathname}${credentialLocation.search}${credentialLocation.hash}`,
      firstRedirect.to
    );
    const fetchFixture = controlFetch(fixture, {
      redirectLocationOverride: credentialLocation.href
    });
    await assert.rejects(
      runControlFixture(fixture, fetchFixture),
      error => {
        assert.match(error.message, /CNYOS_CONTROLLER_NETLIFY_REDIRECT_BEHAVIOR_MISMATCH/);
        assert.equal(error.message.includes(credentialLocation.href), false);
        assert.equal(error.message.includes(credentialLocation.username), false);
        assert.equal(error.message.includes(credentialLocation.password), false);
        return true;
      }
    );
    assert.equal(fetchFixture.calls.length, REQUIRED_NETLIFY_HEADER_RULES.length + 1);
    assert.equal(fetchFixture.calls.at(-1).request.path, firstRedirect.from);
    await assert.rejects(fs.lstat(fixture.output), { code: 'ENOENT' });
  } finally {
    await disposeControlFixture(fixture);
  }
}

{
  const fixture = await createControlFixture({
    headerRules: REQUIRED_NETLIFY_HEADER_RULES.slice(1)
  });
  try {
    const fetchFixture = controlFetch(fixture);
    await assert.rejects(runControlFixture(fixture, fetchFixture),
      /CNYOS_CONTROLLER_NETLIFY_HEADERS_REQUIRED_INVENTORY_MISMATCH/);
    assert.equal(fetchFixture.calls.length, 0);
  } finally {
    await disposeControlFixture(fixture);
  }
}

for (const [label, mutateBoundary] of [
  ['wrong boundary schema version', value => { value.schemaVersion = 2; }],
  ['wrong boundary scope', value => { value.scope = 'production'; }],
  ['missing fixed-site claim', value => { delete value.boundary.fixedTargetSiteId; }],
  ['unfixed deploy claim', value => { value.boundary.fixedTargetDeployId = false; }],
  ['mutable deploy-origin claim', value => { value.boundary.exactDeployOriginRequired = false; }],
  ['candidate routing claim', value => {
    value.boundary.candidateRoutingCanChangeUpstreamTarget = true;
  }],
  ['unbounded read-operation claim', value => {
    value.boundary.readOperationReturnsOnlyHashBoundUpstreamBytes = false;
  }],
  ['unsanitized probe-operation claim', value => {
    value.boundary.probeOperationReturnsOnlySanitizedMetadata = false;
  }],
  ['secret serialization claim', value => { value.boundary.secretSerializationPrevented = false; }],
  ['incomplete canary', value => { delete value.canary.verifiedAt; }],
  ['candidate canary not reached', value => { value.canary.candidateFunctionReached = false; }],
  ['credential-observing canary', value => { value.canary.boundaryCredentialObserved = true; }],
  ['extra boundary field', value => { value.boundary.unreviewed = true; }]
]) {
  const fixture = await createControlFixture({ mutateBoundary });
  try {
    const fetchFixture = controlFetch(fixture);
    await assert.rejects(
      runControlFixture(fixture, fetchFixture),
      /CNYOS_CONTROLLER_NETLIFY_CONTROL_EVIDENCE_CHAIN_INVALID/,
      label
    );
    assert.equal(fetchFixture.calls.length, 0, label);
  } finally {
    await disposeControlFixture(fixture);
  }
}

{
  const fixture = await createControlFixture();
  try {
    const fetchFixture = controlFetch(fixture, { staticHeaderStatus: 404 });
    await assert.rejects(runControlFixture(fixture, fetchFixture),
      /CNYOS_CONTROLLER_NETLIFY_CONTROL_BOUNDARY_RESPONSE_INVALID/);
  } finally {
    await disposeControlFixture(fixture);
  }
}

{
  const fixture = await createControlFixture();
  try {
    await fs.appendFile(fixture.evidenceFiles.verificationFile.filename, ' ');
    const fetchFixture = controlFetch(fixture);
    await assert.rejects(runControlFixture(fixture, fetchFixture),
      /CNYOS_CONTROLLER_NETLIFY_CONTROL_DRAFT_VERIFICATION_EVIDENCE_INVALID/);
    assert.equal(fetchFixture.calls.length, 0);
  } finally {
    await disposeControlFixture(fixture);
  }
}

for (const credentialName of [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_DATABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'PGPASSWORD',
  'DATABASE_URL'
]) {
  let producerReads = 0;
  let networkCalls = 0;
  await assert.rejects(verifyNetlifyControlFileBehavior({
    env: { [credentialName]: '' },
    fetchImpl: async () => { networkCalls += 1; },
    verifyProducerBundleImpl: async () => { producerReads += 1; }
  }), /CNYOS_CONTROLLER_NETLIFY_CONTROL_AUTHORITY_CORESIDENCY_FORBIDDEN/);
  assert.equal(producerReads, 0);
  assert.equal(networkCalls, 0);
}

assert.match(source, /operation: 'probe_exact_netlify_draft_request'/);
assert.match(source, /method: 'HEAD'/);
assert.match(source, /method: 'GET'/);
assert.match(source, /headersBehaviorVerified: true/);
assert.match(source, /redirectsBehaviorVerified: true/);
assert.match(source, /authorization: false/);
assert.match(source, /promotionAuthorization: false/);
assert.match(source, /productionAuthorization: false/);
assert.match(source, /boundaryCredentialForwardedUpstream: false/);
assert.doesNotMatch(source, /fetchImpl\(chain\.deployOrigin/);
assert.doesNotMatch(source, /netlify deploy|\/deploys\/|\/sites\//);
assert.equal((source.match(/'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'/g) || []).length, 1);

process.stdout.write('CNYOS activation contract netlify-control-file-behavior: passed\n');
