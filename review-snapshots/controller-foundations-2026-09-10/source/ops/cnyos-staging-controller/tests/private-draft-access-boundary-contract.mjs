import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  POLICY as SOURCE_POLICY,
  sha256 as sourceSha256
} from '../scripts/policy.mjs';

assert.notEqual(
  process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE,
  'true',
  'private draft boundary activation contract must remain credential-free'
);

const packageRoot = path.resolve(import.meta.dirname, '..');
const temporaryRoot = await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-private-draft-boundary-contract-')
);
const isolatedRoot = path.join(temporaryRoot, 'activated-controller');
const isolatedScripts = path.join(isolatedRoot, 'scripts');
await fs.mkdir(isolatedScripts, { recursive: true, mode: 0o700 });
await fs.writeFile(
  path.join(isolatedRoot, 'package.json'),
  '{"private":true,"type":"module"}\n',
  { flag: 'wx', mode: 0o600 }
);
for (const name of [
  'policy.mjs',
  'verify-producer-bundle.mjs',
  'private-draft-access-boundary.mjs'
]) {
  await fs.copyFile(path.join(packageRoot, 'scripts', name), path.join(isolatedScripts, name));
}

const boundaryOrigin = 'https://cnyos-private-draft-reader.example.test';
const boundaryPolicyId = 'cnyos-private-draft-access-v1';
const boundaryPolicySha256 = sourceSha256('offline-private-draft-boundary-policy-v1');
const sourcePolicyRaw = await fs.readFile(path.join(packageRoot, 'controller-policy.json'), 'utf8');
const isolatedPolicy = structuredClone(SOURCE_POLICY);
isolatedPolicy.privateDraftAccessBoundary = {
  origin: boundaryOrigin,
  policyId: boundaryPolicyId,
  policySha256: boundaryPolicySha256
};
const isolatedPolicyRaw = `${JSON.stringify(isolatedPolicy, null, 2)}\n`;
const restoredPolicy = structuredClone(isolatedPolicy);
restoredPolicy.privateDraftAccessBoundary =
  structuredClone(SOURCE_POLICY.privateDraftAccessBoundary);
assert.deepEqual(
  restoredPolicy,
  JSON.parse(sourcePolicyRaw),
  'isolated policy may replace only the reviewed private-draft boundary block'
);
await fs.writeFile(
  path.join(isolatedRoot, 'controller-policy.json'),
  isolatedPolicyRaw,
  { flag: 'wx', mode: 0o600 }
);

const boundaryModule = await import(
  `${pathToFileURL(path.join(isolatedScripts, 'private-draft-access-boundary.mjs')).href}?contract=1`
);
const isolatedPolicyModule = await import(
  `${pathToFileURL(path.join(isolatedScripts, 'policy.mjs')).href}?contract=1`
);
const {
  DRAFT_ACCESS_BOUNDARY_PATH,
  DRAFT_ACCESS_FORBIDDEN_ENVIRONMENT_NAMES,
  PROBE_RESPONSE_KEYS,
  PROBE_UPSTREAM_HEADER_KEYS,
  probeExactNetlifyDraftRequest,
  validateExactDraftProbeEnvelope,
  verifyPrivateDraftAccessBoundary
} = boundaryModule;
const { POLICY, sha256 } = isolatedPolicyModule;

const observedAt = new Date('2026-09-09T02:00:00.000Z');
const expiresAt = new Date(observedAt.getTime() + 20 * 60 * 1000).toISOString();
const recordedAt = new Date(observedAt.getTime() - 60 * 1000).toISOString();
const controllerCommit = 'a'.repeat(40);
const candidateCommit = 'b'.repeat(40);
const candidateTree = 'c'.repeat(40);
const functionSourceTree = 'd'.repeat(40);
const producerManifestSha256 = 'e'.repeat(64);
const artifactSha256 = 'f'.repeat(64);
const previousDeployId = '1'.repeat(24);
const draftDeployId = '2'.repeat(24);
const draftDeployOrigin = `https://${draftDeployId}--${POLICY.target.netlifySiteName}.netlify.app`;
const dispatchNonce = Buffer.alloc(32, 0x63).toString('base64url');
const requestNonce = Buffer.alloc(32, 0x6e).toString('base64url');
const boundaryToken = `offline-boundary-token.${'x'.repeat(48)}`;
const indexBytes = Buffer.from('<!doctype html><title>CNYOS boundary contract</title>\n');
const indexSha256 = sha256(indexBytes);
const runtime = Object.freeze({
  GITHUB_REPOSITORY: POLICY.controller.repository,
  CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
  GITHUB_RUN_ID: '9001001',
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_REF_PROTECTED: 'true',
  CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
  GITHUB_REF: POLICY.controller.protectedRef,
  GITHUB_SHA: controllerCommit,
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
  GITHUB_WORKFLOW_REF:
    `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
  GITHUB_ACTOR: 'security-reviewer',
  GITHUB_TRIGGERING_ACTOR: 'security-reviewer',
  CNYOS_DISPATCH_NONCE: dispatchNonce,
  CNYOS_CANDIDATE_SHA: candidateCommit
});

const fakeBundle = Object.freeze({
  bundleDirectory: '/offline/producer-bundle',
  manifestPath: '/offline/producer-bundle/producer-manifest.json',
  manifestBytes: Buffer.from('{}'),
  manifestSha256: producerManifestSha256,
  manifest: Object.freeze({
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit,
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerRunAttempt: 1,
    dispatchNonce,
    sourceRepository: POLICY.sourceRepository,
    candidateCommit,
    candidateTree,
    functionSourceTree,
    artifactSha256,
    files: Object.freeze([
      Object.freeze({
        path: 'payload/dist/index.html',
        size: indexBytes.byteLength,
        sha256: indexSha256
      })
    ])
  })
});

function preflightFixture() {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_preflight',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    capturedAt: recordedAt,
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit,
    controllerRunId: runtime.GITHUB_RUN_ID,
    dispatchNonce,
    source: {
      repository: POLICY.sourceRepository,
      commit: candidateCommit,
      tree: candidateTree,
      functionSourceTree
    },
    artifact: {
      producerManifestSha256,
      artifactSha256
    },
    target: structuredClone(POLICY.target),
    targetSiteAndPublisherExclusion: {
      productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin
    },
    authorizationExpiresAt: expiresAt,
    deploymentControlBoundaryExpiresAt: expiresAt,
    principalProofExpiresAt: expiresAt,
    liveNetlifyAuthorityBoundaryExpiresAt: expiresAt,
    previousPublishedDeploy: { id: previousDeployId }
  };
}

function receiptFixture(preflightEvidenceSha256) {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_draft_deploy_receipt',
    authorization: false,
    promotionAuthorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    recordedAt,
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit,
    controllerRunId: runtime.GITHUB_RUN_ID,
    dispatchNonce,
    source: {
      repository: POLICY.sourceRepository,
      commit: candidateCommit,
      tree: candidateTree,
      functionSourceTree
    },
    artifact: {
      producerManifestSha256,
      artifactSha256
    },
    target: structuredClone(POLICY.target),
    previousDeployId,
    currentPublishedDeployId: previousDeployId,
    draftDeployId,
    exactDeployOrigin: draftDeployOrigin,
    deploy: {
      id: draftDeployId,
      siteId: POLICY.target.netlifySiteId,
      state: 'ready',
      context: 'production',
      commitRef: candidateCommit,
      title: `CNYOS-STAGING-CONTROLLER:${runtime.GITHUB_RUN_ID}:${dispatchNonce}:${candidateCommit}`,
      exactDeployOrigin: draftDeployOrigin,
      publishedAt: null
    },
    netlifyCliVersion: POLICY.publishing.netlifyCliVersion,
    cliReceiptSha256: '4'.repeat(64),
    sanitizedCliReceipt: {
      deployId: draftDeployId,
      exactDeployOrigin: draftDeployOrigin,
      siteId: POLICY.target.netlifySiteId,
      siteName: POLICY.target.netlifySiteName
    },
    preflightEvidenceSha256,
    draftGateEvidenceSha256: '5'.repeat(64)
  };
}

let fixtureSequence = 0;
async function writeCanonicalJson(directory, name, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  const filePath = path.join(directory, name);
  await fs.writeFile(filePath, bytes, { flag: 'wx', mode: 0o600 });
  return Object.freeze({ path: filePath, sha256: sha256(bytes), bytes });
}

async function createFixture({ mutatePreflight = () => {}, mutateReceipt = () => {} } = {}) {
  fixtureSequence += 1;
  const directory = path.join(temporaryRoot, `case-${fixtureSequence}`);
  await fs.mkdir(directory, { mode: 0o700 });
  const preflight = preflightFixture();
  mutatePreflight(preflight);
  const preflightFile = await writeCanonicalJson(directory, 'preflight.json', preflight);
  const receipt = receiptFixture(preflightFile.sha256);
  mutateReceipt(receipt);
  const receiptFile = await writeCanonicalJson(directory, 'draft-receipt.json', receipt);
  return {
    directory,
    preflight,
    receipt,
    outputPath: path.join(directory, 'draft-access-boundary.json'),
    env: {
      ...runtime,
      CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL: boundaryOrigin,
      CNYOS_PRODUCER_BUNDLE_DIRECTORY: '/offline/producer-bundle',
      CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: producerManifestSha256,
      CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.path,
      CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.sha256,
      CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH: receiptFile.path,
      CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256: receiptFile.sha256,
      CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: boundaryToken,
      CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH:
        path.join(directory, 'draft-access-boundary.json')
    }
  };
}

function proofHeaders(extra = {}) {
  return {
    'x-cnyos-boundary-policy-id': boundaryPolicyId,
    'x-cnyos-boundary-policy-sha256': boundaryPolicySha256,
    'x-cnyos-upstream-authorization-forwarded': 'false',
    'x-cnyos-upstream-cookies-forwarded': 'false',
    'x-cnyos-upstream-redirect-followed': 'false',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extra
  };
}

function probeHeaders() {
  return {
    'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
    'content-type': 'text/html; charset=UTF-8',
    location: null,
    'permissions-policy': 'camera=(self), geolocation=(), microphone=()',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'SAMEORIGIN',
    'x-robots-tag': 'noindex, nofollow, noarchive'
  };
}

function probeEnvelope(request) {
  return {
    schemaVersion: 1,
    operation: 'probe_exact_netlify_draft_request',
    controllerRunId: request.controllerRunId,
    netlifySiteId: request.netlifySiteId,
    netlifyDeployId: request.netlifyDeployId,
    exactDraftDeployOrigin: request.exactDraftDeployOrigin,
    method: request.method,
    path: request.path,
    expectedStatus: request.expectedStatus,
    upstreamStatus: 200,
    upstreamLocation: null,
    upstreamHeaders: probeHeaders(),
    upstreamBodySize: indexBytes.byteLength,
    upstreamBodySha256: indexSha256,
    canary: {
      verifiedAt: observedAt.toISOString(),
      requestNonce: request.requestNonce,
      candidateFunctionReached: true,
      boundaryCredentialObserved: false,
      authorizationHeaderObserved: false,
      cookiesObserved: false,
      responseReflectedCredential: false
    }
  };
}

function unauthorizedResponse({ status = 401, headers = {}, body } = {}) {
  return new Response(body ?? '{"schemaVersion":1,"error":"unauthorized"}', {
    status,
    headers: proofHeaders({
      'content-type': 'application/json; charset=utf-8',
      'www-authenticate': 'Bearer realm="cnyos-private-draft-access-boundary"',
      ...headers
    })
  });
}

function assertRequestTransport(url, options) {
  assert.equal(url, `${boundaryOrigin}${DRAFT_ACCESS_BOUNDARY_PATH}`);
  assert.equal(options.method, 'POST');
  assert.equal(options.redirect, 'error');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.headers.Cookie, undefined);
  assert.equal(options.headers.cookie, undefined);
  assert.equal(options.headers['X-CNYOS-Boundary-Policy-Id'], boundaryPolicyId);
  assert.equal(options.headers['X-CNYOS-Boundary-Policy-SHA256'], boundaryPolicySha256);
  assert.equal(String(options.body).includes(boundaryToken), false);
  assert.equal(new URL(url).search, '');
  assert.equal(new URL(url).hash, '');
}

function createBoundaryFetch({
  mutateProbe = () => {},
  probeRaw = null,
  mutateProbeOuterHeaders = () => {},
  readBody = indexBytes,
  readStatus = 200,
  mutateReadOuterHeaders = () => {},
  mutateUnauthorized = () => {}
} = {}) {
  const requests = [];
  const fetchImpl = async (url, options) => {
    assertRequestTransport(url, options);
    const request = JSON.parse(options.body);
    requests.push({ url, options, request });
    const authorization = options.headers.Authorization;
    if (authorization !== `Bearer ${boundaryToken}`) {
      const specification = {};
      mutateUnauthorized(specification, requests.length);
      return unauthorizedResponse(specification);
    }
    if (request.operation === 'probe_exact_netlify_draft_request') {
      assert.deepEqual(Object.keys(request), [
        'schemaVersion', 'operation', 'controllerRunId', 'netlifySiteId',
        'netlifyDeployId', 'exactDraftDeployOrigin', 'requestNonce', 'method', 'path',
        'expectedStatus', 'maximumBodyBytes'
      ]);
      assert.match(request.requestNonce, /^[A-Za-z0-9_-]{43}$/);
      assert.equal(request.schemaVersion, 1);
      assert.equal(request.method, 'GET');
      assert.equal(request.path, '/index.html');
      assert.equal(request.expectedStatus, 200);
      assert.equal(request.maximumBodyBytes, indexBytes.byteLength);
      const envelope = probeEnvelope(request);
      mutateProbe(envelope);
      const outerHeaders = proofHeaders({ 'content-type': 'application/json; charset=utf-8' });
      mutateProbeOuterHeaders(outerHeaders);
      return new Response(probeRaw ?? JSON.stringify(envelope), {
        status: 200,
        headers: outerHeaders
      });
    }
    assert.equal(request.operation, 'read_exact_netlify_draft_file');
    assert.deepEqual(Object.keys(request), [
      'schemaVersion', 'operation', 'controllerRunId', 'netlifySiteId',
      'netlifyDeployId', 'exactDraftDeployOrigin', 'path', 'expectedSize',
      'expectedSha256'
    ]);
    assert.equal(request.path, '/index.html');
    assert.equal(request.expectedSize, indexBytes.byteLength);
    assert.equal(request.expectedSha256, indexSha256);
    const outerHeaders = proofHeaders({ 'content-type': 'application/octet-stream' });
    mutateReadOuterHeaders(outerHeaders);
    return new Response(readBody, { status: readStatus, headers: outerHeaders });
  };
  return Object.freeze({ requests, fetchImpl });
}

async function runBoundary(fixture, fetchImpl) {
  let verifierCalls = 0;
  let nonceCalls = 0;
  const result = await verifyPrivateDraftAccessBoundary({
    env: fixture.env,
    fetchImpl,
    now: () => new Date(observedAt),
    randomBytesImpl: size => {
      nonceCalls += 1;
      return Buffer.alloc(size, nonceCalls);
    },
    verifyProducerBundleImpl: async ({ env }) => {
      verifierCalls += 1;
      assert.equal(env, fixture.env);
      return fakeBundle;
    }
  });
  assert.equal(verifierCalls, 1);
  assert.equal(nonceCalls, 3);
  return result;
}

const originalFetch = globalThis.fetch;
let globalFetchCalls = 0;
globalThis.fetch = async () => {
  globalFetchCalls += 1;
  throw new Error('CNYOS_TEST_FORBIDS_LIVE_NETWORK');
};

try {
  assert.deepEqual(Object.keys(probeEnvelope({
    controllerRunId: runtime.GITHUB_RUN_ID,
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyDeployId: draftDeployId,
    exactDraftDeployOrigin: draftDeployOrigin,
    method: 'GET',
    path: '/index.html',
    expectedStatus: 200,
    requestNonce
  })), PROBE_RESPONSE_KEYS);
  assert.deepEqual(Object.keys(probeHeaders()), PROBE_UPSTREAM_HEADER_KEYS);

  const validFixture = await createFixture();
  const validBoundary = createBoundaryFetch();
  const validResult = await runBoundary(validFixture, validBoundary.fetchImpl);
  assert.equal(validBoundary.requests.length, 4);
  assert.equal(validBoundary.requests[0].options.headers.Authorization, undefined);
  assert.match(
    validBoundary.requests[1].options.headers.Authorization,
    /^Bearer cnyos-invalid-boundary-bearer-[0-9a-f]{64}$/
  );
  assert.equal(
    validBoundary.requests[2].options.headers.Authorization,
    `Bearer ${boundaryToken}`
  );
  assert.equal(validBoundary.requests[2].request.operation,
    'probe_exact_netlify_draft_request');
  assert.equal(new Set(
    validBoundary.requests.slice(0, 3).map(item => item.request.requestNonce)
  ).size, 3, 'each proof request must carry a unique challenge');
  const validProbeNonce = validBoundary.requests[2].request.requestNonce;
  assert.equal(validBoundary.requests[3].request.operation,
    'read_exact_netlify_draft_file');
  assert.deepEqual(validResult.evidence, {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_private_draft_access_boundary',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: observedAt.toISOString(),
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit,
    controllerRunId: runtime.GITHUB_RUN_ID,
    source: {
      repository: POLICY.sourceRepository,
      commit: candidateCommit,
      tree: candidateTree
    },
    artifact: { artifactSha256 },
    target: {
      netlifySiteId: POLICY.target.netlifySiteId,
      netlifyOrigin: POLICY.target.netlifyOrigin
    },
    preflightEvidenceSha256: validFixture.env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256,
    draftReceiptEvidenceSha256:
      validFixture.env.CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256,
    currentPublishedDeployId: previousDeployId,
    draftDeployId,
    exactDraftDeployOrigin: draftDeployOrigin,
    boundary: {
      origin: boundaryOrigin,
      policyId: boundaryPolicyId,
      policySha256: boundaryPolicySha256,
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
    },
    canary: {
      verifiedAt: observedAt.toISOString(),
      requestNonce: validProbeNonce,
      candidateFunctionReached: true,
      boundaryCredentialObserved: false,
      authorizationHeaderObserved: false,
      cookiesObserved: false,
      responseReflectedCredential: false
    }
  });
  const evidenceBytes = await fs.readFile(validFixture.outputPath);
  const evidenceStatus = await fs.lstat(validFixture.outputPath);
  assert.equal(evidenceStatus.isFile(), true);
  assert.equal(evidenceStatus.isSymbolicLink(), false);
  assert.equal(evidenceStatus.mode & 0o777, 0o600);
  assert.deepEqual(evidenceBytes,
    Buffer.from(`${JSON.stringify(validResult.evidence, null, 2)}\n`));
  assert.equal(evidenceBytes.includes(Buffer.from(boundaryToken)), false);
  await assert.rejects(
    runBoundary(validFixture, createBoundaryFetch().fetchImpl),
    error => error?.code === 'EEXIST',
    'exclusive output creation must reject overwrite'
  );

  const advancingFixture = await createFixture();
  const requestStartedAt = new Date(observedAt.getTime() + 500);
  const probeObservedAt = new Date(observedAt.getTime() + 1000);
  const completedAt = new Date(observedAt.getTime() + 2000);
  const advancingBoundary = createBoundaryFetch({
    mutateProbe: value => { value.canary.verifiedAt = probeObservedAt.toISOString(); }
  });
  const clockValues = [observedAt, requestStartedAt, probeObservedAt, completedAt];
  let clockReads = 0;
  const advancingResult = await verifyPrivateDraftAccessBoundary({
    env: advancingFixture.env,
    fetchImpl: advancingBoundary.fetchImpl,
    now: () => new Date(clockValues[Math.min(clockReads++, clockValues.length - 1)]),
    verifyProducerBundleImpl: async () => fakeBundle
  });
  assert.equal(advancingResult.evidence.verifiedAt, completedAt.toISOString());
  assert.equal(advancingResult.evidence.canary.verifiedAt, probeObservedAt.toISOString());
  assert.equal(clockReads, 4,
    'boundary evidence must re-observe time after the probe and after the exact-byte read');

  const descriptor = Object.freeze({
    schemaVersion: 1,
    operation: 'probe_exact_netlify_draft_request',
    controllerRunId: runtime.GITHUB_RUN_ID,
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyDeployId: draftDeployId,
    exactDraftDeployOrigin: draftDeployOrigin,
    requestNonce,
    method: 'GET',
    path: '/index.html',
    expectedStatus: 200,
    maximumBodyBytes: indexBytes.byteLength
  });
  const validEnvelope = probeEnvelope(descriptor);
  assert.equal(
    validateExactDraftProbeEnvelope(validEnvelope, descriptor, observedAt).upstreamStatus,
    200
  );
  const envelopeMutations = [
    ['extra response key', value => { value.unreviewed = true; }],
    ['wrong operation', value => { value.operation = 'read_exact_netlify_draft_file'; }],
    ['wrong run', value => { value.controllerRunId = '9001002'; }],
    ['wrong site', value => { value.netlifySiteId = POLICY.productionDenylist.netlifySiteId; }],
    ['wrong deploy', value => { value.netlifyDeployId = previousDeployId; }],
    ['canonical origin substituted', value => {
      value.exactDraftDeployOrigin = POLICY.target.netlifyOrigin;
    }],
    ['wrong method', value => { value.method = 'HEAD'; }],
    ['wrong path', value => { value.path = '/'; }],
    ['wrong expected status echo', value => { value.expectedStatus = null; }],
    ['wrong upstream status', value => { value.upstreamStatus = 404; }],
    ['oversized upstream body', value => {
      value.upstreamBodySize = indexBytes.byteLength + 1;
    }],
    ['invalid upstream digest', value => { value.upstreamBodySha256 = 'A'.repeat(64); }],
    ['location disagreement', value => { value.upstreamLocation = '/elsewhere'; }],
    ['missing sanitized header', value => { delete value.upstreamHeaders['cache-control']; }],
    ['extra sanitized header', value => { value.upstreamHeaders['set-cookie'] = 'secret=1'; }],
    ['newline in sanitized header', value => {
      value.upstreamHeaders['content-type'] = 'text/html\r\nset-cookie: x=1';
    }],
    ['candidate canary not reached', value => { value.canary.candidateFunctionReached = false; }],
    ['boundary credential observed', value => { value.canary.boundaryCredentialObserved = true; }],
    ['authorization observed', value => { value.canary.authorizationHeaderObserved = true; }],
    ['cookies observed', value => { value.canary.cookiesObserved = true; }],
    ['credential reflected', value => { value.canary.responseReflectedCredential = true; }],
    ['wrong request nonce', value => { value.canary.requestNonce = 'z'.repeat(43); }],
    ['pre-request canary', value => {
      value.canary.verifiedAt = new Date(observedAt.getTime() - 1).toISOString();
    }],
    ['future canary', value => {
      value.canary.verifiedAt = new Date(observedAt.getTime() + 1).toISOString();
    }],
    ['stale canary', value => {
      value.canary.verifiedAt =
        new Date(observedAt.getTime() - 10 * 60 * 1000 - 1).toISOString();
    }],
    ['noncanonical canary timestamp', value => {
      value.canary.verifiedAt = '2026-09-09T02:00:00Z';
    }]
  ];
  for (const [label, mutate] of envelopeMutations) {
    const candidate = structuredClone(validEnvelope);
    mutate(candidate);
    assert.throws(
      () => validateExactDraftProbeEnvelope(candidate, descriptor, observedAt),
      /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/,
      label
    );
  }

  const nullableStatusDescriptor = Object.freeze({ ...descriptor, method: 'HEAD', expectedStatus: null });
  const nullableStatusEnvelope = probeEnvelope(nullableStatusDescriptor);
  nullableStatusEnvelope.method = 'HEAD';
  nullableStatusEnvelope.expectedStatus = null;
  nullableStatusEnvelope.upstreamStatus = 405;
  nullableStatusEnvelope.upstreamBodySize = 0;
  nullableStatusEnvelope.upstreamBodySha256 = sha256(Buffer.alloc(0));
  assert.equal(
    validateExactDraftProbeEnvelope(
      nullableStatusEnvelope,
      nullableStatusDescriptor,
      observedAt
    ).upstreamStatus,
    405,
    'HEAD header probes may carry a null expected status'
  );

  let unreviewedBoundaryFetchCalls = 0;
  await assert.rejects(
    probeExactNetlifyDraftRequest({
      fetchImpl: async () => {
        unreviewedBoundaryFetchCalls += 1;
        throw new Error('CNYOS_TEST_FETCH_MUST_NOT_RUN');
      },
      boundary: {
        origin: 'https://attacker.example.test',
        policyId: boundaryPolicyId,
        policySha256: boundaryPolicySha256
      },
      accessToken: boundaryToken,
      now: () => new Date(observedAt),
      ...descriptor
    }),
    /CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_POLICY_INVALID/,
    'an exported probe helper must never send the bearer to an unreviewed origin'
  );
  assert.equal(unreviewedBoundaryFetchCalls, 0);

  let isolationVerifierCalls = 0;
  let isolationFetchCalls = 0;
  for (const name of DRAFT_ACCESS_FORBIDDEN_ENVIRONMENT_NAMES) {
    let tokenReads = 0;
    const env = { ...runtime, [name]: '' };
    Object.defineProperty(env, 'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN', {
      enumerable: true,
      configurable: false,
      get() {
        tokenReads += 1;
        return boundaryToken;
      }
    });
    await assert.rejects(
      verifyPrivateDraftAccessBoundary({
        env,
        fetchImpl: async () => {
          isolationFetchCalls += 1;
          throw new Error('CNYOS_TEST_FETCH_MUST_NOT_RUN');
        },
        now: () => new Date(observedAt),
        verifyProducerBundleImpl: async () => {
          isolationVerifierCalls += 1;
          return fakeBundle;
        }
      }),
      /CNYOS_CONTROLLER_DRAFT_ACCESS_CREDENTIAL_CORESIDENCY_FORBIDDEN/,
      `${name} own-property presence`
    );
    assert.equal(tokenReads, 0, `${name}: boundary token must remain unread`);
  }
  assert.equal(isolationVerifierCalls, 0);
  assert.equal(isolationFetchCalls, 0);

  async function rejectsBeforeTokenAndFetch(fixture, expected, label) {
    let tokenReads = 0;
    const tokenValue = fixture.env.CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN;
    delete fixture.env.CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN;
    Object.defineProperty(fixture.env, 'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN', {
      enumerable: true,
      configurable: false,
      get() {
        tokenReads += 1;
        return tokenValue;
      }
    });
    let fetchCalls = 0;
    await assert.rejects(
      runBoundary(fixture, async () => {
        fetchCalls += 1;
        throw new Error('CNYOS_TEST_FETCH_MUST_NOT_RUN');
      }),
      expected,
      label
    );
    assert.equal(tokenReads, 0, `${label}: token must remain unread`);
    assert.equal(fetchCalls, 0, `${label}: fetch must not run`);
  }

  const wrongBoundaryOrigin = await createFixture();
  wrongBoundaryOrigin.env.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL =
    'https://unreviewed-boundary.example.test';
  await rejectsBeforeTokenAndFetch(
    wrongBoundaryOrigin,
    /CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID/,
    'unreviewed boundary origin'
  );

  const collocatedRoot = path.join(temporaryRoot, 'collocated-boundary-controller');
  const collocatedScripts = path.join(collocatedRoot, 'scripts');
  await fs.mkdir(collocatedScripts, { recursive: true, mode: 0o700 });
  await fs.writeFile(
    path.join(collocatedRoot, 'package.json'),
    '{"private":true,"type":"module"}\n',
    { flag: 'wx', mode: 0o600 }
  );
  for (const name of [
    'policy.mjs',
    'verify-producer-bundle.mjs',
    'private-draft-access-boundary.mjs'
  ]) {
    await fs.copyFile(path.join(packageRoot, 'scripts', name), path.join(collocatedScripts, name));
  }
  const collocatedPolicy = structuredClone(isolatedPolicy);
  collocatedPolicy.privateDraftAccessBoundary.origin = draftDeployOrigin;
  await fs.writeFile(
    path.join(collocatedRoot, 'controller-policy.json'),
    `${JSON.stringify(collocatedPolicy, null, 2)}\n`,
    { flag: 'wx', mode: 0o600 }
  );
  const collocatedModule = await import(
    `${pathToFileURL(path.join(
      collocatedScripts,
      'private-draft-access-boundary.mjs'
    )).href}?contract=collocated`
  );
  const collocatedFixture = await createFixture();
  collocatedFixture.env.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL = draftDeployOrigin;
  delete collocatedFixture.env.CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN;
  let collocatedTokenReads = 0;
  Object.defineProperty(collocatedFixture.env, 'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN', {
    enumerable: true,
    configurable: false,
    get() {
      collocatedTokenReads += 1;
      return boundaryToken;
    }
  });
  let collocatedFetchCalls = 0;
  let collocatedNonceCalls = 0;
  await assert.rejects(
    collocatedModule.verifyPrivateDraftAccessBoundary({
      env: collocatedFixture.env,
      fetchImpl: async () => {
        collocatedFetchCalls += 1;
        throw new Error('CNYOS_TEST_FETCH_MUST_NOT_RUN');
      },
      now: () => new Date(observedAt),
      randomBytesImpl: size => {
        collocatedNonceCalls += 1;
        return Buffer.alloc(size, collocatedNonceCalls);
      },
      verifyProducerBundleImpl: async () => fakeBundle
    }),
    /CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_ORIGIN_INVALID/,
    'the reviewed proof service must never be the bearer-targeted draft origin'
  );
  assert.equal(collocatedTokenReads, 0);
  assert.equal(collocatedFetchCalls, 0);
  assert.equal(collocatedNonceCalls, 0);

  const preflightDigestMismatch = await createFixture();
  preflightDigestMismatch.env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256 = '0'.repeat(64);
  await rejectsBeforeTokenAndFetch(
    preflightDigestMismatch,
    /CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_INVALID_DIGEST_MISMATCH/,
    'preflight transport digest mismatch'
  );

  const receiptDigestMismatch = await createFixture();
  receiptDigestMismatch.env.CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256 = '0'.repeat(64);
  await rejectsBeforeTokenAndFetch(
    receiptDigestMismatch,
    /CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID_DIGEST_MISMATCH/,
    'draft receipt transport digest mismatch'
  );

  const crossSourceReceipt = await createFixture({
    mutateReceipt: value => { value.source.commit = '9'.repeat(40); }
  });
  await rejectsBeforeTokenAndFetch(
    crossSourceReceipt,
    /CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID/,
    'cross-source receipt'
  );

  const wrongProviderCommitReceipt = await createFixture({
    mutateReceipt: value => { value.deploy.commitRef = '9'.repeat(40); }
  });
  await rejectsBeforeTokenAndFetch(
    wrongProviderCommitReceipt,
    /CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID/,
    'provider receipt commit must match the candidate'
  );

  const wrongProviderTitleReceipt = await createFixture({
    mutateReceipt: value => { value.deploy.title = 'unbound-deployment-title'; }
  });
  await rejectsBeforeTokenAndFetch(
    wrongProviderTitleReceipt,
    /CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID/,
    'provider receipt title must match the deployment marker'
  );

  const receiptPredatesPreflight = await createFixture({
    mutateReceipt: value => {
      value.recordedAt = new Date(new Date(recordedAt).getTime() - 1).toISOString();
    }
  });
  await rejectsBeforeTokenAndFetch(
    receiptPredatesPreflight,
    /CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID/,
    'draft receipt must not predate its preflight evidence'
  );

  const mutableOriginReceipt = await createFixture({
    mutateReceipt: value => {
      value.exactDeployOrigin = POLICY.target.netlifyOrigin;
      value.deploy.exactDeployOrigin = POLICY.target.netlifyOrigin;
      value.sanitizedCliReceipt.exactDeployOrigin = POLICY.target.netlifyOrigin;
    }
  });
  await rejectsBeforeTokenAndFetch(
    mutableOriginReceipt,
    /CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_INVALID/,
    'canonical mutable origin substituted for immutable deploy origin'
  );

  const expiredPreflight = await createFixture({
    mutatePreflight: value => { value.authorizationExpiresAt = observedAt.toISOString(); }
  });
  await rejectsBeforeTokenAndFetch(
    expiredPreflight,
    /CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_INVALID/,
    'expired preflight'
  );

  const noncanonicalDirectory = path.join(temporaryRoot, 'noncanonical-evidence');
  await fs.mkdir(noncanonicalDirectory, { mode: 0o700 });
  const noncanonicalPreflight = preflightFixture();
  const noncanonicalBytes = Buffer.from(JSON.stringify(noncanonicalPreflight));
  const noncanonicalPreflightPath = path.join(noncanonicalDirectory, 'preflight.json');
  await fs.writeFile(noncanonicalPreflightPath, noncanonicalBytes, { flag: 'wx', mode: 0o600 });
  const canonicalReceipt = await writeCanonicalJson(
    noncanonicalDirectory,
    'receipt.json',
    receiptFixture(sha256(noncanonicalBytes))
  );
  const noncanonicalFixture = {
    env: {
      ...runtime,
      CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL: boundaryOrigin,
      CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: noncanonicalPreflightPath,
      CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: sha256(noncanonicalBytes),
      CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH: canonicalReceipt.path,
      CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256: canonicalReceipt.sha256,
      CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH:
        path.join(noncanonicalDirectory, 'output.json'),
      CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: boundaryToken
    }
  };
  await rejectsBeforeTokenAndFetch(
    noncanonicalFixture,
    /CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_INVALID/,
    'noncanonical preflight JSON'
  );

  const responseCases = [
    ['missing policy proof', {
      mutateProbeOuterHeaders: headers => { delete headers['x-cnyos-boundary-policy-id']; }
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/],
    ['authorization forwarding reported', {
      mutateProbeOuterHeaders: headers => {
        headers['x-cnyos-upstream-authorization-forwarded'] = 'true';
      }
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/],
    ['cookie forwarding reported', {
      mutateProbeOuterHeaders: headers => {
        headers['x-cnyos-upstream-cookies-forwarded'] = 'true';
      }
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/],
    ['redirect following reported', {
      mutateProbeOuterHeaders: headers => {
        headers['x-cnyos-upstream-redirect-followed'] = 'true';
      }
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/],
    ['noncanonical response JSON', {
      probeRaw: `${JSON.stringify(validEnvelope, null, 2)}\n`
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_NONCANONICAL/],
    ['probe content digest mismatch', {
      mutateProbe: value => { value.upstreamBodySha256 = '6'.repeat(64); }
    }, /CNYOS_CONTROLLER_DRAFT_INDEX_CONTENT_MISMATCH/],
    ['security headers mismatch', {
      mutateProbe: value => { value.upstreamHeaders['x-frame-options'] = 'DENY'; }
    }, /CNYOS_CONTROLLER_DRAFT_SECURITY_HEADERS_INVALID/],
    ['boundary token reflected in response', {
      mutateProbe: value => { value.upstreamHeaders['content-type'] = boundaryToken; }
    }, /CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_REFLECTED/],
    ['boundary token reflected by unauthorized response header', {
      mutateUnauthorized: specification => {
        specification.headers = { 'x-debug-boundary-token': boundaryToken };
      }
    }, /CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_REFLECTED/],
    ['pre-request canary replay', {
      mutateProbe: value => {
        value.canary.verifiedAt = new Date(observedAt.getTime() - 1).toISOString();
      }
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/],
    ['canary challenge replay', {
      mutateProbe: value => { value.canary.requestNonce = requestNonce; }
    }, /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_INVALID/],
    ['raw body mismatch', {
      readBody: Buffer.from(indexBytes.map(byte => byte ^ 0x01))
    }, /CNYOS_CONTROLLER_DRAFT_FILE_BYTES_MISMATCH/],
    ['raw body overflow', {
      readBody: Buffer.concat([indexBytes, Buffer.from('x')])
    }, /CNYOS_CONTROLLER_DRAFT_FILE_TOO_LARGE/],
    ['raw response redirect status', {
      readStatus: 302
    }, /CNYOS_CONTROLLER_DRAFT_FILE_RESPONSE_INVALID|CNYOS_CONTROLLER_DRAFT_FILE_BYTES_MISMATCH/],
    ['raw response missing boundary proof', {
      mutateReadOuterHeaders: headers => {
        delete headers['x-cnyos-boundary-policy-id'];
      }
    }, /CNYOS_CONTROLLER_DRAFT_FILE_RESPONSE_INVALID/],
    ['invalid bearer accepted', {
      mutateUnauthorized: specification => { specification.status = 200; }
    }, /CNYOS_CONTROLLER_DRAFT_ACCESS_AUTHENTICATION_RESPONSE_INVALID/]
  ];
  for (const [label, boundaryOptions, expected] of responseCases) {
    const fixture = await createFixture();
    const boundary = createBoundaryFetch(boundaryOptions);
    await assert.rejects(runBoundary(fixture, boundary.fetchImpl), expected, label);
  }

  const oversizedFixture = await createFixture();
  const oversizedBoundary = createBoundaryFetch({
    probeRaw: 'x'.repeat(64 * 1024 + 1)
  });
  await assert.rejects(
    runBoundary(oversizedFixture, oversizedBoundary.fetchImpl),
    /CNYOS_CONTROLLER_DRAFT_PROBE_RESPONSE_TOO_LARGE/,
    'bounded probe response'
  );

  assert.equal(globalFetchCalls, 0, 'activation contract must never use live network');
  process.stdout.write('CNYOS activation contract private-draft-access-boundary: passed\n');
} finally {
  globalThis.fetch = originalFetch;
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}
