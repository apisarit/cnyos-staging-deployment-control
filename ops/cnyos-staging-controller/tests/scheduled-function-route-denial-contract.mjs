import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  SCHEDULED_ROUTE_DENIAL_FORBIDDEN_ENVIRONMENT_NAMES,
  SCHEDULED_ROUTE_DENIAL_FUNCTIONS,
  SCHEDULED_ROUTE_DENIAL_METHODS,
  verifyScheduledFunctionRouteDenial
} from '../scripts/scheduled-function-route-denial.mjs';
import { validateScheduledFunctionRouteDenialEvidence } from '../scripts/finalize-evidence.mjs';
import {
  EXPECTED_FUNCTION_NAMES,
  POLICY,
  REQUIRED_SCHEDULES,
  deploymentMarker,
  sha256
} from '../scripts/policy.mjs';

const CONTROLLER_COMMIT = 'd'.repeat(40);
const SOURCE_COMMIT = 'a'.repeat(40);
const SOURCE_TREE = 'b'.repeat(40);
const FUNCTION_SOURCE_TREE = 'c'.repeat(40);
const DEPLOY_ID = '0123456789abcdef01234567';
const PREVIOUS_DEPLOY_ID = '89abcdef0123456701234567';
const RUN_ID = '123456789';
const DISPATCH_NONCE = Buffer.alloc(32, 7).toString('base64url');
const OBSERVED_AT = new Date('2026-09-09T04:05:00.000Z');
const PROMOTED_AT = new Date('2026-09-09T04:02:00.000Z');
const POST_PROMOTION_AT = new Date('2026-09-09T04:03:00.000Z');
const EXPIRES_AT = new Date('2026-09-09T04:25:00.000Z').toISOString();
const IMMUTABLE_ORIGIN = `https://${DEPLOY_ID}--${POLICY.target.netlifySiteName}.netlify.app`;

function digest(label) {
  return crypto.createHash('sha256').update(`fixture:${label}`).digest('hex');
}

function canonical(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function writeEvidence(root, name, value) {
  const filename = path.join(root, name);
  const bytes = Buffer.from(canonical(value));
  await fs.writeFile(filename, bytes, { mode: 0o600 });
  return Object.freeze({ filename, sha256: sha256(bytes) });
}

function response(url, { status = 200, body = '', headers = {}, redirected = false,
  responseUrl = url } = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
  return {
    status,
    redirected,
    url: responseUrl,
    headers: new Headers(headers),
    body: new Response(bytes).body
  };
}

function deployManifest() {
  return {
    schemaVersion: 1,
    deploymentId: POLICY.target.deploymentId,
    source: { verified: true, commit: SOURCE_COMMIT, tree: SOURCE_TREE },
    tenant: {
      expectedClinicId: POLICY.target.clinicId,
      expectedClinicCode: POLICY.target.clinicCode
    },
    identity: { qrIssuer: POLICY.target.qrIssuer },
    build: {
      context: 'production',
      deploymentClass: 'dedicated-staging',
      timestamp: '2026-09-09T03:55:00.000Z'
    },
    safety: {
      previewLocked: false,
      databaseLocked: false,
      stagingDatabaseExplicitlyAcknowledged: true
    }
  };
}

function authorizationArtifact(manifestSha256, manifest) {
  return {
    producerManifestSha256: manifestSha256,
    artifactSha256: manifest.artifactSha256,
    fileCount: manifest.fileCount,
    candidateBuildArtifactDigest: manifest.candidateBuildArtifactDigest,
    staticReproducibilityEvidenceSha256: manifest.staticReproducibilityEvidenceSha256,
    staticArtifactSha256: manifest.staticArtifactSha256,
    candidateDependencyLockSha256: manifest.candidateDependencyLockSha256,
    stagingConfigSha256: manifest.stagingConfigSha256,
    productionDenylistConfigSha256: manifest.productionDenylistConfigSha256,
    functionBundleManifestSha256: manifest.functionBundleManifestSha256,
    functionBundleDependencyLockSha256: manifest.functionBundleDependencyLockSha256,
    functionSourcesSha256: manifest.functionSourcesSha256,
    producerRunId: RUN_ID,
    githubArtifactDigest: digest('github-artifact')
  };
}

function source() {
  return {
    repository: POLICY.sourceRepository,
    commit: SOURCE_COMMIT,
    tree: SOURCE_TREE,
    functionSourceTree: FUNCTION_SOURCE_TREE
  };
}

function targetExclusion() {
  return {
    productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
    productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin,
    targetSiteClassifiedStagingOnly: true,
    realPatientDataAbsent: true,
    legacyPublisherInventoryComplete: true,
    candidateRepositoryProductionWorkflowTargetDenied: true,
    candidateRepositoryPreviewWorkflowTargetDenied: true,
    allAlternatePublisherCredentialsTargetDenied: true,
    currentCnyosProductionMappingConflictResolved: true,
    evidenceSha256: digest('target-exclusion')
  };
}

function sanitizedDeploy(id, commit = SOURCE_COMMIT) {
  return {
    id,
    siteId: POLICY.target.netlifySiteId,
    state: 'ready',
    context: 'production',
    commitRef: commit,
    title: id === DEPLOY_ID ? deploymentMarker(RUN_ID, DISPATCH_NONCE, SOURCE_COMMIT) : 'baseline',
    exactDeployOrigin: `https://${id}--${POLICY.target.netlifySiteName}.netlify.app`,
    publishedAt: '2026-09-09T04:02:01.000Z'
  };
}

function postPromotionArtifact(manifest, manifestSha256) {
  const inventory = manifest.files
    .filter(item => item.path.startsWith('payload/dist/') &&
      !['payload/dist/_headers', 'payload/dist/_redirects'].includes(item.path))
    .map(item => ({
      path: `/${item.path.slice('payload/dist/'.length)}`,
      size: item.size,
      sha256: item.sha256
    }));
  return {
    producerManifestSha256: manifestSha256,
    artifactSha256: manifest.artifactSha256,
    fileCount: inventory.length,
    closedWorldInventoryVerified: true,
    inventorySha256: sha256(JSON.stringify(inventory))
  };
}

async function createFixture({
  mutatePreflight = () => {},
  mutatePromotion = () => {},
  mutatePostPromotion = () => {},
  mutateBundle = () => {},
  mutateDeployManifest = () => {}
} = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-scheduled-route-denial-'));
  const bundleDirectory = path.join(root, 'producer');
  const dist = path.join(bundleDirectory, 'payload', 'dist');
  await fs.mkdir(dist, { recursive: true });
  const deployManifestValue = deployManifest();
  mutateDeployManifest(deployManifestValue);
  const manifestBytes = Buffer.from(canonical(deployManifestValue));
  await fs.writeFile(path.join(dist, 'deploy-manifest.json'), manifestBytes, { mode: 0o600 });
  const staticEntries = [
    { path: 'payload/dist/_headers', size: 20, sha256: digest('_headers') },
    { path: 'payload/dist/_redirects', size: 20, sha256: digest('_redirects') },
    {
      path: 'payload/dist/deploy-manifest.json',
      size: manifestBytes.byteLength,
      sha256: sha256(manifestBytes)
    },
    { path: 'payload/dist/index.html', size: 31, sha256: digest('index') }
  ];
  const functionEntries = EXPECTED_FUNCTION_NAMES.map(name => ({
    path: `payload/netlify/functions/${name}.zip`,
    size: 20,
    sha256: digest(`function:${name}`)
  }));
  const producerManifestSha256 = digest('producer-manifest');
  const manifest = {
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: CONTROLLER_COMMIT,
    controllerRunId: RUN_ID,
    dispatchNonce: DISPATCH_NONCE,
    sourceRepository: POLICY.sourceRepository,
    candidateCommit: SOURCE_COMMIT,
    candidateTree: SOURCE_TREE,
    functionSourceTree: FUNCTION_SOURCE_TREE,
    candidateBuildArtifactDigest: digest('build-artifact'),
    staticReproducibilityEvidenceSha256: digest('static-reproducibility'),
    staticArtifactSha256: digest('static-artifact'),
    candidateDependencyLockSha256: digest('dependency-lock'),
    stagingConfigSha256: digest('staging-config'),
    productionDenylistConfigSha256: digest('production-denylist'),
    functionBundleManifestSha256: digest('function-bundle-manifest'),
    functionBundleDependencyLockSha256: digest('function-bundle-lock'),
    functionSourcesSha256: digest('function-sources'),
    artifactSha256: digest('artifact'),
    files: [...staticEntries, ...functionEntries]
      .sort((left, right) => left.path.localeCompare(right.path))
  };
  manifest.fileCount = manifest.files.length;
  mutateBundle(manifest);
  const artifact = authorizationArtifact(producerManifestSha256, manifest);
  const preflight = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_preflight',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    capturedAt: '2026-09-09T04:00:00.000Z',
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: CONTROLLER_COMMIT,
    controllerRunId: RUN_ID,
    dispatchNonce: DISPATCH_NONCE,
    source: source(),
    artifact: { ...artifact },
    target: { ...POLICY.target },
    preReleaseReconciliationEvidenceSha256: digest('reconciliation'),
    authorizationEvidenceSha256: digest('authorization'),
    liveGitHubPrecredentialBoundaryEvidenceSha256: digest('github-precredential'),
    runtimeProofEnvelopeSha256: digest('runtime-proof-envelope'),
    rollbackAttestationDepositEvidenceSha256: digest('rollback-deposit'),
    rollbackAttestationDepositReceiptSha256: digest('rollback-deposit-receipt'),
    rollbackAttestationDepositId: 'deposit-fixture-id',
    rollbackAttestationRetentionUntil: '2026-12-09T04:00:00.000Z',
    authorizationExpiresAt: EXPIRES_AT,
    deploymentControlBoundaryExpiresAt: EXPIRES_AT,
    principalProofExpiresAt: EXPIRES_AT,
    liveNetlifyAuthorityBoundaryEvidenceSha256: digest('netlify-authority'),
    liveNetlifyAuthorityBoundaryExpiresAt: EXPIRES_AT,
    principalProof: {
      inventoryComplete: true,
      subject: 'fixture-publisher',
      accessibleSiteCount: 1,
      accessibleSiteIds: [POLICY.target.netlifySiteId],
      nonStagingSiteAccess: false
    },
    netlifyPrincipalBoundary: { subject: 'fixture-publisher' },
    rollbackNetlifyPrincipalSubject: 'fixture-rollback',
    rollbackNetlifyPrincipalBoundary: { subject: 'fixture-rollback' },
    targetSiteAndPublisherExclusion: targetExclusion(),
    functionEnvironmentEvidenceSha256: digest('function-environment'),
    functionEnvironmentExactValuesSha256: digest('function-values'),
    runtimeCapabilityEvidenceSha256: digest('runtime-capability'),
    backupDisableEvidenceSha256: digest('backup-disable'),
    protectedFunctionSecretPresenceVerified: true,
    backupEnabled: false,
    previousPublishedDeploy: sanitizedDeploy(PREVIOUS_DEPLOY_ID, 'e'.repeat(40)),
    knownGoodRollbackEvidenceSha256: digest('known-good')
  };
  mutatePreflight(preflight);
  const preflightFile = await writeEvidence(root, 'preflight.json', preflight);
  const promotion = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_exact_deploy_promotion',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    promotedAt: PROMOTED_AT.toISOString(),
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: CONTROLLER_COMMIT,
    controllerRunId: RUN_ID,
    dispatchNonce: DISPATCH_NONCE,
    source: source(),
    artifact: { ...artifact },
    target: { ...POLICY.target },
    previousDeployId: preflight.previousPublishedDeploy.id,
    promotedDeployId: DEPLOY_ID,
    exactDeployOrigin: IMMUTABLE_ORIGIN,
    currentPublishedDeployId: DEPLOY_ID,
    deploy: sanitizedDeploy(DEPLOY_ID),
    preflightEvidenceSha256: preflightFile.sha256,
    liveGitHubPrecredentialBoundaryEvidenceSha256: digest('github-precredential'),
    liveGitHubPrepromotionBoundaryEvidenceSha256: digest('github-prepromotion'),
    promotionAttemptEvidenceSha256: digest('promotion-attempt'),
    draftVerificationEvidenceSha256: digest('draft-verification'),
    controlBehaviorEvidenceSha256: digest('control-behavior'),
    privateDraftEvidenceSha256: digest('private-draft'),
    exclusivePublisherEvidenceSha256: digest('publisher'),
    exclusivePublisherLeaseId: 'lease-fixture-0123456789'
  };
  mutatePromotion(promotion);
  const promotionFile = await writeEvidence(root, 'promotion.json', promotion);
  const postPromotion = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_post_promotion_verification',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: POST_PROMOTION_AT.toISOString(),
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: CONTROLLER_COMMIT,
    controllerRunId: RUN_ID,
    dispatchNonce: DISPATCH_NONCE,
    source: source(),
    artifact: postPromotionArtifact(manifest, producerManifestSha256),
    target: { ...POLICY.target },
    netlifyDeployId: DEPLOY_ID,
    exactDeployOrigin: IMMUTABLE_ORIGIN,
    currentPublishedDeployId: DEPLOY_ID,
    schedules: Object.entries(REQUIRED_SCHEDULES).map(([name, cron]) => ({ name, cron })),
    functionNames: [...EXPECTED_FUNCTION_NAMES],
    functionByteAttestationAvailable: false,
    verificationPhase: 'before_authenticated_uat',
    promotionEvidenceSha256: promotionFile.sha256
  };
  mutatePostPromotion(postPromotion);
  const postPromotionFile = await writeEvidence(root, 'post-promotion.json', postPromotion);
  const output = path.join(root, 'scheduled-route-denial.json');
  const workflowPath = POLICY.controller.releaseWorkflowPath;
  const env = {
    GITHUB_REPOSITORY: POLICY.controller.repository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: RUN_ID,
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: POLICY.controller.protectedRef,
    CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: CONTROLLER_COMMIT,
    CNYOS_CONTROLLER_WORKFLOW_PATH: workflowPath,
    GITHUB_WORKFLOW_REF: `${POLICY.controller.repository}/${workflowPath}@${POLICY.controller.protectedRef}`,
    GITHUB_ACTOR: 'apisarit',
    GITHUB_TRIGGERING_ACTOR: 'apisarit',
    CNYOS_DISPATCH_NONCE: DISPATCH_NONCE,
    CNYOS_EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
    CNYOS_EXPECTED_SOURCE_TREE: SOURCE_TREE,
    CNYOS_EXPECTED_NETLIFY_DEPLOY_ID: DEPLOY_ID,
    CNYOS_PRODUCER_BUNDLE_DIRECTORY: bundleDirectory,
    CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: producerManifestSha256,
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.filename,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.sha256,
    CNYOS_CONTROLLER_PROMOTION_EVIDENCE_PATH: promotionFile.filename,
    CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256: promotionFile.sha256,
    CNYOS_CONTROLLER_POST_PROMOTION_EVIDENCE_PATH: postPromotionFile.filename,
    CNYOS_EXPECTED_POST_PROMOTION_EVIDENCE_SHA256: postPromotionFile.sha256,
    CNYOS_CONTROLLER_SCHEDULED_ROUTE_DENIAL_EVIDENCE_PATH: output
  };
  const bundle = { bundleDirectory, manifestSha256: producerManifestSha256, manifest };
  return {
    root,
    env,
    bundle,
    deployManifestSha256: sha256(manifestBytes),
    output,
    files: { preflight: preflightFile, promotion: promotionFile, postPromotion: postPromotionFile }
  };
}

function createFetch(manifestBytes, {
  routeStatus = 404,
  routeBody = 'Not Found',
  routeRedirected = false,
  routeResponseUrl = null,
  manifestMutationAfterFirstPass = false
} = {}) {
  const calls = [];
  let manifestRequests = 0;
  const fetchImpl = async (input, init) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith('/deploy-manifest.json')) {
      manifestRequests += 1;
      const body = manifestMutationAfterFirstPass && manifestRequests > 2
        ? Buffer.from('{}\n')
        : manifestBytes;
      return response(url, {
        status: 200,
        body,
        headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.byteLength) }
      });
    }
    return response(url, {
      status: routeStatus,
      body: routeBody,
      redirected: routeRedirected,
      responseUrl: routeResponseUrl || url,
      headers: { 'Content-Type': 'text/plain' }
    });
  };
  return Object.freeze({ fetchImpl, calls });
}

async function runFixture(fixture, fetchFixture, nowImpl = () => new Date(OBSERVED_AT)) {
  return verifyScheduledFunctionRouteDenial({
    env: fixture.env,
    fetchImpl: fetchFixture.fetchImpl,
    now: nowImpl,
    verifyProducerBundleImpl: async () => fixture.bundle
  });
}

async function dispose(fixture) {
  await fs.rm(fixture.root, { recursive: true, force: true });
}

assert.deepEqual(SCHEDULED_ROUTE_DENIAL_FUNCTIONS, Object.keys(REQUIRED_SCHEDULES));
assert.deepEqual(SCHEDULED_ROUTE_DENIAL_METHODS, ['GET', 'POST']);

{
  const fixture = await createFixture();
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    const fetchFixture = createFetch(manifestBytes);
    const result = await runFixture(fixture, fetchFixture);
    assert.equal(fetchFixture.calls.length, 12, 'four bounded manifest reads plus eight route probes');
    assert.equal(result.evidence.probes.length, 8);
    assert.equal(result.evidence.schemaVersion, 2);
    assert.equal(result.evidence.startedAt, OBSERVED_AT.toISOString());
    assert.equal(result.evidence.deployManifestSha256, fixture.deployManifestSha256);
    assert.equal(result.evidence.publisherExactCurrentEvidence.beforeProbes.currentPublishedDeployId,
      DEPLOY_ID);
    assert.equal(result.evidence.publisherExactCurrentEvidence.beforeProbes.promotionEvidenceSha256,
      fixture.files.promotion.sha256);
    assert.equal(result.evidence.publisherExactCurrentEvidence.beforeProbes.postPromotionEvidenceSha256,
      fixture.files.postPromotion.sha256);
    assert.equal(result.evidence.publisherExactCurrentEvidence.afterProbes, null);
    assert.equal(Object.hasOwn(result.evidence, 'currentPublishedDeployIdBefore'), false);
    assert.equal(Object.hasOwn(result.evidence, 'currentPublishedDeployIdAfter'), false);
    assert.deepEqual(result.evidence.manifestObservations.map(item => [
      item.phase,
      item.originKind,
      item.origin,
      item.bodySha256,
      item.expectedArtifactBytesMatched
    ]), [
      ['before_route_probes', 'immutable', IMMUTABLE_ORIGIN,
        fixture.deployManifestSha256, true],
      ['before_route_probes', 'canonical', POLICY.target.netlifyOrigin,
        fixture.deployManifestSha256, true],
      ['after_route_probes', 'immutable', IMMUTABLE_ORIGIN,
        fixture.deployManifestSha256, true],
      ['after_route_probes', 'canonical', POLICY.target.netlifyOrigin,
        fixture.deployManifestSha256, true]
    ]);
    validateScheduledFunctionRouteDenialEvidence(result.evidence, {
      runtime: {
        repository: POLICY.controller.repository,
        ref: POLICY.controller.protectedRef,
        commit: CONTROLLER_COMMIT,
        runId: RUN_ID
      },
      commit: SOURCE_COMMIT,
      tree: SOURCE_TREE,
      deployId: DEPLOY_ID,
      deployManifestSha256: fixture.deployManifestSha256,
      deployManifestSize: manifestBytes.byteLength,
      promotionEvidenceSha256: fixture.files.promotion.sha256,
      postPromotionEvidenceSha256: fixture.files.postPromotion.sha256,
      observedAt: OBSERVED_AT,
      notBefore: POST_PROMOTION_AT,
      notAfter: OBSERVED_AT
    });
    for (const { url, init } of fetchFixture.calls) {
      assert.ok(url.startsWith(IMMUTABLE_ORIGIN) || url.startsWith(POLICY.target.netlifyOrigin));
      assert.ok(!url.startsWith(POLICY.productionDenylist.netlifyOrigin));
      assert.equal(init.redirect, 'error');
      assert.equal(init.credentials, 'omit');
      assert.equal(init.cache, 'no-store');
      assert.equal(init.referrerPolicy, 'no-referrer');
      assert.ok(init.signal instanceof AbortSignal);
      const headers = new Headers(init.headers);
      assert.equal(headers.has('authorization'), false);
      assert.equal(headers.has('cookie'), false);
      assert.equal(headers.has('proxy-authorization'), false);
      if (init.method === 'POST') {
        assert.equal(init.body, '{');
        assert.equal(headers.get('content-type'), 'application/json');
      } else {
        assert.equal(init.body, undefined);
      }
    }
    const status = await fs.lstat(fixture.output);
    assert.equal(status.isFile(), true);
    assert.equal(status.isSymbolicLink(), false);
    assert.equal(status.mode & 0o777, 0o600);
    const output = await fs.readFile(fixture.output, 'utf8');
    assert.equal(output, canonical(JSON.parse(output)), 'canonical regular JSON output');
    assert.equal(output.includes('Not Found'), false, 'response bodies are never serialized');
  } finally {
    await dispose(fixture);
  }
}

for (const credentialName of [
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY'
]) {
  assert.ok(SCHEDULED_ROUTE_DENIAL_FORBIDDEN_ENVIRONMENT_NAMES.includes(credentialName));
  let bundleCalls = 0;
  let fetchCalls = 0;
  await assert.rejects(
    verifyScheduledFunctionRouteDenial({
      env: { [credentialName]: '' },
      fetchImpl: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
      verifyProducerBundleImpl: async () => { bundleCalls += 1; throw new Error('must not read'); }
    }),
    /CNYOS_CONTROLLER_SCHEDULED_ROUTE_CREDENTIAL_ISOLATION_INVALID/,
    `${credentialName} co-residency`
  );
  assert.equal(bundleCalls, 0, `${credentialName} rejected before producer reads`);
  assert.equal(fetchCalls, 0, `${credentialName} rejected before network`);
}

for (const evidenceName of ['preflight', 'promotion', 'postPromotion']) {
  const fixture = await createFixture();
  try {
    await fs.appendFile(fixture.files[evidenceName].filename, ' ');
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    const fetchFixture = createFetch(manifestBytes);
    await assert.rejects(runFixture(fixture, fetchFixture), /DIGEST_MISMATCH/, `${evidenceName} hash`);
    assert.equal(fetchFixture.calls.length, 0, `${evidenceName} hash rejected before network`);
  } finally {
    await dispose(fixture);
  }
}

for (const [label, fixtureOptions, error] of [
  [
    'source binding',
    { mutatePostPromotion: value => { value.source.commit = 'f'.repeat(40); } },
    /CNYOS_CONTROLLER_SCHEDULED_ROUTE_POST_PROMOTION_INVALID/
  ],
  [
    'site binding',
    { mutatePreflight: value => { value.target.netlifySiteId = POLICY.productionDenylist.netlifySiteId; } },
    /CNYOS_CONTROLLER_SCHEDULED_ROUTE_PREFLIGHT_INVALID/
  ],
  [
    'deploy binding',
    { mutatePromotion: value => { value.promotedDeployId = PREVIOUS_DEPLOY_ID; } },
    /CNYOS_CONTROLLER_SCHEDULED_ROUTE_PROMOTION_INVALID/
  ],
  [
    'promotion hash chain',
    { mutatePostPromotion: value => { value.promotionEvidenceSha256 = digest('wrong-promotion'); } },
    /CNYOS_CONTROLLER_SCHEDULED_ROUTE_POST_PROMOTION_INVALID/
  ],
  [
    'preflight/promotion full artifact binding',
    { mutatePromotion: value => { value.artifact.githubArtifactDigest = digest('other-github-artifact'); } },
    /CNYOS_CONTROLLER_SCHEDULED_ROUTE_PROMOTION_INVALID/
  ]
]) {
  const fixture = await createFixture(fixtureOptions);
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    const fetchFixture = createFetch(manifestBytes);
    await assert.rejects(runFixture(fixture, fetchFixture), error, label);
    assert.equal(fetchFixture.calls.length, 0, `${label} rejected before network`);
  } finally {
    await dispose(fixture);
  }
}

{
  const fixture = await createFixture({
    mutateDeployManifest: value => { value.build.timestamp = '2026-09-09T03:50:00.000Z'; }
  });
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    const fetchFixture = createFetch(manifestBytes);
    let clockReads = 0;
    await assert.rejects(
      runFixture(fixture, fetchFixture, () => {
        clockReads += 1;
        return new Date(clockReads === 1
          ? OBSERVED_AT
          : '2026-09-09T04:20:00.001Z');
      }),
      /CNYOS_CONTROLLER_SCHEDULED_ROUTE_DEPLOY_MANIFEST_INVALID/,
      'deploy-manifest freshness is rechecked at advancing-clock completion'
    );
    assert.equal(clockReads, 2);
    assert.equal(fetchFixture.calls.length, 12, 'completion freshness fails after all observations');
  } finally {
    await dispose(fixture);
  }
}

{
  const fixture = await createFixture();
  try {
    fixture.bundle.manifestSha256 = digest('wrong-producer-manifest');
    const fetchFixture = createFetch(Buffer.from(canonical(deployManifest())));
    await assert.rejects(
      runFixture(fixture, fetchFixture),
      /CNYOS_CONTROLLER_SCHEDULED_ROUTE_PRODUCER_INVALID/,
      'producer manifest hash binding'
    );
    assert.equal(fetchFixture.calls.length, 0);
  } finally {
    await dispose(fixture);
  }
}

for (const [label, fetchOptions, error] of [
  ['public success', { routeStatus: 200 }, /SCHEDULED_ROUTE_PUBLICLY_REACHABLE/],
  [
    'application-shaped denial',
    { routeStatus: 403, routeBody: JSON.stringify({ ok: false, code: 'BACKUP_DENIED' }) },
    /SCHEDULED_ROUTE_PUBLICLY_REACHABLE/
  ],
  [
    'empty object denial body',
    { routeStatus: 403, routeBody: '{}' },
    /SCHEDULED_ROUTE_PUBLICLY_REACHABLE/
  ],
  [
    'array denial body',
    { routeStatus: 404, routeBody: '[]' },
    /SCHEDULED_ROUTE_PUBLICLY_REACHABLE/
  ],
  ['redirect', { routeStatus: 404, routeRedirected: true }, /SCHEDULED_ROUTE_PROBE_RESPONSE_INVALID/],
  [
    'response URL change',
    { routeStatus: 404, routeResponseUrl: 'https://example.invalid/redirected' },
    /SCHEDULED_ROUTE_PROBE_RESPONSE_INVALID/
  ],
  [
    'oversized denial',
    { routeStatus: 404, routeBody: 'x'.repeat(16 * 1024 + 1) },
    /SCHEDULED_ROUTE_PROBE_RESPONSE_INVALID/
  ]
]) {
  const fixture = await createFixture();
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    await assert.rejects(runFixture(fixture, createFetch(manifestBytes, fetchOptions)), error, label);
  } finally {
    await dispose(fixture);
  }
}

for (const [label, timestamp] of [
  ['noncanonical deploy-manifest timestamp', '2026-09-09T03:55:00Z'],
  ['future deploy-manifest timestamp', '2026-09-09T04:05:00.001Z'],
  ['stale deploy-manifest timestamp', '2026-09-09T03:34:59.999Z']
]) {
  const fixture = await createFixture({
    mutateDeployManifest: value => { value.build.timestamp = timestamp; }
  });
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    const fetchFixture = createFetch(manifestBytes);
    await assert.rejects(
      runFixture(fixture, fetchFixture),
      /CNYOS_CONTROLLER_SCHEDULED_ROUTE_DEPLOY_MANIFEST_INVALID/,
      label
    );
    assert.equal(fetchFixture.calls.length, 0, `${label} rejected before network`);
  } finally {
    await dispose(fixture);
  }
}

{
  const fixture = await createFixture();
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    const fetchFixture = createFetch(manifestBytes);
    const completionAt = new Date('2026-09-09T04:06:00.000Z');
    let clockReads = 0;
    const result = await runFixture(fixture, fetchFixture, () => {
      clockReads += 1;
      return new Date(clockReads === 1 ? OBSERVED_AT : completionAt);
    });
    assert.equal(clockReads, 2, 'completion re-reads the advancing clock');
    assert.equal(result.evidence.startedAt, OBSERVED_AT.toISOString());
    assert.equal(result.evidence.verifiedAt, completionAt.toISOString());
  } finally {
    await dispose(fixture);
  }
}

{
  const fixture = await createFixture();
  try {
    const manifestBytes = await fs.readFile(
      path.join(fixture.bundle.bundleDirectory, 'payload', 'dist', 'deploy-manifest.json')
    );
    await assert.rejects(
      runFixture(fixture, createFetch(manifestBytes, { manifestMutationAfterFirstPass: true })),
      /CNYOS_CONTROLLER_SCHEDULED_ROUTE_MANIFEST_MISMATCH/,
      'canonical or immutable artifact changes during probing'
    );
  } finally {
    await dispose(fixture);
  }
}

process.stdout.write('CNYOS activation contract scheduled-function-route-denial: passed\n');
