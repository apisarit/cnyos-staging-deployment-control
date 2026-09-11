import assert from 'node:assert/strict';
import {
  EXPECTED_SCHEDULED_ROUTE_DENIAL_FUNCTIONS,
  EXPECTED_SCHEDULED_ROUTE_DENIAL_METHODS,
  EXPECTED_STAGING_UAT_ROLES,
  EXPECTED_STAGING_UAT_ROUTES,
  validateAuthenticatedUatEvidence,
  validateFinalCurrentEvidence,
  validateScheduledFunctionRouteDenialEvidence
} from '../scripts/finalize-evidence.mjs';
import { validateOwnerSubscriptionProof } from '../scripts/controller-uat-subscription-evidence.mjs';
import {
  EXPECTED_FUNCTION_NAMES,
  POLICY,
  REQUIRED_SCHEDULES,
  sha256
} from '../scripts/policy.mjs';

const commit = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const deployId = '0123456789abcdef01234567';
const pointer = label => ({ sha256: 'c'.repeat(64), reference: `protected:${label}` });
const proofBoundary = () => ({
  clinicId: POLICY.target.clinicId,
  clinicCode: POLICY.target.clinicCode,
  clinicRole: 'practitioner',
  systemRole: 'staff',
  effectiveRole: 'practitioner',
  ready: true,
  clinical: true
});
const validSubscriptionProof = () => ({
  schemaVersion: 1,
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  clinicId: POLICY.target.clinicId,
  clinicCode: POLICY.target.clinicCode,
  offRequestId: '11111111-1111-4111-8111-111111111111',
  onRequestId: '22222222-2222-4222-8222-222222222222',
  initialVersion: 7,
  offExpectedVersion: 7,
  replayExpectedVersion: 7,
  offVersion: 8,
  onExpectedVersion: 8,
  restoreVersion: 9,
  offPayloadSha256: 'a'.repeat(64),
  replayPayloadSha256: 'a'.repeat(64),
  onPayloadSha256: 'b'.repeat(64),
  offReplayIdempotent: true,
  recoveryDisposition: 'confirmed_restored',
  originalBoundary: proofBoundary(),
  restoredBoundary: proofBoundary()
});

function validUat() {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_authenticated_uat',
    status: 'passed',
    controllerOwnedHarness: true,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    sourceCommit: commit,
    sourceTree: tree,
    netlifyDeployId: deployId,
    target: {
      netlifySiteId: POLICY.target.netlifySiteId,
      supabaseProjectRef: POLICY.target.supabaseProjectRef,
      clinicId: POLICY.target.clinicId
    },
    identityProvisioning: {
      status: 'passed',
      syntheticUserCount: 11,
      roleCount: 11,
      roles: [...EXPECTED_STAGING_UAT_ROLES],
      evidence: pointer('identity-provisioning')
    },
    accessControl: {
      status: 'passed',
      currentAccessContextRoleCount: 11,
      departmentCanRoleCount: 11,
      crossTenantDenialsVerified: true,
      evidence: pointer('access-control')
    },
    routeMatrix: {
      status: 'passed',
      browser: 'mobile_chromium',
      roleCount: 11,
      routeCount: 10,
      authorizationDecisionCount: 110,
      deniedRouteBehaviorVerified: true,
      routes: [...EXPECTED_STAGING_UAT_ROUTES],
      evidence: pointer('route-matrix')
    },
    syntheticJourneys: {
      status: 'passed',
      caseCount: 10,
      passed: 10,
      failed: 0,
      clinicalToPaymentVerified: true,
      evidence: pointer('synthetic-journeys')
    },
    migrationHealth: {
      status: 'passed',
      exactLedgerVerified: true,
      evidence: pointer('migration-health')
    },
    auditAndSegregation: {
      status: 'passed',
      producerApproverSeparationVerified: true,
      evidence: pointer('audit-segregation')
    },
    subscriptionRestoration: {
      status: 'passed',
      initialState: 'on',
      offStateVerified: true,
      onStateRestored: true,
      originalTenantBoundaryRestored: true,
      versionBoundProof: validSubscriptionProof(),
      evidence: pointer('subscription-restoration')
    },
    unresolvedFailures: 0
  };
}

assert.equal(validateAuthenticatedUatEvidence(validUat(), { commit, tree, deployId }), true);
assert.equal(validateOwnerSubscriptionProof(validSubscriptionProof()), true);

for (const key of [
  'schemaVersion', 'scope', 'productionAuthorization', 'clinicId', 'clinicCode',
  'offRequestId', 'onRequestId', 'initialVersion', 'offExpectedVersion',
  'replayExpectedVersion', 'offVersion', 'onExpectedVersion', 'restoreVersion',
  'offPayloadSha256', 'replayPayloadSha256', 'onPayloadSha256',
  'offReplayIdempotent', 'recoveryDisposition', 'originalBoundary', 'restoredBoundary'
]) {
  const candidate = validSubscriptionProof();
  delete candidate[key];
  assert.throws(() => validateOwnerSubscriptionProof(candidate), /VERSION_BOUND_PROOF_INVALID/, `missing proof field ${key}`);
}
for (const boundaryName of ['originalBoundary', 'restoredBoundary']) {
  for (const key of ['clinicId', 'clinicCode', 'clinicRole', 'systemRole', 'effectiveRole', 'ready', 'clinical']) {
    const candidate = validSubscriptionProof();
    delete candidate[boundaryName][key];
    assert.throws(() => validateOwnerSubscriptionProof(candidate), /VERSION_BOUND_PROOF_INVALID/, `missing ${boundaryName}.${key}`);
  }
}
for (const version of [null, '7', Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER]) {
  const candidate = validSubscriptionProof();
  candidate.initialVersion = version;
  if (version === Number.MAX_SAFE_INTEGER - 1) {
    candidate.offExpectedVersion = version;
    candidate.replayExpectedVersion = version;
    candidate.offVersion = version + 1;
    candidate.onExpectedVersion = version + 1;
    candidate.restoreVersion = version + 2;
  }
  assert.throws(() => validateOwnerSubscriptionProof(candidate), /VERSION_BOUND_PROOF_INVALID/, `unsafe version ${String(version)}`);
}
const maxSafe = validSubscriptionProof();
maxSafe.initialVersion = Number.MAX_SAFE_INTEGER - 2;
maxSafe.offExpectedVersion = Number.MAX_SAFE_INTEGER - 2;
maxSafe.replayExpectedVersion = Number.MAX_SAFE_INTEGER - 2;
maxSafe.offVersion = Number.MAX_SAFE_INTEGER - 1;
maxSafe.onExpectedVersion = Number.MAX_SAFE_INTEGER - 1;
maxSafe.restoreVersion = Number.MAX_SAFE_INTEGER;
assert.equal(validateOwnerSubscriptionProof(maxSafe), true);
for (const [label, mutate] of [
  ['reused UUID', value => { value.onRequestId = value.offRequestId; }],
  ['malformed UUID', value => { value.offRequestId = 'not-a-uuid'; }],
  ['wrong target', value => { value.clinicCode = 'CHANANYA'; }],
  ['wrong role', value => { value.originalBoundary.clinicRole = 'admin'; }],
  ['wrong replay hash', value => { value.replayPayloadSha256 = 'c'.repeat(64); }],
  ['wrong OFF version', value => { value.offVersion = 9; }],
  ['wrong ON version', value => { value.onExpectedVersion = 9; }],
  ['non-idempotent replay', value => { value.offReplayIdempotent = false; }],
  ['unconfirmed recovery', value => { value.recoveryDisposition = 'needs_recovery'; }],
  ['sensitive response field', value => { value.responseBody = 'synthetic-no-token'; }]
]) {
  const candidate = validSubscriptionProof();
  mutate(candidate);
  assert.throws(() => validateOwnerSubscriptionProof(candidate), /VERSION_BOUND_PROOF_INVALID/, label);
}

for (const [label, mutate, pattern] of [
  ['missing role', value => value.identityProvisioning.roles.pop(), /IDENTITY_PROVISIONING_INVALID/],
  ['same count with duplicate role', value => { value.identityProvisioning.roles[10] = 'viewer'; value.identityProvisioning.roles[9] = 'viewer'; }, /IDENTITY_PROVISIONING_INVALID/],
  ['incomplete access matrix', value => { value.accessControl.departmentCanRoleCount = 10; }, /ACCESS_CONTROL_INVALID/],
  ['missing denied-route proof', value => { value.routeMatrix.deniedRouteBehaviorVerified = false; }, /ROUTE_MATRIX_INVALID/],
  ['one failed journey', value => { value.syntheticJourneys.passed = 9; value.syntheticJourneys.failed = 1; }, /JOURNEYS_INVALID/],
  ['unverified migration ledger', value => { value.migrationHealth.exactLedgerVerified = false; }, /DATABASE_GATES_INVALID/],
  ['subscription not restored', value => { value.subscriptionRestoration.onStateRestored = false; }, /SUBSCRIPTION_RESTORATION_INVALID/],
  ['legacy boolean-only subscription proof', value => { delete value.subscriptionRestoration.versionBoundProof; }, /VERSION_BOUND_PROOF_INVALID/],
  ['unresolved failure', value => { value.unresolvedFailures = 1; }, /UAT_EVIDENCE_INVALID/],
  ['missing gate hash', value => { delete value.routeMatrix.evidence.sha256; }, /ROUTE_MATRIX_INVALID/]
]) {
  const candidate = validUat();
  mutate(candidate);
  assert.throws(
    () => validateAuthenticatedUatEvidence(candidate, { commit, tree, deployId }),
    pattern,
    label
  );
}

const controllerRuntime = Object.freeze({
  repository: POLICY.controller.repository,
  ref: POLICY.controller.protectedRef,
  commit: 'd'.repeat(40),
  runId: '123456'
});
const postPromotionVerifiedAt = new Date('2026-09-08T12:00:00.000Z');
const routeDeniedAt = new Date('2026-09-08T12:01:00.000Z');
const uatCompletedAt = new Date('2026-09-08T12:02:00.000Z');
const routeObservedAt = new Date('2026-09-08T12:03:00.000Z');
const immutableOrigin = `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`;
const deployManifestSha256 = 'e'.repeat(64);
const promotionEvidenceSha256 = 'f'.repeat(64);
const postPromotionEvidenceSha256 = '9'.repeat(64);

function validScheduledRouteDenial() {
  const probes = [];
  const manifestObservations = [];
  for (const phase of ['before_route_probes', 'after_route_probes']) {
    for (const [originKind, origin] of [
      ['immutable', immutableOrigin],
      ['canonical', POLICY.target.netlifyOrigin]
    ]) {
      manifestObservations.push({
        phase,
        originKind,
        origin,
        status: 200,
        bodyByteLength: 512,
        bodySha256: deployManifestSha256,
        expectedArtifactBytesMatched: true,
        redirectFollowed: false,
        credentialForwarded: false
      });
    }
  }
  for (const [originKind, origin] of [
    ['immutable', immutableOrigin],
    ['canonical', POLICY.target.netlifyOrigin]
  ]) {
    for (const functionName of EXPECTED_SCHEDULED_ROUTE_DENIAL_FUNCTIONS) {
      for (const method of EXPECTED_SCHEDULED_ROUTE_DENIAL_METHODS) {
        probes.push({
          originKind,
          origin,
          functionName,
          method,
          path: `/.netlify/functions/${functionName}`,
          requestBodyKind: method === 'GET' ? 'none' : 'deliberately_malformed_json',
          status: 404,
          responseApplicationShaped: false,
          redirectFollowed: false,
          credentialForwarded: false
        });
      }
    }
  }
  return {
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_scheduled_function_route_denial',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    startedAt: routeDeniedAt.toISOString(),
    verifiedAt: routeDeniedAt.toISOString(),
    controllerRepository: controllerRuntime.repository,
    controllerRef: controllerRuntime.ref,
    controllerCommit: controllerRuntime.commit,
    controllerRunId: controllerRuntime.runId,
    source: { repository: POLICY.sourceRepository, commit, tree },
    target: { ...POLICY.target },
    netlifyDeployId: deployId,
    immutableOrigin,
    canonicalOrigin: POLICY.target.netlifyOrigin,
    deployManifestSha256,
    publisherExactCurrentEvidence: {
      beforeProbes: {
        promotionEvidenceSha256,
        postPromotionEvidenceSha256,
        currentPublishedDeployId: deployId,
        verifiedAt: postPromotionVerifiedAt.toISOString()
      },
      afterProbes: null
    },
    manifestObservations,
    probes
  };
}

const routeValidationOptions = Object.freeze({
  runtime: controllerRuntime,
  commit,
  tree,
  deployId,
  deployManifestSha256,
  deployManifestSize: 512,
  promotionEvidenceSha256,
  postPromotionEvidenceSha256,
  observedAt: routeObservedAt,
  notBefore: postPromotionVerifiedAt,
  notAfter: uatCompletedAt
});
assert.equal(
  validateScheduledFunctionRouteDenialEvidence(
    validScheduledRouteDenial(),
    routeValidationOptions
  ).toISOString(),
  routeDeniedAt.toISOString()
);
for (const [label, mutate] of [
  ['successful public response', value => { value.probes[0].status = 200; }],
  ['application-shaped denial', value => { value.probes[1].responseApplicationShaped = true; }],
  ['credential forwarding', value => { value.probes[2].credentialForwarded = true; }],
  ['redirect following', value => { value.probes[3].redirectFollowed = true; }],
  ['duplicate probe', value => { value.probes[7] = { ...value.probes[0] }; }],
  ['wrong malformed body', value => { value.probes[1].requestBodyKind = 'none'; }],
  ['extra unreviewed field', value => { value.probes[0].body = 'ignored'; }],
  ['stale evidence', value => {
    value.startedAt = '2026-09-08T11:32:59.999Z';
    value.verifiedAt = '2026-09-08T11:32:59.999Z';
  }],
  ['publisher receipt mismatch', value => {
    value.publisherExactCurrentEvidence.beforeProbes.postPromotionEvidenceSha256 = '8'.repeat(64);
  }],
  ['false post-probe publisher receipt', value => {
    value.publisherExactCurrentEvidence.afterProbes = { currentPublishedDeployId: deployId };
  }],
  ['manifest observation mismatch', value => {
    value.manifestObservations[3].bodySha256 = '7'.repeat(64);
  }],
  ['manifest observation size mismatch', value => {
    value.manifestObservations[2].bodyByteLength = 511;
  }],
  ['publisher receipt timestamp mismatch', value => {
    value.publisherExactCurrentEvidence.beforeProbes.verifiedAt =
      new Date(postPromotionVerifiedAt.getTime() + 1).toISOString();
  }]
]) {
  const candidate = validScheduledRouteDenial();
  mutate(candidate);
  assert.throws(
    () => validateScheduledFunctionRouteDenialEvidence(candidate, routeValidationOptions),
    /CNYOS_FINAL_SCHEDULED_ROUTE_DENIAL/,
    label
  );
}

assert.doesNotThrow(() => validateScheduledFunctionRouteDenialEvidence(
  validScheduledRouteDenial(),
  { ...routeValidationOptions, observedAt: new Date('2026-09-08T12:30:59.999Z') }
), 'route denial remains fresh through the controller authorization lifetime');
assert.throws(() => validateScheduledFunctionRouteDenialEvidence(
  validScheduledRouteDenial(),
  { ...routeValidationOptions, observedAt: new Date('2026-09-08T12:31:00.001Z') }
), /CNYOS_FINAL_SCHEDULED_ROUTE_DENIAL_TIMESTAMP_INVALID/,
'route denial expires after the controller authorization lifetime');

const finalCurrentArtifactSha256 = '1'.repeat(64);
const finalCurrentManifestSha256 = '4'.repeat(64);
const finalCurrentFunctionSourceTree = '5'.repeat(40);
const finalCurrentVerifiedAt = new Date('2026-09-08T12:02:30.000Z');
const finalCurrentObservedAt = new Date('2026-09-08T12:03:00.000Z');
const finalCurrentBundle = Object.freeze({
  manifestSha256: finalCurrentManifestSha256,
  manifest: Object.freeze({
    sourceRepository: POLICY.sourceRepository,
    candidateCommit: commit,
    candidateTree: tree,
    functionSourceTree: finalCurrentFunctionSourceTree,
    artifactSha256: finalCurrentArtifactSha256,
    dispatchNonce: 'final-current-dispatch-nonce',
    files: Object.freeze([
      Object.freeze({ path: 'payload/dist/index.html', size: 41, sha256: '6'.repeat(64) }),
      Object.freeze({ path: 'payload/dist/deploy-manifest.json', size: 512, sha256: '7'.repeat(64) }),
      Object.freeze({ path: 'payload/dist/_headers', size: 90, sha256: '8'.repeat(64) }),
      Object.freeze({ path: 'payload/dist/_redirects', size: 70, sha256: '9'.repeat(64) })
    ])
  })
});
const finalCurrentInventorySha256 = sha256(JSON.stringify([
  { path: '/index.html', size: 41, sha256: '6'.repeat(64) },
  { path: '/deploy-manifest.json', size: 512, sha256: '7'.repeat(64) }
]));

function validFinalCurrent() {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_final_current_verification',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: finalCurrentVerifiedAt.toISOString(),
    controllerRepository: controllerRuntime.repository,
    controllerRef: controllerRuntime.ref,
    controllerCommit: controllerRuntime.commit,
    controllerRunId: controllerRuntime.runId,
    dispatchNonce: finalCurrentBundle.manifest.dispatchNonce,
    source: {
      repository: POLICY.sourceRepository,
      commit,
      tree,
      functionSourceTree: finalCurrentFunctionSourceTree
    },
    artifact: {
      producerManifestSha256: finalCurrentManifestSha256,
      artifactSha256: finalCurrentArtifactSha256,
      fileCount: 2,
      closedWorldInventoryVerified: true,
      inventorySha256: finalCurrentInventorySha256
    },
    target: { ...POLICY.target },
    netlifyDeployId: deployId,
    exactDeployOrigin: immutableOrigin,
    currentPublishedDeployId: deployId,
    schedules: Object.entries(REQUIRED_SCHEDULES).map(([name, cron]) => ({ name, cron })),
    functionNames: [...EXPECTED_FUNCTION_NAMES],
    functionByteAttestationAvailable: false,
    verificationPhase: 'after_authenticated_uat',
    promotionEvidenceSha256
  };
}

const finalCurrentOptions = Object.freeze({
  runtime: controllerRuntime,
  bundle: finalCurrentBundle,
  commit,
  tree,
  artifactSha256: finalCurrentArtifactSha256,
  deployId,
  promotionEvidenceSha256,
  uatCompletedAt,
  observedAt: finalCurrentObservedAt
});
assert.equal(
  validateFinalCurrentEvidence(validFinalCurrent(), finalCurrentOptions).toISOString(),
  finalCurrentVerifiedAt.toISOString()
);
for (const [label, mutate] of [
  ['extra top-level field', value => { value.unreviewed = true; }],
  ['missing dispatch nonce', value => { delete value.dispatchNonce; }],
  ['wrong dispatch nonce', value => { value.dispatchNonce = 'other'; }],
  ['wrong source', value => { value.source.commit = '2'.repeat(40); }],
  ['extra source field', value => { value.source.unreviewed = true; }],
  ['wrong function source tree', value => { value.source.functionSourceTree = '2'.repeat(40); }],
  ['wrong manifest', value => { value.artifact.producerManifestSha256 = '2'.repeat(64); }],
  ['wrong artifact', value => { value.artifact.artifactSha256 = '2'.repeat(64); }],
  ['wrong file count', value => { value.artifact.fileCount = 1; }],
  ['open inventory', value => { value.artifact.closedWorldInventoryVerified = false; }],
  ['wrong inventory digest', value => { value.artifact.inventorySha256 = '2'.repeat(64); }],
  ['extra artifact field', value => { value.artifact.unreviewed = true; }],
  ['wrong deploy', value => { value.netlifyDeployId = '3'.repeat(24); }],
  ['wrong current deploy', value => { value.currentPublishedDeployId = '3'.repeat(24); }],
  ['wrong exact origin', value => { value.exactDeployOrigin = POLICY.target.netlifyOrigin; }],
  ['wrong promotion', value => { value.promotionEvidenceSha256 = '3'.repeat(64); }],
  ['missing schedule', value => { value.schedules.pop(); }],
  ['duplicate schedule', value => { value.schedules[1] = { ...value.schedules[0] }; }],
  ['wrong schedule cron', value => { value.schedules[0].cron = '* * * * *'; }],
  ['extra schedule field', value => { value.schedules[0].unreviewed = true; }],
  ['missing function', value => { value.functionNames.pop(); }],
  ['reordered function inventory', value => { value.functionNames.reverse(); }],
  ['false byte attestation', value => { value.functionByteAttestationAvailable = true; }],
  ['extra target field', value => { value.target.unreviewed = true; }],
  ['wrong phase', value => { value.verificationPhase = 'before_authenticated_uat'; }],
  ['before UAT', value => {
    value.verifiedAt = new Date(uatCompletedAt.getTime() - 1).toISOString();
  }],
  ['future receipt', value => {
    value.verifiedAt = new Date(finalCurrentObservedAt.getTime() + 1).toISOString();
  }]
]) {
  const candidate = validFinalCurrent();
  mutate(candidate);
  assert.throws(
    () => validateFinalCurrentEvidence(candidate, finalCurrentOptions),
    /CNYOS_FINAL_CURRENT_EVIDENCE_INVALID/,
    label
  );
}

process.stdout.write('CNYOS authenticated-UAT evidence schema contract: passed\n');
