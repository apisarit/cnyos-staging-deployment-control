import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

assert.notEqual(
  process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE,
  'true',
  'release-state reconciliation contract must remain offline and credential-free'
);

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporaryRoot = await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-release-state-reconciliation-contract-')
);
const isolatedRoot = path.join(temporaryRoot, 'isolated-controller');
const scriptsRoot = path.join(isolatedRoot, 'scripts');
await fs.mkdir(scriptsRoot, { recursive: true });
await Promise.all([
  fs.copyFile(
    path.join(packageRoot, 'scripts', 'verify-rollback-authorization-chain.mjs'),
    path.join(scriptsRoot, 'verify-rollback-authorization-chain.mjs')
  ),
  fs.copyFile(path.join(packageRoot, 'scripts', 'policy.mjs'), path.join(scriptsRoot, 'policy.mjs')),
  fs.copyFile(
    path.join(packageRoot, 'scripts', 'reconcile-netlify-release-state.mjs'),
    path.join(scriptsRoot, 'reconcile-netlify-release-state.mjs')
  ),
  fs.copyFile(
    path.join(packageRoot, 'scripts', 'verify-producer-bundle.mjs'),
    path.join(scriptsRoot, 'verify-producer-bundle.mjs')
  )
]);

function keyFixture(id, role, login, ownerName) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  return Object.freeze({
    pair,
    record: Object.freeze({
      id,
      role,
      githubLogin: login,
      ownerName,
      publicKeyPem,
      spkiSha256: crypto.createHash('sha256')
        .update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
    })
  });
}

const reconciliationKey = keyFixture(
  'reconciliation-signing-key-0001', 'broker', 'reconcile-broker', 'Reconciliation Broker'
);
const draftKey = keyFixture(
  'draft-signing-key-0001', 'broker', 'draft-broker', 'Draft Broker'
);
const rollbackKey = keyFixture(
  'rollback-signing-key-0001', 'broker', 'rollback-broker', 'Rollback Broker'
);
const reviewerKey = keyFixture(
  'independent-reviewer-key-0001', 'independent_security_reviewer',
  'IndependentReviewer', 'Independent Reviewer'
);
const riskKey = keyFixture(
  'managed-risk-owner-key-0001', 'managed_platform_risk_owner',
  'ManagedRiskOwner', 'Managed Risk Owner'
);

const sourcePolicy = JSON.parse(await fs.readFile(
  path.join(packageRoot, 'controller-policy.json'), 'utf8'
));
sourcePolicy.externalReconciliationBroker = {
  ...sourcePolicy.externalReconciliationBroker,
  origin: 'https://reconciliation.test',
  operationPath: '/v1/reconcile',
  policyId: 'reconciliation-policy-0001',
  policySha256: '1'.repeat(64),
  signingKeyId: reconciliationKey.record.id,
  signingPublicKeyPem: reconciliationKey.record.publicKeyPem,
  signingKeySpkiSha256: reconciliationKey.record.spkiSha256,
  oidcAudience: 'https://reconciliation.test/oidc'
};
sourcePolicy.draftLifecycleBroker = {
  ...sourcePolicy.draftLifecycleBroker,
  origin: 'https://draft.test',
  operationPath: '/v1/drafts',
  policyId: 'draft-policy-0001',
  policySha256: '2'.repeat(64),
  signingKeyId: draftKey.record.id,
  signingPublicKeyPem: draftKey.record.publicKeyPem,
  signingKeySpkiSha256: draftKey.record.spkiSha256,
  oidcAudience: 'https://draft.test/oidc'
};
sourcePolicy.rollbackAttestationBroker = {
  ...sourcePolicy.rollbackAttestationBroker,
  origin: 'https://rollback.test',
  policyId: 'rollback-policy-0001',
  policySha256: '3'.repeat(64),
  receiptSigningKeyId: rollbackKey.record.id,
  receiptSigningPublicKeyPem: rollbackKey.record.publicKeyPem,
  receiptSigningSpkiSha256: rollbackKey.record.spkiSha256,
  oidcAudience: 'https://rollback.test/oidc'
};
const isolatedPolicyRaw = `${JSON.stringify(sourcePolicy, null, 2)}\n`;
const isolatedPolicyPath = path.join(isolatedRoot, 'controller-policy.json');
await fs.writeFile(isolatedPolicyPath, isolatedPolicyRaw, { flag: 'wx', mode: 0o600 });

const policyModule = await import(`${pathToFileURL(path.join(scriptsRoot, 'policy.mjs')).href}?test=1`);
const reconciliation = await import(
  `${pathToFileURL(path.join(scriptsRoot, 'reconcile-netlify-release-state.mjs')).href}?test=1`
);
const { POLICY, POLICY_SHA256, deploymentMarker, sha256 } = policyModule;

assert.deepEqual(reconciliation.RECOVERY_DISPOSITIONS, [
  'recovery_required',
  'terminal_success_rehydrated',
  'terminal_recovery_rehydrated'
]);
assert.deepEqual(reconciliation.RECONCILIATION_MODES, [
  'assert-clean',
  'commit-successful-release',
  'prepare-failed-release-reconciliation',
  'execute-failed-release-reconciliation-plan',
  'finalize-failed-release-reconciliation-success',
  'finalize-rehydrated-successful-release',
  'finalize-rehydrated-recovery',
  'record-incomplete-failed-release-reconciliation',
  'prepare-watchdog-recovery',
  'execute-watchdog-recovery-plan',
  'finalize-watchdog-recovery-success',
  'record-incomplete-watchdog-recovery'
]);
const additionalForbiddenEnvironmentNames = Object.freeze([
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'SUPABASE_DB_PASSWORD',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64'
]);
for (const name of additionalForbiddenEnvironmentNames) {
  assert.ok(reconciliation.OIDC_FORBIDDEN_ENVIRONMENT_NAMES.includes(name));
  assert.ok(reconciliation.EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES.includes(name));
}

const observedAt = new Date('2032-01-01T00:05:00.000Z');
const issuedAt = '2032-01-01T00:04:00.000Z';
const expiresAt = '2032-01-01T00:10:00.000Z';
const targetRunId = '880001';
const mainRunId = targetRunId;
const watchdogRunId = '990001';
const targetCommit = 'a'.repeat(40);
const watchdogCommit = 'b'.repeat(40);
const sourceCommit = 'c'.repeat(40);
const previousDeployId = '1'.repeat(24);
const promotedDeployId = '2'.repeat(24);
const rejectedDraftId = '3'.repeat(24);
const nonce = Buffer.alloc(32, 0x42).toString('base64url');
const otherNonce = Buffer.alloc(32, 0x43).toString('base64url');
const generation = 'lease-generation-00000001';
const rollbackToken = 'offline_rollback_token_canary_which_never_leaves_netlify_headers';

const mainRuntime = Object.freeze({
  controllerRepository: POLICY.controller.repository,
  controllerRef: POLICY.controller.protectedRef,
  controllerWorkflowPath: POLICY.controller.releaseWorkflowPath,
  controllerRunId: mainRunId,
  controllerRunAttempt: 1,
  controllerCommit: targetCommit
});
const watchdogRuntime = Object.freeze({
  controllerRepository: POLICY.controller.repository,
  controllerRef: POLICY.controller.protectedRef,
  controllerWorkflowPath: POLICY.controller.rollbackWorkflowPath,
  controllerRunId: watchdogRunId,
  controllerRunAttempt: 1,
  controllerCommit: watchdogCommit
});
const baseTarget = Object.freeze({
  controllerRepository: POLICY.controller.repository,
  controllerRef: POLICY.controller.protectedRef,
  controllerWorkflowPath: POLICY.controller.releaseWorkflowPath,
  controllerRunId: targetRunId,
  controllerRunAttempt: 1,
  controllerCommit: targetCommit,
  dispatchNonce: nonce,
  netlifySiteId: POLICY.target.netlifySiteId,
  barrierGeneration: null
});
const claimedTarget = Object.freeze({ ...baseTarget, barrierGeneration: generation });

const trustKeys = Object.freeze({
  reconciliation: reconciliationKey.pair.privateKey,
  draft: draftKey.pair.privateKey,
  rollback: rollbackKey.pair.privateKey
});

function signatureFor(statement, privateKey, keyId) {
  const statementRaw = JSON.stringify(statement);
  const signature = crypto.sign(null, Buffer.from(statementRaw), privateKey);
  return Object.freeze({
    algorithm: 'Ed25519',
    keyId,
    statementSha256: sha256(statementRaw),
    signatureBase64: signature.toString('base64'),
    signatureSha256: sha256(signature)
  });
}

function brokerEnvelope(kind, operation, requestSha256, result, {
  issued = issuedAt,
  expires = expiresAt
} = {}) {
  const trust = reconciliation.brokerTrustRoot(kind);
  const statement = Object.freeze({
    schemaVersion: 1,
    operationDomain: trust.operationDomain,
    operation,
    policyId: trust.policyId,
    policySha256: trust.policySha256,
    requestSha256,
    issuedAt: issued,
    expiresAt: expires,
    result
  });
  return Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_broker_envelope',
    statement,
    brokerSignature: signatureFor(statement, trustKeys[kind], trust.signingKeyId)
  });
}

function terminalEnvelope(type, target, overrides = {}) {
  const record = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_terminal_record',
    status: 'committed',
    terminalType: type,
    terminalRecordId: type === 'committed_success'
      ? 'terminal-success-record-00000001' : 'terminal-recovery-record-00000001',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    target,
    barrierGeneration: target.barrierGeneration,
    claimId: type === 'committed_recovery' ? 'recovery-claim-00000001' : null,
    planCoreSha256: type === 'committed_recovery' ? '4'.repeat(64) : null,
    executionReceiptSha256: type === 'committed_recovery' ? '5'.repeat(64) : null,
    recoveryFinalizationGeneration:
      type === 'committed_recovery' ? 'recovery-finalization-00000001' : null,
    netlifyDeployId: type === 'committed_recovery' ? previousDeployId : promotedDeployId,
    finalEvidenceSha256: type === 'committed_success' ? '6'.repeat(64) : null,
    publisherReleaseEvidenceSha256: type === 'committed_success' ? '7'.repeat(64) : null,
    leaseActive: false,
    runReconciliationBarrierActive: false,
    automaticRunReconciliationBarrierExpiryPermitted: false,
    allRunOwnedDraftIntentsTerminal: true,
    rollbackEligible: false,
    committedAt: issuedAt,
    ...overrides
  });
  return Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_terminal_envelope',
    terminalRecord: record,
    brokerSignature: signatureFor(
      record, reconciliationKey.pair.privateKey, reconciliationKey.record.id
    )
  });
}

function resumerAuthorization(target, resumer) {
  return Object.freeze({
    targetControllerRepository: target.controllerRepository,
    targetControllerRef: target.controllerRef,
    targetControllerWorkflowPath: target.controllerWorkflowPath,
    targetControllerRunId: target.controllerRunId,
    targetControllerRunAttempt: target.controllerRunAttempt,
    targetControllerCommit: target.controllerCommit,
    targetDispatchNonce: target.dispatchNonce,
    targetNetlifySiteId: target.netlifySiteId,
    allowedResumerRepository: POLICY.controller.repository,
    allowedResumerProtectedRef: POLICY.controller.protectedRef,
    allowedResumerWorkflowPaths: [
      POLICY.controller.releaseWorkflowPath,
      POLICY.controller.rollbackWorkflowPath
    ],
    actualResumer: resumer
  });
}

function canonicalResponse(value, {
  redirected = false, status = 200, url, raw, additionalHeaders = []
} = {}) {
  const body = Buffer.from(raw ?? JSON.stringify(value));
  const headers = new Map([
    ['content-type', 'application/json; charset=utf-8'],
    ['content-length', String(body.byteLength)],
    ...additionalHeaders.map(([name, headerValue]) => [String(name).toLowerCase(), headerValue])
  ]);
  return {
    status,
    redirected,
    url,
    headers: {
      get: name => headers.get(String(name).toLowerCase()) ?? null,
      entries: () => headers.entries()
    },
    body: {
      getReader() {
        let delivered = false;
        return {
          async read() {
            if (delivered) return { done: true, value: undefined };
            delivered = true;
            return { done: false, value: Uint8Array.from(body) };
          },
          async cancel() {}
        };
      }
    }
  };
}

const globalFetch = globalThis.fetch;
let forbiddenGlobalNetworkCalls = 0;
globalThis.fetch = async () => {
  forbiddenGlobalNetworkCalls += 1;
  throw new Error('CNYOS_TEST_FORBIDS_GLOBAL_NETWORK');
};

function runtimeEnvironment(runtime) {
  return {
    GITHUB_REPOSITORY: runtime.controllerRepository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: runtime.controllerRepository,
    GITHUB_RUN_ID: runtime.controllerRunId,
    GITHUB_RUN_ATTEMPT: String(runtime.controllerRunAttempt),
    GITHUB_REF_PROTECTED: 'true',
    CNYOS_CONTROLLER_PROTECTED_REF: runtime.controllerRef,
    GITHUB_REF: runtime.controllerRef,
    GITHUB_SHA: runtime.controllerCommit,
    CNYOS_CONTROLLER_WORKFLOW_PATH: runtime.controllerWorkflowPath,
    GITHUB_WORKFLOW_REF:
      `${runtime.controllerRepository}/${runtime.controllerWorkflowPath}@${runtime.controllerRef}`,
    GITHUB_ACTOR: 'ManagedRiskOwner',
    GITHUB_TRIGGERING_ACTOR: 'ManagedRiskOwner'
  };
}

function targetEnvironment(target) {
  return {
    CNYOS_TARGET_CONTROLLER_RUN_ID: target.controllerRunId,
    CNYOS_TARGET_CONTROLLER_RUN_ATTEMPT: String(target.controllerRunAttempt),
    CNYOS_TARGET_CONTROLLER_COMMIT: target.controllerCommit,
    CNYOS_TARGET_CONTROLLER_REPOSITORY: target.controllerRepository
  };
}

function brokerEnvironment() {
  return {
    CNYOS_ROLLBACK_ATTESTATION_BROKER_URL: POLICY.rollbackAttestationBroker.origin,
    CNYOS_DRAFT_LIFECYCLE_BROKER_URL:
      `${POLICY.draftLifecycleBroker.origin}${POLICY.draftLifecycleBroker.operationPath}`,
    CNYOS_NETLIFY_PUBLISH_BROKER_URL:
      `${POLICY.externalReconciliationBroker.origin}` +
      `${POLICY.externalReconciliationBroker.operationPath}`
  };
}

const oidcCalls = [];
async function oidcTokenProvider({ audience }) {
  oidcCalls.push(audience);
  return `offline-oidc-token-for-${new URL(audience).hostname}`;
}

async function writeJsonFixture(name, value, { canonical = false } = {}) {
  const filename = path.join(temporaryRoot, name);
  const bytes = Buffer.from(canonical ? JSON.stringify(value) : `${JSON.stringify(value, null, 2)}\n`);
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, bytes, { flag: 'wx', mode: 0o600 });
  return Object.freeze({ filename, bytes, sha256: sha256(bytes), value });
}

async function expectCode(operation, expression) {
  await assert.rejects(operation, error => {
    assert.match(String(error?.message || ''), expression);
    return true;
  });
}

const reconciliationTrust = reconciliation.brokerTrustRoot('reconciliation');
assert.equal(reconciliationTrust.endpoint, 'https://reconciliation.test/v1/reconcile');
assert.equal(reconciliation.brokerTrustRoot('draft').endpoint, 'https://draft.test/v1/drafts');
assert.equal(reconciliation.brokerTrustRoot('rollback').endpoint, 'https://rollback.test/');

const verificationRequestSha = '8'.repeat(64);
const verificationResult = Object.freeze({ status: 'verified' });
const verifiedEnvelope = brokerEnvelope(
  'reconciliation', 'verification_probe', verificationRequestSha, verificationResult
);
assert.equal(reconciliation.verifySignedBrokerEnvelope(JSON.stringify(verifiedEnvelope), {
  trust: reconciliationTrust,
  operation: 'verification_probe',
  requestSha256: verificationRequestSha,
  observedAt
}).result.status, 'verified');
await expectCode(async () => reconciliation.verifySignedBrokerEnvelope(
  `${JSON.stringify(verifiedEnvelope)}\n`, {
    trust: reconciliationTrust,
    operation: 'verification_probe',
    requestSha256: verificationRequestSha,
    observedAt
  }), /NONCANONICAL/);
const unsignedMutation = structuredClone(verifiedEnvelope);
unsignedMutation.statement.result.status = 'tampered';
await expectCode(async () => reconciliation.verifySignedBrokerEnvelope(
  JSON.stringify(unsignedMutation), {
    trust: reconciliationTrust,
    operation: 'verification_probe',
    requestSha256: verificationRequestSha,
    observedAt
  }), /SIGNATURE_INVALID/);
await expectCode(async () => reconciliation.verifySignedBrokerEnvelope(
  JSON.stringify(brokerEnvelope('reconciliation', 'verification_probe', verificationRequestSha,
    verificationResult, {
      issued: '2031-12-31T23:40:00.000Z',
      expires: '2031-12-31T23:45:00.000Z'
    })), {
    trust: reconciliationTrust,
    operation: 'verification_probe',
    requestSha256: verificationRequestSha,
    observedAt
  }), /STALE/);
await expectCode(async () => reconciliation.verifySignedBrokerEnvelope(
  JSON.stringify(verifiedEnvelope), {
    trust: reconciliationTrust,
    operation: 'different_operation',
    requestSha256: verificationRequestSha,
    observedAt
  }), /RESPONSE_INVALID/);
await expectCode(async () => reconciliation.verifySignedBrokerEnvelope(
  JSON.stringify(verifiedEnvelope), {
    trust: reconciliationTrust,
    operation: 'verification_probe',
    requestSha256: '9'.repeat(64),
    observedAt
  }), /RESPONSE_INVALID/);

let timingProbeCompleted = false;
await expectCode(() => reconciliation.callSignedBrokerOperation({
  env: {},
  fetchImpl: async (url, options) => {
    assert.equal(options.credentials, 'omit');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.cache, 'no-store');
    timingProbeCompleted = true;
    return canonicalResponse(brokerEnvelope(
      'reconciliation', 'timing_probe', sha256(options.body), verificationResult,
      { issued: '2032-01-01T00:04:00.000Z', expires: '2032-01-01T00:05:00.000Z' }
    ), { url: url.href });
  },
  oidcTokenProvider,
  trust: reconciliationTrust,
  configuredUrl: reconciliationTrust.endpoint,
  operation: 'timing_probe',
  resumer: mainRuntime,
  target: baseTarget,
  evidence: Object.freeze({ probe: true }),
  now: () => timingProbeCompleted
    ? new Date('2032-01-01T00:05:01.000Z')
    : new Date('2032-01-01T00:04:30.000Z')
}), /BROKER_RESPONSE_STALE/);

const reflectedOidcToken = 'offline-oidc-token-reflection-canary-0001';
await expectCode(() => reconciliation.callSignedBrokerOperation({
  env: {},
  fetchImpl: async (url, options) => canonicalResponse(brokerEnvelope(
    'reconciliation', 'signed_body_reflection_probe', sha256(options.body),
    Object.freeze({ status: 'verified', reflectedCredential: reflectedOidcToken })
  ), { url: url.href }),
  oidcTokenProvider: async () => reflectedOidcToken,
  trust: reconciliationTrust,
  configuredUrl: reconciliationTrust.endpoint,
  operation: 'signed_body_reflection_probe',
  resumer: mainRuntime,
  target: baseTarget,
  evidence: Object.freeze({ probe: true }),
  now: () => observedAt
}), /OIDC_TOKEN_REFLECTION_INVALID/);
await expectCode(() => reconciliation.callSignedBrokerOperation({
  env: {},
  fetchImpl: async (url, options) => canonicalResponse(brokerEnvelope(
    'reconciliation', 'signed_header_reflection_probe', sha256(options.body),
    Object.freeze({ status: 'verified' })
  ), {
    url: url.href,
    additionalHeaders: [['x-reflected-credential', reflectedOidcToken]]
  }),
  oidcTokenProvider: async () => reflectedOidcToken,
  trust: reconciliationTrust,
  configuredUrl: reconciliationTrust.endpoint,
  operation: 'signed_header_reflection_probe',
  resumer: mainRuntime,
  target: baseTarget,
  evidence: Object.freeze({ probe: true }),
  now: () => observedAt
}), /OIDC_TOKEN_REFLECTION_INVALID/);

const authorizationBrokerBoundary = Object.freeze({
  policyId: POLICY.externalReconciliationBroker.policyId,
  policySha256: POLICY.externalReconciliationBroker.policySha256,
  executionAuthority: 'external_rollback_reconciliation_broker',
  immutablePolicy: true,
  independentOfTargetRunCode: true,
  independentOfWatchdogRevision: true,
  targetControllerRepository: baseTarget.controllerRepository,
  targetControllerRef: baseTarget.controllerRef,
  targetControllerRunId: baseTarget.controllerRunId,
  targetControllerRunAttempt: baseTarget.controllerRunAttempt,
  targetControllerCommit: baseTarget.controllerCommit,
  targetControllerWorkflowPath: baseTarget.controllerWorkflowPath,
  targetDispatchNonce: baseTarget.dispatchNonce,
  targetNetlifySiteId: baseTarget.netlifySiteId,
  targetRunCannotSuppressReconciliation: true,
  watchdogRevisionCannotSuppressReconciliation: true,
  enforcesRollback: true,
  enforcesDraftCleanup: true,
  enforcesLeaseRelease: true,
  enforcesRunReconciliationBarrier: true,
  atomicLeaseReleaseRetainsRunReconciliationBarrier: true,
  blocksNewMutationWhileRunReconciliationBarrierActive: true,
  successfulReleaseCommitRequiresFinalEvidenceHashes: true,
  draftIntentTerminalBeforeBarrierClearRequired: true,
  automaticRunReconciliationBarrierExpiryPermitted: false,
  exactTerminalCommitRetryIdempotent: true,
  terminalSuccessAndRecoveryClaimMutuallyExclusive: true,
  terminalSuccessNeverRollbackEligible: true,
  recoveryClaimConflictsWithDelayedTerminalCommit: true,
  recoveryTerminalRecordImmutableAndRetrievable: true,
  recoveryTerminalRecordBindsExecutionReceipt: true,
  exactRecoveryFinalizationRetryIdempotent: true,
  terminalRecoveryNeverRollbackEligible: true,
  recoveryClaimAndPlanCorePersistedAtomically: true,
  recoveryClaimPlanCoreImmutableAndRetrievable: true,
  exactRecoveryClaimRetryIdempotent: true,
  authorizedWatchdogRecoveryClaimResumptionEnforced: true,
  recoveryAuthorizationRefreshPreservesClaimAndPlanCore: true,
  conflictingRecoveryClaimBindingsOrGenerationRejected: true,
  automaticRecoveryClaimExpiryPermitted: false,
  incompleteRecoveryRecordPreservesRecoveryClaimAndPlan: true,
  recoveryClaimAuthorizedResumerRepository: POLICY.controller.repository,
  recoveryClaimAuthorizedResumerProtectedRef: POLICY.controller.protectedRef,
  recoveryClaimAuthorizedResumerWorkflowPaths: [
    POLICY.controller.releaseWorkflowPath,
    POLICY.controller.rollbackWorkflowPath
  ],
  evidence: { sha256: 'a'.repeat(64), reference: 'offline-contract-fixture' }
});

const authorizationSource = Object.freeze({
  repository: POLICY.sourceRepository,
  commit: sourceCommit,
  tree: 'd'.repeat(40),
  functionSourceTree: 'e'.repeat(40)
});
const authorizationArtifact = Object.freeze({
  producerManifestSha256: '0'.repeat(64),
  artifactSha256: 'b'.repeat(64),
  fileCount: 12,
  candidateBuildArtifactDigest: '1'.repeat(64),
  staticReproducibilityEvidenceSha256: '2'.repeat(64),
  staticArtifactSha256: '3'.repeat(64),
  candidateDependencyLockSha256: '4'.repeat(64),
  stagingConfigSha256: '5'.repeat(64),
  productionDenylistConfigSha256: '6'.repeat(64),
  functionBundleManifestSha256: '7'.repeat(64),
  functionBundleDependencyLockSha256: '8'.repeat(64),
  functionSourcesSha256: '9'.repeat(64),
  producerRunId: baseTarget.controllerRunId,
  githubArtifactDigest: 'a'.repeat(64)
});
const knownGood = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_bootstrap_known_good',
  status: 'passed',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  recordedAt: '2031-01-01T00:00:00.000Z',
  controllerRepository: POLICY.controller.repository,
  policySha256: POLICY_SHA256,
  source: { repository: POLICY.sourceRepository, commit: 'f'.repeat(40) },
  target: POLICY.target,
  netlifyDeployId: previousDeployId,
  evidence: { sha256: 'f'.repeat(64), reference: 'offline-known-good-fixture' }
});
const knownGoodBytes = Buffer.from(`${JSON.stringify(knownGood, null, 2)}\n`);

const authorizationPacket = Object.freeze({
  schemaVersion: 3,
  evidenceType: 'cnyos_staging_controller_authorization',
  controller: Object.freeze({
    repository: baseTarget.controllerRepository,
    ref: baseTarget.controllerRef,
    workflowPath: baseTarget.controllerWorkflowPath,
    workflowRef:
      `${baseTarget.controllerRepository}/${baseTarget.controllerWorkflowPath}@${baseTarget.controllerRef}`,
    runId: baseTarget.controllerRunId,
    runAttempt: baseTarget.controllerRunAttempt,
    commit: baseTarget.controllerCommit,
    dispatchNonce: baseTarget.dispatchNonce
  }),
  source: authorizationSource,
  artifact: authorizationArtifact,
  target: Object.freeze({ ...POLICY.target }),
  exactHeadCi: Object.freeze({}),
  runtimeCapabilityBoundary: Object.freeze({}),
  deploymentControlBoundary: Object.freeze({
    rollbackPrincipal: Object.freeze({ subject: 'rollback-principal-offline-subject' }),
    externalRollbackReconciliationBroker: authorizationBrokerBoundary
  }),
  principalProof: Object.freeze({}),
  independentSecurityReview: Object.freeze({}),
  managedPlatformRiskAcceptance: Object.freeze({}),
  rollbackRehearsal: Object.freeze({}),
  migrationPromotion: Object.freeze({}),
  strictPostRemediation: Object.freeze({}),
  rollback: Object.freeze({
    restoreOnAnyPostPublishFailure: true,
    externalWatchdogRequired: true,
    restoreOnlyControllerOwnedDeploy: true,
    previousDeployId,
    knownGoodEvidence: {
      sha256: sha256(knownGoodBytes),
      reference: 'offline-known-good-fixture'
    }
  }),
  signatureKeyIds: Object.freeze({
    independentSecurityReviewer: reviewerKey.record.id,
    managedPlatformRiskOwner: riskKey.record.id
  }),
  authorization: Object.freeze({
    decision: 'authorize_exact_cnyos_staging_controller_run',
    authorizedByGitHubLogin: 'ManagedRiskOwner',
    authorizedByName: 'Managed Risk Owner',
    authorizedByRole: 'Managed platform risk owner',
    authorizedAt: '2031-12-31T23:50:00.000Z',
    expiresAt: '2031-12-31T23:59:00.000Z',
    evidence: { sha256: 'b'.repeat(64), reference: 'offline-authorization-fixture' }
  }),
  productionAuthorization: false,
  realPatientDataAuthorized: false
});
const authorizationBytes = Buffer.from(JSON.stringify(authorizationPacket));
const reviewerSignature = crypto.sign(null, authorizationBytes, reviewerKey.pair.privateKey);
const riskSignature = crypto.sign(null, authorizationBytes, riskKey.pair.privateKey);
const registry = Object.freeze({
  schemaVersion: 1,
  environment: 'cnyos-staging',
  keys: [reviewerKey.record, riskKey.record]
});
const registryBytes = Buffer.from(`${JSON.stringify(registry, null, 2)}\n`);
const validationEvidence = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_authorization_validation',
  status: 'authorized',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  verifiedAt: '2031-12-31T23:55:00.000Z',
  controllerRepository: baseTarget.controllerRepository,
  controllerRef: baseTarget.controllerRef,
  controllerWorkflowPath: baseTarget.controllerWorkflowPath,
  controllerRunId: baseTarget.controllerRunId,
  controllerRunAttempt: baseTarget.controllerRunAttempt,
  controllerCommit: baseTarget.controllerCommit,
  dispatchNonce: baseTarget.dispatchNonce,
  authorizationExpiresAt: authorizationPacket.authorization.expiresAt,
  target: POLICY.target,
  source: authorizationPacket.source,
  artifact: authorizationPacket.artifact,
  previousDeployId,
  authorizationPacketSha256: sha256(authorizationBytes),
  knownGoodRollbackEvidenceSha256: sha256(knownGoodBytes),
  rollbackNetlifyPrincipalSubject: 'rollback-principal-offline-subject'
});
const authorizationBundle = Object.freeze({
  schemaVersion: 2,
  evidenceType: 'cnyos_staging_controller_authorization_verification_bundle',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  secretValuesSerialized: false,
  authorizationPacketSha256: sha256(authorizationBytes),
  authorizationDecision: { decision: 'authorize_exact_cnyos_staging_controller_run' },
  approverRegistrySha256: sha256(registryBytes),
  approverPublicKeys: [reviewerKey.record, riskKey.record],
  signatureKeyIds: authorizationPacket.signatureKeyIds,
  signatureSha256: {
    independentSecurityReviewer: sha256(reviewerSignature),
    managedPlatformRiskOwner: sha256(riskSignature)
  },
  knownGoodEvidence: {
    evidenceType: knownGood.evidenceType,
    sourceRepository: knownGood.source.repository,
    sourceCommit: knownGood.source.commit,
    netlifySiteId: knownGood.target.netlifySiteId,
    netlifyOrigin: knownGood.target.netlifyOrigin,
    netlifyDeployId: knownGood.netlifyDeployId
  },
  knownGoodEvidenceSha256: sha256(knownGoodBytes),
  validationEvidence
});
const authorizationBundleBytes = Buffer.from(`${JSON.stringify(authorizationBundle, null, 2)}\n`);

const depositReceipt = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_rollback_attestation_deposit_receipt',
  status: 'sealed',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  depositId: 'rollback-deposit-00000001',
  depositSequence: 1,
  depositRequestSha256: sha256('rollback-deposit-request-00000001'),
  broker: {
    origin: POLICY.rollbackAttestationBroker.origin,
    policyId: POLICY.rollbackAttestationBroker.policyId,
    policySha256: POLICY.rollbackAttestationBroker.policySha256,
    receiptSigningKeyId: POLICY.rollbackAttestationBroker.receiptSigningKeyId,
    receiptSigningSpkiSha256: POLICY.rollbackAttestationBroker.receiptSigningSpkiSha256
  },
  controller: {
    repository: baseTarget.controllerRepository,
    ref: baseTarget.controllerRef,
    commit: baseTarget.controllerCommit,
    workflowPath: baseTarget.controllerWorkflowPath,
    workflowRef:
      `${baseTarget.controllerRepository}/${baseTarget.controllerWorkflowPath}@${baseTarget.controllerRef}`,
    runId: baseTarget.controllerRunId,
    runAttempt: baseTarget.controllerRunAttempt,
    dispatchNonce: baseTarget.dispatchNonce,
    policySha256: POLICY_SHA256
  },
  source: authorizationSource,
  artifact: authorizationArtifact,
  target: {
    netlifySiteId: baseTarget.netlifySiteId,
    netlifyOrigin: POLICY.target.netlifyOrigin,
    supabaseProjectRef: POLICY.target.supabaseProjectRef,
    databaseSystemIdentifier: POLICY.target.databaseSystemIdentifier,
    targetSha256: sha256(JSON.stringify(POLICY.target)),
    previousDeployId
  },
  authorizationMaterial: {
    authorizationPacketSha256: sha256(authorizationBytes),
    authorizationBundleSha256: sha256(authorizationBundleBytes),
    approverRegistrySha256: sha256(registryBytes),
    independentSecurityReviewerKeyId: reviewerKey.record.id,
    independentSecurityReviewerSignatureSha256: sha256(reviewerSignature),
    managedPlatformRiskOwnerKeyId: riskKey.record.id,
    managedPlatformRiskOwnerSignatureSha256: sha256(riskSignature),
    knownGoodEvidenceSha256: sha256(knownGoodBytes)
  },
  depositSemantics: {
    appendOnly: true,
    immutable: true,
    oneDepositPerRunNonce: true,
    conflictingOverwriteRejected: true,
    identicalReplayReturnsOriginalReceipt: true,
    rawPayloadArtifactExposure: false
  },
  recoveryMaterial: {
    canonicalAuthorizationJsonStored: true,
    independentSecurityReviewerSignatureStored: true,
    managedPlatformRiskOwnerSignatureStored: true,
    knownGoodEvidenceBytesStored: true,
    authorizationVerificationBundleBytesStored: true,
    approverRegistryBytesStored: true,
    encryptedAtRest: true,
    hashVerifiedBeforeSeal: true,
    retrievableForRecovery: true
  },
  retrievalBoundary: {
    oidcAudience: POLICY.rollbackAttestationBroker.oidcAudience,
    requiredControllerRepository: baseTarget.controllerRepository,
    requiredControllerRef: baseTarget.controllerRef,
    requiredControllerWorkflowPath: baseTarget.controllerWorkflowPath,
    requiredControllerRunId: baseTarget.controllerRunId,
    requiredControllerRunAttempt: baseTarget.controllerRunAttempt,
    requiredDispatchNonce: baseTarget.dispatchNonce,
    externalReconciliationPolicyId: POLICY.externalReconciliationBroker.policyId,
    externalReconciliationPolicySha256: POLICY.externalReconciliationBroker.policySha256,
    failedRunCodeCannotDelete: true,
    watchdogRevisionCannotDelete: true,
    exactRunAndNonceRequired: true,
    oidcControllerIdentityRequired: true
  },
  depositedAt: '2031-12-31T23:55:00.000Z',
  retentionUntil: '2033-01-01T00:00:00.000Z'
});
const depositEnvelope = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
  receipt: depositReceipt,
  brokerSignature: signatureFor(
    depositReceipt, rollbackKey.pair.privateKey, rollbackKey.record.id
  )
});
const depositEnvelopeBytes = Buffer.from(JSON.stringify(depositEnvelope));
const recoveryMaterialResult = Object.freeze({
  target: baseTarget,
  depositReceiptEnvelopeBase64: depositEnvelopeBytes.toString('base64'),
  authorizationJsonBase64: authorizationBytes.toString('base64'),
  independentSecurityReviewerSignatureBase64: reviewerSignature.toString('base64'),
  managedPlatformRiskOwnerSignatureBase64: riskSignature.toString('base64'),
  knownGoodEvidenceBase64: knownGoodBytes.toString('base64'),
  authorizationBundleBase64: authorizationBundleBytes.toString('base64'),
  approverRegistryBase64: registryBytes.toString('base64')
});

const emptyDraftInventory = Object.freeze({
  target: baseTarget,
  inventoryComplete: true,
  intents: []
});

function recoveryClaim(core) {
  return Object.freeze({
    claimId: 'recovery-claim-00000001',
    claimKeySha256: reconciliation.recoveryClaimKeySha256(claimedTarget),
    barrierGeneration: generation,
    planCoreSha256: sha256(JSON.stringify(core)),
    createdAt: issuedAt,
    persistedAtomicallyWithPlanCore: true,
    immutable: true,
    exactRetryIdempotent: true,
    authorizedResumptionEnforced: true,
    authorizationRefreshPreservesPlanCore: true,
    automaticExpiryPermitted: false,
    incompleteRecordPreservesClaim: true
  });
}

class LocalAtomicBroker {
  constructor() {
    this.claim = null;
    this.core = null;
    this.terminal = null;
    this.incompleteCount = 0;
    this.claimCreationCount = 0;
    this.lossAfterCommit = false;
    this.failBeforeAtomicCommit = false;
  }

  candidateCore(request) {
    const rollback = request.evidence.rollbackAuthorization;
    const target = Object.freeze({ ...request.target, barrierGeneration: generation });
    return Object.freeze({
      target,
      previousDeployId: rollback.previousDeployId,
      currentDeployId: previousDeployId,
      knownGoodEvidenceSha256: rollback.knownGoodEvidenceSha256,
      rollbackAuthorizationChainSha256: request.evidence.rollbackAuthorizationChainSha256,
      orderedActions: [],
      draftIntents: request.evidence.draftIntents
    });
  }

  prepare(request) {
    const requestedCore = this.candidateCore(request);
    if (this.terminal) {
      const success = this.terminal.terminalRecord.terminalType === 'committed_success';
      return Object.freeze({
        recoveryDisposition: success ? 'terminal_success_rehydrated' :
          'terminal_recovery_rehydrated',
        target: this.terminal.terminalRecord.target,
        resumerAuthorization: resumerAuthorization(
          this.terminal.terminalRecord.target, request.resumer
        ),
        claim: null,
        planCore: null,
        planCoreSha256: null,
        rollbackAuthorizationChainSha256:
          request.evidence.rollbackAuthorizationChainSha256,
        terminalRecord: this.terminal
      });
    }
    if (!this.claim) {
      if (this.failBeforeAtomicCommit) throw new Error('INJECTED_BEFORE_ATOMIC_COMMIT');
      this.core = requestedCore;
      this.claim = recoveryClaim(requestedCore);
      this.claimCreationCount += 1;
      if (this.lossAfterCommit) {
        this.lossAfterCommit = false;
        throw new Error('INJECTED_RESPONSE_LOSS_AFTER_CLAIM_AND_CORE_COMMIT');
      }
    } else if (!assert.deepEqual(requestedCore, this.core)) {
      // assert.deepEqual returns undefined on equality and throws on conflict.
    }
    const target = this.core.target;
    if (request.resumer.controllerRepository !== POLICY.controller.repository ||
      request.resumer.controllerRef !== POLICY.controller.protectedRef ||
      ![POLICY.controller.releaseWorkflowPath, POLICY.controller.rollbackWorkflowPath]
        .includes(request.resumer.controllerWorkflowPath)) throw new Error('CONFLICTING_RESUMER');
    return Object.freeze({
      recoveryDisposition: 'recovery_required',
      target,
      resumerAuthorization: resumerAuthorization(target, request.resumer),
      claim: this.claim,
      planCore: this.core,
      planCoreSha256: sha256(JSON.stringify(this.core)),
      rollbackAuthorizationChainSha256: this.core.rollbackAuthorizationChainSha256,
      terminalRecord: null
    });
  }

  commitSuccess(request) {
    if (this.claim) throw new Error('RECOVERY_CLAIM_CONFLICTS_WITH_SUCCESS_COMMIT');
    const proposed = terminalEnvelope('committed_success', request.target, {
      netlifyDeployId: request.evidence.netlifyDeployId,
      finalEvidenceSha256: request.evidence.finalEvidenceSha256,
      publisherReleaseEvidenceSha256: request.evidence.publisherReleaseEvidenceSha256
    });
    if (this.terminal && !assert.deepEqual(this.terminal, proposed)) {}
    this.terminal ||= proposed;
    return Object.freeze({ status: 'committed', terminalRecord: this.terminal });
  }

  finalize(request) {
    const proposed = terminalEnvelope('committed_recovery', this.core.target, {
      claimId: this.claim.claimId,
      planCoreSha256: this.claim.planCoreSha256,
      executionReceiptSha256: request.evidence.executionReceiptSha256,
      netlifyDeployId: this.core.previousDeployId
    });
    if (this.terminal) assert.deepEqual(this.terminal, proposed);
    this.terminal ||= proposed;
    this.claim = null;
    return Object.freeze({
      status: 'committed',
      publisherLeaseReleased: true,
      runReconciliationBarrierActive: false,
      recoveryClaimPreserved: false,
      automaticExpiryPermitted: false,
      terminalRecord: this.terminal
    });
  }

  incomplete(request) {
    this.incompleteCount += 1;
    if (this.terminal) return Object.freeze({
      status: 'incomplete_recorded',
      target: this.terminal.terminalRecord.target,
      publisherLeaseReleased: true,
      runReconciliationBarrierActive: false,
      recoveryClaimPreserved: false,
      automaticExpiryPermitted: false
    });
    return Object.freeze({
      status: 'incomplete_recorded',
      target: this.core?.target || Object.freeze({
        ...request.target,
        dispatchNonce: request.target.dispatchNonce || nonce,
        barrierGeneration: generation
      }),
      publisherLeaseReleased: false,
      runReconciliationBarrierActive: true,
      recoveryClaimPreserved: this.claim !== null,
      automaticExpiryPermitted: false
    });
  }
}

function planRequest(resumer, rollbackChainSha256 = 'd'.repeat(64), target = baseTarget) {
  return Object.freeze({
    resumer,
    target,
    evidence: Object.freeze({
      rollbackAuthorizationChainSha256: rollbackChainSha256,
      rollbackAuthorization: Object.freeze({
        previousDeployId,
        knownGoodEvidenceSha256: sha256(knownGoodBytes),
        depositReceiptSha256: sha256(depositEnvelopeBytes),
        authorizationPacketSha256: sha256(authorizationBytes)
      }),
      draftIntents: [],
      producerLedger: null,
      recoveryClaimAndPlanCoreAtomicRequired: true,
      exactClaimResumptionRequired: true
    })
  });
}

const atomicBroker = new LocalAtomicBroker();
atomicBroker.lossAfterCommit = true;
assert.throws(() => atomicBroker.prepare(planRequest(mainRuntime)), /RESPONSE_LOSS/);
assert.equal(atomicBroker.claimCreationCount, 1);
const resumed = atomicBroker.prepare(planRequest(watchdogRuntime));
assert.equal(resumed.claim.claimId, 'recovery-claim-00000001');
assert.equal(resumed.claim.barrierGeneration, generation);
assert.equal(resumed.claim.planCoreSha256, sha256(JSON.stringify(resumed.planCore)));
assert.deepEqual(resumed.planCore.orderedActions, []);
assert.equal(resumed.resumerAuthorization.actualResumer.controllerRunId, watchdogRunId);
assert.equal(atomicBroker.claimCreationCount, 1);
const refreshed = atomicBroker.prepare(planRequest(mainRuntime));
assert.strictEqual(refreshed.planCore, resumed.planCore);
assert.strictEqual(refreshed.claim, resumed.claim);
const expiredPlanEnvelope = brokerEnvelope(
  'reconciliation', 'prepare_recovery', 'e'.repeat(64), refreshed,
  { issued: '2031-12-31T23:40:00.000Z', expires: '2031-12-31T23:45:00.000Z' }
);
await expectCode(async () => reconciliation.verifySignedBrokerEnvelope(
  JSON.stringify(expiredPlanEnvelope), {
    trust: reconciliationTrust,
    operation: 'prepare_recovery',
    requestSha256: 'e'.repeat(64),
    observedAt
  }), /STALE/);
const refreshedPlanEnvelope = brokerEnvelope(
  'reconciliation', 'prepare_recovery', 'f'.repeat(64), refreshed
);
assert.strictEqual(refreshedPlanEnvelope.statement.result.claim, resumed.claim);
assert.strictEqual(refreshedPlanEnvelope.statement.result.planCore, resumed.planCore);
assert.throws(() => atomicBroker.prepare(planRequest(mainRuntime, 'e'.repeat(64))),
  /Expected values to be strictly deep-equal/);
assert.throws(() => atomicBroker.prepare(planRequest({
  ...watchdogRuntime,
  controllerRepository: 'attacker/controller'
})), /CONFLICTING_RESUMER|Expected values/);
assert.throws(() => atomicBroker.prepare(planRequest(mainRuntime, 'd'.repeat(64), {
  ...baseTarget,
  controllerCommit: 'f'.repeat(40)
})), /Expected values/);
const beforeAtomic = new LocalAtomicBroker();
beforeAtomic.failBeforeAtomicCommit = true;
assert.throws(() => beforeAtomic.prepare(planRequest(mainRuntime)), /BEFORE_ATOMIC_COMMIT/);
assert.equal(beforeAtomic.claim, null);
assert.equal(beforeAtomic.core, null);
atomicBroker.incomplete(planRequest(watchdogRuntime));
assert.equal(atomicBroker.claim.claimId, resumed.claim.claimId);
assert.strictEqual(atomicBroker.core, resumed.planCore);
assert.throws(() => atomicBroker.commitSuccess({ target: claimedTarget, evidence: {} }),
  /RECOVERY_CLAIM_CONFLICTS/);

const raceBroker = new LocalAtomicBroker();
const raceResults = await Promise.all([
  Promise.resolve().then(() => raceBroker.prepare(planRequest(mainRuntime))),
  Promise.resolve().then(() => raceBroker.prepare(planRequest(watchdogRuntime)))
]);
assert.equal(raceBroker.claimCreationCount, 1);
assert.equal(raceResults[0].claim.claimId, raceResults[1].claim.claimId);
assert.strictEqual(raceResults[0].planCore, raceResults[1].planCore);

const validationAuthorization = Object.freeze({
  previousDeployId,
  knownGoodEvidenceSha256: sha256(knownGoodBytes),
  sourceCommit
});
const validatedPlan = brokerEnvelope(
  'reconciliation', 'prepare_recovery', '0'.repeat(64), resumed
);
const validatedPlanWrapper = Object.freeze({
  result: validatedPlan.statement.result
});
assert.equal(reconciliation.validateRecoveryPlanEnvelope(validatedPlanWrapper, {
  trust: reconciliationTrust,
  expectedTarget: baseTarget,
  expectedResumer: watchdogRuntime,
  rollbackAuthorization: validationAuthorization,
  rollbackChainSha256: 'd'.repeat(64),
  draftIntents: [],
  observedAt
}).result.recoveryDisposition, 'recovery_required');
const changedGenerationPlan = structuredClone(resumed);
changedGenerationPlan.claim.barrierGeneration = 'lease-generation-conflict';
await expectCode(async () => reconciliation.validateRecoveryPlanEnvelope(
  { result: changedGenerationPlan }, {
    trust: reconciliationTrust,
    expectedTarget: baseTarget,
    expectedResumer: watchdogRuntime,
    rollbackAuthorization: validationAuthorization,
    rollbackChainSha256: 'd'.repeat(64),
    draftIntents: [],
    observedAt
  }), /PLAN_INVALID/);

let brokerState = new LocalAtomicBroker();
const requestLog = [];
let injectedLoss = false;

function routeBrokerRequest(url, options) {
  assert.equal(options.method, 'POST');
  assert.equal(options.redirect, 'error');
  assert.ok(options.signal);
  assert.match(options.headers.Authorization, /^Bearer offline-oidc-token-for-/);
  assert.equal(options.body.includes(rollbackToken), false);
  const request = JSON.parse(options.body);
  requestLog.push(Object.freeze({ url: url.href, request, authorization: options.headers.Authorization }));
  let kind;
  let result;
  if (url.href === 'https://rollback.test/') {
    kind = 'rollback';
    assert.equal(request.operation, 'retrieve_recovery_material');
    result = recoveryMaterialResult;
  } else if (url.href === 'https://draft.test/v1/drafts') {
    kind = 'draft';
    assert.equal(request.operation, 'inventory_run_draft_intents');
    result = emptyDraftInventory;
  } else if (url.href === 'https://reconciliation.test/v1/reconcile') {
    kind = 'reconciliation';
    if (request.operation === 'assert_clean') {
      result = {
        status: 'clean',
        target: request.target,
        brokerInventoryComplete: true,
        allPriorRunsTerminal: true,
        activeRunReconciliationBarrierCount: 0,
        newMutationBlockedWhileAnyRunReconciliationBarrierActive: true,
        automaticRunReconciliationBarrierExpiryPermitted: false
      };
    } else if (request.operation === 'prepare_recovery') {
      try { result = brokerState.prepare(request); }
      catch (error) {
        if (String(error.message).includes('RESPONSE_LOSS')) injectedLoss = true;
        throw error;
      }
    } else if (request.operation === 'commit_successful_release') {
      result = brokerState.commitSuccess(request);
    } else if (request.operation === 'finalize_recovery') {
      result = brokerState.finalize(request);
    } else if (request.operation === 'record_incomplete_recovery') {
      result = brokerState.incomplete(request);
    } else if (request.operation === 'acknowledge_rehydrated_terminal') {
      result = {
        status: 'terminal_noop',
        publisherLeaseReleased: true,
        runReconciliationBarrierActive: false,
        recoveryClaimPreserved: false,
        automaticExpiryPermitted: false,
        terminalRecord: brokerState.terminal
      };
    } else throw new Error(`UNEXPECTED_RECONCILIATION_OPERATION:${request.operation}`);
  } else throw new Error(`UNEXPECTED_BROKER_URL:${url.href}`);
  const response = brokerEnvelope(kind, request.operation, sha256(options.body), result);
  return canonicalResponse(response, { url: url.href });
}

const preflight = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_preflight',
  controllerRepository: baseTarget.controllerRepository,
  controllerRef: baseTarget.controllerRef,
  controllerRunId: baseTarget.controllerRunId,
  controllerCommit: baseTarget.controllerCommit,
  dispatchNonce: baseTarget.dispatchNonce,
  target: POLICY.target,
  previousPublishedDeploy: { id: previousDeployId }
});
const preflightFile = await writeJsonFixture('main-input/preflight.json', preflight);
const bundleFile = await writeJsonFixture('main-input/authorization-verification-bundle.json',
  authorizationBundle);
assert.ok(bundleFile.bytes.equals(authorizationBundleBytes));
const depositFile = await writeJsonFixture('main-input/rollback-attestation-deposit-receipt.json',
  depositEnvelope, { canonical: true });
const registryFile = await writeJsonFixture('approver-registry.json', registry);

function mainPreparationEnvironment(label) {
  const outputRoot = path.join(temporaryRoot, label);
  return {
    ...runtimeEnvironment(mainRuntime),
    ...targetEnvironment(baseTarget),
    ...brokerEnvironment(),
    CNYOS_DISPATCH_NONCE: nonce,
    CNYOS_CONTROLLER_RECOVERY_INPUT_DIRECTORY: path.dirname(preflightFile.filename),
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.filename,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.sha256,
    CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: bundleFile.filename,
    CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: bundleFile.sha256,
    CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH: depositFile.filename,
    CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256: depositFile.sha256,
    CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH: registryFile.filename,
    CNYOS_DRAFT_INTENT_JOB_RESULT: 'failure',
    CNYOS_DRAFT_INTENT_ARTIFACT_DOWNLOAD_OUTCOME: 'skipped',
    CNYOS_DRAFT_DEPLOY_JOB_RESULT: 'failure',
    CNYOS_DRAFT_ARTIFACT_DOWNLOAD_OUTCOME: 'skipped',
    CNYOS_ACQUIRE_PUBLISHER_JOB_RESULT: 'failure',
    CNYOS_ATTEMPT_ARTIFACT_DOWNLOAD_OUTCOME: 'skipped',
    CNYOS_PROMOTION_JOB_RESULT: 'skipped',
    CNYOS_PROMOTION_ARTIFACT_DOWNLOAD_OUTCOME: 'skipped',
    CNYOS_ROUTE_VALIDATION_JOB_RESULT: 'skipped',
    CNYOS_UAT_JOB_RESULT: 'skipped',
    CNYOS_FINAL_CURRENT_JOB_RESULT: 'skipped',
    CNYOS_RELEASE_FINALIZE_JOB_RESULT: 'skipped',
    CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME: 'skipped',
    CNYOS_SUCCESSFUL_RELEASE_COMMIT_JOB_RESULT: 'skipped',
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: path.join(outputRoot, 'reconciliation-plan.json'),
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH:
      path.join(outputRoot, 'rollback-authorization-chain.json'),
    CNYOS_CONTROLLER_RECOVERY_DISPOSITION_PATH:
      path.join(outputRoot, 'recovery-disposition.txt'),
    CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH:
      path.join(outputRoot, 'successful-release-terminal.json'),
    CNYOS_CONTROLLER_RECOVERY_TERMINAL_EVIDENCE_PATH:
      path.join(outputRoot, 'recovery-terminal.json')
  };
}

const mismatchedPreflight = Object.freeze({
  ...preflight,
  previousPublishedDeploy: Object.freeze({ id: '4'.repeat(24) })
});
const mismatchedPreflightFile = await writeJsonFixture(
  'main-input/mismatched-previous-deploy-preflight.json', mismatchedPreflight
);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-failed-release-reconciliation',
  env: {
    ...mainPreparationEnvironment('mismatched-preflight'),
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: mismatchedPreflightFile.filename,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: mismatchedPreflightFile.sha256
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /PREFLIGHT_PREVIOUS_DEPLOY_MISMATCH/);

const mismatchedNoncePreflightFile = await writeJsonFixture(
  'main-input/mismatched-nonce-preflight.json',
  Object.freeze({ ...preflight, dispatchNonce: otherNonce })
);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-failed-release-reconciliation',
  env: {
    ...mainPreparationEnvironment('mismatched-preflight-nonce'),
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: mismatchedNoncePreflightFile.filename,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: mismatchedNoncePreflightFile.sha256
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /PREFLIGHT_NONCE_MISMATCH/);

const missingLocalBundleEnvironment = mainPreparationEnvironment('missing-local-bundle');
delete missingLocalBundleEnvironment.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH;
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-failed-release-reconciliation',
  env: missingLocalBundleEnvironment,
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /AUTHORIZATION_BUNDLE_INVALID/);

async function crossSourceDraftInventoryFetch(url, options) {
  if (url.href !== 'https://draft.test/v1/drafts') {
    return routeBrokerRequest(url, options);
  }
  const request = JSON.parse(options.body);
  const wrongSourceInventory = Object.freeze({
    target: request.target,
    inventoryComplete: true,
    intents: [Object.freeze({
      intentId: 'draft-intent-cross-source-0001',
      deployId: rejectedDraftId,
      status: 'deploy_created',
      ownershipMarker: deploymentMarker(targetRunId, nonce, 'f'.repeat(40))
    })]
  });
  return canonicalResponse(brokerEnvelope(
    'draft', request.operation, sha256(options.body), wrongSourceInventory
  ), { url: url.href });
}
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-failed-release-reconciliation',
  env: mainPreparationEnvironment('cross-source-draft-inventory'),
  fetchImpl: crossSourceDraftInventoryFetch,
  oidcTokenProvider,
  now: () => observedAt
}), /DRAFT_INVENTORY_INVALID/);

brokerState = new LocalAtomicBroker();
brokerState.lossAfterCommit = true;
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-failed-release-reconciliation',
  env: mainPreparationEnvironment('lost-main-preparation'),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /BROKER_REQUEST_FAILED/);
assert.equal(brokerState.claimCreationCount, 1);
assert.equal(injectedLoss, true);

const mainPreparation = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-failed-release-reconciliation',
  env: mainPreparationEnvironment('resumed-main-preparation'),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
const recoveryMaterialRequests = requestLog.filter(
  item => item.request.operation === 'retrieve_recovery_material'
);
assert.ok(recoveryMaterialRequests.length > 0);
for (const item of recoveryMaterialRequests) {
  assert.equal(Object.hasOwn(item.request.evidence, 'localDepositValidationSha256'), false,
    'client-derived deposit validation must not be broker recovery material');
}
assert.equal(Object.hasOwn(recoveryMaterialResult, 'depositValidationBase64'), false);
assert.equal(mainPreparation.recoveryDisposition, 'recovery_required');
assert.equal(mainPreparation.claimId, 'recovery-claim-00000001');
assert.equal(brokerState.claimCreationCount, 1);
const mainPlanBytes = await fs.readFile(mainPreparation.planPath);
const mainChainBytes = await fs.readFile(mainPreparation.chainPath);
const preparedPlan = JSON.parse(mainPlanBytes);
const mainChainEvidence = JSON.parse(mainChainBytes);
assert.equal(
  preparedPlan.statement.requestSha256,
  mainChainEvidence.prepareRequestSha256,
  'the separately hash-bound chain must retain the exact prepare request hash'
);
assert.equal(mainPlanBytes.at(-1), 0x7d, 'signed plan must remain canonical without a newline');
assert.equal(mainChainBytes.includes(authorizationBytes), false);
assert.equal(mainChainBytes.includes(reviewerSignature), false);
assert.equal(mainChainBytes.includes(riskSignature), false);
assert.equal(mainChainBytes.includes(knownGoodBytes), false);
assert.equal(mainChainBytes.includes(Buffer.from(rollbackToken)), false);

function watchdogPreparationEnvironment(label, runId = watchdogRunId) {
  const runtime = Object.freeze({ ...watchdogRuntime, controllerRunId: runId });
  const outputRoot = path.join(temporaryRoot, label);
  return {
    ...runtimeEnvironment(runtime),
    ...targetEnvironment(baseTarget),
    ...brokerEnvironment(),
    CNYOS_WATCHDOG_RUN_ID: runtime.controllerRunId,
    CNYOS_WATCHDOG_RUN_ATTEMPT: String(runtime.controllerRunAttempt),
    CNYOS_WATCHDOG_CONTROLLER_COMMIT: runtime.controllerCommit,
    CNYOS_CONTROLLER_POLICY_PATH: isolatedPolicyPath,
    CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH: registryFile.filename,
    CNYOS_CONTROLLER_RAW_RECOVERY_INPUT_DIRECTORY: path.join(outputRoot, 'raw'),
    CNYOS_CONTROLLER_RECOVERY_PLAN_PATH: path.join(outputRoot, 'recovery-plan.json'),
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH:
      path.join(outputRoot, 'rollback-chain-validation.json'),
    CNYOS_CONTROLLER_RECOVERY_DISPOSITION_PATH:
      path.join(outputRoot, 'recovery-disposition.txt'),
    CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH:
      path.join(outputRoot, 'successful-release-terminal.json'),
    CNYOS_CONTROLLER_RECOVERY_TERMINAL_EVIDENCE_PATH:
      path.join(outputRoot, 'recovery-terminal.json')
  };
}

const missingWatchdogPolicyEnvironment = watchdogPreparationEnvironment(
  'watchdog-missing-policy'
);
delete missingWatchdogPolicyEnvironment.CNYOS_CONTROLLER_POLICY_PATH;
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: missingWatchdogPolicyEnvironment,
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /POLICY_PATH_REQUIRED/);

const mismatchedRegistryFile = await writeJsonFixture('mismatched-approver-registry.json', {
  ...registry,
  environment: 'wrong-environment'
});
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: {
    ...watchdogPreparationEnvironment('watchdog-mismatched-registry'),
    CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH: mismatchedRegistryFile.filename
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /LOCAL_APPROVERREGISTRY_MISMATCH/);

const insufficientRetentionReceipt = Object.freeze({
  ...depositReceipt,
  retentionUntil: '2032-01-02T00:00:00.000Z'
});
const insufficientRetentionEnvelope = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
  receipt: insufficientRetentionReceipt,
  brokerSignature: signatureFor(
    insufficientRetentionReceipt, rollbackKey.pair.privateKey, rollbackKey.record.id
  )
});
const insufficientRetentionMaterial = Object.freeze({
  ...recoveryMaterialResult,
  depositReceiptEnvelopeBase64:
    Buffer.from(JSON.stringify(insufficientRetentionEnvelope)).toString('base64')
});
async function insufficientRetentionFetch(url, options) {
  if (url.href !== 'https://rollback.test/') return routeBrokerRequest(url, options);
  const request = JSON.parse(options.body);
  return canonicalResponse(brokerEnvelope(
    'rollback', request.operation, sha256(options.body), insufficientRetentionMaterial
  ), { url: url.href });
}
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: watchdogPreparationEnvironment('watchdog-insufficient-retention'),
  fetchImpl: insufficientRetentionFetch,
  oidcTokenProvider,
  now: () => observedAt
}), /DEPOSIT_RETENTION_INSUFFICIENT/);

for (const field of [
  'authorizationVerificationBundleBytesStored',
  'approverRegistryBytesStored'
]) {
  const incompleteReceipt = Object.freeze({
    ...depositReceipt,
    recoveryMaterial: Object.freeze({ ...depositReceipt.recoveryMaterial, [field]: false })
  });
  const incompleteEnvelope = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
    receipt: incompleteReceipt,
    brokerSignature: signatureFor(
      incompleteReceipt, rollbackKey.pair.privateKey, rollbackKey.record.id
    )
  });
  const incompleteMaterial = Object.freeze({
    ...recoveryMaterialResult,
    depositReceiptEnvelopeBase64:
      Buffer.from(JSON.stringify(incompleteEnvelope)).toString('base64')
  });
  const incompleteFetch = async (url, options) => {
    if (url.href !== 'https://rollback.test/') return routeBrokerRequest(url, options);
    const request = JSON.parse(options.body);
    return canonicalResponse(brokerEnvelope(
      'rollback', request.operation, sha256(options.body), incompleteMaterial
    ), { url: url.href });
  };
  await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
    mode: 'prepare-watchdog-recovery',
    env: watchdogPreparationEnvironment(`watchdog-incomplete-${field}`),
    fetchImpl: incompleteFetch,
    oidcTokenProvider,
    now: () => observedAt
  }), /DEPOSIT_RECEIPT_INVALID/);
}

const wrongBundleDigestReceipt = Object.freeze({
  ...depositReceipt,
  authorizationMaterial: Object.freeze({
    ...depositReceipt.authorizationMaterial,
    authorizationBundleSha256: '0'.repeat(64)
  })
});
const wrongBundleDigestEnvelope = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
  receipt: wrongBundleDigestReceipt,
  brokerSignature: signatureFor(
    wrongBundleDigestReceipt, rollbackKey.pair.privateKey, rollbackKey.record.id
  )
});
const wrongBundleDigestMaterial = Object.freeze({
  ...recoveryMaterialResult,
  depositReceiptEnvelopeBase64:
    Buffer.from(JSON.stringify(wrongBundleDigestEnvelope)).toString('base64')
});
async function wrongBundleDigestFetch(url, options) {
  if (url.href !== 'https://rollback.test/') return routeBrokerRequest(url, options);
  const request = JSON.parse(options.body);
  return canonicalResponse(brokerEnvelope(
    'rollback', request.operation, sha256(options.body), wrongBundleDigestMaterial
  ), { url: url.href });
}
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: watchdogPreparationEnvironment('watchdog-wrong-authorization-bundle-digest'),
  fetchImpl: wrongBundleDigestFetch,
  oidcTokenProvider,
  now: () => observedAt
}), /RECOVERY_MATERIAL_INVALID/);

const authorizationExpiredDepositReceipt = Object.freeze({
  ...depositReceipt,
  depositedAt: authorizationPacket.authorization.expiresAt
});
const authorizationExpiredDepositEnvelope = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
  receipt: authorizationExpiredDepositReceipt,
  brokerSignature: signatureFor(
    authorizationExpiredDepositReceipt, rollbackKey.pair.privateKey, rollbackKey.record.id
  )
});
const authorizationExpiredRecoveryMaterial = Object.freeze({
  ...recoveryMaterialResult,
  depositReceiptEnvelopeBase64:
    Buffer.from(JSON.stringify(authorizationExpiredDepositEnvelope)).toString('base64')
});
async function authorizationExpiredRecoveryFetch(url, options) {
  if (url.href !== 'https://rollback.test/') return routeBrokerRequest(url, options);
  const request = JSON.parse(options.body);
  return canonicalResponse(brokerEnvelope(
    'rollback', request.operation, sha256(options.body), authorizationExpiredRecoveryMaterial
  ), { url: url.href });
}
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: watchdogPreparationEnvironment('watchdog-authorization-expired-before-deposit'),
  fetchImpl: authorizationExpiredRecoveryFetch,
  oidcTokenProvider,
  now: () => observedAt
}), /RECOVERY_MATERIAL_INVALID/);

async function prematureGenerationFetch(url, options) {
  if (url.href !== 'https://rollback.test/') return routeBrokerRequest(url, options);
  const request = JSON.parse(options.body);
  return canonicalResponse(brokerEnvelope(
    'rollback', request.operation, sha256(options.body),
    Object.freeze({ ...recoveryMaterialResult, target: claimedTarget })
  ), { url: url.href });
}
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: watchdogPreparationEnvironment('watchdog-premature-generation'),
  fetchImpl: prematureGenerationFetch,
  oidcTokenProvider,
  now: () => observedAt
}), /RECOVERY_MATERIAL_INVALID/);

const watchdogPreparation = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'prepare-watchdog-recovery',
  env: watchdogPreparationEnvironment('watchdog-resumption'),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(watchdogPreparation.claimId, mainPreparation.claimId);
assert.equal(watchdogPreparation.planCoreSha256, mainPreparation.planCoreSha256);
const watchdogChainBytes = await fs.readFile(watchdogPreparation.chainPath);
const watchdogChainEvidence = JSON.parse(watchdogChainBytes);
const watchdogPreparedPlan = JSON.parse(await fs.readFile(watchdogPreparation.planPath));
assert.equal(watchdogPreparedPlan.statement.requestSha256,
  watchdogChainEvidence.prepareRequestSha256);
assert.notEqual(watchdogChainEvidence.prepareRequestSha256,
  mainChainEvidence.prepareRequestSha256,
  'different resumers must retain their exact distinct prepare request hashes');
const mainChainCore = structuredClone(mainChainEvidence);
const watchdogChainCore = structuredClone(watchdogChainEvidence);
delete mainChainCore.prepareRequestSha256;
delete watchdogChainCore.prepareRequestSha256;
assert.deepEqual(watchdogChainCore, mainChainCore,
  'prepare request binding must not change the sanitized authorization core');
assert.notDeepEqual(await fs.readFile(watchdogPreparation.planPath), mainPlanBytes,
  'fresh signed envelope binds the different authorized resumer');
assert.equal(brokerState.claimCreationCount, 1);

const planResult = preparedPlan.statement.result;
assert.equal(planResult.claim.persistedAtomicallyWithPlanCore, true);
assert.equal(planResult.claim.automaticExpiryPermitted, false);
assert.equal(planResult.claim.incompleteRecordPreservesClaim, true);
assert.equal(planResult.planCoreSha256, sha256(JSON.stringify(planResult.planCore)));

const cleanEvidencePath = path.join(temporaryRoot, 'clean/pre-release-reconciliation.json');
const clean = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'assert-clean',
  env: {
    ...runtimeEnvironment(mainRuntime),
    ...targetEnvironment(baseTarget),
    ...brokerEnvironment(),
    CNYOS_DISPATCH_NONCE: nonce,
    CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH: cleanEvidencePath
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(clean.evidence.activeRunReconciliationBarrierCount, 0);
assert.equal(clean.evidence.automaticRunReconciliationBarrierExpiryPermitted, false);

const maliciousUrlEnvironment = {
  ...runtimeEnvironment(mainRuntime),
  ...targetEnvironment(baseTarget),
  ...brokerEnvironment(),
  CNYOS_DISPATCH_NONCE: nonce,
  CNYOS_NETLIFY_PUBLISH_BROKER_URL: 'https://reconciliation.test.evil.invalid/v1/reconcile',
  CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH:
    path.join(temporaryRoot, 'invalid-url/evidence.json')
};
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'assert-clean', env: maliciousUrlEnvironment,
  fetchImpl: routeBrokerRequest, oidcTokenProvider, now: () => observedAt
}), /BROKER_URL_INVALID/);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'assert-clean',
  env: { ...maliciousUrlEnvironment,
    CNYOS_NETLIFY_PUBLISH_BROKER_URL:
      `${POLICY.externalReconciliationBroker.origin}${POLICY.externalReconciliationBroker.operationPath}`,
    CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: rollbackToken },
  fetchImpl: routeBrokerRequest, oidcTokenProvider, now: () => observedAt
}), /OIDC_CREDENTIAL_ISOLATION_INVALID/);
for (const name of additionalForbiddenEnvironmentNames) {
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
    mode: 'assert-clean',
    env: {
      ...maliciousUrlEnvironment,
      CNYOS_NETLIFY_PUBLISH_BROKER_URL:
        `${POLICY.externalReconciliationBroker.origin}` +
        `${POLICY.externalReconciliationBroker.operationPath}`,
      [name]: ''
    },
    fetchImpl: routeBrokerRequest,
    oidcTokenProvider,
    now: () => observedAt
  }), new RegExp(`OIDC_CREDENTIAL_ISOLATION_INVALID:${name}`));
}

function manualRecoveryPlan(resumer = mainRuntime) {
  const marker = deploymentMarker(targetRunId, nonce, sourceCommit);
  const intents = Object.freeze([Object.freeze({
    intentId: 'draft-intent-00000001',
    deployId: rejectedDraftId,
    status: 'deploy_created',
    ownershipMarker: marker
  })]);
  const core = Object.freeze({
    target: claimedTarget,
    previousDeployId,
    currentDeployId: promotedDeployId,
    knownGoodEvidenceSha256: sha256(knownGoodBytes),
    rollbackAuthorizationChainSha256: planResult.rollbackAuthorizationChainSha256,
    orderedActions: Object.freeze([
      Object.freeze({
        sequence: 1,
        kind: 'restore_previous_deploy',
        siteId: POLICY.target.netlifySiteId,
        fromDeployId: promotedDeployId,
        toDeployId: previousDeployId,
        requiredCurrentDeployId: promotedDeployId,
        requiredOwnershipMarker: marker
      }),
      Object.freeze({
        sequence: 2,
        kind: 'delete_run_owned_draft',
        siteId: POLICY.target.netlifySiteId,
        deployId: rejectedDraftId,
        intentId: intents[0].intentId,
        requiredOwnershipMarker: marker
      })
    ]),
    draftIntents: intents
  });
  const claim = recoveryClaim(core);
  return Object.freeze({
    recoveryDisposition: 'recovery_required',
    target: claimedTarget,
    resumerAuthorization: resumerAuthorization(claimedTarget, resumer),
    claim,
    planCore: core,
    planCoreSha256: sha256(JSON.stringify(core)),
    rollbackAuthorizationChainSha256: planResult.rollbackAuthorizationChainSha256,
    terminalRecord: null
  });
}

const manualPlanResult = manualRecoveryPlan();
const omittedDraftCleanupPlan = structuredClone(manualPlanResult);
omittedDraftCleanupPlan.planCore.orderedActions =
  omittedDraftCleanupPlan.planCore.orderedActions.slice(0, 1);
omittedDraftCleanupPlan.planCoreSha256 = sha256(JSON.stringify(omittedDraftCleanupPlan.planCore));
omittedDraftCleanupPlan.claim.planCoreSha256 = omittedDraftCleanupPlan.planCoreSha256;
await expectCode(async () => reconciliation.validateRecoveryPlanEnvelope(
  { result: omittedDraftCleanupPlan }, {
    trust: reconciliationTrust,
    expectedTarget: baseTarget,
    expectedResumer: mainRuntime,
    rollbackAuthorization: {
      previousDeployId,
      knownGoodEvidenceSha256: sha256(knownGoodBytes),
      sourceCommit
    },
    rollbackChainSha256: planResult.rollbackAuthorizationChainSha256,
    draftIntents: omittedDraftCleanupPlan.planCore.draftIntents,
    observedAt
  }
), /PLAN_INVALID/);
const crossSourceDeletePlan = structuredClone(manualPlanResult);
const crossSourceMarker = deploymentMarker(targetRunId, nonce, 'f'.repeat(40));
crossSourceDeletePlan.planCore.draftIntents[0].ownershipMarker = crossSourceMarker;
crossSourceDeletePlan.planCore.orderedActions[1].requiredOwnershipMarker = crossSourceMarker;
crossSourceDeletePlan.planCoreSha256 = sha256(JSON.stringify(crossSourceDeletePlan.planCore));
crossSourceDeletePlan.claim.planCoreSha256 = crossSourceDeletePlan.planCoreSha256;
await expectCode(async () => reconciliation.validateRecoveryPlanEnvelope(
  { result: crossSourceDeletePlan }, {
    trust: reconciliationTrust,
    expectedTarget: baseTarget,
    expectedResumer: mainRuntime,
    rollbackAuthorization: {
      previousDeployId,
      knownGoodEvidenceSha256: sha256(knownGoodBytes),
      sourceCommit
    },
    rollbackChainSha256: planResult.rollbackAuthorizationChainSha256,
    draftIntents: crossSourceDeletePlan.planCore.draftIntents,
    observedAt
  }
), /PLAN_INVALID/);
const manualPlanRequestSha = mainChainEvidence.prepareRequestSha256;
const manualPlanEnvelope = brokerEnvelope(
  'reconciliation', 'prepare_recovery', manualPlanRequestSha, manualPlanResult
);
const manualPlanFile = await writeJsonFixture(
  'execution/reconciliation-plan.json', manualPlanEnvelope, { canonical: true }
);
const manualChainFile = Object.freeze({
  filename: path.join(temporaryRoot, 'execution/rollback-authorization-chain.json'),
  bytes: mainChainBytes,
  sha256: sha256(mainChainBytes)
});
await fs.writeFile(manualChainFile.filename, manualChainFile.bytes, { flag: 'wx', mode: 0o600 });
const watchdogChainFile = Object.freeze({
  filename: path.join(temporaryRoot, 'watchdog-execution/rollback-authorization-chain.json'),
  bytes: watchdogChainBytes,
  sha256: sha256(watchdogChainBytes)
});
await fs.mkdir(path.dirname(watchdogChainFile.filename), { recursive: true });
await fs.writeFile(watchdogChainFile.filename, watchdogChainFile.bytes,
  { flag: 'wx', mode: 0o600 });

const netlifyState = {
  currentDeployId: promotedDeployId,
  drafts: new Set([rejectedDraftId]),
  calls: []
};
function netlifyObject(pathname) {
  const marker = deploymentMarker(targetRunId, nonce, sourceCommit);
  if (pathname === '/api/v1/user') return { id: 'rollback-principal-offline-subject' };
  if (pathname === '/api/v1/sites?per_page=100&page=1') return [{
    id: POLICY.target.netlifySiteId,
    name: POLICY.target.netlifySiteName,
    ssl_url: POLICY.target.netlifyOrigin
  }];
  if (pathname === `/api/v1/sites/${POLICY.target.netlifySiteId}`) return {
    id: POLICY.target.netlifySiteId,
    published_deploy: { id: netlifyState.currentDeployId }
  };
  const deployMatch = pathname.match(/^\/api\/v1\/deploys\/([0-9a-f]{24})$/);
  if (deployMatch) {
    const id = deployMatch[1];
    if (id === rejectedDraftId && !netlifyState.drafts.has(id)) return null;
    if (![previousDeployId, promotedDeployId, rejectedDraftId].includes(id)) return null;
    return {
      id,
      site_id: POLICY.target.netlifySiteId,
      title: id === previousDeployId ? 'known-good-baseline' : marker,
      state: 'ready',
      draft: id === rejectedDraftId,
      published_at: id === rejectedDraftId ? null : '2031-12-31T23:50:00.000Z'
    };
  }
  return undefined;
}

async function netlifyFetch(url, options) {
  assert.ok(url instanceof URL);
  assert.equal(url.origin, 'https://api.netlify.com');
  assert.equal(url.href.includes(rollbackToken), false);
  assert.equal(options.headers.Authorization, `Bearer ${rollbackToken}`);
  assert.equal(options.redirect, 'error');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.cache, 'no-store');
  assert.ok(options.signal);
  netlifyState.calls.push({ method: options.method, path: `${url.pathname}${url.search}` });
  const requestPath = `${url.pathname}${url.search}`;
  const restorePath = `/api/v1/sites/${POLICY.target.netlifySiteId}/deploys/${previousDeployId}/restore`;
  if (options.method === 'POST' && requestPath === restorePath) {
    netlifyState.currentDeployId = previousDeployId;
    return canonicalResponse({ id: previousDeployId }, { url: url.href, status: 200 });
  }
  if (options.method === 'DELETE' &&
    requestPath === `/api/v1/deploys/${rejectedDraftId}`) {
    netlifyState.drafts.delete(rejectedDraftId);
    return canonicalResponse({}, { url: url.href, status: 204 });
  }
  const value = netlifyObject(requestPath);
  if (value === null) return canonicalResponse({}, { url: url.href, status: 404 });
  if (value === undefined) throw new Error(`UNEXPECTED_NETLIFY_REQUEST:${options.method}:${requestPath}`);
  return canonicalResponse(value, { url: url.href });
}

function executionEnvironment(label, planFile = manualPlanFile) {
  return {
    ...runtimeEnvironment(mainRuntime),
    ...targetEnvironment(baseTarget),
    CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: rollbackToken,
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: planFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: planFile.sha256,
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: manualChainFile.filename,
    CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: manualChainFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_EXECUTION_RECEIPT_PATH:
      path.join(temporaryRoot, label, 'reconciliation-execution-receipt.json'),
    CNYOS_REQUIRED_RECOVERY_DISPOSITION: 'recovery_required'
  };
}

const execution = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-failed-release-reconciliation-plan',
  env: executionEnvironment('execution-first'),
  fetchImpl: netlifyFetch,
  now: () => observedAt
});
assert.equal(execution.receipt.actionResults[0].result, 'restored_previous_deploy');
assert.equal(execution.receipt.actionResults[1].result, 'deleted_run_owned_draft');
assert.equal(execution.receipt.publisherLeaseReleased, false);
assert.equal(execution.receipt.runReconciliationBarrierReleased, false);
assert.equal(netlifyState.currentDeployId, previousDeployId);
assert.equal(netlifyState.drafts.has(rejectedDraftId), false);
assert.equal(JSON.stringify(execution.receipt).includes(rollbackToken), false);
const executionReceiptBytes = await fs.readFile(execution.receiptPath);
const executionReceiptSha256 = sha256(executionReceiptBytes);

const executionRetry = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-failed-release-reconciliation-plan',
  env: executionEnvironment('execution-retry'),
  fetchImpl: netlifyFetch,
  now: () => observedAt
});
assert.equal(executionRetry.receipt.actionResults[0].result, 'already_restored');
assert.equal(executionRetry.receipt.actionResults[1].result, 'already_absent');

netlifyState.currentDeployId = '4'.repeat(24);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-failed-release-reconciliation-plan',
  env: executionEnvironment('execution-current-conflict'),
  fetchImpl: netlifyFetch,
  now: () => observedAt
}), /CURRENT_DEPLOY_CONFLICT/);
netlifyState.currentDeployId = previousDeployId;

const watchdogManualPlanResult = manualRecoveryPlan(watchdogRuntime);
const watchdogManualPlanFile = await writeJsonFixture(
  'watchdog-execution/recovery-plan.json',
  brokerEnvelope(
    'reconciliation', 'prepare_recovery',
    watchdogChainEvidence.prepareRequestSha256, watchdogManualPlanResult
  ),
  { canonical: true }
);
netlifyState.currentDeployId = promotedDeployId;
netlifyState.drafts = new Set([rejectedDraftId]);
const watchdogExecutionEnvironment = {
  ...runtimeEnvironment(watchdogRuntime),
  ...targetEnvironment(baseTarget),
  CNYOS_WATCHDOG_RUN_ID: watchdogRuntime.controllerRunId,
  CNYOS_WATCHDOG_RUN_ATTEMPT: String(watchdogRuntime.controllerRunAttempt),
  CNYOS_WATCHDOG_CONTROLLER_COMMIT: watchdogRuntime.controllerCommit,
  CNYOS_CONTROLLER_POLICY_PATH: isolatedPolicyPath,
  CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: rollbackToken,
  CNYOS_CONTROLLER_RECOVERY_PLAN_PATH: watchdogManualPlanFile.filename,
  CNYOS_EXPECTED_RECOVERY_PLAN_SHA256: watchdogManualPlanFile.sha256,
  CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: watchdogChainFile.filename,
  CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: watchdogChainFile.sha256,
  CNYOS_CONTROLLER_RECOVERY_EXECUTION_RECEIPT_PATH:
    path.join(temporaryRoot, 'watchdog-execution/recovery-execution-receipt.json'),
  CNYOS_REQUIRED_RECOVERY_DISPOSITION: 'recovery_required'
};
const watchdogExecution = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-watchdog-recovery-plan',
  env: watchdogExecutionEnvironment,
  fetchImpl: netlifyFetch,
  now: () => observedAt
});
assert.equal(watchdogExecution.receipt.executor.controllerWorkflowPath,
  POLICY.controller.rollbackWorkflowPath);
assert.equal(watchdogExecution.receipt.actionResults[0].result,
  'restored_previous_deploy');
assert.equal(watchdogExecution.receipt.actionResults[1].result,
  'deleted_run_owned_draft');

await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-failed-release-reconciliation-plan',
  env: { ...executionEnvironment('execution-forbidden'),
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.actions.test' },
  fetchImpl: netlifyFetch,
  now: () => observedAt
}), /EXECUTION_CREDENTIAL_ISOLATION_INVALID/);
for (const name of additionalForbiddenEnvironmentNames) {
  await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
    mode: 'execute-failed-release-reconciliation-plan',
    env: { ...executionEnvironment(`execution-forbidden-${name}`), [name]: '' },
    fetchImpl: netlifyFetch,
    now: () => observedAt
  }), new RegExp(`EXECUTION_CREDENTIAL_ISOLATION_INVALID:${name}`));
}

const unrelatedRequestPlanFile = await writeJsonFixture(
  'execution/unrelated-prepare-request-plan.json',
  brokerEnvelope(
    'reconciliation', 'prepare_recovery', 'f'.repeat(64), manualPlanResult
  ),
  { canonical: true }
);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-failed-release-reconciliation-plan',
  env: executionEnvironment('execution-unrelated-request', unrelatedRequestPlanFile),
  fetchImpl: netlifyFetch,
  now: () => observedAt
}), /BROKER_RESPONSE_INVALID/);

const changedActionEnvelope = structuredClone(manualPlanEnvelope);
for (const [label, field, replacement, failure] of [
  ['wrong-schema', 'schemaVersion', 2, /ROLLBACK_CHAIN_INVALID/],
  ['wrong-scope', 'scope', 'production', /ROLLBACK_CHAIN_INVALID/],
  ['changed-source', 'sourceCommit', 'e'.repeat(40), /PLAN_INVALID/]
]) {
  const changedChain = await writeJsonFixture(`execution/${label}-chain.json`, {
    ...mainChainEvidence, [field]: replacement
  });
  let providerCalls = 0;
  await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
    mode: 'execute-failed-release-reconciliation-plan',
    env: {
      ...executionEnvironment(`execution-${label}`),
      CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: changedChain.filename,
      CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: changedChain.sha256
    },
    fetchImpl: async () => { providerCalls += 1; throw new Error('UNEXPECTED_PROVIDER_CALL'); },
    now: () => observedAt
  }), failure);
  assert.equal(providerCalls, 0,
    'changing a chain and its local hash cannot authorize a provider request');
}
changedActionEnvelope.statement.result.planCore.orderedActions[0].toDeployId = rejectedDraftId;
const changedActionFile = await writeJsonFixture(
  'execution/changed-action-plan.json', changedActionEnvelope, { canonical: true }
);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'execute-failed-release-reconciliation-plan',
  env: executionEnvironment('execution-tampered', changedActionFile),
  fetchImpl: netlifyFetch,
  now: () => observedAt
}), /BROKER_SIGNATURE_INVALID/);

const finalizationPlanResult = manualRecoveryPlan();
const finalizationPlanEnvelope = brokerEnvelope(
  'reconciliation', 'prepare_recovery',
  mainChainEvidence.prepareRequestSha256, finalizationPlanResult
);
const finalizationPlanFile = await writeJsonFixture(
  'finalize/reconciliation-plan.json', finalizationPlanEnvelope, { canonical: true }
);
const finalizationReceiptValue = {
  ...execution.receipt,
  reconciliationPlanSha256: finalizationPlanFile.sha256
};
const finalizationReceiptFile = await writeJsonFixture(
  'finalize/reconciliation-execution-receipt.json', finalizationReceiptValue
);
brokerState = new LocalAtomicBroker();
brokerState.core = finalizationPlanResult.planCore;
brokerState.claim = finalizationPlanResult.claim;
const finalizationEnv = {
  ...runtimeEnvironment(mainRuntime),
  ...targetEnvironment(baseTarget),
  ...brokerEnvironment(),
  CNYOS_PREPARATION_JOB_RESULT: 'success',
  CNYOS_PREPARATION_DOWNLOAD_OUTCOME: 'success',
  CNYOS_EXECUTION_JOB_RESULT: 'success',
  CNYOS_EXECUTION_DOWNLOAD_OUTCOME: 'success',
  CNYOS_RECOVERY_DISPOSITION: 'recovery_required',
  CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: finalizationPlanFile.filename,
  CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: finalizationPlanFile.sha256,
  CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: manualChainFile.filename,
  CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: manualChainFile.sha256,
  CNYOS_CONTROLLER_RECONCILIATION_EXECUTION_RECEIPT_PATH: finalizationReceiptFile.filename,
  CNYOS_EXPECTED_RECONCILIATION_EXECUTION_RECEIPT_SHA256: finalizationReceiptFile.sha256,
  CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'finalize/reconciliation-finalization.json')
};
const semanticallyInvalidReceipt = structuredClone(finalizationReceiptValue);
semanticallyInvalidReceipt.actionResults[0].result = 'deleted_run_owned_draft';
const semanticallyInvalidReceiptFile = await writeJsonFixture(
  'finalize/semantically-invalid-execution-receipt.json', semanticallyInvalidReceipt
);
const mainPlanPrecommitFailure = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-failed-release-reconciliation-success',
  env: {
    ...finalizationEnv,
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: unrelatedRequestPlanFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: unrelatedRequestPlanFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'finalize/plan-precommit-incomplete.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(mainPlanPrecommitFailure.evidence.status, 'incomplete_recorded');
assert.equal(mainPlanPrecommitFailure.evidence.claimId, null);
assert.equal(requestLog.at(-1).request.operation, 'record_incomplete_recovery');
assert.equal(requestLog.at(-1).request.evidence.claim, null);
const incompleteCountBeforeMainPrecommitFailure = brokerState.incompleteCount;
const mainPrecommitFailure = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-failed-release-reconciliation-success',
  env: {
    ...finalizationEnv,
    CNYOS_CONTROLLER_RECONCILIATION_EXECUTION_RECEIPT_PATH:
      semanticallyInvalidReceiptFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_EXECUTION_RECEIPT_SHA256:
      semanticallyInvalidReceiptFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'finalize/precommit-incomplete.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(mainPrecommitFailure.evidence.status, 'incomplete_recorded');
assert.equal(mainPrecommitFailure.evidence.incompleteReason,
  'finalizer_precommit_validation_failed');
assert.equal(mainPrecommitFailure.evidence.claimId, null,
  'an untrusted plan must not be represented as a validated claim');
assert.equal(brokerState.incompleteCount, incompleteCountBeforeMainPrecommitFailure + 1);
assert.equal(brokerState.terminal, null);
assert.equal(brokerState.claim.claimId, finalizationPlanResult.claim.claimId);
const mainPrecommitRequest = requestLog.at(-1).request;
assert.equal(mainPrecommitRequest.operation, 'record_incomplete_recovery');
assert.equal(mainPrecommitRequest.evidence.claim, null);
const finalized = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-failed-release-reconciliation-success',
  env: finalizationEnv,
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(finalized.evidence.runReconciliationBarrierActive, false);
assert.equal(finalized.evidence.recoveryClaimPreserved, false);
assert.equal(finalized.evidence.executionReceiptSha256, finalizationReceiptFile.sha256);

const watchdogFinalizationPlanResult = manualRecoveryPlan(watchdogRuntime);
const watchdogFinalizationPlanFile = await writeJsonFixture(
  'watchdog-finalize/recovery-plan.json',
  brokerEnvelope(
      'reconciliation', 'prepare_recovery',
      watchdogChainEvidence.prepareRequestSha256, watchdogFinalizationPlanResult
  ),
  { canonical: true }
);
const watchdogFinalizationReceipt = {
  ...watchdogExecution.receipt,
  reconciliationPlanSha256: watchdogFinalizationPlanFile.sha256
};
const watchdogFinalizationReceiptFile = await writeJsonFixture(
  'watchdog-finalize/recovery-execution-receipt.json', watchdogFinalizationReceipt
);
brokerState = new LocalAtomicBroker();
brokerState.core = watchdogFinalizationPlanResult.planCore;
brokerState.claim = watchdogFinalizationPlanResult.claim;
const watchdogFinalizationEnvironment = {
  ...runtimeEnvironment(watchdogRuntime),
  ...targetEnvironment(baseTarget),
  ...brokerEnvironment(),
  CNYOS_WATCHDOG_RUN_ID: watchdogRuntime.controllerRunId,
  CNYOS_WATCHDOG_RUN_ATTEMPT: String(watchdogRuntime.controllerRunAttempt),
  CNYOS_WATCHDOG_CONTROLLER_COMMIT: watchdogRuntime.controllerCommit,
  CNYOS_CONTROLLER_POLICY_PATH: isolatedPolicyPath,
  CNYOS_RECOVERY_PREPARATION_JOB_RESULT: 'success',
  CNYOS_RECOVERY_PLAN_DOWNLOAD_OUTCOME: 'success',
  CNYOS_RECOVERY_EXECUTION_JOB_RESULT: 'success',
  CNYOS_RECOVERY_EXECUTION_RECEIPT_DOWNLOAD_OUTCOME: 'success',
  CNYOS_RECOVERY_DISPOSITION: 'recovery_required',
  CNYOS_CONTROLLER_RECOVERY_PLAN_PATH: watchdogFinalizationPlanFile.filename,
  CNYOS_EXPECTED_RECOVERY_PLAN_SHA256: watchdogFinalizationPlanFile.sha256,
  CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: watchdogChainFile.filename,
  CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: watchdogChainFile.sha256,
  CNYOS_CONTROLLER_RECOVERY_EXECUTION_RECEIPT_PATH:
    watchdogFinalizationReceiptFile.filename,
  CNYOS_EXPECTED_RECOVERY_EXECUTION_RECEIPT_SHA256:
    watchdogFinalizationReceiptFile.sha256,
  CNYOS_CONTROLLER_RECOVERY_FINALIZATION_EVIDENCE_PATH:
    path.join(temporaryRoot, 'watchdog-finalize/recovery-finalization.json')
};
const invalidWatchdogReceipt = structuredClone(watchdogFinalizationReceipt);
invalidWatchdogReceipt.actionResults[1].result = 'restored_previous_deploy';
const invalidWatchdogReceiptFile = await writeJsonFixture(
  'watchdog-finalize/semantically-invalid-receipt.json', invalidWatchdogReceipt
);
const watchdogPrecommitFailure = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-watchdog-recovery-success',
  env: {
    ...watchdogFinalizationEnvironment,
    CNYOS_CONTROLLER_RECOVERY_EXECUTION_RECEIPT_PATH: invalidWatchdogReceiptFile.filename,
    CNYOS_EXPECTED_RECOVERY_EXECUTION_RECEIPT_SHA256: invalidWatchdogReceiptFile.sha256,
    CNYOS_CONTROLLER_RECOVERY_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'watchdog-finalize/precommit-incomplete.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(watchdogPrecommitFailure.evidence.status, 'incomplete_recorded');
assert.equal(watchdogPrecommitFailure.evidence.claimId, null);
assert.equal(brokerState.terminal, null);
assert.equal(brokerState.claim.claimId, watchdogFinalizationPlanResult.claim.claimId);
assert.equal(requestLog.at(-1).request.operation, 'record_incomplete_recovery');
assert.equal(requestLog.at(-1).request.evidence.claim, null);
const watchdogFinalization = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-watchdog-recovery-success',
  env: watchdogFinalizationEnvironment,
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(watchdogFinalization.evidence.finalizer.controllerWorkflowPath,
  POLICY.controller.rollbackWorkflowPath);
assert.equal(watchdogFinalization.evidence.runReconciliationBarrierActive, false);

const terminalRecovery = brokerState.terminal;
const terminalRecoveryFile = await writeJsonFixture(
  'terminal-recovery/recovery-terminal.json', terminalRecovery, { canonical: true }
);
const terminalRecoveryPlanResult = Object.freeze({
  recoveryDisposition: 'terminal_recovery_rehydrated',
  target: claimedTarget,
  resumerAuthorization: resumerAuthorization(claimedTarget, mainRuntime),
  claim: null,
  planCore: null,
  planCoreSha256: null,
  rollbackAuthorizationChainSha256: planResult.rollbackAuthorizationChainSha256,
  terminalRecord: terminalRecovery
});
const terminalRecoveryPlanFile = await writeJsonFixture(
  'terminal-recovery/reconciliation-plan.json',
  brokerEnvelope(
    'reconciliation', 'prepare_recovery',
    mainChainEvidence.prepareRequestSha256, terminalRecoveryPlanResult
  ),
  { canonical: true }
);
const terminalRecoveryResult = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-rehydrated-recovery',
  env: {
    ...runtimeEnvironment(mainRuntime), ...targetEnvironment(baseTarget), ...brokerEnvironment(),
    CNYOS_PREPARATION_JOB_RESULT: 'success',
    CNYOS_PREPARATION_DOWNLOAD_OUTCOME: 'success',
    CNYOS_RECOVERY_DISPOSITION: 'terminal_recovery_rehydrated',
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: terminalRecoveryPlanFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: terminalRecoveryPlanFile.sha256,
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: manualChainFile.filename,
    CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: manualChainFile.sha256,
    CNYOS_CONTROLLER_RECOVERY_TERMINAL_EVIDENCE_PATH: terminalRecoveryFile.filename,
    CNYOS_EXPECTED_RECOVERY_TERMINAL_EVIDENCE_SHA256: terminalRecoveryFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'terminal-recovery/finalization.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(terminalRecoveryResult.evidence.rollbackExecutionAttempted, false);
assert.equal(terminalRecoveryResult.evidence.recoveryDisposition,
  'terminal_recovery_rehydrated');

brokerState = new LocalAtomicBroker();
brokerState.terminal = terminalEnvelope('committed_success', claimedTarget);
const terminalSuccessFile = await writeJsonFixture(
  'terminal-success/successful-release-terminal.json', brokerState.terminal,
  { canonical: true }
);
const terminalSuccessPlanResult = Object.freeze({
  recoveryDisposition: 'terminal_success_rehydrated',
  target: claimedTarget,
  resumerAuthorization: resumerAuthorization(claimedTarget, mainRuntime),
  claim: null,
  planCore: null,
  planCoreSha256: null,
  rollbackAuthorizationChainSha256: planResult.rollbackAuthorizationChainSha256,
  terminalRecord: brokerState.terminal
});
const terminalSuccessPlanFile = await writeJsonFixture(
  'terminal-success/reconciliation-plan.json',
  brokerEnvelope(
    'reconciliation', 'prepare_recovery',
    mainChainEvidence.prepareRequestSha256, terminalSuccessPlanResult
  ),
  { canonical: true }
);
const terminalSuccessResult = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'finalize-rehydrated-successful-release',
  env: {
    ...runtimeEnvironment(mainRuntime), ...targetEnvironment(baseTarget), ...brokerEnvironment(),
    CNYOS_PREPARATION_JOB_RESULT: 'success',
    CNYOS_PREPARATION_DOWNLOAD_OUTCOME: 'success',
    CNYOS_RECOVERY_DISPOSITION: 'terminal_success_rehydrated',
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: terminalSuccessPlanFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: terminalSuccessPlanFile.sha256,
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: manualChainFile.filename,
    CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: manualChainFile.sha256,
    CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH: terminalSuccessFile.filename,
    CNYOS_EXPECTED_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_SHA256: terminalSuccessFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'terminal-success/finalization.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(terminalSuccessResult.evidence.rollbackExecutionAttempted, false);
assert.equal(terminalSuccessResult.evidence.recoveryDisposition,
  'terminal_success_rehydrated');

const terminalIncompleteEvidencePath = path.join(
  temporaryRoot, 'terminal-success/incomplete-finalization.json'
);
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'record-incomplete-failed-release-reconciliation',
  env: {
    ...runtimeEnvironment(mainRuntime), ...targetEnvironment(baseTarget), ...brokerEnvironment(),
    CNYOS_DISPATCH_NONCE: nonce,
    CNYOS_RECOVERY_INCOMPLETE_REASON: 'unverified_terminal_success_receipt',
    CNYOS_PREPARATION_JOB_RESULT: 'success',
    CNYOS_EXECUTION_JOB_RESULT: 'skipped',
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: terminalSuccessPlanFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: terminalSuccessPlanFile.sha256,
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: manualChainFile.filename,
    CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: manualChainFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      terminalIncompleteEvidencePath
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /INCOMPLETE_RESULT_INVALID/);
await assert.rejects(fs.access(terminalIncompleteEvidencePath), { code: 'ENOENT' });

brokerState = new LocalAtomicBroker();
brokerState.core = manualPlanResult.planCore;
brokerState.claim = manualPlanResult.claim;
await expectCode(() => reconciliation.reconcileNetlifyReleaseState({
  mode: 'record-incomplete-failed-release-reconciliation',
  env: {
    ...runtimeEnvironment(mainRuntime), ...targetEnvironment(baseTarget), ...brokerEnvironment(),
    CNYOS_DISPATCH_NONCE: nonce,
    CNYOS_RECOVERY_INCOMPLETE_REASON: 'unverified_recovery_preparation',
    CNYOS_PREPARATION_JOB_RESULT: 'failure',
    CNYOS_EXECUTION_JOB_RESULT: 'skipped',
    CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH: changedActionFile.filename,
    CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256: changedActionFile.sha256,
    CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: manualChainFile.filename,
    CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: manualChainFile.sha256,
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'incomplete/tampered-plan-finalization.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /BROKER_SIGNATURE_INVALID/);
assert.equal(brokerState.incompleteCount, 0,
  'a present but invalid plan must fail closed before any claim:null broker request');
const incompleteResult = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'record-incomplete-failed-release-reconciliation',
  env: {
    ...runtimeEnvironment(mainRuntime), ...targetEnvironment(baseTarget), ...brokerEnvironment(),
    CNYOS_DISPATCH_NONCE: nonce,
    CNYOS_RECOVERY_INCOMPLETE_REASON: 'unverified_recovery_preparation',
    CNYOS_PREPARATION_JOB_RESULT: 'failure',
    CNYOS_EXECUTION_JOB_RESULT: 'skipped',
    CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH:
      path.join(temporaryRoot, 'incomplete/main-finalization.json')
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(incompleteResult.evidence.runReconciliationBarrierActive, true);
assert.equal(incompleteResult.evidence.leaseOrRunBarrierRetained, true);
assert.equal(brokerState.claim.claimId, manualPlanResult.claim.claimId);
assert.strictEqual(brokerState.core, manualPlanResult.planCore);

const watchdogIncompleteEnvironment = {
  ...watchdogPreparationEnvironment('watchdog-incomplete'),
  CNYOS_RECOVERY_INCOMPLETE_REASON: 'unverified_recovery_inputs',
  CNYOS_RECOVERY_PREPARATION_JOB_RESULT: 'failure',
  CNYOS_RECOVERY_EXECUTION_JOB_RESULT: 'skipped',
  CNYOS_CONTROLLER_RECOVERY_FINALIZATION_EVIDENCE_PATH:
    path.join(temporaryRoot, 'watchdog-incomplete/finalization.json')
};
delete watchdogIncompleteEnvironment.CNYOS_CONTROLLER_RECOVERY_PLAN_PATH;
delete watchdogIncompleteEnvironment.CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH;
const watchdogIncompleteResult = await reconciliation.reconcileNetlifyReleaseState({
  mode: 'record-incomplete-watchdog-recovery',
  env: watchdogIncompleteEnvironment,
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.equal(watchdogIncompleteResult.evidence.runReconciliationBarrierActive, true);
assert.equal(brokerState.claim.claimId, manualPlanResult.claim.claimId);

brokerState = new LocalAtomicBroker();
const successfulAuthorizationEvidence = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_authorization_validation',
  status: 'authorized',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  verifiedAt: validationEvidence.verifiedAt,
  controllerRepository: baseTarget.controllerRepository,
  controllerRef: baseTarget.controllerRef,
  controllerCommit: baseTarget.controllerCommit,
  controllerWorkflowPath: baseTarget.controllerWorkflowPath,
  controllerRunId: baseTarget.controllerRunId,
  controllerRunAttempt: baseTarget.controllerRunAttempt,
  githubActor: 'OfflineControllerActor',
  dispatchNonce: baseTarget.dispatchNonce,
  policySha256: POLICY_SHA256,
  source: authorizationSource,
  artifact: authorizationArtifact,
  target: POLICY.target,
  previousDeployId,
  knownGoodRollbackEvidenceSha256: sha256(knownGoodBytes),
  independentReviewerGitHubLogin: reviewerKey.record.githubLogin,
  namedRiskOwnerGitHubLogin: riskKey.record.githubLogin,
  functionRemoteByteAttestationUnavailableAccepted: true,
  authorizationExpiresAt: authorizationPacket.authorization.expiresAt,
  principalProofVerifiedAt: '2031-12-31T23:50:00.000Z',
  principalProofExpiresAt: '2032-01-01T00:10:00.000Z',
  deploymentControlBoundaryObservedAt: '2031-12-31T23:50:00.000Z',
  deploymentControlBoundaryExpiresAt: '2032-01-01T00:10:00.000Z',
  netlifyPrincipalSubject: 'publisher-principal-offline-subject',
  rollbackNetlifyPrincipalSubject: 'rollback-principal-offline-subject',
  netlifyPrincipalBoundary: Object.freeze({}),
  rollbackNetlifyPrincipalBoundary: Object.freeze({}),
  targetSiteAndPublisherExclusion: Object.freeze({}),
  exclusivePublisherEnforced: true,
  privateDraftAccessEnforced: true,
  failedDraftCleanupEnforced: true,
  githubReleaseBoundary: Object.freeze({}),
  authorizationPacketSha256: sha256(authorizationBytes),
  approverRegistrySha256: sha256(registryBytes),
  signatureKeyIds: authorizationPacket.signatureKeyIds,
  signatureSha256: Object.freeze({
    independentSecurityReviewer: sha256(reviewerSignature),
    managedPlatformRiskOwner: sha256(riskSignature)
  })
});
const successfulAuthorizationFile = await writeJsonFixture(
  'success/authorization.json', successfulAuthorizationEvidence
);
const successfulAuthorizationBundle = Object.freeze({
  ...authorizationBundle,
  authorizationDecision: Object.freeze({
    decision: authorizationPacket.authorization.decision,
    authorizedByGitHubLogin: authorizationPacket.authorization.authorizedByGitHubLogin,
    authorizedAt: authorizationPacket.authorization.authorizedAt,
    expiresAt: authorizationPacket.authorization.expiresAt,
    controllerRunId: baseTarget.controllerRunId,
    dispatchNonce: baseTarget.dispatchNonce,
    candidateCommit: authorizationSource.commit,
    candidateTree: authorizationSource.tree,
    artifactSha256: authorizationArtifact.artifactSha256
  }),
  validationEvidence: successfulAuthorizationEvidence
});
const successfulAuthorizationBundleFile = await writeJsonFixture(
  'success/authorization-verification-bundle.json', successfulAuthorizationBundle
);
const trustedProducerManifest = Object.freeze({
  sourceRepository: POLICY.sourceRepository,
  candidateCommit: authorizationSource.commit,
  candidateTree: authorizationSource.tree,
  functionSourceTree: authorizationSource.functionSourceTree,
  artifactSha256: authorizationArtifact.artifactSha256,
  fileCount: authorizationArtifact.fileCount,
  candidateBuildArtifactDigest: authorizationArtifact.candidateBuildArtifactDigest,
  staticReproducibilityEvidenceSha256:
    authorizationArtifact.staticReproducibilityEvidenceSha256,
  staticArtifactSha256: authorizationArtifact.staticArtifactSha256,
  candidateDependencyLockSha256: authorizationArtifact.candidateDependencyLockSha256,
  stagingConfigSha256: authorizationArtifact.stagingConfigSha256,
  productionDenylistConfigSha256: authorizationArtifact.productionDenylistConfigSha256,
  functionBundleManifestSha256: authorizationArtifact.functionBundleManifestSha256,
  functionBundleDependencyLockSha256:
    authorizationArtifact.functionBundleDependencyLockSha256,
  functionSourcesSha256: authorizationArtifact.functionSourcesSha256
});
let successfulProducerVerificationCalls = 0;
const verifySuccessfulProducerBundle = async ({ env }) => {
  successfulProducerVerificationCalls += 1;
  assert.equal(env.CNYOS_CANDIDATE_SHA, authorizationSource.commit);
  assert.equal(env.CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256,
    authorizationArtifact.producerManifestSha256);
  return Object.freeze({
    manifestSha256: authorizationArtifact.producerManifestSha256,
    manifest: trustedProducerManifest
  });
};
const publisherRelease = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_exclusive_publisher_release',
  status: 'passed',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  releasedAt: '2032-01-01T00:03:00.000Z',
  controllerRepository: baseTarget.controllerRepository,
  controllerRef: baseTarget.controllerRef,
  controllerCommit: baseTarget.controllerCommit,
  controllerRunId: baseTarget.controllerRunId,
  source: {
    repository: authorizationSource.repository,
    commit: authorizationSource.commit,
    tree: authorizationSource.tree
  },
  netlifyDeployId: promotedDeployId,
  lockLeaseId: generation,
  originalExclusivePublisherEvidenceSha256: 'b'.repeat(64),
  releaseAction: 'released',
  leaseActiveAfterRelease: false,
  runReconciliationBarrierActiveAfterRelease: true,
  runReconciliationBarrierGeneration: generation,
  automaticRunReconciliationBarrierExpiryPermitted: false,
  draftIntentTerminalBeforeRunReconciliationBarrierClearRequired: true,
  brokerPolicyId: POLICY.externalReconciliationBroker.policyId,
  brokerPolicySha256: POLICY.externalReconciliationBroker.policySha256,
  currentPublishedDeployIdBeforeRelease: promotedDeployId,
  currentPublishedDeployIdAfterRelease: promotedDeployId
});
const publisherReleaseFile = await writeJsonFixture(
  'success/publisher-release.json', publisherRelease
);
const retainedEvidenceSha256 = Object.freeze({
  producerManifest: authorizationArtifact.producerManifestSha256,
  preReleaseReconciliation: '8'.repeat(64),
  authorization: successfulAuthorizationFile.sha256,
  authorizationVerificationBundle: successfulAuthorizationBundleFile.sha256,
  liveGitHubPrecredentialBoundary: '8'.repeat(64),
  liveGitHubPrepromotionBoundary: '8'.repeat(64),
  rollbackAttestationDepositReceipt: '8'.repeat(64),
  rollbackAttestationDepositValidation: '8'.repeat(64),
  liveNetlifyAuthorityBoundary: '8'.repeat(64),
  functionEnvironment: '8'.repeat(64),
  backupDisableRuntimeBoundary: '8'.repeat(64),
  runtimeProofEnvelope: '9'.repeat(64),
  runtimeCapabilityBoundary: '8'.repeat(64),
  preflight: '8'.repeat(64),
  rollbackReadiness: '8'.repeat(64),
  draftGate: '8'.repeat(64),
  durableDraftIntent: '8'.repeat(64),
  draftReceipt: '8'.repeat(64),
  draftMetadata: '8'.repeat(64),
  draftVerification: '8'.repeat(64),
  controlBehavior: '8'.repeat(64),
  privateDraftAccessBoundary: '8'.repeat(64),
  privateDraftLifecycle: '8'.repeat(64),
  exclusivePublisherLease: publisherRelease.originalExclusivePublisherEvidenceSha256,
  promotionAttempt: '8'.repeat(64),
  exactPromotion: '8'.repeat(64),
  postPromotionVerification: '8'.repeat(64),
  scheduledFunctionRouteDenial: '8'.repeat(64),
  authenticatedUat: '8'.repeat(64),
  finalCurrentVerification: '8'.repeat(64),
  exclusivePublisherRelease: publisherReleaseFile.sha256
});
const finalEvidence = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_final_release',
  status: 'passed',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  finalizedAt: issuedAt,
  controllerRepository: baseTarget.controllerRepository,
  controllerRef: baseTarget.controllerRef,
  controllerCommit: baseTarget.controllerCommit,
  controllerRunId: baseTarget.controllerRunId,
  controllerRunAttempt: 1,
  dispatchNonce: nonce,
  policySha256: POLICY_SHA256,
  source: {
    ...authorizationSource
  },
  artifact: {
    sha256: authorizationArtifact.artifactSha256,
    fileCount: authorizationArtifact.fileCount
  },
  target: POLICY.target,
  netlifyDeployId: promotedDeployId,
  previousDeployId,
  functionByteAttestationAvailable: false,
  authenticatedUatPassed: true,
  retainedEvidenceSha256,
  evidenceSetSha256: sha256(JSON.stringify(retainedEvidenceSha256))
});
const finalFile = await writeJsonFixture('success/final.json', finalEvidence);
const successCommitEnvironment = (label, {
  finalFixture = finalFile,
  releaseFixture = publisherReleaseFile,
  trustedNonce = nonce
} = {}) => ({
  ...runtimeEnvironment(mainRuntime), ...targetEnvironment(baseTarget), ...brokerEnvironment(),
  CNYOS_DISPATCH_NONCE: trustedNonce,
  CNYOS_CANDIDATE_SHA: authorizationSource.commit,
  CNYOS_RELEASE_FINALIZE_JOB_RESULT: 'success',
  CNYOS_PRODUCER_JOB_RESULT: 'success',
  CNYOS_AUTHORIZATION_JOB_RESULT: 'success',
  CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME: 'success',
  CNYOS_PRODUCER_ARTIFACT_DOWNLOAD_OUTCOME: 'success',
  CNYOS_AUTHORIZATION_ARTIFACT_DOWNLOAD_OUTCOME: 'success',
  CNYOS_PRODUCER_BUNDLE_DIRECTORY: path.join(temporaryRoot, 'success/producer'),
  CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256:
    authorizationArtifact.producerManifestSha256,
  CNYOS_EXPECTED_PRODUCER_ARTIFACT_SHA256: authorizationArtifact.artifactSha256,
  CNYOS_EXPECTED_PRODUCER_FILE_COUNT: String(authorizationArtifact.fileCount),
  CNYOS_EXPECTED_PRODUCER_CANDIDATE_TREE: authorizationSource.tree,
  CNYOS_EXPECTED_PRODUCER_FUNCTION_SOURCE_TREE: authorizationSource.functionSourceTree,
  CNYOS_EXPECTED_GITHUB_ARTIFACT_DIGEST: authorizationArtifact.githubArtifactDigest,
  CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: successfulAuthorizationFile.filename,
  CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: successfulAuthorizationFile.sha256,
  CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: successfulAuthorizationBundleFile.filename,
  CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: successfulAuthorizationBundleFile.sha256,
  CNYOS_CONTROLLER_FINAL_EVIDENCE_PATH: finalFixture.filename,
  CNYOS_EXPECTED_FINAL_EVIDENCE_SHA256: finalFixture.sha256,
  CNYOS_CONTROLLER_PUBLISHER_RELEASE_EVIDENCE_PATH: releaseFixture.filename,
  CNYOS_EXPECTED_PUBLISHER_RELEASE_EVIDENCE_SHA256: releaseFixture.sha256,
  CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH:
    path.join(temporaryRoot, label, 'successful-release-terminal.json')
});
const reconcileSuccessfulRelease = options => reconciliation.reconcileNetlifyReleaseState({
  ...options,
  producerBundleVerifier: verifySuccessfulProducerBundle
});
const wrongPolicyFinalFile = await writeJsonFixture('success/wrong-policy-final.json', {
  ...finalEvidence,
  policySha256: '0'.repeat(64)
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: {
    ...successCommitEnvironment('success/wrong-policy'),
    CNYOS_CONTROLLER_FINAL_EVIDENCE_PATH: wrongPolicyFinalFile.filename,
    CNYOS_EXPECTED_FINAL_EVIDENCE_SHA256: wrongPolicyFinalFile.sha256
  },
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const extraKeyReleaseFile = await writeJsonFixture('success/extra-key-release.json', {
  ...publisherRelease,
  untrustedExtension: true
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/extra-key-release', {
    releaseFixture: extraKeyReleaseFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const extraKeyFinalFile = await writeJsonFixture('success/extra-key-final.json', {
  ...finalEvidence,
  untrustedExtension: true
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/extra-key', { finalFixture: extraKeyFinalFile }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const requestsBeforeNonceMismatch = requestLog.length;
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/nonce-mismatch', { trustedNonce: otherNonce }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);
assert.equal(requestLog.length, requestsBeforeNonceMismatch,
  'artifact nonce must never replace the trusted workflow nonce');

const crossSourceFinalFile = await writeJsonFixture('success/cross-source-final.json', {
  ...finalEvidence,
  source: { ...finalEvidence.source, commit: 'f'.repeat(40) }
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/cross-source', { finalFixture: crossSourceFinalFile }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const coherentlyMutatedSource = Object.freeze({
  repository: authorizationSource.repository,
  commit: 'f'.repeat(40),
  tree: 'a'.repeat(40),
  functionSourceTree: 'b'.repeat(40)
});
const coherentCrossSourceReleaseFile = await writeJsonFixture(
  'success/coherent-cross-source-release.json', {
    ...publisherRelease,
    source: {
      repository: coherentlyMutatedSource.repository,
      commit: coherentlyMutatedSource.commit,
      tree: coherentlyMutatedSource.tree
    }
  }
);
const coherentCrossSourceRetained = Object.freeze({
  ...retainedEvidenceSha256,
  exclusivePublisherRelease: coherentCrossSourceReleaseFile.sha256
});
const coherentCrossSourceFinalFile = await writeJsonFixture(
  'success/coherent-cross-source-final.json', {
    ...finalEvidence,
    source: coherentlyMutatedSource,
    retainedEvidenceSha256: coherentCrossSourceRetained,
    evidenceSetSha256: sha256(JSON.stringify(coherentCrossSourceRetained))
  }
);
const requestsBeforeCoherentCrossSource = requestLog.length;
const oidcBeforeCoherentCrossSource = oidcCalls.length;
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/coherent-cross-source', {
    finalFixture: coherentCrossSourceFinalFile,
    releaseFixture: coherentCrossSourceReleaseFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_INDEPENDENT_BINDING_INVALID/);
assert.equal(requestLog.length, requestsBeforeCoherentCrossSource);
assert.equal(oidcCalls.length, oidcBeforeCoherentCrossSource,
  'coherently cross-source terminal evidence must fail before OIDC');

const independentlyMismatchedArtifactFinalFile = await writeJsonFixture(
  'success/independently-mismatched-artifact-final.json', {
    ...finalEvidence,
    artifact: { sha256: 'f'.repeat(64), fileCount: finalEvidence.artifact.fileCount + 1 }
  }
);
const requestsBeforeIndependentArtifactMismatch = requestLog.length;
const oidcBeforeIndependentArtifactMismatch = oidcCalls.length;
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/independent-artifact-mismatch', {
    finalFixture: independentlyMismatchedArtifactFinalFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_INDEPENDENT_BINDING_INVALID/);
assert.equal(requestLog.length, requestsBeforeIndependentArtifactMismatch);
assert.equal(oidcCalls.length, oidcBeforeIndependentArtifactMismatch,
  'artifact mismatch with producer and authorization must fail before OIDC');

const invalidArtifactFinalFile = await writeJsonFixture('success/invalid-artifact-final.json', {
  ...finalEvidence,
  artifact: { ...finalEvidence.artifact, fileCount: 0 }
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/invalid-artifact', {
    finalFixture: invalidArtifactFinalFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

for (const [label, mutation] of [
  ['previous-deploy', { previousDeployId: promotedDeployId }],
  ['uat', { authenticatedUatPassed: false }],
  ['future-finalized', { finalizedAt: '2032-01-01T00:06:00.000Z' }]
]) {
  const invalidFinalFile = await writeJsonFixture(`success/${label}-final.json`, {
    ...finalEvidence,
    ...mutation
  });
  await expectCode(() => reconcileSuccessfulRelease({
    mode: 'commit-successful-release',
    env: successCommitEnvironment(`success/${label}`, { finalFixture: invalidFinalFile }),
    fetchImpl: routeBrokerRequest,
    oidcTokenProvider,
    now: () => observedAt
  }), /SUCCESS_EVIDENCE_INVALID/);
}

const unauthorizedPreviousDeployFinalFile = await writeJsonFixture(
  'success/unauthorized-previous-deploy-final.json', {
    ...finalEvidence,
    previousDeployId: '4'.repeat(24)
  }
);
const requestsBeforeUnauthorizedPreviousDeploy = requestLog.length;
const oidcBeforeUnauthorizedPreviousDeploy = oidcCalls.length;
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/unauthorized-previous-deploy', {
    finalFixture: unauthorizedPreviousDeployFinalFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_INDEPENDENT_BINDING_INVALID/);
assert.equal(requestLog.length, requestsBeforeUnauthorizedPreviousDeploy);
assert.equal(oidcCalls.length, oidcBeforeUnauthorizedPreviousDeploy,
  'unauthorized previous deploy must fail before OIDC');

const missingRetainedEvidence = structuredClone(retainedEvidenceSha256);
delete missingRetainedEvidence.authenticatedUat;
const missingRetainedFinalFile = await writeJsonFixture('success/missing-retained-final.json', {
  ...finalEvidence,
  retainedEvidenceSha256: missingRetainedEvidence,
  evidenceSetSha256: sha256(JSON.stringify(missingRetainedEvidence))
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/missing-retained', {
    finalFixture: missingRetainedFinalFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const crossArtifactRetained = Object.freeze({
  ...retainedEvidenceSha256,
  exclusivePublisherRelease: 'f'.repeat(64)
});
const crossArtifactRetainedFinalFile = await writeJsonFixture(
  'success/cross-artifact-retained-final.json', {
    ...finalEvidence,
    retainedEvidenceSha256: crossArtifactRetained,
    evidenceSetSha256: sha256(JSON.stringify(crossArtifactRetained))
  }
);
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/cross-artifact-retained', {
    finalFixture: crossArtifactRetainedFinalFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const wrongLeaseReleaseFile = await writeJsonFixture('success/wrong-lease-release.json', {
  ...publisherRelease,
  originalExclusivePublisherEvidenceSha256: 'c'.repeat(64)
});
const wrongLeaseRetained = Object.freeze({
  ...retainedEvidenceSha256,
  exclusivePublisherRelease: wrongLeaseReleaseFile.sha256
});
const wrongLeaseFinalFile = await writeJsonFixture('success/wrong-lease-final.json', {
  ...finalEvidence,
  retainedEvidenceSha256: wrongLeaseRetained,
  evidenceSetSha256: sha256(JSON.stringify(wrongLeaseRetained))
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/wrong-lease', {
    finalFixture: wrongLeaseFinalFile,
    releaseFixture: wrongLeaseReleaseFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const lateReleaseFile = await writeJsonFixture('success/late-release.json', {
  ...publisherRelease,
  releasedAt: '2032-01-01T00:04:30.000Z'
});
const lateReleaseRetained = Object.freeze({
  ...retainedEvidenceSha256,
  exclusivePublisherRelease: lateReleaseFile.sha256
});
const lateReleaseFinalFile = await writeJsonFixture('success/late-release-final.json', {
  ...finalEvidence,
  retainedEvidenceSha256: lateReleaseRetained,
  evidenceSetSha256: sha256(JSON.stringify(lateReleaseRetained))
});
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/late-release', {
    finalFixture: lateReleaseFinalFile,
    releaseFixture: lateReleaseFile
  }),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /SUCCESS_EVIDENCE_INVALID/);

const successCommit = await reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/commit-one'),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.ok(successfulProducerVerificationCalls > 0,
  'successful terminal commit must independently verify the producer bundle');
assert.equal(successCommit.terminalRecord.terminalType, 'committed_success');
const successfulCommitRequest = requestLog.at(-1).request;
assert.equal(successfulCommitRequest.evidence.previousDeployId, previousDeployId);
assert.deepEqual(successfulCommitRequest.evidence.source, finalEvidence.source);
assert.deepEqual(successfulCommitRequest.evidence.artifact, finalEvidence.artifact);
assert.deepEqual(successfulCommitRequest.evidence.retainedEvidenceSha256,
  finalEvidence.retainedEvidenceSha256);
assert.equal(successfulCommitRequest.evidence.originalExclusivePublisherEvidenceSha256,
  publisherRelease.originalExclusivePublisherEvidenceSha256);
const successRetry = await reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/commit-retry'),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
});
assert.deepEqual(successRetry.terminalRecord, successCommit.terminalRecord);

const claimedBroker = new LocalAtomicBroker();
claimedBroker.prepare(planRequest(mainRuntime));
brokerState = claimedBroker;
await expectCode(() => reconcileSuccessfulRelease({
  mode: 'commit-successful-release',
  env: successCommitEnvironment('success/delayed-conflict'),
  fetchImpl: routeBrokerRequest,
  oidcTokenProvider,
  now: () => observedAt
}), /BROKER_REQUEST_FAILED/);

const brokerRequestCredentials = requestLog.map(item => item.authorization);
assert.ok(brokerRequestCredentials.every(value => value.startsWith('Bearer offline-oidc-token-for-')));
assert.ok(requestLog.every(item => !JSON.stringify(item.request).includes(rollbackToken)));
assert.ok(requestLog
  .filter(item => item.request.operation === 'inventory_run_draft_intents')
  .every(item => item.request.evidence.sourceCommit === sourceCommit));
assert.ok(oidcCalls.includes(POLICY.externalReconciliationBroker.oidcAudience));
assert.ok(oidcCalls.includes(POLICY.draftLifecycleBroker.oidcAudience));
assert.ok(oidcCalls.includes(POLICY.rollbackAttestationBroker.oidcAudience));
assert.equal(forbiddenGlobalNetworkCalls, 0);

const source = await fs.readFile(
  path.join(packageRoot, 'scripts', 'reconcile-netlify-release-state.mjs'), 'utf8'
);
for (const mode of reconciliation.RECONCILIATION_MODES) assert.match(source, new RegExp(mode));
for (const requiredPhrase of [
  'persistedAtomicallyWithPlanCore',
  'authorizationRefreshPreservesPlanCore',
  'incompleteRecordPreservesClaim',
  'automaticExpiryPermitted',
  'targetControllerRunAttempt',
  'targetNetlifySiteId',
  'immutablePolicy',
  'independentOfTargetRunCode',
  'blocksNewMutationWhileRunReconciliationBarrierActive',
  'recoveryTerminalRecordImmutableAndRetrievable',
  'recoveryClaimAuthorizedResumerWorkflowPaths',
  'brokerStateMutationAttempted: false',
  'publisherLeaseReleased: false',
  'runReconciliationBarrierReleased: false',
  "credentials: 'omit'",
  "referrerPolicy: 'no-referrer'",
  "cache: 'no-store'",
  "redirect: 'error'",
  'prepareRequestSha256',
  'finalizer_precommit_validation_failed',
  'CNYOS_RECONCILIATION_OIDC_TOKEN_REFLECTION_INVALID',
  'CNYOS_RECONCILIATION_BROKER_RESPONSE_NONCANONICAL'
]) assert.ok(source.includes(requiredPhrase), `missing reconciliation invariant: ${requiredPhrase}`);

globalThis.fetch = globalFetch;
await fs.rm(temporaryRoot, { recursive: true, force: true });
process.stdout.write('CNYOS activation contract release-state-reconciliation: passed\n');
