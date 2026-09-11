import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY,
  POLICY_SHA256,
  assertControllerRuntime,
  assertExactKeys,
  assertPolicyTarget,
  canonicalIsoTimestamp,
  decodeNonce,
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

const ENVELOPE_KEYS = Object.freeze([
  'schemaVersion',
  'evidenceType',
  'receipt',
  'brokerSignature'
]);
const RECEIPT_KEYS = Object.freeze([
  'schemaVersion',
  'evidenceType',
  'status',
  'scope',
  'productionAuthorization',
  'realPatientDataAuthorized',
  'depositId',
  'depositSequence',
  'depositRequestSha256',
  'broker',
  'controller',
  'source',
  'artifact',
  'target',
  'authorizationMaterial',
  'depositSemantics',
  'recoveryMaterial',
  'retrievalBoundary',
  'depositedAt',
  'retentionUntil'
]);
const BROKER_KEYS = Object.freeze([
  'origin', 'policyId', 'policySha256', 'receiptSigningKeyId',
  'receiptSigningSpkiSha256'
]);
const CONTROLLER_KEYS = Object.freeze([
  'repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
  'runAttempt', 'dispatchNonce', 'policySha256'
]);
const SOURCE_KEYS = Object.freeze(['repository', 'commit', 'tree', 'functionSourceTree']);
const ARTIFACT_KEYS = Object.freeze([
  'producerManifestSha256', 'artifactSha256', 'fileCount',
  'candidateBuildArtifactDigest', 'staticReproducibilityEvidenceSha256',
  'staticArtifactSha256', 'candidateDependencyLockSha256', 'stagingConfigSha256',
  'productionDenylistConfigSha256', 'functionBundleManifestSha256',
  'functionBundleDependencyLockSha256', 'functionSourcesSha256', 'producerRunId',
  'githubArtifactDigest'
]);
const TARGET_KEYS = Object.freeze([
  'netlifySiteId', 'netlifyOrigin', 'supabaseProjectRef', 'databaseSystemIdentifier',
  'targetSha256', 'previousDeployId'
]);
const AUTHORIZATION_MATERIAL_KEYS = Object.freeze([
  'authorizationPacketSha256', 'authorizationBundleSha256', 'approverRegistrySha256',
  'independentSecurityReviewerKeyId', 'independentSecurityReviewerSignatureSha256',
  'managedPlatformRiskOwnerKeyId', 'managedPlatformRiskOwnerSignatureSha256',
  'knownGoodEvidenceSha256'
]);
const DEPOSIT_SEMANTICS_KEYS = Object.freeze([
  'appendOnly', 'immutable', 'oneDepositPerRunNonce',
  'conflictingOverwriteRejected', 'identicalReplayReturnsOriginalReceipt',
  'rawPayloadArtifactExposure'
]);
const RECOVERY_MATERIAL_KEYS = Object.freeze([
  'canonicalAuthorizationJsonStored', 'independentSecurityReviewerSignatureStored',
  'managedPlatformRiskOwnerSignatureStored', 'knownGoodEvidenceBytesStored',
  'authorizationVerificationBundleBytesStored', 'approverRegistryBytesStored',
  'encryptedAtRest', 'hashVerifiedBeforeSeal', 'retrievableForRecovery'
]);
const RETRIEVAL_BOUNDARY_KEYS = Object.freeze([
  'oidcAudience', 'requiredControllerRepository', 'requiredControllerRef',
  'requiredControllerWorkflowPath', 'requiredControllerRunId',
  'requiredControllerRunAttempt', 'requiredDispatchNonce',
  'externalReconciliationPolicyId', 'externalReconciliationPolicySha256',
  'failedRunCodeCannotDelete', 'watchdogRevisionCannotDelete',
  'exactRunAndNonceRequired', 'oidcControllerIdentityRequired'
]);
const SIGNATURE_KEYS = Object.freeze([
  'algorithm', 'keyId', 'statementSha256', 'signatureBase64', 'signatureSha256'
]);

function activatedPolicyValue(value, code, maximum = 500) {
  const result = required(value, code, maximum);
  if (/^__[A-Z0-9_]+__$/.test(result)) fail(code);
  return result;
}

function decodeSignature(value) {
  const encoded = required(value, 'CNYOS_ROLLBACK_ATTESTATION_RECEIPT_SIGNATURE_INVALID', 256);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_SIGNATURE_INVALID');
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.byteLength !== 64 || bytes.toString('base64') !== encoded) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_SIGNATURE_INVALID');
  }
  return bytes;
}

function brokerTrustRoot() {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_BROKER_POLICY_INVALID';
  const policy = POLICY.rollbackAttestationBroker;
  if (!isPlainObject(policy) || policy.maximumReceiptAgeMinutes !== 10 ||
    policy.minimumRetentionDays < 365 || policy.minimumRetentionDays > 3650 ||
    !Number.isSafeInteger(policy.minimumRetentionDays)) {
    fail(code);
  }
  const originValue = activatedPolicyValue(policy.origin, code);
  const origin = safeOrigin(originValue, code);
  if (origin !== originValue) fail(code);
  const policyId = activatedPolicyValue(policy.policyId, code, 200);
  const policySha256 = exactSha256(policy.policySha256, code);
  const receiptSigningKeyId = activatedPolicyValue(policy.receiptSigningKeyId, code, 200);
  const receiptSigningSpkiSha256 = exactSha256(policy.receiptSigningSpkiSha256, code);
  const oidcAudience = activatedPolicyValue(policy.oidcAudience, code, 300);
  if (!/^https:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$/.test(oidcAudience)) {
    fail(code);
  }
  const publicKeyPem = policy.receiptSigningPublicKeyPem;
  if (typeof publicKeyPem !== 'string' || publicKeyPem.length > 2048 ||
    !publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n') ||
    !publicKeyPem.endsWith('-----END PUBLIC KEY-----\n')) fail(code);
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicKeyPem); }
  catch { fail(code); }
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519' ||
    publicKey.export({ type: 'spki', format: 'pem' }) !== publicKeyPem ||
    sha256(publicKey.export({ type: 'spki', format: 'der' })) !== receiptSigningSpkiSha256) {
    fail(code);
  }
  return Object.freeze({
    origin,
    policyId,
    policySha256,
    receiptSigningKeyId,
    receiptSigningSpkiSha256,
    oidcAudience,
    publicKey,
    maximumReceiptAgeMs: policy.maximumReceiptAgeMinutes * 60 * 1000,
    minimumRetentionMs: policy.minimumRetentionDays * 24 * 60 * 60 * 1000
  });
}

async function loadJson(filename, expectedDigest, code, { canonical = false } = {}) {
  const bytes = await readFileBounded(filename, 4 * 1024 * 1024, code);
  const digest = sha256(bytes);
  if (digest !== exactSha256(expectedDigest, `${code}_DIGEST_REQUIRED`)) {
    fail(`${code}_DIGEST_MISMATCH`);
  }
  const raw = bytes.toString('utf8');
  let value;
  try { value = JSON.parse(raw); }
  catch { fail(code); }
  if (!isPlainObject(value) || (canonical && raw !== JSON.stringify(value))) fail(code);
  return Object.freeze({ bytes, raw, value, sha256: digest });
}

function assertAuthorizationBundle(bundle, runtime, env) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_INVALID';
  if (bundle.schemaVersion !== 2 ||
    bundle.evidenceType !== 'cnyos_staging_controller_authorization_verification_bundle' ||
    bundle.scope !== 'cnyos_staging_only' || bundle.productionAuthorization !== false ||
    bundle.secretValuesSerialized !== false ||
    bundle.validationEvidence?.evidenceType !==
      'cnyos_staging_controller_authorization_validation' ||
    bundle.validationEvidence?.status !== 'authorized' ||
    bundle.validationEvidence?.controllerRepository !== runtime.repository ||
    bundle.validationEvidence?.controllerRef !== runtime.ref ||
    bundle.validationEvidence?.controllerCommit !== runtime.commit ||
    bundle.validationEvidence?.controllerWorkflowPath !== runtime.workflowPath ||
    bundle.validationEvidence?.controllerRunId !== runtime.runId ||
    bundle.validationEvidence?.controllerRunAttempt !== 1 ||
    bundle.validationEvidence?.policySha256 !== POLICY_SHA256 ||
    bundle.validationEvidence?.dispatchNonce !== decodeNonce(env.CNYOS_DISPATCH_NONCE).value ||
    bundle.authorizationDecision?.controllerRunId !== runtime.runId ||
    bundle.authorizationDecision?.dispatchNonce !== bundle.validationEvidence.dispatchNonce ||
    bundle.authorizationDecision?.candidateCommit !== bundle.validationEvidence.source?.commit ||
    bundle.authorizationDecision?.candidateTree !== bundle.validationEvidence.source?.tree ||
    bundle.authorizationDecision?.artifactSha256 !==
      bundle.validationEvidence.artifact?.artifactSha256 ||
    bundle.authorizationDecision?.expiresAt !==
      bundle.validationEvidence.authorizationExpiresAt ||
    bundle.authorizationPacketSha256 !== bundle.validationEvidence.authorizationPacketSha256 ||
    bundle.approverRegistrySha256 !== bundle.validationEvidence.approverRegistrySha256 ||
    !isDeepStrictEqual(bundle.signatureKeyIds, bundle.validationEvidence.signatureKeyIds) ||
    !isDeepStrictEqual(bundle.signatureSha256, bundle.validationEvidence.signatureSha256) ||
    bundle.knownGoodEvidenceSha256 !==
      bundle.validationEvidence.knownGoodRollbackEvidenceSha256) {
    fail(code);
  }
  assertExactKeys(bundle.validationEvidence.source, SOURCE_KEYS, code);
  assertExactKeys(bundle.validationEvidence.artifact, ARTIFACT_KEYS, code);
  assertPolicyTarget(bundle.validationEvidence.target, code);
  for (const value of [
    bundle.authorizationPacketSha256,
    bundle.approverRegistrySha256,
    bundle.signatureSha256?.independentSecurityReviewer,
    bundle.signatureSha256?.managedPlatformRiskOwner,
    bundle.knownGoodEvidenceSha256
  ]) exactSha256(value, code);
}

export async function verifyRollbackAttestationDeposit({
  env = process.env,
  now = () => new Date()
} = {}) {
  const runtime = assertControllerRuntime(env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RELEASE_WORKFLOW_REQUIRED');
  }
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_ROLLBACK_ATTESTATION_TIME_INVALID');
  }
  const trust = brokerTrustRoot();
  const authorizationBundle = await loadJson(
    required(env.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH,
      'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256,
    'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_INVALID'
  );
  assertAuthorizationBundle(authorizationBundle.value, runtime, env);

  const envelope = await loadJson(
    required(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH,
      'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID',
    { canonical: true }
  );
  assertExactKeys(envelope.value, ENVELOPE_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  if (envelope.value.schemaVersion !== 1 ||
    envelope.value.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_envelope') {
    fail('CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  }
  const receipt = envelope.value.receipt;
  const brokerSignature = envelope.value.brokerSignature;
  assertExactKeys(receipt, RECEIPT_KEYS, 'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.broker, BROKER_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.controller, CONTROLLER_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.source, SOURCE_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.artifact, ARTIFACT_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.target, TARGET_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.authorizationMaterial, AUTHORIZATION_MATERIAL_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.depositSemantics, DEPOSIT_SEMANTICS_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.recoveryMaterial, RECOVERY_MATERIAL_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(receipt.retrievalBoundary, RETRIEVAL_BOUNDARY_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  assertExactKeys(brokerSignature, SIGNATURE_KEYS,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SIGNATURE_INVALID');

  const validation = authorizationBundle.value.validationEvidence;
  const expectedTarget = {
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyOrigin: POLICY.target.netlifyOrigin,
    supabaseProjectRef: POLICY.target.supabaseProjectRef,
    databaseSystemIdentifier: POLICY.target.databaseSystemIdentifier,
    targetSha256: sha256(JSON.stringify(POLICY.target)),
    previousDeployId: validation.previousDeployId
  };
  const expectedController = {
    repository: runtime.repository,
    ref: runtime.ref,
    commit: runtime.commit,
    workflowPath: runtime.workflowPath,
    workflowRef: runtime.workflowRef,
    runId: runtime.runId,
    runAttempt: 1,
    dispatchNonce: decodeNonce(env.CNYOS_DISPATCH_NONCE).value,
    policySha256: POLICY_SHA256
  };
  const expectedAuthorizationMaterial = {
    authorizationPacketSha256: authorizationBundle.value.authorizationPacketSha256,
    authorizationBundleSha256: authorizationBundle.sha256,
    approverRegistrySha256: authorizationBundle.value.approverRegistrySha256,
    independentSecurityReviewerKeyId:
      authorizationBundle.value.signatureKeyIds.independentSecurityReviewer,
    independentSecurityReviewerSignatureSha256:
      authorizationBundle.value.signatureSha256.independentSecurityReviewer,
    managedPlatformRiskOwnerKeyId:
      authorizationBundle.value.signatureKeyIds.managedPlatformRiskOwner,
    managedPlatformRiskOwnerSignatureSha256:
      authorizationBundle.value.signatureSha256.managedPlatformRiskOwner,
    knownGoodEvidenceSha256: authorizationBundle.value.knownGoodEvidenceSha256
  };
  if (receipt.schemaVersion !== 1 ||
    receipt.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_receipt' ||
    receipt.status !== 'sealed' || receipt.scope !== 'cnyos_staging_only' ||
    receipt.productionAuthorization !== false || receipt.realPatientDataAuthorized !== false ||
    typeof receipt.depositId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$/.test(receipt.depositId) ||
    receipt.depositSequence !== 1 ||
    receipt.depositRequestSha256 !== exactSha256(
      receipt.depositRequestSha256,
      'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID'
    ) ||
    !isDeepStrictEqual(receipt.controller, expectedController) ||
    !isDeepStrictEqual(receipt.source, validation.source) ||
    !isDeepStrictEqual(receipt.artifact, validation.artifact) ||
    !isDeepStrictEqual(receipt.target, expectedTarget) ||
    !isDeepStrictEqual(receipt.authorizationMaterial, expectedAuthorizationMaterial) ||
    receipt.broker.origin !== trust.origin || receipt.broker.policyId !== trust.policyId ||
    receipt.broker.policySha256 !== trust.policySha256 ||
    receipt.broker.receiptSigningKeyId !== trust.receiptSigningKeyId ||
    receipt.broker.receiptSigningSpkiSha256 !== trust.receiptSigningSpkiSha256 ||
    receipt.depositSemantics.appendOnly !== true ||
    receipt.depositSemantics.immutable !== true ||
    receipt.depositSemantics.oneDepositPerRunNonce !== true ||
    receipt.depositSemantics.conflictingOverwriteRejected !== true ||
    receipt.depositSemantics.identicalReplayReturnsOriginalReceipt !== true ||
    receipt.depositSemantics.rawPayloadArtifactExposure !== false ||
    receipt.recoveryMaterial.canonicalAuthorizationJsonStored !== true ||
    receipt.recoveryMaterial.independentSecurityReviewerSignatureStored !== true ||
    receipt.recoveryMaterial.managedPlatformRiskOwnerSignatureStored !== true ||
    receipt.recoveryMaterial.knownGoodEvidenceBytesStored !== true ||
    receipt.recoveryMaterial.authorizationVerificationBundleBytesStored !== true ||
    receipt.recoveryMaterial.approverRegistryBytesStored !== true ||
    receipt.recoveryMaterial.encryptedAtRest !== true ||
    receipt.recoveryMaterial.hashVerifiedBeforeSeal !== true ||
    receipt.recoveryMaterial.retrievableForRecovery !== true ||
    receipt.retrievalBoundary.oidcAudience !== trust.oidcAudience ||
    receipt.retrievalBoundary.requiredControllerRepository !== runtime.repository ||
    receipt.retrievalBoundary.requiredControllerRef !== runtime.ref ||
    receipt.retrievalBoundary.requiredControllerWorkflowPath !== runtime.workflowPath ||
    receipt.retrievalBoundary.requiredControllerRunId !== runtime.runId ||
    receipt.retrievalBoundary.requiredControllerRunAttempt !== 1 ||
    receipt.retrievalBoundary.requiredDispatchNonce !== expectedController.dispatchNonce ||
    receipt.retrievalBoundary.externalReconciliationPolicyId !==
      POLICY.externalReconciliationBroker.policyId ||
    receipt.retrievalBoundary.externalReconciliationPolicySha256 !== exactSha256(
      POLICY.externalReconciliationBroker.policySha256,
      'CNYOS_ROLLBACK_ATTESTATION_BROKER_POLICY_INVALID'
    ) || receipt.retrievalBoundary.failedRunCodeCannotDelete !== true ||
    receipt.retrievalBoundary.watchdogRevisionCannotDelete !== true ||
    receipt.retrievalBoundary.exactRunAndNonceRequired !== true ||
    receipt.retrievalBoundary.oidcControllerIdentityRequired !== true) {
    fail('CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  }
  exactDeployId(receipt.target.previousDeployId,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID');
  const depositedAt = recentCanonicalTimestamp(
    receipt.depositedAt,
    observedAt,
    trust.maximumReceiptAgeMs,
    'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_STALE'
  );
  const authorizationVerifiedAt = canonicalIsoTimestamp(
    validation.verifiedAt,
    'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_INVALID'
  );
  const authorizationExpiresAt = canonicalIsoTimestamp(
    validation.authorizationExpiresAt,
    'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_INVALID'
  );
  if (depositedAt < authorizationVerifiedAt || depositedAt >= authorizationExpiresAt) {
    fail('CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_STALE');
  }
  const retentionUntil = canonicalIsoTimestamp(
    receipt.retentionUntil,
    'CNYOS_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT'
  );
  if (retentionUntil <= observedAt ||
    retentionUntil.getTime() - depositedAt.getTime() < trust.minimumRetentionMs) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT');
  }

  if (brokerSignature.algorithm !== 'Ed25519' ||
    brokerSignature.keyId !== trust.receiptSigningKeyId) {
    fail('CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SIGNATURE_INVALID');
  }
  const statement = JSON.stringify(receipt);
  const statementSha256 = sha256(statement);
  const signature = decodeSignature(brokerSignature.signatureBase64);
  if (brokerSignature.statementSha256 !== statementSha256 ||
    brokerSignature.signatureSha256 !== sha256(signature) ||
    !crypto.verify(null, Buffer.from(statement), trust.publicKey, signature)) {
    fail('CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SIGNATURE_INVALID');
  }

  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_validation',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    verifiedAt: observedAt.toISOString(),
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerWorkflowPath: runtime.workflowPath,
    controllerRunId: runtime.runId,
    controllerRunAttempt: 1,
    dispatchNonce: expectedController.dispatchNonce,
    policySha256: POLICY_SHA256,
    source: receipt.source,
    artifact: receipt.artifact,
    target: receipt.target,
    previousDeployId: receipt.target.previousDeployId,
    authorizationBundleSha256: authorizationBundle.sha256,
    authorizationPacketSha256: receipt.authorizationMaterial.authorizationPacketSha256,
    approverRegistrySha256: receipt.authorizationMaterial.approverRegistrySha256,
    independentSecurityReviewerSignatureSha256:
      receipt.authorizationMaterial.independentSecurityReviewerSignatureSha256,
    managedPlatformRiskOwnerSignatureSha256:
      receipt.authorizationMaterial.managedPlatformRiskOwnerSignatureSha256,
    knownGoodEvidenceSha256: receipt.authorizationMaterial.knownGoodEvidenceSha256,
    depositId: receipt.depositId,
    depositRequestSha256: receipt.depositRequestSha256,
    depositReceiptSha256: envelope.sha256,
    depositedAt: receipt.depositedAt,
    retentionUntil: receipt.retentionUntil,
    brokerOrigin: trust.origin,
    brokerPolicyId: trust.policyId,
    brokerPolicySha256: trust.policySha256,
    brokerReceiptSigningKeyId: trust.receiptSigningKeyId,
    brokerReceiptSigningSpkiSha256: trust.receiptSigningSpkiSha256,
    brokerStatementSha256: statementSha256,
    brokerSignatureSha256: sha256(signature),
    immutableAppendOnlyDepositVerified: true,
    exactRunNonceRetrievalBoundaryVerified: true,
    completeRecoveryMaterialStoredVerified: true,
    rawPayloadArtifactExposure: false
  });
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH,
      'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({
    evidence,
    evidencePath,
    receiptPath: path.resolve(
      env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH
    )
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  verifyRollbackAttestationDeposit().then(async result => {
    process.stdout.write(`${JSON.stringify({
      evidencePath: result.evidencePath,
      evidenceSha256: sha256(await fs.readFile(result.evidencePath)),
      depositReceiptSha256: result.evidence.depositReceiptSha256,
      depositId: result.evidence.depositId
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message ||
      'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_VERIFICATION_FAILED')}\n`);
    process.exitCode = 1;
  });
}
