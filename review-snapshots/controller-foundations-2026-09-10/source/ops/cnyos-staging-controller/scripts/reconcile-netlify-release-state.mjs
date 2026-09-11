import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  DEPLOY_ID,
  POLICY,
  POLICY_SHA256,
  SHA256,
  SITE_ID,
  assertExactKeys,
  canonicalIsoTimestamp,
  decodeNonce,
  deploymentMarker,
  exactDeployId,
  exactSha256,
  fail,
  isPlainObject,
  parseJsonObject,
  readFileBounded,
  required,
  safeOrigin,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';
import { rollbackChainBinding, authorizationFromChain } from './verify-rollback-authorization-chain.mjs';

export const RECOVERY_DISPOSITIONS = Object.freeze([
  'recovery_required',
  'terminal_success_rehydrated',
  'terminal_recovery_rehydrated'
]);

export const RECONCILIATION_MODES = Object.freeze([
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

export const OIDC_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'DATABASE_URL',
  'PGPASSWORD',
  'POSTGRES_PASSWORD',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_DB_PASSWORD',
  'SUPABASE_SERVICE_ROLE_KEY'
]);

export const EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_ROLLBACK_ATTESTATION_BROKER_URL',
  'CNYOS_NETLIFY_PUBLISH_BROKER_URL',
  'CNYOS_DRAFT_LIFECYCLE_BROKER_URL',
  'CNYOS_NETLIFY_AUTHORITY_BROKER_URL',
  'CNYOS_NETLIFY_PRINCIPAL_MEMBERSHIP_BROKER_URL',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'DATABASE_URL',
  'PGPASSWORD',
  'POSTGRES_PASSWORD',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_DB_PASSWORD',
  'SUPABASE_SERVICE_ROLE_KEY'
]);

const BROKER_ENVELOPE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'statement', 'brokerSignature'
]);
const BROKER_STATEMENT_KEYS = Object.freeze([
  'schemaVersion', 'operationDomain', 'operation', 'policyId', 'policySha256',
  'requestSha256', 'issuedAt', 'expiresAt', 'result'
]);
const SIGNATURE_KEYS = Object.freeze([
  'algorithm', 'keyId', 'statementSha256', 'signatureBase64', 'signatureSha256'
]);
const TARGET_KEYS = Object.freeze([
  'controllerRepository', 'controllerRef', 'controllerWorkflowPath',
  'controllerRunId', 'controllerRunAttempt', 'controllerCommit', 'dispatchNonce',
  'netlifySiteId', 'barrierGeneration'
]);
const RESUMER_KEYS = Object.freeze([
  'controllerRepository', 'controllerRef', 'controllerWorkflowPath',
  'controllerRunId', 'controllerRunAttempt', 'controllerCommit'
]);
const RESUMER_AUTHORIZATION_KEYS = Object.freeze([
  'targetControllerRepository', 'targetControllerRef', 'targetControllerWorkflowPath',
  'targetControllerRunId', 'targetControllerRunAttempt', 'targetControllerCommit',
  'targetDispatchNonce', 'targetNetlifySiteId', 'allowedResumerRepository',
  'allowedResumerProtectedRef', 'allowedResumerWorkflowPaths', 'actualResumer'
]);
const CLAIM_KEYS = Object.freeze([
  'claimId', 'claimKeySha256', 'barrierGeneration', 'planCoreSha256', 'createdAt',
  'persistedAtomicallyWithPlanCore', 'immutable', 'exactRetryIdempotent',
  'authorizedResumptionEnforced', 'authorizationRefreshPreservesPlanCore',
  'automaticExpiryPermitted', 'incompleteRecordPreservesClaim'
]);
const PLAN_CORE_KEYS = Object.freeze([
  'target', 'previousDeployId', 'currentDeployId', 'knownGoodEvidenceSha256',
  'rollbackAuthorizationChainSha256', 'orderedActions', 'draftIntents'
]);
const PLAN_RESULT_KEYS = Object.freeze([
  'recoveryDisposition', 'target', 'resumerAuthorization', 'claim', 'planCore',
  'planCoreSha256', 'rollbackAuthorizationChainSha256', 'terminalRecord'
]);
const INTENT_KEYS = Object.freeze([
  'intentId', 'deployId', 'status', 'ownershipMarker'
]);
const RESTORE_ACTION_KEYS = Object.freeze([
  'sequence', 'kind', 'siteId', 'fromDeployId', 'toDeployId',
  'requiredCurrentDeployId', 'requiredOwnershipMarker'
]);
const DELETE_ACTION_KEYS = Object.freeze([
  'sequence', 'kind', 'siteId', 'deployId', 'intentId', 'requiredOwnershipMarker'
]);
const TERMINAL_ENVELOPE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'terminalRecord', 'brokerSignature'
]);
const TERMINAL_RECORD_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'terminalType', 'terminalRecordId',
  'scope', 'productionAuthorization', 'realPatientDataAuthorized', 'target',
  'barrierGeneration', 'claimId', 'planCoreSha256', 'executionReceiptSha256',
  'recoveryFinalizationGeneration', 'netlifyDeployId', 'finalEvidenceSha256',
  'publisherReleaseEvidenceSha256', 'leaseActive',
  'runReconciliationBarrierActive', 'automaticRunReconciliationBarrierExpiryPermitted',
  'allRunOwnedDraftIntentsTerminal', 'rollbackEligible', 'committedAt'
]);
const DEPOSIT_RECEIPT_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'depositId', 'depositSequence', 'depositRequestSha256',
  'broker', 'controller',
  'source', 'artifact', 'target', 'authorizationMaterial', 'depositSemantics',
  'recoveryMaterial', 'retrievalBoundary', 'depositedAt', 'retentionUntil'
]);
const DEPOSIT_BROKER_KEYS = Object.freeze([
  'origin', 'policyId', 'policySha256', 'receiptSigningKeyId',
  'receiptSigningSpkiSha256'
]);
const DEPOSIT_CONTROLLER_KEYS = Object.freeze([
  'repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
  'runAttempt', 'dispatchNonce', 'policySha256'
]);
const AUTHORIZATION_SOURCE_KEYS = Object.freeze([
  'repository', 'commit', 'tree', 'functionSourceTree'
]);
const AUTHORIZATION_ARTIFACT_KEYS = Object.freeze([
  'producerManifestSha256', 'artifactSha256', 'fileCount',
  'candidateBuildArtifactDigest', 'staticReproducibilityEvidenceSha256',
  'staticArtifactSha256', 'candidateDependencyLockSha256', 'stagingConfigSha256',
  'productionDenylistConfigSha256', 'functionBundleManifestSha256',
  'functionBundleDependencyLockSha256', 'functionSourcesSha256', 'producerRunId',
  'githubArtifactDigest'
]);
const AUTHORIZATION_PACKET_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'controller', 'source', 'artifact', 'target',
  'exactHeadCi', 'runtimeCapabilityBoundary', 'deploymentControlBoundary',
  'principalProof', 'independentSecurityReview', 'managedPlatformRiskAcceptance',
  'rollbackRehearsal', 'migrationPromotion', 'strictPostRemediation', 'rollback',
  'signatureKeyIds', 'authorization', 'productionAuthorization',
  'realPatientDataAuthorized'
]);
const AUTHORIZATION_CONTROLLER_KEYS = Object.freeze([
  'repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
  'runAttempt', 'dispatchNonce'
]);
const AUTHORIZATION_ROLLBACK_KEYS = Object.freeze([
  'restoreOnAnyPostPublishFailure', 'externalWatchdogRequired',
  'restoreOnlyControllerOwnedDeploy', 'previousDeployId', 'knownGoodEvidence'
]);
const AUTHORIZATION_DECISION_KEYS = Object.freeze([
  'decision', 'authorizedByGitHubLogin', 'authorizedByName', 'authorizedByRole',
  'authorizedAt', 'expiresAt', 'evidence'
]);
const AUTHORIZATION_BROKER_KEYS = Object.freeze([
  'policyId', 'policySha256', 'executionAuthority', 'immutablePolicy',
  'independentOfTargetRunCode', 'independentOfWatchdogRevision',
  'targetControllerRepository', 'targetControllerRef', 'targetControllerRunId',
  'targetControllerRunAttempt', 'targetControllerCommit',
  'targetControllerWorkflowPath', 'targetDispatchNonce', 'targetNetlifySiteId',
  'targetRunCannotSuppressReconciliation', 'watchdogRevisionCannotSuppressReconciliation',
  'enforcesRollback', 'enforcesDraftCleanup', 'enforcesLeaseRelease',
  'enforcesRunReconciliationBarrier',
  'atomicLeaseReleaseRetainsRunReconciliationBarrier',
  'blocksNewMutationWhileRunReconciliationBarrierActive',
  'successfulReleaseCommitRequiresFinalEvidenceHashes',
  'draftIntentTerminalBeforeBarrierClearRequired',
  'automaticRunReconciliationBarrierExpiryPermitted',
  'exactTerminalCommitRetryIdempotent',
  'terminalSuccessAndRecoveryClaimMutuallyExclusive',
  'terminalSuccessNeverRollbackEligible',
  'recoveryClaimConflictsWithDelayedTerminalCommit',
  'recoveryTerminalRecordImmutableAndRetrievable',
  'recoveryTerminalRecordBindsExecutionReceipt',
  'exactRecoveryFinalizationRetryIdempotent',
  'terminalRecoveryNeverRollbackEligible',
  'recoveryClaimAndPlanCorePersistedAtomically',
  'recoveryClaimPlanCoreImmutableAndRetrievable',
  'exactRecoveryClaimRetryIdempotent',
  'authorizedWatchdogRecoveryClaimResumptionEnforced',
  'recoveryAuthorizationRefreshPreservesClaimAndPlanCore',
  'conflictingRecoveryClaimBindingsOrGenerationRejected',
  'automaticRecoveryClaimExpiryPermitted',
  'incompleteRecoveryRecordPreservesRecoveryClaimAndPlan',
  'recoveryClaimAuthorizedResumerRepository',
  'recoveryClaimAuthorizedResumerProtectedRef',
  'recoveryClaimAuthorizedResumerWorkflowPaths', 'evidence'
]);
const DEPOSIT_TARGET_KEYS = Object.freeze([
  'netlifySiteId', 'netlifyOrigin', 'supabaseProjectRef', 'databaseSystemIdentifier',
  'targetSha256', 'previousDeployId'
]);
const DEPOSIT_AUTHORIZATION_MATERIAL_KEYS = Object.freeze([
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
const EXECUTION_RECEIPT_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'secretValuesSerialized', 'executedAt', 'target',
  'executor', 'claimId', 'barrierGeneration', 'planCoreSha256',
  'reconciliationPlanSha256', 'rollbackAuthorizationChainSha256',
  'orderedActions', 'actionResults', 'brokerStateMutationAttempted',
  'publisherLeaseReleased', 'runReconciliationBarrierReleased'
]);
const ACTION_RESULT_KEYS = Object.freeze([
  'sequence', 'kind', 'result', 'deployId'
]);
const FINAL_RELEASE_EVIDENCE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'finalizedAt', 'controllerRepository', 'controllerRef',
  'controllerCommit', 'controllerRunId', 'controllerRunAttempt', 'dispatchNonce',
  'policySha256', 'source', 'artifact', 'target', 'netlifyDeployId', 'previousDeployId',
  'functionByteAttestationAvailable', 'authenticatedUatPassed',
  'retainedEvidenceSha256', 'evidenceSetSha256'
]);
const FINAL_RETAINED_EVIDENCE_KEYS = Object.freeze([
  'producerManifest', 'preReleaseReconciliation', 'authorization',
  'authorizationVerificationBundle', 'liveGitHubPrecredentialBoundary',
  'liveGitHubPrepromotionBoundary', 'rollbackAttestationDepositReceipt',
  'rollbackAttestationDepositValidation', 'liveNetlifyAuthorityBoundary',
  'functionEnvironment', 'runtimeProofEnvelope', 'backupDisableRuntimeBoundary', 'runtimeCapabilityBoundary',
  'preflight', 'rollbackReadiness', 'draftGate', 'durableDraftIntent', 'draftReceipt',
  'draftMetadata', 'draftVerification', 'controlBehavior', 'privateDraftAccessBoundary',
  'privateDraftLifecycle', 'exclusivePublisherLease', 'promotionAttempt',
  'exactPromotion', 'postPromotionVerification', 'scheduledFunctionRouteDenial',
  'authenticatedUat', 'finalCurrentVerification', 'exclusivePublisherRelease'
]);
const EXCLUSIVE_PUBLISHER_RELEASE_EVIDENCE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'releasedAt', 'controllerRepository', 'controllerRef', 'controllerCommit',
  'controllerRunId', 'source', 'netlifyDeployId', 'lockLeaseId',
  'originalExclusivePublisherEvidenceSha256', 'releaseAction',
  'leaseActiveAfterRelease', 'runReconciliationBarrierActiveAfterRelease',
  'runReconciliationBarrierGeneration',
  'automaticRunReconciliationBarrierExpiryPermitted',
  'draftIntentTerminalBeforeRunReconciliationBarrierClearRequired',
  'brokerPolicyId', 'brokerPolicySha256',
  'currentPublishedDeployIdBeforeRelease', 'currentPublishedDeployIdAfterRelease'
]);
const SUCCESS_AUTHORIZATION_VALIDATION_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'verifiedAt', 'controllerRepository', 'controllerRef',
  'controllerCommit', 'controllerWorkflowPath', 'controllerRunId',
  'controllerRunAttempt', 'githubActor', 'dispatchNonce', 'policySha256', 'source',
  'artifact', 'target', 'previousDeployId', 'knownGoodRollbackEvidenceSha256',
  'independentReviewerGitHubLogin', 'namedRiskOwnerGitHubLogin',
  'functionRemoteByteAttestationUnavailableAccepted', 'authorizationExpiresAt',
  'principalProofVerifiedAt', 'principalProofExpiresAt',
  'deploymentControlBoundaryObservedAt', 'deploymentControlBoundaryExpiresAt',
  'netlifyPrincipalSubject', 'rollbackNetlifyPrincipalSubject',
  'netlifyPrincipalBoundary', 'rollbackNetlifyPrincipalBoundary',
  'targetSiteAndPublisherExclusion', 'exclusivePublisherEnforced',
  'privateDraftAccessEnforced', 'failedDraftCleanupEnforced', 'githubReleaseBoundary',
  'authorizationPacketSha256', 'approverRegistrySha256', 'signatureKeyIds',
  'signatureSha256'
]);
const SUCCESS_AUTHORIZATION_BUNDLE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'scope', 'productionAuthorization',
  'secretValuesSerialized', 'authorizationPacketSha256', 'authorizationDecision',
  'approverRegistrySha256', 'approverPublicKeys', 'signatureKeyIds', 'signatureSha256',
  'knownGoodEvidence', 'knownGoodEvidenceSha256', 'validationEvidence'
]);
const SUCCESS_AUTHORIZATION_DECISION_KEYS = Object.freeze([
  'decision', 'authorizedByGitHubLogin', 'authorizedAt', 'expiresAt',
  'controllerRunId', 'dispatchNonce', 'candidateCommit', 'candidateTree',
  'artifactSha256'
]);
const AUTHORIZATION_SIGNER_KEYS = Object.freeze([
  'independentSecurityReviewer', 'managedPlatformRiskOwner'
]);
const TERMINAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$/;
const GENERATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/;
const INTENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/;
const JOB_RESULTS = new Set(['success', 'failure', 'cancelled', 'skipped']);
const INTENT_STATUSES = new Set([
  'recorded', 'deploy_created', 'promoted', 'deleted', 'access_revoked', 'closed'
]);
const TERMINAL_INTENT_STATUSES = new Set(['promoted', 'deleted', 'access_revoked', 'closed']);
const NETLIFY_API_ORIGIN = 'https://api.netlify.com';
const NETLIFY_API_PREFIX = '/api/v1';

function activated(value, code, maximum = 500) {
  const result = required(value, code, maximum);
  if (/^__[A-Z0-9_]+__$/.test(result)) fail(code);
  return result;
}

function positiveInteger(value, code) {
  const raw = required(value, code, 32);
  if (!/^[1-9][0-9]*$/.test(raw)) fail(code);
  const number = Number(raw);
  if (!Number.isSafeInteger(number)) fail(code);
  return Object.freeze({ raw, number });
}

function exactSha40(value, code) {
  const result = required(value, code, 40).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(result) || result !== value) fail(code);
  return result;
}

function exactIdentifier(value, expression, code) {
  const result = required(value, code, 200);
  if (result !== value || !expression.test(result)) fail(code);
  return result;
}

function validateEvidencePointer(value, code) {
  assertExactKeys(value, ['sha256', 'reference'], code);
  exactSha256(value.sha256, code);
  const reference = required(value.reference, code, 500);
  if (reference !== value.reference || reference.length < 8) fail(code);
}

function strictBase64(value, code, maximum = 6 * 1024 * 1024) {
  const encoded = required(value, code, maximum);
  if (encoded !== value || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    fail(code);
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.toString('base64') !== encoded) fail(code);
  return bytes;
}

function decodeEd25519Signature(value, code) {
  const bytes = strictBase64(value, code, 256);
  if (bytes.byteLength !== 64) fail(code);
  return bytes;
}

function strictPublicKey(pem, expectedSpkiSha256, code) {
  if (typeof pem !== 'string' || pem.length > 2048 ||
    !pem.startsWith('-----BEGIN PUBLIC KEY-----\n') ||
    !pem.endsWith('-----END PUBLIC KEY-----\n')) fail(code);
  let key;
  try { key = crypto.createPublicKey(pem); }
  catch { fail(code); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519' ||
    key.export({ type: 'spki', format: 'pem' }) !== pem ||
    sha256(key.export({ type: 'spki', format: 'der' })) !== exactSha256(expectedSpkiSha256, code)) {
    fail(code);
  }
  return key;
}

function exactOperationPath(value, code) {
  const result = activated(value, code, 500);
  let url;
  try { url = new URL(result, 'https://policy.invalid'); }
  catch { fail(code); }
  if (!result.startsWith('/') || url.origin !== 'https://policy.invalid' ||
    url.pathname !== result || url.pathname.includes('//') || url.pathname.includes('/../') ||
    url.search || url.hash) fail(code);
  return result;
}

function exactAudience(value, code) {
  const result = activated(value, code, 500);
  let url;
  try { url = new URL(result); }
  catch { fail(code); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash ||
    url.href !== result) fail(code);
  return result;
}

export function brokerTrustRoot(kind) {
  const code = `CNYOS_RECONCILIATION_${String(kind).toUpperCase()}_BROKER_POLICY_INVALID`;
  const mapping = {
    reconciliation: {
      policy: POLICY.externalReconciliationBroker,
      keyId: 'signingKeyId', publicKey: 'signingPublicKeyPem',
      spki: 'signingKeySpkiSha256', maximum: 'maximumEvidenceAgeMinutes', path: true
    },
    draft: {
      policy: POLICY.draftLifecycleBroker,
      keyId: 'signingKeyId', publicKey: 'signingPublicKeyPem',
      spki: 'signingKeySpkiSha256', maximum: 'maximumEvidenceAgeMinutes', path: true
    },
    membership: {
      policy: POLICY.rollbackPrincipalMembershipBroker,
      keyId: 'signingKeyId', publicKey: 'signingPublicKeyPem',
      spki: 'signingKeySpkiSha256', maximum: 'maximumEvidenceAgeMinutes', path: true
    },
    authority: {
      policy: POLICY.netlifyAuthorityBoundary,
      keyId: 'signingKeyId', publicKey: 'signingPublicKeyPem',
      spki: 'signingKeySpkiSha256', maximum: 'maximumAgeMinutes', path: true
    },
    runtime: {
      policy: POLICY.runtimeEvidenceBroker,
      keyId: 'signingKeyId', publicKey: 'signingPublicKeyPem',
      spki: 'signingKeySpkiSha256', maximum: 'maximumEvidenceAgeMinutes', path: true
    },
    rollback: {
      policy: POLICY.rollbackAttestationBroker,
      keyId: 'receiptSigningKeyId', publicKey: 'receiptSigningPublicKeyPem',
      spki: 'receiptSigningSpkiSha256', maximum: 'maximumReceiptAgeMinutes', path: false
    }
  }[kind];
  if (!mapping || !isPlainObject(mapping.policy)) fail(code);
  const policy = mapping.policy;
  const originValue = activated(policy.origin, code);
  const origin = safeOrigin(originValue, code);
  if (origin !== originValue) fail(code);
  const operationPath = mapping.path ? exactOperationPath(policy.operationPath, code) : '/';
  const operationDomain = mapping.path
    ? activated(policy.operationDomain, code, 200)
    : 'cnyos_staging_rollback_attestation';
  const policyId = activated(policy.policyId, code, 200);
  const policySha256 = exactSha256(policy.policySha256, code);
  const signingKeyId = activated(policy[mapping.keyId], code, 200);
  const signingKeySpkiSha256 = exactSha256(policy[mapping.spki], code);
  const publicKey = strictPublicKey(policy[mapping.publicKey], signingKeySpkiSha256, code);
  const oidcAudience = exactAudience(policy.oidcAudience, code);
  const maximumMinutes = policy[mapping.maximum];
  if (!Number.isSafeInteger(maximumMinutes) || maximumMinutes < 1 || maximumMinutes > 30) fail(code);
  const maximumResponseBytes = mapping.path ? policy.maximumResponseBytes : 2 * 1024 * 1024;
  if (!Number.isSafeInteger(maximumResponseBytes) || maximumResponseBytes < 1024 ||
    maximumResponseBytes > 4 * 1024 * 1024) fail(code);
  return Object.freeze({
    kind, origin, operationPath, endpoint: new URL(operationPath, `${origin}/`).href,
    operationDomain, policyId, policySha256, signingKeyId, signingKeySpkiSha256,
    publicKey, oidcAudience, maximumAgeMs: maximumMinutes * 60 * 1000,
    maximumResponseBytes
  });
}

function assertEndpoint(value, trust, code) {
  const configured = required(value, code, 1000);
  let url;
  try { url = new URL(configured); }
  catch { fail(code); }
  if (url.href !== trust.endpoint || url.username || url.password || url.hash) fail(code);
  return url;
}

function assertAbsentEnvironmentNames(env, names, code) {
  for (const name of names) if (Object.hasOwn(env, name)) fail(`${code}:${name}`);
}

function controllerRuntime(env) {
  if (env.GITHUB_REF_PROTECTED !== 'true') fail('CNYOS_RECONCILIATION_PROTECTED_REF_REQUIRED');
  const repository = required(env.GITHUB_REPOSITORY, 'CNYOS_RECONCILIATION_REPOSITORY_REQUIRED', 200);
  if (repository !== POLICY.controller.repository ||
    env.CNYOS_CONTROLLER_EXPECTED_REPOSITORY !== repository) {
    fail('CNYOS_RECONCILIATION_REPOSITORY_INVALID');
  }
  const ref = required(env.GITHUB_REF, 'CNYOS_RECONCILIATION_REF_REQUIRED', 300);
  if (ref !== POLICY.controller.protectedRef || env.CNYOS_CONTROLLER_PROTECTED_REF !== ref) {
    fail('CNYOS_RECONCILIATION_REF_INVALID');
  }
  const workflowPath = required(
    env.CNYOS_CONTROLLER_WORKFLOW_PATH,
    'CNYOS_RECONCILIATION_WORKFLOW_PATH_REQUIRED',
    300
  );
  if (![POLICY.controller.releaseWorkflowPath, POLICY.controller.rollbackWorkflowPath]
    .includes(workflowPath)) fail('CNYOS_RECONCILIATION_WORKFLOW_PATH_INVALID');
  const commit = exactSha40(env.GITHUB_SHA, 'CNYOS_RECONCILIATION_COMMIT_INVALID');
  const run = positiveInteger(env.GITHUB_RUN_ID, 'CNYOS_RECONCILIATION_RUN_ID_INVALID');
  const attempt = positiveInteger(env.GITHUB_RUN_ATTEMPT, 'CNYOS_RECONCILIATION_RUN_ATTEMPT_INVALID');
  const expectedWorkflowRef = `${repository}/${workflowPath}@${ref}`;
  if (env.GITHUB_WORKFLOW_REF !== expectedWorkflowRef) {
    fail('CNYOS_RECONCILIATION_WORKFLOW_REF_INVALID');
  }
  return Object.freeze({
    controllerRepository: repository,
    controllerRef: ref,
    controllerWorkflowPath: workflowPath,
    controllerRunId: run.raw,
    controllerRunAttempt: attempt.number,
    controllerCommit: commit
  });
}

function assertRuntimeMode(runtime, env, watchdog) {
  if (watchdog !==
    (runtime.controllerWorkflowPath === POLICY.controller.rollbackWorkflowPath)) {
    fail('CNYOS_RECONCILIATION_WORKFLOW_MISMATCH');
  }
  if (!watchdog) {
    if (runtime.controllerRunAttempt !== 1) fail('CNYOS_RECONCILIATION_RELEASE_RUNTIME_REQUIRED');
    return;
  }
  if (env.CNYOS_WATCHDOG_RUN_ID !== runtime.controllerRunId ||
    positiveInteger(env.CNYOS_WATCHDOG_RUN_ATTEMPT,
      'CNYOS_RECONCILIATION_WATCHDOG_RUN_ATTEMPT_INVALID').number !==
      runtime.controllerRunAttempt ||
    env.CNYOS_WATCHDOG_CONTROLLER_COMMIT !== runtime.controllerCommit) {
    fail('CNYOS_RECONCILIATION_WATCHDOG_IDENTITY_MISMATCH');
  }
}

function assertPreparationResultGate(env, watchdog, expectedDisposition) {
  const result = watchdog ? env.CNYOS_RECOVERY_PREPARATION_JOB_RESULT :
    env.CNYOS_PREPARATION_JOB_RESULT;
  const outcome = watchdog ? env.CNYOS_RECOVERY_PLAN_DOWNLOAD_OUTCOME :
    env.CNYOS_PREPARATION_DOWNLOAD_OUTCOME;
  if (result !== 'success' || outcome !== 'success' ||
    env.CNYOS_RECOVERY_DISPOSITION !== expectedDisposition) {
    fail('CNYOS_RECONCILIATION_PREPARATION_NOT_VERIFIED');
  }
}

function assertWatchdogPolicyFile(env) {
  if (!Object.hasOwn(env, 'CNYOS_CONTROLLER_POLICY_PATH')) {
    if (env.CNYOS_CONTROLLER_WORKFLOW_PATH === POLICY.controller.rollbackWorkflowPath) {
      fail('CNYOS_RECONCILIATION_POLICY_PATH_REQUIRED');
    }
    return Promise.resolve();
  }
  return readFileBounded(
    required(env.CNYOS_CONTROLLER_POLICY_PATH, 'CNYOS_RECONCILIATION_POLICY_PATH_REQUIRED', 4096),
    1024 * 1024,
    'CNYOS_RECONCILIATION_POLICY_FILE_INVALID'
  ).then(bytes => {
    if (sha256(bytes) !== POLICY_SHA256 ||
      !isDeepStrictEqual(parseJsonObject(bytes.toString('utf8'),
        'CNYOS_RECONCILIATION_POLICY_FILE_INVALID'), POLICY)) {
      fail('CNYOS_RECONCILIATION_POLICY_FILE_MISMATCH');
    }
  });
}

function targetFromEnvironment(env, runtime, { allowUnknownNonce = false } = {}) {
  const watchdog = runtime.controllerWorkflowPath === POLICY.controller.rollbackWorkflowPath;
  const repository = watchdog
    ? required(env.CNYOS_TARGET_CONTROLLER_REPOSITORY,
      'CNYOS_RECONCILIATION_TARGET_REPOSITORY_REQUIRED', 200)
    : runtime.controllerRepository;
  const runId = positiveInteger(
    env.CNYOS_TARGET_CONTROLLER_RUN_ID || runtime.controllerRunId,
    'CNYOS_RECONCILIATION_TARGET_RUN_ID_INVALID'
  ).raw;
  const runAttempt = positiveInteger(
    env.CNYOS_TARGET_CONTROLLER_RUN_ATTEMPT || String(runtime.controllerRunAttempt),
    'CNYOS_RECONCILIATION_TARGET_RUN_ATTEMPT_INVALID'
  ).number;
  const commit = exactSha40(
    env.CNYOS_TARGET_CONTROLLER_COMMIT || runtime.controllerCommit,
    'CNYOS_RECONCILIATION_TARGET_COMMIT_INVALID'
  );
  if (repository !== POLICY.controller.repository || runAttempt !== 1 ||
    (!watchdog && (runId !== runtime.controllerRunId || commit !== runtime.controllerCommit))) {
    fail('CNYOS_RECONCILIATION_TARGET_IDENTITY_MISMATCH');
  }
  let dispatchNonce = null;
  if (Object.hasOwn(env, 'CNYOS_DISPATCH_NONCE')) dispatchNonce = decodeNonce(env.CNYOS_DISPATCH_NONCE).value;
  else if (!allowUnknownNonce && !watchdog) fail('CNYOS_RECONCILIATION_TARGET_NONCE_REQUIRED');
  return Object.freeze({
    controllerRepository: repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerWorkflowPath: POLICY.controller.releaseWorkflowPath,
    controllerRunId: runId,
    controllerRunAttempt: runAttempt,
    controllerCommit: commit,
    dispatchNonce,
    netlifySiteId: POLICY.target.netlifySiteId,
    barrierGeneration: null
  });
}

function assertTarget(value, expected, code, { requireGeneration = true } = {}) {
  assertExactKeys(value, TARGET_KEYS, code);
  if (value.controllerRepository !== expected.controllerRepository ||
    value.controllerRef !== expected.controllerRef ||
    value.controllerWorkflowPath !== expected.controllerWorkflowPath ||
    value.controllerRunId !== expected.controllerRunId ||
    value.controllerRunAttempt !== expected.controllerRunAttempt ||
    value.controllerCommit !== expected.controllerCommit ||
    value.netlifySiteId !== POLICY.target.netlifySiteId ||
    (expected.dispatchNonce !== null && value.dispatchNonce !== expected.dispatchNonce) ||
    (expected.barrierGeneration !== null &&
      value.barrierGeneration !== expected.barrierGeneration)) fail(code);
  decodeNonce(value.dispatchNonce);
  if (requireGeneration) exactIdentifier(value.barrierGeneration, GENERATION, code);
  else if (value.barrierGeneration !== null) exactIdentifier(value.barrierGeneration, GENERATION, code);
  return value;
}

function assertResumer(value, expected, code) {
  assertExactKeys(value, RESUMER_KEYS, code);
  if (!isDeepStrictEqual(value, expected)) fail(code);
  return value;
}

function nowDate(now) {
  const value = now();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    fail('CNYOS_RECONCILIATION_TIME_INVALID');
  }
  return value;
}

async function boundedResponseBytes(response, maximum, code) {
  const lengthHeader = String(response?.headers?.get?.('content-length') || '').trim();
  if (lengthHeader) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(lengthHeader) || Number(lengthHeader) > maximum) fail(code);
  }
  const reader = response?.body?.getReader?.();
  if (!reader) fail(code);
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (!isPlainObject(item) || typeof item.done !== 'boolean' ||
        (!item.done && !(item.value instanceof Uint8Array))) fail(code);
      if (item.done) break;
      length += item.value.byteLength;
      if (length > maximum) {
        try { await reader.cancel(); } catch {}
        fail(code);
      }
      chunks.push(Buffer.from(item.value));
    }
  } catch (error) {
    if (String(error?.message || '').startsWith('CNYOS_')) throw error;
    fail(code);
  }
  if (length < 2) fail(code);
  return Buffer.concat(chunks, length);
}

function assertResponseHeadersDoNotReflectCredential(response, credential) {
  const code = 'CNYOS_RECONCILIATION_OIDC_TOKEN_REFLECTION_INVALID';
  if (typeof response?.headers?.entries !== 'function') fail(code);
  let entries;
  try { entries = [...response.headers.entries()]; }
  catch { fail(code); }
  if (entries.length > 256) fail(code);
  let totalBytes = 0;
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2 ||
      typeof entry[0] !== 'string' || typeof entry[1] !== 'string') fail(code);
    totalBytes += Buffer.byteLength(entry[0]) + Buffer.byteLength(entry[1]);
    if (totalBytes > 64 * 1024 || entry[0].includes(credential) ||
      entry[1].includes(credential)) fail(code);
  }
}

function assertResponseBodyDoesNotReflectCredential(bytes, credential) {
  if (bytes.includes(Buffer.from(credential))) {
    fail('CNYOS_RECONCILIATION_OIDC_TOKEN_REFLECTION_INVALID');
  }
}

function validateSignature(signature, statement, trust, code) {
  assertExactKeys(signature, SIGNATURE_KEYS, code);
  const raw = JSON.stringify(statement);
  const bytes = decodeEd25519Signature(signature.signatureBase64, code);
  if (signature.algorithm !== 'Ed25519' || signature.keyId !== trust.signingKeyId ||
    signature.statementSha256 !== sha256(raw) ||
    signature.signatureSha256 !== sha256(bytes) ||
    !crypto.verify(null, Buffer.from(raw), trust.publicKey, bytes)) fail(code);
}

export function verifySignedBrokerEnvelope(raw, {
  trust,
  operation,
  requestSha256,
  observedAt,
  requireFresh = true
}) {
  const code = 'CNYOS_RECONCILIATION_BROKER_RESPONSE_INVALID';
  const value = parseJsonObject(Buffer.isBuffer(raw) ? raw.toString('utf8') : raw, code);
  const canonical = JSON.stringify(value);
  if ((Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)) !== canonical) {
    fail('CNYOS_RECONCILIATION_BROKER_RESPONSE_NONCANONICAL');
  }
  assertExactKeys(value, BROKER_ENVELOPE_KEYS, code);
  assertExactKeys(value.statement, BROKER_STATEMENT_KEYS, code);
  const statement = value.statement;
  if (value.schemaVersion !== 1 ||
    value.evidenceType !== 'cnyos_staging_reconciliation_broker_envelope' ||
    statement.schemaVersion !== 1 || statement.operationDomain !== trust.operationDomain ||
    statement.operation !== operation || statement.policyId !== trust.policyId ||
    statement.policySha256 !== trust.policySha256 ||
    statement.requestSha256 !== requestSha256 || !isPlainObject(statement.result)) fail(code);
  const issuedAt = canonicalIsoTimestamp(statement.issuedAt, code);
  const expiresAt = canonicalIsoTimestamp(statement.expiresAt, code);
  if (expiresAt <= issuedAt || expiresAt.getTime() - issuedAt.getTime() > trust.maximumAgeMs ||
    issuedAt > observedAt || observedAt.getTime() - issuedAt.getTime() > trust.maximumAgeMs ||
    (requireFresh && expiresAt <= observedAt)) fail('CNYOS_RECONCILIATION_BROKER_RESPONSE_STALE');
  validateSignature(value.brokerSignature, statement, trust,
    'CNYOS_RECONCILIATION_BROKER_SIGNATURE_INVALID');
  return Object.freeze({ value, raw: canonical, statement, result: statement.result });
}

async function defaultOidcTokenProvider({ env, audience, fetchImpl }) {
  const requestUrl = required(env.ACTIONS_ID_TOKEN_REQUEST_URL,
    'CNYOS_RECONCILIATION_OIDC_REQUEST_URL_REQUIRED', 2000);
  const requestToken = required(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    'CNYOS_RECONCILIATION_OIDC_REQUEST_TOKEN_REQUIRED', 8192);
  let url;
  try { url = new URL(requestUrl); }
  catch { fail('CNYOS_RECONCILIATION_OIDC_REQUEST_URL_INVALID'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    fail('CNYOS_RECONCILIATION_OIDC_REQUEST_URL_INVALID');
  }
  url.searchParams.set('audience', audience);
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET', redirect: 'error', credentials: 'omit',
      referrerPolicy: 'no-referrer', cache: 'no-store',
      signal: AbortSignal.timeout(15_000),
      headers: { Accept: 'application/json', Authorization: `Bearer ${requestToken}` }
    });
  } catch { fail('CNYOS_RECONCILIATION_OIDC_REQUEST_FAILED'); }
  if (response?.redirected || response?.status !== 200 ||
    !String(response?.headers?.get?.('content-type') || '').toLowerCase()
      .startsWith('application/json')) fail('CNYOS_RECONCILIATION_OIDC_RESPONSE_INVALID');
  const bytes = await boundedResponseBytes(response, 64 * 1024,
    'CNYOS_RECONCILIATION_OIDC_RESPONSE_INVALID');
  const value = parseJsonObject(bytes.toString('utf8'),
    'CNYOS_RECONCILIATION_OIDC_RESPONSE_INVALID');
  const token = required(value.value, 'CNYOS_RECONCILIATION_OIDC_TOKEN_INVALID', 8192);
  if (/\s|\0/.test(token)) fail('CNYOS_RECONCILIATION_OIDC_TOKEN_INVALID');
  return token;
}

function requestBody(operation, trust, resumer, target, evidence) {
  const value = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_broker_request',
    operationDomain: trust.operationDomain,
    operation,
    policyId: trust.policyId,
    policySha256: trust.policySha256,
    controllerPolicySha256: POLICY_SHA256,
    resumer,
    target,
    evidence
  });
  return JSON.stringify(value);
}

export async function callSignedBrokerOperation({
  env,
  fetchImpl,
  oidcTokenProvider = defaultOidcTokenProvider,
  trust,
  configuredUrl,
  operation,
  resumer,
  target,
  evidence,
  now = () => new Date()
}) {
  const endpoint = assertEndpoint(configuredUrl, trust,
    'CNYOS_RECONCILIATION_BROKER_URL_INVALID');
  const body = requestBody(operation, trust, resumer, target, evidence);
  const providedOidcToken = await oidcTokenProvider({
    env, audience: trust.oidcAudience, fetchImpl
  });
  const oidcToken = required(
    providedOidcToken,
    'CNYOS_RECONCILIATION_OIDC_TOKEN_INVALID',
    8192
  );
  if (providedOidcToken !== oidcToken || oidcToken.length < 20 || /[\s\0]/.test(oidcToken)) {
    fail('CNYOS_RECONCILIATION_OIDC_TOKEN_INVALID');
  }
  if (body.includes(oidcToken)) fail('CNYOS_RECONCILIATION_CREDENTIAL_SERIALIZATION_INVALID');
  let response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST', redirect: 'error', credentials: 'omit',
      referrerPolicy: 'no-referrer', cache: 'no-store',
      signal: AbortSignal.timeout(20_000),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${oidcToken}`
      },
      body
    });
  } catch { fail('CNYOS_RECONCILIATION_BROKER_REQUEST_FAILED'); }
  assertResponseHeadersDoNotReflectCredential(response, oidcToken);
  if (response?.redirected || response?.status !== 200 || response?.url !== endpoint.href ||
    !String(response?.headers?.get?.('content-type') || '').toLowerCase()
      .startsWith('application/json')) fail('CNYOS_RECONCILIATION_BROKER_RESPONSE_INVALID');
  const bytes = await boundedResponseBytes(response, trust.maximumResponseBytes,
    'CNYOS_RECONCILIATION_BROKER_RESPONSE_INVALID');
  assertResponseBodyDoesNotReflectCredential(bytes, oidcToken);
  const observedAt = nowDate(now);
  const requestSha256 = sha256(body);
  const verified = verifySignedBrokerEnvelope(bytes, {
    trust, operation, requestSha256, observedAt
  });
  return Object.freeze({ ...verified, observedAt, requestSha256 });
}

async function writeBytesExclusive(filename, bytes) {
  const destination = path.resolve(required(filename,
    'CNYOS_RECONCILIATION_OUTPUT_PATH_REQUIRED', 4096));
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const handle = await fs.open(destination, 'wx', 0o600);
  try { await handle.writeFile(bytes); }
  finally { await handle.close(); }
  await fs.chmod(destination, 0o600);
  return destination;
}

async function loadHashedJson(filename, expectedDigest, code, { canonical = false } = {}) {
  const bytes = await readFileBounded(required(filename, `${code}_PATH_REQUIRED`, 4096),
    4 * 1024 * 1024, code);
  const digest = sha256(bytes);
  if (digest !== exactSha256(expectedDigest, `${code}_DIGEST_REQUIRED`)) {
    fail(`${code}_DIGEST_MISMATCH`);
  }
  const raw = bytes.toString('utf8');
  const value = parseJsonObject(raw, code);
  if (canonical && raw !== JSON.stringify(value)) fail(`${code}_NONCANONICAL`);
  return Object.freeze({ bytes, raw, value, sha256: digest });
}

function assertBrokerSignatureObject(envelope, trust, statement, code) {
  validateSignature(envelope.brokerSignature, statement, trust, code);
}

export function verifyDepositReceipt(raw, trust, target, observedAt) {
  const code = 'CNYOS_RECONCILIATION_DEPOSIT_RECEIPT_INVALID';
  const envelope = parseJsonObject(raw, code);
  if (raw !== JSON.stringify(envelope)) fail(`${code}_NONCANONICAL`);
  assertExactKeys(envelope, ['schemaVersion', 'evidenceType', 'receipt', 'brokerSignature'], code);
  if (envelope.schemaVersion !== 1 ||
    envelope.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_envelope' ||
    !isPlainObject(envelope.receipt)) fail(code);
  const receipt = envelope.receipt;
  const controller = receipt.controller;
  const receiptTarget = receipt.target;
  assertExactKeys(receipt, DEPOSIT_RECEIPT_KEYS, code);
  assertExactKeys(receipt.broker, DEPOSIT_BROKER_KEYS, code);
  assertExactKeys(controller, DEPOSIT_CONTROLLER_KEYS, code);
  assertExactKeys(receipt.source, AUTHORIZATION_SOURCE_KEYS, code);
  assertExactKeys(receipt.artifact, AUTHORIZATION_ARTIFACT_KEYS, code);
  assertExactKeys(receiptTarget, DEPOSIT_TARGET_KEYS, code);
  assertExactKeys(receipt.authorizationMaterial, DEPOSIT_AUTHORIZATION_MATERIAL_KEYS, code);
  assertExactKeys(receipt.depositSemantics, DEPOSIT_SEMANTICS_KEYS, code);
  assertExactKeys(receipt.recoveryMaterial, RECOVERY_MATERIAL_KEYS, code);
  assertExactKeys(receipt.retrievalBoundary, RETRIEVAL_BOUNDARY_KEYS, code);
  if (receipt.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_receipt' ||
    receipt.status !== 'sealed' || receipt.scope !== 'cnyos_staging_only' ||
    receipt.productionAuthorization !== false || receipt.realPatientDataAuthorized !== false ||
    receipt.depositSequence !== 1 ||
    !SHA256.test(String(receipt.depositRequestSha256 || '')) ||
    receipt.broker?.origin !== trust.origin || receipt.broker?.policyId !== trust.policyId ||
    receipt.broker?.policySha256 !== trust.policySha256 ||
    receipt.broker?.receiptSigningKeyId !== trust.signingKeyId ||
    receipt.broker?.receiptSigningSpkiSha256 !== trust.signingKeySpkiSha256 ||
    controller?.repository !== target.controllerRepository ||
    controller?.ref !== target.controllerRef ||
    controller?.workflowPath !== target.controllerWorkflowPath ||
    controller?.runId !== target.controllerRunId ||
    controller?.runAttempt !== target.controllerRunAttempt ||
    controller?.commit !== target.controllerCommit ||
    controller?.dispatchNonce !== target.dispatchNonce ||
    controller?.policySha256 !== POLICY_SHA256 ||
    controller?.workflowRef !==
      `${target.controllerRepository}/${target.controllerWorkflowPath}@${target.controllerRef}` ||
    receiptTarget?.netlifySiteId !== target.netlifySiteId ||
    receiptTarget?.netlifyOrigin !== POLICY.target.netlifyOrigin ||
    receiptTarget?.supabaseProjectRef !== POLICY.target.supabaseProjectRef ||
    receiptTarget?.databaseSystemIdentifier !== POLICY.target.databaseSystemIdentifier ||
    receiptTarget?.targetSha256 !== sha256(JSON.stringify(POLICY.target)) ||
    receipt.retrievalBoundary?.requiredControllerRepository !== target.controllerRepository ||
    receipt.retrievalBoundary?.requiredControllerRef !== target.controllerRef ||
    receipt.retrievalBoundary?.requiredControllerWorkflowPath !== target.controllerWorkflowPath ||
    receipt.retrievalBoundary?.requiredControllerRunId !== target.controllerRunId ||
    receipt.retrievalBoundary?.requiredControllerRunAttempt !== target.controllerRunAttempt ||
    receipt.retrievalBoundary?.requiredDispatchNonce !== target.dispatchNonce ||
    receipt.retrievalBoundary?.exactRunAndNonceRequired !== true ||
    receipt.retrievalBoundary?.oidcControllerIdentityRequired !== true ||
    receipt.retrievalBoundary?.externalReconciliationPolicyId !==
      POLICY.externalReconciliationBroker.policyId ||
    receipt.retrievalBoundary?.externalReconciliationPolicySha256 !==
      exactSha256(POLICY.externalReconciliationBroker.policySha256, code)) fail(code);
  if (receipt.depositSemantics.appendOnly !== true ||
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
    receipt.retrievalBoundary.failedRunCodeCannotDelete !== true ||
    receipt.retrievalBoundary.watchdogRevisionCannotDelete !== true) fail(code);
  exactIdentifier(receipt.depositId, TERMINAL_ID, code);
  exactDeployId(receiptTarget.previousDeployId, code);
  const depositedAt = canonicalIsoTimestamp(receipt.depositedAt, code);
  const retentionUntil = canonicalIsoTimestamp(receipt.retentionUntil, code);
  const minimumRetentionDays = POLICY.rollbackAttestationBroker.minimumRetentionDays;
  if (!Number.isSafeInteger(minimumRetentionDays) || minimumRetentionDays < 365 ||
    minimumRetentionDays > 3650 ||
    retentionUntil.getTime() - depositedAt.getTime() < minimumRetentionDays * 86_400_000) {
    fail('CNYOS_RECONCILIATION_DEPOSIT_RETENTION_INSUFFICIENT');
  }
  if (depositedAt > observedAt || retentionUntil <= observedAt) {
    fail('CNYOS_RECONCILIATION_DEPOSIT_RETENTION_EXPIRED');
  }
  assertBrokerSignatureObject(envelope, trust, receipt,
    'CNYOS_RECONCILIATION_DEPOSIT_RECEIPT_SIGNATURE_INVALID');
  return Object.freeze({ envelope, receipt, sha256: sha256(raw) });
}

function authorizationBrokerContract(packet, target, code) {
  const broker = packet.deploymentControlBoundary?.externalRollbackReconciliationBroker;
  assertExactKeys(broker, AUTHORIZATION_BROKER_KEYS, code);
  if (!isPlainObject(broker) ||
    broker.policyId !== POLICY.externalReconciliationBroker.policyId ||
    broker.policySha256 !== POLICY.externalReconciliationBroker.policySha256 ||
    broker.executionAuthority !== 'external_rollback_reconciliation_broker' ||
    broker.immutablePolicy !== true ||
    broker.independentOfTargetRunCode !== true ||
    broker.independentOfWatchdogRevision !== true ||
    broker.targetControllerRepository !== target.controllerRepository ||
    broker.targetControllerRef !== target.controllerRef ||
    broker.targetControllerWorkflowPath !== target.controllerWorkflowPath ||
    broker.targetControllerRunId !== target.controllerRunId ||
    broker.targetControllerRunAttempt !== target.controllerRunAttempt ||
    broker.targetControllerCommit !== target.controllerCommit ||
    broker.targetDispatchNonce !== target.dispatchNonce ||
    broker.targetNetlifySiteId !== target.netlifySiteId ||
    broker.targetRunCannotSuppressReconciliation !== true ||
    broker.watchdogRevisionCannotSuppressReconciliation !== true ||
    broker.enforcesRollback !== true ||
    broker.enforcesDraftCleanup !== true ||
    broker.enforcesLeaseRelease !== true ||
    broker.enforcesRunReconciliationBarrier !== true ||
    broker.recoveryClaimAndPlanCorePersistedAtomically !== true ||
    broker.recoveryClaimPlanCoreImmutableAndRetrievable !== true ||
    broker.exactRecoveryClaimRetryIdempotent !== true ||
    broker.authorizedWatchdogRecoveryClaimResumptionEnforced !== true ||
    broker.recoveryAuthorizationRefreshPreservesClaimAndPlanCore !== true ||
    broker.conflictingRecoveryClaimBindingsOrGenerationRejected !== true ||
    broker.automaticRecoveryClaimExpiryPermitted !== false ||
    broker.incompleteRecoveryRecordPreservesRecoveryClaimAndPlan !== true ||
    broker.recoveryClaimAuthorizedResumerRepository !== POLICY.controller.repository ||
    broker.recoveryClaimAuthorizedResumerProtectedRef !== POLICY.controller.protectedRef ||
    JSON.stringify(broker.recoveryClaimAuthorizedResumerWorkflowPaths) !== JSON.stringify([
      POLICY.controller.releaseWorkflowPath, POLICY.controller.rollbackWorkflowPath
    ]) || broker.terminalSuccessAndRecoveryClaimMutuallyExclusive !== true ||
    broker.recoveryClaimConflictsWithDelayedTerminalCommit !== true ||
    broker.recoveryTerminalRecordBindsExecutionReceipt !== true ||
    broker.exactTerminalCommitRetryIdempotent !== true ||
    broker.exactRecoveryFinalizationRetryIdempotent !== true ||
    broker.terminalSuccessNeverRollbackEligible !== true ||
    broker.terminalRecoveryNeverRollbackEligible !== true ||
    broker.recoveryTerminalRecordImmutableAndRetrievable !== true ||
    broker.atomicLeaseReleaseRetainsRunReconciliationBarrier !== true ||
    broker.blocksNewMutationWhileRunReconciliationBarrierActive !== true ||
    broker.successfulReleaseCommitRequiresFinalEvidenceHashes !== true ||
    broker.draftIntentTerminalBeforeBarrierClearRequired !== true ||
    broker.automaticRunReconciliationBarrierExpiryPermitted !== false) fail(code);
  validateEvidencePointer(broker.evidence, code);
}

function validateRecoveredKnownGood(value, bytes, target, previousDeployId, code) {
  if (!isPlainObject(value) || value.schemaVersion !== 1 || value.status !== 'passed' ||
    !['cnyos_staging_controller_final_release',
      'cnyos_staging_controller_bootstrap_known_good'].includes(value.evidenceType) ||
    value.scope !== 'cnyos_staging_only' || value.productionAuthorization !== false ||
    value.realPatientDataAuthorized !== false || value.controllerRepository !==
      POLICY.controller.repository || value.policySha256 !== POLICY_SHA256 ||
    value.source?.repository !== POLICY.sourceRepository ||
    !/^[0-9a-f]{40}$/.test(String(value.source?.commit || '')) ||
    value.target?.netlifySiteId !== target.netlifySiteId ||
    value.target?.netlifyOrigin !== POLICY.target.netlifyOrigin ||
    !isDeepStrictEqual(value.target, POLICY.target) ||
    value.netlifyDeployId !== previousDeployId || bytes.byteLength < 2) fail(code);
  if (value.evidenceType === 'cnyos_staging_controller_bootstrap_known_good') {
    assertExactKeys(value, [
      'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
      'realPatientDataAuthorized', 'recordedAt', 'controllerRepository', 'policySha256',
      'source', 'target', 'netlifyDeployId', 'evidence'
    ], code);
    assertExactKeys(value.source, ['repository', 'commit'], code);
    assertExactKeys(value.evidence, ['sha256', 'reference'], code);
    canonicalIsoTimestamp(value.recordedAt, code);
    exactSha256(value.evidence.sha256, code);
    required(value.evidence.reference, code, 500);
  } else {
    assertExactKeys(value, FINAL_RELEASE_EVIDENCE_KEYS, code);
    assertExactKeys(value.source, ['repository', 'commit', 'tree', 'functionSourceTree'], code);
    assertExactKeys(value.artifact, ['sha256', 'fileCount'], code);
    assertExactKeys(value.retainedEvidenceSha256, FINAL_RETAINED_EVIDENCE_KEYS, code);
    if (value.controllerRef !== POLICY.controller.protectedRef ||
      value.controllerRunAttempt !== 1 || value.functionByteAttestationAvailable !== false ||
      value.authenticatedUatPassed !== true ||
      value.evidenceSetSha256 !== sha256(JSON.stringify(value.retainedEvidenceSha256)) ||
      !Object.values(value.retainedEvidenceSha256).every(item => SHA256.test(String(item || ''))) ||
      !SHA256.test(String(value.artifact.sha256 || '')) ||
      !Number.isSafeInteger(value.artifact.fileCount) || value.artifact.fileCount < 1) fail(code);
    exactSha40(value.controllerCommit, code);
    positiveInteger(value.controllerRunId, code);
    decodeNonce(value.dispatchNonce);
    exactSha40(value.source.tree, code);
    exactSha40(value.source.functionSourceTree, code);
    exactDeployId(value.previousDeployId, code);
    exactSha256(value.evidenceSetSha256, code);
    canonicalIsoTimestamp(value.finalizedAt, code);
  }
}

function verifyRecoveryAuthorizationMaterial(result, trust, expectedTarget, local, observedAt) {
  const code = 'CNYOS_RECONCILIATION_RECOVERY_MATERIAL_INVALID';
  assertExactKeys(result, [
    'target', 'depositReceiptEnvelopeBase64', 'authorizationJsonBase64',
    'independentSecurityReviewerSignatureBase64',
    'managedPlatformRiskOwnerSignatureBase64', 'knownGoodEvidenceBase64',
    'authorizationBundleBase64', 'approverRegistryBase64'
  ], code);
  assertTarget(result.target, expectedTarget, code, { requireGeneration: false });
  const target = result.target;
  if (target.barrierGeneration !== null) fail(code);
  const material = {};
  for (const name of [
    'depositReceiptEnvelope', 'authorizationJson', 'knownGoodEvidence',
    'authorizationBundle', 'approverRegistry'
  ]) material[name] = strictBase64(result[`${name}Base64`], code);
  const receipt = verifyDepositReceipt(
    material.depositReceiptEnvelope.toString('utf8'), trust, target, observedAt
  );
  if (local) {
    for (const [name, item] of Object.entries(local)) {
      if (item && !item.bytes.equals(material[name])) fail(`${code}_LOCAL_${name.toUpperCase()}_MISMATCH`);
    }
  }
  const authorizationRaw = material.authorizationJson.toString('utf8');
  const packet = parseJsonObject(authorizationRaw, code);
  if (authorizationRaw !== JSON.stringify(packet)) fail(`${code}_AUTHORIZATION_NONCANONICAL`);
  assertExactKeys(packet, AUTHORIZATION_PACKET_KEYS, code);
  assertExactKeys(packet.controller, AUTHORIZATION_CONTROLLER_KEYS, code);
  assertExactKeys(packet.source, AUTHORIZATION_SOURCE_KEYS, code);
  assertExactKeys(packet.artifact, AUTHORIZATION_ARTIFACT_KEYS, code);
  assertExactKeys(packet.target, Object.keys(POLICY.target), code);
  assertExactKeys(packet.rollback, AUTHORIZATION_ROLLBACK_KEYS, code);
  assertExactKeys(packet.signatureKeyIds, [
    'independentSecurityReviewer', 'managedPlatformRiskOwner'
  ], code);
  assertExactKeys(packet.authorization, AUTHORIZATION_DECISION_KEYS, code);
  validateEvidencePointer(packet.rollback.knownGoodEvidence, code);
  validateEvidencePointer(packet.authorization.evidence, code);
  const authorizedAt = canonicalIsoTimestamp(packet.authorization.authorizedAt, code);
  const authorizationExpiresAt = canonicalIsoTimestamp(packet.authorization.expiresAt, code);
  if (packet.authorization.decision !== 'authorize_exact_cnyos_staging_controller_run' ||
    required(packet.authorization.authorizedByGitHubLogin, code, 100) !==
      packet.authorization.authorizedByGitHubLogin ||
    required(packet.authorization.authorizedByName, code, 200) !==
      packet.authorization.authorizedByName ||
    required(packet.authorization.authorizedByRole, code, 200) !==
      packet.authorization.authorizedByRole || authorizedAt > observedAt ||
    authorizationExpiresAt <= authorizedAt ||
    authorizationExpiresAt.getTime() - authorizedAt.getTime() >
      POLICY.authorization.maximumLifetimeMinutes * 60_000) fail(code);
  if (packet.source.repository !== POLICY.sourceRepository ||
    !/^[0-9a-f]{40}$/.test(String(packet.source.commit || '')) ||
    !/^[0-9a-f]{40}$/.test(String(packet.source.tree || '')) ||
    !/^[0-9a-f]{40}$/.test(String(packet.source.functionSourceTree || '')) ||
    !Number.isSafeInteger(packet.artifact.fileCount) || packet.artifact.fileCount < 1 ||
    positiveInteger(packet.artifact.producerRunId, code).raw !==
      String(packet.artifact.producerRunId) ||
    !Object.entries(packet.artifact).every(([name, value]) =>
      ['fileCount', 'producerRunId'].includes(name) || SHA256.test(String(value || '')))) {
    fail(code);
  }
  const bundle = parseJsonObject(material.authorizationBundle.toString('utf8'), code);
  const validation = bundle.validationEvidence;
  const registry = parseJsonObject(material.approverRegistry.toString('utf8'), code);
  const knownGood = parseJsonObject(material.knownGoodEvidence.toString('utf8'), code);
  const receiptAuthorization = receipt.receipt.authorizationMaterial;
  if (bundle.schemaVersion !== 2 ||
    bundle.evidenceType !== 'cnyos_staging_controller_authorization_verification_bundle' ||
    bundle.scope !== 'cnyos_staging_only' || bundle.productionAuthorization !== false ||
    bundle.secretValuesSerialized !== false || !isPlainObject(validation) ||
    validation.schemaVersion !== 1 ||
    validation.evidenceType !== 'cnyos_staging_controller_authorization_validation' ||
    validation.status !== 'authorized' || validation.scope !== 'cnyos_staging_only' ||
    validation.productionAuthorization !== false ||
    validation.realPatientDataAuthorized !== false ||
    validation.authorizationPacketSha256 !== sha256(material.authorizationJson) ||
    bundle.authorizationPacketSha256 !== sha256(material.authorizationJson) ||
    receiptAuthorization?.authorizationBundleSha256 !==
      sha256(material.authorizationBundle) ||
    bundle.approverRegistrySha256 !== sha256(material.approverRegistry) ||
    bundle.knownGoodEvidenceSha256 !== sha256(material.knownGoodEvidence) ||
    receiptAuthorization?.authorizationPacketSha256 !== sha256(material.authorizationJson) ||
    receiptAuthorization?.approverRegistrySha256 !== sha256(material.approverRegistry) ||
    receiptAuthorization?.knownGoodEvidenceSha256 !== sha256(material.knownGoodEvidence) ||
    validation.controllerRepository !== target.controllerRepository ||
    validation.controllerRef !== target.controllerRef ||
    validation.controllerWorkflowPath !== target.controllerWorkflowPath ||
    validation.controllerRunId !== target.controllerRunId ||
    validation.controllerRunAttempt !== target.controllerRunAttempt ||
    validation.controllerCommit !== target.controllerCommit ||
    validation.dispatchNonce !== target.dispatchNonce ||
    validation.authorizationExpiresAt !== packet.authorization.expiresAt ||
    validation.target?.netlifySiteId !== target.netlifySiteId ||
    packet.controller?.repository !== target.controllerRepository ||
    packet.controller?.ref !== target.controllerRef ||
    packet.controller?.workflowPath !== target.controllerWorkflowPath ||
    packet.controller?.runId !== target.controllerRunId ||
    packet.controller?.runAttempt !== target.controllerRunAttempt ||
    packet.controller?.commit !== target.controllerCommit ||
    packet.controller?.dispatchNonce !== target.dispatchNonce ||
    packet.controller?.workflowRef !==
      `${target.controllerRepository}/${target.controllerWorkflowPath}@${target.controllerRef}` ||
    packet.schemaVersion !== 3 ||
    packet.evidenceType !== 'cnyos_staging_controller_authorization' ||
    packet.productionAuthorization !== false || packet.realPatientDataAuthorized !== false ||
    packet.target?.netlifySiteId !== target.netlifySiteId ||
    !isDeepStrictEqual(packet.target, POLICY.target) ||
    !isDeepStrictEqual(packet.source, validation.source) ||
    !isDeepStrictEqual(packet.artifact, validation.artifact) ||
    !isDeepStrictEqual(receipt.receipt.source, packet.source) ||
    !isDeepStrictEqual(receipt.receipt.artifact, packet.artifact) ||
    packet.rollback?.previousDeployId !== receipt.receipt.target?.previousDeployId ||
    packet.rollback?.restoreOnlyControllerOwnedDeploy !== true ||
    packet.rollback?.restoreOnAnyPostPublishFailure !== true ||
    packet.rollback?.externalWatchdogRequired !== true ||
    packet.rollback?.knownGoodEvidence?.sha256 !== sha256(material.knownGoodEvidence) ||
    packet.deploymentControlBoundary?.rollbackPrincipal?.subject !==
      validation.rollbackNetlifyPrincipalSubject) fail(code);
  authorizationBrokerContract(packet, target, code);
  if (packet.signatureKeyIds.independentSecurityReviewer ===
    packet.signatureKeyIds.managedPlatformRiskOwner) fail(code);
  if (!Array.isArray(bundle.approverPublicKeys) || bundle.approverPublicKeys.length !== 2 ||
    registry.schemaVersion !== 1 || registry.environment !== 'cnyos-staging' ||
    !Array.isArray(registry.keys) || registry.keys.length < 2) fail(code);
  const signatures = [
    ['independentSecurityReviewer', 'independent_security_reviewer',
      result.independentSecurityReviewerSignatureBase64],
    ['managedPlatformRiskOwner', 'managed_platform_risk_owner',
      result.managedPlatformRiskOwnerSignatureBase64]
  ];
  const signerSpkiSha256 = new Set();
  for (const [slot, role, encoded] of signatures) {
    const signature = decodeEd25519Signature(encoded, code);
    const keyId = bundle.signatureKeyIds?.[slot];
    const archivedMatches = bundle.approverPublicKeys.filter(
      item => item?.id === keyId && item?.role === role
    );
    const currentMatches = registry.keys.filter(
      item => item?.id === keyId && item?.role === role
    );
    const archived = archivedMatches[0];
    const current = currentMatches[0];
    if (keyId !== packet.signatureKeyIds[slot] ||
      archivedMatches.length !== 1 || currentMatches.length !== 1 ||
      !isDeepStrictEqual(archived, current) ||
      bundle.signatureSha256?.[slot] !== sha256(signature) ||
      receiptAuthorization?.[`${slot}KeyId`] !== keyId ||
      receiptAuthorization?.[`${slot}SignatureSha256`] !== sha256(signature)) fail(code);
    const key = strictPublicKey(archived.publicKeyPem, archived.spkiSha256, code);
    signerSpkiSha256.add(archived.spkiSha256);
    if (!crypto.verify(null, material.authorizationJson, key, signature)) fail(code);
  }
  if (signerSpkiSha256.size !== signatures.length) fail(code);
  validateRecoveredKnownGood(
    knownGood, material.knownGoodEvidence, target,
    receipt.receipt.target?.previousDeployId, code
  );
  if (validation.knownGoodRollbackEvidenceSha256 !== sha256(material.knownGoodEvidence)) fail(code);
  const authorizationVerifiedAt = canonicalIsoTimestamp(validation.verifiedAt, code);
  const depositedAt = canonicalIsoTimestamp(receipt.receipt.depositedAt, code);
  if (authorizedAt > authorizationVerifiedAt || authorizationVerifiedAt > depositedAt ||
    depositedAt >= authorizationExpiresAt || authorizationVerifiedAt > observedAt) fail(code);
  return Object.freeze({
    target,
    previousDeployId: exactDeployId(receipt.receipt.target.previousDeployId, code),
    sourceCommit: exactSha40(validation.source?.commit, code),
    rollbackPrincipalSubject: validation.rollbackNetlifyPrincipalSubject,
    authorizationVerifiedAt: authorizationVerifiedAt.toISOString(),
    authorizationPacketSha256: sha256(material.authorizationJson),
    authorizationBundleSha256: sha256(material.authorizationBundle),
    approverRegistrySha256: sha256(material.approverRegistry),
    knownGoodEvidenceSha256: sha256(material.knownGoodEvidence),
    depositReceiptSha256: receipt.sha256,
    depositId: receipt.receipt.depositId,
    signatureKeyIds: bundle.signatureKeyIds,
    signatureSha256: bundle.signatureSha256
  });
}

function sanitizedRollbackChain(authorization) {
  return Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_rollback_authorization_chain',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    authorizationVerifiedAt: authorization.authorizationVerifiedAt,
    targetControllerRepository: authorization.target.controllerRepository,
    targetControllerRef: authorization.target.controllerRef,
    targetControllerWorkflowPath: authorization.target.controllerWorkflowPath,
    targetControllerRunId: authorization.target.controllerRunId,
    targetControllerRunAttempt: authorization.target.controllerRunAttempt,
    targetControllerCommit: authorization.target.controllerCommit,
    dispatchNonce: authorization.target.dispatchNonce,
    targetNetlifySiteId: authorization.target.netlifySiteId,
    sourceCommit: authorization.sourceCommit,
    previousDeployId: authorization.previousDeployId,
    rollbackNetlifyPrincipalSubject: authorization.rollbackPrincipalSubject,
    authorizationPacketSha256: authorization.authorizationPacketSha256,
    authorizationBundleSha256: authorization.authorizationBundleSha256,
    approverRegistrySha256: authorization.approverRegistrySha256,
    knownGoodEvidenceSha256: authorization.knownGoodEvidenceSha256,
    depositReceiptSha256: authorization.depositReceiptSha256,
    depositId: authorization.depositId,
    authorizationKeyIds: authorization.signatureKeyIds,
    authorizationSignatureSha256: authorization.signatureSha256,
    artifactProvenanceAuthenticated: true,
    authorizationSignaturesVerified: true,
    protectedApproverRegistryVerified: true,
    knownGoodEvidenceVerified: true,
    authorizationExpiryIgnoredForRecoveryOnly: true
  });
}

function validateDraftInventory(result, target, sourceCommit) {
  const code = 'CNYOS_RECONCILIATION_DRAFT_INVENTORY_INVALID';
  assertExactKeys(result, ['target', 'inventoryComplete', 'intents'], code);
  assertTarget(result.target, target, code, { requireGeneration: false });
  if (target.barrierGeneration === null && result.target.barrierGeneration !== null) fail(code);
  if (result.inventoryComplete !== true || !Array.isArray(result.intents) ||
    result.intents.length > 1000) fail(code);
  const ids = new Set();
  return Object.freeze(result.intents.map(intent => {
    assertExactKeys(intent, INTENT_KEYS, code);
    const intentId = exactIdentifier(intent.intentId, INTENT_ID, code);
    if (ids.has(intentId) || !INTENT_STATUSES.has(intent.status)) fail(code);
    ids.add(intentId);
    const deployId = intent.deployId === null ? null : exactDeployId(intent.deployId, code);
    const marker = required(intent.ownershipMarker, code, 500);
    const expectedMarker = deploymentMarker(
      target.controllerRunId, target.dispatchNonce, exactSha40(sourceCommit, code)
    );
    if (marker !== expectedMarker) fail(code);
    return Object.freeze({ intentId, deployId, status: intent.status, ownershipMarker: marker });
  }));
}

function assertResumerAuthorization(value, target, resumer, code) {
  assertExactKeys(value, RESUMER_AUTHORIZATION_KEYS, code);
  if (value.targetControllerRepository !== target.controllerRepository ||
    value.targetControllerRef !== target.controllerRef ||
    value.targetControllerWorkflowPath !== target.controllerWorkflowPath ||
    value.targetControllerRunId !== target.controllerRunId ||
    value.targetControllerRunAttempt !== target.controllerRunAttempt ||
    value.targetControllerCommit !== target.controllerCommit ||
    value.targetDispatchNonce !== target.dispatchNonce ||
    value.targetNetlifySiteId !== target.netlifySiteId ||
    value.allowedResumerRepository !== POLICY.controller.repository ||
    value.allowedResumerProtectedRef !== POLICY.controller.protectedRef ||
    JSON.stringify(value.allowedResumerWorkflowPaths) !== JSON.stringify([
      POLICY.controller.releaseWorkflowPath, POLICY.controller.rollbackWorkflowPath
    ])) fail(code);
  assertResumer(value.actualResumer, resumer, code);
}

export function recoveryClaimKeySha256(target, trust = brokerTrustRoot('reconciliation')) {
  assertTarget(target, target, 'CNYOS_RECONCILIATION_CLAIM_KEY_INVALID');
  return sha256(JSON.stringify({
    schemaVersion: 1,
    operationDomain: trust.operationDomain,
    policyId: trust.policyId,
    policySha256: trust.policySha256,
    target
  }));
}

function validateIntent(value, target, sourceCommit, code) {
  assertExactKeys(value, INTENT_KEYS, code);
  exactIdentifier(value.intentId, INTENT_ID, code);
  if (value.deployId !== null) exactDeployId(value.deployId, code);
  if (!INTENT_STATUSES.has(value.status)) fail(code);
  if (value.ownershipMarker !== deploymentMarker(
    target.controllerRunId, target.dispatchNonce, exactSha40(sourceCommit, code)
  )) fail(code);
}

function validateActions(actions, core, authorization, code) {
  if (!Array.isArray(actions) || actions.length > 1001) fail(code);
  let sawDelete = false;
  let restoreCount = 0;
  const draftById = new Map(core.draftIntents.map(item => [item.intentId, item]));
  const deletedIntentIds = new Set();
  for (const [index, action] of actions.entries()) {
    if (!isPlainObject(action) || action.sequence !== index + 1 ||
      action.siteId !== core.target.netlifySiteId) fail(code);
    if (action.kind === 'restore_previous_deploy') {
      assertExactKeys(action, RESTORE_ACTION_KEYS, code);
      restoreCount += 1;
      if (sawDelete || restoreCount !== 1 || action.fromDeployId !== core.currentDeployId ||
        action.toDeployId !== core.previousDeployId ||
        action.requiredCurrentDeployId !== core.currentDeployId ||
        action.requiredOwnershipMarker !== deploymentMarker(
          core.target.controllerRunId, core.target.dispatchNonce, authorization.sourceCommit
        ) || core.currentDeployId === core.previousDeployId) fail(code);
      exactDeployId(action.fromDeployId, code);
      exactDeployId(action.toDeployId, code);
    } else if (action.kind === 'delete_run_owned_draft') {
      sawDelete = true;
      assertExactKeys(action, DELETE_ACTION_KEYS, code);
      const intent = draftById.get(action.intentId);
      if (!intent || !intent.deployId || intent.deployId !== action.deployId ||
        intent.ownershipMarker !== action.requiredOwnershipMarker ||
        action.requiredOwnershipMarker !== deploymentMarker(
          core.target.controllerRunId, core.target.dispatchNonce, authorization.sourceCommit
        ) ||
        TERMINAL_INTENT_STATUSES.has(intent.status) || action.deployId === core.currentDeployId ||
        action.deployId === core.previousDeployId || deletedIntentIds.has(action.intentId)) fail(code);
      deletedIntentIds.add(action.intentId);
      exactDeployId(action.deployId, code);
    } else fail(code);
  }
  if (core.currentDeployId !== core.previousDeployId && restoreCount !== 1) fail(code);
  if (core.currentDeployId === core.previousDeployId && restoreCount !== 0) fail(code);
  for (const intent of core.draftIntents) {
    if (!TERMINAL_INTENT_STATUSES.has(intent.status) && intent.deployId !== null &&
      intent.deployId !== core.currentDeployId) {
      if (intent.deployId === core.previousDeployId || !deletedIntentIds.has(intent.intentId)) {
        fail(code);
      }
    }
  }
}

export function validateTerminalEnvelope(value, {
  trust,
  expectedTarget,
  expectedType,
  observedAt,
  expectedExecutionReceiptSha256 = null,
  expectedFinalSha256 = null,
  expectedPublisherReleaseSha256 = null
}) {
  const code = 'CNYOS_RECONCILIATION_TERMINAL_RECORD_INVALID';
  assertExactKeys(value, TERMINAL_ENVELOPE_KEYS, code);
  if (value.schemaVersion !== 1 ||
    value.evidenceType !== 'cnyos_staging_reconciliation_terminal_envelope') fail(code);
  const record = value.terminalRecord;
  assertExactKeys(record, TERMINAL_RECORD_KEYS, code);
  assertTarget(record.target, expectedTarget, code);
  if (record.schemaVersion !== 1 ||
    record.evidenceType !== 'cnyos_staging_reconciliation_terminal_record' ||
    record.status !== 'committed' || record.terminalType !== expectedType ||
    !TERMINAL_ID.test(String(record.terminalRecordId || '')) ||
    record.scope !== 'cnyos_staging_only' || record.productionAuthorization !== false ||
    record.realPatientDataAuthorized !== false ||
    record.barrierGeneration !== record.target.barrierGeneration ||
    record.leaseActive !== false || record.runReconciliationBarrierActive !== false ||
    record.automaticRunReconciliationBarrierExpiryPermitted !== false ||
    record.allRunOwnedDraftIntentsTerminal !== true || record.rollbackEligible !== false) fail(code);
  exactDeployId(record.netlifyDeployId, code);
  const committedAt = canonicalIsoTimestamp(record.committedAt, code);
  if (committedAt > observedAt) fail(code);
  if (expectedType === 'committed_success') {
    if (record.claimId !== null || record.planCoreSha256 !== null ||
      record.executionReceiptSha256 !== null || record.recoveryFinalizationGeneration !== null ||
      record.finalEvidenceSha256 !== exactSha256(expectedFinalSha256, code) ||
      record.publisherReleaseEvidenceSha256 !==
        exactSha256(expectedPublisherReleaseSha256, code)) fail(code);
  } else if (expectedType === 'committed_recovery') {
    if (!TERMINAL_ID.test(String(record.claimId || '')) ||
      !SHA256.test(String(record.planCoreSha256 || '')) ||
      record.executionReceiptSha256 !== exactSha256(expectedExecutionReceiptSha256, code) ||
      !GENERATION.test(String(record.recoveryFinalizationGeneration || '')) ||
      record.finalEvidenceSha256 !== null ||
      record.publisherReleaseEvidenceSha256 !== null) fail(code);
  } else fail(code);
  validateSignature(value.brokerSignature, record, trust,
    'CNYOS_RECONCILIATION_TERMINAL_SIGNATURE_INVALID');
  return record;
}

export function validateRecoveryPlanEnvelope(envelope, {
  trust,
  expectedTarget,
  expectedResumer,
  rollbackAuthorization,
  rollbackChainSha256,
  draftIntents,
  observedAt
}) {
  const code = 'CNYOS_RECONCILIATION_PLAN_INVALID';
  const result = envelope.result;
  assertExactKeys(result, PLAN_RESULT_KEYS, code);
  if (!RECOVERY_DISPOSITIONS.includes(result.recoveryDisposition)) fail(code);
  const target = assertTarget(result.target, expectedTarget, code);
  assertResumerAuthorization(result.resumerAuthorization, target, expectedResumer, code);
  if (result.rollbackAuthorizationChainSha256 !== exactSha256(rollbackChainSha256, code)) fail(code);
  if (result.recoveryDisposition === 'recovery_required') {
    assertExactKeys(result.claim, CLAIM_KEYS, code);
    const claim = result.claim;
    if (!TERMINAL_ID.test(String(claim.claimId || '')) ||
      claim.claimKeySha256 !== recoveryClaimKeySha256(target, trust) ||
      claim.barrierGeneration !== target.barrierGeneration ||
      claim.planCoreSha256 !== result.planCoreSha256 ||
      claim.persistedAtomicallyWithPlanCore !== true || claim.immutable !== true ||
      claim.exactRetryIdempotent !== true || claim.authorizedResumptionEnforced !== true ||
      claim.authorizationRefreshPreservesPlanCore !== true ||
      claim.automaticExpiryPermitted !== false ||
      claim.incompleteRecordPreservesClaim !== true) fail(code);
    if (canonicalIsoTimestamp(claim.createdAt, code) > observedAt) fail(code);
    assertExactKeys(result.planCore, PLAN_CORE_KEYS, code);
    const core = result.planCore;
    assertTarget(core.target, target, code);
    if (core.previousDeployId !== rollbackAuthorization.previousDeployId ||
      core.knownGoodEvidenceSha256 !== rollbackAuthorization.knownGoodEvidenceSha256 ||
      core.rollbackAuthorizationChainSha256 !== rollbackChainSha256 ||
      !Array.isArray(core.draftIntents) || core.draftIntents.length !== draftIntents.length ||
      !isDeepStrictEqual(core.draftIntents, draftIntents) ||
      result.planCoreSha256 !== sha256(JSON.stringify(core)) ||
      result.terminalRecord !== null) fail(code);
    exactDeployId(core.previousDeployId, code);
    exactDeployId(core.currentDeployId, code);
    for (const intent of core.draftIntents) {
      validateIntent(intent, target, rollbackAuthorization.sourceCommit, code);
    }
    validateActions(core.orderedActions, core, rollbackAuthorization, code);
  } else {
    if (result.claim !== null || result.planCore !== null || result.planCoreSha256 !== null ||
      !isPlainObject(result.terminalRecord)) fail(code);
    validateTerminalEnvelope(result.terminalRecord, {
      trust, expectedTarget: target,
      expectedType: result.recoveryDisposition === 'terminal_success_rehydrated'
        ? 'committed_success' : 'committed_recovery',
      observedAt,
      expectedExecutionReceiptSha256:
        result.terminalRecord.terminalRecord?.executionReceiptSha256,
      expectedFinalSha256: result.terminalRecord.terminalRecord?.finalEvidenceSha256,
      expectedPublisherReleaseSha256:
        result.terminalRecord.terminalRecord?.publisherReleaseEvidenceSha256
    });
  }
  return Object.freeze({ result, target });
}

async function localRecoveryInputs(env, { requireRecoveryArtifacts }) {
  const registryBytes = await readFileBounded(required(
    env.CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH,
    'CNYOS_RECONCILIATION_APPROVER_REGISTRY_PATH_REQUIRED', 4096
  ), 1024 * 1024, 'CNYOS_RECONCILIATION_APPROVER_REGISTRY_INVALID');
  const approverRegistry = Object.freeze({
    bytes: registryBytes,
    sha256: sha256(registryBytes)
  });
  if (!env.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH && !requireRecoveryArtifacts) {
    return Object.freeze({ approverRegistry });
  }
  const [authorizationBundle, depositReceiptEnvelope] = await Promise.all([
    loadHashedJson(env.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH,
      env.CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256,
      'CNYOS_RECONCILIATION_AUTHORIZATION_BUNDLE_INVALID'),
    loadHashedJson(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH,
      env.CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256,
      'CNYOS_RECONCILIATION_DEPOSIT_RECEIPT_INVALID', { canonical: true })
  ]);
  return Object.freeze({
    authorizationBundle,
    depositReceiptEnvelope,
    approverRegistry
  });
}

async function optionalProducerArtifacts(env) {
  const directory = path.resolve(required(env.CNYOS_CONTROLLER_RECOVERY_INPUT_DIRECTORY,
    'CNYOS_RECONCILIATION_RECOVERY_INPUT_DIRECTORY_REQUIRED', 4096));
  const specifications = [
    ['draftIntent', 'CNYOS_DRAFT_INTENT_JOB_RESULT',
      'CNYOS_DRAFT_INTENT_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256', 'draft-intent.json'],
    ['draftReceipt', 'CNYOS_DRAFT_DEPLOY_JOB_RESULT',
      'CNYOS_DRAFT_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256', 'draft-receipt.json'],
    ['exclusivePublisher', 'CNYOS_ACQUIRE_PUBLISHER_JOB_RESULT',
      'CNYOS_ATTEMPT_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_EXCLUSIVE_PUBLISHER_EVIDENCE_SHA256', 'exclusive-publisher.json'],
    ['publishAttempt', 'CNYOS_ACQUIRE_PUBLISHER_JOB_RESULT',
      'CNYOS_ATTEMPT_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_PUBLISH_ATTEMPT_EVIDENCE_SHA256', 'promotion-attempt.json'],
    ['promotion', 'CNYOS_PROMOTION_JOB_RESULT',
      'CNYOS_PROMOTION_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256', 'promotion.json'],
    ['final', 'CNYOS_RELEASE_FINALIZE_JOB_RESULT',
      'CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_FINAL_EVIDENCE_SHA256', 'final.json'],
    ['publisherRelease', 'CNYOS_RELEASE_FINALIZE_JOB_RESULT',
      'CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME',
      'CNYOS_EXPECTED_PUBLISHER_RELEASE_EVIDENCE_SHA256', 'publisher-release.json']
  ];
  const ledger = {};
  for (const [name, resultName, outcomeName, digestName, filename] of specifications) {
    const jobResult = required(env[resultName], `CNYOS_RECONCILIATION_${resultName}_INVALID`, 20);
    if (!JOB_RESULTS.has(jobResult)) fail(`CNYOS_RECONCILIATION_${resultName}_INVALID`);
    const downloadOutcome = String(env[outcomeName] || 'skipped');
    if (!JOB_RESULTS.has(downloadOutcome)) fail(`CNYOS_RECONCILIATION_${outcomeName}_INVALID`);
    let artifact = null;
    if (jobResult === 'success' && downloadOutcome === 'success') {
      artifact = await loadHashedJson(path.join(directory, filename), env[digestName],
        `CNYOS_RECONCILIATION_${name.toUpperCase()}_INVALID`);
    }
    ledger[name] = Object.freeze({
      producerJobResult: jobResult,
      artifactDownloadOutcome: downloadOutcome,
      sha256: artifact?.sha256 || null
    });
  }
  for (const name of [
    'CNYOS_ROUTE_VALIDATION_JOB_RESULT', 'CNYOS_UAT_JOB_RESULT',
    'CNYOS_FINAL_CURRENT_JOB_RESULT', 'CNYOS_SUCCESSFUL_RELEASE_COMMIT_JOB_RESULT'
  ]) {
    const value = required(env[name], `CNYOS_RECONCILIATION_${name}_INVALID`, 20);
    if (!JOB_RESULTS.has(value)) fail(`CNYOS_RECONCILIATION_${name}_INVALID`);
    ledger[name] = value;
  }
  return Object.freeze(ledger);
}

async function retrieveRecoveryMaterial({ env, fetchImpl, oidcTokenProvider, resumer, target, now }) {
  const trust = brokerTrustRoot('rollback');
  const local = await localRecoveryInputs(env, {
    requireRecoveryArtifacts:
      resumer.controllerWorkflowPath === POLICY.controller.releaseWorkflowPath
  });
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_ROLLBACK_ATTESTATION_BROKER_URL,
    operation: 'retrieve_recovery_material', resumer, target,
    evidence: Object.freeze({
      localAuthorizationBundleSha256: local.authorizationBundle?.sha256 || null,
      localDepositReceiptSha256: local.depositReceiptEnvelope?.sha256 || null,
      localApproverRegistrySha256: local.approverRegistry.sha256
    }), now
  });
  return verifyRecoveryAuthorizationMaterial(
    response.result, trust, target, local, response.observedAt
  );
}

async function retrieveDraftInventory({
  env, fetchImpl, oidcTokenProvider, resumer, target, sourceCommit, now
}) {
  const trust = brokerTrustRoot('draft');
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_DRAFT_LIFECYCLE_BROKER_URL,
    operation: 'inventory_run_draft_intents', resumer, target,
    evidence: Object.freeze({
      sourceCommit: exactSha40(sourceCommit, 'CNYOS_RECONCILIATION_DRAFT_INVENTORY_INVALID'),
      exactRunAndNonceRequired: true,
      inventoryCompleteRequired: true
    }),
    now
  });
  return validateDraftInventory(response.result, target, sourceCommit);
}

export async function assertClean({
  env = process.env, fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider, now = () => new Date()
} = {}) {
  assertAbsentEnvironmentNames(env, OIDC_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_OIDC_CREDENTIAL_ISOLATION_INVALID');
  const runtime = controllerRuntime(env);
  if (runtime.controllerWorkflowPath !== POLICY.controller.releaseWorkflowPath ||
    runtime.controllerRunAttempt !== 1) fail('CNYOS_RECONCILIATION_RELEASE_RUNTIME_REQUIRED');
  const target = targetFromEnvironment(env, runtime);
  const trust = brokerTrustRoot('reconciliation');
  const observedAt = nowDate(now);
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL,
    operation: 'assert_clean', resumer: runtime, target,
    evidence: Object.freeze({
      requireCompleteInventory: true,
      requireAllPriorRunsTerminal: true,
      blockWhileAnyBarrierActive: true
    }), now
  });
  const code = 'CNYOS_RECONCILIATION_CLEAN_RESULT_INVALID';
  assertExactKeys(response.result, [
    'status', 'target', 'brokerInventoryComplete', 'allPriorRunsTerminal',
    'activeRunReconciliationBarrierCount',
    'newMutationBlockedWhileAnyRunReconciliationBarrierActive',
    'automaticRunReconciliationBarrierExpiryPermitted'
  ], code);
  assertTarget(response.result.target, target, code, { requireGeneration: false });
  if (response.result.target.barrierGeneration !== null) fail(code);
  if (response.result.status !== 'clean' || response.result.brokerInventoryComplete !== true ||
    response.result.allPriorRunsTerminal !== true ||
    response.result.activeRunReconciliationBarrierCount !== 0 ||
    response.result.newMutationBlockedWhileAnyRunReconciliationBarrierActive !== true ||
    response.result.automaticRunReconciliationBarrierExpiryPermitted !== false) fail(code);
  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_pre_release_reconciliation',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    checkedAt: observedAt.toISOString(),
    controllerRepository: runtime.controllerRepository,
    controllerRef: runtime.controllerRef,
    controllerCommit: runtime.controllerCommit,
    controllerRunId: runtime.controllerRunId,
    controllerRunAttempt: runtime.controllerRunAttempt,
    policySha256: POLICY_SHA256,
    target: POLICY.target,
    brokerPolicyId: trust.policyId,
    brokerPolicySha256: trust.policySha256,
    brokerInventoryComplete: true,
    allPriorRunsTerminal: true,
    activeRunReconciliationBarrierCount: 0,
    newMutationBlockedWhileAnyRunReconciliationBarrierActive: true,
    automaticRunReconciliationBarrierExpiryPermitted: false
  });
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH,
      'CNYOS_RECONCILIATION_EVIDENCE_PATH_REQUIRED', 4096), evidence
  );
  return Object.freeze({ evidence, evidencePath });
}

function validateSuccessfulReleaseArtifacts(final, release, target, observedAt) {
  const code = 'CNYOS_RECONCILIATION_SUCCESS_EVIDENCE_INVALID';
  const f = final.value;
  const r = release.value;
  assertExactKeys(f, FINAL_RELEASE_EVIDENCE_KEYS, code);
  assertExactKeys(r, EXCLUSIVE_PUBLISHER_RELEASE_EVIDENCE_KEYS, code);
  assertExactKeys(r.source, ['repository', 'commit', 'tree'], code);
  const deployId = exactDeployId(f.netlifyDeployId, code);
  validateRecoveredKnownGood(f, final.bytes, target, deployId, code);
  const finalizedAt = canonicalIsoTimestamp(f.finalizedAt, code);
  const releasedAt = canonicalIsoTimestamp(r.releasedAt, code);
  const previousDeployId = exactDeployId(f.previousDeployId, code);
  const originalLeaseSha256 = exactSha256(
    r.originalExclusivePublisherEvidenceSha256, code
  );
  if (finalizedAt > observedAt || releasedAt > finalizedAt ||
    previousDeployId === deployId ||
    f.controllerRepository !== target.controllerRepository || f.controllerRef !== target.controllerRef ||
    f.controllerRunId !== target.controllerRunId || f.controllerRunAttempt !== 1 ||
    f.controllerCommit !== target.controllerCommit || f.dispatchNonce !== target.dispatchNonce ||
    f.authenticatedUatPassed !== true ||
    f.retainedEvidenceSha256.exclusivePublisherRelease !== release.sha256 ||
    f.retainedEvidenceSha256.exclusivePublisherLease !== originalLeaseSha256 ||
    r.schemaVersion !== 1 ||
    r.evidenceType !== 'cnyos_staging_controller_exclusive_publisher_release' ||
    r.status !== 'passed' || r.scope !== 'cnyos_staging_only' ||
    r.productionAuthorization !== false || r.controllerRepository !== target.controllerRepository ||
    r.controllerRef !== target.controllerRef || r.controllerRunId !== target.controllerRunId ||
    r.controllerCommit !== target.controllerCommit ||
    r.source.repository !== f.source.repository || r.source.commit !== f.source.commit ||
    r.source.tree !== f.source.tree || r.netlifyDeployId !== deployId ||
    r.releaseAction !== 'released' || r.leaseActiveAfterRelease !== false ||
    r.runReconciliationBarrierActiveAfterRelease !== true ||
    r.automaticRunReconciliationBarrierExpiryPermitted !== false ||
    r.draftIntentTerminalBeforeRunReconciliationBarrierClearRequired !== true ||
    r.currentPublishedDeployIdBeforeRelease !== deployId ||
    r.currentPublishedDeployIdAfterRelease !== deployId ||
    r.brokerPolicyId !== POLICY.externalReconciliationBroker.policyId ||
    r.brokerPolicySha256 !== POLICY.externalReconciliationBroker.policySha256 ||
    r.runReconciliationBarrierGeneration !== r.lockLeaseId) fail(code);
  exactSha40(r.source.commit, code);
  exactSha40(r.source.tree, code);
  const generation = exactIdentifier(r.lockLeaseId, GENERATION, code);
  return Object.freeze({
    deployId,
    previousDeployId,
    generation,
    source: f.source,
    artifact: f.artifact,
    evidenceSetSha256: f.evidenceSetSha256,
    retainedEvidenceSha256: f.retainedEvidenceSha256,
    authenticatedUatPassed: true,
    originalExclusivePublisherEvidenceSha256: originalLeaseSha256,
    finalizedAt: finalizedAt.toISOString(),
    releasedAt: releasedAt.toISOString()
  });
}

function validateSuccessfulReleaseIndependentBindings({
  final, target, runtime, producer, authorization, authorizationBundle, env
}) {
  const code = 'CNYOS_RECONCILIATION_SUCCESS_INDEPENDENT_BINDING_INVALID';
  if (!isPlainObject(producer) || !isPlainObject(producer.manifest)) fail(code);
  const manifest = producer.manifest;
  const manifestSha256 = exactSha256(producer.manifestSha256, code);
  const expectedManifestSha256 = exactSha256(
    required(env.CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256, code, 64), code
  );
  const expectedArtifactSha256 = exactSha256(
    required(env.CNYOS_EXPECTED_PRODUCER_ARTIFACT_SHA256, code, 64), code
  );
  const expectedFileCount = positiveInteger(
    env.CNYOS_EXPECTED_PRODUCER_FILE_COUNT, code
  ).number;
  const expectedCandidateCommit = exactSha40(
    required(env.CNYOS_CANDIDATE_SHA, code, 40), code
  );
  const expectedCandidateTree = exactSha40(
    required(env.CNYOS_EXPECTED_PRODUCER_CANDIDATE_TREE, code, 40), code
  );
  const expectedFunctionSourceTree = exactSha40(
    required(env.CNYOS_EXPECTED_PRODUCER_FUNCTION_SOURCE_TREE, code, 40), code
  );
  const expectedGitHubArtifactDigest = exactSha256(
    required(env.CNYOS_EXPECTED_GITHUB_ARTIFACT_DIGEST, code, 64), code
  );
  if (manifestSha256 !== expectedManifestSha256 ||
    manifest.artifactSha256 !== expectedArtifactSha256 ||
    manifest.fileCount !== expectedFileCount ||
    manifest.candidateCommit !== expectedCandidateCommit ||
    manifest.candidateTree !== expectedCandidateTree ||
    manifest.functionSourceTree !== expectedFunctionSourceTree) fail(code);

  const a = authorization.value;
  const b = authorizationBundle.value;
  assertExactKeys(a, SUCCESS_AUTHORIZATION_VALIDATION_KEYS, code);
  assertExactKeys(a.source, AUTHORIZATION_SOURCE_KEYS, code);
  assertExactKeys(a.artifact, AUTHORIZATION_ARTIFACT_KEYS, code);
  assertExactKeys(a.signatureKeyIds, AUTHORIZATION_SIGNER_KEYS, code);
  assertExactKeys(a.signatureSha256, AUTHORIZATION_SIGNER_KEYS, code);
  assertExactKeys(b, SUCCESS_AUTHORIZATION_BUNDLE_KEYS, code);
  assertExactKeys(b.authorizationDecision, SUCCESS_AUTHORIZATION_DECISION_KEYS, code);
  assertExactKeys(b.signatureKeyIds, AUTHORIZATION_SIGNER_KEYS, code);
  assertExactKeys(b.signatureSha256, AUTHORIZATION_SIGNER_KEYS, code);

  const expectedSource = Object.freeze({
    repository: POLICY.sourceRepository,
    commit: manifest.candidateCommit,
    tree: manifest.candidateTree,
    functionSourceTree: manifest.functionSourceTree
  });
  const expectedArtifact = Object.freeze({
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
    producerRunId: runtime.controllerRunId,
    githubArtifactDigest: expectedGitHubArtifactDigest
  });
  const decision = b.authorizationDecision;
  if (a.schemaVersion !== 1 ||
    a.evidenceType !== 'cnyos_staging_controller_authorization_validation' ||
    a.status !== 'authorized' || a.scope !== 'cnyos_staging_only' ||
    a.productionAuthorization !== false || a.realPatientDataAuthorized !== false ||
    a.controllerRepository !== target.controllerRepository ||
    a.controllerRef !== target.controllerRef ||
    a.controllerCommit !== target.controllerCommit ||
    a.controllerWorkflowPath !== target.controllerWorkflowPath ||
    a.controllerRunId !== target.controllerRunId ||
    a.controllerRunAttempt !== target.controllerRunAttempt ||
    a.dispatchNonce !== target.dispatchNonce || a.policySha256 !== POLICY_SHA256 ||
    a.previousDeployId !== final.value.previousDeployId ||
    !isDeepStrictEqual(a.target, POLICY.target) ||
    !isDeepStrictEqual(a.source, expectedSource) ||
    !isDeepStrictEqual(a.artifact, expectedArtifact) ||
    b.schemaVersion !== 2 ||
    b.evidenceType !== 'cnyos_staging_controller_authorization_verification_bundle' ||
    b.scope !== 'cnyos_staging_only' || b.productionAuthorization !== false ||
    b.secretValuesSerialized !== false ||
    !isDeepStrictEqual(b.validationEvidence, a) ||
    b.authorizationPacketSha256 !== a.authorizationPacketSha256 ||
    b.approverRegistrySha256 !== a.approverRegistrySha256 ||
    b.knownGoodEvidenceSha256 !== a.knownGoodRollbackEvidenceSha256 ||
    !isDeepStrictEqual(b.signatureKeyIds, a.signatureKeyIds) ||
    !isDeepStrictEqual(b.signatureSha256, a.signatureSha256) ||
    decision.decision !== 'authorize_exact_cnyos_staging_controller_run' ||
    decision.controllerRunId !== target.controllerRunId ||
    decision.dispatchNonce !== target.dispatchNonce ||
    decision.candidateCommit !== expectedSource.commit ||
    decision.candidateTree !== expectedSource.tree ||
    decision.artifactSha256 !== expectedArtifact.artifactSha256 ||
    !isDeepStrictEqual(final.value.source, expectedSource) ||
    !isDeepStrictEqual(final.value.artifact, {
      sha256: expectedArtifact.artifactSha256,
      fileCount: expectedArtifact.fileCount
    }) ||
    final.value.retainedEvidenceSha256.producerManifest !== manifestSha256 ||
    final.value.retainedEvidenceSha256.authorization !== authorization.sha256 ||
    final.value.retainedEvidenceSha256.authorizationVerificationBundle !==
      authorizationBundle.sha256) fail(code);
}

export async function commitSuccessfulRelease({
  env = process.env, fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider, now = () => new Date(),
  producerBundleVerifier = verifyProducerBundle
} = {}) {
  assertAbsentEnvironmentNames(env, OIDC_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_OIDC_CREDENTIAL_ISOLATION_INVALID');
  if (env.CNYOS_RELEASE_FINALIZE_JOB_RESULT !== 'success' ||
    env.CNYOS_PRODUCER_JOB_RESULT !== 'success' ||
    env.CNYOS_AUTHORIZATION_JOB_RESULT !== 'success' ||
    env.CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME !== 'success' ||
    env.CNYOS_PRODUCER_ARTIFACT_DOWNLOAD_OUTCOME !== 'success' ||
    env.CNYOS_AUTHORIZATION_ARTIFACT_DOWNLOAD_OUTCOME !== 'success') {
    fail('CNYOS_RECONCILIATION_SUCCESS_PRODUCER_NOT_SUCCESSFUL');
  }
  const runtime = controllerRuntime(env);
  if (runtime.controllerWorkflowPath !== POLICY.controller.releaseWorkflowPath ||
    runtime.controllerRunAttempt !== 1) fail('CNYOS_RECONCILIATION_RELEASE_RUNTIME_REQUIRED');
  const [final, release, producer, authorization, authorizationBundle] = await Promise.all([
    loadHashedJson(env.CNYOS_CONTROLLER_FINAL_EVIDENCE_PATH,
      env.CNYOS_EXPECTED_FINAL_EVIDENCE_SHA256,
      'CNYOS_RECONCILIATION_FINAL_EVIDENCE_INVALID'),
    loadHashedJson(env.CNYOS_CONTROLLER_PUBLISHER_RELEASE_EVIDENCE_PATH,
      env.CNYOS_EXPECTED_PUBLISHER_RELEASE_EVIDENCE_SHA256,
      'CNYOS_RECONCILIATION_PUBLISHER_RELEASE_EVIDENCE_INVALID'),
    producerBundleVerifier({ env }),
    loadHashedJson(env.CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH,
      env.CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256,
      'CNYOS_RECONCILIATION_AUTHORIZATION_EVIDENCE_INVALID'),
    loadHashedJson(env.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH,
      env.CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256,
      'CNYOS_RECONCILIATION_AUTHORIZATION_BUNDLE_INVALID')
  ]);
  const observedAt = nowDate(now);
  const target = Object.freeze({
    ...targetFromEnvironment(env, runtime),
    barrierGeneration: release.value.runReconciliationBarrierGeneration
  });
  const binding = validateSuccessfulReleaseArtifacts(final, release, target, observedAt);
  validateSuccessfulReleaseIndependentBindings({
    final, target, runtime, producer, authorization, authorizationBundle, env
  });
  const trust = brokerTrustRoot('reconciliation');
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL,
    operation: 'commit_successful_release', resumer: runtime, target,
    evidence: Object.freeze({
      finalEvidenceSha256: final.sha256,
      publisherReleaseEvidenceSha256: release.sha256,
      netlifyDeployId: binding.deployId,
      previousDeployId: binding.previousDeployId,
      source: binding.source,
      artifact: binding.artifact,
      retainedEvidenceSha256: binding.retainedEvidenceSha256,
      evidenceSetSha256: binding.evidenceSetSha256,
      authenticatedUatPassed: binding.authenticatedUatPassed,
      originalExclusivePublisherEvidenceSha256:
        binding.originalExclusivePublisherEvidenceSha256,
      finalEvidenceFinalizedAt: binding.finalizedAt,
      publisherReleasedAt: binding.releasedAt,
      leaseActiveAfterRelease: false,
      runReconciliationBarrierActiveBeforeCommit: true,
      allRunOwnedDraftIntentsTerminalRequired: true
    }), now
  });
  const terminal = response.result.terminalRecord;
  assertExactKeys(response.result, ['status', 'terminalRecord'],
    'CNYOS_RECONCILIATION_SUCCESS_COMMIT_RESULT_INVALID');
  if (!['committed', 'already_committed'].includes(response.result.status)) {
    fail('CNYOS_RECONCILIATION_SUCCESS_COMMIT_RESULT_INVALID');
  }
  const record = validateTerminalEnvelope(terminal, {
    trust, expectedTarget: target, expectedType: 'committed_success',
    observedAt: response.observedAt,
    expectedFinalSha256: final.sha256,
    expectedPublisherReleaseSha256: release.sha256
  });
  if (record.netlifyDeployId !== binding.deployId) {
    fail('CNYOS_RECONCILIATION_SUCCESS_COMMIT_RESULT_INVALID');
  }
  const terminalPath = await writeBytesExclusive(
    env.CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH,
    Buffer.from(JSON.stringify(terminal))
  );
  return Object.freeze({ terminalRecord: record, terminalPath });
}

export async function prepareRecovery({
  env = process.env, fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider, now = () => new Date(), watchdog = false
} = {}) {
  assertAbsentEnvironmentNames(env, OIDC_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_OIDC_CREDENTIAL_ISOLATION_INVALID');
  await assertWatchdogPolicyFile(env);
  const runtime = controllerRuntime(env);
  assertRuntimeMode(runtime, env, watchdog);
  let target = targetFromEnvironment(env, runtime, { allowUnknownNonce: watchdog });
  let producerLedger = null;
  let preflightPreviousDeployId = null;
  if (!watchdog) {
    const preflight = await loadHashedJson(env.CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH,
      env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256,
      'CNYOS_RECONCILIATION_PREFLIGHT_EVIDENCE_INVALID');
    if (preflight.value.evidenceType !== 'cnyos_staging_controller_preflight' ||
      preflight.value.controllerRepository !== target.controllerRepository ||
      preflight.value.controllerRef !== target.controllerRef ||
      preflight.value.controllerRunId !== target.controllerRunId ||
      preflight.value.controllerCommit !== target.controllerCommit ||
      preflight.value.target?.netlifySiteId !== target.netlifySiteId) {
      fail('CNYOS_RECONCILIATION_PREFLIGHT_EVIDENCE_INVALID');
    }
    preflightPreviousDeployId = exactDeployId(
      preflight.value.previousPublishedDeploy?.id,
      'CNYOS_RECONCILIATION_PREFLIGHT_EVIDENCE_INVALID'
    );
    if (decodeNonce(preflight.value.dispatchNonce).value !== target.dispatchNonce) {
      fail('CNYOS_RECONCILIATION_PREFLIGHT_NONCE_MISMATCH');
    }
    producerLedger = await optionalProducerArtifacts(env);
  }
  const authorization = await retrieveRecoveryMaterial({
    env, fetchImpl, oidcTokenProvider, resumer: runtime, target, now
  });
  if (preflightPreviousDeployId !== null &&
    authorization.previousDeployId !== preflightPreviousDeployId) {
    fail('CNYOS_RECONCILIATION_PREFLIGHT_PREVIOUS_DEPLOY_MISMATCH');
  }
  target = authorization.target;
  const chainCore = sanitizedRollbackChain(authorization);
  const chainCoreBytes = Buffer.from(`${JSON.stringify(chainCore, null, 2)}\n`);
  const chainCoreSha256 = sha256(chainCoreBytes);
  const draftIntents = await retrieveDraftInventory({
    env, fetchImpl, oidcTokenProvider, resumer: runtime, target,
    sourceCommit: authorization.sourceCommit, now
  });
  const trust = brokerTrustRoot('reconciliation');
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL,
    operation: 'prepare_recovery', resumer: runtime, target,
    evidence: Object.freeze({
      rollbackAuthorizationChainSha256: chainCoreSha256,
      rollbackAuthorization: Object.freeze({
        previousDeployId: authorization.previousDeployId,
        knownGoodEvidenceSha256: authorization.knownGoodEvidenceSha256,
        depositReceiptSha256: authorization.depositReceiptSha256,
        authorizationPacketSha256: authorization.authorizationPacketSha256
      }),
      draftIntents,
      producerLedger,
      recoveryClaimAndPlanCoreAtomicRequired: true,
      exactClaimResumptionRequired: true
    }), now
  });
  const validated = validateRecoveryPlanEnvelope(response, {
    trust, expectedTarget: target, expectedResumer: runtime,
    rollbackAuthorization: authorization, rollbackChainSha256: chainCoreSha256,
    draftIntents, observedAt: response.observedAt
  });
  const chain = Object.freeze({
    ...chainCore,
    prepareRequestSha256: response.requestSha256
  });
  const chainBytes = Buffer.from(`${JSON.stringify(chain, null, 2)}\n`);
  const planPath = await writeBytesExclusive(
    watchdog ? env.CNYOS_CONTROLLER_RECOVERY_PLAN_PATH :
      env.CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH,
    Buffer.from(response.raw)
  );
  const chainPath = await writeBytesExclusive(
    env.CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH, chainBytes
  );
  const dispositionPath = await writeBytesExclusive(
    env.CNYOS_CONTROLLER_RECOVERY_DISPOSITION_PATH,
    Buffer.from(validated.result.recoveryDisposition)
  );
  let terminalPath = null;
  if (validated.result.recoveryDisposition === 'terminal_success_rehydrated') {
    terminalPath = await writeBytesExclusive(
      env.CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH,
      Buffer.from(JSON.stringify(validated.result.terminalRecord))
    );
  } else if (validated.result.recoveryDisposition === 'terminal_recovery_rehydrated') {
    terminalPath = await writeBytesExclusive(
      env.CNYOS_CONTROLLER_RECOVERY_TERMINAL_EVIDENCE_PATH,
      Buffer.from(JSON.stringify(validated.result.terminalRecord))
    );
  }
  return Object.freeze({
    recoveryDisposition: validated.result.recoveryDisposition,
    planPath, chainPath, dispositionPath, terminalPath,
    claimId: validated.result.claim?.claimId || null,
    planCoreSha256: validated.result.planCoreSha256
  });
}

function loadPlanInputs(env, watchdog) {
  const planPath = watchdog ? env.CNYOS_CONTROLLER_RECOVERY_PLAN_PATH :
    env.CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH;
  const planDigest = watchdog ? env.CNYOS_EXPECTED_RECOVERY_PLAN_SHA256 :
    env.CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256;
  return Promise.all([
    loadHashedJson(planPath, planDigest, 'CNYOS_RECONCILIATION_PLAN_INVALID', { canonical: true }),
    loadHashedJson(env.CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH,
      env.CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256,
      'CNYOS_RECONCILIATION_ROLLBACK_CHAIN_INVALID')
  ]).then(([plan, chain]) => ({ plan, chain }));
}


function parsePlan(plan, trust, observedAt, prepareRequestSha256) {
  return verifySignedBrokerEnvelope(plan.raw, {
    trust,
    operation: 'prepare_recovery',
    requestSha256: exactSha256(
      prepareRequestSha256, 'CNYOS_RECONCILIATION_PLAN_REQUEST_BINDING_INVALID'
    ),
    observedAt
  });
}

function strictRollbackToken(value) {
  const token = required(value, 'CNYOS_RECONCILIATION_ROLLBACK_TOKEN_REQUIRED', 8192);
  if (token !== value || token.length < 20 || /[\s\0]/.test(token)) {
    fail('CNYOS_RECONCILIATION_ROLLBACK_TOKEN_INVALID');
  }
  return token;
}

async function netlifyResponse(fetchImpl, token, pathname, {
  method = 'GET', allow404 = false, allowArray = false
} = {}) {
  const url = new URL(`${NETLIFY_API_PREFIX}${pathname}`, `${NETLIFY_API_ORIGIN}/`);
  if (url.origin !== NETLIFY_API_ORIGIN || url.username || url.password || url.hash) {
    fail('CNYOS_RECONCILIATION_NETLIFY_TARGET_INVALID');
  }
  let response;
  try {
    response = await fetchImpl(url, {
      method, redirect: 'error', credentials: 'omit',
      referrerPolicy: 'no-referrer', cache: 'no-store',
      signal: AbortSignal.timeout(20_000),
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}` }
    });
  } catch { fail('CNYOS_RECONCILIATION_NETLIFY_REQUEST_FAILED'); }
  if (response?.redirected || (response?.url && response.url !== url.href)) {
    fail('CNYOS_RECONCILIATION_NETLIFY_RESPONSE_INVALID');
  }
  if (allow404 && response.status === 404) return Object.freeze({ status: 404, value: null });
  if (method === 'DELETE' && [200, 204].includes(response?.status)) {
    return Object.freeze({ status: response.status, value: null });
  }
  if (![200, 201].includes(response?.status) ||
    !String(response?.headers?.get?.('content-type') || '').toLowerCase()
      .startsWith('application/json')) fail('CNYOS_RECONCILIATION_NETLIFY_RESPONSE_INVALID');
  const bytes = await boundedResponseBytes(response, 2 * 1024 * 1024,
    'CNYOS_RECONCILIATION_NETLIFY_RESPONSE_INVALID');
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_RECONCILIATION_NETLIFY_RESPONSE_INVALID'); }
  if (allowArray ? !Array.isArray(value) : !isPlainObject(value)) {
    fail('CNYOS_RECONCILIATION_NETLIFY_RESPONSE_INVALID');
  }
  return Object.freeze({
    status: response.status,
    value,
    link: String(response?.headers?.get?.('link') || '')
  });
}

function deployIdentity(value, deployId, siteId, marker, { draft }) {
  const code = 'CNYOS_RECONCILIATION_NETLIFY_DEPLOY_IDENTITY_INVALID';
  if (value?.id !== deployId || value?.site_id !== siteId || value?.title !== marker ||
    value?.state !== 'ready' || value?.draft !== draft ||
    (draft ? value?.published_at !== null :
      typeof value?.published_at !== 'string')) fail(code);
}

async function executeAction(action, context) {
  const { fetchImpl, token, core } = context;
  const sitePath = `/sites/${encodeURIComponent(action.siteId)}`;
  if (action.kind === 'restore_previous_deploy') {
    const before = await netlifyResponse(fetchImpl, token, sitePath);
    const current = before.value?.published_deploy?.id || before.value?.published_deploy_id;
    if (before.value?.id !== action.siteId || !DEPLOY_ID.test(String(current || ''))) {
      fail('CNYOS_RECONCILIATION_NETLIFY_SITE_INVALID');
    }
    if (current === action.toDeployId) {
      return Object.freeze({ sequence: action.sequence, kind: action.kind,
        result: 'already_restored', deployId: action.toDeployId });
    }
    if (current !== action.requiredCurrentDeployId) {
      fail('CNYOS_RECONCILIATION_CURRENT_DEPLOY_CONFLICT');
    }
    const owned = await netlifyResponse(fetchImpl, token,
      `/deploys/${encodeURIComponent(action.fromDeployId)}`);
    deployIdentity(owned.value, action.fromDeployId, action.siteId,
      action.requiredOwnershipMarker, { draft: false });
    await netlifyResponse(fetchImpl, token,
      `/sites/${encodeURIComponent(action.siteId)}/deploys/${encodeURIComponent(action.toDeployId)}/restore`,
      { method: 'POST' });
    const after = await netlifyResponse(fetchImpl, token, sitePath);
    const afterCurrent = after.value?.published_deploy?.id || after.value?.published_deploy_id;
    if (after.value?.id !== action.siteId || afterCurrent !== action.toDeployId) {
      fail('CNYOS_RECONCILIATION_RESTORE_VERIFICATION_FAILED');
    }
    const restored = await netlifyResponse(fetchImpl, token,
      `/deploys/${encodeURIComponent(action.toDeployId)}`);
    if (restored.value?.id !== core.previousDeployId || restored.value?.site_id !== action.siteId ||
      restored.value?.state !== 'ready' || restored.value?.draft !== false ||
      typeof restored.value?.published_at !== 'string') {
      fail('CNYOS_RECONCILIATION_RESTORE_VERIFICATION_FAILED');
    }
    return Object.freeze({ sequence: action.sequence, kind: action.kind,
      result: 'restored_previous_deploy', deployId: action.toDeployId });
  }
  const existing = await netlifyResponse(fetchImpl, token,
    `/deploys/${encodeURIComponent(action.deployId)}`, { allow404: true });
  if (existing.status === 404) return Object.freeze({
    sequence: action.sequence, kind: action.kind, result: 'already_absent', deployId: action.deployId
  });
  deployIdentity(existing.value, action.deployId, action.siteId,
    action.requiredOwnershipMarker, { draft: true });
  await netlifyResponse(fetchImpl, token,
    `/deploys/${encodeURIComponent(action.deployId)}`, { method: 'DELETE' });
  const after = await netlifyResponse(fetchImpl, token,
    `/deploys/${encodeURIComponent(action.deployId)}`, { allow404: true });
  if (after.status !== 404) fail('CNYOS_RECONCILIATION_DRAFT_DELETE_VERIFICATION_FAILED');
  return Object.freeze({ sequence: action.sequence, kind: action.kind,
    result: 'deleted_run_owned_draft', deployId: action.deployId });
}

async function assertRollbackPrincipalBoundary(fetchImpl, token, chain) {
  const code = 'CNYOS_RECONCILIATION_ROLLBACK_PRINCIPAL_BOUNDARY_INVALID';
  const principal = await netlifyResponse(fetchImpl, token, '/user');
  if (String(principal.value?.id || '') !==
    required(chain.value.rollbackNetlifyPrincipalSubject, code, 200)) fail(code);
  const inventory = await netlifyResponse(fetchImpl, token, '/sites?per_page=100&page=1',
    { allowArray: true });
  if (!Array.isArray(inventory.value) || inventory.value.length !== 1 ||
    /rel="?next"?/i.test(inventory.link) ||
    inventory.value[0]?.id !== POLICY.target.netlifySiteId ||
    inventory.value[0]?.name !== POLICY.target.netlifySiteName ||
    (inventory.value[0]?.ssl_url || inventory.value[0]?.url) !== POLICY.target.netlifyOrigin) {
    fail(code);
  }
}

async function currentPublishedDeployId(fetchImpl, token, siteId) {
  const site = await netlifyResponse(
    fetchImpl, token, `/sites/${encodeURIComponent(siteId)}`
  );
  const deployId = site.value?.published_deploy?.id || site.value?.published_deploy_id;
  if (site.value?.id !== siteId || !DEPLOY_ID.test(String(deployId || ''))) {
    fail('CNYOS_RECONCILIATION_NETLIFY_SITE_INVALID');
  }
  return deployId;
}

export async function executeRecoveryPlan({
  env = process.env, fetchImpl = fetch, now = () => new Date(), watchdog = false
} = {}) {
  assertAbsentEnvironmentNames(env, EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_EXECUTION_CREDENTIAL_ISOLATION_INVALID');
  await assertWatchdogPolicyFile(env);
  if (env.CNYOS_REQUIRED_RECOVERY_DISPOSITION !== 'recovery_required') {
    fail('CNYOS_RECONCILIATION_EXECUTION_DISPOSITION_INVALID');
  }
  const runtime = controllerRuntime(env);
  assertRuntimeMode(runtime, env, watchdog);
  const expectedTarget = targetFromEnvironment(env, runtime, { allowUnknownNonce: true });
  const inputs = await loadPlanInputs(env, watchdog);
  const observedAt = nowDate(now);
  const trust = brokerTrustRoot('reconciliation');
  const chainBinding = rollbackChainBinding(inputs.chain);
  const envelope = parsePlan(
    inputs.plan, trust, observedAt, chainBinding.prepareRequestSha256
  );
  const target = assertTarget(envelope.result.target, expectedTarget,
    'CNYOS_RECONCILIATION_PLAN_INVALID');
  const authorization = authorizationFromChain(inputs.chain, target);
  const validated = validateRecoveryPlanEnvelope(envelope, {
    trust, expectedTarget: target,
    expectedResumer: runtime,
    rollbackAuthorization: authorization,
    rollbackChainSha256: authorization.rollbackAuthorizationChainSha256,
    draftIntents: envelope.result.planCore?.draftIntents || [], observedAt
  });
  if (validated.result.recoveryDisposition !== 'recovery_required') {
    fail('CNYOS_RECONCILIATION_EXECUTION_DISPOSITION_INVALID');
  }
  const token = strictRollbackToken(env.CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN);
  await assertRollbackPrincipalBoundary(fetchImpl, token, inputs.chain);
  const core = validated.result.planCore;
  const currentBeforeExecution = await currentPublishedDeployId(
    fetchImpl, token, target.netlifySiteId
  );
  if (currentBeforeExecution !== core.currentDeployId &&
    currentBeforeExecution !== core.previousDeployId) {
    fail('CNYOS_RECONCILIATION_CURRENT_DEPLOY_CONFLICT');
  }
  const actionResults = [];
  for (const action of core.orderedActions) {
    actionResults.push(await executeAction(action, {
      fetchImpl, token, core
    }));
  }
  if (await currentPublishedDeployId(fetchImpl, token, target.netlifySiteId) !==
    core.previousDeployId) {
    fail('CNYOS_RECONCILIATION_RESTORE_VERIFICATION_FAILED');
  }
  const receipt = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_execution_receipt',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    executedAt: observedAt.toISOString(),
    target,
    executor: runtime,
    claimId: validated.result.claim.claimId,
    barrierGeneration: target.barrierGeneration,
    planCoreSha256: validated.result.planCoreSha256,
    reconciliationPlanSha256: inputs.plan.sha256,
    rollbackAuthorizationChainSha256: inputs.chain.sha256,
    orderedActions: validated.result.planCore.orderedActions,
    actionResults: Object.freeze(actionResults),
    brokerStateMutationAttempted: false,
    publisherLeaseReleased: false,
    runReconciliationBarrierReleased: false
  });
  const receiptPath = await writeJsonExclusive(
    env.CNYOS_CONTROLLER_RECONCILIATION_EXECUTION_RECEIPT_PATH ||
      env.CNYOS_CONTROLLER_RECOVERY_EXECUTION_RECEIPT_PATH,
    receipt
  );
  return Object.freeze({ receipt, receiptPath });
}

function validateExecutionReceipt(receipt, expectedDigest, plan, chain, target) {
  const code = 'CNYOS_RECONCILIATION_EXECUTION_RECEIPT_INVALID';
  assertExactKeys(receipt.value, EXECUTION_RECEIPT_KEYS, code);
  const value = receipt.value;
  assertTarget(value.target, target, code);
  if (value.schemaVersion !== 1 ||
    value.evidenceType !== 'cnyos_staging_reconciliation_execution_receipt' ||
    value.status !== 'passed' || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false || value.realPatientDataAuthorized !== false ||
    value.secretValuesSerialized !== false || value.claimId !== plan.result.claim.claimId ||
    value.barrierGeneration !== target.barrierGeneration ||
    value.planCoreSha256 !== plan.result.planCoreSha256 ||
    value.reconciliationPlanSha256 !== plan.sha256 ||
    value.rollbackAuthorizationChainSha256 !== chain.sha256 ||
    !isDeepStrictEqual(value.orderedActions, plan.result.planCore.orderedActions) ||
    !Array.isArray(value.actionResults) ||
    value.actionResults.length !== value.orderedActions.length ||
    value.brokerStateMutationAttempted !== false || value.publisherLeaseReleased !== false ||
    value.runReconciliationBarrierReleased !== false || receipt.sha256 !== expectedDigest) fail(code);
  for (const [index, action] of value.orderedActions.entries()) {
    const result = value.actionResults[index];
    assertExactKeys(result, ACTION_RESULT_KEYS, code);
    if (result.sequence !== action.sequence || result.kind !== action.kind) fail(code);
    if (action.kind === 'restore_previous_deploy') {
      if (!['restored_previous_deploy', 'already_restored'].includes(result.result) ||
        result.deployId !== action.toDeployId) fail(code);
    } else if (action.kind === 'delete_run_owned_draft') {
      if (!['deleted_run_owned_draft', 'already_absent'].includes(result.result) ||
        result.deployId !== action.deployId) fail(code);
    } else fail(code);
  }
  assertResumer(value.executor, plan.result.resumerAuthorization.actualResumer, code);
  canonicalIsoTimestamp(value.executedAt, code);
  return value;
}

async function validatePlanForFinalizer(env, runtime, watchdog, observedAt) {
  const inputs = await loadPlanInputs(env, watchdog);
  const trust = brokerTrustRoot('reconciliation');
  const chainBinding = rollbackChainBinding(inputs.chain);
  const envelope = parsePlan(
    inputs.plan, trust, observedAt, chainBinding.prepareRequestSha256
  );
  const target = assertTarget(envelope.result.target,
    targetFromEnvironment(env, runtime, { allowUnknownNonce: true }),
    'CNYOS_RECONCILIATION_PLAN_INVALID');
  const authorization = authorizationFromChain(inputs.chain, target);
  const validated = validateRecoveryPlanEnvelope(envelope, {
    trust, expectedTarget: target,
    expectedResumer: runtime,
    rollbackAuthorization: authorization,
    rollbackChainSha256: authorization.rollbackAuthorizationChainSha256,
    draftIntents: envelope.result.planCore?.draftIntents || [], observedAt
  });
  return Object.freeze({ ...inputs, ...validated, trust, sha256: inputs.plan.sha256 });
}

function finalizationOutputPath(env) {
  return env.CNYOS_CONTROLLER_RECONCILIATION_FINALIZATION_EVIDENCE_PATH ||
    env.CNYOS_CONTROLLER_RECOVERY_FINALIZATION_EVIDENCE_PATH;
}

async function writeFinalizationEvidence(env, runtime, target, operation, brokerResult,
  observedAt, extra = {}) {
  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_finalization',
    status: brokerResult.status,
    operation,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    recordedAt: observedAt.toISOString(),
    target,
    finalizer: runtime,
    publisherLeaseReleased: brokerResult.publisherLeaseReleased,
    runReconciliationBarrierActive: brokerResult.runReconciliationBarrierActive,
    recoveryClaimPreserved: brokerResult.recoveryClaimPreserved,
    automaticExpiryPermitted: brokerResult.automaticExpiryPermitted,
    ...extra
  });
  return Object.freeze({
    evidence,
    evidencePath: await writeJsonExclusive(required(finalizationOutputPath(env),
      'CNYOS_RECONCILIATION_FINALIZATION_PATH_REQUIRED', 4096), evidence)
  });
}

function planlessIncompleteEnvironment(env, reason) {
  const value = {
    ...env,
    CNYOS_RECOVERY_INCOMPLETE_REASON: reason
  };
  for (const name of [
    'CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH',
    'CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256',
    'CNYOS_CONTROLLER_RECOVERY_PLAN_PATH',
    'CNYOS_EXPECTED_RECOVERY_PLAN_SHA256',
    'CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH',
    'CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256'
  ]) delete value[name];
  return value;
}

function recordPreCommitFinalizerFailure({
  env, fetchImpl, oidcTokenProvider, now, watchdog
}) {
  return recordIncompleteRecovery({
    env: planlessIncompleteEnvironment(env, 'finalizer_precommit_validation_failed'),
    fetchImpl,
    oidcTokenProvider,
    now,
    watchdog
  });
}

export async function finalizeRecoverySuccess({
  env = process.env, fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider, now = () => new Date(), watchdog = false
} = {}) {
  assertAbsentEnvironmentNames(env, OIDC_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_OIDC_CREDENTIAL_ISOLATION_INVALID');
  await assertWatchdogPolicyFile(env);
  const runtime = controllerRuntime(env);
  assertRuntimeMode(runtime, env, watchdog);
  let observedAt;
  let plan;
  let receipt;
  try {
    assertPreparationResultGate(env, watchdog, 'recovery_required');
    observedAt = nowDate(now);
    plan = await validatePlanForFinalizer(env, runtime, watchdog, observedAt);
    if (plan.result.recoveryDisposition !== 'recovery_required') {
      fail('CNYOS_RECONCILIATION_FINALIZATION_DISPOSITION_INVALID');
    }
    const jobResult = watchdog ? env.CNYOS_RECOVERY_EXECUTION_JOB_RESULT :
      env.CNYOS_EXECUTION_JOB_RESULT;
    const downloadOutcome = watchdog ?
      env.CNYOS_RECOVERY_EXECUTION_RECEIPT_DOWNLOAD_OUTCOME :
      env.CNYOS_EXECUTION_DOWNLOAD_OUTCOME;
    if (jobResult !== 'success' || downloadOutcome !== 'success') {
      fail('CNYOS_RECONCILIATION_EXECUTION_NOT_VERIFIED');
    }
    const expectedReceiptSha = exactSha256(
      watchdog ? env.CNYOS_EXPECTED_RECOVERY_EXECUTION_RECEIPT_SHA256 :
        env.CNYOS_EXPECTED_RECONCILIATION_EXECUTION_RECEIPT_SHA256,
      'CNYOS_RECONCILIATION_EXECUTION_RECEIPT_DIGEST_REQUIRED'
    );
    receipt = await loadHashedJson(
      watchdog ? env.CNYOS_CONTROLLER_RECOVERY_EXECUTION_RECEIPT_PATH :
        env.CNYOS_CONTROLLER_RECONCILIATION_EXECUTION_RECEIPT_PATH,
      expectedReceiptSha, 'CNYOS_RECONCILIATION_EXECUTION_RECEIPT_INVALID'
    );
    validateExecutionReceipt(receipt, expectedReceiptSha, plan, plan.chain, plan.target);
  } catch {
    return recordPreCommitFinalizerFailure({
      env, fetchImpl, oidcTokenProvider, now, watchdog
    });
  }
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust: plan.trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL,
    operation: 'finalize_recovery', resumer: runtime, target: plan.target,
    evidence: Object.freeze({
      claimId: plan.result.claim.claimId,
      planCoreSha256: plan.result.planCoreSha256,
      executionReceiptSha256: receipt.sha256,
      closeAllRunOwnedDraftIntentsRequired: true
    }), now
  });
  assertExactKeys(response.result, [
    'status', 'publisherLeaseReleased', 'runReconciliationBarrierActive',
    'recoveryClaimPreserved', 'automaticExpiryPermitted', 'terminalRecord'
  ], 'CNYOS_RECONCILIATION_RECOVERY_FINALIZATION_RESULT_INVALID');
  if (!['committed', 'already_committed'].includes(response.result.status) ||
    response.result.publisherLeaseReleased !== true ||
    response.result.runReconciliationBarrierActive !== false ||
    response.result.recoveryClaimPreserved !== false ||
    response.result.automaticExpiryPermitted !== false) {
    fail('CNYOS_RECONCILIATION_RECOVERY_FINALIZATION_RESULT_INVALID');
  }
  const terminal = validateTerminalEnvelope(response.result.terminalRecord, {
    trust: plan.trust, expectedTarget: plan.target, expectedType: 'committed_recovery',
    observedAt: response.observedAt, expectedExecutionReceiptSha256: receipt.sha256
  });
  if (terminal.claimId !== plan.result.claim.claimId ||
    terminal.planCoreSha256 !== plan.result.planCoreSha256 ||
    terminal.netlifyDeployId !== plan.result.planCore.previousDeployId) {
    fail('CNYOS_RECONCILIATION_RECOVERY_FINALIZATION_RESULT_INVALID');
  }
  return writeFinalizationEvidence(env, runtime, plan.target,
    'finalize_recovery', response.result, response.observedAt, {
      recoveryDisposition: 'recovery_required', claimId: plan.result.claim.claimId,
      planCoreSha256: plan.result.planCoreSha256,
      executionReceiptSha256: receipt.sha256,
      terminalRecordId: terminal.terminalRecordId
    });
}

async function loadTerminalFile(env, success) {
  const filename = success ? env.CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH :
    env.CNYOS_CONTROLLER_RECOVERY_TERMINAL_EVIDENCE_PATH;
  const digest = success ? env.CNYOS_EXPECTED_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_SHA256 :
    env.CNYOS_EXPECTED_RECOVERY_TERMINAL_EVIDENCE_SHA256;
  return loadHashedJson(filename, digest, 'CNYOS_RECONCILIATION_TERMINAL_RECORD_INVALID',
    { canonical: true });
}

export async function finalizeRehydratedTerminal({
  env = process.env, fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider, now = () => new Date(), success
} = {}) {
  assertAbsentEnvironmentNames(env, OIDC_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_OIDC_CREDENTIAL_ISOLATION_INVALID');
  await assertWatchdogPolicyFile(env);
  const runtime = controllerRuntime(env);
  const watchdog = runtime.controllerWorkflowPath === POLICY.controller.rollbackWorkflowPath;
  assertRuntimeMode(runtime, env, watchdog);
  const expectedDisposition = success ? 'terminal_success_rehydrated' :
    'terminal_recovery_rehydrated';
  const type = success ? 'committed_success' : 'committed_recovery';
  let observedAt;
  let plan;
  let file;
  let terminal;
  try {
    observedAt = nowDate(now);
    plan = await validatePlanForFinalizer(env, runtime, watchdog, observedAt);
    assertPreparationResultGate(env, watchdog, expectedDisposition);
    if (plan.result.recoveryDisposition !== expectedDisposition) {
      fail('CNYOS_RECONCILIATION_FINALIZATION_DISPOSITION_INVALID');
    }
    file = await loadTerminalFile(env, success);
    if (!isDeepStrictEqual(file.value, plan.result.terminalRecord)) {
      fail('CNYOS_RECONCILIATION_TERMINAL_RECORD_MISMATCH');
    }
    terminal = validateTerminalEnvelope(file.value, {
      trust: plan.trust, expectedTarget: plan.target, expectedType: type, observedAt,
      expectedExecutionReceiptSha256: file.value.terminalRecord.executionReceiptSha256,
      expectedFinalSha256: file.value.terminalRecord.finalEvidenceSha256,
      expectedPublisherReleaseSha256: file.value.terminalRecord.publisherReleaseEvidenceSha256
    });
  } catch {
    return recordPreCommitFinalizerFailure({
      env, fetchImpl, oidcTokenProvider, now, watchdog
    });
  }
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust: plan.trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL,
    operation: 'acknowledge_rehydrated_terminal', resumer: runtime, target: plan.target,
    evidence: Object.freeze({
      expectedTerminalType: type,
      terminalRecordId: terminal.terminalRecordId,
      terminalRecordSha256: file.sha256,
      noRollbackExecutionPermitted: true
    }), now
  });
  assertExactKeys(response.result, [
    'status', 'publisherLeaseReleased', 'runReconciliationBarrierActive',
    'recoveryClaimPreserved', 'automaticExpiryPermitted', 'terminalRecord'
  ], 'CNYOS_RECONCILIATION_TERMINAL_ACKNOWLEDGEMENT_INVALID');
  if (response.result.status !== 'terminal_noop' ||
    response.result.publisherLeaseReleased !== true ||
    response.result.runReconciliationBarrierActive !== false ||
    response.result.recoveryClaimPreserved !== false ||
    response.result.automaticExpiryPermitted !== false ||
    !isDeepStrictEqual(response.result.terminalRecord, file.value)) {
    fail('CNYOS_RECONCILIATION_TERMINAL_ACKNOWLEDGEMENT_INVALID');
  }
  return writeFinalizationEvidence(env, runtime, plan.target,
    'acknowledge_rehydrated_terminal', response.result, observedAt, {
      recoveryDisposition: expectedDisposition,
      terminalRecordId: terminal.terminalRecordId,
      terminalRecordSha256: file.sha256,
      rollbackExecutionAttempted: false
    });
}

export async function recordIncompleteRecovery({
  env = process.env, fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider, now = () => new Date(), watchdog = false
} = {}) {
  assertAbsentEnvironmentNames(env, OIDC_FORBIDDEN_ENVIRONMENT_NAMES,
    'CNYOS_RECONCILIATION_OIDC_CREDENTIAL_ISOLATION_INVALID');
  await assertWatchdogPolicyFile(env);
  const runtime = controllerRuntime(env);
  assertRuntimeMode(runtime, env, watchdog);
  const observedAt = nowDate(now);
  let target = targetFromEnvironment(env, runtime, { allowUnknownNonce: true });
  const reason = exactIdentifier(env.CNYOS_RECOVERY_INCOMPLETE_REASON,
    /^[a-z][a-z0-9_]{7,99}$/, 'CNYOS_RECONCILIATION_INCOMPLETE_REASON_INVALID');
  let claim = null;
  const planBindingNames = watchdog ? [
    'CNYOS_CONTROLLER_RECOVERY_PLAN_PATH',
    'CNYOS_EXPECTED_RECOVERY_PLAN_SHA256',
    'CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH',
    'CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256'
  ] : [
    'CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH',
    'CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256',
    'CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH',
    'CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256'
  ];
  const presentPlanBindings = planBindingNames.filter(name => Object.hasOwn(env, name));
  if (presentPlanBindings.length !== 0 &&
    presentPlanBindings.length !== planBindingNames.length) {
    fail('CNYOS_RECONCILIATION_INCOMPLETE_PLAN_BINDING_PARTIAL');
  }
  if (presentPlanBindings.length === planBindingNames.length) {
    const plan = await validatePlanForFinalizer(env, runtime, watchdog, observedAt);
    target = plan.target;
    if (plan.result.recoveryDisposition === 'recovery_required') {
      claim = Object.freeze({
        claimId: plan.result.claim.claimId,
        barrierGeneration: plan.target.barrierGeneration,
        planCoreSha256: plan.result.planCoreSha256
      });
    }
  }
  const trust = brokerTrustRoot('reconciliation');
  const response = await callSignedBrokerOperation({
    env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL,
    operation: 'record_incomplete_recovery', resumer: runtime, target,
    evidence: Object.freeze({
      reason, claim,
      preparationJobResult: env.CNYOS_PREPARATION_JOB_RESULT ||
        env.CNYOS_RECOVERY_PREPARATION_JOB_RESULT || null,
      executionJobResult: env.CNYOS_EXECUTION_JOB_RESULT ||
        env.CNYOS_RECOVERY_EXECUTION_JOB_RESULT || null,
      preserveLeaseOrRunBarrierRequired: true,
      preserveClaimAndPlanCoreRequired: claim !== null,
      automaticExpiryPermitted: false
    }), now
  });
  assertExactKeys(response.result, [
    'status', 'target', 'publisherLeaseReleased', 'runReconciliationBarrierActive',
    'recoveryClaimPreserved', 'automaticExpiryPermitted'
  ], 'CNYOS_RECONCILIATION_INCOMPLETE_RESULT_INVALID');
  const resolvedTarget = assertTarget(response.result.target, target,
    'CNYOS_RECONCILIATION_INCOMPLETE_RESULT_INVALID');
  if (response.result.status !== 'incomplete_recorded' ||
    response.result.runReconciliationBarrierActive !== true ||
    typeof response.result.publisherLeaseReleased !== 'boolean' ||
    typeof response.result.recoveryClaimPreserved !== 'boolean' ||
    (claim !== null && response.result.recoveryClaimPreserved !== true) ||
    response.result.automaticExpiryPermitted !== false) {
    fail('CNYOS_RECONCILIATION_INCOMPLETE_RESULT_INVALID');
  }
  return writeFinalizationEvidence(env, runtime, resolvedTarget,
    'record_incomplete_recovery', response.result, observedAt, {
      incompleteReason: reason,
      claimId: claim?.claimId || null,
      planCoreSha256: claim?.planCoreSha256 || null,
      leaseOrRunBarrierRetained: true
    });
}

export async function reconcileNetlifyReleaseState({
  mode,
  env = process.env,
  fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider,
  now = () => new Date(),
  producerBundleVerifier = verifyProducerBundle
} = {}) {
  if (!RECONCILIATION_MODES.includes(mode)) {
    fail(`Usage: node reconcile-netlify-release-state.mjs <${RECONCILIATION_MODES.join('|')}>`);
  }
  if (mode === 'assert-clean') return assertClean({ env, fetchImpl, oidcTokenProvider, now });
  if (mode === 'commit-successful-release') {
    return commitSuccessfulRelease({
      env, fetchImpl, oidcTokenProvider, now, producerBundleVerifier
    });
  }
  if (mode === 'prepare-failed-release-reconciliation') {
    return prepareRecovery({ env, fetchImpl, oidcTokenProvider, now, watchdog: false });
  }
  if (mode === 'prepare-watchdog-recovery') {
    return prepareRecovery({ env, fetchImpl, oidcTokenProvider, now, watchdog: true });
  }
  if (mode === 'execute-failed-release-reconciliation-plan') {
    return executeRecoveryPlan({ env, fetchImpl, now, watchdog: false });
  }
  if (mode === 'execute-watchdog-recovery-plan') {
    return executeRecoveryPlan({ env, fetchImpl, now, watchdog: true });
  }
  if (mode === 'finalize-failed-release-reconciliation-success') {
    return finalizeRecoverySuccess({ env, fetchImpl, oidcTokenProvider, now, watchdog: false });
  }
  if (mode === 'finalize-watchdog-recovery-success') {
    return finalizeRecoverySuccess({ env, fetchImpl, oidcTokenProvider, now, watchdog: true });
  }
  if (mode === 'finalize-rehydrated-successful-release') {
    return finalizeRehydratedTerminal({ env, fetchImpl, oidcTokenProvider, now, success: true });
  }
  if (mode === 'finalize-rehydrated-recovery') {
    return finalizeRehydratedTerminal({ env, fetchImpl, oidcTokenProvider, now, success: false });
  }
  return recordIncompleteRecovery({
    env, fetchImpl, oidcTokenProvider, now,
    watchdog: mode === 'record-incomplete-watchdog-recovery'
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  reconcileNetlifyReleaseState({ mode: process.argv[2] }).then(result => {
    process.stdout.write(`${JSON.stringify({
      status: 'passed',
      mode: process.argv[2],
      recoveryDisposition: result.recoveryDisposition || null,
      evidencePath: result.evidencePath || result.receiptPath || result.terminalPath || null,
      planPath: result.planPath || null,
      chainPath: result.chainPath || null
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_RECONCILIATION_FAILED')}\n`);
    process.exitCode = 1;
  });
}
