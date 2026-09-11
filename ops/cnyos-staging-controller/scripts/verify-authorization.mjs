import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  GITHUB_LOGIN,
  POLICY,
  POLICY_SHA256,
  PR36_LEGACY_REQUIRED_STATE,
  PR36_REVIEW_ONLY_REQUIRED_STATE,
  assertPr36PolicyConfiguration,
  assertPr36RequiredState,
  REQUIRED_REVIEW_AREAS,
  assertControllerRuntime,
  assertExactKeys,
  assertPolicyTarget,
  canonicalIsoTimestamp,
  decodeNonce,
  exactDeployId,
  exactSha256,
  fail,
  isPlainObject,
  parseJsonObject,
  readFileBounded,
  required,
  recentCanonicalTimestamp,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';

const APPROVER_REGISTRY_KEYS = Object.freeze(['schemaVersion', 'environment', 'keys']);
const APPROVER_KEY_KEYS = Object.freeze([
  'id', 'role', 'githubLogin', 'ownerName', 'publicKeyPem', 'spkiSha256'
]);
const APPROVER_ROLES = Object.freeze([
  'independent_security_reviewer',
  'managed_platform_risk_owner'
]);
const EVIDENCE_POINTER_KEYS = Object.freeze(['sha256', 'reference']);
const PRINCIPAL_COMMON_KEYS = Object.freeze([
  'status', 'tokenClass', 'subject', 'inventoryComplete', 'accessibleSiteCount',
  'allowedSiteIds', 'productionAccess', 'membershipRole', 'teamOwner',
  'teamAdministrator', 'siteAccessScope', 'accountConfigurationCapabilityAbsent',
  'teamAdministrationCapabilityAbsent', 'deployCapabilityVerified', 'membershipEvidence',
  'evidence', 'verifiedAt', 'expiresAt'
]);

function authorizationMaximumMilliseconds() {
  const maximum = POLICY.authorization?.maximumLifetimeMinutes * 60 * 1000;
  if (!Number.isSafeInteger(maximum) || maximum <= 0) {
    fail('CNYOS_CONTROLLER_AUTHORIZATION_POLICY_INVALID');
  }
  return maximum;
}

function boundedFreshWindow(verifiedAtValue, expiresAtValue, now, code) {
  const maximum = authorizationMaximumMilliseconds();
  const verifiedAt = recentCanonicalTimestamp(verifiedAtValue, now, maximum, code);
  const expiresAt = canonicalIsoTimestamp(expiresAtValue, code);
  if (expiresAt <= now || expiresAt <= verifiedAt ||
    expiresAt.getTime() - verifiedAt.getTime() > maximum) fail(code);
  return Object.freeze({ verifiedAt, expiresAt });
}

export function sameGitHubLogin(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftValue = left;
  const rightValue = right;
  return GITHUB_LOGIN.test(leftValue) && GITHUB_LOGIN.test(rightValue) &&
    leftValue.toLowerCase() === rightValue.toLowerCase();
}

export function assertDistinctOpaquePrincipalSubjects(publishSubject, rollbackSubject) {
  if (typeof publishSubject !== 'string' || !/^[\x21-\x7e]{3,200}$/.test(publishSubject) ||
    typeof rollbackSubject !== 'string' || !/^[\x21-\x7e]{3,200}$/.test(rollbackSubject) ||
    publishSubject === rollbackSubject) {
    fail('CNYOS_CONTROLLER_NETLIFY_PRINCIPALS_NOT_DISTINCT');
  }
}

function decodeSignature(value) {
  const encoded = required(value, 'CNYOS_CONTROLLER_SIGNATURE_REQUIRED', 256);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) fail('CNYOS_CONTROLLER_SIGNATURE_INVALID');
  const signature = Buffer.from(encoded, 'base64');
  if (signature.byteLength !== 64 || signature.toString('base64') !== encoded) {
    fail('CNYOS_CONTROLLER_SIGNATURE_INVALID');
  }
  return signature;
}

function validateApproverKeyRecord(record) {
  const code = 'CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID';
  assertExactKeys(record, APPROVER_KEY_KEYS, code);
  const configuredRoles = POLICY.authorization?.requiredSignatureRoles;
  if (!Array.isArray(configuredRoles) ||
    JSON.stringify([...configuredRoles].sort()) !== JSON.stringify([...APPROVER_ROLES].sort()) ||
    typeof record.id !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/.test(record.id) ||
    !APPROVER_ROLES.includes(record.role) ||
    typeof record.githubLogin !== 'string' || !GITHUB_LOGIN.test(record.githubLogin) ||
    typeof record.ownerName !== 'string' || record.ownerName.length < 1 ||
    record.ownerName.length > 200 || record.ownerName !== record.ownerName.trim() ||
    /[\u0000-\u001f\u007f]/.test(record.ownerName) ||
    typeof record.spkiSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(record.spkiSha256) ||
    typeof record.publicKeyPem !== 'string' || record.publicKeyPem.length > 1024 ||
    !record.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n') ||
    !record.publicKeyPem.endsWith('-----END PUBLIC KEY-----\n')) {
    fail(code);
  }
  let publicKey;
  try { publicKey = crypto.createPublicKey(record.publicKeyPem); }
  catch { fail(code); }
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') fail(code);
  const canonicalPublicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  if (typeof canonicalPublicKeyPem !== 'string' ||
    record.publicKeyPem !== canonicalPublicKeyPem) fail(code);
  const fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  if (fingerprint !== record.spkiSha256) {
    fail('CNYOS_CONTROLLER_APPROVER_KEY_FINGERPRINT_MISMATCH');
  }
  return Object.freeze({ record, publicKey, fingerprint });
}

function loadRegistry(raw) {
  const registry = parseJsonObject(raw, 'CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID');
  assertExactKeys(
    registry,
    APPROVER_REGISTRY_KEYS,
    'CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID'
  );
  if (registry.schemaVersion !== 1 || registry.environment !== POLICY.target.environment ||
    !Array.isArray(registry.keys) || registry.keys.length < 2) {
    fail('CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID');
  }
  const validated = registry.keys.map(validateApproverKeyRecord);
  const ids = validated.map(item => item.record.id);
  const fingerprints = validated.map(item => item.fingerprint);
  if (new Set(ids).size !== ids.length) {
    fail('CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID');
  }
  if (new Set(fingerprints).size !== fingerprints.length) {
    fail('CNYOS_CONTROLLER_APPROVER_REGISTRY_DUPLICATE_FINGERPRINT');
  }
  return registry;
}

function pinnedKey(registry, { id, role, login, ownerName }) {
  const matches = registry.keys.filter(item => item?.id === id);
  const record = matches[0];
  if (matches.length !== 1 || !isPlainObject(record) || record.role !== role ||
    !sameGitHubLogin(record.githubLogin, login) || record.ownerName !== ownerName) {
    fail('CNYOS_CONTROLLER_APPROVER_KEY_NOT_PINNED');
  }
  const { publicKey } = validateApproverKeyRecord(record);
  return Object.freeze({ record, publicKey });
}

function evidencePointer(value, code) {
  assertExactKeys(value, EVIDENCE_POINTER_KEYS, code);
  if (!/^[0-9a-f]{64}$/.test(String(value.sha256 || '')) ||
    typeof value.reference !== 'string' || value.reference.trim().length < 8 ||
    value.reference.length > 500 || value.reference !== value.reference.trim()) fail(code);
}

function validateKnownGoodEvidence(value, rollback) {
  if (!isPlainObject(value) || value.schemaVersion !== 1 || value.status !== 'passed' ||
    !['cnyos_staging_controller_final_release',
      'cnyos_staging_controller_bootstrap_known_good'].includes(value.evidenceType) ||
    value.scope !== 'cnyos_staging_only' || value.productionAuthorization !== false ||
    value.realPatientDataAuthorized !== false ||
    value.netlifyDeployId !== rollback.previousDeployId ||
    value.target?.netlifySiteId !== POLICY.target.netlifySiteId ||
    value.target?.netlifyOrigin !== POLICY.target.netlifyOrigin ||
    value.source?.repository !== POLICY.sourceRepository ||
    !/^[0-9a-f]{40}$/.test(String(value.source?.commit || ''))) {
    fail('CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
  }
  assertExactKeys(
    value.source,
    value.evidenceType === 'cnyos_staging_controller_final_release'
      ? ['repository', 'commit', 'tree', 'functionSourceTree']
      : ['repository', 'commit'],
    'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID'
  );
  assertExactKeys(
    value.target,
    Object.keys(POLICY.target),
    'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID'
  );
  assertPolicyTarget(value.target, 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
  if (value.evidenceType === 'cnyos_staging_controller_final_release') {
    assertExactKeys(value, [
      'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
      'realPatientDataAuthorized', 'finalizedAt', 'controllerRepository', 'controllerRef',
      'controllerCommit', 'controllerRunId', 'controllerRunAttempt', 'dispatchNonce',
      'policySha256', 'source', 'artifact', 'target', 'netlifyDeployId', 'previousDeployId',
      'functionByteAttestationAvailable', 'authenticatedUatPassed',
      'retainedEvidenceSha256', 'evidenceSetSha256'
    ], 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    assertExactKeys(
      value.artifact,
      ['sha256', 'fileCount'],
      'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID'
    );
    assertExactKeys(value.retainedEvidenceSha256, [
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
    ], 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    if (!Object.values(value.retainedEvidenceSha256).every(item =>
      /^[0-9a-f]{64}$/.test(String(item || ''))) ||
      !/^[0-9a-f]{64}$/.test(String(value.evidenceSetSha256 || '')) ||
      value.evidenceSetSha256 !== sha256(JSON.stringify(value.retainedEvidenceSha256)) ||
      value.controllerRepository !== POLICY.controller.repository ||
      value.controllerRef !== POLICY.controller.protectedRef ||
      !/^[0-9a-f]{40}$/.test(String(value.controllerCommit || '')) ||
      !/^\d+$/.test(String(value.controllerRunId || '')) ||
      value.controllerRunAttempt !== 1 ||
      value.policySha256 !== POLICY_SHA256 ||
      value.functionByteAttestationAvailable !== false ||
      value.authenticatedUatPassed !== true ||
      !/^[0-9a-f]{64}$/.test(String(value.artifact.sha256 || '')) ||
      !Number.isSafeInteger(value.artifact.fileCount) || value.artifact.fileCount < 1 ||
      !/^[0-9a-f]{40}$/.test(String(value.source.tree || '')) ||
      !/^[0-9a-f]{40}$/.test(String(value.source.functionSourceTree || ''))) {
      fail('CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    }
    canonicalIsoTimestamp(value.finalizedAt, 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    exactDeployId(value.previousDeployId, 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
  } else {
    assertExactKeys(value, [
      'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
      'realPatientDataAuthorized', 'recordedAt', 'controllerRepository', 'policySha256',
      'source', 'target', 'netlifyDeployId', 'evidence'
    ], 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    if (value.controllerRepository !== POLICY.controller.repository ||
      value.policySha256 !== POLICY_SHA256) {
      fail('CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    }
    canonicalIsoTimestamp(value.recordedAt, 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
    evidencePointer(value.evidence, 'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID');
  }
}

function passedEvidence(value, code) {
  if (!isPlainObject(value) || value.status !== 'passed') fail(code);
  evidencePointer(value.evidence, code);
  return value;
}

function assertLeastPrivilegeNetlifyPrincipal(value, code, { rollback = false } = {}) {
  assertExactKeys(
    value,
    rollback ? [...PRINCIPAL_COMMON_KEYS, 'restoreCapabilityVerified'] : PRINCIPAL_COMMON_KEYS,
    code
  );
  if (value.status !== 'passed' || value.membershipRole !== 'Publisher' ||
    value.teamOwner !== false || value.teamAdministrator !== false ||
    value.siteAccessScope !== 'single_site' ||
    value.accountConfigurationCapabilityAbsent !== true ||
    value.teamAdministrationCapabilityAbsent !== true ||
    value.deployCapabilityVerified !== true ||
    (rollback && value.restoreCapabilityVerified !== true)) {
    fail(code);
  }
  evidencePointer(value.membershipEvidence, code);
}

function reviewedInventoryBaseline() {
  const baseline = POLICY.databaseEvidence?.inventoryBaseline;
  const identity = {
    schemaVersion: baseline?.schemaVersion,
    baselineId: baseline?.baselineId,
    observerSchemaVersion: baseline?.observerSchemaVersion,
    supabaseProjectRef: baseline?.supabaseProjectRef,
    databaseSystemIdentifier: baseline?.databaseSystemIdentifier,
    counts: baseline?.counts
  };
  if (!isPlainObject(baseline) || baseline.schemaVersion !== 1 ||
    typeof baseline.baselineId !== 'string' || baseline.baselineId.length < 16 ||
    baseline.observerSchemaVersion !== 2 ||
    baseline.supabaseProjectRef !== POLICY.target.supabaseProjectRef ||
    baseline.databaseSystemIdentifier !== POLICY.target.databaseSystemIdentifier ||
    !isPlainObject(baseline.counts) ||
    !Object.values(baseline.counts).every(value => Number.isSafeInteger(value) && value >= 0) ||
    baseline.sha256 !== sha256(JSON.stringify(identity))) {
    fail('CNYOS_CONTROLLER_DATABASE_INVENTORY_POLICY_INVALID');
  }
  return baseline;
}

function validateProtocolGates(packet, manifest, now) {
  const databaseMaximumAge = POLICY.databaseEvidence?.maximumAgeMinutes * 60 * 1000;
  if (!Number.isSafeInteger(databaseMaximumAge) || databaseMaximumAge <= 0) {
    fail('CNYOS_CONTROLLER_DATABASE_EVIDENCE_POLICY_INVALID');
  }
  const inventoryBaseline = reviewedInventoryBaseline();
  const ci = passedEvidence(packet.exactHeadCi, 'CNYOS_CONTROLLER_EXACT_HEAD_CI_INVALID');
  assertExactKeys(ci, [
    'status', 'sourceCommit', 'sourceTree', 'artifactSha256', 'conclusion',
    'unresolvedBlockers', 'completedAt', 'evidence'
  ], 'CNYOS_CONTROLLER_EXACT_HEAD_CI_INVALID');
  if (ci.sourceCommit !== manifest.candidateCommit || ci.sourceTree !== manifest.candidateTree ||
    ci.artifactSha256 !== manifest.artifactSha256 || ci.conclusion !== 'success' ||
    ci.unresolvedBlockers !== 0 || canonicalIsoTimestamp(
      ci.completedAt,
      'CNYOS_CONTROLLER_EXACT_HEAD_CI_INVALID'
    ) > now) fail('CNYOS_CONTROLLER_EXACT_HEAD_CI_INVALID');

  const rehearsal = passedEvidence(
    packet.rollbackRehearsal,
    'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID'
  );
  assertExactKeys(rehearsal, [
    'status', 'sourceCommit', 'sourceTree', 'artifactSha256', 'postgresqlMajorVersion',
    'connectionMode', 'projectRef', 'databaseSystemIdentifier', 'maintenanceWindowStatus',
    'maintenanceWindowReference', 'quiescenceVerified', 'quiescenceEvidence',
    'normalRollback', 'injectedFailure', 'ambiguityRecoveryStatus', 'freshPostObserver',
    'completedAt', 'evidence'
  ], 'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');
  assertExactKeys(rehearsal.normalRollback, [
    'status', 'atomicRollbackVerified', 'receipt', 'noExecutableCommitDerivative',
    'advisoryLockReleased', 'preAclCatalogSha256', 'postAclCatalogSha256', 'evidence'
  ], 'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');
  assertExactKeys(rehearsal.injectedFailure, [
    'status', 'exitWasNonzero', 'exactFailureObserved', 'failureInjectionPoint',
    'observedErrorSha256', 'postStateEqual', 'noExecutableCommitDerivative',
    'advisoryLockReleased', 'preAclCatalogSha256', 'postAclCatalogSha256', 'evidence'
  ], 'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');
  assertExactKeys(rehearsal.freshPostObserver, [
    'status', 'schemaVersion', 'baselineSchemaVersion', 'baselineId', 'baselineSha256',
    'observedAt', 'afterNormalRollback', 'afterInjectedFailure', 'projectRef',
    'databaseSystemIdentifier', 'datasetCount', 'publicRoutineCount',
    'securityDefinerCount', 'triggerCount', 'eventTriggerCount', 'expectedAclDigest',
    'observedAclDigest', 'aclCatalogSha256', 'evidence'
  ], 'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');
  const rehearsalCompletedAt = recentCanonicalTimestamp(
    rehearsal.completedAt,
    now,
    databaseMaximumAge,
    'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_STALE'
  );
  const observerObservedAt = recentCanonicalTimestamp(
    rehearsal.freshPostObserver?.observedAt,
    now,
    databaseMaximumAge,
    'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_STALE'
  );
  if (rehearsal.sourceCommit !== manifest.candidateCommit ||
    rehearsal.sourceTree !== manifest.candidateTree ||
    rehearsal.artifactSha256 !== manifest.artifactSha256 ||
    rehearsal.postgresqlMajorVersion !== 17 || rehearsal.connectionMode !== 'direct' ||
    rehearsal.projectRef !== POLICY.target.supabaseProjectRef ||
    rehearsal.databaseSystemIdentifier !== POLICY.target.databaseSystemIdentifier ||
    rehearsal.maintenanceWindowStatus !== 'completed' ||
    typeof rehearsal.maintenanceWindowReference !== 'string' ||
    rehearsal.maintenanceWindowReference.trim().length < 8 ||
    rehearsal.quiescenceVerified !== true ||
    observerObservedAt < rehearsalCompletedAt ||
    rehearsal.normalRollback?.status !== 'passed' ||
    rehearsal.normalRollback?.atomicRollbackVerified !== true ||
    rehearsal.normalRollback?.receipt !== 'ACL_CATALOG_ROLLBACK_VERIFIED' ||
    rehearsal.normalRollback?.noExecutableCommitDerivative !== true ||
    rehearsal.normalRollback?.advisoryLockReleased !== true ||
    !/^[0-9a-f]{64}$/.test(String(rehearsal.normalRollback?.preAclCatalogSha256 || '')) ||
    rehearsal.normalRollback?.preAclCatalogSha256 !==
      rehearsal.normalRollback?.postAclCatalogSha256 ||
    rehearsal.injectedFailure?.status !== 'passed' ||
    rehearsal.injectedFailure?.exitWasNonzero !== true ||
    rehearsal.injectedFailure?.exactFailureObserved !== true ||
    typeof rehearsal.injectedFailure?.failureInjectionPoint !== 'string' ||
    rehearsal.injectedFailure.failureInjectionPoint.trim().length < 8 ||
    !/^[0-9a-f]{64}$/.test(String(rehearsal.injectedFailure?.observedErrorSha256 || '')) ||
    rehearsal.injectedFailure?.postStateEqual !== true ||
    rehearsal.injectedFailure?.noExecutableCommitDerivative !== true ||
    rehearsal.injectedFailure?.advisoryLockReleased !== true ||
    !/^[0-9a-f]{64}$/.test(String(rehearsal.injectedFailure?.preAclCatalogSha256 || '')) ||
    rehearsal.injectedFailure?.preAclCatalogSha256 !==
      rehearsal.injectedFailure?.postAclCatalogSha256 ||
    !['not_required_no_ambiguous_outcome', 'recovered_and_reverified'].includes(
      rehearsal.ambiguityRecoveryStatus
    ) ||
    rehearsal.freshPostObserver?.status !== 'passed' ||
    rehearsal.freshPostObserver?.schemaVersion !== inventoryBaseline.observerSchemaVersion ||
    rehearsal.freshPostObserver?.baselineSchemaVersion !== inventoryBaseline.schemaVersion ||
    rehearsal.freshPostObserver?.baselineId !== inventoryBaseline.baselineId ||
    rehearsal.freshPostObserver?.baselineSha256 !== inventoryBaseline.sha256 ||
    rehearsal.freshPostObserver?.afterNormalRollback !== true ||
    rehearsal.freshPostObserver?.afterInjectedFailure !== true ||
    rehearsal.freshPostObserver?.projectRef !== POLICY.target.supabaseProjectRef ||
    rehearsal.freshPostObserver?.databaseSystemIdentifier !== POLICY.target.databaseSystemIdentifier ||
    rehearsal.freshPostObserver?.datasetCount !== inventoryBaseline.counts.datasetCount ||
    rehearsal.freshPostObserver?.publicRoutineCount !== inventoryBaseline.counts.publicRoutineCount ||
    rehearsal.freshPostObserver?.securityDefinerCount !== inventoryBaseline.counts.securityDefinerCount ||
    rehearsal.freshPostObserver?.triggerCount !== inventoryBaseline.counts.triggerCount ||
    rehearsal.freshPostObserver?.eventTriggerCount !== inventoryBaseline.counts.eventTriggerCount ||
    !/^[0-9a-f]{64}$/.test(String(rehearsal.freshPostObserver?.expectedAclDigest || '')) ||
    rehearsal.freshPostObserver?.expectedAclDigest !==
      rehearsal.freshPostObserver?.observedAclDigest ||
    rehearsal.freshPostObserver?.aclCatalogSha256 !==
      rehearsal.normalRollback?.postAclCatalogSha256 ||
    rehearsal.freshPostObserver?.aclCatalogSha256 !==
      rehearsal.injectedFailure?.postAclCatalogSha256) {
    fail('CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');
  }
  for (const item of [rehearsal.normalRollback, rehearsal.injectedFailure,
    rehearsal.freshPostObserver]) {
    evidencePointer(item?.evidence, 'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');
  }
  evidencePointer(rehearsal.quiescenceEvidence, 'CNYOS_CONTROLLER_ROLLBACK_REHEARSAL_INVALID');

  const capability = passedEvidence(
    packet.runtimeCapabilityBoundary,
    'CNYOS_CONTROLLER_RUNTIME_CAPABILITY_BOUNDARY_INVALID'
  );
  assertExactKeys(capability, [
    'status', 'sourceCommit', 'sourceTree', 'artifactSha256', 'projectRef',
    'netlifySiteId', 'platformControlEnabled', 'ownerDriveEnabled',
    'restoreSourceApiEnabled', 'pubmedEnabled', 'directJsonRestoreTestEnabled',
    'ownerControlEnabled', 'ownerControlScope', 'githubProductionDispatchReachable',
    'driveOrBlobProductionReachable', 'lineProductionReachable',
    'secretProjectBindingVerified', 'syntheticOnly', 'realPatientDataAuthorized',
    'functionEnvironmentAllowlistComplete', 'functionSecretInventoryClosedWorld',
    'browserProcessEnvironmentSanitized', 'candidateFunctionEgressPolicyEnforced',
    'productionCredentialAbsenceVerified', 'stagingOnlyCredentialScopeVerified',
    'serviceRoleNotInheritedByBrowserProcess',
    'candidateFunctionsReceiveOnlyReviewedStagingSecrets', 'evidence'
  ], 'CNYOS_CONTROLLER_RUNTIME_CAPABILITY_BOUNDARY_INVALID');
  if (capability.sourceCommit !== manifest.candidateCommit ||
    capability.sourceTree !== manifest.candidateTree ||
    capability.artifactSha256 !== manifest.artifactSha256 ||
    capability.projectRef !== POLICY.target.supabaseProjectRef ||
    capability.netlifySiteId !== POLICY.target.netlifySiteId ||
    capability.platformControlEnabled !== false || capability.ownerDriveEnabled !== false ||
    capability.restoreSourceApiEnabled !== false || capability.pubmedEnabled !== false ||
    capability.directJsonRestoreTestEnabled !== false ||
    capability.ownerControlEnabled !== false ||
    capability.ownerControlScope !== 'disabled' ||
    capability.githubProductionDispatchReachable !== false ||
    capability.driveOrBlobProductionReachable !== false ||
    capability.lineProductionReachable !== false ||
    capability.secretProjectBindingVerified !== true || capability.syntheticOnly !== true ||
    capability.functionEnvironmentAllowlistComplete !== true ||
    capability.functionSecretInventoryClosedWorld !== true ||
    capability.browserProcessEnvironmentSanitized !== true ||
    capability.candidateFunctionEgressPolicyEnforced !== true ||
    capability.productionCredentialAbsenceVerified !== true ||
    capability.stagingOnlyCredentialScopeVerified !== true ||
    capability.serviceRoleNotInheritedByBrowserProcess !== true ||
    capability.candidateFunctionsReceiveOnlyReviewedStagingSecrets !== true ||
    capability.realPatientDataAuthorized !== false) {
    fail('CNYOS_CONTROLLER_RUNTIME_CAPABILITY_BOUNDARY_INVALID');
  }

  const deploymentBoundary = passedEvidence(
    packet.deploymentControlBoundary,
    'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID'
  );
  assertExactKeys(deploymentBoundary, [
    'status', 'sourceCommit', 'sourceTree', 'artifactSha256', 'netlifySiteId',
    'productionNetlifySiteId', 'productionNetlifyOrigin',
    'exclusivePublisherEnforced', 'netlifyGitPublishingDisabled', 'buildHooksDisabled',
    'manualUiPublishingDenied', 'targetSiteClassifiedStagingOnly', 'realPatientDataAbsent',
    'legacyPublisherInventoryComplete', 'candidateRepositoryProductionWorkflowTargetDenied',
    'candidateRepositoryPreviewWorkflowTargetDenied',
    'allAlternatePublisherCredentialsTargetDenied',
    'currentCnyosProductionMappingConflictResolved',
    'compareAndSwapOrEquivalentLockEnforced', 'privateDraftAccessEnforced',
    'failedDraftCleanupEnforced', 'rollbackEnvironmentNoninteractive',
    'rollbackPrincipal', 'externalRollbackReconciliationBroker', 'observedAt', 'expiresAt',
    'evidence'
  ], 'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID');
  const reconciliationBroker = deploymentBoundary.externalRollbackReconciliationBroker;
  const reconciliationPolicyId = required(
    POLICY.externalReconciliationBroker?.policyId,
    'CNYOS_CONTROLLER_RECONCILIATION_BROKER_POLICY_INVALID',
    200
  );
  if (/^__[A-Z0-9_]+__$/.test(reconciliationPolicyId)) {
    fail('CNYOS_CONTROLLER_RECONCILIATION_BROKER_POLICY_INVALID');
  }
  const reconciliationPolicySha256 = exactSha256(
    POLICY.externalReconciliationBroker?.policySha256,
    'CNYOS_CONTROLLER_RECONCILIATION_BROKER_POLICY_INVALID'
  );
  const deploymentBoundaryWindow = boundedFreshWindow(
    deploymentBoundary.observedAt,
    deploymentBoundary.expiresAt,
    now,
    'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_EXPIRED'
  );
  const rollbackPrincipalWindow = boundedFreshWindow(
    deploymentBoundary.rollbackPrincipal?.verifiedAt,
    deploymentBoundary.rollbackPrincipal?.expiresAt,
    now,
    'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_EXPIRED'
  );
  assertLeastPrivilegeNetlifyPrincipal(
    deploymentBoundary.rollbackPrincipal,
    'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID',
    { rollback: true }
  );
  if (deploymentBoundary.sourceCommit !== manifest.candidateCommit ||
    deploymentBoundary.sourceTree !== manifest.candidateTree ||
    deploymentBoundary.artifactSha256 !== manifest.artifactSha256 ||
    deploymentBoundary.netlifySiteId !== POLICY.target.netlifySiteId ||
    deploymentBoundary.productionNetlifySiteId !==
      POLICY.productionDenylist.netlifySiteId ||
    deploymentBoundary.productionNetlifyOrigin !==
      POLICY.productionDenylist.netlifyOrigin ||
    deploymentBoundary.exclusivePublisherEnforced !== true ||
    deploymentBoundary.netlifyGitPublishingDisabled !== true ||
    deploymentBoundary.buildHooksDisabled !== true ||
    deploymentBoundary.manualUiPublishingDenied !== true ||
    deploymentBoundary.targetSiteClassifiedStagingOnly !== true ||
    deploymentBoundary.realPatientDataAbsent !== true ||
    deploymentBoundary.legacyPublisherInventoryComplete !== true ||
    deploymentBoundary.candidateRepositoryProductionWorkflowTargetDenied !== true ||
    deploymentBoundary.candidateRepositoryPreviewWorkflowTargetDenied !== true ||
    deploymentBoundary.allAlternatePublisherCredentialsTargetDenied !== true ||
    deploymentBoundary.currentCnyosProductionMappingConflictResolved !== true ||
    deploymentBoundary.compareAndSwapOrEquivalentLockEnforced !== true ||
    deploymentBoundary.privateDraftAccessEnforced !== true ||
    deploymentBoundary.failedDraftCleanupEnforced !== true ||
    deploymentBoundary.rollbackEnvironmentNoninteractive !== true ||
    deploymentBoundary.rollbackPrincipal?.tokenClass !== 'dedicated_staging_only' ||
    typeof deploymentBoundary.rollbackPrincipal?.subject !== 'string' ||
    deploymentBoundary.rollbackPrincipal.subject.trim().length < 3 ||
    deploymentBoundary.rollbackPrincipal?.inventoryComplete !== true ||
    deploymentBoundary.rollbackPrincipal?.accessibleSiteCount !== 1 ||
    !Array.isArray(deploymentBoundary.rollbackPrincipal?.allowedSiteIds) ||
    deploymentBoundary.rollbackPrincipal.allowedSiteIds.length !== 1 ||
    deploymentBoundary.rollbackPrincipal.allowedSiteIds[0] !== POLICY.target.netlifySiteId ||
    deploymentBoundary.rollbackPrincipal?.productionAccess !== false ||
    !isPlainObject(reconciliationBroker) ||
    reconciliationBroker.policyId !== reconciliationPolicyId ||
    reconciliationBroker.policySha256 !== reconciliationPolicySha256 ||
    reconciliationBroker.executionAuthority !== 'external_rollback_reconciliation_broker' ||
    reconciliationBroker.immutablePolicy !== true ||
    reconciliationBroker.independentOfTargetRunCode !== true ||
    reconciliationBroker.independentOfWatchdogRevision !== true ||
    reconciliationBroker.targetControllerRepository !== packet.controller?.repository ||
    reconciliationBroker.targetControllerRef !== packet.controller?.ref ||
    reconciliationBroker.targetControllerRunId !== packet.controller?.runId ||
    reconciliationBroker.targetControllerRunAttempt !== packet.controller?.runAttempt ||
    reconciliationBroker.targetControllerCommit !== packet.controller?.commit ||
    reconciliationBroker.targetControllerWorkflowPath !== packet.controller?.workflowPath ||
    reconciliationBroker.targetDispatchNonce !== packet.controller?.dispatchNonce ||
    reconciliationBroker.targetNetlifySiteId !== POLICY.target.netlifySiteId ||
    reconciliationBroker.targetRunCannotSuppressReconciliation !== true ||
    reconciliationBroker.watchdogRevisionCannotSuppressReconciliation !== true ||
    reconciliationBroker.enforcesRollback !== true ||
    reconciliationBroker.enforcesDraftCleanup !== true ||
    reconciliationBroker.enforcesLeaseRelease !== true ||
    reconciliationBroker.enforcesRunReconciliationBarrier !== true ||
    reconciliationBroker.atomicLeaseReleaseRetainsRunReconciliationBarrier !== true ||
    reconciliationBroker.blocksNewMutationWhileRunReconciliationBarrierActive !== true ||
    reconciliationBroker.successfulReleaseCommitRequiresFinalEvidenceHashes !== true ||
    reconciliationBroker.draftIntentTerminalBeforeBarrierClearRequired !== true ||
    reconciliationBroker.automaticRunReconciliationBarrierExpiryPermitted !== false ||
    reconciliationBroker.exactTerminalCommitRetryIdempotent !== true ||
    reconciliationBroker.terminalSuccessAndRecoveryClaimMutuallyExclusive !== true ||
    reconciliationBroker.terminalSuccessNeverRollbackEligible !== true ||
    reconciliationBroker.recoveryClaimConflictsWithDelayedTerminalCommit !== true ||
    reconciliationBroker.recoveryTerminalRecordImmutableAndRetrievable !== true ||
    reconciliationBroker.recoveryTerminalRecordBindsExecutionReceipt !== true ||
    reconciliationBroker.exactRecoveryFinalizationRetryIdempotent !== true ||
    reconciliationBroker.terminalRecoveryNeverRollbackEligible !== true ||
    reconciliationBroker.recoveryClaimAndPlanCorePersistedAtomically !== true ||
    reconciliationBroker.recoveryClaimPlanCoreImmutableAndRetrievable !== true ||
    reconciliationBroker.exactRecoveryClaimRetryIdempotent !== true ||
    reconciliationBroker.authorizedWatchdogRecoveryClaimResumptionEnforced !== true ||
    reconciliationBroker.recoveryAuthorizationRefreshPreservesClaimAndPlanCore !== true ||
    reconciliationBroker.conflictingRecoveryClaimBindingsOrGenerationRejected !== true ||
    reconciliationBroker.automaticRecoveryClaimExpiryPermitted !== false ||
    reconciliationBroker.incompleteRecoveryRecordPreservesRecoveryClaimAndPlan !== true ||
    reconciliationBroker.recoveryClaimAuthorizedResumerRepository !==
      POLICY.controller.repository ||
    reconciliationBroker.recoveryClaimAuthorizedResumerProtectedRef !==
      POLICY.controller.protectedRef ||
    !Array.isArray(reconciliationBroker.recoveryClaimAuthorizedResumerWorkflowPaths) ||
    JSON.stringify(reconciliationBroker.recoveryClaimAuthorizedResumerWorkflowPaths) !==
      JSON.stringify([
        POLICY.controller.releaseWorkflowPath,
        POLICY.controller.rollbackWorkflowPath
      ])) {
    fail('CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID');
  }
  assertExactKeys(reconciliationBroker, [
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
  ], 'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID');
  evidencePointer(deploymentBoundary.rollbackPrincipal?.evidence,
    'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID');
  evidencePointer(reconciliationBroker?.evidence,
    'CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID');

  const promotion = passedEvidence(
    packet.migrationPromotion,
    'CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID'
  );
  const requiredPr36State = assertPr36RequiredState(
    promotion.pr36RequiredState,
    'CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID'
  );
  assertPr36PolicyConfiguration(POLICY.githubReleaseBoundary);
  const migrationPromotionKeys = requiredPr36State === PR36_LEGACY_REQUIRED_STATE
    ? ['pr36RemainsDraftAndUnapproved']
    : ['pr36RemainsDraftAndUnmerged', 'pr36ReviewDoesNotAuthorizeExecution'];
  assertExactKeys(promotion, [
    'status', 'promotionPullRequest', 'promotionHeadRef', 'promotionHeadCommit',
    'promotionBaseRef', 'promotionBaseCommit', 'promotionRequiredState',
    'pr36HeadRef', 'pr36HeadCommit', 'pr36BaseRef', 'pr36BaseCommit',
    'pr36RequiredState', ...migrationPromotionKeys, 'sourceCommit',
    'sourceTree', 'artifactSha256', 'orderedMigrationChainAppliedToChananyaStaging',
    'chananyaLedger', 'jitarsaLedger', 'preDeploymentAuthenticatedRegression', 'evidence'
  ], 'CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID');
  for (const item of [promotion.chananyaLedger, promotion.jitarsaLedger,
    promotion.preDeploymentAuthenticatedRegression]) {
    assertExactKeys(item, ['status', 'evidence'], 'CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID');
  }
  const pr = String(promotion.promotionPullRequest || '').match(
    /^https:\/\/github\.com\/apisarit\/chananya-clinical-wellness-os\/pull\/(\d+)$/
  );
  const branch = value => typeof value === 'string' && value.length >= 1 && value.length <= 200 &&
    /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) && !value.endsWith('/') &&
    !value.includes('..') && !value.includes('//') && !value.includes('@{') &&
    !value.split('/').some(part => !part || part === '.' || part.endsWith('.lock'));
  if (!pr || Number(pr[1]) === POLICY.githubReleaseBoundary?.pr36Number ||
    POLICY.githubReleaseBoundary?.sourceRepository !== POLICY.sourceRepository ||
    promotion.promotionRequiredState !== 'open_ready_for_independent_review' ||
    promotion.pr36RequiredState !== requiredPr36State ||
    !branch(promotion.promotionHeadRef) || promotion.promotionHeadRef === 'main' ||
    !branch(promotion.promotionBaseRef) ||
    promotion.promotionHeadCommit !== manifest.candidateCommit ||
    !/^[0-9a-f]{40}$/.test(String(promotion.promotionBaseCommit || '')) ||
    !branch(promotion.pr36HeadRef) || promotion.pr36HeadRef === 'main' ||
    !branch(promotion.pr36BaseRef) ||
    !/^[0-9a-f]{40}$/.test(String(promotion.pr36HeadCommit || '')) ||
    !/^[0-9a-f]{40}$/.test(String(promotion.pr36BaseCommit || '')) ||
    (requiredPr36State === PR36_LEGACY_REQUIRED_STATE
      ? promotion.pr36RemainsDraftAndUnapproved !== true
      : promotion.pr36RemainsDraftAndUnmerged !== true ||
        promotion.pr36ReviewDoesNotAuthorizeExecution !== true) ||
    promotion.sourceCommit !== manifest.candidateCommit ||
    promotion.sourceTree !== manifest.candidateTree ||
    promotion.artifactSha256 !== manifest.artifactSha256 ||
    promotion.orderedMigrationChainAppliedToChananyaStaging !== true ||
    promotion.chananyaLedger?.status !== 'reconciled' ||
    promotion.jitarsaLedger?.status !== 'independently_reconciled' ||
    promotion.preDeploymentAuthenticatedRegression?.status !== 'passed') {
    fail('CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID');
  }
  for (const item of [promotion.chananyaLedger, promotion.jitarsaLedger,
    promotion.preDeploymentAuthenticatedRegression]) {
    evidencePointer(item?.evidence, 'CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID');
  }

  const strict = passedEvidence(
    packet.strictPostRemediation,
    'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID'
  );
  assertExactKeys(strict, [
    'status', 'sourceCommit', 'sourceTree', 'artifactSha256', 'projectRef',
    'databaseSystemIdentifier', 'verificationSql', 'triggerAndBrowserRpcAcl',
    'postRemediationAuthenticatedRegression', 'unresolvedBlockers', 'verifiedAt', 'evidence'
  ], 'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID');
  assertExactKeys(strict.verificationSql, ['status', 'readOnlyEnforced', 'evidence'],
    'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID');
  assertExactKeys(strict.triggerAndBrowserRpcAcl, ['status', 'evidence'],
    'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID');
  assertExactKeys(strict.postRemediationAuthenticatedRegression, ['status', 'evidence'],
    'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID');
  const strictVerifiedAt = recentCanonicalTimestamp(
    strict.verifiedAt,
    now,
    databaseMaximumAge,
    'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_STALE'
  );
  if (strict.sourceCommit !== manifest.candidateCommit || strict.sourceTree !== manifest.candidateTree ||
    strict.artifactSha256 !== manifest.artifactSha256 ||
    strict.projectRef !== POLICY.target.supabaseProjectRef ||
    strict.databaseSystemIdentifier !== POLICY.target.databaseSystemIdentifier ||
    strict.verificationSql?.status !== 'passed' || strict.verificationSql?.readOnlyEnforced !== true ||
    strict.triggerAndBrowserRpcAcl?.status !== 'passed' ||
    strict.postRemediationAuthenticatedRegression?.status !== 'passed' ||
    strict.unresolvedBlockers !== 0 || strictVerifiedAt > now) {
    fail('CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID');
  }
  for (const item of [strict.verificationSql, strict.triggerAndBrowserRpcAcl,
    strict.postRemediationAuthenticatedRegression]) {
    evidencePointer(item?.evidence, 'CNYOS_CONTROLLER_STRICT_POST_REMEDIATION_INVALID');
  }
  return Object.freeze({ capability, deploymentBoundary, promotion });
}

function validateAuthorizationPacket(packet, runtime, bundle, env, now) {
  assertExactKeys(packet, [
    'schemaVersion',
    'evidenceType',
    'controller',
    'source',
    'artifact',
    'target',
    'exactHeadCi',
    'runtimeCapabilityBoundary',
    'deploymentControlBoundary',
    'principalProof',
    'independentSecurityReview',
    'managedPlatformRiskAcceptance',
    'rollbackRehearsal',
    'migrationPromotion',
    'strictPostRemediation',
    'rollback',
    'signatureKeyIds',
    'authorization',
    'productionAuthorization',
    'realPatientDataAuthorized'
  ], 'CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID');
  if (packet.schemaVersion !== 3 ||
    packet.evidenceType !== 'cnyos_staging_controller_authorization' ||
    packet.productionAuthorization !== false || packet.realPatientDataAuthorized !== false) {
    fail('CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID');
  }
  assertExactKeys(packet.controller, [
    'repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
    'runAttempt', 'dispatchNonce'
  ], 'CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID');
  assertExactKeys(packet.source, [
    'repository', 'commit', 'tree', 'functionSourceTree'
  ], 'CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID');
  assertExactKeys(packet.artifact, [
    'producerManifestSha256', 'artifactSha256', 'fileCount',
    'candidateBuildArtifactDigest', 'staticReproducibilityEvidenceSha256',
    'staticArtifactSha256', 'candidateDependencyLockSha256', 'stagingConfigSha256',
    'productionDenylistConfigSha256', 'functionBundleManifestSha256',
    'functionBundleDependencyLockSha256', 'functionSourcesSha256', 'producerRunId',
    'githubArtifactDigest'
  ], 'CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID');
  assertExactKeys(
    packet.target,
    Object.keys(POLICY.target),
    'CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID'
  );
  assertExactKeys(packet.signatureKeyIds, [
    'independentSecurityReviewer', 'managedPlatformRiskOwner'
  ], 'CNYOS_CONTROLLER_AUTHORIZATION_SCHEMA_INVALID');
  if (env.GITHUB_EVENT_NAME !== 'workflow_dispatch') fail('CNYOS_CONTROLLER_EVENT_INVALID');
  const workflowRef = required(env.GITHUB_WORKFLOW_REF, 'CNYOS_CONTROLLER_WORKFLOW_REF_REQUIRED', 500);
  const expectedWorkflowRef = `${runtime.repository}/${runtime.workflowPath}@${runtime.ref}`;
  if (workflowRef !== expectedWorkflowRef) fail('CNYOS_CONTROLLER_WORKFLOW_REF_INVALID');
  if (!isPlainObject(packet.controller) ||
    packet.controller.repository !== runtime.repository ||
    packet.controller.ref !== runtime.ref || packet.controller.commit !== runtime.commit ||
    packet.controller.workflowPath !== runtime.workflowPath ||
    packet.controller.workflowRef !== workflowRef ||
    packet.controller.runId !== runtime.runId || packet.controller.runAttempt !== 1 ||
    packet.controller.dispatchNonce !== decodeNonce(env.CNYOS_DISPATCH_NONCE).value) {
    fail('CNYOS_CONTROLLER_RUN_BINDING_MISMATCH');
  }

  const manifest = bundle.manifest;
  if (!isPlainObject(packet.source) || packet.source.repository !== POLICY.sourceRepository ||
    packet.source.commit !== manifest.candidateCommit || packet.source.tree !== manifest.candidateTree ||
    packet.source.functionSourceTree !== manifest.functionSourceTree) {
    fail('CNYOS_CONTROLLER_SOURCE_BINDING_MISMATCH');
  }
  if (!isPlainObject(packet.artifact) ||
    packet.artifact.producerManifestSha256 !== bundle.manifestSha256 ||
    packet.artifact.artifactSha256 !== manifest.artifactSha256 ||
    packet.artifact.fileCount !== manifest.fileCount ||
    packet.artifact.candidateBuildArtifactDigest !== manifest.candidateBuildArtifactDigest ||
    packet.artifact.staticReproducibilityEvidenceSha256 !==
      manifest.staticReproducibilityEvidenceSha256 ||
    packet.artifact.staticArtifactSha256 !== manifest.staticArtifactSha256 ||
    packet.artifact.candidateDependencyLockSha256 !== manifest.candidateDependencyLockSha256 ||
    packet.artifact.stagingConfigSha256 !== manifest.stagingConfigSha256 ||
    packet.artifact.productionDenylistConfigSha256 !==
      manifest.productionDenylistConfigSha256 ||
    packet.artifact.functionBundleManifestSha256 !== manifest.functionBundleManifestSha256 ||
    packet.artifact.functionBundleDependencyLockSha256 !==
      manifest.functionBundleDependencyLockSha256 ||
    packet.artifact.functionSourcesSha256 !== manifest.functionSourcesSha256 ||
    packet.artifact.producerRunId !== runtime.runId ||
    packet.artifact.githubArtifactDigest !== exactSha256(
      env.CNYOS_EXPECTED_GITHUB_ARTIFACT_DIGEST,
      'CNYOS_CONTROLLER_GITHUB_ARTIFACT_DIGEST_INVALID'
    )) {
    fail('CNYOS_CONTROLLER_ARTIFACT_BINDING_MISMATCH');
  }
  assertPolicyTarget(packet.target);
  const protocol = validateProtocolGates(packet, manifest, now);

  const principal = packet.principalProof;
  if (!isPlainObject(principal) || principal.status !== 'passed' ||
    principal.tokenClass !== 'dedicated_staging_only' ||
    typeof principal.subject !== 'string' || principal.subject.trim().length < 3 ||
    principal.inventoryComplete !== true || principal.accessibleSiteCount !== 1 ||
    !Array.isArray(principal.allowedSiteIds) || principal.allowedSiteIds.length !== 1 ||
    principal.allowedSiteIds[0] !== POLICY.target.netlifySiteId ||
    principal.productionAccess !== false) {
    fail('CNYOS_CONTROLLER_PRINCIPAL_PROOF_INVALID');
  }
  assertLeastPrivilegeNetlifyPrincipal(
    principal,
    'CNYOS_CONTROLLER_PRINCIPAL_PROOF_INVALID'
  );
  assertDistinctOpaquePrincipalSubjects(
    principal.subject,
    protocol.deploymentBoundary.rollbackPrincipal.subject
  );
  evidencePointer(principal.evidence, 'CNYOS_CONTROLLER_PRINCIPAL_PROOF_INVALID');
  const principalWindow = boundedFreshWindow(
    principal.verifiedAt,
    principal.expiresAt,
    now,
    'CNYOS_CONTROLLER_PRINCIPAL_PROOF_EXPIRED'
  );

  const review = packet.independentSecurityReview;
  assertExactKeys(review, [
    'status', 'verdict', 'sourceCommit', 'sourceTree', 'artifactSha256',
    'reviewerGitHubLogin', 'reviewerName', 'reviewerRole', 'areas', 'evidence', 'reviewedAt'
  ], 'CNYOS_CONTROLLER_SECURITY_REVIEW_INVALID');
  if (Array.isArray(review.areas)) {
    for (const area of review.areas) {
      assertExactKeys(
        area,
        ['id', 'verdict', 'disposition'],
        'CNYOS_CONTROLLER_SECURITY_REVIEW_INVALID'
      );
    }
  }
  if (!isPlainObject(review) || review.status !== 'passed' || review.verdict !== 'approved' ||
    review.sourceCommit !== manifest.candidateCommit || review.sourceTree !== manifest.candidateTree ||
    review.artifactSha256 !== manifest.artifactSha256 ||
    !GITHUB_LOGIN.test(String(review.reviewerGitHubLogin || '')) ||
    typeof review.reviewerName !== 'string' || review.reviewerName.trim().length < 3 ||
    typeof review.reviewerRole !== 'string' || review.reviewerRole.trim().length < 3 ||
    !Array.isArray(review.areas) || review.areas.length !== REQUIRED_REVIEW_AREAS.length ||
    !review.areas.every((area, index) => isPlainObject(area) &&
      area.id === REQUIRED_REVIEW_AREAS[index] && area.verdict === 'passed' &&
      typeof area.disposition === 'string' && area.disposition.trim().length >= 8)) {
    fail('CNYOS_CONTROLLER_SECURITY_REVIEW_INVALID');
  }
  evidencePointer(review.evidence, 'CNYOS_CONTROLLER_SECURITY_REVIEW_INVALID');
  if (canonicalIsoTimestamp(review.reviewedAt, 'CNYOS_CONTROLLER_SECURITY_REVIEW_INVALID') > now) {
    fail('CNYOS_CONTROLLER_SECURITY_REVIEW_INVALID');
  }

  const risk = packet.managedPlatformRiskAcceptance;
  assertExactKeys(risk, [
    'status', 'scope', 'ownerGitHubLogin', 'ownerName', 'ownerRole', 'projectRef',
    'databaseSystemIdentifier', 'managedDefaultAclScope',
    'managedSupabaseAdminDefaultAclAccepted',
    'functionRemoteByteAttestationUnavailableAccepted', 'currentPublicOwnership',
    'runtimeSetRole', 'rationale', 'driftCheckOwner', 'providerEscalationReference',
    'driftPolicy', 'productionAuthorization', 'evidence', 'acceptedAt', 'nextReviewAt',
    'expiresAt'
  ], 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  assertExactKeys(risk.currentPublicOwnership, [
    'routines', 'relations', 'types', 'evidence'
  ], 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  assertExactKeys(risk.runtimeSetRole, [
    'runtimeAndUntrustedCannotSetRoleToReviewedCreators', 'reviewedCreators', 'evidence'
  ], 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  assertExactKeys(risk.driftPolicy, [
    'blockOnOwnershipDrift', 'blockOnCreatorDrift', 'blockOnRoleAttributeDrift',
    'blockOnRoleMembershipDrift', 'blockOnDefaultAclDrift', 'evidence'
  ], 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  if (!isPlainObject(risk) || risk.status !== 'accepted' || risk.scope !== 'cnyos_staging_only' ||
    !GITHUB_LOGIN.test(String(risk.ownerGitHubLogin || '')) ||
    typeof risk.ownerName !== 'string' || risk.ownerName.trim().length < 3 ||
    typeof risk.ownerRole !== 'string' || risk.ownerRole.trim().length < 3 ||
    risk.projectRef !== POLICY.target.supabaseProjectRef ||
    risk.databaseSystemIdentifier !== POLICY.target.databaseSystemIdentifier ||
    risk.managedDefaultAclScope !== 'supabase_admin function defaults for public only' ||
    risk.managedSupabaseAdminDefaultAclAccepted !== true ||
    risk.functionRemoteByteAttestationUnavailableAccepted !== true ||
    risk.currentPublicOwnership?.routines !== 0 ||
    risk.currentPublicOwnership?.relations !== 0 || risk.currentPublicOwnership?.types !== 0 ||
    risk.runtimeSetRole?.runtimeAndUntrustedCannotSetRoleToReviewedCreators !== true ||
    !Array.isArray(risk.runtimeSetRole?.reviewedCreators) ||
    risk.runtimeSetRole.reviewedCreators.length !== 1 ||
    risk.runtimeSetRole.reviewedCreators[0] !== 'supabase_admin' ||
    typeof risk.rationale !== 'string' || risk.rationale.trim().length < 16 ||
    typeof risk.driftCheckOwner !== 'string' || risk.driftCheckOwner.trim().length < 3 ||
    typeof risk.providerEscalationReference !== 'string' ||
    risk.providerEscalationReference.trim().length < 8 ||
    risk.driftPolicy?.blockOnOwnershipDrift !== true ||
    risk.driftPolicy?.blockOnCreatorDrift !== true ||
    risk.driftPolicy?.blockOnRoleAttributeDrift !== true ||
    risk.driftPolicy?.blockOnRoleMembershipDrift !== true ||
    risk.driftPolicy?.blockOnDefaultAclDrift !== true ||
    risk.productionAuthorization !== false) {
    fail('CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  }
  evidencePointer(risk.evidence, 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  evidencePointer(risk.currentPublicOwnership?.evidence,
    'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  evidencePointer(risk.runtimeSetRole?.evidence,
    'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  evidencePointer(risk.driftPolicy?.evidence,
    'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  const riskAccepted = canonicalIsoTimestamp(risk.acceptedAt, 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  const riskNextReview = canonicalIsoTimestamp(risk.nextReviewAt,
    'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  const riskExpires = canonicalIsoTimestamp(risk.expiresAt, 'CNYOS_CONTROLLER_RISK_ACCEPTANCE_INVALID');
  if (riskAccepted > now || riskNextReview <= now || riskExpires <= now ||
    riskNextReview <= riskAccepted || riskExpires < riskNextReview) {
    fail('CNYOS_CONTROLLER_RISK_ACCEPTANCE_EXPIRED');
  }

  const rollback = packet.rollback;
  assertExactKeys(rollback, [
    'restoreOnAnyPostPublishFailure', 'externalWatchdogRequired',
    'restoreOnlyControllerOwnedDeploy', 'previousDeployId', 'knownGoodEvidence'
  ], 'CNYOS_CONTROLLER_ROLLBACK_AUTHORIZATION_INVALID');
  if (!isPlainObject(rollback) || rollback.restoreOnAnyPostPublishFailure !== true ||
    rollback.externalWatchdogRequired !== true || rollback.restoreOnlyControllerOwnedDeploy !== true) {
    fail('CNYOS_CONTROLLER_ROLLBACK_AUTHORIZATION_INVALID');
  }
  exactDeployId(rollback.previousDeployId, 'CNYOS_CONTROLLER_ROLLBACK_DEPLOY_ID_INVALID');
  evidencePointer(rollback.knownGoodEvidence, 'CNYOS_CONTROLLER_ROLLBACK_AUTHORIZATION_INVALID');

  const authorization = packet.authorization;
  assertExactKeys(authorization, [
    'decision', 'authorizedByGitHubLogin', 'authorizedByName', 'authorizedByRole',
    'authorizedAt', 'expiresAt', 'evidence'
  ], 'CNYOS_CONTROLLER_AUTHORIZATION_DECISION_INVALID');
  if (!isPlainObject(authorization) ||
    authorization.decision !== 'authorize_exact_cnyos_staging_controller_run' ||
    !sameGitHubLogin(authorization.authorizedByGitHubLogin, risk.ownerGitHubLogin) ||
    authorization.authorizedByName !== risk.ownerName ||
    authorization.authorizedByRole !== risk.ownerRole) {
    fail('CNYOS_CONTROLLER_AUTHORIZATION_DECISION_INVALID');
  }
  evidencePointer(authorization.evidence, 'CNYOS_CONTROLLER_AUTHORIZATION_DECISION_INVALID');
  const authorizedAt = canonicalIsoTimestamp(
    authorization.authorizedAt,
    'CNYOS_CONTROLLER_AUTHORIZATION_TIME_INVALID'
  );
  const expiresAt = canonicalIsoTimestamp(
    authorization.expiresAt,
    'CNYOS_CONTROLLER_AUTHORIZATION_TIME_INVALID'
  );
  const maximum = authorizationMaximumMilliseconds();
  if (authorizedAt > now || expiresAt <= now || expiresAt <= authorizedAt ||
    expiresAt.getTime() - authorizedAt.getTime() > maximum ||
    authorizedAt < canonicalIsoTimestamp(manifest.generatedAt, 'CNYOS_PRODUCER_TIME_INVALID') ||
    principalWindow.expiresAt > expiresAt ||
    protocol.deploymentBoundary.expiresAt !== authorization.expiresAt ||
    protocol.deploymentBoundary.rollbackPrincipal.expiresAt !== authorization.expiresAt) {
    fail('CNYOS_CONTROLLER_AUTHORIZATION_EXPIRED');
  }
  if (!sameGitHubLogin(runtime.actor, risk.ownerGitHubLogin) ||
    sameGitHubLogin(review.reviewerGitHubLogin, risk.ownerGitHubLogin)) {
    fail('CNYOS_CONTROLLER_APPROVER_INDEPENDENCE_INVALID');
  }
  return Object.freeze({ review, risk, authorization, rollback, principal, protocol });
}

export async function verifyControllerAuthorization({
  env = process.env,
  now = () => new Date()
} = {}) {
  const runtime = assertControllerRuntime(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_AUTHORIZATION_TIME_INVALID');
  }
  const raw = required(
    env.CNYOS_CONTROLLER_AUTHORIZATION_JSON,
    'CNYOS_CONTROLLER_AUTHORIZATION_JSON_REQUIRED',
    64 * 1024
  );
  const packet = parseJsonObject(raw, 'CNYOS_CONTROLLER_AUTHORIZATION_JSON_INVALID');
  if (raw !== JSON.stringify(packet)) fail('CNYOS_CONTROLLER_AUTHORIZATION_JSON_NONCANONICAL');
  const bundle = await verifyProducerBundle({ env });
  const validated = validateAuthorizationPacket(packet, runtime, bundle, env, observedAt);

  const registryBytes = await readFileBounded(
    required(env.CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH,
      'CNYOS_CONTROLLER_APPROVER_REGISTRY_PATH_REQUIRED', 4096),
    64 * 1024,
    'CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID'
  );
  const registryRaw = registryBytes.toString('utf8');
  const registry = loadRegistry(registryRaw);
  const reviewerKeyId = required(
    packet.signatureKeyIds?.independentSecurityReviewer,
    'CNYOS_CONTROLLER_SIGNATURE_KEY_ID_INVALID',
    200
  );
  const riskKeyId = required(
    packet.signatureKeyIds?.managedPlatformRiskOwner,
    'CNYOS_CONTROLLER_SIGNATURE_KEY_ID_INVALID',
    200
  );
  if (reviewerKeyId === riskKeyId) fail('CNYOS_CONTROLLER_SIGNATURE_KEYS_NOT_INDEPENDENT');
  const reviewerKey = pinnedKey(registry, {
    id: reviewerKeyId,
    role: 'independent_security_reviewer',
    login: validated.review.reviewerGitHubLogin,
    ownerName: validated.review.reviewerName
  });
  const riskKey = pinnedKey(registry, {
    id: riskKeyId,
    role: 'managed_platform_risk_owner',
    login: validated.risk.ownerGitHubLogin,
    ownerName: validated.risk.ownerName
  });
  if (reviewerKey.record.spkiSha256 === riskKey.record.spkiSha256) {
    fail('CNYOS_CONTROLLER_SIGNATURE_KEYS_NOT_INDEPENDENT');
  }
  const reviewerSignature = decodeSignature(env.CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64);
  const riskSignature = decodeSignature(env.CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64);
  if (!crypto.verify(null, Buffer.from(raw), reviewerKey.publicKey, reviewerSignature) ||
    !crypto.verify(null, Buffer.from(raw), riskKey.publicKey, riskSignature)) {
    fail('CNYOS_CONTROLLER_SIGNATURE_INVALID');
  }

  const knownGoodBytes = await readFileBounded(
    required(env.CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_PATH_REQUIRED', 4096),
    4 * 1024 * 1024,
    'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID'
  );
  if (sha256(knownGoodBytes) !== validated.rollback.knownGoodEvidence.sha256) {
    fail('CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_DIGEST_MISMATCH');
  }
  let knownGood;
  try { knownGood = JSON.parse(knownGoodBytes.toString('utf8')); }
  catch { fail('CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID'); }
  validateKnownGoodEvidence(knownGood, validated.rollback);

  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_authorization_validation',
    status: 'authorized',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    verifiedAt: observedAt.toISOString(),
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerWorkflowPath: runtime.workflowPath,
    controllerRunId: runtime.runId,
    controllerRunAttempt: 1,
    githubActor: runtime.actor,
    dispatchNonce: packet.controller.dispatchNonce,
    policySha256: POLICY_SHA256,
    source: packet.source,
    artifact: packet.artifact,
    target: packet.target,
    previousDeployId: validated.rollback.previousDeployId,
    knownGoodRollbackEvidenceSha256: validated.rollback.knownGoodEvidence.sha256,
    independentReviewerGitHubLogin: validated.review.reviewerGitHubLogin,
    namedRiskOwnerGitHubLogin: validated.risk.ownerGitHubLogin,
    functionRemoteByteAttestationUnavailableAccepted:
      validated.risk.functionRemoteByteAttestationUnavailableAccepted,
    authorizationExpiresAt: validated.authorization.expiresAt,
    principalProofVerifiedAt: validated.principal.verifiedAt,
    principalProofExpiresAt: validated.principal.expiresAt,
    deploymentControlBoundaryObservedAt:
      validated.protocol.deploymentBoundary.observedAt,
    deploymentControlBoundaryExpiresAt:
      validated.protocol.deploymentBoundary.expiresAt,
    netlifyPrincipalSubject: validated.principal.subject,
    rollbackNetlifyPrincipalSubject:
      validated.protocol.deploymentBoundary.rollbackPrincipal.subject,
    netlifyPrincipalBoundary: Object.freeze({
      subject: validated.principal.subject,
      membershipRole: validated.principal.membershipRole,
      teamOwner: validated.principal.teamOwner,
      teamAdministrator: validated.principal.teamAdministrator,
      siteAccessScope: validated.principal.siteAccessScope,
      accountConfigurationCapabilityAbsent:
        validated.principal.accountConfigurationCapabilityAbsent,
      teamAdministrationCapabilityAbsent:
        validated.principal.teamAdministrationCapabilityAbsent,
      deployCapabilityVerified: validated.principal.deployCapabilityVerified,
      membershipEvidenceSha256: validated.principal.membershipEvidence.sha256
    }),
    rollbackNetlifyPrincipalBoundary: Object.freeze({
      subject: validated.protocol.deploymentBoundary.rollbackPrincipal.subject,
      membershipRole: validated.protocol.deploymentBoundary.rollbackPrincipal.membershipRole,
      teamOwner: validated.protocol.deploymentBoundary.rollbackPrincipal.teamOwner,
      teamAdministrator:
        validated.protocol.deploymentBoundary.rollbackPrincipal.teamAdministrator,
      siteAccessScope:
        validated.protocol.deploymentBoundary.rollbackPrincipal.siteAccessScope,
      accountConfigurationCapabilityAbsent:
        validated.protocol.deploymentBoundary.rollbackPrincipal.accountConfigurationCapabilityAbsent,
      teamAdministrationCapabilityAbsent:
        validated.protocol.deploymentBoundary.rollbackPrincipal.teamAdministrationCapabilityAbsent,
      deployCapabilityVerified:
        validated.protocol.deploymentBoundary.rollbackPrincipal.deployCapabilityVerified,
      restoreCapabilityVerified:
        validated.protocol.deploymentBoundary.rollbackPrincipal.restoreCapabilityVerified,
      verifiedAt: validated.protocol.deploymentBoundary.rollbackPrincipal.verifiedAt,
      expiresAt: validated.protocol.deploymentBoundary.rollbackPrincipal.expiresAt,
      membershipEvidenceSha256:
        validated.protocol.deploymentBoundary.rollbackPrincipal.membershipEvidence.sha256
    }),
    targetSiteAndPublisherExclusion: Object.freeze({
      productionNetlifySiteId:
        validated.protocol.deploymentBoundary.productionNetlifySiteId,
      productionNetlifyOrigin:
        validated.protocol.deploymentBoundary.productionNetlifyOrigin,
      targetSiteClassifiedStagingOnly:
        validated.protocol.deploymentBoundary.targetSiteClassifiedStagingOnly,
      realPatientDataAbsent: validated.protocol.deploymentBoundary.realPatientDataAbsent,
      legacyPublisherInventoryComplete:
        validated.protocol.deploymentBoundary.legacyPublisherInventoryComplete,
      candidateRepositoryProductionWorkflowTargetDenied:
        validated.protocol.deploymentBoundary.candidateRepositoryProductionWorkflowTargetDenied,
      candidateRepositoryPreviewWorkflowTargetDenied:
        validated.protocol.deploymentBoundary.candidateRepositoryPreviewWorkflowTargetDenied,
      allAlternatePublisherCredentialsTargetDenied:
        validated.protocol.deploymentBoundary.allAlternatePublisherCredentialsTargetDenied,
      currentCnyosProductionMappingConflictResolved:
        validated.protocol.deploymentBoundary.currentCnyosProductionMappingConflictResolved,
      evidenceSha256: validated.protocol.deploymentBoundary.evidence.sha256
    }),
    exclusivePublisherEnforced: validated.protocol.deploymentBoundary.exclusivePublisherEnforced,
    privateDraftAccessEnforced: validated.protocol.deploymentBoundary.privateDraftAccessEnforced,
    failedDraftCleanupEnforced: validated.protocol.deploymentBoundary.failedDraftCleanupEnforced,
    githubReleaseBoundary: Object.freeze({
      repository: POLICY.sourceRepository,
      pr36: Object.freeze({
        number: POLICY.githubReleaseBoundary.pr36Number,
        url: `${POLICY.githubReleaseBoundary.webOrigin}/${POLICY.sourceRepository}/pull/${POLICY.githubReleaseBoundary.pr36Number}`,
        headRef: validated.protocol.promotion.pr36HeadRef,
        headCommit: validated.protocol.promotion.pr36HeadCommit,
        baseRef: validated.protocol.promotion.pr36BaseRef,
        baseCommit: validated.protocol.promotion.pr36BaseCommit,
        requiredState: validated.protocol.promotion.pr36RequiredState
      }),
      promotion: Object.freeze({
        number: Number(validated.protocol.promotion.promotionPullRequest.split('/').at(-1)),
        url: validated.protocol.promotion.promotionPullRequest,
        headRef: validated.protocol.promotion.promotionHeadRef,
        headCommit: validated.protocol.promotion.promotionHeadCommit,
        headTree: validated.protocol.promotion.sourceTree,
        baseRef: validated.protocol.promotion.promotionBaseRef,
        baseCommit: validated.protocol.promotion.promotionBaseCommit,
        requiredState: validated.protocol.promotion.promotionRequiredState,
        orderedMigrationEvidenceSha256: validated.protocol.promotion.evidence.sha256
      }),
      independentReviewerGitHubLogin: validated.review.reviewerGitHubLogin
    }),
    authorizationPacketSha256: sha256(raw),
    approverRegistrySha256: sha256(registryRaw),
    signatureKeyIds: Object.freeze({
      independentSecurityReviewer: reviewerKeyId,
      managedPlatformRiskOwner: riskKeyId
    }),
    signatureSha256: Object.freeze({
      independentSecurityReviewer: sha256(reviewerSignature),
      managedPlatformRiskOwner: sha256(riskSignature)
    })
  });
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  const archivedApproverKeys = Object.freeze([
    Object.freeze({
      id: reviewerKey.record.id,
      role: reviewerKey.record.role,
      githubLogin: reviewerKey.record.githubLogin,
      ownerName: reviewerKey.record.ownerName,
      publicKeyPem: reviewerKey.record.publicKeyPem,
      spkiSha256: reviewerKey.record.spkiSha256
    }),
    Object.freeze({
      id: riskKey.record.id,
      role: riskKey.record.role,
      githubLogin: riskKey.record.githubLogin,
      ownerName: riskKey.record.ownerName,
      publicKeyPem: riskKey.record.publicKeyPem,
      spkiSha256: riskKey.record.spkiSha256
    })
  ]);
  const verificationBundle = Object.freeze({
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_authorization_verification_bundle',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    secretValuesSerialized: false,
    authorizationPacketSha256: sha256(raw),
    authorizationDecision: Object.freeze({
      decision: validated.authorization.decision,
      authorizedByGitHubLogin: validated.authorization.authorizedByGitHubLogin,
      authorizedAt: validated.authorization.authorizedAt,
      expiresAt: validated.authorization.expiresAt,
      controllerRunId: runtime.runId,
      dispatchNonce: packet.controller.dispatchNonce,
      candidateCommit: packet.source.commit,
      candidateTree: packet.source.tree,
      artifactSha256: packet.artifact.artifactSha256
    }),
    approverRegistrySha256: sha256(registryRaw),
    approverPublicKeys: archivedApproverKeys,
    signatureKeyIds: evidence.signatureKeyIds,
    signatureSha256: evidence.signatureSha256,
    knownGoodEvidence: Object.freeze({
      evidenceType: knownGood.evidenceType,
      sourceRepository: knownGood.source.repository,
      sourceCommit: knownGood.source.commit,
      netlifySiteId: knownGood.target.netlifySiteId,
      netlifyOrigin: knownGood.target.netlifyOrigin,
      netlifyDeployId: knownGood.netlifyDeployId
    }),
    knownGoodEvidenceSha256: sha256(knownGoodBytes),
    validationEvidence: evidence
  });
  const verificationBundlePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH,
      'CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH_REQUIRED', 4096),
    verificationBundle
  );
  return Object.freeze({ evidence, evidencePath, verificationBundlePath, bundle });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  verifyControllerAuthorization().then(async result => {
    process.stdout.write(`${JSON.stringify({
      evidencePath: result.evidencePath,
      verificationBundlePath: result.verificationBundlePath,
      authorizationEvidenceSha256: sha256(await fs.readFile(result.evidencePath)),
      artifactSha256: result.evidence.artifact.artifactSha256,
      candidateCommit: result.evidence.source.commit
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_CONTROLLER_AUTHORIZATION_FAILED')}\n`);
    process.exitCode = 1;
  });
}
