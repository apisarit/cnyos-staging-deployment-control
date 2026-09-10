import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY,
  POLICY_SHA256,
  assertControllerRuntime,
  assertExactKeys,
  canonicalIsoTimestamp,
  decodeNonce,
  exactDeployId,
  fail,
  isPlainObject,
  parseJsonObject,
  readRegularFileStable,
  recentCanonicalTimestamp,
  required,
  safeOrigin,
  sha256
} from './policy.mjs';

const MAX_AUTHORIZATION_BYTES = 64 * 1024;
const MAX_REGISTRY_BYTES = 64 * 1024;
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
const MAX_KNOWN_GOOD_BYTES = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 512 * 1024;
const MAX_OIDC_RESPONSE_BYTES = 64 * 1024;

const FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ALL_PROXY',
  'DATABASE_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NETLIFY_AUTH_TOKEN',
  'NODE_EXTRA_CA_CERTS',
  'NODE_USE_ENV_PROXY',
  'PGPASSWORD',
  'POSTGRES_PASSWORD',
  'SSL_CERT_FILE',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_DB_PASSWORD',
  'SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_DRAFT_LIFECYCLE_BROKER_URL',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_NETLIFY_AUTHORITY_BROKER_URL',
  'CNYOS_NETLIFY_PRINCIPAL_MEMBERSHIP_BROKER_URL',
  'CNYOS_NETLIFY_PUBLISH_BROKER_URL',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'all_proxy',
  'http_proxy',
  'https_proxy'
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
const SOURCE_KEYS = Object.freeze(['repository', 'commit', 'tree', 'functionSourceTree']);
const ARTIFACT_KEYS = Object.freeze([
  'producerManifestSha256', 'artifactSha256', 'fileCount',
  'candidateBuildArtifactDigest', 'staticReproducibilityEvidenceSha256',
  'staticArtifactSha256', 'candidateDependencyLockSha256', 'stagingConfigSha256',
  'productionDenylistConfigSha256', 'functionBundleManifestSha256',
  'functionBundleDependencyLockSha256', 'functionSourcesSha256', 'producerRunId',
  'githubArtifactDigest'
]);
const ROLLBACK_KEYS = Object.freeze([
  'restoreOnAnyPostPublishFailure', 'externalWatchdogRequired',
  'restoreOnlyControllerOwnedDeploy', 'previousDeployId', 'knownGoodEvidence'
]);
const SIGNER_SLOT_KEYS = Object.freeze([
  'independentSecurityReviewer', 'managedPlatformRiskOwner'
]);
const BUNDLE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'scope', 'productionAuthorization',
  'secretValuesSerialized', 'authorizationPacketSha256', 'authorizationDecision',
  'approverRegistrySha256', 'approverPublicKeys', 'signatureKeyIds',
  'signatureSha256', 'knownGoodEvidence', 'knownGoodEvidenceSha256',
  'validationEvidence'
]);
const BUNDLE_DECISION_KEYS = Object.freeze([
  'decision', 'authorizedByGitHubLogin', 'authorizedAt', 'expiresAt',
  'controllerRunId', 'dispatchNonce', 'candidateCommit', 'candidateTree',
  'artifactSha256'
]);
const BUNDLE_KNOWN_GOOD_KEYS = Object.freeze([
  'evidenceType', 'sourceRepository', 'sourceCommit', 'netlifySiteId',
  'netlifyOrigin', 'netlifyDeployId'
]);
const VALIDATION_EVIDENCE_KEYS = Object.freeze([
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
const AUTHORIZATION_DECISION_KEYS = Object.freeze([
  'decision', 'authorizedByGitHubLogin', 'authorizedByName', 'authorizedByRole',
  'authorizedAt', 'expiresAt', 'evidence'
]);
const EVIDENCE_POINTER_KEYS = Object.freeze(['sha256', 'reference']);
const APPROVER_REGISTRY_KEYS = Object.freeze(['schemaVersion', 'environment', 'keys']);
const APPROVER_KEY_KEYS = Object.freeze([
  'id', 'role', 'githubLogin', 'ownerName', 'publicKeyPem', 'spkiSha256'
]);
const RECEIPT_ENVELOPE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'receipt', 'brokerSignature'
]);
const RECEIPT_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'depositId', 'depositSequence',
  'depositRequestSha256', 'broker', 'controller', 'source', 'artifact', 'target',
  'authorizationMaterial', 'depositSemantics', 'recoveryMaterial',
  'retrievalBoundary', 'depositedAt', 'retentionUntil'
]);
const RECEIPT_BROKER_KEYS = Object.freeze([
  'origin', 'policyId', 'policySha256', 'receiptSigningKeyId',
  'receiptSigningSpkiSha256'
]);
const RECEIPT_CONTROLLER_KEYS = Object.freeze([
  'repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
  'runAttempt', 'dispatchNonce', 'policySha256'
]);
const RECEIPT_TARGET_KEYS = Object.freeze([
  'netlifySiteId', 'netlifyOrigin', 'supabaseProjectRef', 'databaseSystemIdentifier',
  'targetSha256', 'previousDeployId'
]);
const RECEIPT_AUTHORIZATION_KEYS = Object.freeze([
  'authorizationPacketSha256', 'authorizationBundleSha256',
  'approverRegistrySha256', 'independentSecurityReviewerKeyId',
  'independentSecurityReviewerSignatureSha256', 'managedPlatformRiskOwnerKeyId',
  'managedPlatformRiskOwnerSignatureSha256', 'knownGoodEvidenceSha256'
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

function activated(value, code, maximum = 500) {
  const result = required(value, code, maximum);
  if (result !== value || /^__[A-Z0-9_]+__$/.test(result)) fail(code);
  return result;
}

function assertAbsentEnvironmentNames(env) {
  for (const name of FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) {
      fail('CNYOS_ROLLBACK_ATTESTATION_CREDENTIAL_ISOLATION_INVALID');
    }
  }
}

function exactIdentifier(value, expression, code, maximum = 200) {
  const result = activated(value, code, maximum);
  if (!expression.test(result)) fail(code);
  return result;
}

function canonicalSha256(value, code) {
  const result = activated(value, code, 64);
  if (!/^[0-9a-f]{64}$/.test(result)) fail(code);
  return result;
}

function strictBase64(value, code, maximum = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    fail(code);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail(code);
  return bytes;
}

function decodeEd25519Signature(value, code) {
  const bytes = strictBase64(value, code);
  if (bytes.byteLength !== 64) fail(code);
  return bytes;
}

function parseUtf8Object(bytes, code) {
  const raw = bytes.toString('utf8');
  if (!Buffer.from(raw, 'utf8').equals(bytes)) fail(code);
  return Object.freeze({ raw, value: parseJsonObject(raw, code) });
}

function canonicalAuthorization(value, code) {
  if (typeof value !== 'string' || value.length < 2 ||
    Buffer.byteLength(value) > MAX_AUTHORIZATION_BYTES) fail(code);
  const parsed = parseJsonObject(value, code);
  if (value !== JSON.stringify(parsed)) fail(`${code}_NONCANONICAL`);
  return Object.freeze({ raw: value, bytes: Buffer.from(value), value: parsed });
}

function strictPublicKey(pem, expectedSpkiSha256, code) {
  if (typeof pem !== 'string' || pem.length > 2048 ||
    !pem.startsWith('-----BEGIN PUBLIC KEY-----\n') ||
    !pem.endsWith('-----END PUBLIC KEY-----\n')) fail(code);
  let publicKey;
  try { publicKey = crypto.createPublicKey(pem); }
  catch { fail(code); }
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519' ||
    publicKey.export({ type: 'spki', format: 'pem' }) !== pem ||
    sha256(publicKey.export({ type: 'spki', format: 'der' })) !==
      canonicalSha256(expectedSpkiSha256, code)) fail(code);
  return publicKey;
}

function strictAudience(value, code) {
  const audience = activated(value, code, 1000);
  let url;
  try { url = new URL(audience); }
  catch { fail(code); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
    url.search || url.hash || url.origin.toLowerCase() !== url.origin ||
    url.href !== audience) fail(code);
  return audience;
}

function strictOperationPath(value, code) {
  const operationPath = activated(value, code, 500);
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/.test(operationPath) ||
    operationPath.includes('//') || operationPath.endsWith('/') ||
    new URL(operationPath, 'https://boundary.invalid').pathname !== operationPath) fail(code);
  return operationPath;
}

function rollbackTrustRoot() {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_BROKER_POLICY_INVALID';
  const policy = POLICY.rollbackAttestationBroker;
  if (!isPlainObject(policy) || policy.maximumReceiptAgeMinutes !== 10 ||
    !Number.isSafeInteger(policy.minimumRetentionDays) ||
    policy.minimumRetentionDays < 365 || policy.minimumRetentionDays > 3650) fail(code);
  const origin = safeOrigin(activated(policy.origin, code), code);
  if (origin !== policy.origin) fail(code);
  const trust = {
    origin,
    endpoint: new URL(origin),
    policyId: exactIdentifier(policy.policyId, /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/, code),
    policySha256: canonicalSha256(policy.policySha256, code),
    receiptSigningKeyId: exactIdentifier(
      policy.receiptSigningKeyId,
      /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/,
      code
    ),
    receiptSigningSpkiSha256: canonicalSha256(policy.receiptSigningSpkiSha256, code),
    oidcAudience: strictAudience(policy.oidcAudience, code),
    maximumReceiptAgeMs: policy.maximumReceiptAgeMinutes * 60_000,
    minimumRetentionDays: policy.minimumRetentionDays,
    minimumRetentionMs: policy.minimumRetentionDays * 86_400_000
  };
  trust.publicKey = strictPublicKey(
    policy.receiptSigningPublicKeyPem,
    trust.receiptSigningSpkiSha256,
    code
  );
  return Object.freeze(trust);
}

function externalReconciliationPolicy() {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_RECONCILIATION_POLICY_INVALID';
  const policy = POLICY.externalReconciliationBroker;
  if (!isPlainObject(policy)) fail(code);
  const origin = safeOrigin(activated(policy.origin, code), code);
  if (origin !== policy.origin) fail(code);
  const signingKeySpkiSha256 = canonicalSha256(policy.signingKeySpkiSha256, code);
  strictPublicKey(policy.signingPublicKeyPem, signingKeySpkiSha256, code);
  if (!Number.isSafeInteger(policy.maximumEvidenceAgeMinutes) ||
    policy.maximumEvidenceAgeMinutes < 1 || policy.maximumEvidenceAgeMinutes > 30 ||
    !Number.isSafeInteger(policy.maximumResponseBytes) ||
    policy.maximumResponseBytes < 1024 ||
    policy.maximumResponseBytes > 4 * 1024 * 1024) fail(code);
  return Object.freeze({
    origin,
    operationPath: strictOperationPath(policy.operationPath, code),
    operationDomain: exactIdentifier(
      policy.operationDomain,
      /^[a-z][a-z0-9_]{7,99}$/,
      code,
      100
    ),
    policyId: exactIdentifier(policy.policyId, /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/, code),
    policySha256: canonicalSha256(policy.policySha256, code),
    signingKeyId: exactIdentifier(
      policy.signingKeyId,
      /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/,
      code
    ),
    signingKeySpkiSha256,
    oidcAudience: strictAudience(policy.oidcAudience, code),
    maximumEvidenceAgeMinutes: policy.maximumEvidenceAgeMinutes,
    maximumResponseBytes: policy.maximumResponseBytes
  });
}

function assertEndpoint(configured, trust) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_BROKER_URL_INVALID';
  const value = activated(configured, code, 1000);
  if (value !== trust.origin || safeOrigin(value, code) !== trust.origin) fail(code);
  return trust.endpoint;
}

function validateRegistry(registryBytes) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_APPROVER_REGISTRY_INVALID';
  const { value } = parseUtf8Object(registryBytes, code);
  assertExactKeys(value, APPROVER_REGISTRY_KEYS, code);
  if (value.schemaVersion !== 1 || value.environment !== POLICY.target.environment ||
    !Array.isArray(value.keys) || value.keys.length < 2 || value.keys.length > 100) fail(code);
  const records = [];
  const ids = new Set();
  const fingerprints = new Set();
  for (const record of value.keys) {
    assertExactKeys(record, APPROVER_KEY_KEYS, code);
    const id = exactIdentifier(record.id, /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/, code);
    if (!['independent_security_reviewer', 'managed_platform_risk_owner']
      .includes(record.role) || typeof record.githubLogin !== 'string' ||
      !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(record.githubLogin) ||
      typeof record.ownerName !== 'string' || record.ownerName.length < 1 ||
      record.ownerName.length > 200 || record.ownerName !== record.ownerName.trim() ||
      /[\u0000-\u001f\u007f]/.test(record.ownerName)) fail(code);
    const publicKey = strictPublicKey(record.publicKeyPem, record.spkiSha256, code);
    if (ids.has(id) || fingerprints.has(record.spkiSha256)) fail(code);
    ids.add(id);
    fingerprints.add(record.spkiSha256);
    records.push(Object.freeze({ record, publicKey }));
  }
  return Object.freeze({ value, records });
}

function selectedRegistryKey(registry, id, role, code) {
  const matches = registry.records.filter(item => item.record.id === id);
  if (matches.length !== 1 || matches[0].record.role !== role) fail(code);
  return matches[0];
}

function validateKnownGood(bytes, packet, bundle, previousDeployId) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_KNOWN_GOOD_EVIDENCE_INVALID';
  const { value } = parseUtf8Object(bytes, code);
  if (!isPlainObject(value) || value.schemaVersion !== 1 || value.status !== 'passed' ||
    !['cnyos_staging_controller_final_release',
      'cnyos_staging_controller_bootstrap_known_good'].includes(value.evidenceType) ||
    value.scope !== 'cnyos_staging_only' || value.productionAuthorization !== false ||
    value.realPatientDataAuthorized !== false ||
    value.controllerRepository !== POLICY.controller.repository ||
    value.policySha256 !== POLICY_SHA256 ||
    value.source?.repository !== POLICY.sourceRepository ||
    !/^[0-9a-f]{40}$/.test(String(value.source?.commit || '')) ||
    !isDeepStrictEqual(value.target, POLICY.target) ||
    value.netlifyDeployId !== previousDeployId ||
    packet.rollback.knownGoodEvidence?.sha256 !== sha256(bytes) ||
    bundle.knownGoodEvidenceSha256 !== sha256(bytes) ||
    bundle.knownGoodEvidence?.evidenceType !== value.evidenceType ||
    bundle.knownGoodEvidence?.sourceRepository !== value.source.repository ||
    bundle.knownGoodEvidence?.sourceCommit !== value.source.commit ||
    bundle.knownGoodEvidence?.netlifySiteId !== value.target.netlifySiteId ||
    bundle.knownGoodEvidence?.netlifyOrigin !== value.target.netlifyOrigin ||
    bundle.knownGoodEvidence?.netlifyDeployId !== value.netlifyDeployId) fail(code);
  exactDeployId(value.netlifyDeployId, code);
  return value;
}

function validateAuthorizationMaterial({
  env, runtime, observedAt, authorization, bundleBytes, registryBytes, knownGoodBytes,
  reviewerSignature, riskSignature
}) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_MATERIAL_INVALID';
  const packet = authorization.value;
  assertExactKeys(packet, AUTHORIZATION_PACKET_KEYS, code);
  assertExactKeys(packet.controller, AUTHORIZATION_CONTROLLER_KEYS, code);
  assertExactKeys(packet.source, SOURCE_KEYS, code);
  assertExactKeys(packet.artifact, ARTIFACT_KEYS, code);
  assertExactKeys(packet.target, Object.keys(POLICY.target), code);
  assertExactKeys(packet.rollback, ROLLBACK_KEYS, code);
  assertExactKeys(packet.rollback.knownGoodEvidence, EVIDENCE_POINTER_KEYS, code);
  assertExactKeys(packet.signatureKeyIds, SIGNER_SLOT_KEYS, code);
  assertExactKeys(packet.authorization, AUTHORIZATION_DECISION_KEYS, code);
  assertExactKeys(packet.authorization.evidence, EVIDENCE_POINTER_KEYS, code);
  if (packet.schemaVersion !== 3 ||
    packet.evidenceType !== 'cnyos_staging_controller_authorization' ||
    packet.productionAuthorization !== false || packet.realPatientDataAuthorized !== false ||
    packet.controller.repository !== runtime.repository ||
    packet.controller.ref !== runtime.ref || packet.controller.commit !== runtime.commit ||
    packet.controller.workflowPath !== runtime.workflowPath ||
    packet.controller.workflowRef !== runtime.workflowRef ||
    packet.controller.runId !== runtime.runId || packet.controller.runAttempt !== 1 ||
    packet.controller.dispatchNonce !== decodeNonce(env.CNYOS_DISPATCH_NONCE).value ||
    packet.source.repository !== POLICY.sourceRepository ||
    !/^[0-9a-f]{40}$/.test(packet.source.commit) ||
    !/^[0-9a-f]{40}$/.test(packet.source.tree) ||
    !/^[0-9a-f]{40}$/.test(packet.source.functionSourceTree) ||
    !Number.isSafeInteger(packet.artifact.fileCount) || packet.artifact.fileCount < 1 ||
    !Object.entries(packet.artifact).every(([name, value]) =>
      ['fileCount', 'producerRunId'].includes(name) || /^[0-9a-f]{64}$/.test(String(value))) ||
    String(packet.artifact.producerRunId) !== runtime.runId ||
    !isDeepStrictEqual(packet.target, POLICY.target) ||
    packet.rollback.restoreOnAnyPostPublishFailure !== true ||
    packet.rollback.externalWatchdogRequired !== true ||
    packet.rollback.restoreOnlyControllerOwnedDeploy !== true ||
    packet.authorization.decision !== 'authorize_exact_cnyos_staging_controller_run' ||
    required(packet.authorization.authorizedByGitHubLogin, code, 100) !==
      packet.authorization.authorizedByGitHubLogin ||
    required(packet.authorization.authorizedByName, code, 200) !==
      packet.authorization.authorizedByName ||
    required(packet.authorization.authorizedByRole, code, 200) !==
      packet.authorization.authorizedByRole ||
    required(packet.rollback.knownGoodEvidence.reference, code, 500) !==
      packet.rollback.knownGoodEvidence.reference ||
    !/^[0-9a-f]{64}$/.test(String(packet.authorization.evidence.sha256 || '')) ||
    required(packet.authorization.evidence.reference, code, 500) !==
      packet.authorization.evidence.reference) fail(code);
  const previousDeployId = exactDeployId(packet.rollback.previousDeployId, code);

  const bundleDocument = parseUtf8Object(bundleBytes, code);
  const bundle = bundleDocument.value;
  assertExactKeys(bundle, BUNDLE_KEYS, code);
  assertExactKeys(bundle.authorizationDecision, BUNDLE_DECISION_KEYS, code);
  assertExactKeys(bundle.knownGoodEvidence, BUNDLE_KNOWN_GOOD_KEYS, code);
  assertExactKeys(bundle.signatureKeyIds, SIGNER_SLOT_KEYS, code);
  assertExactKeys(bundle.signatureSha256, SIGNER_SLOT_KEYS, code);
  const validation = bundle.validationEvidence;
  assertExactKeys(validation, VALIDATION_EVIDENCE_KEYS, code);
  if (bundle.schemaVersion !== 2 ||
    bundle.evidenceType !== 'cnyos_staging_controller_authorization_verification_bundle' ||
    bundle.scope !== 'cnyos_staging_only' || bundle.productionAuthorization !== false ||
    bundle.secretValuesSerialized !== false || !isPlainObject(validation) ||
    validation.schemaVersion !== 1 ||
    validation.evidenceType !== 'cnyos_staging_controller_authorization_validation' ||
    validation.status !== 'authorized' || validation.scope !== 'cnyos_staging_only' ||
    validation.productionAuthorization !== false ||
    validation.realPatientDataAuthorized !== false ||
    validation.controllerRepository !== runtime.repository ||
    validation.controllerRef !== runtime.ref ||
    validation.controllerCommit !== runtime.commit ||
    validation.controllerWorkflowPath !== runtime.workflowPath ||
    validation.controllerRunId !== runtime.runId || validation.controllerRunAttempt !== 1 ||
    validation.dispatchNonce !== packet.controller.dispatchNonce ||
    validation.policySha256 !== POLICY_SHA256 ||
    validation.githubActor !== runtime.actor ||
    !isDeepStrictEqual(validation.source, packet.source) ||
    !isDeepStrictEqual(validation.artifact, packet.artifact) ||
    !isDeepStrictEqual(validation.target, packet.target) ||
    validation.previousDeployId !== previousDeployId ||
    validation.knownGoodRollbackEvidenceSha256 !== packet.rollback.knownGoodEvidence?.sha256 ||
    bundle.authorizationPacketSha256 !== sha256(authorization.bytes) ||
    validation.authorizationPacketSha256 !== sha256(authorization.bytes) ||
    bundle.authorizationDecision.decision !==
      'authorize_exact_cnyos_staging_controller_run' ||
    bundle.authorizationDecision.authorizedByGitHubLogin !==
      packet.authorization.authorizedByGitHubLogin ||
    bundle.authorizationDecision.authorizedAt !== packet.authorization.authorizedAt ||
    bundle.authorizationDecision.expiresAt !== packet.authorization.expiresAt ||
    bundle.authorizationDecision.controllerRunId !== runtime.runId ||
    bundle.authorizationDecision.dispatchNonce !== packet.controller.dispatchNonce ||
    bundle.authorizationDecision.candidateCommit !== packet.source.commit ||
    bundle.authorizationDecision.candidateTree !== packet.source.tree ||
    bundle.authorizationDecision.artifactSha256 !== packet.artifact.artifactSha256 ||
    validation.authorizationExpiresAt !== packet.authorization.expiresAt ||
    String(validation.independentReviewerGitHubLogin || '').toLowerCase() !==
      String(packet.independentSecurityReview?.reviewerGitHubLogin || '').toLowerCase() ||
    String(validation.namedRiskOwnerGitHubLogin || '').toLowerCase() !==
      String(packet.managedPlatformRiskAcceptance?.ownerGitHubLogin || '').toLowerCase() ||
    !isDeepStrictEqual(bundle.signatureKeyIds, packet.signatureKeyIds) ||
    !isDeepStrictEqual(bundle.signatureKeyIds, validation.signatureKeyIds) ||
    !isDeepStrictEqual(bundle.signatureSha256, validation.signatureSha256) ||
    bundle.approverRegistrySha256 !== sha256(registryBytes) ||
    bundle.knownGoodEvidenceSha256 !== sha256(knownGoodBytes)) fail(code);

  const verifiedAt = recentCanonicalTimestamp(
    validation.verifiedAt,
    observedAt,
    POLICY.authorization.maximumLifetimeMinutes * 60_000,
    code
  );
  const authorizedAt = canonicalIsoTimestamp(bundle.authorizationDecision.authorizedAt, code);
  const expiresAt = canonicalIsoTimestamp(bundle.authorizationDecision.expiresAt, code);
  if (authorizedAt > verifiedAt || expiresAt <= observedAt || expiresAt <= authorizedAt ||
    expiresAt.getTime() - authorizedAt.getTime() >
      POLICY.authorization.maximumLifetimeMinutes * 60_000) fail(code);

  const external = packet.deploymentControlBoundary?.externalRollbackReconciliationBroker;
  if (!isPlainObject(external) ||
    external.policyId !== POLICY.externalReconciliationBroker.policyId ||
    external.policySha256 !== POLICY.externalReconciliationBroker.policySha256 ||
    external.targetControllerRepository !== runtime.repository ||
    external.targetControllerRef !== runtime.ref ||
    external.targetControllerWorkflowPath !== runtime.workflowPath ||
    external.targetControllerRunId !== runtime.runId ||
    external.targetControllerRunAttempt !== 1 ||
    external.targetControllerCommit !== runtime.commit ||
    external.targetDispatchNonce !== packet.controller.dispatchNonce ||
    external.targetNetlifySiteId !== POLICY.target.netlifySiteId) fail(code);

  const registry = validateRegistry(registryBytes);
  const reviewerKey = selectedRegistryKey(
    registry,
    packet.signatureKeyIds.independentSecurityReviewer,
    'independent_security_reviewer',
    code
  );
  const riskKey = selectedRegistryKey(
    registry,
    packet.signatureKeyIds.managedPlatformRiskOwner,
    'managed_platform_risk_owner',
    code
  );
  if (reviewerKey.record.spkiSha256 === riskKey.record.spkiSha256 ||
    reviewerKey.record.githubLogin.toLowerCase() !==
      String(packet.independentSecurityReview?.reviewerGitHubLogin || '').toLowerCase() ||
    reviewerKey.record.ownerName !== packet.independentSecurityReview?.reviewerName ||
    riskKey.record.githubLogin.toLowerCase() !==
      String(packet.managedPlatformRiskAcceptance?.ownerGitHubLogin || '').toLowerCase() ||
    riskKey.record.ownerName !== packet.managedPlatformRiskAcceptance?.ownerName ||
    bundle.signatureSha256.independentSecurityReviewer !== sha256(reviewerSignature) ||
    bundle.signatureSha256.managedPlatformRiskOwner !== sha256(riskSignature) ||
    !crypto.verify(null, authorization.bytes, reviewerKey.publicKey, reviewerSignature) ||
    !crypto.verify(null, authorization.bytes, riskKey.publicKey, riskSignature)) fail(code);

  if (!Array.isArray(bundle.approverPublicKeys) || bundle.approverPublicKeys.length !== 2) {
    fail(code);
  }
  const expectedArchivedKeys = [reviewerKey.record, riskKey.record].map(record => ({
    id: record.id,
    role: record.role,
    githubLogin: record.githubLogin,
    ownerName: record.ownerName,
    publicKeyPem: record.publicKeyPem,
    spkiSha256: record.spkiSha256
  }));
  if (!isDeepStrictEqual(bundle.approverPublicKeys, expectedArchivedKeys)) fail(code);
  validateKnownGood(knownGoodBytes, packet, bundle, previousDeployId);
  return Object.freeze({ packet, bundle, validation, previousDeployId });
}

function materialDescriptor(bytes) {
  return Object.freeze({
    encoding: 'base64',
    byteLength: bytes.byteLength,
    sha256: sha256(bytes),
    base64: bytes.toString('base64')
  });
}

function buildRequest({
  runtime, nonce, trust, reconciliation, authorization, reviewerSignature,
  riskSignature, registryBytes, knownGoodBytes, bundleBytes, validated
}) {
  const packet = validated.packet;
  const request = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_request',
    operation: 'deposit_recovery_material',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    controller: Object.freeze({
      repository: runtime.repository,
      ref: runtime.ref,
      commit: runtime.commit,
      workflowPath: runtime.workflowPath,
      workflowRef: runtime.workflowRef,
      runId: runtime.runId,
      runAttempt: 1,
      dispatchNonce: nonce,
      policySha256: POLICY_SHA256
    }),
    source: packet.source,
    artifact: packet.artifact,
    target: Object.freeze({
      netlifySiteId: POLICY.target.netlifySiteId,
      netlifyOrigin: POLICY.target.netlifyOrigin,
      supabaseProjectRef: POLICY.target.supabaseProjectRef,
      databaseSystemIdentifier: POLICY.target.databaseSystemIdentifier,
      targetSha256: sha256(JSON.stringify(POLICY.target)),
      previousDeployId: validated.previousDeployId
    }),
    rollbackAttestationPolicy: Object.freeze({
      origin: trust.origin,
      policyId: trust.policyId,
      policySha256: trust.policySha256,
      receiptSigningKeyId: trust.receiptSigningKeyId,
      receiptSigningSpkiSha256: trust.receiptSigningSpkiSha256,
      oidcAudience: trust.oidcAudience,
      maximumReceiptAgeMinutes: POLICY.rollbackAttestationBroker.maximumReceiptAgeMinutes,
      minimumRetentionDays: trust.minimumRetentionDays
    }),
    externalReconciliationPolicy: reconciliation,
    authorizationMaterial: Object.freeze({
      authorizationPacketSha256: sha256(authorization.bytes),
      authorizationBundleSha256: sha256(bundleBytes),
      approverRegistrySha256: sha256(registryBytes),
      independentSecurityReviewerKeyId:
        packet.signatureKeyIds.independentSecurityReviewer,
      independentSecurityReviewerSignatureSha256: sha256(reviewerSignature),
      managedPlatformRiskOwnerKeyId: packet.signatureKeyIds.managedPlatformRiskOwner,
      managedPlatformRiskOwnerSignatureSha256: sha256(riskSignature),
      knownGoodEvidenceSha256: sha256(knownGoodBytes)
    }),
    recoveryMaterial: Object.freeze({
      authorizationJson: materialDescriptor(authorization.bytes),
      independentSecurityReviewerSignature: materialDescriptor(reviewerSignature),
      managedPlatformRiskOwnerSignature: materialDescriptor(riskSignature),
      knownGoodEvidence: materialDescriptor(knownGoodBytes),
      authorizationBundle: materialDescriptor(bundleBytes),
      approverRegistry: materialDescriptor(registryBytes)
    }),
    requiredDepositSemantics: Object.freeze({
      appendOnly: true,
      immutable: true,
      oneDepositPerRunNonce: true,
      conflictingOverwriteRejected: true,
      identicalReplayReturnsOriginalReceipt: true,
      encryptedAtRest: true,
      hashVerifiedBeforeSeal: true,
      retrievableForRecovery: true,
      rawPayloadArtifactExposure: false
    }),
    requiredRetrievalBoundary: Object.freeze({
      oidcAudience: trust.oidcAudience,
      requiredControllerRepository: runtime.repository,
      requiredControllerRef: runtime.ref,
      requiredControllerWorkflowPath: runtime.workflowPath,
      requiredControllerRunId: runtime.runId,
      requiredControllerRunAttempt: 1,
      requiredDispatchNonce: nonce,
      externalReconciliationPolicyId: reconciliation.policyId,
      externalReconciliationPolicySha256: reconciliation.policySha256,
      failedRunCodeCannotDelete: true,
      watchdogRevisionCannotDelete: true,
      exactRunAndNonceRequired: true,
      oidcControllerIdentityRequired: true
    })
  });
  const raw = JSON.stringify(request);
  const bytes = Buffer.from(raw);
  if (bytes.byteLength > MAX_REQUEST_BYTES || raw !== JSON.stringify(JSON.parse(raw))) {
    fail('CNYOS_ROLLBACK_ATTESTATION_REQUEST_INVALID');
  }
  return Object.freeze({ value: request, raw, bytes, sha256: sha256(bytes) });
}

function strictContentType(response, code) {
  const contentType = String(response?.headers?.get?.('content-type') || '').toLowerCase();
  if (!/^application\/json(?:;\s*charset=utf-8)?$/.test(contentType)) fail(code);
}

function assertHeadersDoNotReflectCredential(response, credential, code) {
  if (typeof response?.headers?.entries !== 'function') fail(code);
  let entries;
  try { entries = [...response.headers.entries()]; }
  catch { fail(code); }
  if (entries.length > 256) fail(code);
  let size = 0;
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2 ||
      typeof entry[0] !== 'string' || typeof entry[1] !== 'string') fail(code);
    size += Buffer.byteLength(entry[0]) + Buffer.byteLength(entry[1]);
    if (size > 64 * 1024 || entry[0].includes(credential) || entry[1].includes(credential)) {
      fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_REFLECTION_INVALID');
    }
  }
}

async function boundedResponseBytes(response, maximum, code) {
  const declared = String(response?.headers?.get?.('content-length') || '').trim();
  if (declared && (!/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > maximum)) {
    fail(code);
  }
  const reader = response?.body?.getReader?.();
  if (!reader) fail(code);
  const chunks = [];
  let size = 0;
  let chunkCount = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (!isPlainObject(item) || typeof item.done !== 'boolean' ||
        (!item.done && !(item.value instanceof Uint8Array))) fail(code);
      if (item.done) break;
      chunkCount += 1;
      if (chunkCount > 4096 || item.value.byteLength < 1) fail(code);
      size += item.value.byteLength;
      if (size > maximum) {
        try { await reader.cancel(); } catch {}
        fail(code);
      }
      chunks.push(Buffer.from(item.value));
    }
  } catch (error) {
    if (String(error?.message || '').startsWith('CNYOS_')) throw error;
    fail(code);
  }
  if (size < 2 || (declared && Number(declared) !== size)) fail(code);
  return Buffer.concat(chunks, size);
}

async function defaultOidcTokenProvider({ env, audience, fetchImpl }) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_OIDC_RESPONSE_INVALID';
  const requestUrl = activated(
    env.ACTIONS_ID_TOKEN_REQUEST_URL,
    'CNYOS_ROLLBACK_ATTESTATION_OIDC_REQUEST_URL_REQUIRED',
    2000
  );
  const requestToken = activated(
    env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    'CNYOS_ROLLBACK_ATTESTATION_OIDC_REQUEST_TOKEN_REQUIRED',
    8192
  );
  let url;
  try { url = new URL(requestUrl); }
  catch { fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_REQUEST_URL_INVALID'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash) {
    fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_REQUEST_URL_INVALID');
  }
  url.searchParams.set('audience', audience);
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'error',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      signal: AbortSignal.timeout(15_000),
      headers: { Accept: 'application/json', Authorization: `Bearer ${requestToken}` }
    });
  } catch { fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_REQUEST_FAILED'); }
  assertHeadersDoNotReflectCredential(response, requestToken, code);
  if (response?.redirected || response?.status !== 200 || response?.url !== url.href) fail(code);
  strictContentType(response, code);
  const bytes = await boundedResponseBytes(response, MAX_OIDC_RESPONSE_BYTES, code);
  if (bytes.includes(Buffer.from(requestToken))) {
    fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_REFLECTION_INVALID');
  }
  const value = parseJsonObject(bytes.toString('utf8'), code);
  assertExactKeys(value, ['value'], code);
  const token = activated(value.value, 'CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_INVALID', 8192);
  if (token.length < 20 || /[\s\0]/.test(token)) {
    fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_INVALID');
  }
  return token;
}

function validateReceipt(rawBytes, { trust, request, validated, observedAt }) {
  const code = 'CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID';
  const { raw, value: envelope } = parseUtf8Object(rawBytes, code);
  if (raw !== JSON.stringify(envelope)) fail(`${code}_NONCANONICAL`);
  assertExactKeys(envelope, RECEIPT_ENVELOPE_KEYS, code);
  assertExactKeys(envelope.receipt, RECEIPT_KEYS, code);
  assertExactKeys(envelope.receipt.broker, RECEIPT_BROKER_KEYS, code);
  assertExactKeys(envelope.receipt.controller, RECEIPT_CONTROLLER_KEYS, code);
  assertExactKeys(envelope.receipt.source, SOURCE_KEYS, code);
  assertExactKeys(envelope.receipt.artifact, ARTIFACT_KEYS, code);
  assertExactKeys(envelope.receipt.target, RECEIPT_TARGET_KEYS, code);
  assertExactKeys(envelope.receipt.authorizationMaterial, RECEIPT_AUTHORIZATION_KEYS, code);
  assertExactKeys(envelope.receipt.depositSemantics, DEPOSIT_SEMANTICS_KEYS, code);
  assertExactKeys(envelope.receipt.recoveryMaterial, RECOVERY_MATERIAL_KEYS, code);
  assertExactKeys(envelope.receipt.retrievalBoundary, RETRIEVAL_BOUNDARY_KEYS, code);
  assertExactKeys(envelope.brokerSignature, SIGNATURE_KEYS, code);
  const receipt = envelope.receipt;
  const expectedBroker = {
    origin: trust.origin,
    policyId: trust.policyId,
    policySha256: trust.policySha256,
    receiptSigningKeyId: trust.receiptSigningKeyId,
    receiptSigningSpkiSha256: trust.receiptSigningSpkiSha256
  };
  if (envelope.schemaVersion !== 1 ||
    envelope.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_envelope' ||
    receipt.schemaVersion !== 1 ||
    receipt.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_receipt' ||
    receipt.status !== 'sealed' || receipt.scope !== 'cnyos_staging_only' ||
    receipt.productionAuthorization !== false || receipt.realPatientDataAuthorized !== false ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$/.test(String(receipt.depositId || '')) ||
    receipt.depositSequence !== 1 || receipt.depositRequestSha256 !== request.sha256 ||
    !isDeepStrictEqual(receipt.broker, expectedBroker) ||
    !isDeepStrictEqual(receipt.controller, request.value.controller) ||
    !isDeepStrictEqual(receipt.source, request.value.source) ||
    !isDeepStrictEqual(receipt.artifact, request.value.artifact) ||
    !isDeepStrictEqual(receipt.target, request.value.target) ||
    !isDeepStrictEqual(receipt.authorizationMaterial,
      request.value.authorizationMaterial) ||
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
    !isDeepStrictEqual(receipt.retrievalBoundary,
      request.value.requiredRetrievalBoundary)) fail(code);
  const depositedAt = recentCanonicalTimestamp(
    receipt.depositedAt,
    observedAt,
    trust.maximumReceiptAgeMs,
    'CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_STALE'
  );
  const authorizationVerifiedAt = canonicalIsoTimestamp(
    validated.validation.verifiedAt,
    code
  );
  const authorizationExpiresAt = canonicalIsoTimestamp(
    validated.validation.authorizationExpiresAt,
    code
  );
  if (depositedAt < authorizationVerifiedAt || depositedAt >= authorizationExpiresAt) {
    fail(code);
  }
  const retentionUntil = canonicalIsoTimestamp(
    receipt.retentionUntil,
    'CNYOS_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT'
  );
  if (retentionUntil <= observedAt ||
    retentionUntil.getTime() - depositedAt.getTime() < trust.minimumRetentionMs) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT');
  }
  const signature = decodeEd25519Signature(
    envelope.brokerSignature.signatureBase64,
    'CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_SIGNATURE_INVALID'
  );
  const statement = JSON.stringify(receipt);
  if (envelope.brokerSignature.algorithm !== 'Ed25519' ||
    envelope.brokerSignature.keyId !== trust.receiptSigningKeyId ||
    envelope.brokerSignature.statementSha256 !== sha256(statement) ||
    envelope.brokerSignature.signatureSha256 !== sha256(signature) ||
    !crypto.verify(null, Buffer.from(statement), trust.publicKey, signature)) {
    fail('CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_SIGNATURE_INVALID');
  }
  return Object.freeze({ envelope, receipt, signatureSha256: sha256(signature) });
}

async function assertOutputVacant(filename) {
  const destination = path.resolve(activated(
    filename,
    'CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_PATH_REQUIRED',
    4096
  ));
  try {
    await fsp.lstat(destination);
    fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_EXISTS');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return destination;
}

async function publishBytesExclusive(filename, bytes) {
  const destination = path.resolve(filename);
  const directory = path.dirname(destination);
  await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryStatus = await fsp.lstat(directory);
  if (!directoryStatus.isDirectory() || directoryStatus.isSymbolicLink()) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_DIRECTORY_INVALID');
  }
  const temporary = path.join(
    directory,
    `.${path.basename(destination)}.${process.pid}.${crypto.randomBytes(16).toString('hex')}.tmp`
  );
  let handle;
  let linked = false;
  try {
    handle = await fsp.open(
      temporary,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY |
        (fs.constants.O_NOFOLLOW || 0),
      0o600
    );
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await fsp.link(temporary, destination);
    linked = true;
  } catch (error) {
    if (error?.code === 'EEXIST') {
      fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_EXISTS');
    }
    if (String(error?.message || '').startsWith('CNYOS_')) throw error;
    fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_FAILED');
  } finally {
    if (handle) await handle.close().catch(() => {});
    await fsp.unlink(temporary).catch(() => {});
  }
  if (!linked) fail('CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_FAILED');
  return destination;
}

export async function depositRollbackAttestation({
  env = process.env,
  fetchImpl = fetch,
  oidcTokenProvider = defaultOidcTokenProvider,
  now = () => new Date(),
  publishReceipt = publishBytesExclusive
} = {}) {
  assertAbsentEnvironmentNames(env);
  const runtime = assertControllerRuntime(env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath) {
    fail('CNYOS_ROLLBACK_ATTESTATION_RELEASE_WORKFLOW_REQUIRED');
  }
  const requestObservedAt = now();
  if (!(requestObservedAt instanceof Date) || Number.isNaN(requestObservedAt.getTime())) {
    fail('CNYOS_ROLLBACK_ATTESTATION_TIME_INVALID');
  }
  const nonce = decodeNonce(env.CNYOS_DISPATCH_NONCE).value;
  const trust = rollbackTrustRoot();
  const reconciliation = externalReconciliationPolicy();
  const endpoint = assertEndpoint(env.CNYOS_ROLLBACK_ATTESTATION_BROKER_URL, trust);
  const destination = await assertOutputVacant(
    env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH
  );
  const authorization = canonicalAuthorization(
    env.CNYOS_CONTROLLER_AUTHORIZATION_JSON,
    'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_JSON_INVALID'
  );
  const reviewerSignature = decodeEd25519Signature(
    env.CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64,
    'CNYOS_ROLLBACK_ATTESTATION_SECURITY_SIGNATURE_INVALID'
  );
  const riskSignature = decodeEd25519Signature(
    env.CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64,
    'CNYOS_ROLLBACK_ATTESTATION_RISK_SIGNATURE_INVALID'
  );
  const [bundleBytes, registryBytes, knownGoodBytes] = await Promise.all([
    readRegularFileStable(
      activated(env.CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH,
        'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_PATH_REQUIRED', 4096),
      MAX_BUNDLE_BYTES,
      'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_INVALID',
      2
    ),
    readRegularFileStable(
      activated(env.CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH,
        'CNYOS_ROLLBACK_ATTESTATION_APPROVER_REGISTRY_PATH_REQUIRED', 4096),
      MAX_REGISTRY_BYTES,
      'CNYOS_ROLLBACK_ATTESTATION_APPROVER_REGISTRY_INVALID',
      2
    ),
    readRegularFileStable(
      activated(env.CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_PATH,
        'CNYOS_ROLLBACK_ATTESTATION_KNOWN_GOOD_EVIDENCE_PATH_REQUIRED', 4096),
      MAX_KNOWN_GOOD_BYTES,
      'CNYOS_ROLLBACK_ATTESTATION_KNOWN_GOOD_EVIDENCE_INVALID',
      2
    )
  ]);
  if (sha256(bundleBytes) !== canonicalSha256(
    env.CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256,
    'CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_DIGEST_REQUIRED'
  )) fail('CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_DIGEST_MISMATCH');
  const validated = validateAuthorizationMaterial({
    env, runtime, observedAt: requestObservedAt, authorization,
    bundleBytes, registryBytes, knownGoodBytes,
    reviewerSignature, riskSignature
  });
  const request = buildRequest({
    runtime, nonce, trust, reconciliation, authorization, reviewerSignature,
    riskSignature, registryBytes, knownGoodBytes, bundleBytes, validated
  });
  const providedToken = await oidcTokenProvider({
    env,
    audience: trust.oidcAudience,
    fetchImpl
  });
  const oidcToken = activated(
    providedToken,
    'CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_INVALID',
    8192
  );
  if (providedToken !== oidcToken || oidcToken.length < 20 || /[\s\0]/.test(oidcToken) ||
    request.raw.includes(oidcToken)) fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_INVALID');
  let response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      redirect: 'error',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      signal: AbortSignal.timeout(20_000),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${oidcToken}`
      },
      body: request.raw
    });
  } catch { fail('CNYOS_ROLLBACK_ATTESTATION_BROKER_REQUEST_FAILED'); }
  assertHeadersDoNotReflectCredential(
    response,
    oidcToken,
    'CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID'
  );
  if (response?.redirected || ![200, 201].includes(response?.status) ||
    response?.url !== endpoint.href) fail('CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID');
  strictContentType(response, 'CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID');
  const receiptBytes = await boundedResponseBytes(
    response,
    MAX_RECEIPT_BYTES,
    'CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID'
  );
  if (receiptBytes.includes(Buffer.from(oidcToken))) {
    fail('CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_REFLECTION_INVALID');
  }
  const responseObservedAt = now();
  if (!(responseObservedAt instanceof Date) || Number.isNaN(responseObservedAt.getTime()) ||
    responseObservedAt < requestObservedAt) {
    fail('CNYOS_ROLLBACK_ATTESTATION_TIME_INVALID');
  }
  const verified = validateReceipt(receiptBytes, {
    trust, request, validated, observedAt: responseObservedAt
  });
  const receiptPath = await publishReceipt(destination, receiptBytes);
  return Object.freeze({
    receiptPath,
    receiptSha256: sha256(receiptBytes),
    depositRequestSha256: request.sha256,
    depositId: verified.receipt.depositId,
    depositedAt: verified.receipt.depositedAt,
    retentionUntil: verified.receipt.retentionUntil,
    brokerSignatureSha256: verified.signatureSha256,
    rawPayloadArtifactExposure: false,
    secretValuesSerialized: false
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  depositRollbackAttestation().then(result => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message ||
      'CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_FAILED')}\n`);
    process.exitCode = 1;
  });
}
