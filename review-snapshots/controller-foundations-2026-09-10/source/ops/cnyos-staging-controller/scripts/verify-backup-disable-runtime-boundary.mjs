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
  canonicalIsoTimestamp,
  decodeNonce,
  exactDeployId,
  exactSha256,
  fail,
  isPlainObject,
  readFileBounded,
  required,
  safeOrigin,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';
import {
  assertAuthorization,
  assertRollbackAttestationRetention,
  loadEvidence,
  validateLiveNetlifyAuthorityBoundary
} from './netlify-evidence.mjs';
import {
  brokerTrustRoot,
  verifySignedBrokerEnvelope
} from './reconcile-netlify-release-state.mjs';

export const RUNTIME_PROOF_OPERATION = 'observe_runtime_boundary_v1';
export const RUNTIME_PROOF_MODE = 'deployment_process_provenance';
export const RUNTIME_FUNCTION_BYTE_ATTESTATION_AVAILABLE = false;
export const RUNTIME_PROOF_MAXIMUM_BYTES = 4 * 1024 * 1024;

export const BACKUP_DISABLE_FUNCTION_NAMES = Object.freeze([
  'database-backup',
  'database-backup-background',
  'database-backup-recovery'
]);

export const RUNTIME_PROOF_CAPABILITY_INTERCEPTORS = Object.freeze([
  'configuration',
  'dns',
  'environment',
  'fetch',
  'socket',
  'supabase'
]);

export const RUNTIME_PROOF_OFFLINE_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'DATABASE_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'PGPASSWORD',
  'POSTGRES_PASSWORD',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_DB_PASSWORD',
  'SUPABASE_SERVICE_ROLE_KEY'
].sort());

export const RUNTIME_PROOF_PREREQUISITE_ENVIRONMENT_NAMES = Object.freeze([
  'CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_EXPECTED_REPOSITORY',
  'CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_PROTECTED_REF',
  'CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_RUNTIME_PROOF_ENVELOPE_PATH',
  'CNYOS_CONTROLLER_WORKFLOW_PATH',
  'CNYOS_DISPATCH_NONCE',
  'CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_FUNCTION_ENV_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256',
  'CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256',
  'CNYOS_PRODUCER_BUNDLE_DIRECTORY',
  'GITHUB_ACTOR',
  'GITHUB_REF',
  'GITHUB_REF_PROTECTED',
  'GITHUB_REPOSITORY',
  'GITHUB_RUN_ATTEMPT',
  'GITHUB_RUN_ID',
  'GITHUB_SHA',
  'GITHUB_TRIGGERING_ACTOR',
  'GITHUB_WORKFLOW_REF'
].sort());

const RUNTIME_PROOF_ACQUISITION_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze(
  RUNTIME_PROOF_OFFLINE_FORBIDDEN_ENVIRONMENT_NAMES.filter(name =>
    name !== 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' && name !== 'ACTIONS_ID_TOKEN_REQUEST_URL')
);

const RESULT_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'secretValuesSerialized', 'observedAt', 'controller',
  'policySha256', 'authorizationEvidenceSha256',
  'rollbackAttestationDepositEvidenceSha256', 'liveNetlifyAuthorityEvidenceSha256',
  'functionEnvironmentEvidenceSha256', 'candidate', 'previousLiveDeployment',
  'deploymentProcess', 'environmentSnapshot', 'handlerVerifier',
  'handlerExecutions', 'browserArtifactInspection', 'egressEnforcement', 'retention'
]);
const CONTROLLER_KEYS = Object.freeze([
  'repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
  'runAttempt', 'dispatchNonce'
]);
const CANDIDATE_KEYS = Object.freeze([
  'repository', 'commit', 'tree', 'functionSourceTree', 'producerManifestSha256',
  'artifactSha256', 'staticArtifactSha256', 'functionBundleManifestSha256',
  'functionSourcesSha256'
]);
const PREVIOUS_DEPLOYMENT_KEYS = Object.freeze([
  'netlifySiteId', 'netlifyOrigin', 'deployId', 'deployOrigin', 'state', 'context',
  'draft', 'sourceCommit', 'createdAt', 'publishedAt', 'deployManifestSha256',
  'functionArchiveInventorySha256', 'environmentSnapshotRevision'
]);
const DEPLOYMENT_PROCESS_KEYS = Object.freeze([
  'proofMode', 'functionByteAttestationAvailable', 'deployId', 'sourceCommit',
  'deployManifestSha256', 'environmentSnapshotRevision',
  'deploymentProcessId', 'deploymentProcessRecordSha256', 'archivedInputSetSha256',
  'archivedInputSetSize', 'archivedInputReference', 'functionArchives',
  'functionArchiveInventorySha256'
]);
const FUNCTION_ARCHIVE_KEYS = Object.freeze(['functionName', 'sha256', 'size']);
const ENVIRONMENT_SNAPSHOT_KEYS = Object.freeze([
  'deployId', 'revision', 'inventoryDefinition', 'configuredAt', 'sealedAt',
  'entryCount', 'entries', 'inventorySha256'
]);
const ENVIRONMENT_ENTRY_KEYS = Object.freeze([
  'name', 'kind', 'contexts', 'scopes', 'origins', 'precedence', 'valueSha256',
  'credentialReference', 'bindingProvider', 'bindingResourceId', 'bindingEnvironment'
]);
const HANDLER_VERIFIER_KEYS = Object.freeze([
  'imageDigest', 'sourceSha256', 'nodeVersion', 'captureMode', 'interceptors',
  'networkNamespace', 'capturePhase'
]);
const HANDLER_EXECUTION_KEYS = Object.freeze([
  'functionName', 'archiveSha256', 'deploymentProcessId', 'executionRecordId',
  'executedAt', 'invocationKind', 'input', 'inputSha256', 'backupEnabledValue',
  'outputStatusCode', 'outputBodySha256', 'events', 'recordSha256'
]);
const HANDLER_INPUT_KEYS = Object.freeze(['method', 'headers', 'body']);
const TRACE_EVENT_KEYS = Object.freeze([
  'sequence', 'type', 'name', 'target', 'statusCode', 'bodySha256'
]);
const BROWSER_INSPECTION_KEYS = Object.freeze([
  'artifactSha256', 'fileCount', 'inspectorImageDigest', 'inspectorSourceSha256',
  'processEnvironmentReferences', 'secretNameReferences',
  'dynamicEnvironmentAccessCount', 'credentialPatternMatchCount',
  'sourceMapExternalReferenceCount', 'recordSha256'
]);
const EGRESS_KEYS = Object.freeze([
  'policyId', 'policyRevision', 'siteId', 'candidateArtifactSha256',
  'enforcementPoint', 'defaultAction', 'candidateBindingMode',
  'configurationRevision', 'observedAt', 'rules', 'rulesSha256'
]);
const EGRESS_RULE_KEYS = Object.freeze(['order', 'action', 'origin']);
const RETENTION_KEYS = Object.freeze([
  'proofId', 'depositSequence', 'depositedAt', 'retentionUntil', 'immutable',
  'appendOnly'
]);
const BOUNDARY_POLICY_KEYS = Object.freeze([
  'maximumProofAgeMinutes', 'minimumRetentionDays', 'handlerVerifierImageDigest',
  'handlerVerifierSourceSha256', 'handlerVerifierNodeVersion',
  'functionSecretBindings', 'platformReservedEnvironmentNames',
  'browserEnvironmentAllowlist', 'egressPolicyId', 'egressPolicyRevision',
  'allowedEgressOrigins'
]);
const SECRET_BINDING_KEYS = Object.freeze(['name', 'provider', 'resourceId']);
const ENVIRONMENT_NAME = /^[A-Z][A-Z0-9_]{1,127}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/;
const LOWER_IDENTIFIER = /^[a-z0-9][a-z0-9._-]{1,99}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const EXPECTED_DISABLED_BODY_SHA256 = sha256(JSON.stringify({ ok: true, enabled: false }));

function bytewiseCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function activated(value, code, maximum = 500) {
  const result = required(value, code, maximum);
  if (result !== value || /^__[A-Z0-9_]+__$/.test(result)) fail(code);
  return result;
}

function exactIdentifier(value, expression, code, maximum = 256) {
  const result = activated(value, code, maximum);
  if (!expression.test(result)) fail(code);
  return result;
}

function exactStringArray(value, code, {
  expression = null,
  allowEmpty = true,
  maximum = 512
} = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) ||
    value.length > maximum) fail(code);
  const result = [];
  let previous = null;
  for (const item of value) {
    if (typeof item !== 'string' || !item || item.length > 500 ||
      (expression && !expression.test(item)) ||
      (previous !== null && bytewiseCompare(previous, item) >= 0)) fail(code);
    result.push(item);
    previous = item;
  }
  return Object.freeze(result);
}

function exactOriginArray(value, code, { allowEmpty = false } = {}) {
  const origins = exactStringArray(value, code, { allowEmpty, maximum: 128 });
  for (const origin of origins) if (safeOrigin(origin, code) !== origin) fail(code);
  return origins;
}

function ownEnvironmentNameAbsent(env, name) {
  return !Object.prototype.hasOwnProperty.call(env, name);
}

export function assertRuntimeProofCredentialIsolation(env, { acquisition = false } = {}) {
  if (!env || typeof env !== 'object') fail('CNYOS_RUNTIME_PROOF_ENVIRONMENT_INVALID');
  const forbidden = acquisition
    ? RUNTIME_PROOF_ACQUISITION_FORBIDDEN_ENVIRONMENT_NAMES
    : RUNTIME_PROOF_OFFLINE_FORBIDDEN_ENVIRONMENT_NAMES;
  for (const name of forbidden) {
    if (!ownEnvironmentNameAbsent(env, name)) {
      fail('CNYOS_RUNTIME_PROOF_CREDENTIAL_ISOLATION_INVALID');
    }
  }
  if (acquisition) {
    required(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
      'CNYOS_RUNTIME_PROOF_OIDC_CREDENTIAL_REQUIRED', 8192);
    required(env.ACTIONS_ID_TOKEN_REQUEST_URL,
      'CNYOS_RUNTIME_PROOF_OIDC_CREDENTIAL_REQUIRED', 2000);
  }
}

export function runtimeProofPrerequisiteEnvironment(env) {
  if (!env || typeof env !== 'object') fail('CNYOS_RUNTIME_PROOF_ENVIRONMENT_INVALID');
  const result = {};
  for (const name of RUNTIME_PROOF_PREREQUISITE_ENVIRONMENT_NAMES) {
    if (Object.prototype.hasOwnProperty.call(env, name)) result[name] = env[name];
  }
  if (JSON.stringify(Object.keys(result).sort()) !== JSON.stringify(
    RUNTIME_PROOF_PREREQUISITE_ENVIRONMENT_NAMES.filter(name =>
      Object.prototype.hasOwnProperty.call(env, name)).sort()
  )) fail('CNYOS_RUNTIME_PROOF_ENVIRONMENT_INVALID');
  return Object.freeze(result);
}

export function runtimeEvidenceBoundaryPolicy(policy = POLICY) {
  const code = 'CNYOS_RUNTIME_PROOF_BOUNDARY_POLICY_INVALID';
  const value = policy?.runtimeEvidenceBoundary;
  assertExactKeys(value, BOUNDARY_POLICY_KEYS, code);
  if (!Number.isSafeInteger(value.maximumProofAgeMinutes) ||
    value.maximumProofAgeMinutes < 1 || value.maximumProofAgeMinutes > 30 ||
    !Number.isSafeInteger(value.minimumRetentionDays) ||
    value.minimumRetentionDays < 1 || value.minimumRetentionDays > 3650 ||
    !IMAGE_DIGEST.test(String(value.handlerVerifierImageDigest || '')) ||
    !SHA256.test(String(value.handlerVerifierSourceSha256 || '')) ||
    value.handlerVerifierNodeVersion !== '24.20.0') fail(code);

  const bindings = value.functionSecretBindings;
  if (!Array.isArray(bindings) || bindings.length < 1 || bindings.length > 256) fail(code);
  let previousName = null;
  const secretNames = new Set();
  for (const binding of bindings) {
    assertExactKeys(binding, SECRET_BINDING_KEYS, code);
    const name = exactIdentifier(binding.name, ENVIRONMENT_NAME, code, 128);
    exactIdentifier(binding.provider, LOWER_IDENTIFIER, code, 100);
    exactIdentifier(binding.resourceId, IDENTIFIER, code, 256);
    if ((previousName !== null && bytewiseCompare(previousName, name) >= 0) ||
      JSON.stringify(binding).includes(POLICY.productionDenylist.supabaseProjectRef) ||
      JSON.stringify(binding).includes(POLICY.productionDenylist.netlifySiteId)) fail(code);
    previousName = name;
    secretNames.add(name);
  }
  const reserved = exactStringArray(value.platformReservedEnvironmentNames, code, {
    expression: ENVIRONMENT_NAME,
    allowEmpty: false,
    maximum: 256
  });
  const browser = exactStringArray(value.browserEnvironmentAllowlist, code, {
    expression: ENVIRONMENT_NAME,
    maximum: 256
  });
  const publicNames = Object.keys(POLICY.functionEnvironment).sort(bytewiseCompare);
  const allNames = [...publicNames, ...secretNames, ...reserved];
  if (new Set(allNames).size !== allNames.length ||
    browser.some(name => secretNames.has(name))) fail(code);
  const egressPolicyId = exactIdentifier(value.egressPolicyId, IDENTIFIER, code);
  const egressPolicyRevision = exactIdentifier(value.egressPolicyRevision, IDENTIFIER, code);
  const allowedEgressOrigins = exactOriginArray(value.allowedEgressOrigins, code);
  if (!allowedEgressOrigins.includes(POLICY.target.supabaseOrigin) ||
    allowedEgressOrigins.includes(POLICY.productionDenylist.supabaseOrigin) ||
    allowedEgressOrigins.includes(POLICY.productionDenylist.netlifyOrigin)) fail(code);
  return Object.freeze({
    ...value,
    functionSecretBindings: Object.freeze(bindings.map(item => Object.freeze({ ...item }))),
    platformReservedEnvironmentNames: reserved,
    browserEnvironmentAllowlist: browser,
    allowedEgressOrigins,
    egressPolicyId,
    egressPolicyRevision,
    maximumAgeMs: value.maximumProofAgeMinutes * 60 * 1000,
    minimumRetentionMs: value.minimumRetentionDays * 24 * 60 * 60 * 1000
  });
}

function exactRuntimeNow(now) {
  const value = typeof now === 'function' ? now() : now;
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    fail('CNYOS_RUNTIME_PROOF_TIME_INVALID');
  }
  return value;
}

function validateFunctionEnvironmentEvidence(value, runtime) {
  const code = 'CNYOS_RUNTIME_PROOF_FUNCTION_ENVIRONMENT_INVALID';
  const entries = Object.entries(POLICY.functionEnvironment)
    .sort(([left], [right]) => left.localeCompare(right));
  if (!isPlainObject(value) || value.schemaVersion !== 2 ||
    value.evidenceType !== 'cnyos_staging_controller_function_environment_validation' ||
    value.status !== 'passed' || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false || value.controllerRepository !== runtime.repository ||
    value.controllerRef !== runtime.ref || value.controllerCommit !== runtime.commit ||
    value.controllerRunId !== runtime.runId || value.policySha256 !== POLICY_SHA256 ||
    JSON.stringify(value.target) !== JSON.stringify(POLICY.target) ||
    JSON.stringify(value.validatedVariableNames) !==
      JSON.stringify(entries.map(([name]) => name).sort()) ||
    value.exactValuesSha256 !== sha256(JSON.stringify(entries)) ||
    value.productionDenylistConfirmed !== true ||
    value.protectedSecretPresenceVerified !== false || value.valuesSerialized !== false) fail(code);
}

function validateRollbackDepositEvidence(value, runtime, authorization, now) {
  const code = 'CNYOS_RUNTIME_PROOF_ROLLBACK_DEPOSIT_INVALID';
  assertRollbackAttestationRetention(value, now);
  if (!isPlainObject(value) ||
    value.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_validation' ||
    value.status !== 'passed' || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false || value.realPatientDataAuthorized !== false ||
    value.secretValuesSerialized !== false || value.rawPayloadArtifactExposure !== false ||
    value.controllerRepository !== runtime.repository || value.controllerRef !== runtime.ref ||
    value.controllerCommit !== runtime.commit || value.controllerWorkflowPath !== runtime.workflowPath ||
    value.controllerRunId !== runtime.runId || value.controllerRunAttempt !== 1 ||
    value.dispatchNonce !== authorization.dispatchNonce || value.policySha256 !== POLICY_SHA256 ||
    value.source?.commit !== authorization.source?.commit ||
    value.source?.tree !== authorization.source?.tree ||
    value.artifact?.artifactSha256 !== authorization.artifact?.artifactSha256 ||
    value.previousDeployId !== authorization.previousDeployId ||
    value.target?.netlifySiteId !== POLICY.target.netlifySiteId ||
    value.target?.supabaseProjectRef !== POLICY.target.supabaseProjectRef ||
    value.immutableAppendOnlyDepositVerified !== true ||
    value.exactRunNonceRetrievalBoundaryVerified !== true ||
    value.completeRecoveryMaterialStoredVerified !== true) fail(code);
}

function validateProducerAuthorizationBinding(manifest, manifestSha256, authorization) {
  const code = 'CNYOS_RUNTIME_PROOF_PRODUCER_AUTHORIZATION_MISMATCH';
  if (manifestSha256 !== authorization.artifact?.producerManifestSha256 ||
    manifest.candidateCommit !== authorization.source?.commit ||
    manifest.candidateTree !== authorization.source?.tree ||
    manifest.functionSourceTree !== authorization.source?.functionSourceTree ||
    manifest.artifactSha256 !== authorization.artifact?.artifactSha256 ||
    manifest.staticArtifactSha256 !== authorization.artifact?.staticArtifactSha256 ||
    manifest.functionBundleManifestSha256 !==
      authorization.artifact?.functionBundleManifestSha256 ||
    manifest.functionSourcesSha256 !== authorization.artifact?.functionSourcesSha256) fail(code);
}

export async function loadRuntimeProofPrerequisites({
  env = process.env,
  now = () => new Date(),
  credentialMode = 'offline'
} = {}) {
  assertRuntimeProofCredentialIsolation(env, { acquisition: credentialMode === 'acquire' });
  const runtime = assertControllerRuntime(env);
  const observedAt = exactRuntimeNow(now);
  const producer = await verifyProducerBundle({ env });
  const authorization = await loadEvidence(
    required(env.CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH,
      'CNYOS_RUNTIME_PROOF_AUTHORIZATION_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256,
    'CNYOS_RUNTIME_PROOF_AUTHORIZATION_INVALID'
  );
  assertAuthorization(authorization.value, runtime, env, observedAt);
  if (authorization.value.functionRemoteByteAttestationUnavailableAccepted !== true ||
    POLICY.publishing.functionByteAttestationAvailable !== false) {
    fail('CNYOS_RUNTIME_PROOF_BYTE_ATTESTATION_RISK_BOUNDARY_INVALID');
  }
  validateProducerAuthorizationBinding(
    producer.manifest,
    producer.manifestSha256,
    authorization.value
  );
  const functionEnvironment = await loadEvidence(
    required(env.CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH,
      'CNYOS_RUNTIME_PROOF_FUNCTION_ENVIRONMENT_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_FUNCTION_ENV_EVIDENCE_SHA256,
    'CNYOS_RUNTIME_PROOF_FUNCTION_ENVIRONMENT_INVALID'
  );
  validateFunctionEnvironmentEvidence(functionEnvironment.value, runtime);
  const rollbackDeposit = await loadEvidence(
    required(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH,
      'CNYOS_RUNTIME_PROOF_ROLLBACK_DEPOSIT_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256,
    'CNYOS_RUNTIME_PROOF_ROLLBACK_DEPOSIT_INVALID'
  );
  validateRollbackDepositEvidence(
    rollbackDeposit.value,
    runtime,
    authorization.value,
    observedAt
  );
  const liveAuthority = await loadEvidence(
    required(env.CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH,
      'CNYOS_RUNTIME_PROOF_LIVE_AUTHORITY_PATH_REQUIRED', 4096),
    env.CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256,
    'CNYOS_RUNTIME_PROOF_LIVE_AUTHORITY_INVALID'
  );
  validateLiveNetlifyAuthorityBoundary(liveAuthority.value, {
    runtime,
    authorization: authorization.value,
    authorizationSha256: authorization.sha256,
    depositSha256: rollbackDeposit.sha256,
    now: observedAt
  });
  return Object.freeze({
    runtime,
    observedAt,
    producer,
    authorization,
    functionEnvironment,
    rollbackDeposit,
    liveAuthority,
    boundary: runtimeEvidenceBoundaryPolicy(POLICY),
    dispatchNonce: decodeNonce(env.CNYOS_DISPATCH_NONCE).value
  });
}

export function runtimeProofBrokerRequestComponents(context) {
  const { runtime, producer, authorization, functionEnvironment, rollbackDeposit,
    liveAuthority, dispatchNonce } = context;
  const manifest = producer.manifest;
  const resumer = Object.freeze({
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerWorkflowPath: runtime.workflowPath,
    controllerWorkflowRef: runtime.workflowRef,
    controllerRunId: runtime.runId,
    controllerRunAttempt: 1,
    dispatchNonce
  });
  const target = Object.freeze({
    environment: POLICY.target.environment,
    netlifySiteId: POLICY.target.netlifySiteId,
    netlifyOrigin: POLICY.target.netlifyOrigin,
    supabaseProjectRef: POLICY.target.supabaseProjectRef,
    databaseSystemIdentifier: POLICY.target.databaseSystemIdentifier,
    previousDeployId: authorization.value.previousDeployId
  });
  const evidence = Object.freeze({
    authorizationEvidenceSha256: authorization.sha256,
    rollbackAttestationDepositEvidenceSha256: rollbackDeposit.sha256,
    liveNetlifyAuthorityEvidenceSha256: liveAuthority.sha256,
    functionEnvironmentEvidenceSha256: functionEnvironment.sha256,
    runtimeEvidenceBoundarySha256: sha256(JSON.stringify(POLICY.runtimeEvidenceBoundary)),
    proofMode: RUNTIME_PROOF_MODE,
    functionByteAttestationAvailable: false,
    candidate: Object.freeze({
      repository: POLICY.sourceRepository,
      commit: manifest.candidateCommit,
      tree: manifest.candidateTree,
      functionSourceTree: manifest.functionSourceTree,
      producerManifestSha256: producer.manifestSha256,
      artifactSha256: manifest.artifactSha256,
      staticArtifactSha256: manifest.staticArtifactSha256,
      functionBundleManifestSha256: manifest.functionBundleManifestSha256,
      functionSourcesSha256: manifest.functionSourcesSha256
    })
  });
  return Object.freeze({ resumer, target, evidence });
}

export function runtimeProofBrokerRequestSha256(trust, components) {
  const body = JSON.stringify({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_broker_request',
    operationDomain: trust.operationDomain,
    operation: RUNTIME_PROOF_OPERATION,
    policyId: trust.policyId,
    policySha256: trust.policySha256,
    controllerPolicySha256: POLICY_SHA256,
    resumer: components.resumer,
    target: components.target,
    evidence: components.evidence
  });
  return sha256(body);
}

function assertExactCandidate(candidate, context, code) {
  assertExactKeys(candidate, CANDIDATE_KEYS, code);
  const expected = runtimeProofBrokerRequestComponents(context).evidence.candidate;
  if (JSON.stringify(candidate) !== JSON.stringify(expected)) fail(code);
}

function validatePreviousLiveDeployment(value, context, resultObservedAt, code) {
  assertExactKeys(value, PREVIOUS_DEPLOYMENT_KEYS, code);
  const deployId = exactDeployId(value.deployId, code);
  const expectedDeployOrigin =
    `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`;
  const createdAt = canonicalIsoTimestamp(value.createdAt, code);
  const publishedAt = canonicalIsoTimestamp(value.publishedAt, code);
  if (value.netlifySiteId !== POLICY.target.netlifySiteId ||
    value.netlifyOrigin !== POLICY.target.netlifyOrigin ||
    safeOrigin(value.netlifyOrigin, code) !== POLICY.target.netlifyOrigin ||
    value.deployId !== deployId || value.deployOrigin !== expectedDeployOrigin ||
    safeOrigin(value.deployOrigin, code) !== expectedDeployOrigin ||
    value.state !== 'ready' || value.context !== 'production' || value.draft !== false ||
    deployId !== context.authorization.value.previousDeployId ||
    !SHA40.test(String(value.sourceCommit || '')) ||
    !SHA256.test(String(value.deployManifestSha256 || '')) ||
    !SHA256.test(String(value.functionArchiveInventorySha256 || '')) ||
    !IDENTIFIER.test(String(value.environmentSnapshotRevision || '')) ||
    createdAt >= publishedAt || publishedAt > resultObservedAt) fail(code);
  return Object.freeze({ deployId, createdAt, publishedAt });
}

function validateDeploymentProcess(value, previous, previousWindow, code) {
  assertExactKeys(value, DEPLOYMENT_PROCESS_KEYS, code);
  if (value.proofMode !== RUNTIME_PROOF_MODE ||
    value.functionByteAttestationAvailable !== false ||
    value.deployId !== previous.deployId || value.sourceCommit !== previous.sourceCommit ||
    value.deployManifestSha256 !== previous.deployManifestSha256 ||
    value.environmentSnapshotRevision !== previous.environmentSnapshotRevision ||
    !IDENTIFIER.test(String(value.deploymentProcessId || '')) ||
    !SHA256.test(String(value.deploymentProcessRecordSha256 || '')) ||
    !SHA256.test(String(value.archivedInputSetSha256 || '')) ||
    !Number.isSafeInteger(value.archivedInputSetSize) || value.archivedInputSetSize < 1 ||
    value.archivedInputSetSize > 128 * 1024 * 1024 ||
    !IDENTIFIER.test(String(value.archivedInputReference || '')) ||
    !Array.isArray(value.functionArchives) ||
    value.functionArchives.length !== BACKUP_DISABLE_FUNCTION_NAMES.length) fail(code);
  let previousName = null;
  for (const archive of value.functionArchives) {
    assertExactKeys(archive, FUNCTION_ARCHIVE_KEYS, code);
    if (!BACKUP_DISABLE_FUNCTION_NAMES.includes(archive.functionName) ||
      (previousName !== null && bytewiseCompare(previousName, archive.functionName) >= 0) ||
      !SHA256.test(String(archive.sha256 || '')) ||
      !Number.isSafeInteger(archive.size) || archive.size < 1 ||
      archive.size > 32 * 1024 * 1024) fail(code);
    previousName = archive.functionName;
  }
  const archivedFunctionBytes = value.functionArchives.reduce(
    (total, archive) => total + archive.size,
    0
  );
  if (value.archivedInputSetSize < archivedFunctionBytes ||
    value.functionArchiveInventorySha256 !== sha256(JSON.stringify(value.functionArchives)) ||
    value.functionArchiveInventorySha256 !== previous.functionArchiveInventorySha256 ||
    value.deploymentProcessRecordSha256 !== sha256(JSON.stringify({
      proofMode: value.proofMode,
      functionByteAttestationAvailable: value.functionByteAttestationAvailable,
      deployId: value.deployId,
      sourceCommit: value.sourceCommit,
      deployManifestSha256: value.deployManifestSha256,
      environmentSnapshotRevision: value.environmentSnapshotRevision,
      deploymentProcessId: value.deploymentProcessId,
      archivedInputSetSha256: value.archivedInputSetSha256,
      archivedInputSetSize: value.archivedInputSetSize,
      archivedInputReference: value.archivedInputReference,
      functionArchives: value.functionArchives,
      functionArchiveInventorySha256: value.functionArchiveInventorySha256
    })) ||
    previousWindow.createdAt >= previousWindow.publishedAt) fail(code);
  return new Map(value.functionArchives.map(entry => [entry.functionName, entry]));
}

function expectedEnvironmentEntries(boundary) {
  const entries = [];
  for (const name of Object.keys(POLICY.functionEnvironment).sort(bytewiseCompare)) {
    entries.push(Object.freeze({
      name,
      kind: 'reviewed_public',
      contexts: Object.freeze(['production']),
      scopes: Object.freeze(['functions']),
      origins: Object.freeze(['site']),
      precedence: 1,
      valueSha256: sha256(POLICY.functionEnvironment[name]),
      credentialReference: null,
      bindingProvider: null,
      bindingResourceId: null,
      bindingEnvironment: null
    }));
  }
  for (const binding of boundary.functionSecretBindings) {
    entries.push(Object.freeze({
      name: binding.name,
      kind: 'reviewed_secret',
      contexts: Object.freeze(['production']),
      scopes: Object.freeze(['functions']),
      origins: null,
      precedence: null,
      valueSha256: null,
      credentialReference: null,
      bindingProvider: binding.provider,
      bindingResourceId: binding.resourceId,
      bindingEnvironment: 'staging'
    }));
  }
  for (const name of boundary.platformReservedEnvironmentNames) {
    entries.push(Object.freeze({
      name,
      kind: 'platform_reserved',
      contexts: Object.freeze(['production']),
      scopes: Object.freeze(['functions']),
      origins: Object.freeze(['platform']),
      precedence: 0,
      valueSha256: null,
      credentialReference: null,
      bindingProvider: null,
      bindingResourceId: null,
      bindingEnvironment: null
    }));
  }
  return entries.sort((left, right) => bytewiseCompare(left.name, right.name));
}

function validateEnvironmentSnapshot(value, previous, previousWindow, resultObservedAt,
  boundary, code) {
  assertExactKeys(value, ENVIRONMENT_SNAPSHOT_KEYS, code);
  if (value.deployId !== previous.deployId || value.revision !== previous.environmentSnapshotRevision ||
    value.inventoryDefinition !==
      'complete_effective_user_and_platform_function_environment_at_deploy' ||
    !Array.isArray(value.entries) || value.entryCount !== value.entries.length) fail(code);
  const configuredAt = canonicalIsoTimestamp(value.configuredAt, code);
  const sealedAt = canonicalIsoTimestamp(value.sealedAt, code);
  if (configuredAt >= previousWindow.createdAt || sealedAt < previousWindow.createdAt ||
    sealedAt > resultObservedAt) fail(code);
  const expected = expectedEnvironmentEntries(boundary);
  if (value.entries.length !== expected.length) fail(code);
  let previousName = null;
  for (let index = 0; index < value.entries.length; index += 1) {
    const entry = value.entries[index];
    const wanted = expected[index];
    assertExactKeys(entry, ENVIRONMENT_ENTRY_KEYS, code);
    if (entry.name !== wanted.name ||
      (previousName !== null && bytewiseCompare(previousName, entry.name) >= 0) ||
      entry.kind !== wanted.kind || JSON.stringify(entry.contexts) !== '["production"]' ||
      JSON.stringify(entry.scopes) !== '["functions"]') fail(code);
    if (entry.kind === 'reviewed_public') {
      if (JSON.stringify(entry.origins) !== '["site"]' || entry.precedence !== 1 ||
        entry.valueSha256 !== wanted.valueSha256 || entry.credentialReference !== null ||
        entry.bindingProvider !== null || entry.bindingResourceId !== null ||
        entry.bindingEnvironment !== null) fail(code);
    } else if (entry.kind === 'reviewed_secret') {
      if (!Array.isArray(entry.origins) || entry.origins.length < 1 || entry.origins.length > 2 ||
        entry.origins.some(origin => !['shared', 'site'].includes(origin)) ||
        new Set(entry.origins).size !== entry.origins.length ||
        entry.origins.some((origin, index) => index > 0 &&
          bytewiseCompare(entry.origins[index - 1], origin) >= 0) ||
        !Number.isSafeInteger(entry.precedence) || entry.precedence < 1 || entry.precedence > 2 ||
        entry.valueSha256 !== null ||
        !IDENTIFIER.test(String(entry.credentialReference || '')) ||
        entry.bindingProvider !== wanted.bindingProvider ||
        entry.bindingResourceId !== wanted.bindingResourceId ||
        entry.bindingEnvironment !== 'staging') fail(code);
    } else if (JSON.stringify(entry) !== JSON.stringify(wanted)) {
      fail(code);
    }
    previousName = entry.name;
  }
  if (value.inventorySha256 !== sha256(JSON.stringify(value.entries))) fail(code);
  return Object.freeze({ configuredAt, sealedAt, entries: Object.freeze(value.entries) });
}

function validateHandlerVerifier(value, boundary, code) {
  assertExactKeys(value, HANDLER_VERIFIER_KEYS, code);
  if (value.imageDigest !== boundary.handlerVerifierImageDigest ||
    value.sourceSha256 !== boundary.handlerVerifierSourceSha256 ||
    value.nodeVersion !== boundary.handlerVerifierNodeVersion ||
    value.captureMode !== 'sealed_complete_security_capability_trace_v1' ||
    JSON.stringify(value.interceptors) !== JSON.stringify(RUNTIME_PROOF_CAPABILITY_INTERCEPTORS) ||
    value.networkNamespace !== 'deny_all' ||
    value.capturePhase !== 'module_load_and_handler_invocation') fail(code);
}

function handlerRecordDigest(value) {
  const { recordSha256: ignored, ...record } = value;
  return sha256(JSON.stringify(record));
}

function validateHandlerInput(input, invocationKind, code) {
  assertExactKeys(input, HANDLER_INPUT_KEYS, code);
  if (input.method !== 'POST' || !isPlainObject(input.headers) ||
    Object.keys(input.headers).length > 2 || typeof input.body !== 'string' ||
    Buffer.byteLength(input.body, 'utf8') > 256) fail(code);
  if (invocationKind === 'background_post') {
    if (Object.keys(input.headers).length !== 0 || input.body !== '') fail(code);
  } else {
    const bodyBytes = Buffer.byteLength(input.body, 'utf8');
    if (JSON.stringify(Object.keys(input.headers).sort()) !== '["content-length"]' ||
      input.headers['content-length'] !== String(bodyBytes)) fail(code);
    let event;
    try { event = JSON.parse(input.body); }
    catch { fail(code); }
    if (!isPlainObject(event) || JSON.stringify(Object.keys(event)) !== '["next_run"]' ||
      typeof event.next_run !== 'string' ||
      canonicalIsoTimestamp(event.next_run, code).toISOString() !== event.next_run) fail(code);
  }
  return sha256(JSON.stringify(input));
}

function validateHandlerExecutions(value, archiveByName, deploymentProcess,
  previousWindow, code) {
  if (!Array.isArray(value) || value.length !== BACKUP_DISABLE_FUNCTION_NAMES.length) fail(code);
  let previousName = null;
  const verifiedTimes = [];
  for (const record of value) {
    assertExactKeys(record, HANDLER_EXECUTION_KEYS, code);
    const archive = archiveByName.get(record.functionName);
    const executedAt = canonicalIsoTimestamp(record.executedAt, code);
    const expectedInvocation = record.functionName === 'database-backup-background'
      ? 'background_post' : 'scheduled_event';
    const expectedInputSha256 = validateHandlerInput(record.input, expectedInvocation, code);
    if (!archive || (previousName !== null && bytewiseCompare(previousName, record.functionName) >= 0) ||
      record.archiveSha256 !== archive.sha256 ||
      record.deploymentProcessId !== deploymentProcess.deploymentProcessId ||
      !IDENTIFIER.test(String(record.executionRecordId || '')) ||
      executedAt < previousWindow.createdAt || executedAt > previousWindow.publishedAt ||
      record.invocationKind !== expectedInvocation ||
      record.inputSha256 !== expectedInputSha256 || record.backupEnabledValue !== 'false' ||
      record.outputStatusCode !== 200 ||
      record.outputBodySha256 !== EXPECTED_DISABLED_BODY_SHA256 ||
      !Array.isArray(record.events) || record.events.length !== 2 ||
      record.recordSha256 !== handlerRecordDigest(record)) fail(code);
    const [environmentRead, response] = record.events;
    assertExactKeys(environmentRead, TRACE_EVENT_KEYS, code);
    assertExactKeys(response, TRACE_EVENT_KEYS, code);
    if (environmentRead.sequence !== 1 || environmentRead.type !== 'environment_read' ||
      environmentRead.name !== 'BACKUP_ENABLED' || environmentRead.target !== null ||
      environmentRead.statusCode !== null || environmentRead.bodySha256 !== null ||
      response.sequence !== 2 || response.type !== 'response' || response.name !== null ||
      response.target !== null || response.statusCode !== 200 ||
      response.bodySha256 !== EXPECTED_DISABLED_BODY_SHA256) fail(code);
    previousName = record.functionName;
    verifiedTimes.push(executedAt);
  }
  return new Date(Math.max(...verifiedTimes.map(item => item.getTime())));
}

function browserInspectionDigest(value) {
  const { recordSha256: ignored, ...record } = value;
  return sha256(JSON.stringify(record));
}

function validateBrowserInspection(value, context, boundary, code) {
  assertExactKeys(value, BROWSER_INSPECTION_KEYS, code);
  const staticFiles = context.producer.manifest.files.filter(entry =>
    entry.path.startsWith('payload/dist/'));
  if (value.artifactSha256 !== context.producer.manifest.staticArtifactSha256 ||
    value.fileCount !== staticFiles.length || value.fileCount < 1 ||
    value.inspectorImageDigest !== boundary.handlerVerifierImageDigest ||
    value.inspectorSourceSha256 !== boundary.handlerVerifierSourceSha256 ||
    JSON.stringify(value.processEnvironmentReferences) !==
      JSON.stringify(boundary.browserEnvironmentAllowlist) ||
    !Array.isArray(value.secretNameReferences) || value.secretNameReferences.length !== 0 ||
    value.dynamicEnvironmentAccessCount !== 0 ||
    value.credentialPatternMatchCount !== 0 ||
    value.sourceMapExternalReferenceCount !== 0 ||
    value.recordSha256 !== browserInspectionDigest(value)) fail(code);
}

function validateEgressEnforcement(value, context, boundary, resultObservedAt, code) {
  assertExactKeys(value, EGRESS_KEYS, code);
  const observedAt = canonicalIsoTimestamp(value.observedAt, code);
  if (value.policyId !== boundary.egressPolicyId ||
    value.policyRevision !== boundary.egressPolicyRevision ||
    value.siteId !== POLICY.target.netlifySiteId ||
    value.candidateArtifactSha256 !== context.producer.manifest.artifactSha256 ||
    value.enforcementPoint !== 'provider_function_runtime' || value.defaultAction !== 'deny' ||
    value.candidateBindingMode !== 'site_policy_applies_to_exact_next_deploy' ||
    !IDENTIFIER.test(String(value.configurationRevision || '')) ||
    observedAt > resultObservedAt || !Array.isArray(value.rules) ||
    value.rules.length !== boundary.allowedEgressOrigins.length) fail(code);
  for (let index = 0; index < value.rules.length; index += 1) {
    const rule = value.rules[index];
    assertExactKeys(rule, EGRESS_RULE_KEYS, code);
    if (rule.order !== index + 1 || rule.action !== 'allow' ||
      rule.origin !== boundary.allowedEgressOrigins[index]) fail(code);
  }
  if (value.rulesSha256 !== sha256(JSON.stringify(value.rules))) fail(code);
}

function validateRetention(value, resultObservedAt, envelopeIssuedAt, now, boundary, code) {
  assertExactKeys(value, RETENTION_KEYS, code);
  const depositedAt = canonicalIsoTimestamp(value.depositedAt, code);
  const retentionUntil = canonicalIsoTimestamp(value.retentionUntil, code);
  if (!IDENTIFIER.test(String(value.proofId || '')) || value.depositSequence !== 1 ||
    value.immutable !== true || value.appendOnly !== true || depositedAt < resultObservedAt ||
    depositedAt > now || (envelopeIssuedAt && depositedAt > envelopeIssuedAt) ||
    retentionUntil <= now ||
    retentionUntil.getTime() - depositedAt.getTime() < boundary.minimumRetentionMs) fail(code);
  return Object.freeze({ depositedAt, retentionUntil });
}

export function validateRuntimeBoundaryProviderResult(result, {
  context,
  envelopeIssuedAt,
  now = context?.observedAt
}) {
  const code = 'CNYOS_RUNTIME_PROOF_RESULT_INVALID';
  const observedAt = exactRuntimeNow(now);
  assertExactKeys(result, RESULT_KEYS, code);
  assertExactKeys(result.controller, CONTROLLER_KEYS, code);
  const resultObservedAt = canonicalIsoTimestamp(result.observedAt, code);
  const expectedController = {
    repository: context.runtime.repository,
    ref: context.runtime.ref,
    commit: context.runtime.commit,
    workflowPath: context.runtime.workflowPath,
    workflowRef: context.runtime.workflowRef,
    runId: context.runtime.runId,
    runAttempt: 1,
    dispatchNonce: context.dispatchNonce
  };
  if (result.schemaVersion !== 1 ||
    result.evidenceType !== 'cnyos_staging_runtime_boundary_provider_result' ||
    result.status !== 'observed' || result.scope !== 'cnyos_staging_only' ||
    result.productionAuthorization !== false || result.realPatientDataAuthorized !== false ||
    result.secretValuesSerialized !== false || result.policySha256 !== POLICY_SHA256 ||
    JSON.stringify(result.controller) !== JSON.stringify(expectedController) ||
    result.authorizationEvidenceSha256 !== context.authorization.sha256 ||
    result.rollbackAttestationDepositEvidenceSha256 !== context.rollbackDeposit.sha256 ||
    result.liveNetlifyAuthorityEvidenceSha256 !== context.liveAuthority.sha256 ||
    result.functionEnvironmentEvidenceSha256 !== context.functionEnvironment.sha256 ||
    resultObservedAt > observedAt ||
    observedAt.getTime() - resultObservedAt.getTime() > context.boundary.maximumAgeMs ||
    (envelopeIssuedAt && resultObservedAt > envelopeIssuedAt)) fail(code);
  assertExactCandidate(result.candidate, context, code);
  const previousWindow = validatePreviousLiveDeployment(
    result.previousLiveDeployment,
    context,
    resultObservedAt,
    code
  );
  const archiveByName = validateDeploymentProcess(
    result.deploymentProcess,
    result.previousLiveDeployment,
    previousWindow,
    code
  );
  validateHandlerVerifier(result.handlerVerifier, context.boundary, code);
  const handlerVerifiedAt = validateHandlerExecutions(
    result.handlerExecutions,
    archiveByName,
    result.deploymentProcess,
    previousWindow,
    code
  );
  const environment = validateEnvironmentSnapshot(
    result.environmentSnapshot,
    result.previousLiveDeployment,
    previousWindow,
    resultObservedAt,
    context.boundary,
    code
  );
  validateBrowserInspection(result.browserArtifactInspection, context, context.boundary, code);
  validateEgressEnforcement(
    result.egressEnforcement,
    context,
    context.boundary,
    resultObservedAt,
    code
  );
  validateRetention(
    result.retention,
    resultObservedAt,
    envelopeIssuedAt,
    observedAt,
    context.boundary,
    code
  );
  return Object.freeze({
    result,
    resultObservedAt,
    previousWindow,
    handlerVerifiedAt,
    environment,
    archiveByName
  });
}

export function validateRuntimeProofEnvelope(raw, {
  trust,
  context,
  requestSha256,
  now = context?.observedAt
}) {
  const observedAt = exactRuntimeNow(now);
  const verified = verifySignedBrokerEnvelope(raw, {
    trust,
    operation: RUNTIME_PROOF_OPERATION,
    requestSha256,
    observedAt
  });
  const issuedAt = canonicalIsoTimestamp(verified.statement.issuedAt,
    'CNYOS_RUNTIME_PROOF_RESULT_INVALID');
  const validation = validateRuntimeBoundaryProviderResult(verified.result, {
    context,
    envelopeIssuedAt: issuedAt,
    now: observedAt
  });
  return Object.freeze({ ...verified, ...validation });
}

export async function loadAndValidateRuntimeProofEnvelope({
  env = process.env,
  now = () => new Date(),
  context = null,
  trust = null
} = {}) {
  const loadedContext = context || await loadRuntimeProofPrerequisites({ env, now });
  const runtimeTrust = trust || brokerTrustRoot('runtime');
  const components = runtimeProofBrokerRequestComponents(loadedContext);
  const requestSha256 = runtimeProofBrokerRequestSha256(runtimeTrust, components);
  const filename = required(
    env.CNYOS_CONTROLLER_RUNTIME_PROOF_ENVELOPE_PATH,
    'CNYOS_RUNTIME_PROOF_ENVELOPE_PATH_REQUIRED',
    4096
  );
  const bytes = await readFileBounded(
    filename,
    RUNTIME_PROOF_MAXIMUM_BYTES,
    'CNYOS_RUNTIME_PROOF_ENVELOPE_INVALID'
  );
  const digest = sha256(bytes);
  if (digest !== exactSha256(
    env.CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256,
    'CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256_INVALID'
  )) fail('CNYOS_RUNTIME_PROOF_ENVELOPE_DIGEST_MISMATCH');
  const verified = validateRuntimeProofEnvelope(bytes, {
    trust: runtimeTrust,
    context: loadedContext,
    requestSha256,
    now: loadedContext.observedAt
  });
  return Object.freeze({
    context: loadedContext,
    trust: runtimeTrust,
    components,
    requestSha256,
    bytes,
    sha256: digest,
    ...verified
  });
}

export function deriveBackupDisableRuntimeEvidence(validated, {
  verifiedAt = validated.context.observedAt
} = {}) {
  const now = exactRuntimeNow(verifiedAt);
  const { context, result, previousWindow, handlerVerifiedAt } = validated;
  const proofSha256 = exactSha256(
    validated.sha256,
    'CNYOS_RUNTIME_PROOF_ENVELOPE_DIGEST_INVALID'
  );
  const manifest = context.producer.manifest;
  const environmentEntry = result.environmentSnapshot.entries.find(entry =>
    entry.name === 'BACKUP_ENABLED');
  if (!environmentEntry || environmentEntry.valueSha256 !== sha256('false') ||
    POLICY.functionEnvironment.BACKUP_ENABLED !== 'false') {
    fail('CNYOS_RUNTIME_PROOF_BACKUP_DISABLE_VALUE_INVALID');
  }
  return Object.freeze({
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_backup_disable_runtime_boundary',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    validatedAt: now.toISOString(),
    controllerRepository: context.runtime.repository,
    controllerRef: context.runtime.ref,
    controllerCommit: context.runtime.commit,
    controllerRunId: context.runtime.runId,
    policySha256: POLICY_SHA256,
    source: Object.freeze({
      repository: POLICY.sourceRepository,
      commit: manifest.candidateCommit,
      tree: manifest.candidateTree,
      functionSourceTree: manifest.functionSourceTree
    }),
    artifact: Object.freeze({
      producerManifestSha256: context.producer.manifestSha256,
      artifactSha256: manifest.artifactSha256
    }),
    target: Object.freeze({
      netlifySiteId: POLICY.target.netlifySiteId,
      supabaseProjectRef: POLICY.target.supabaseProjectRef
    }),
    previousLiveDeployment: Object.freeze({ ...result.previousLiveDeployment }),
    currentDeployId: result.previousLiveDeployment.deployId,
    currentDeployCreatedAt: result.previousLiveDeployment.createdAt,
    backupEnabled: false,
    backupDisabledConfiguredAt: result.environmentSnapshot.configuredAt,
    configuredBeforeDeploy: true,
    functionByteAttestationAvailable: false,
    proofMode: RUNTIME_PROOF_MODE,
    runtimeProofEnvelopeSha256: proofSha256,
    handlerFailClosed: Object.freeze({
      verifiedAt: validated.resultObservedAt.toISOString(),
      dailyBeforeConfigurationOrSupabase: true,
      recoveryBeforeConfigurationOrSupabase: true,
      backgroundBeforeConfigurationOrSupabase: true,
      evidenceSha256: proofSha256,
      evidenceReference: result.retention.proofId
    }),
    handlerExecutionRecordLastExecutedAt: handlerVerifiedAt.toISOString(),
    secretValuesSerialized: false
  });
}

export function validateBackupDisableRuntimeEvidenceReceipt(evidence, validated, observedAt) {
  const code = 'CNYOS_CONTROLLER_BACKUP_DISABLE_EVIDENCE_INVALID';
  const now = exactRuntimeNow(observedAt);
  const verifiedAt = canonicalIsoTimestamp(evidence?.validatedAt, code);
  const issuedAt = canonicalIsoTimestamp(validated?.statement?.issuedAt, code);
  const expiresAt = canonicalIsoTimestamp(validated?.statement?.expiresAt, code);
  if (verifiedAt > now || now.getTime() - verifiedAt.getTime() >
    validated.context.boundary.maximumAgeMs || verifiedAt < issuedAt ||
    verifiedAt >= expiresAt) fail(code);
  const expected = deriveBackupDisableRuntimeEvidence(validated, { verifiedAt });
  if (!isDeepStrictEqual(evidence, expected)) fail(code);
  return Object.freeze({ evidence, verifiedAt, expected });
}

export async function verifyBackupDisableRuntimeBoundary({
  env = process.env,
  now = () => new Date()
} = {}) {
  const validated = await loadAndValidateRuntimeProofEnvelope({ env, now });
  const evidence = deriveBackupDisableRuntimeEvidence(validated);
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_BACKUP_DISABLE_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_BACKUP_DISABLE_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({ evidence, evidencePath, runtimeProofEnvelopeSha256: validated.sha256 });
}

export async function writeCanonicalBytesExclusive(filename, raw) {
  const destination = path.resolve(required(filename,
    'CNYOS_RUNTIME_PROOF_ENVELOPE_PATH_REQUIRED', 4096));
  const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
  if (bytes.length < 2 || bytes.length > RUNTIME_PROOF_MAXIMUM_BYTES) {
    fail('CNYOS_RUNTIME_PROOF_ENVELOPE_INVALID');
  }
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const handle = await fs.open(destination, 'wx', 0o600);
  try { await handle.writeFile(bytes); }
  finally { await handle.close(); }
  await fs.chmod(destination, 0o600);
  return destination;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  if (process.argv.length !== 2) {
    process.stderr.write('CNYOS_BACKUP_DISABLE_RUNTIME_ARGUMENTS_INVALID\n');
    process.exitCode = 1;
  } else {
    verifyBackupDisableRuntimeBoundary().then(async result => {
      const bytes = await readFileBounded(
        result.evidencePath,
        RUNTIME_PROOF_MAXIMUM_BYTES,
        'CNYOS_CONTROLLER_BACKUP_DISABLE_EVIDENCE_INVALID'
      );
      process.stdout.write(`${JSON.stringify({
        evidencePath: result.evidencePath,
        evidenceSha256: sha256(bytes),
        runtimeProofEnvelopeSha256: result.runtimeProofEnvelopeSha256
      })}\n`);
    }).catch(error => {
      process.stderr.write(`${String(error?.message ||
        'CNYOS_BACKUP_DISABLE_RUNTIME_BOUNDARY_FAILED')}\n`);
      process.exitCode = 1;
    });
  }
}
