import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY,
  POLICY_SHA256,
  canonicalIsoTimestamp,
  exactSha256,
  fail,
  readFileBounded,
  required,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import {
  RUNTIME_PROOF_MAXIMUM_BYTES,
  RUNTIME_PROOF_MODE,
  RUNTIME_PROOF_OPERATION,
  loadAndValidateRuntimeProofEnvelope,
  loadRuntimeProofPrerequisites,
  runtimeProofBrokerRequestComponents,
  runtimeProofBrokerRequestSha256,
  validateRuntimeBoundaryProviderResult,
  writeCanonicalBytesExclusive
} from './verify-backup-disable-runtime-boundary.mjs';
import {
  brokerTrustRoot,
  callSignedBrokerOperation
} from './reconcile-netlify-release-state.mjs';

function exactNow(now) {
  const result = typeof now === 'function' ? now() : now;
  if (!(result instanceof Date) || Number.isNaN(result.getTime())) {
    fail('CNYOS_RUNTIME_PROOF_TIME_INVALID');
  }
  return result;
}

function disabledCapability(name) {
  if (POLICY.functionEnvironment[name] !== 'false') {
    fail('CNYOS_RUNTIME_CAPABILITY_POLICY_INVALID');
  }
  return false;
}

export function deriveRuntimeCapabilityEvidence(validated, {
  verifiedAt = validated.context.observedAt
} = {}) {
  const observedAt = exactNow(verifiedAt);
  const { context, result } = validated;
  const manifest = context.producer.manifest;
  const boundary = context.boundary;
  const proofSha256 = exactSha256(
    validated.sha256,
    'CNYOS_RUNTIME_PROOF_ENVELOPE_DIGEST_INVALID'
  );
  const secretEntries = result.environmentSnapshot.entries.filter(entry =>
    entry.kind === 'reviewed_secret');
  const expectedSecretNames = boundary.functionSecretBindings.map(item => item.name);
  if (JSON.stringify(secretEntries.map(item => item.name)) !==
      JSON.stringify(expectedSecretNames) || secretEntries.length < 1) {
    fail('CNYOS_RUNTIME_CAPABILITY_SECRET_INVENTORY_INVALID');
  }
  const secretInventorySha256 = sha256(JSON.stringify(secretEntries.map(entry => ({
    name: entry.name,
    credentialReference: entry.credentialReference,
    bindingProvider: entry.bindingProvider,
    bindingResourceId: entry.bindingResourceId,
    bindingEnvironment: entry.bindingEnvironment,
    contexts: entry.contexts,
    scopes: entry.scopes,
    origins: entry.origins,
    precedence: entry.precedence
  }))));
  return Object.freeze({
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_runtime_capability_boundary',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: observedAt.toISOString(),
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
      artifactSha256: manifest.artifactSha256,
      staticArtifactSha256: manifest.staticArtifactSha256,
      functionBundleManifestSha256: manifest.functionBundleManifestSha256,
      functionSourcesSha256: manifest.functionSourcesSha256
    }),
    previousLiveDeployment: Object.freeze({ ...result.previousLiveDeployment }),
    projectRef: POLICY.target.supabaseProjectRef,
    netlifySiteId: POLICY.target.netlifySiteId,
    platformControlEnabled: disabledCapability('CNYOS_PLATFORM_CONTROL_ENABLED'),
    ownerDriveEnabled: disabledCapability('CNYOS_OWNER_DRIVE_ENABLED'),
    restoreSourceApiEnabled: disabledCapability('RESTORE_SOURCE_API_ENABLED'),
    pubmedEnabled: disabledCapability('CNYOS_EVIDENCE_PUBMED_ENABLED'),
    directJsonRestoreTestEnabled:
      disabledCapability('GOOGLE_DRIVE_SERVICE_ACCOUNT_ALLOW_RESTORE_TEST_DIRECT_JSON'),
    ownerControlEnabled: disabledCapability('CNYOS_OWNER_CONTROL_ENABLED'),
    ownerControlScope: 'disabled',
    githubProductionDispatchReachable: false,
    driveOrBlobProductionReachable: false,
    lineProductionReachable: false,
    protectedSecretPresenceVerified: true,
    functionEnvironmentAllowlistComplete: true,
    functionSecretInventoryClosedWorld: true,
    browserProcessEnvironmentSanitized: true,
    candidateFunctionEgressPolicyEnforced: true,
    productionCredentialAbsenceVerified: true,
    stagingOnlyCredentialScopeVerified: true,
    serviceRoleNotInheritedByBrowserProcess: true,
    candidateFunctionsReceiveOnlyReviewedStagingSecrets: true,
    functionByteAttestationAvailable: false,
    proofMode: RUNTIME_PROOF_MODE,
    runtimeProofEnvelopeSha256: proofSha256,
    environmentSnapshotRevision: result.environmentSnapshot.revision,
    environmentInventorySha256: result.environmentSnapshot.inventorySha256,
    secretInventorySha256,
    browserInspectionRecordSha256: result.browserArtifactInspection.recordSha256,
    egressPolicyId: result.egressEnforcement.policyId,
    egressPolicyRevision: result.egressEnforcement.policyRevision,
    egressRulesSha256: result.egressEnforcement.rulesSha256,
    retainedProofId: result.retention.proofId,
    retentionUntil: result.retention.retentionUntil,
    secretValuesSerialized: false,
    realPatientDataAuthorized: false
  });
}

export function validateRuntimeCapabilityEvidenceReceipt(evidence, validated, observedAt) {
  const code = 'CNYOS_CONTROLLER_RUNTIME_CAPABILITY_EVIDENCE_INVALID';
  const now = exactNow(observedAt);
  const verifiedAt = canonicalIsoTimestamp(evidence?.verifiedAt, code);
  const issuedAt = canonicalIsoTimestamp(validated?.statement?.issuedAt, code);
  const expiresAt = canonicalIsoTimestamp(validated?.statement?.expiresAt, code);
  if (verifiedAt > now || now.getTime() - verifiedAt.getTime() >
    validated.context.boundary.maximumAgeMs || verifiedAt < issuedAt ||
    verifiedAt >= expiresAt) fail(code);
  const expected = deriveRuntimeCapabilityEvidence(validated, { verifiedAt });
  if (!isDeepStrictEqual(evidence, expected)) fail(code);
  return Object.freeze({ evidence, verifiedAt, expected });
}

export async function verifyRuntimeCapabilityBoundary({
  env = process.env,
  now = () => new Date()
} = {}) {
  const validated = await loadAndValidateRuntimeProofEnvelope({ env, now });
  const evidence = deriveRuntimeCapabilityEvidence(validated);
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_RUNTIME_CAPABILITY_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_RUNTIME_CAPABILITY_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({ evidence, evidencePath, runtimeProofEnvelopeSha256: validated.sha256 });
}

export async function acquireRuntimeBoundaryProof({
  env = process.env,
  fetchImpl = fetch,
  oidcTokenProvider,
  now = () => new Date()
} = {}) {
  const context = await loadRuntimeProofPrerequisites({
    env,
    now,
    credentialMode: 'acquire'
  });
  const trust = brokerTrustRoot('runtime');
  const components = runtimeProofBrokerRequestComponents(context);
  const expectedRequestSha256 = runtimeProofBrokerRequestSha256(trust, components);
  const response = await callSignedBrokerOperation({
    env,
    fetchImpl,
    ...(oidcTokenProvider ? { oidcTokenProvider } : {}),
    trust,
    configuredUrl: env.CNYOS_RUNTIME_EVIDENCE_BROKER_URL,
    operation: RUNTIME_PROOF_OPERATION,
    resumer: components.resumer,
    target: components.target,
    evidence: components.evidence,
    now
  });
  if (response.requestSha256 !== expectedRequestSha256) {
    fail('CNYOS_RUNTIME_PROOF_BROKER_REQUEST_MISMATCH');
  }
  validateRuntimeBoundaryProviderResult(response.result, {
    context,
    envelopeIssuedAt: new Date(response.statement.issuedAt),
    now: response.observedAt
  });
  const envelopePath = await writeCanonicalBytesExclusive(
    required(env.CNYOS_CONTROLLER_RUNTIME_PROOF_ENVELOPE_PATH,
      'CNYOS_RUNTIME_PROOF_ENVELOPE_PATH_REQUIRED', 4096),
    response.raw
  );
  return Object.freeze({
    envelopePath,
    envelopeSha256: sha256(response.raw),
    requestSha256: expectedRequestSha256
  });
}

async function emitResult(mode, result) {
  if (mode === 'acquire') {
    process.stdout.write(`${JSON.stringify({
      runtimeProofEnvelopePath: result.envelopePath,
      runtimeProofEnvelopeSha256: result.envelopeSha256,
      requestSha256: result.requestSha256
    })}\n`);
    return;
  }
  const bytes = await readFileBounded(
    result.evidencePath,
    RUNTIME_PROOF_MAXIMUM_BYTES,
    'CNYOS_CONTROLLER_RUNTIME_CAPABILITY_EVIDENCE_INVALID'
  );
  process.stdout.write(`${JSON.stringify({
    evidencePath: result.evidencePath,
    evidenceSha256: sha256(bytes),
    runtimeProofEnvelopeSha256: result.runtimeProofEnvelopeSha256
  })}\n`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const mode = process.argv[2] || 'verify';
  if (process.argv.length > 3 || !['acquire', 'verify'].includes(mode)) {
    process.stderr.write('CNYOS_RUNTIME_CAPABILITY_ARGUMENTS_INVALID\n');
    process.exitCode = 1;
  } else {
    const action = mode === 'acquire'
      ? acquireRuntimeBoundaryProof()
      : verifyRuntimeCapabilityBoundary();
    action.then(result => emitResult(mode, result)).catch(error => {
      process.stderr.write(`${String(error?.message ||
        'CNYOS_RUNTIME_CAPABILITY_BOUNDARY_FAILED')}\n`);
      process.exitCode = 1;
    });
  }
}
