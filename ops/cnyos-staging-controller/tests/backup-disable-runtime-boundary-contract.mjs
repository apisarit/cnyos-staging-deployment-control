import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BACKUP_DISABLE_FUNCTION_NAMES,
  RUNTIME_FUNCTION_BYTE_ATTESTATION_AVAILABLE,
  RUNTIME_PROOF_CAPABILITY_INTERCEPTORS,
  RUNTIME_PROOF_MODE,
  RUNTIME_PROOF_OPERATION,
  deriveBackupDisableRuntimeEvidence,
  runtimeProofBrokerRequestComponents,
  runtimeProofBrokerRequestSha256,
  validateBackupDisableRuntimeEvidenceReceipt,
  validateRuntimeProofEnvelope,
  writeCanonicalBytesExclusive
} from '../scripts/verify-backup-disable-runtime-boundary.mjs';
import { POLICY, POLICY_SHA256, sha256 } from '../scripts/policy.mjs';

const NOW = new Date('2030-01-01T00:10:00.000Z');
const RESULT_OBSERVED_AT = '2030-01-01T00:08:00.000Z';
const ISSUED_AT = '2030-01-01T00:09:00.000Z';
const EXPIRES_AT = '2030-01-01T00:19:00.000Z';
const CREATED_AT = '2029-12-31T23:55:00.000Z';
const PUBLISHED_AT = '2030-01-01T00:00:00.000Z';
const CONFIGURED_AT = '2029-12-31T23:50:00.000Z';
const SEALED_AT = '2030-01-01T00:01:00.000Z';
const EXECUTED_AT = '2029-12-31T23:58:00.000Z';
const RETENTION_UNTIL = '2032-01-01T00:00:00.000Z';
const SOURCE_COMMIT = 'a'.repeat(40);
const SOURCE_TREE = 'b'.repeat(40);
const FUNCTION_TREE = 'c'.repeat(40);
const CONTROLLER_COMMIT = 'd'.repeat(40);
const PREVIOUS_SOURCE_COMMIT = 'e'.repeat(40);
const PREVIOUS_DEPLOY_ID = '0123456789abcdef01234567';
const RUN_ID = '123456789';
const DISPATCH_NONCE = Buffer.alloc(32, 17).toString('base64url');

function digest(label) {
  return sha256(`fixture:${label}`);
}

function bytewiseCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function recordDigest(value) {
  const { recordSha256: ignored, ...record } = value;
  return sha256(JSON.stringify(record));
}

function deploymentProcessDigest(value) {
  return sha256(JSON.stringify({
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
  }));
}

function signedEnvelope(result, fixture, {
  issuedAt = ISSUED_AT,
  expiresAt = EXPIRES_AT,
  requestSha256 = fixture.requestSha256,
  privateKey = fixture.privateKey,
  keyId = fixture.trust.signingKeyId
} = {}) {
  const statement = {
    schemaVersion: 1,
    operationDomain: fixture.trust.operationDomain,
    operation: RUNTIME_PROOF_OPERATION,
    policyId: fixture.trust.policyId,
    policySha256: fixture.trust.policySha256,
    requestSha256,
    issuedAt,
    expiresAt,
    result
  };
  const rawStatement = JSON.stringify(statement);
  const signature = crypto.sign(null, Buffer.from(rawStatement), privateKey);
  return JSON.stringify({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_broker_envelope',
    statement,
    brokerSignature: {
      algorithm: 'Ed25519',
      keyId,
      statementSha256: sha256(rawStatement),
      signatureBase64: signature.toString('base64'),
      signatureSha256: sha256(signature)
    }
  });
}

function publicEnvironmentEntry(name) {
  return {
    name,
    kind: 'reviewed_public',
    contexts: ['production'],
    scopes: ['functions'],
    origins: ['site'],
    precedence: 1,
    valueSha256: sha256(POLICY.functionEnvironment[name]),
    credentialReference: null,
    bindingProvider: null,
    bindingResourceId: null,
    bindingEnvironment: null
  };
}

function secretEnvironmentEntry(binding) {
  return {
    name: binding.name,
    kind: 'reviewed_secret',
    contexts: ['production'],
    scopes: ['functions'],
    origins: ['site'],
    precedence: 1,
    valueSha256: null,
    credentialReference: `credential:${binding.name.toLowerCase()}`,
    bindingProvider: binding.provider,
    bindingResourceId: binding.resourceId,
    bindingEnvironment: 'staging'
  };
}

function reservedEnvironmentEntry(name) {
  return {
    name,
    kind: 'platform_reserved',
    contexts: ['production'],
    scopes: ['functions'],
    origins: ['platform'],
    precedence: 0,
    valueSha256: null,
    credentialReference: null,
    bindingProvider: null,
    bindingResourceId: null,
    bindingEnvironment: null
  };
}

export function createRuntimeProofFixture() {
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const boundary = Object.freeze({
    maximumProofAgeMinutes: 10,
    minimumRetentionDays: 365,
    handlerVerifierImageDigest: `sha256:${digest('handler-image')}`,
    handlerVerifierSourceSha256: digest('handler-source'),
    handlerVerifierNodeVersion: '24.20.0',
    functionSecretBindings: Object.freeze([
      Object.freeze({
        name: 'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
        provider: 'supabase',
        resourceId: POLICY.target.supabaseProjectRef
      })
    ]),
    platformReservedEnvironmentNames: Object.freeze(['CONTEXT', 'DEPLOY_ID']),
    browserEnvironmentAllowlist: Object.freeze([]),
    egressPolicyId: 'cnyos-staging-egress-v1',
    egressPolicyRevision: 'revision-00000001',
    allowedEgressOrigins: Object.freeze([POLICY.target.supabaseOrigin]),
    maximumAgeMs: 10 * 60 * 1000,
    minimumRetentionMs: 365 * 24 * 60 * 60 * 1000
  });
  const manifest = {
    candidateCommit: SOURCE_COMMIT,
    candidateTree: SOURCE_TREE,
    functionSourceTree: FUNCTION_TREE,
    artifactSha256: digest('candidate-artifact'),
    staticArtifactSha256: digest('static-artifact'),
    functionBundleManifestSha256: digest('function-bundle'),
    functionSourcesSha256: digest('function-sources'),
    files: [
      { path: 'payload/dist/deploy-manifest.json', size: 40, sha256: digest('deploy') },
      { path: 'payload/dist/index.html', size: 30, sha256: digest('index') }
    ]
  };
  const context = {
    runtime: {
      repository: POLICY.controller.repository,
      ref: POLICY.controller.protectedRef,
      commit: CONTROLLER_COMMIT,
      workflowPath: POLICY.controller.releaseWorkflowPath,
      workflowRef:
        `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@` +
        POLICY.controller.protectedRef,
      runId: RUN_ID
    },
    observedAt: NOW,
    producer: {
      manifest,
      manifestSha256: digest('producer-manifest')
    },
    authorization: {
      sha256: digest('authorization'),
      value: { previousDeployId: PREVIOUS_DEPLOY_ID }
    },
    functionEnvironment: { sha256: digest('function-environment') },
    rollbackDeposit: { sha256: digest('rollback-deposit') },
    liveAuthority: { sha256: digest('live-authority') },
    boundary,
    dispatchNonce: DISPATCH_NONCE
  };
  const trust = Object.freeze({
    operationDomain: 'cnyos_staging_runtime_boundary',
    policyId: 'cnyos-staging-runtime-evidence-v1',
    policySha256: digest('runtime-broker-policy'),
    signingKeyId: 'runtime-signing-key-00000001',
    publicKey: keyPair.publicKey,
    maximumAgeMs: 10 * 60 * 1000
  });
  const components = runtimeProofBrokerRequestComponents(context);
  const requestSha256 = runtimeProofBrokerRequestSha256(trust, components);
  const archives = BACKUP_DISABLE_FUNCTION_NAMES.map((functionName, index) => ({
    functionName,
    sha256: digest(`archive:${functionName}`),
    size: 1000 + index
  }));
  const deploymentProcessId = 'deployment-process-00000001';
  const handlerExecutions = archives.map(archive => {
    const invocationKind = archive.functionName === 'database-backup-background'
      ? 'background_post' : 'scheduled_event';
    const body = invocationKind === 'scheduled_event'
      ? JSON.stringify({ next_run: '2030-01-01T00:00:00.000Z' }) : '';
    const input = {
      method: 'POST',
      headers: invocationKind === 'scheduled_event'
        ? { 'content-length': String(Buffer.byteLength(body, 'utf8')) } : {},
      body
    };
    const record = {
      functionName: archive.functionName,
      archiveSha256: archive.sha256,
      deploymentProcessId,
      executionRecordId: `execution-record:${archive.functionName}`,
      executedAt: EXECUTED_AT,
      invocationKind,
      input,
      inputSha256: sha256(JSON.stringify(input)),
      backupEnabledValue: 'false',
      outputStatusCode: 200,
      outputBodySha256: sha256(JSON.stringify({ ok: true, enabled: false })),
      events: [
        {
          sequence: 1,
          type: 'environment_read',
          name: 'BACKUP_ENABLED',
          target: null,
          statusCode: null,
          bodySha256: null
        },
        {
          sequence: 2,
          type: 'response',
          name: null,
          target: null,
          statusCode: 200,
          bodySha256: sha256(JSON.stringify({ ok: true, enabled: false }))
        }
      ],
      recordSha256: ''
    };
    record.recordSha256 = recordDigest(record);
    return record;
  });
  const environmentEntries = [
    ...Object.keys(POLICY.functionEnvironment).sort(bytewiseCompare)
      .map(publicEnvironmentEntry),
    ...boundary.functionSecretBindings.map(secretEnvironmentEntry),
    ...boundary.platformReservedEnvironmentNames.map(reservedEnvironmentEntry)
  ].sort((left, right) => bytewiseCompare(left.name, right.name));
  const browserInspection = {
    artifactSha256: manifest.staticArtifactSha256,
    fileCount: manifest.files.filter(entry => entry.path.startsWith('payload/dist/')).length,
    inspectorImageDigest: boundary.handlerVerifierImageDigest,
    inspectorSourceSha256: boundary.handlerVerifierSourceSha256,
    processEnvironmentReferences: [],
    secretNameReferences: [],
    dynamicEnvironmentAccessCount: 0,
    credentialPatternMatchCount: 0,
    sourceMapExternalReferenceCount: 0,
    recordSha256: ''
  };
  browserInspection.recordSha256 = recordDigest(browserInspection);
  const egressRules = boundary.allowedEgressOrigins.map((origin, index) => ({
    order: index + 1,
    action: 'allow',
    origin
  }));
  const candidate = components.evidence.candidate;
  const result = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_runtime_boundary_provider_result',
    status: 'observed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    observedAt: RESULT_OBSERVED_AT,
    controller: {
      repository: context.runtime.repository,
      ref: context.runtime.ref,
      commit: context.runtime.commit,
      workflowPath: context.runtime.workflowPath,
      workflowRef: context.runtime.workflowRef,
      runId: context.runtime.runId,
      runAttempt: 1,
      dispatchNonce: context.dispatchNonce
    },
    policySha256: POLICY_SHA256,
    authorizationEvidenceSha256: context.authorization.sha256,
    rollbackAttestationDepositEvidenceSha256: context.rollbackDeposit.sha256,
    liveNetlifyAuthorityEvidenceSha256: context.liveAuthority.sha256,
    functionEnvironmentEvidenceSha256: context.functionEnvironment.sha256,
    candidate,
    previousLiveDeployment: {
      netlifySiteId: POLICY.target.netlifySiteId,
      netlifyOrigin: POLICY.target.netlifyOrigin,
      deployId: PREVIOUS_DEPLOY_ID,
      deployOrigin: `https://${PREVIOUS_DEPLOY_ID}--${POLICY.target.netlifySiteName}.netlify.app`,
      state: 'ready',
      context: 'production',
      draft: false,
      sourceCommit: PREVIOUS_SOURCE_COMMIT,
      createdAt: CREATED_AT,
      publishedAt: PUBLISHED_AT,
      deployManifestSha256: digest('previous-deploy-manifest'),
      functionArchiveInventorySha256: sha256(JSON.stringify(archives)),
      environmentSnapshotRevision: 'environment-snapshot-00000001'
    },
    deploymentProcess: {
      proofMode: RUNTIME_PROOF_MODE,
      functionByteAttestationAvailable: false,
      deployId: PREVIOUS_DEPLOY_ID,
      sourceCommit: PREVIOUS_SOURCE_COMMIT,
      deployManifestSha256: digest('previous-deploy-manifest'),
      environmentSnapshotRevision: 'environment-snapshot-00000001',
      deploymentProcessId,
      deploymentProcessRecordSha256: digest('deployment-process'),
      archivedInputSetSha256: digest('archived-inputs'),
      archivedInputSetSize: 8192,
      archivedInputReference: 'retained-input-set:00000001',
      functionArchives: archives,
      functionArchiveInventorySha256: sha256(JSON.stringify(archives))
    },
    environmentSnapshot: {
      deployId: PREVIOUS_DEPLOY_ID,
      revision: 'environment-snapshot-00000001',
      inventoryDefinition:
        'complete_effective_user_and_platform_function_environment_at_deploy',
      configuredAt: CONFIGURED_AT,
      sealedAt: SEALED_AT,
      entryCount: environmentEntries.length,
      entries: environmentEntries,
      inventorySha256: sha256(JSON.stringify(environmentEntries))
    },
    handlerVerifier: {
      imageDigest: boundary.handlerVerifierImageDigest,
      sourceSha256: boundary.handlerVerifierSourceSha256,
      nodeVersion: boundary.handlerVerifierNodeVersion,
      captureMode: 'sealed_complete_security_capability_trace_v1',
      interceptors: RUNTIME_PROOF_CAPABILITY_INTERCEPTORS,
      networkNamespace: 'deny_all',
      capturePhase: 'module_load_and_handler_invocation'
    },
    handlerExecutions,
    browserArtifactInspection: browserInspection,
    egressEnforcement: {
      policyId: boundary.egressPolicyId,
      policyRevision: boundary.egressPolicyRevision,
      siteId: POLICY.target.netlifySiteId,
      candidateArtifactSha256: manifest.artifactSha256,
      enforcementPoint: 'provider_function_runtime',
      defaultAction: 'deny',
      candidateBindingMode: 'site_policy_applies_to_exact_next_deploy',
      configurationRevision: 'egress-configuration-00000001',
      observedAt: RESULT_OBSERVED_AT,
      rules: egressRules,
      rulesSha256: sha256(JSON.stringify(egressRules))
    },
    retention: {
      proofId: 'runtime-proof:00000001',
      depositSequence: 1,
      depositedAt: RESULT_OBSERVED_AT,
      retentionUntil: RETENTION_UNTIL,
      immutable: true,
      appendOnly: true
    }
  };
  result.deploymentProcess.deploymentProcessRecordSha256 =
    deploymentProcessDigest(result.deploymentProcess);
  const fixture = {
    context,
    trust,
    privateKey: keyPair.privateKey,
    requestSha256,
    result
  };
  return Object.freeze({
    ...fixture,
    raw: signedEnvelope(result, fixture),
    sign: (candidate, options) => signedEnvelope(candidate, fixture, options)
  });
}

async function expectCode(action, expression) {
  await assert.rejects(action, expression);
}

function resignMutation(fixture, mutate) {
  const result = structuredClone(fixture.result);
  mutate(result);
  return fixture.sign(result);
}

export async function runBackupDisableRuntimeBoundaryContract() {
  const fixture = createRuntimeProofFixture();
  const validation = validateRuntimeProofEnvelope(fixture.raw, {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  });
  const proofSha256 = sha256(fixture.raw);
  const evidence = deriveBackupDisableRuntimeEvidence({
    ...validation,
    context: fixture.context,
    sha256: proofSha256
  });
  assert.equal(evidence.status, 'passed');
  assert.equal(evidence.backupEnabled, false);
  assert.equal(evidence.currentDeployId, PREVIOUS_DEPLOY_ID);
  assert.equal(evidence.source.commit, SOURCE_COMMIT,
    'candidate identity remains separate from previous live deployment');
  assert.equal(evidence.previousLiveDeployment.sourceCommit, PREVIOUS_SOURCE_COMMIT);
  assert.equal(evidence.functionByteAttestationAvailable,
    RUNTIME_FUNCTION_BYTE_ATTESTATION_AVAILABLE);
  assert.equal(evidence.proofMode, RUNTIME_PROOF_MODE);
  assert.equal(evidence.handlerFailClosed.evidenceSha256, proofSha256);
  assert.equal(validateBackupDisableRuntimeEvidenceReceipt(
    evidence,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    NOW
  ).evidence, evidence);
  const forgedReceipt = structuredClone(evidence);
  forgedReceipt.handlerFailClosed.dailyBeforeConfigurationOrSupabase = false;
  await expectCode(async () => validateBackupDisableRuntimeEvidenceReceipt(
    forgedReceipt,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    NOW
  ), /BACKUP_DISABLE_EVIDENCE_INVALID/);
  const claimedBeforeSignedWindow = deriveBackupDisableRuntimeEvidence({
    ...validation,
    context: fixture.context,
    sha256: proofSha256
  }, { verifiedAt: new Date('2030-01-01T00:08:59.999Z') });
  await expectCode(async () => validateBackupDisableRuntimeEvidenceReceipt(
    claimedBeforeSignedWindow,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    NOW
  ), /BACKUP_DISABLE_EVIDENCE_INVALID/);
  const claimedAtSignedExpiry = deriveBackupDisableRuntimeEvidence({
    ...validation,
    context: fixture.context,
    sha256: proofSha256
  }, { verifiedAt: new Date(EXPIRES_AT) });
  await expectCode(async () => validateBackupDisableRuntimeEvidenceReceipt(
    claimedAtSignedExpiry,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    new Date(EXPIRES_AT)
  ), /BACKUP_DISABLE_EVIDENCE_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(`${fixture.raw}\n`, {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /NONCANONICAL/);

  const unsigned = JSON.parse(fixture.raw);
  unsigned.statement.result.status = 'passed';
  await expectCode(async () => validateRuntimeProofEnvelope(JSON.stringify(unsigned), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /SIGNATURE_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(fixture.raw, {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: digest('wrong-request'),
    now: NOW
  }), /RESPONSE_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(fixture.sign(fixture.result, {
    issuedAt: '2029-12-31T23:00:00.000Z',
    expiresAt: '2029-12-31T23:10:00.000Z'
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /STALE/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.deploymentProcess.functionByteAttestationAvailable = true;
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.deploymentProcess.deployManifestSha256 = digest('unbound-deploy-manifest');
    result.deploymentProcess.deploymentProcessRecordSha256 =
      deploymentProcessDigest(result.deploymentProcess);
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    const record = result.handlerExecutions.find(entry =>
      entry.invocationKind === 'scheduled_event');
    record.input.headers['x-unreviewed'] = '1';
    record.inputSha256 = sha256(JSON.stringify(record.input));
    record.recordSha256 = recordDigest(record);
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.browserArtifactInspection.dynamicEnvironmentAccessCount = 1;
    result.browserArtifactInspection.recordSha256 =
      recordDigest(result.browserArtifactInspection);
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.previousLiveDeployment.deployId = 'f'.repeat(24);
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    const record = result.handlerExecutions[0];
    record.events.splice(1, 0, {
      sequence: 2,
      type: 'supabase',
      name: null,
      target: POLICY.target.supabaseOrigin,
      statusCode: null,
      bodySha256: null
    });
    record.events[2].sequence = 3;
    record.recordSha256 = recordDigest(record);
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    const secret = result.environmentSnapshot.entries.find(entry =>
      entry.kind === 'reviewed_secret');
    secret.valueSha256 = digest('secret-value-forbidden');
    result.environmentSnapshot.inventorySha256 =
      sha256(JSON.stringify(result.environmentSnapshot.entries));
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.environmentSnapshot.entries.push(structuredClone(
      result.environmentSnapshot.entries.at(-1)
    ));
    result.environmentSnapshot.entryCount += 1;
    result.environmentSnapshot.inventorySha256 =
      sha256(JSON.stringify(result.environmentSnapshot.entries));
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.browserArtifactInspection.secretNameReferences =
      ['CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY'];
    result.browserArtifactInspection.recordSha256 =
      recordDigest(result.browserArtifactInspection);
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.egressEnforcement.rules[0].origin = POLICY.productionDenylist.supabaseOrigin;
    result.egressEnforcement.rulesSha256 = sha256(JSON.stringify(
      result.egressEnforcement.rules
    ));
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.retention.retentionUntil = '2030-06-01T00:00:00.000Z';
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.retention.depositedAt = '2030-01-01T00:09:00.001Z';
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.publicHttpResponseProof = { statusCode: 200, bodySha256: digest('public') };
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  await expectCode(async () => validateRuntimeProofEnvelope(resignMutation(fixture, result => {
    result.handlerOrderingVerified = true;
  }), {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  }), /RESULT_INVALID/);

  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-runtime-proof-'));
  try {
    const retainedPath = path.join(temporary, 'proof.json');
    await writeCanonicalBytesExclusive(retainedPath, fixture.raw);
    assert.equal(await fs.readFile(retainedPath, 'utf8'), fixture.raw);
    await expectCode(() => writeCanonicalBytesExclusive(retainedPath, fixture.raw), /EEXIST/);
    assert.equal(await fs.readFile(retainedPath, 'utf8'), fixture.raw,
      'exclusive retained proof publication never overwrites existing bytes');
    const failedEvidencePath = path.join(temporary, 'must-not-exist.json');
    await expectCode(async () => {
      validateRuntimeProofEnvelope(resignMutation(fixture, result => {
        result.handlerExecutions = [];
      }), {
        trust: fixture.trust,
        context: fixture.context,
        requestSha256: fixture.requestSha256,
        now: NOW
      });
      await fs.writeFile(failedEvidencePath, 'unexpected');
    }, /RESULT_INVALID/);
    await assert.rejects(() => fs.stat(failedEvidencePath), /ENOENT/);
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }

  return Object.freeze({ fixture, validation, proofSha256 });
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runBackupDisableRuntimeBoundaryContract().then(() => {
    process.stdout.write('CNYOS activation contract backup-disable-runtime-boundary: passed\n');
  }).catch(error => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exitCode = 1;
  });
}
