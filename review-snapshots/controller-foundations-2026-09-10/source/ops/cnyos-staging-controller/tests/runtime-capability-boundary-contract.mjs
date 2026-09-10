import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  RUNTIME_PROOF_MODE,
  assertRuntimeProofCredentialIsolation,
  runtimeEvidenceBoundaryPolicy,
  validateRuntimeProofEnvelope
} from '../scripts/verify-backup-disable-runtime-boundary.mjs';
import {
  deriveRuntimeCapabilityEvidence,
  validateRuntimeCapabilityEvidenceReceipt
} from '../scripts/verify-runtime-capability-boundary.mjs';
import { POLICY, sha256 } from '../scripts/policy.mjs';
import { createRuntimeProofFixture } from './backup-disable-runtime-boundary-contract.mjs';

const NOW = new Date('2030-01-01T00:10:00.000Z');
const SIGNED_EXPIRY = new Date('2030-01-01T00:19:00.000Z');

async function expectCode(action, expression) {
  await assert.rejects(action, expression);
}

function validBoundaryPolicy(fixture) {
  return {
    ...structuredClone(POLICY),
    runtimeEvidenceBoundary: {
      maximumProofAgeMinutes: fixture.context.boundary.maximumProofAgeMinutes,
      minimumRetentionDays: fixture.context.boundary.minimumRetentionDays,
      handlerVerifierImageDigest: fixture.context.boundary.handlerVerifierImageDigest,
      handlerVerifierSourceSha256: fixture.context.boundary.handlerVerifierSourceSha256,
      handlerVerifierNodeVersion: fixture.context.boundary.handlerVerifierNodeVersion,
      functionSecretBindings: structuredClone(
        fixture.context.boundary.functionSecretBindings
      ),
      platformReservedEnvironmentNames: structuredClone(
        fixture.context.boundary.platformReservedEnvironmentNames
      ),
      browserEnvironmentAllowlist: [],
      egressPolicyId: fixture.context.boundary.egressPolicyId,
      egressPolicyRevision: fixture.context.boundary.egressPolicyRevision,
      allowedEgressOrigins: structuredClone(
        fixture.context.boundary.allowedEgressOrigins
      )
    }
  };
}

export async function runRuntimeCapabilityBoundaryContract() {
  const fixture = createRuntimeProofFixture();
  const validation = validateRuntimeProofEnvelope(fixture.raw, {
    trust: fixture.trust,
    context: fixture.context,
    requestSha256: fixture.requestSha256,
    now: NOW
  });
  const proofSha256 = sha256(fixture.raw);
  const evidence = deriveRuntimeCapabilityEvidence({
    ...validation,
    context: fixture.context,
    sha256: proofSha256
  });
  assert.equal(evidence.status, 'passed');
  assert.equal(evidence.functionByteAttestationAvailable, false,
    'accepted limitation is stated, never upgraded to remote Function-byte proof');
  assert.equal(evidence.proofMode, RUNTIME_PROOF_MODE);
  assert.equal(evidence.runtimeProofEnvelopeSha256, proofSha256);
  assert.equal(evidence.platformControlEnabled, false);
  assert.equal(evidence.ownerDriveEnabled, false);
  assert.equal(evidence.restoreSourceApiEnabled, false);
  assert.equal(evidence.pubmedEnabled, false);
  assert.equal(evidence.directJsonRestoreTestEnabled, false);
  assert.equal(evidence.ownerControlEnabled, false);
  assert.equal(evidence.ownerControlScope, 'disabled');
  assert.equal(evidence.protectedSecretPresenceVerified, true);
  assert.equal(evidence.functionEnvironmentAllowlistComplete, true);
  assert.equal(evidence.functionSecretInventoryClosedWorld, true);
  assert.equal(evidence.browserProcessEnvironmentSanitized, true);
  assert.equal(evidence.candidateFunctionEgressPolicyEnforced, true);
  assert.equal(evidence.productionCredentialAbsenceVerified, true);
  assert.equal(evidence.stagingOnlyCredentialScopeVerified, true);
  assert.equal(evidence.serviceRoleNotInheritedByBrowserProcess, true);
  assert.equal(evidence.candidateFunctionsReceiveOnlyReviewedStagingSecrets, true);
  assert.equal(evidence.previousLiveDeployment.deployId,
    fixture.context.authorization.value.previousDeployId);
  assert.equal(evidence.source.commit, fixture.context.producer.manifest.candidateCommit);
  assert.equal(evidence.secretValuesSerialized, false);
  assert.doesNotMatch(JSON.stringify(evidence), /credential:cnyos/i,
    'sanitized output excludes provider credential references');
  assert.equal(validateRuntimeCapabilityEvidenceReceipt(
    evidence,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    NOW
  ).evidence, evidence);
  const forgedReceipt = structuredClone(evidence);
  forgedReceipt.functionSecretInventoryClosedWorld = false;
  await expectCode(async () => validateRuntimeCapabilityEvidenceReceipt(
    forgedReceipt,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    NOW
  ), /RUNTIME_CAPABILITY_EVIDENCE_INVALID/);
  const claimedBeforeSignedWindow = deriveRuntimeCapabilityEvidence({
    ...validation,
    context: fixture.context,
    sha256: proofSha256
  }, { verifiedAt: new Date('2030-01-01T00:08:59.999Z') });
  await expectCode(async () => validateRuntimeCapabilityEvidenceReceipt(
    claimedBeforeSignedWindow,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    NOW
  ), /RUNTIME_CAPABILITY_EVIDENCE_INVALID/);
  const claimedAtSignedExpiry = deriveRuntimeCapabilityEvidence({
    ...validation,
    context: fixture.context,
    sha256: proofSha256
  }, { verifiedAt: SIGNED_EXPIRY });
  await expectCode(async () => validateRuntimeCapabilityEvidenceReceipt(
    claimedAtSignedExpiry,
    { ...validation, context: fixture.context, sha256: proofSha256 },
    SIGNED_EXPIRY
  ), /RUNTIME_CAPABILITY_EVIDENCE_INVALID/);

  const reviewed = runtimeEvidenceBoundaryPolicy(validBoundaryPolicy(fixture));
  assert.deepEqual(reviewed.allowedEgressOrigins,
    fixture.context.boundary.allowedEgressOrigins);
  assert.equal(reviewed.minimumRetentionMs, 365 * 24 * 60 * 60 * 1000);

  await expectCode(async () => runtimeEvidenceBoundaryPolicy(POLICY),
    /BOUNDARY_POLICY_INVALID/);

  const productionEgress = validBoundaryPolicy(fixture);
  productionEgress.runtimeEvidenceBoundary.allowedEgressOrigins = [
    POLICY.productionDenylist.supabaseOrigin,
    POLICY.target.supabaseOrigin
  ].sort();
  await expectCode(async () => runtimeEvidenceBoundaryPolicy(productionEgress),
    /BOUNDARY_POLICY_INVALID/);

  const secretCollision = validBoundaryPolicy(fixture);
  secretCollision.runtimeEvidenceBoundary.platformReservedEnvironmentNames = [
    secretCollision.runtimeEvidenceBoundary.functionSecretBindings[0].name
  ];
  await expectCode(async () => runtimeEvidenceBoundaryPolicy(secretCollision),
    /BOUNDARY_POLICY_INVALID/);

  const unsortedBindings = validBoundaryPolicy(fixture);
  unsortedBindings.runtimeEvidenceBoundary.functionSecretBindings = [
    {
      name: 'Z_SECRET',
      provider: 'supabase',
      resourceId: POLICY.target.supabaseProjectRef
    },
    ...unsortedBindings.runtimeEvidenceBoundary.functionSecretBindings
  ];
  await expectCode(async () => runtimeEvidenceBoundaryPolicy(unsortedBindings),
    /BOUNDARY_POLICY_INVALID/);

  await expectCode(async () => assertRuntimeProofCredentialIsolation({
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-token',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.example/token'
  }), /CREDENTIAL_ISOLATION_INVALID/);
  assert.doesNotThrow(() => assertRuntimeProofCredentialIsolation({
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'a'.repeat(20),
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.example/token'
  }, { acquisition: true }));
  await expectCode(async () => assertRuntimeProofCredentialIsolation({
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'a'.repeat(20),
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.example/token',
    CNYOS_STAGING_NETLIFY_AUTH_TOKEN: 'forbidden'
  }, { acquisition: true }), /CREDENTIAL_ISOLATION_INVALID/);

  const missingSecret = structuredClone(validation.result);
  missingSecret.environmentSnapshot.entries =
    missingSecret.environmentSnapshot.entries.filter(entry =>
      entry.kind !== 'reviewed_secret');
  missingSecret.environmentSnapshot.entryCount = missingSecret.environmentSnapshot.entries.length;
  missingSecret.environmentSnapshot.inventorySha256 =
    sha256(JSON.stringify(missingSecret.environmentSnapshot.entries));
  await expectCode(async () => deriveRuntimeCapabilityEvidence({
    ...validation,
    result: missingSecret,
    context: fixture.context,
    sha256: proofSha256
  }), /SECRET_INVENTORY_INVALID/);

  const scriptPath = fileURLToPath(new URL(
    '../scripts/verify-runtime-capability-boundary.mjs',
    import.meta.url
  ));
  const backupScriptPath = fileURLToPath(new URL(
    '../scripts/verify-backup-disable-runtime-boundary.mjs',
    import.meta.url
  ));
  const [script, backupScript] = await Promise.all([
    fs.readFile(scriptPath, 'utf8'),
    fs.readFile(backupScriptPath, 'utf8')
  ]);
  assert.match(script, /callSignedBrokerOperation\(\{/,
    'acquisition uses the canonical signed broker client');
  assert.match(script, /mode === 'acquire'/);
  assert.match(script, /CNYOS_RUNTIME_EVIDENCE_BROKER_URL/);
  assert.match(backupScript, /CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256/);
  assert.match(backupScript, /verifySignedBrokerEnvelope\(raw,/,
    'offline verification uses the canonical signed broker verifier');
  assert.doesNotMatch(backupScript, /fetch\s*\(/,
    'offline backup proof verification has no network path');
  assert.doesNotMatch(backupScript, /publicHttpResponse|HTTP response is proof/i);
  assert.match(backupScript, /functionByteAttestationAvailable:\s*false/);
  assert.match(backupScript, /deployment_process_provenance/);

  return Object.freeze({ fixture, validation, evidence });
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runRuntimeCapabilityBoundaryContract().then(() => {
    process.stdout.write('CNYOS activation contract runtime-capability-boundary: passed\n');
  }).catch(error => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exitCode = 1;
  });
}
