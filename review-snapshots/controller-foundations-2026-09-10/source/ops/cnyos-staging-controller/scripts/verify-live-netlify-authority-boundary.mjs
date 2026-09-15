import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  POLICY, POLICY_SHA256, assertControllerRuntime,
  assertPolicyTarget, decodeNonce, exactSha40,
  exactSha256, fail, required, sha256
} from './policy.mjs';
import { assertAuthorization, assertRollbackAttestationRetention, loadEvidence, validateLiveNetlifyAuthorityBoundary } from './netlify-evidence.mjs';
import { OIDC_FORBIDDEN_ENVIRONMENT_NAMES, brokerTrustRoot, callSignedBrokerOperation } from './reconcile-netlify-release-state.mjs';

export { LIVE_AUTHORITY_OPERATION, AUTHORITY_DENIED_PUBLISHER_KINDS,
  validateAuthorityMeasurements, authorityEvidenceFromVerifiedResponse } from './netlify-evidence.mjs';
import { LIVE_AUTHORITY_OPERATION, authorityEvidenceFromVerifiedResponse } from './netlify-evidence.mjs';
const CODE = 'CNYOS_LIVE_NETLIFY_AUTHORITY_PROOF_INVALID';

async function destination(value) {
  const filename = required(value, 'CNYOS_LIVE_NETLIFY_AUTHORITY_OUTPUT_REQUIRED', 4096);
  if (!path.isAbsolute(filename) || path.resolve(filename) !== filename ||
    await fs.realpath(path.dirname(filename)) !== path.dirname(filename)) fail(CODE);
  try { await fs.lstat(filename); } catch (error) { if (error.code === 'ENOENT') return filename; throw error; }
  fail('CNYOS_LIVE_NETLIFY_AUTHORITY_OUTPUT_EXISTS');
}

export async function verifyLiveNetlifyAuthorityBoundary({ env = process.env, fetchImpl = globalThis.fetch, oidcTokenProvider, now = () => new Date() } = {}) {
  env = Object.freeze({ ...env });
  for (const name of OIDC_FORBIDDEN_ENVIRONMENT_NAMES) if (Object.hasOwn(env, name)) fail('CNYOS_LIVE_NETLIFY_AUTHORITY_CREDENTIAL_REJECTED');
  const runtime = assertControllerRuntime(env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath ||
    (Object.hasOwn(env, 'CNYOS_TARGET_CONTROLLER_RUN_ID') && env.CNYOS_TARGET_CONTROLLER_RUN_ID !== runtime.runId)) fail(CODE);
  const trust = brokerTrustRoot('authority'); // Inactive pins fail before token acquisition or a network call.
  const startedAt = now();
  if (!(startedAt instanceof Date) || !Number.isFinite(startedAt.getTime())) fail(CODE);
  const output = await destination(env.CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH);
  const authorization = await loadEvidence(env.CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256, CODE);
  assertAuthorization(authorization.value, runtime, env, startedAt);
  if (authorization.value.policySha256 !== POLICY_SHA256 ||
    authorization.value.controllerRunId !== runtime.runId ||
    authorization.value.source?.repository !== POLICY.sourceRepository ||
    authorization.value.dispatchNonce !== decodeNonce(env.CNYOS_DISPATCH_NONCE).value) fail(CODE);
  assertPolicyTarget(authorization.value.target, CODE);
  decodeNonce(authorization.value.dispatchNonce);
  exactSha40(authorization.value.source?.commit, CODE);
  exactSha40(authorization.value.source?.tree, CODE);
  exactSha256(authorization.value.artifact?.artifactSha256, CODE);
  const deposit = await loadEvidence(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256, CODE);
  const deposited = deposit.value;
  if (deposited.schemaVersion !== 1 || deposited.status !== 'passed' || deposited.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_validation' ||
    deposited.scope !== 'cnyos_staging_only' || deposited.productionAuthorization !== false ||
    deposited.realPatientDataAuthorized !== false || deposited.secretValuesSerialized !== false ||
    deposited.controllerRepository !== runtime.repository || deposited.controllerRef !== runtime.ref ||
    deposited.controllerWorkflowPath !== runtime.workflowPath ||
    deposited.controllerRunAttempt !== 1 || deposited.immutableAppendOnlyDepositVerified !== true ||
    deposited.exactRunNonceRetrievalBoundaryVerified !== true || deposited.completeRecoveryMaterialStoredVerified !== true ||
    deposited.rawPayloadArtifactExposure !== false ||
    deposited.controllerRunId !== runtime.runId || deposited.controllerCommit !== runtime.commit ||
    deposited.policySha256 !== POLICY_SHA256 || deposited.dispatchNonce !== authorization.value.dispatchNonce ||
    !isDeepStrictEqual(deposited.source, authorization.value.source) ||
    !isDeepStrictEqual(deposited.artifact, authorization.value.artifact) ||
    !isDeepStrictEqual(deposited.target, {
      netlifySiteId: POLICY.target.netlifySiteId, netlifyOrigin: POLICY.target.netlifyOrigin,
      supabaseProjectRef: POLICY.target.supabaseProjectRef, databaseSystemIdentifier: POLICY.target.databaseSystemIdentifier,
      targetSha256: sha256(JSON.stringify(POLICY.target)), previousDeployId: authorization.value.previousDeployId
    }) ||
    deposited.previousDeployId !== authorization.value.previousDeployId) fail(CODE);
  assertRollbackAttestationRetention(deposited, startedAt);
  const resumer = { controllerRepository: runtime.repository, controllerRef: runtime.ref,
    controllerWorkflowPath: runtime.workflowPath, controllerRunId: runtime.runId,
    controllerRunAttempt: 1, controllerCommit: runtime.commit };
  const target = { ...resumer, dispatchNonce: authorization.value.dispatchNonce,
    netlifySiteId: POLICY.target.netlifySiteId, barrierGeneration: null };
  const verified = await callSignedBrokerOperation({ env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_AUTHORITY_BROKER_URL, operation: LIVE_AUTHORITY_OPERATION, resumer, target,
    evidence: { authorizationEvidenceSha256: authorization.sha256, rollbackAttestationDepositEvidenceSha256: deposit.sha256,
      source: { repository: POLICY.sourceRepository, commit: authorization.value.source.commit, tree: authorization.value.source.tree },
      artifactSha256: authorization.value.artifact.artifactSha256, startedAt: startedAt.toISOString() }, now });
  const evidence = authorityEvidenceFromVerifiedResponse(verified, { runtime, authorization: authorization.value,
    authorizationSha256: authorization.sha256, depositSha256: deposit.sha256, trust, startedAt });
  validateLiveNetlifyAuthorityBoundary(evidence, { runtime, authorization: authorization.value,
    authorizationSha256: authorization.sha256, depositSha256: deposit.sha256, now: verified.observedAt });
  assertAuthorization(authorization.value, runtime, env, now());
  const staged = await fs.mkdtemp(path.join(path.dirname(output), '.cnyos-authority-'));
  try {
    const filename = path.join(staged, 'receipt.json');
    await fs.writeFile(filename, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    await fs.link(filename, output);
  } finally { await fs.rm(staged, { recursive: true, force: true }); }
  return Object.freeze({ evidence, evidencePath: output });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyLiveNetlifyAuthorityBoundary().then(() => process.stdout.write('CNYOS live Netlify authority verification: passed\n')).catch(error => {
    process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message : 'CNYOS_LIVE_NETLIFY_AUTHORITY_VERIFICATION_FAILED'}\n`);
    process.exitCode = 1;
  });
}
