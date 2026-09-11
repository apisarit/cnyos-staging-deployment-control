import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY, POLICY_SHA256, assertControllerRuntime, assertExactKeys, assertPolicyTarget,
  canonicalIsoTimestamp, decodeNonce, exactDeployId, exactSha256, fail,
  parseJsonObject, readRegularFileStable, required, sha256, writeJsonExclusive
} from './policy.mjs';
import {
  OIDC_FORBIDDEN_ENVIRONMENT_NAMES, brokerTrustRoot, callSignedBrokerOperation,
  verifySignedBrokerEnvelope
} from './reconcile-netlify-release-state.mjs';
import {
  assertFreshPreflight, assertDraftMetadataPromotionChain, validateRollbackReadinessEvidence,
  validatePromotionDraftGate
} from './netlify-evidence.mjs';
import { validateStoredLiveGitHubReleaseBoundary } from './verify-live-github-release-boundary.mjs';

export const PUBLISHER_OPERATIONS = Object.freeze({ acquire: 'acquire_exclusive_publisher', release: 'release_exclusive_publisher' });
const ERROR = 'CNYOS_EXCLUSIVE_PUBLISHER_INVALID';
const LEASE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'controllerRepository', 'controllerRef', 'controllerCommit', 'controllerRunId',
  'controllerRunAttempt', 'dispatchNonce', 'source', 'artifact', 'netlifySiteId',
  'draftDeployId', 'previousPublishedDeployId', 'enforcementAuthority', 'brokerPolicyId',
  'brokerPolicySha256', 'netlifyGitPublishingDisabled', 'buildHooksDisabled',
  'manualUiPublishingDenied', 'lockLeaseActive', 'runReconciliationBarrierActive',
  'runReconciliationBarrierGeneration', 'newMutationBlockedWhileRunReconciliationBarrierActive',
  'automaticRunReconciliationBarrierExpiryPermitted', 'renewalSupported', 'releaseRequired',
  'lockLeaseId', 'acquiredAt', 'expiresAt', 'brokerRequest', 'brokerEnvelope'
]);

export function publisherOidcEnvironment(env) {
  for (const key of OIDC_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, key)) fail('CNYOS_PUBLISHER_CREDENTIAL_CORESIDENCY_FORBIDDEN');
  }
}

export function publisherNow(now) {
  const result = now();
  if (!(result instanceof Date) || !Number.isFinite(result.getTime())) fail(ERROR);
  return result;
}

export function publisherRuntime(env) {
  const runtime = assertControllerRuntime(env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath) fail(ERROR);
  return runtime;
}

export function publisherResumer(runtime) {
  return {
    controllerRepository: runtime.repository, controllerRef: runtime.ref,
    controllerWorkflowPath: runtime.workflowPath, controllerRunId: runtime.runId,
    controllerRunAttempt: 1, controllerCommit: runtime.commit
  };
}

export function publisherTarget(runtime, nonce, generation = null) {
  if (generation !== null && !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$/.test(generation)) fail(ERROR);
  return { ...publisherResumer(runtime), dispatchNonce: decodeNonce(nonce).value,
    netlifySiteId: POLICY.target.netlifySiteId, barrierGeneration: generation };
}

export async function publisherEvidence(env, suffix, type = null) {
  const filename = required(env[`CNYOS_CONTROLLER_${suffix}_EVIDENCE_PATH`], `${ERROR}_PATH`, 4096);
  const bytes = await readRegularFileStable(filename, 4 * 1024 * 1024, ERROR, 1);
  const digest = sha256(bytes);
  if (digest !== exactSha256(env[`CNYOS_EXPECTED_${suffix}_EVIDENCE_SHA256`], ERROR)) fail(`${ERROR}_DIGEST`);
  const value = parseJsonObject(bytes.toString('utf8'), ERROR);
  if (type !== null && value.evidenceType !== type) fail(ERROR);
  return { filename, bytes, sha256: digest, value };
}

export async function publisherInputsUnchanged(inputs) {
  for (const item of inputs) {
    const bytes = await readRegularFileStable(item.filename, 4 * 1024 * 1024, ERROR, 1);
    if (!bytes.equals(item.bytes)) fail('CNYOS_PUBLISHER_INPUT_CHANGED');
  }
}

export async function publisherOutputAvailable(filename, inputs = []) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || path.resolve(filename) !== filename) fail(ERROR);
  if (inputs.some(item => path.resolve(item.filename) === filename)) fail(ERROR);
  const parent = path.dirname(filename);
  const stat = await fs.lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(parent) !== parent) fail(ERROR);
  try { await fs.lstat(filename); } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  fail('CNYOS_PUBLISHER_OUTPUT_EXISTS');
}

export function publisherRequest(operation, trust, resumer, target, evidence) {
  // Exact existing reconciliation request schema/order, retained for later signature verification.
  return {
    schemaVersion: 1, evidenceType: 'cnyos_staging_reconciliation_broker_request',
    operationDomain: trust.operationDomain, operation, policyId: trust.policyId,
    policySha256: trust.policySha256, controllerPolicySha256: POLICY_SHA256,
    resumer, target, evidence
  };
}

function assertIdentity(value, runtime, preflight, observedAt) {
  assertPolicyTarget(value.target, ERROR);
  const verifiedAt = canonicalIsoTimestamp(value.verifiedAt, ERROR);
  if (value.controllerRepository !== runtime.repository || value.controllerRef !== runtime.ref ||
    value.controllerCommit !== runtime.commit || value.controllerRunId !== runtime.runId ||
    value.schemaVersion !== 1 || value.authorization !== false || value.promotionAuthorization !== false ||
    value.productionAuthorization !== false || value.scope !== 'cnyos_staging_only' ||
    value.dispatchNonce !== preflight.dispatchNonce || value.source?.repository !== POLICY.sourceRepository ||
    value.source?.commit !== preflight.source.commit || value.source?.tree !== preflight.source.tree ||
    value.artifact?.artifactSha256 !== preflight.artifact.artifactSha256 ||
    verifiedAt > observedAt || observedAt - verifiedAt > 10 * 60_000) fail(ERROR);
}

export async function loadPublisherAcquisition(env, runtime, now) {
  const preflight = await publisherEvidence(env, 'PREFLIGHT', 'cnyos_staging_controller_preflight');
  assertFreshPreflight(preflight.value, runtime, now);
  if (preflight.value.dispatchNonce !== decodeNonce(env.CNYOS_DISPATCH_NONCE).value ||
    preflight.value.source.commit !== env.CNYOS_CANDIDATE_SHA) fail(ERROR);
  const readiness = await publisherEvidence(env, 'ROLLBACK_READINESS', 'cnyos_staging_controller_rollback_readiness');
  validateRollbackReadinessEvidence(readiness.value, { runtime, preflight: preflight.value,
    preflightSha256: preflight.sha256, observedAt: now });
  const gate = await publisherEvidence(env, 'DRAFT_GATE', 'cnyos_staging_controller_draft_gate');
  validatePromotionDraftGate(gate.value, { runtime, preflight: preflight.value,
    preflightSha256: preflight.sha256, rollbackReadinessSha256: readiness.sha256, observedAt: now });
  const verification = await publisherEvidence(env, 'DRAFT_VERIFICATION', 'cnyos_staging_controller_draft_verification');
  const metadata = await publisherEvidence(env, 'DRAFT_METADATA', 'cnyos_staging_controller_draft_metadata_verification');
  const control = await publisherEvidence(env, 'CONTROL_BEHAVIOR', 'cnyos_staging_controller_netlify_control_behavior_verification');
  const lifecycle = await publisherEvidence(env, 'PRIVATE_DRAFT', 'cnyos_staging_controller_private_draft_lifecycle');
  assertDraftMetadataPromotionChain(metadata, verification, preflight, runtime, now, ERROR);
  for (const record of [verification, metadata, control, lifecycle]) assertIdentity(record.value, runtime, preflight.value, now);
  const draft = exactDeployId(verification.value.draftDeployId, ERROR);
  const previous = exactDeployId(preflight.value.previousPublishedDeploy.id, ERROR);
  if (draft === previous || gate.value.authorization !== false || gate.value.promotionAuthorization !== false ||
    gate.value.productionAuthorization !== false || gate.value.previousDeployId !== previous ||
    gate.value.preflightEvidenceSha256 !== preflight.sha256 ||
    gate.value.rollbackReadinessEvidenceSha256 !== readiness.sha256 ||
    gate.value.controllerRunId !== runtime.runId || gate.value.controllerCommit !== runtime.commit ||
    verification.value.status !== 'passed' || verification.value.promotionAuthorization !== false ||
    verification.value.previousDeployId !== previous || verification.value.currentPublishedDeployId !== previous ||
    verification.value.authenticatedDraftContentAccessVerified !== true ||
    verification.value.draftAccessCredentialConsumedOnlyAtBoundary !== true ||
    verification.value.draftAccessCredentialForwardedToCandidateOrigin !== false ||
    verification.value.draftContentAccessTokenSeparatedFromNetlifyPrincipalToken !== true ||
    verification.value.publisherAndDraftAccessCredentialCoResidencyPrevented !== true ||
    verification.value.draftAccessTokenSerialized !== false ||
    control.value.status !== 'passed' || control.value.draftDeployId !== draft ||
    control.value.currentPublishedDeployId !== previous || control.value.headersBehaviorVerified !== true ||
    control.value.redirectsBehaviorVerified !== true || control.value.draftVerificationEvidenceSha256 !== verification.sha256 ||
    lifecycle.value.status !== 'passed' || lifecycle.value.draftDeployId !== draft ||
    lifecycle.value.currentPublishedDeployId !== previous || lifecycle.value.accessRestrictedToController !== true ||
    lifecycle.value.anonymousDraftAccessDenied !== true || lifecycle.value.publicAnonymousFunctionAccessDenied !== true ||
    lifecycle.value.cleanupOnPrePromotionFailureArmed !== true ||
    lifecycle.value.preflightEvidenceSha256 !== preflight.sha256 ||
    lifecycle.value.draftVerificationEvidenceSha256 !== verification.sha256 ||
    lifecycle.value.draftMetadataEvidenceSha256 !== metadata.sha256 ||
    lifecycle.value.controlBehaviorEvidenceSha256 !== control.sha256 ||
    lifecycle.value.intentBindingScope !== 'signed_intent_and_provider_ownership_marker' ||
    Date.parse(control.value.verifiedAt) < Date.parse(verification.value.verifiedAt) ||
    Date.parse(lifecycle.value.verifiedAt) < Date.parse(control.value.verifiedAt)) fail(ERROR);
  exactSha256(lifecycle.value.draftIntentEvidenceSha256, ERROR);
  const github = await validateStoredLiveGitHubReleaseBoundary({ env, runtime, now: () => now });
  if (github.evidence.phase !== 'before_promotion' ||
    github.evidence.priorBoundaryEvidenceSha256 !== preflight.value.liveGitHubPrecredentialBoundaryEvidenceSha256) fail(ERROR);
  const authorization = await publisherEvidence(env, 'AUTHORIZATION');
  if (authorization.sha256 !== preflight.value.authorizationEvidenceSha256) fail(ERROR);
  const inputs = [preflight, readiness, gate, verification, metadata, control, lifecycle, authorization];
  const evidence = {
    schemaVersion: 1, source: preflight.value.source, artifact: preflight.value.artifact,
    draftDeployId: draft, previousPublishedDeployId: previous,
    inputEvidenceSha256: {
      preflight: preflight.sha256, rollbackReadiness: readiness.sha256, draftGate: gate.sha256,
      draftVerification: verification.sha256, draftMetadata: metadata.sha256,
      controlBehavior: control.sha256, privateDraft: lifecycle.sha256, authorization: authorization.sha256,
      githubPrecredential: github.evidence.priorBoundaryEvidenceSha256, githubPrepromotion: github.sha256
    },
    minimumLeaseMinutes: POLICY.publishing.minimumExclusiveLeaseMinutes,
    expectedLeaseActive: false, expectedRunBarrierActive: false,
    atomicLeaseAndBarrierRequired: true, productionAuthorization: false
  };
  return { preflight, inputs, evidence, github };
}

export function validatePublisherAcquisitionResult(result, { target, evidence, observedAt, trust }) {
  assertExactKeys(result, ['schemaVersion', 'status', 'target', 'requestEvidenceSha256', 'lockLeaseId',
    'acquiredAt', 'expiresAt', 'transition', 'publisherExclusion'], ERROR);
  assertExactKeys(result.transition, ['atomicCompareAndSwap', 'leaseActiveBefore', 'runBarrierActiveBefore',
    'leaseActiveAfter', 'runBarrierActiveAfter', 'automaticBarrierExpiryPermitted',
    'newMutationBlockedWhileRunBarrierActive', 'renewalSupported', 'releaseRequired'], ERROR);
  assertExactKeys(result.publisherExclusion, ['netlifyGitPublishingDisabled', 'buildHooksDisabled',
    'manualUiPublishingDenied', 'alternatePublishersDenied', 'inventoryComplete', 'evidenceSha256'], ERROR);
  const leaseId = required(result.lockLeaseId, ERROR, 200);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$/.test(leaseId) ||
    !isDeepStrictEqual(result.target, { ...target, barrierGeneration: leaseId }) ||
    result.schemaVersion !== 1 || result.status !== 'acquired' ||
    result.requestEvidenceSha256 !== sha256(JSON.stringify(evidence))) fail(ERROR);
  const t = result.transition;
  if (t.atomicCompareAndSwap !== true || t.leaseActiveBefore !== false || t.runBarrierActiveBefore !== false ||
    t.leaseActiveAfter !== true || t.runBarrierActiveAfter !== true || t.automaticBarrierExpiryPermitted !== false ||
    t.newMutationBlockedWhileRunBarrierActive !== true || t.renewalSupported !== true || t.releaseRequired !== true) fail(ERROR);
  for (const key of ['netlifyGitPublishingDisabled', 'buildHooksDisabled', 'manualUiPublishingDenied',
    'alternatePublishersDenied', 'inventoryComplete']) if (result.publisherExclusion[key] !== true) fail(ERROR);
  exactSha256(result.publisherExclusion.evidenceSha256, ERROR);
  const acquiredAt = canonicalIsoTimestamp(result.acquiredAt, ERROR);
  const expiresAt = canonicalIsoTimestamp(result.expiresAt, ERROR);
  if (acquiredAt > observedAt || observedAt - acquiredAt > trust.maximumAgeMs ||
    expiresAt - observedAt < POLICY.publishing.minimumExclusiveLeaseMinutes * 60_000 ||
    expiresAt - acquiredAt > 24 * 60 * 60_000) fail(ERROR);
  return { acquiredAt, expiresAt };
}

export function publisherLeaseFromResponse(response, request, runtime) {
  const result = response.result;
  const trust = brokerTrustRoot('reconciliation');
  validatePublisherAcquisitionResult(result, { target: request.target, evidence: request.evidence,
    observedAt: response.observedAt, trust });
  if (response.requestSha256 !== sha256(JSON.stringify(request)) ||
    Date.parse(result.acquiredAt) < Date.parse(response.statement.issuedAt) ||
    Date.parse(result.acquiredAt) >= Date.parse(response.statement.expiresAt)) fail(ERROR);
  return {
    schemaVersion: 1, evidenceType: 'cnyos_staging_controller_exclusive_publisher_lease',
    status: 'passed', scope: 'cnyos_staging_only', productionAuthorization: false,
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerRunId: runtime.runId, controllerRunAttempt: 1, dispatchNonce: request.target.dispatchNonce,
    source: request.evidence.source, artifact: request.evidence.artifact, netlifySiteId: POLICY.target.netlifySiteId,
    draftDeployId: request.evidence.draftDeployId, previousPublishedDeployId: request.evidence.previousPublishedDeployId,
    enforcementAuthority: 'independent_netlify_publish_broker', brokerPolicyId: trust.policyId, brokerPolicySha256: trust.policySha256,
    netlifyGitPublishingDisabled: result.publisherExclusion.netlifyGitPublishingDisabled,
    buildHooksDisabled: result.publisherExclusion.buildHooksDisabled,
    manualUiPublishingDenied: result.publisherExclusion.manualUiPublishingDenied,
    lockLeaseActive: result.transition.leaseActiveAfter, runReconciliationBarrierActive: result.transition.runBarrierActiveAfter,
    runReconciliationBarrierGeneration: result.lockLeaseId,
    newMutationBlockedWhileRunReconciliationBarrierActive: result.transition.newMutationBlockedWhileRunBarrierActive,
    automaticRunReconciliationBarrierExpiryPermitted: result.transition.automaticBarrierExpiryPermitted,
    renewalSupported: result.transition.renewalSupported, releaseRequired: result.transition.releaseRequired,
    lockLeaseId: result.lockLeaseId, acquiredAt: result.acquiredAt, expiresAt: result.expiresAt,
    brokerRequest: request, brokerEnvelope: response.value
  };
}

export function validateRetainedPublisherLease(value, runtime, observedAt) {
  assertExactKeys(value, LEASE_KEYS, ERROR);
  const trust = brokerTrustRoot('reconciliation');
  const request = value.brokerRequest;
  const expectedRequest = publisherRequest(PUBLISHER_OPERATIONS.acquire, trust,
    publisherResumer(runtime), publisherTarget(runtime, value.dispatchNonce), request?.evidence);
  if (!isDeepStrictEqual(request, expectedRequest)) fail(ERROR);
  const issued = canonicalIsoTimestamp(value.acquiredAt, ERROR);
  if (issued > observedAt || canonicalIsoTimestamp(value.expiresAt, ERROR) <= observedAt) fail(ERROR);
  const verified = verifySignedBrokerEnvelope(JSON.stringify(value.brokerEnvelope), {
    trust, operation: PUBLISHER_OPERATIONS.acquire, requestSha256: sha256(JSON.stringify(request)),
    observedAt: issued, requireFresh: true
  });
  const expected = publisherLeaseFromResponse({ ...verified, requestSha256: sha256(JSON.stringify(request)), observedAt: issued }, request, runtime);
  if (!isDeepStrictEqual(value, expected)) fail(ERROR);
  return value;
}

export async function verifyNetlifyExclusivePublisher({ env = process.env, fetchImpl = fetch, oidcTokenProvider, now = () => new Date() } = {}) {
  env = Object.freeze({ ...env });
  publisherOidcEnvironment(env);
  const runtime = publisherRuntime(env);
  const trust = brokerTrustRoot('reconciliation');
  const context = await loadPublisherAcquisition(env, runtime, publisherNow(now));
  const output = env.CNYOS_CONTROLLER_EXCLUSIVE_PUBLISHER_EVIDENCE_PATH;
  await publisherOutputAvailable(output, context.inputs);
  const resumer = publisherResumer(runtime);
  const target = publisherTarget(runtime, context.preflight.value.dispatchNonce);
  const request = publisherRequest(PUBLISHER_OPERATIONS.acquire, trust, resumer, target, context.evidence);
  await publisherInputsUnchanged(context.inputs);
  const response = await callSignedBrokerOperation({ env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL, operation: PUBLISHER_OPERATIONS.acquire,
    resumer, target, evidence: context.evidence, now });
  const evidence = publisherLeaseFromResponse(response, request, runtime);
  await publisherInputsUnchanged(context.inputs);
  assertFreshPreflight(context.preflight.value, runtime, publisherNow(now));
  const github = await validateStoredLiveGitHubReleaseBoundary({ env, runtime, now });
  if (github.sha256 !== context.github.sha256) fail(ERROR);
  const evidencePath = await writeJsonExclusive(output, evidence);
  return Object.freeze({ evidence, evidencePath });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyNetlifyExclusivePublisher().catch(error => {
    process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message : ERROR}\n`);
    process.exitCode = 1;
  });
}
