import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  POLICY, assertExactKeys, assertPolicyTarget, canonicalIsoTimestamp, exactDeployId, fail, sha256, writeJsonExclusive
} from './policy.mjs';
import { brokerTrustRoot, callSignedBrokerOperation } from './reconcile-netlify-release-state.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';
import {
  validateAuthenticatedUatEvidence, validateFinalCurrentEvidence, validateExclusivePublisherReleaseEvidence
} from './finalize-evidence.mjs';
import {
  PUBLISHER_OPERATIONS, publisherOidcEnvironment, publisherRuntime, publisherNow,
  publisherResumer, publisherTarget, publisherEvidence, publisherInputsUnchanged,
  publisherOutputAvailable, validateRetainedPublisherLease
} from './verify-netlify-exclusive-publisher.mjs';

const ERROR = 'CNYOS_PUBLISHER_RELEASE_INVALID';

export function validatePublisherReleaseResult(result, { target, evidence, trust, observedAt }) {
  assertExactKeys(result, ['schemaVersion', 'status', 'target', 'requestEvidenceSha256', 'releasedAt',
    'currentPublishedDeployIdBeforeRelease', 'currentPublishedDeployIdAfterRelease', 'transition'], ERROR);
  assertExactKeys(result.transition, ['atomicCompareAndSwap', 'leaseActiveBefore', 'runBarrierActiveBefore',
    'leaseActiveAfter', 'runBarrierActiveAfter', 'immutableReleaseReceiptStored',
    'automaticBarrierExpiryPermitted', 'draftIntentsTerminalBeforeBarrierClearRequired'], ERROR);
  const transition = result.transition;
  const releasedAt = canonicalIsoTimestamp(result.releasedAt, ERROR);
  if (result.schemaVersion !== 1 || result.status !== 'released' ||
    !isDeepStrictEqual(result.target, target) || result.requestEvidenceSha256 !== sha256(JSON.stringify(evidence)) ||
    result.currentPublishedDeployIdBeforeRelease !== evidence.netlifyDeployId ||
    result.currentPublishedDeployIdAfterRelease !== evidence.netlifyDeployId ||
    transition.atomicCompareAndSwap !== true || transition.leaseActiveBefore !== true || transition.runBarrierActiveBefore !== true ||
    transition.leaseActiveAfter !== false || transition.runBarrierActiveAfter !== true ||
    transition.immutableReleaseReceiptStored !== true || transition.automaticBarrierExpiryPermitted !== false ||
    transition.draftIntentsTerminalBeforeBarrierClearRequired !== true ||
    releasedAt > observedAt || observedAt - releasedAt > trust.maximumAgeMs ||
    releasedAt <= canonicalIsoTimestamp(evidence.finalCurrentVerifiedAt, ERROR) ||
    releasedAt <= canonicalIsoTimestamp(evidence.uatCompletedAt, ERROR)) fail(ERROR);
  return releasedAt;
}

export function publisherReleaseReceiptFromResponse(response, { runtime, target, evidence }) {
  const trust = brokerTrustRoot('reconciliation');
  validatePublisherReleaseResult(response.result, { target, evidence, trust, observedAt: response.observedAt });
  const result = response.result;
  if (Date.parse(result.releasedAt) < Date.parse(response.statement.issuedAt) ||
    Date.parse(result.releasedAt) >= Date.parse(response.statement.expiresAt)) fail(ERROR);
  return {
    schemaVersion: 1, evidenceType: 'cnyos_staging_controller_exclusive_publisher_release',
    status: 'passed', scope: 'cnyos_staging_only', productionAuthorization: false, releasedAt: result.releasedAt,
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerRunId: runtime.runId, source: { repository: POLICY.sourceRepository,
      commit: evidence.source.commit, tree: evidence.source.tree },
    netlifyDeployId: evidence.netlifyDeployId, lockLeaseId: target.barrierGeneration,
    originalExclusivePublisherEvidenceSha256: evidence.originalExclusivePublisherEvidenceSha256,
    releaseAction: result.status, leaseActiveAfterRelease: result.transition.leaseActiveAfter,
    runReconciliationBarrierActiveAfterRelease: result.transition.runBarrierActiveAfter,
    runReconciliationBarrierGeneration: target.barrierGeneration,
    automaticRunReconciliationBarrierExpiryPermitted: result.transition.automaticBarrierExpiryPermitted,
    draftIntentTerminalBeforeRunReconciliationBarrierClearRequired: result.transition.draftIntentsTerminalBeforeBarrierClearRequired,
    brokerPolicyId: trust.policyId, brokerPolicySha256: trust.policySha256,
    currentPublishedDeployIdBeforeRelease: result.currentPublishedDeployIdBeforeRelease,
    currentPublishedDeployIdAfterRelease: result.currentPublishedDeployIdAfterRelease
  };
}

export async function releaseNetlifyExclusivePublisher({ env = process.env, fetchImpl = fetch, oidcTokenProvider, now = () => new Date() } = {}) {
  env = Object.freeze({ ...env });
  publisherOidcEnvironment(env);
  const runtime = publisherRuntime(env);
  const trust = brokerTrustRoot('reconciliation');
  const observedAt = publisherNow(now);
  const bundle = await verifyProducerBundle({ env });
  const lease = await publisherEvidence(env, 'EXCLUSIVE_PUBLISHER', 'cnyos_staging_controller_exclusive_publisher_lease');
  validateRetainedPublisherLease(lease.value, runtime, observedAt);
  const attempt = await publisherEvidence(env, 'PUBLISH_ATTEMPT', 'cnyos_staging_controller_promotion_attempt');
  const promotion = await publisherEvidence(env, 'PROMOTION', 'cnyos_staging_controller_exact_deploy_promotion');
  const finalCurrent = await publisherEvidence(env, 'FINAL_CURRENT', 'cnyos_staging_controller_final_current_verification');
  const uat = await publisherEvidence(env, 'UAT', 'cnyos_staging_controller_authenticated_uat');
  const commit = bundle.manifest.candidateCommit;
  const tree = bundle.manifest.candidateTree;
  const deployId = exactDeployId(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, ERROR);
  for (const record of [attempt.value, promotion.value]) {
    assertPolicyTarget(record.target, ERROR);
    if (record.schemaVersion !== 1 || record.authorization !== false || record.productionAuthorization !== false ||
      record.scope !== 'cnyos_staging_only' || record.controllerRepository !== runtime.repository || record.controllerRef !== runtime.ref ||
      record.dispatchNonce !== lease.value.dispatchNonce || !isDeepStrictEqual(record.source, lease.value.source) ||
      !isDeepStrictEqual(record.artifact, lease.value.artifact) ||
      record.previousDeployId !== lease.value.previousPublishedDeployId) fail(ERROR);
  }
  const attemptedAt = canonicalIsoTimestamp(attempt.value.attemptedAt, ERROR);
  const promotedAt = canonicalIsoTimestamp(promotion.value.promotedAt, ERROR);
  const inputHashes = lease.value.brokerRequest.evidence.inputEvidenceSha256;
  if (attempt.value.promotionAuthorization !== true ||
    attemptedAt < canonicalIsoTimestamp(lease.value.acquiredAt, ERROR) || promotedAt < attemptedAt || promotedAt > observedAt ||
    attempt.value.preflightEvidenceSha256 !== inputHashes.preflight ||
    attempt.value.rollbackReadinessEvidenceSha256 !== inputHashes.rollbackReadiness ||
    attempt.value.draftGateEvidenceSha256 !== inputHashes.draftGate ||
    attempt.value.draftVerificationEvidenceSha256 !== inputHashes.draftVerification ||
    attempt.value.controlBehaviorEvidenceSha256 !== inputHashes.controlBehavior ||
    attempt.value.privateDraftEvidenceSha256 !== inputHashes.privateDraft ||
    attempt.value.liveGitHubPrecredentialBoundaryEvidenceSha256 !== inputHashes.githubPrecredential ||
    attempt.value.liveGitHubPrepromotionBoundaryEvidenceSha256 !== inputHashes.githubPrepromotion ||
    promotion.value.preflightEvidenceSha256 !== inputHashes.preflight ||
    promotion.value.draftVerificationEvidenceSha256 !== inputHashes.draftVerification ||
    promotion.value.controlBehaviorEvidenceSha256 !== inputHashes.controlBehavior ||
    promotion.value.privateDraftEvidenceSha256 !== inputHashes.privateDraft ||
    promotion.value.liveGitHubPrecredentialBoundaryEvidenceSha256 !== inputHashes.githubPrecredential ||
    promotion.value.liveGitHubPrepromotionBoundaryEvidenceSha256 !== inputHashes.githubPrepromotion) fail(ERROR);
  if (lease.value.source.commit !== commit || lease.value.source.tree !== tree ||
    lease.value.artifact.artifactSha256 !== bundle.manifest.artifactSha256 ||
    lease.value.dispatchNonce !== bundle.manifest.dispatchNonce || lease.value.draftDeployId !== deployId ||
    attempt.value.exclusivePublisherEvidenceSha256 !== lease.sha256 ||
    attempt.value.exclusivePublisherLeaseId !== lease.value.lockLeaseId || attempt.value.draftDeployId !== deployId ||
    attempt.value.controllerRunId !== runtime.runId || attempt.value.controllerCommit !== runtime.commit ||
    promotion.value.exclusivePublisherEvidenceSha256 !== lease.sha256 ||
    promotion.value.exclusivePublisherLeaseId !== lease.value.lockLeaseId ||
    promotion.value.controllerRunId !== runtime.runId || promotion.value.controllerCommit !== runtime.commit ||
    promotion.value.promotedDeployId !== deployId || promotion.value.currentPublishedDeployId !== deployId ||
    promotion.value.promotionAttemptEvidenceSha256 !== attempt.sha256 || promotion.value.status !== 'passed' ||
    promotion.value.productionAuthorization !== false) fail(ERROR);
  validateAuthenticatedUatEvidence(uat.value, { commit, tree, deployId });
  const uatCompletedAt = canonicalIsoTimestamp(uat.value.completedAt, ERROR);
  if (uatCompletedAt < promotedAt) fail(ERROR);
  const finalCurrentVerifiedAt = validateFinalCurrentEvidence(finalCurrent.value, {
    runtime, bundle, commit, tree, artifactSha256: bundle.manifest.artifactSha256, deployId,
    promotionEvidenceSha256: promotion.sha256, uatCompletedAt, observedAt
  });
  const inputs = [lease, attempt, promotion, finalCurrent, uat,
    { filename: bundle.manifestPath, bytes: bundle.manifestBytes }];
  const output = env.CNYOS_CONTROLLER_PUBLISHER_RELEASE_EVIDENCE_PATH;
  await publisherOutputAvailable(output, inputs);
  const target = publisherTarget(runtime, lease.value.dispatchNonce, lease.value.lockLeaseId);
  const evidence = {
    schemaVersion: 1, netlifyDeployId: deployId, source: lease.value.source, artifact: lease.value.artifact,
    originalExclusivePublisherEvidenceSha256: lease.sha256, publishAttemptEvidenceSha256: attempt.sha256,
    promotionEvidenceSha256: promotion.sha256, finalCurrentEvidenceSha256: finalCurrent.sha256, uatEvidenceSha256: uat.sha256,
    finalCurrentVerifiedAt: finalCurrentVerifiedAt.toISOString(), uatCompletedAt: uatCompletedAt.toISOString(),
    expectedLeaseActive: true, expectedRunBarrierActive: true, retainRunBarrier: true,
    expectedCurrentPublishedDeployId: deployId, atomicReleaseReceiptRequired: true
  };
  await publisherInputsUnchanged(inputs);
  const response = await callSignedBrokerOperation({ env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_NETLIFY_PUBLISH_BROKER_URL, operation: PUBLISHER_OPERATIONS.release,
    resumer: publisherResumer(runtime), target, evidence, now });
  const receipt = publisherReleaseReceiptFromResponse(response, { runtime, target, evidence });
  validateExclusivePublisherReleaseEvidence(receipt, { runtime, commit, tree, deployId,
    exclusivePublisher: lease.value, exclusivePublisherSha256: lease.sha256,
    observedAt: publisherNow(now), uatCompletedAt, finalCurrentVerifiedAt });
  await publisherInputsUnchanged(inputs);
  const evidencePath = await writeJsonExclusive(output, receipt);
  return Object.freeze({ evidence: receipt, evidencePath });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  releaseNetlifyExclusivePublisher().catch(error => {
    process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message : ERROR}\n`);
    process.exitCode = 1;
  });
}
