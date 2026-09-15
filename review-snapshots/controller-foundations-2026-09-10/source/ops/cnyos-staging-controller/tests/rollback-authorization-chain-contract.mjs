import assert from 'node:assert/strict';
import { POLICY, sha256 } from '../scripts/policy.mjs';
import {
  authorizationFromChain, rollbackChainBinding
} from '../scripts/verify-rollback-authorization-chain.mjs';

assert.notEqual(process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE, 'true');
const target = {
  controllerRepository: POLICY.controller.repository,
  controllerRef: POLICY.controller.protectedRef,
  controllerWorkflowPath: POLICY.controller.releaseWorkflowPath,
  controllerRunId: '7001001', controllerRunAttempt: 1,
  controllerCommit: 'a'.repeat(40),
  dispatchNonce: Buffer.alloc(32, 65).toString('base64url'),
  netlifySiteId: POLICY.target.netlifySiteId
};
// Synthetic sanitized evidence tests structure only. It is not a signed approval.
const value = {
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_rollback_authorization_chain',
  status: 'passed', scope: 'cnyos_staging_only', productionAuthorization: false,
  realPatientDataAuthorized: false, secretValuesSerialized: false,
  authorizationVerifiedAt: '2030-01-01T00:00:00.000Z',
  targetControllerRepository: target.controllerRepository,
  targetControllerRef: target.controllerRef,
  targetControllerWorkflowPath: target.controllerWorkflowPath,
  targetControllerRunId: target.controllerRunId,
  targetControllerRunAttempt: target.controllerRunAttempt,
  targetControllerCommit: target.controllerCommit,
  dispatchNonce: target.dispatchNonce, targetNetlifySiteId: target.netlifySiteId,
  sourceCommit: 'b'.repeat(40), previousDeployId: 'c'.repeat(24),
  rollbackNetlifyPrincipalSubject: 'fixture-rollback-principal',
  authorizationPacketSha256: '1'.repeat(64), authorizationBundleSha256: '2'.repeat(64),
  approverRegistrySha256: '3'.repeat(64), knownGoodEvidenceSha256: '4'.repeat(64),
  depositReceiptSha256: '5'.repeat(64), depositId: 'fixture-deposit-000001',
  authorizationKeyIds: {
    independentSecurityReviewer: 'fixture-reviewer', managedPlatformRiskOwner: 'fixture-owner'
  },
  authorizationSignatureSha256: {
    independentSecurityReviewer: '6'.repeat(64), managedPlatformRiskOwner: '7'.repeat(64)
  },
  artifactProvenanceAuthenticated: true, authorizationSignaturesVerified: true,
  protectedApproverRegistryVerified: true, knownGoodEvidenceVerified: true,
  authorizationExpiryIgnoredForRecoveryOnly: true,
  prepareRequestSha256: '8'.repeat(64)
};
const chain = { value };
const result = authorizationFromChain(chain, target);
assert.equal(result.previousDeployId, value.previousDeployId);
const { prepareRequestSha256, ...core } = value;
assert.equal(result.rollbackAuthorizationChainSha256,
  sha256(`${JSON.stringify(core, null, 2)}\n`));
assert.equal(result.prepareRequestSha256, prepareRequestSha256);
assert.ok(Object.isFrozen(result));
const code = /CNYOS_RECONCILIATION_ROLLBACK_CHAIN_INVALID/;
for (const field of Object.keys(value)) {
  const missing = structuredClone(value);
  delete missing[field];
  assert.throws(() => authorizationFromChain({ value: missing }, target), code, field);
}
assert.throws(() => authorizationFromChain({ value: { ...value, extra: true } }, target), code);
for (const [field, replacement] of [
  ['schemaVersion', 2], ['scope', 'production'], ['status', 'pending'],
  ['productionAuthorization', true], ['realPatientDataAuthorized', true],
  ['secretValuesSerialized', true], ['authorizationVerifiedAt', 'not-a-date'],
  ['sourceCommit', 'g'.repeat(40)], ['previousDeployId', 'invalid'],
  ['rollbackNetlifyPrincipalSubject', 'principal with spaces'], ['depositId', 'short'],
  ['authorizationPacketSha256', 'G'.repeat(64)], ['authorizationBundleSha256', null],
  ['approverRegistrySha256', 'short'], ['depositReceiptSha256', ''],
  ['artifactProvenanceAuthenticated', false], ['authorizationSignaturesVerified', false],
  ['protectedApproverRegistryVerified', false], ['knownGoodEvidenceVerified', false],
  ['authorizationExpiryIgnoredForRecoveryOnly', false]
]) {
  assert.throws(() => authorizationFromChain({ value: { ...value, [field]: replacement } },
    target), code, field);
}
for (const field of Object.keys(target)) {
  assert.throws(() => authorizationFromChain(chain, { ...target, [field]: 'other' }), code, field);
}
const sameSigner = structuredClone(value);
sameSigner.authorizationKeyIds.managedPlatformRiskOwner =
  sameSigner.authorizationKeyIds.independentSecurityReviewer;
assert.throws(() => authorizationFromChain({ value: sameSigner }, target), code);
const extraSignature = structuredClone(value);
extraSignature.authorizationSignatureSha256.unknown = '9'.repeat(64);
assert.throws(() => authorizationFromChain({ value: extraSignature }, target), code);

// Distinct resumption requests bind different envelopes, but preserve the core.
const retry = rollbackChainBinding({ value: { ...value, prepareRequestSha256: '9'.repeat(64) } });
assert.equal(retry.coreSha256, result.rollbackAuthorizationChainSha256);
assert.notEqual(retry.prepareRequestSha256, result.prepareRequestSha256);
const changed = rollbackChainBinding({ value: { ...value, sourceCommit: 'd'.repeat(40) } });
assert.notEqual(changed.coreSha256, result.rollbackAuthorizationChainSha256);
// A caller must reject that changed digest against the authenticated broker plan.
process.stdout.write('CNYOS activation contract rollback-authorization-chain: passed\n');
