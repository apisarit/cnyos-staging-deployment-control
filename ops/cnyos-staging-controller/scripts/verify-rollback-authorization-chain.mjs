// Structural validation of a sanitized rollback chain. This is not signature
// verification: callers must authenticate the returned digest with the signed
// broker plan before using it to authorize recovery.
import {
  assertExactKeys, canonicalIsoTimestamp, exactDeployId, exactSha256,
  fail, sha256
} from './policy.mjs';

function exactSha40(value, code) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) fail(code);
  return value;
}

const ROLLBACK_CHAIN_CORE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'scope', 'productionAuthorization',
  'realPatientDataAuthorized', 'secretValuesSerialized', 'authorizationVerifiedAt',
  'targetControllerRepository', 'targetControllerRef', 'targetControllerWorkflowPath',
  'targetControllerRunId', 'targetControllerRunAttempt', 'targetControllerCommit',
  'dispatchNonce', 'targetNetlifySiteId', 'sourceCommit', 'previousDeployId',
  'rollbackNetlifyPrincipalSubject', 'authorizationPacketSha256',
  'authorizationBundleSha256', 'approverRegistrySha256', 'knownGoodEvidenceSha256',
  'depositReceiptSha256', 'depositId', 'authorizationKeyIds',
  'authorizationSignatureSha256', 'artifactProvenanceAuthenticated',
  'authorizationSignaturesVerified', 'protectedApproverRegistryVerified',
  'knownGoodEvidenceVerified', 'authorizationExpiryIgnoredForRecoveryOnly'
]);
const ROLLBACK_CHAIN_KEYS = Object.freeze([
  ...ROLLBACK_CHAIN_CORE_KEYS, 'prepareRequestSha256'
]);
export function rollbackChainBinding(chain) {
  const code = 'CNYOS_RECONCILIATION_ROLLBACK_CHAIN_INVALID';
  assertExactKeys(chain.value, ROLLBACK_CHAIN_KEYS, code);
  const core = {};
  for (const name of ROLLBACK_CHAIN_CORE_KEYS) core[name] = chain.value[name];
  return Object.freeze({
    core: Object.freeze(core),
    coreSha256: sha256(Buffer.from(`${JSON.stringify(core, null, 2)}\n`)),
    prepareRequestSha256: exactSha256(chain.value.prepareRequestSha256, code)
  });
}

export function authorizationFromChain(chain, target) {
  const code = 'CNYOS_RECONCILIATION_ROLLBACK_CHAIN_INVALID';
  const binding = rollbackChainBinding(chain);
  const value = binding.core;
  if (value.schemaVersion !== 1 || value.scope !== 'cnyos_staging_only' ||
    value.evidenceType !== 'cnyos_staging_controller_rollback_authorization_chain' ||
    value.status !== 'passed' || value.productionAuthorization !== false ||
    value.realPatientDataAuthorized !== false || value.secretValuesSerialized !== false ||
    value.targetControllerRepository !== target.controllerRepository ||
    value.targetControllerRef !== target.controllerRef ||
    value.targetControllerWorkflowPath !== target.controllerWorkflowPath ||
    value.targetControllerRunId !== target.controllerRunId ||
    value.targetControllerRunAttempt !== target.controllerRunAttempt ||
    value.targetControllerCommit !== target.controllerCommit ||
    value.dispatchNonce !== target.dispatchNonce || value.targetNetlifySiteId !== target.netlifySiteId ||
    value.artifactProvenanceAuthenticated !== true ||
    value.authorizationSignaturesVerified !== true ||
    value.protectedApproverRegistryVerified !== true || value.knownGoodEvidenceVerified !== true ||
    value.authorizationExpiryIgnoredForRecoveryOnly !== true) fail(code);
  canonicalIsoTimestamp(value.authorizationVerifiedAt, code);
  for (const field of [
    'authorizationPacketSha256', 'authorizationBundleSha256',
    'approverRegistrySha256', 'knownGoodEvidenceSha256', 'depositReceiptSha256'
  ]) {
    if (typeof value[field] !== 'string' || !/^[0-9a-f]{64}$/.test(value[field])) fail(code);
  }
  if (typeof value.rollbackNetlifyPrincipalSubject !== 'string' ||
    !/^[^\s\x00-\x1f\x7f]{1,200}$/.test(value.rollbackNetlifyPrincipalSubject) ||
    typeof value.depositId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$/.test(value.depositId)) fail(code);
  const slots = ['independentSecurityReviewer', 'managedPlatformRiskOwner'];
  assertExactKeys(value.authorizationKeyIds, slots, code);
  assertExactKeys(value.authorizationSignatureSha256, slots, code);
  for (const slot of slots) {
    if (typeof value.authorizationKeyIds[slot] !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/.test(value.authorizationKeyIds[slot]) ||
      typeof value.authorizationSignatureSha256[slot] !== 'string' ||
      !/^[0-9a-f]{64}$/.test(value.authorizationSignatureSha256[slot])) fail(code);
  }
  if (value.authorizationKeyIds.independentSecurityReviewer ===
    value.authorizationKeyIds.managedPlatformRiskOwner) fail(code);
  return Object.freeze({
    target,
    previousDeployId: exactDeployId(value.previousDeployId, code),
    sourceCommit: exactSha40(value.sourceCommit, code),
    knownGoodEvidenceSha256: exactSha256(value.knownGoodEvidenceSha256, code),
    rollbackAuthorizationChainSha256: binding.coreSha256,
    prepareRequestSha256: binding.prepareRequestSha256
  });
}
