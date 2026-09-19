import { POLICY, assertExactKeys, isPlainObject } from './policy.mjs';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH_256 = /^[0-9a-f]{64}$/;
const PROOF_KEYS = Object.freeze([
  'schemaVersion', 'scope', 'productionAuthorization', 'clinicId', 'clinicCode',
  'offRequestId', 'onRequestId', 'initialVersion', 'offExpectedVersion',
  'replayExpectedVersion', 'offVersion', 'onExpectedVersion', 'restoreVersion',
  'offPayloadSha256', 'replayPayloadSha256', 'onPayloadSha256',
  'offReplayIdempotent', 'recoveryDisposition', 'originalBoundary', 'restoredBoundary'
]);
const BOUNDARY_KEYS = Object.freeze([
  'clinicId', 'clinicCode', 'clinicRole', 'systemRole', 'effectiveRole', 'ready', 'clinical'
]);

function invalid() {
  throw new Error('CNYOS_FINAL_UAT_SUBSCRIPTION_VERSION_BOUND_PROOF_INVALID');
}

function positiveSafeVersion(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function boundary(value, expected) {
  if (!isPlainObject(value)) invalid();
  assertExactKeys(value, BOUNDARY_KEYS, 'CNYOS_FINAL_UAT_SUBSCRIPTION_VERSION_BOUND_PROOF_INVALID');
  if (value.clinicId !== expected.clinicId || value.clinicCode !== expected.clinicCode ||
    value.clinicRole !== 'practitioner' || value.systemRole !== 'staff' ||
    value.effectiveRole !== 'practitioner' || value.ready !== true || value.clinical !== true) {
    invalid();
  }
}

// This schema proves consistency of a supplied synthetic record only; it is not
// authenticity, live UAT, approval, or activation evidence. The blocked live
// harness remains inert and is not activated by this validator.
export function validateOwnerSubscriptionProof(value) {
  if (!isPlainObject(value)) invalid();
  assertExactKeys(value, PROOF_KEYS, 'CNYOS_FINAL_UAT_SUBSCRIPTION_VERSION_BOUND_PROOF_INVALID');
  if (value.schemaVersion !== 1 || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false || value.clinicId !== POLICY.target.clinicId ||
    value.clinicCode !== POLICY.target.clinicCode ||
    typeof value.offRequestId !== 'string' || typeof value.onRequestId !== 'string' ||
    !UUID_V4.test(value.offRequestId) || !UUID_V4.test(value.onRequestId) ||
    value.offRequestId === value.onRequestId ||
    !positiveSafeVersion(value.initialVersion) ||
    value.initialVersion > Number.MAX_SAFE_INTEGER - 2 ||
    value.offExpectedVersion !== value.initialVersion ||
    value.replayExpectedVersion !== value.initialVersion ||
    value.offVersion !== value.initialVersion + 1 ||
    value.onExpectedVersion !== value.offVersion ||
    value.restoreVersion !== value.initialVersion + 2 ||
    typeof value.offPayloadSha256 !== 'string' ||
    typeof value.replayPayloadSha256 !== 'string' ||
    typeof value.onPayloadSha256 !== 'string' ||
    !HASH_256.test(value.offPayloadSha256) ||
    !HASH_256.test(value.replayPayloadSha256) ||
    !HASH_256.test(value.onPayloadSha256) ||
    value.offPayloadSha256 !== value.replayPayloadSha256 ||
    value.onPayloadSha256 === value.offPayloadSha256 ||
    value.offReplayIdempotent !== true ||
    value.recoveryDisposition !== 'confirmed_restored') invalid();
  const expectedBoundary = { clinicId: value.clinicId, clinicCode: value.clinicCode };
  boundary(value.originalBoundary, expectedBoundary);
  boundary(value.restoredBoundary, expectedBoundary);
  return true;
}
