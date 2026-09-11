import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import {
  POLICY, POLICY_SHA256, assertExactKeys, canonicalIsoTimestamp, exactSha256,
  fail, isPlainObject, parseJsonObject, readRegularFileStable, required, sha256,
  writeJsonExclusive
} from './policy.mjs';
import {
  EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES, brokerTrustRoot, callSignedBrokerOperation,
  verifyDepositReceipt, verifySignedBrokerEnvelope
} from './reconcile-netlify-release-state.mjs';
import { assertFreshPreflight, validateRollbackReadinessEvidence } from './netlify-evidence.mjs';
import {
  publisherEvidence, publisherInputsUnchanged, publisherNow, publisherOidcEnvironment,
  publisherOutputAvailable, publisherRequest, publisherResumer, publisherRuntime, publisherTarget
} from './verify-netlify-exclusive-publisher.mjs';

const ERROR = 'CNYOS_ROLLBACK_READINESS_INVALID';
const API = 'https://api.netlify.com/api/v1';
const MAX_API_BYTES = 1024 * 1024;
export const ROLLBACK_READINESS_OPERATIONS = Object.freeze({
  availability: 'attest_recovery_material_available',
  membership: 'attest_rollback_principal_membership'
});

// These are explicit broker wire contracts, not a local replacement for broker authority.
// Reviewed policy pins and native implementation/acceptance evidence are still required.
function boundedWindow(verifiedAt, expiresAt, observedAt, maximumAgeMs) {
  const verified = canonicalIsoTimestamp(verifiedAt, ERROR);
  const expires = canonicalIsoTimestamp(expiresAt, ERROR);
  if (verified > observedAt || observedAt - verified > maximumAgeMs || expires <= observedAt ||
    expires <= verified || expires - verified > maximumAgeMs) fail(ERROR);
  return { verifiedAt: verified, expiresAt: expires };
}

export function readinessTokenEnvironment(env) {
  for (const name of EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) fail('CNYOS_ROLLBACK_READINESS_CREDENTIAL_CORESIDENCY_FORBIDDEN');
  }
}

async function receiptInput(env) {
  const filename = required(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH, ERROR, 4096);
  const bytes = await readRegularFileStable(filename, 2 * 1024 * 1024, ERROR, 1);
  const digest = sha256(bytes);
  if (digest !== exactSha256(env.CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256, ERROR)) fail(ERROR);
  return { filename, bytes, sha256: digest };
}

export async function loadReadinessInputs(env, runtime, observedAt) {
  const trust = brokerTrustRoot('rollback');
  const preflight = await publisherEvidence(env, 'PREFLIGHT', 'cnyos_staging_controller_preflight');
  assertFreshPreflight(preflight.value, runtime, observedAt);
  const target = publisherTarget(runtime, env.CNYOS_DISPATCH_NONCE);
  if (preflight.value.dispatchNonce !== target.dispatchNonce ||
    preflight.value.source?.repository !== POLICY.sourceRepository ||
    preflight.value.source?.commit !== env.CNYOS_CANDIDATE_SHA) fail(ERROR);
  const depositInput = await receiptInput(env);
  const deposit = verifyDepositReceipt(depositInput.bytes.toString('utf8'), trust, target, observedAt);
  const validation = await publisherEvidence(env, 'ROLLBACK_ATTESTATION_DEPOSIT',
    'cnyos_staging_rollback_attestation_deposit_validation');
  const receipt = deposit.receipt;
  const value = validation.value;
  if (value.schemaVersion !== 1 || value.status !== 'passed' || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false || value.realPatientDataAuthorized !== false ||
    value.secretValuesSerialized !== false || value.rawPayloadArtifactExposure !== false ||
    value.controllerRepository !== runtime.repository || value.controllerRef !== runtime.ref ||
    value.controllerCommit !== runtime.commit || value.controllerWorkflowPath !== runtime.workflowPath ||
    value.controllerRunId !== runtime.runId || value.controllerRunAttempt !== 1 ||
    value.dispatchNonce !== target.dispatchNonce || value.policySha256 !== POLICY_SHA256 ||
    !isDeepStrictEqual(value.source, receipt.source) || !isDeepStrictEqual(value.artifact, receipt.artifact) ||
    !isDeepStrictEqual(value.target, receipt.target) ||
    !isDeepStrictEqual(preflight.value.source, receipt.source) ||
    !isDeepStrictEqual(preflight.value.artifact, receipt.artifact) ||
    value.previousDeployId !== receipt.target.previousDeployId ||
    preflight.value.previousPublishedDeploy.id !== receipt.target.previousDeployId ||
    value.depositId !== receipt.depositId || value.depositReceiptSha256 !== deposit.sha256 ||
    value.depositRequestSha256 !== receipt.depositRequestSha256 ||
    value.depositedAt !== receipt.depositedAt || value.retentionUntil !== receipt.retentionUntil ||
    value.immutableAppendOnlyDepositVerified !== true || value.exactRunNonceRetrievalBoundaryVerified !== true ||
    value.completeRecoveryMaterialStoredVerified !== true ||
    value.brokerOrigin !== trust.origin || value.brokerPolicyId !== trust.policyId ||
    value.brokerPolicySha256 !== trust.policySha256 || value.brokerReceiptSigningKeyId !== trust.signingKeyId ||
    value.brokerReceiptSigningSpkiSha256 !== trust.signingKeySpkiSha256 ||
    value.brokerStatementSha256 !== deposit.envelope.brokerSignature.statementSha256 ||
    value.brokerSignatureSha256 !== deposit.envelope.brokerSignature.signatureSha256 ||
    preflight.value.rollbackAttestationDepositEvidenceSha256 !== validation.sha256 ||
    preflight.value.rollbackAttestationDepositReceiptSha256 !== deposit.sha256 ||
    preflight.value.rollbackAttestationDepositId !== receipt.depositId ||
    preflight.value.rollbackAttestationRetentionUntil !== receipt.retentionUntil ||
    preflight.value.knownGoodRollbackEvidenceSha256 !== receipt.authorizationMaterial.knownGoodEvidenceSha256) fail(ERROR);
  for (const field of ['authorizationBundleSha256', 'authorizationPacketSha256', 'approverRegistrySha256',
    'independentSecurityReviewerSignatureSha256', 'managedPlatformRiskOwnerSignatureSha256', 'knownGoodEvidenceSha256']) {
    if (value[field] !== exactSha256(receipt.authorizationMaterial[field], ERROR)) fail(ERROR);
  }
  const validationTime = canonicalIsoTimestamp(value.verifiedAt, ERROR);
  if (validationTime < canonicalIsoTimestamp(receipt.depositedAt, ERROR) || validationTime > observedAt) fail(ERROR);
  const boundary = preflight.value.rollbackNetlifyPrincipalBoundary;
  const publisherSubject = required(preflight.value.netlifyPrincipalBoundary?.subject, ERROR, 200);
  const subject = required(boundary?.subject, ERROR, 200);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(subject) || subject === publisherSubject ||
    preflight.value.rollbackNetlifyPrincipalSubject !== subject || boundary.membershipRole !== 'Publisher' ||
    boundary.teamOwner !== false || boundary.teamAdministrator !== false || boundary.siteAccessScope !== 'single_site' ||
    boundary.accountConfigurationCapabilityAbsent !== true || boundary.teamAdministrationCapabilityAbsent !== true ||
    boundary.deployCapabilityVerified !== true || boundary.restoreCapabilityVerified !== true) fail(ERROR);
  exactSha256(boundary.membershipEvidenceSha256, ERROR);
  const boundaryAt = canonicalIsoTimestamp(boundary.verifiedAt, ERROR);
  const boundaryExpiry = canonicalIsoTimestamp(boundary.expiresAt, ERROR);
  if (boundaryAt > observedAt || boundaryExpiry <= observedAt || boundaryExpiry <= boundaryAt) fail(ERROR);
  const evidence = {
    schemaVersion: 1, preflightEvidenceSha256: preflight.sha256,
    depositValidationEvidenceSha256: validation.sha256, depositReceiptSha256: deposit.sha256,
    depositId: receipt.depositId, source: receipt.source, artifact: receipt.artifact,
    previousPublishedDeployId: receipt.target.previousDeployId,
    authorizationMaterial: receipt.authorizationMaterial,
    recoveryPrincipalSubject: subject, publisherPrincipalSubject: publisherSubject,
    priorMembershipEvidenceSha256: boundary.membershipEvidenceSha256,
    productionAuthorization: false, rawRecoveryPayloadPermitted: false
  };
  return { target, evidence, deposit, preflight, validation, boundary,
    inputs: [preflight, depositInput, validation] };
}

export function validateAvailabilityResult(result, { target, evidence, observedAt, trust }) {
  assertExactKeys(result, ['schemaVersion', 'status', 'target', 'requestEvidenceSha256', 'depositId',
    'depositReceiptSha256', 'authorizationMaterial', 'previousPublishedDeployId', 'verifiedAt', 'expiresAt',
    'recoveryMaterialAvailable', 'hashesReverified', 'exactRunNonceRetrievalEnforced', 'rawPayloadDisclosed',
    'recoveryEvidenceSha256'], ERROR);
  if (result.schemaVersion !== 1 || result.status !== 'available' ||
    !isDeepStrictEqual(result.target, target) || result.requestEvidenceSha256 !== sha256(JSON.stringify(evidence)) ||
    result.depositId !== evidence.depositId || result.depositReceiptSha256 !== evidence.depositReceiptSha256 ||
    !isDeepStrictEqual(result.authorizationMaterial, evidence.authorizationMaterial) ||
    result.previousPublishedDeployId !== evidence.previousPublishedDeployId ||
    result.recoveryMaterialAvailable !== true || result.hashesReverified !== true ||
    result.exactRunNonceRetrievalEnforced !== true || result.rawPayloadDisclosed !== false) fail(ERROR);
  exactSha256(result.recoveryEvidenceSha256, ERROR);
  return boundedWindow(result.verifiedAt, result.expiresAt, observedAt, trust.maximumAgeMs);
}

export function readinessMembershipEvidence(context, availabilityEnvelope) {
  return { ...context.evidence, recoveryAvailabilityEnvelopeSha256: sha256(JSON.stringify(availabilityEnvelope)),
    recoveryAvailabilityVerifiedAt: availabilityEnvelope.statement.result.verifiedAt,
    expectedRole: 'Publisher', expectedAccessibleSiteIds: [POLICY.target.netlifySiteId],
    requireRestoreCapability: true, requireNoAccountOrTeamAdministration: true };
}

export function validateMembershipResult(result, { target, evidence, observedAt, trust }) {
  assertExactKeys(result, ['schemaVersion', 'status', 'target', 'requestEvidenceSha256', 'principalSubject',
    'publisherPrincipalSubject', 'membershipRole', 'membershipEvidenceSha256', 'currentMembershipEvidenceSha256',
    'verifiedAt', 'expiresAt', 'teamOwner', 'teamAdministrator', 'siteAccessScope',
    'accountConfigurationCapabilityAbsent', 'teamAdministrationCapabilityAbsent', 'deployCapabilityVerified',
    'restoreCapabilityVerified', 'inventoryComplete', 'accessibleSiteIds', 'productionAccess'], ERROR);
  if (result.schemaVersion !== 1 || result.status !== 'verified' ||
    !isDeepStrictEqual(result.target, target) || result.requestEvidenceSha256 !== sha256(JSON.stringify(evidence)) ||
    result.principalSubject !== evidence.recoveryPrincipalSubject ||
    result.publisherPrincipalSubject !== evidence.publisherPrincipalSubject ||
    result.principalSubject === result.publisherPrincipalSubject || result.membershipRole !== 'Publisher' ||
    result.membershipEvidenceSha256 !== evidence.priorMembershipEvidenceSha256 ||
    result.teamOwner !== false || result.teamAdministrator !== false || result.siteAccessScope !== 'single_site' ||
    result.accountConfigurationCapabilityAbsent !== true || result.teamAdministrationCapabilityAbsent !== true ||
    result.deployCapabilityVerified !== true || result.restoreCapabilityVerified !== true ||
    result.inventoryComplete !== true || result.productionAccess !== false ||
    !isDeepStrictEqual(result.accessibleSiteIds, [POLICY.target.netlifySiteId])) fail(ERROR);
  exactSha256(result.currentMembershipEvidenceSha256, ERROR);
  const window = boundedWindow(result.verifiedAt, result.expiresAt, observedAt, trust.maximumAgeMs);
  if (window.verifiedAt < canonicalIsoTimestamp(evidence.recoveryAvailabilityVerifiedAt, ERROR)) fail(ERROR);
  return window;
}

function proofWindow(response, window) {
  if (window.verifiedAt < canonicalIsoTimestamp(response.statement.issuedAt, ERROR) ||
    window.expiresAt > canonicalIsoTimestamp(response.statement.expiresAt, ERROR)) fail(ERROR);
}

export function validateReadinessBrokerEvidence(value, context, runtime, observedAt) {
  assertExactKeys(value, ['schemaVersion', 'evidenceType', 'scope', 'productionAuthorization',
    'secretValuesSerialized', 'preparedAt', 'target', 'inputEvidence', 'availabilityEnvelope', 'membershipEnvelope'], ERROR);
  if (value.schemaVersion !== 1 || value.evidenceType !== 'cnyos_staging_controller_rollback_readiness_broker_evidence' ||
    value.scope !== 'cnyos_staging_only' || value.productionAuthorization !== false || value.secretValuesSerialized !== false ||
    !isDeepStrictEqual(value.target, context.target) || !isDeepStrictEqual(value.inputEvidence, context.evidence)) fail(ERROR);
  const availabilityTrust = brokerTrustRoot('rollback');
  const membershipTrust = brokerTrustRoot('membership');
  const availabilityRequest = publisherRequest(ROLLBACK_READINESS_OPERATIONS.availability, availabilityTrust,
    publisherResumer(runtime), context.target, context.evidence);
  const availability = verifySignedBrokerEnvelope(JSON.stringify(value.availabilityEnvelope), {
    trust: availabilityTrust, operation: ROLLBACK_READINESS_OPERATIONS.availability,
    requestSha256: sha256(JSON.stringify(availabilityRequest)), observedAt
  });
  const availabilityWindow = validateAvailabilityResult(availability.result, {
    target: context.target, evidence: context.evidence, observedAt, trust: availabilityTrust
  });
  proofWindow(availability, availabilityWindow);
  const membershipEvidence = readinessMembershipEvidence(context, value.availabilityEnvelope);
  const membershipRequest = publisherRequest(ROLLBACK_READINESS_OPERATIONS.membership, membershipTrust,
    publisherResumer(runtime), context.target, membershipEvidence);
  const membership = verifySignedBrokerEnvelope(JSON.stringify(value.membershipEnvelope), {
    trust: membershipTrust, operation: ROLLBACK_READINESS_OPERATIONS.membership,
    requestSha256: sha256(JSON.stringify(membershipRequest)), observedAt
  });
  const membershipWindow = validateMembershipResult(membership.result, {
    target: context.target, evidence: membershipEvidence, observedAt, trust: membershipTrust
  });
  proofWindow(membership, membershipWindow);
  const preparedAt = canonicalIsoTimestamp(value.preparedAt, ERROR);
  if (preparedAt > observedAt || preparedAt < availabilityWindow.verifiedAt || preparedAt < membershipWindow.verifiedAt) fail(ERROR);
  return { availability, membership, expiresAt: new Date(Math.min(availabilityWindow.expiresAt.getTime(),
    membershipWindow.expiresAt.getTime(), Date.parse(context.preflight.value.authorizationExpiresAt),
    Date.parse(context.boundary.expiresAt))) };
}

export async function prepareRollbackReadinessBrokerEvidence({ env = process.env, fetchImpl = fetch,
  oidcTokenProvider, now = () => new Date() } = {}) {
  env = Object.freeze({ ...env });
  publisherOidcEnvironment(env);
  const runtime = publisherRuntime(env);
  const trust = brokerTrustRoot('rollback');
  const membershipTrust = brokerTrustRoot('membership');
  const context = await loadReadinessInputs(env, runtime, publisherNow(now));
  const output = env.CNYOS_CONTROLLER_ROLLBACK_READINESS_BROKER_EVIDENCE_PATH;
  await publisherOutputAvailable(output, context.inputs);
  await publisherInputsUnchanged(context.inputs);
  const availability = await callSignedBrokerOperation({ env, fetchImpl, oidcTokenProvider, trust,
    configuredUrl: env.CNYOS_ROLLBACK_ATTESTATION_BROKER_URL,
    operation: ROLLBACK_READINESS_OPERATIONS.availability, resumer: publisherResumer(runtime),
    target: context.target, evidence: context.evidence, now });
  proofWindow(availability, validateAvailabilityResult(availability.result, {
    target: context.target, evidence: context.evidence, observedAt: availability.observedAt, trust
  }));
  await publisherInputsUnchanged(context.inputs);
  assertFreshPreflight(context.preflight.value, runtime, publisherNow(now));
  const membershipEvidence = readinessMembershipEvidence(context, availability.value);
  const membership = await callSignedBrokerOperation({ env, fetchImpl, oidcTokenProvider, trust: membershipTrust,
    configuredUrl: env.CNYOS_NETLIFY_PRINCIPAL_MEMBERSHIP_BROKER_URL,
    operation: ROLLBACK_READINESS_OPERATIONS.membership, resumer: publisherResumer(runtime),
    target: context.target, evidence: membershipEvidence, now });
  const evidence = { schemaVersion: 1, evidenceType: 'cnyos_staging_controller_rollback_readiness_broker_evidence',
    scope: 'cnyos_staging_only', productionAuthorization: false, secretValuesSerialized: false,
    preparedAt: publisherNow(now).toISOString(), target: context.target, inputEvidence: context.evidence,
    availabilityEnvelope: availability.value, membershipEnvelope: membership.value };
  validateReadinessBrokerEvidence(evidence, context, runtime, publisherNow(now));
  await publisherInputsUnchanged(context.inputs);
  assertFreshPreflight(context.preflight.value, runtime, publisherNow(now));
  const evidencePath = await writeJsonExclusive(output, evidence);
  return Object.freeze({ evidence, evidencePath });
}

async function netlifyRead(fetchImpl, token, pathname) {
  const url = `${API}${pathname}`;
  let response;
  try {
    response = await fetchImpl(url, { method: 'GET', redirect: 'error', credentials: 'omit',
      referrerPolicy: 'no-referrer', cache: 'no-store',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(20_000) });
  } catch { fail('CNYOS_ROLLBACK_READINESS_NETLIFY_REQUEST_FAILED'); }
  if (response.status !== 200 || response.redirected || response.url !== url ||
    !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '') ||
    response.headers.get('set-cookie')) fail('CNYOS_ROLLBACK_READINESS_NETLIFY_RESPONSE_INVALID');
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_API_BYTES)) fail(ERROR);
  if (!response.body || typeof response.body.getReader !== 'function') fail(ERROR);
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_API_BYTES) { await reader.cancel().catch(() => {}); fail(ERROR); }
      chunks.push(Buffer.from(next.value));
    }
  } finally { reader.releaseLock(); }
  const bytes = Buffer.concat(chunks);
  if (bytes.includes(Buffer.from(token)) || [...response.headers].some(([, value]) => value.includes(token))) fail(ERROR);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(ERROR); }
  return { value, response };
}

export async function observeRollbackToken({ fetchImpl, token, expectedSubject, previousDeployId }) {
  const userBefore = await netlifyRead(fetchImpl, token, '/user');
  if (!isPlainObject(userBefore.value) || userBefore.value.id !== expectedSubject) fail(ERROR);
  const sites = await netlifyRead(fetchImpl, token, '/sites?per_page=100&page=1');
  const link = String(sites.response.headers.get('link') || '');
  const next = String(sites.response.headers.get('x-next-page') || '').trim();
  const pages = String(sites.response.headers.get('x-page-count') || sites.response.headers.get('x-total-pages') || '').trim();
  if (/\brel\s*=\s*["']?next["']?/i.test(link) || (next && next !== '0') ||
    (pages && (!/^\d+$/.test(pages) || Number(pages) !== 1)) ||
    !Array.isArray(sites.value) || sites.value.length !== 1) fail(ERROR);
  const site = sites.value[0];
  if (!isPlainObject(site) || site.id !== POLICY.target.netlifySiteId || site.name !== POLICY.target.netlifySiteName ||
    site.ssl_url !== POLICY.target.netlifyOrigin || site.published_deploy?.id !== previousDeployId) fail(ERROR);
  const userAfter = await netlifyRead(fetchImpl, token, '/user');
  if (!isPlainObject(userAfter.value) || userAfter.value.id !== expectedSubject) fail(ERROR);
  return { subject: expectedSubject, allowedSiteIds: [site.id], accessibleSiteCount: 1 };
}

export async function verifyRollbackReadinessToken({ env = process.env, fetchImpl = fetch, now = () => new Date() } = {}) {
  env = Object.freeze({ ...env });
  readinessTokenEnvironment(env);
  const runtime = publisherRuntime(env);
  brokerTrustRoot('rollback');
  brokerTrustRoot('membership');
  const context = await loadReadinessInputs(env, runtime, publisherNow(now));
  const broker = await publisherEvidence(env, 'ROLLBACK_READINESS_BROKER',
    'cnyos_staging_controller_rollback_readiness_broker_evidence');
  validateReadinessBrokerEvidence(broker.value, context, runtime, publisherNow(now));
  const inputs = [...context.inputs, broker];
  const output = env.CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH;
  await publisherOutputAvailable(output, inputs);
  await publisherInputsUnchanged(inputs);
  // Token is consumed only after both authority signatures and every local binding validate.
  const token = required(env.CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN, ERROR, 4096);
  if (token.length < 20 || /\s/.test(token)) fail(ERROR);
  const inventory = await observeRollbackToken({ fetchImpl, token, expectedSubject: context.boundary.subject,
    previousDeployId: context.evidence.previousPublishedDeployId });
  const observedAt = publisherNow(now);
  await publisherInputsUnchanged(inputs);
  assertFreshPreflight(context.preflight.value, runtime, observedAt);
  const verified = validateReadinessBrokerEvidence(broker.value, context, runtime, observedAt);
  if (verified.expiresAt <= observedAt) fail(ERROR);
  const member = verified.membership.result;
  const evidence = {
    schemaVersion: 1, evidenceType: 'cnyos_staging_controller_rollback_readiness', status: 'passed',
    scope: 'cnyos_staging_only', productionAuthorization: false,
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerRunId: runtime.runId, preflightEvidenceSha256: context.preflight.sha256,
    brokerEvidenceSha256: broker.sha256, depositReceiptSha256: context.deposit.sha256,
    target: POLICY.target, principalSubject: inventory.subject, membershipRole: member.membershipRole,
    membershipEvidenceSha256: member.membershipEvidenceSha256,
    currentMembershipEvidenceSha256: member.currentMembershipEvidenceSha256,
    teamOwner: member.teamOwner, teamAdministrator: member.teamAdministrator, siteAccessScope: member.siteAccessScope,
    liveTokenVerified: true, inventoryComplete: member.inventoryComplete, accessibleSiteCount: inventory.accessibleSiteCount,
    allowedSiteIds: inventory.allowedSiteIds, restoreCapabilityVerified: member.restoreCapabilityVerified,
    productionAccess: member.productionAccess, secretValuesSerialized: false,
    verifiedAt: observedAt.toISOString(), expiresAt: verified.expiresAt.toISOString()
  };
  validateRollbackReadinessEvidence(evidence, { runtime, preflight: context.preflight.value,
    preflightSha256: context.preflight.sha256, observedAt });
  const evidencePath = await writeJsonExclusive(output, evidence);
  return Object.freeze({ evidence, evidencePath });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  const run = mode === 'prepare-broker-evidence' ? prepareRollbackReadinessBrokerEvidence :
    mode === 'verify-token' ? verifyRollbackReadinessToken : null;
  Promise.resolve().then(() => {
    if (!run || process.argv.length !== 3) fail('CNYOS_ROLLBACK_READINESS_MODE_INVALID');
    return run();
  }).catch(error => {
    process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message : ERROR}\n`);
    process.exitCode = 1;
  });
}
