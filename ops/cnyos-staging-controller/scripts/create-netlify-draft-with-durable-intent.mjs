import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY, POLICY_SHA256, assertControllerRuntime, assertExactKeys, assertPolicyTarget,
  canonicalIsoTimestamp, decodeNonce, exactSha256, exactSha40,
  exactDeployId, sha256, writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';
import {
  loadEvidence, assertFreshPreflight, validateRollbackReadinessEvidence,
  validatePromotionDraftGate, exactSiteInventory, netlifyJson, assertSite, parseDeployReceipt,
  reviewedDraftAccessBoundary
} from './netlify-evidence.mjs';
import {
  brokerTrustRoot, callSignedBrokerOperation, verifySignedBrokerEnvelope,
  OIDC_FORBIDDEN_ENVIRONMENT_NAMES
} from './reconcile-netlify-release-state.mjs';
import {
  validateProtectedNetlifyCliProvenance, netlifyCliChildEnvironment
} from './validate-function-environment.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/;
const fail = suffix => { throw new Error(`CNYOS_DRAFT_${suffix}`); };
export const DRAFT_INTENT_OPERATION = 'record_draft_intent';
export const DRAFT_PUBLISHER_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  ...OIDC_FORBIDDEN_ENVIRONMENT_NAMES.filter(name =>
    !['CNYOS_STAGING_NETLIFY_AUTH_TOKEN', 'NETLIFY_AUTH_TOKEN'].includes(name)),
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_DRAFT_LIFECYCLE_BROKER_URL', 'NODE_OPTIONS', 'NODE_PATH'
]);
const RESULT_KEYS = Object.freeze([
  'status', 'target', 'intentId', 'intentGeneration', 'source', 'artifact',
  'previousDeployId', 'principalSubject', 'ownershipMarker', 'producerManifestSha256',
  'preflightEvidenceSha256', 'draftGateEvidenceSha256', 'rollbackReadinessEvidenceSha256',
  'durable', 'discoverableByRunAndNonce', 'ownershipMarkerLookupRequired',
  'automaticReplayPermitted', 'cleanupOnPrePromotionFailureArmed', 'privateDraftBoundary',
  'anonymousAccessDeniedBeforeCreation', 'anonymousFunctionAccessDeniedBeforeCreation', 'createdAt', 'expiresAt'
]);
const RECEIPT_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'authorization', 'promotionAuthorization',
  'scope', 'productionAuthorization', 'realPatientDataAuthorized', 'secretValuesSerialized',
  'controllerRepository', 'controllerRef', 'controllerCommit', 'controllerRunId',
  'dispatchNonce', 'source', 'artifact', 'target', 'previousDeployId', 'intentId',
  'intentGeneration', 'deployMessage', 'principalSubject', 'producerManifestSha256',
  'preflightEvidenceSha256', 'draftGateEvidenceSha256', 'rollbackReadinessEvidenceSha256',
  'recordedAt', 'expiresAt', 'brokerRequestSha256', 'brokerEnvelope'
]);

export function assertDraftCredentialIsolation(env, mode) {
  if (!['oidc', 'publisher'].includes(mode)) fail('CREDENTIAL_ISOLATION_INVALID');
  const names = mode === 'oidc' ? OIDC_FORBIDDEN_ENVIRONMENT_NAMES :
    DRAFT_PUBLISHER_FORBIDDEN_ENVIRONMENT_NAMES;
  for (const name of names) if (Object.hasOwn(env, name)) fail('CREDENTIAL_ISOLATION_INVALID');
  if (Object.keys(env).some(name => /^(?:LD_|DYLD_)/.test(name) ||
    ['NODE_OPTIONS', 'NODE_PATH'].includes(name))) fail('CREDENTIAL_ISOLATION_INVALID');
}
function nowDate(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail('TIME_INVALID');
  return value;
}
function publisherToken(env) {
  const token = env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN;
  if (typeof token !== 'string' || token.length < 20 || token.length > 4096 || /[\s\0]/.test(token) ||
    (Object.hasOwn(env, 'NETLIFY_AUTH_TOKEN') && env.NETLIFY_AUTH_TOKEN !== token)) fail('PUBLISHER_TOKEN_INVALID');
  return token;
}
export function draftResumer(runtime) {
  return Object.freeze({ controllerRepository: runtime.repository, controllerRef: runtime.ref,
    controllerWorkflowPath: runtime.workflowPath, controllerRunId: runtime.runId,
    controllerRunAttempt: 1, controllerCommit: runtime.commit });
}
export function draftTarget(context) {
  return Object.freeze({ ...draftResumer(context.runtime), dispatchNonce: context.preflight.value.dispatchNonce,
    netlifySiteId: POLICY.target.netlifySiteId, barrierGeneration: null });
}
export function draftIntentRequestEvidence(context) {
  return Object.freeze({ source: context.preflight.value.source, artifact: context.preflight.value.artifact,
    previousDeployId: context.preflight.value.previousPublishedDeploy.id,
    principalSubject: context.preflight.value.principalProof.subject,
    ownershipMarker: context.gate.value.deployMessage,
    producerManifestSha256: context.bundle.manifestSha256,
    preflightEvidenceSha256: context.preflight.sha256, draftGateEvidenceSha256: context.gate.sha256,
    rollbackReadinessEvidenceSha256: context.readiness.sha256,
    privateDraftBoundary: reviewedDraftAccessBoundary(),
    anonymousAccessDeniedBeforeCreationRequired: true,
    anonymousFunctionAccessDeniedBeforeCreationRequired: true,
    durableBeforeMutationRequired: true, discoverableByRunAndNonceRequired: true,
    ownershipMarkerLookupRequired: true, automaticReplayPermitted: false,
    cleanupOnPrePromotionFailureRequired: true });
}
function requestSha256(context, trust) {
  return sha256(JSON.stringify({ schemaVersion: 1,
    evidenceType: 'cnyos_staging_reconciliation_broker_request', operationDomain: trust.operationDomain,
    operation: DRAFT_INTENT_OPERATION, policyId: trust.policyId, policySha256: trust.policySha256,
    controllerPolicySha256: POLICY_SHA256, resumer: draftResumer(context.runtime),
    target: draftTarget(context), evidence: draftIntentRequestEvidence(context) }));
}

export async function loadDraftMutationContext({ env, now = () => new Date(),
  bundleVerifier = verifyProducerBundle } = {}) {
  const runtime = assertControllerRuntime(env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath) fail('RELEASE_WORKFLOW_REQUIRED');
  const observedAt = nowDate(now);
  const bundle = await bundleVerifier({ env });
  const preflight = await loadEvidence(env.CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256, 'CNYOS_DRAFT_PREFLIGHT_INVALID');
  assertFreshPreflight(preflight.value, runtime, observedAt);
  assertPolicyTarget(preflight.value.target, 'CNYOS_DRAFT_TARGET_INVALID');
  if (preflight.value.dispatchNonce !== decodeNonce(env.CNYOS_DISPATCH_NONCE).value ||
    preflight.value.dispatchNonce !== bundle.manifest.dispatchNonce ||
    preflight.value.source?.repository !== POLICY.sourceRepository ||
    preflight.value.source?.commit !== bundle.manifest.candidateCommit ||
    preflight.value.source?.tree !== bundle.manifest.candidateTree ||
    preflight.value.artifact?.artifactSha256 !== bundle.manifest.artifactSha256 ||
    typeof preflight.value.principalProof?.subject !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(preflight.value.principalProof.subject)) fail('SOURCE_BINDING_INVALID');
  exactSha40(bundle.manifest.candidateCommit, 'CNYOS_DRAFT_SOURCE_INVALID');
  exactSha256(bundle.manifestSha256, 'CNYOS_DRAFT_SOURCE_INVALID');
  const readiness = await loadEvidence(env.CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_ROLLBACK_READINESS_EVIDENCE_SHA256, 'CNYOS_DRAFT_READINESS_INVALID');
  validateRollbackReadinessEvidence(readiness.value, { runtime, preflight: preflight.value,
    preflightSha256: preflight.sha256, observedAt });
  const gate = await loadEvidence(env.CNYOS_CONTROLLER_DRAFT_GATE_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_DRAFT_GATE_EVIDENCE_SHA256, 'CNYOS_DRAFT_GATE_INVALID');
  validatePromotionDraftGate(gate.value, { runtime, preflight: preflight.value,
    preflightSha256: preflight.sha256, rollbackReadinessSha256: readiness.sha256, observedAt });
  return Object.freeze({ runtime, bundle, preflight, gate, readiness, observedAt });
}

export function validateDraftIntentEnvelope(raw, { context, trust = brokerTrustRoot('draft'),
  observedAt = context.observedAt } = {}) {
  const verified = verifySignedBrokerEnvelope(raw, { trust, operation: DRAFT_INTENT_OPERATION,
    requestSha256: requestSha256(context, trust), observedAt });
  const r = verified.result;
  assertExactKeys(r, RESULT_KEYS, 'CNYOS_DRAFT_INTENT_RESULT_INVALID');
  const expected = draftIntentRequestEvidence(context);
  for (const key of ['source', 'artifact', 'previousDeployId', 'principalSubject', 'ownershipMarker',
    'producerManifestSha256', 'preflightEvidenceSha256', 'draftGateEvidenceSha256',
    'rollbackReadinessEvidenceSha256', 'privateDraftBoundary']) {
    if (!isDeepStrictEqual(r[key], expected[key])) fail('INTENT_BINDING_INVALID');
  }
  const createdAt = canonicalIsoTimestamp(r.createdAt, 'CNYOS_DRAFT_INTENT_TIME_INVALID');
  const expiresAt = canonicalIsoTimestamp(r.expiresAt, 'CNYOS_DRAFT_INTENT_TIME_INVALID');
  if (r.status !== 'recorded' || !isDeepStrictEqual(r.target, draftTarget(context)) ||
    !IDENTIFIER.test(r.intentId || '') || !IDENTIFIER.test(r.intentGeneration || '') ||
    r.durable !== true || r.discoverableByRunAndNonce !== true || r.ownershipMarkerLookupRequired !== true ||
    r.automaticReplayPermitted !== false || r.cleanupOnPrePromotionFailureArmed !== true ||
    r.anonymousAccessDeniedBeforeCreation !== true || r.anonymousFunctionAccessDeniedBeforeCreation !== true ||
    createdAt > observedAt || createdAt < canonicalIsoTimestamp(context.gate.value.checkedAt) ||
    expiresAt <= observedAt || expiresAt <= createdAt || expiresAt.getTime() - createdAt.getTime() > trust.maximumAgeMs ||
    expiresAt > canonicalIsoTimestamp(verified.statement.expiresAt) ||
    expiresAt > canonicalIsoTimestamp(context.preflight.value.authorizationExpiresAt)) fail('INTENT_RESULT_INVALID');
  return verified;
}
function intentReceipt(context, verified) {
  const r = verified.result;
  return Object.freeze({ schemaVersion: 1, evidenceType: 'cnyos_staging_controller_draft_intent',
    status: 'recorded', authorization: false, promotionAuthorization: false,
    scope: 'cnyos_staging_only', productionAuthorization: false, realPatientDataAuthorized: false,
    secretValuesSerialized: false, controllerRepository: context.runtime.repository,
    controllerRef: context.runtime.ref, controllerCommit: context.runtime.commit,
    controllerRunId: context.runtime.runId, dispatchNonce: r.target.dispatchNonce,
    source: r.source, artifact: r.artifact, target: POLICY.target, previousDeployId: r.previousDeployId,
    intentId: r.intentId, intentGeneration: r.intentGeneration, deployMessage: r.ownershipMarker,
    principalSubject: r.principalSubject, producerManifestSha256: r.producerManifestSha256,
    preflightEvidenceSha256: r.preflightEvidenceSha256, draftGateEvidenceSha256: r.draftGateEvidenceSha256,
    rollbackReadinessEvidenceSha256: r.rollbackReadinessEvidenceSha256,
    recordedAt: r.createdAt, expiresAt: r.expiresAt,
    brokerRequestSha256: verified.statement.requestSha256, brokerEnvelope: verified.value });
}
export async function validateStoredDraftIntent({ env, context, now = () => new Date(),
  trust = brokerTrustRoot('draft') } = {}) {
  const stored = await loadEvidence(env.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH,
    env.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256, 'CNYOS_DRAFT_INTENT_EVIDENCE_INVALID');
  assertExactKeys(stored.value, RECEIPT_KEYS, 'CNYOS_DRAFT_INTENT_EVIDENCE_INVALID');
  const verified = validateDraftIntentEnvelope(JSON.stringify(stored.value.brokerEnvelope),
    { context, trust, observedAt: nowDate(now) });
  if (!isDeepStrictEqual(stored.value, intentReceipt(context, verified))) fail('INTENT_EVIDENCE_INVALID');
  return Object.freeze({ ...stored, verified });
}
export async function recordDraftIntent({ env = process.env, fetchImpl = fetch,
  oidcTokenProvider, now = () => new Date(), contextLoader = loadDraftMutationContext } = {}) {
  env = Object.freeze({ ...env });
  assertDraftCredentialIsolation(env, 'oidc');
  const trust = brokerTrustRoot('draft');
  const context = await contextLoader({ env, now });
  const response = await callSignedBrokerOperation({ env, fetchImpl, oidcTokenProvider,
    trust, configuredUrl: env.CNYOS_DRAFT_LIFECYCLE_BROKER_URL,
    operation: DRAFT_INTENT_OPERATION, resumer: draftResumer(context.runtime), target: draftTarget(context),
    evidence: draftIntentRequestEvidence(context), now });
  const verified = validateDraftIntentEnvelope(response.raw, { context, trust, observedAt: response.observedAt });
  const evidence = intentReceipt(context, verified);
  const evidencePath = await writeJsonExclusive(env.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH, evidence);
  return Object.freeze({ evidence, evidencePath });
}

async function freshOutput(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value ||
    /[\0\r\n]/.test(value)) fail('OUTPUT_PATH_INVALID');
  const parent = path.dirname(value);
  const status = await fs.lstat(parent);
  if (!status.isDirectory() || status.isSymbolicLink() || await fs.realpath(parent) !== parent) fail('OUTPUT_PATH_INVALID');
  try { await fs.lstat(value); } catch (error) {
    if (error.code === 'ENOENT') return value;
    throw error;
  }
  fail('OUTPUT_ALREADY_EXISTS');
}
export function draftCliArguments({ cliRealPath, bundleDirectory, deployMessage }) {
  return Object.freeze([cliRealPath, 'deploy', '--no-build', '--json', '--context', 'production',
    '--site', POLICY.target.netlifySiteId, '--dir', path.join(bundleDirectory, 'payload/dist'),
    '--functions', path.join(bundleDirectory, 'payload/netlify/functions'),
    '--skip-functions-cache', '--message', deployMessage, '--timeout', '120']);
}
export async function deployFromIntent({ env = process.env, fetchImpl = fetch, now = () => new Date(),
  contextLoader = loadDraftMutationContext, cliProvenanceVerifier = validateProtectedNetlifyCliProvenance,
  execFileImpl = execFileSync } = {}) {
  env = Object.freeze({ ...env });
  assertDraftCredentialIsolation(env, 'publisher');
  const trust = brokerTrustRoot('draft');
  const context = await contextLoader({ env, now });
  const intent = await validateStoredDraftIntent({ env, context, now, trust });
  const output = await freshOutput(env.CNYOS_NETLIFY_CLI_RECEIPT_PATH);
  for (const protectedRoot of [ROOT, context.bundle.bundleDirectory]) {
    if (output === protectedRoot || output.startsWith(`${protectedRoot}${path.sep}`)) fail('OUTPUT_PATH_INVALID');
  }
  // A separate exclusive journal survives timeout, malformed output and receipt loss.
  // Never delete it or automatically repeat a possibly accepted deploy operation.
  const journal = await freshOutput(`${output}.attempt.json`);
  const provenance = await cliProvenanceVerifier({ cliPath: env.CNYOS_NETLIFY_CLI_PATH,
    controllerPackageRoot: ROOT, expectedVersion: POLICY.publishing.netlifyCliVersion });
  if (env.CNYOS_NETLIFY_CLI_VERSION !== POLICY.publishing.netlifyCliVersion) fail('CLI_VERSION_INVALID');
  const token = publisherToken(env);
  await exactSiteInventory(fetchImpl, token, intent.value.principalSubject);
  const site = await netlifyJson(fetchImpl, token, `/sites/${POLICY.target.netlifySiteId}`);
  assertSite(site.value, intent.value.previousDeployId);
  assertFreshPreflight(context.preflight.value, context.runtime, nowDate(now));
  await validateStoredDraftIntent({ env, context, now, trust });
  const scratch = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'cnyos-draft-cli-'));
  try {
    for (const dir of ['home', 'tmp', 'cache', 'config']) await fs.mkdir(path.join(scratch, dir), { mode: 0o700 });
    // Empty controller-owned configuration prevents ancestor/candidate build/plugin discovery.
    await fs.writeFile(path.join(scratch, 'netlify.toml'), '[build]\ncommand = ""\n', { flag: 'wx', mode: 0o600 });
    await writeJsonExclusive(journal, { schemaVersion: 1,
      evidenceType: 'cnyos_staging_draft_mutation_attempt', status: 'outcome_unknown',
      controllerRunId: context.runtime.runId, target: draftTarget(context),
      intentId: intent.value.intentId, intentGeneration: intent.value.intentGeneration,
      intentEvidenceSha256: intent.sha256, deployMessage: intent.value.deployMessage,
      attemptedAt: nowDate(now).toISOString(), automaticReplayPermitted: false,
      reconciliationRequired: true, productionAuthorization: false, secretValuesSerialized: false });
    let raw;
    try {
      raw = execFileImpl(process.execPath, draftCliArguments({ cliRealPath: provenance.cliRealPath,
        bundleDirectory: context.bundle.bundleDirectory, deployMessage: intent.value.deployMessage }), {
        cwd: scratch, env: netlifyCliChildEnvironment({ token, isolatedStateRoot: scratch }),
        encoding: 'utf8', maxBuffer: 2 * 1024 * 1024, timeout: 150_000,
        stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true
      });
    } catch { fail('DEPLOY_OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED'); }
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > 2 * 1024 * 1024 || raw.includes(token)) {
      fail('DEPLOY_OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED');
    }
    let parsed;
    try { parsed = parseDeployReceipt(JSON.parse(raw)); } catch { fail('DEPLOY_OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED'); }
    if (parsed.deployId === intent.value.previousDeployId) fail('FRESH_DEPLOY_REQUIRED');
    exactDeployId(parsed.deployId, 'CNYOS_DRAFT_DEPLOY_ID_INVALID');
    // Retain only the provider identity needed by the existing receipt recorder.
    await writeJsonExclusive(output, { deploy_id: parsed.deployId, site_id: POLICY.target.netlifySiteId,
      deploy_ssl_url: parsed.exactDeployOrigin });
    return Object.freeze({ deployId: parsed.deployId, intentId: intent.value.intentId,
      intentGeneration: intent.value.intentGeneration, intentEvidenceSha256: intent.sha256,
      receiptPath: output, attemptPath: journal, automaticReplayPermitted: false });
  } finally { await fs.rm(scratch, { recursive: true, force: false }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const operation = process.argv[2];
  const fn = operation === 'record-intent' ? recordDraftIntent : operation === 'deploy-from-intent' ? deployFromIntent : null;
  Promise.resolve().then(() => { if (!fn) fail('MODE_INVALID'); return fn(); }).then(() => {
    process.stdout.write('CNYOS draft operation: completed\n');
  }).catch(error => { process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ?
    error.message : 'CNYOS_DRAFT_OPERATION_FAILED'}\n`); process.exitCode = 1; });
}
