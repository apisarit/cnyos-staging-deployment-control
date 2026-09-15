import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY, POLICY_SHA256, EXPECTED_FUNCTION_NAMES, REQUIRED_SCHEDULES,
  assertPolicyTarget, canonicalIsoTimestamp, recentCanonicalTimestamp,
  exactDeployId, sha256, writeJsonExclusive
} from './policy.mjs';
import {
  loadEvidence, assertFreshPreflight, exactSiteInventory, netlifyJson, assertSite, assertDeploy,
  reviewedDraftAccessBoundary, assertDraftAccessBoundaryEvidence, assertDraftMetadataPromotionChain
} from './netlify-evidence.mjs';
import { validateNetlifyControlBehaviorEvidence } from './verify-netlify-control-file-behavior.mjs';
import {
  assertDraftCredentialIsolation, loadDraftMutationContext, validateStoredDraftIntent
} from './create-netlify-draft-with-durable-intent.mjs';

const fail = suffix => { throw new Error(`CNYOS_PRIVATE_DRAFT_${suffix}`); };
const MAX_PROBE_BYTES = 64 * 1024;
const AGE = 10 * 60 * 1000;
export const PRIVATE_DRAFT_CUSTOM_FUNCTION_PATHS = Object.freeze([
  '/api/account-access', '/api/evidence-search', '/api/line-oa-webhook', '/api/owner-drive',
  '/api/owner-subscription', '/api/patient-identity', '/api/platform-console', '/api/restore-source'
]);
function nowDate(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail('TIME_INVALID');
  return value;
}
export function privateDraftProbeInventory(bundle) {
  const staticPaths = bundle.manifest.files.filter(item => item.path.startsWith('payload/dist/') &&
    !['payload/dist/_headers', 'payload/dist/_redirects'].includes(item.path))
    .map(item => `/${item.path.slice('payload/dist/'.length)}`);
  const functions = EXPECTED_FUNCTION_NAMES.map(name => `/.netlify/functions/${name}`)
    .concat(PRIVATE_DRAFT_CUSTOM_FUNCTION_PATHS);
  return Object.freeze([
    ...[...new Set(['/', ...staticPaths])].sort().map(pathname => ({ pathname, method: 'GET', kind: 'static' })),
    ...functions.flatMap(pathname => ['GET', 'POST'].map(method => ({ pathname, method, kind: 'function' })))
  ].map(Object.freeze));
}
export async function probeAnonymousPrivateDraft(fetchImpl, origin, probe) {
  const allowedOrigin = /^https:\/\/[0-9a-f]{24}--cnyos\.netlify\.app$/;
  if (!allowedOrigin.test(origin) || !['GET', 'POST'].includes(probe.method) ||
    typeof probe.pathname !== 'string' || !probe.pathname.startsWith('/') ||
    probe.pathname.startsWith('//') || /[\s?#\\]/.test(probe.pathname)) fail('PROBE_TARGET_INVALID');
  const url = new URL(probe.pathname, origin);
  if (url.origin !== origin || url.pathname !== probe.pathname) fail('PROBE_TARGET_INVALID');
  let response;
  try {
    response = await fetchImpl(url, { method: probe.method, redirect: 'error', credentials: 'omit',
      referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(10_000),
      headers: probe.method === 'POST' ? { Accept: 'text/html', 'Content-Type': 'application/json' } :
        { Accept: 'text/html' }, ...(probe.method === 'POST' ? { body: '{' } : {}) });
  } catch { fail('ANONYMOUS_ACCESS_NOT_DENIED'); }
  if (response?.redirected || response?.url !== url.href || ![401, 403].includes(response.status)) {
    fail('ANONYMOUS_ACCESS_NOT_DENIED');
  }
  const reader = response.body?.getReader?.();
  if (!reader) fail('PROBE_RESPONSE_INVALID');
  const chunks = []; let size = 0;
  while (true) {
    const next = await reader.read(); if (next.done) break;
    size += next.value.byteLength;
    if (size > MAX_PROBE_BYTES) { await reader.cancel(); fail('PROBE_RESPONSE_TOO_LARGE'); }
    chunks.push(Buffer.from(next.value));
  }
  const bytes = Buffer.concat(chunks, size);
  // Application JSON denial is not evidence of the private deployment boundary.
  const type = String(response.headers.get('content-type') || '').toLowerCase();
  if (!type.startsWith('text/html') || !size || /^[\s]*[\[{]/.test(bytes.toString('utf8'))) {
    fail('APPLICATION_RESPONSE_NOT_PRIVATE_BOUNDARY');
  }
  return Object.freeze({ path: probe.pathname, method: probe.method, kind: probe.kind,
    status: response.status, bodySize: size, bodySha256: sha256(bytes), redirectsFollowed: false,
    credentialsSent: false });
}

export function validatePrivateDraftContentChain({ context, receipt, boundary, verification, metadata,
  control, observedAt }) {
  const { runtime, bundle, preflight } = context;
  const deployId = exactDeployId(receipt.value.draftDeployId, 'CNYOS_PRIVATE_DRAFT_ID_INVALID');
  const previousDeployId = preflight.value.previousPublishedDeploy.id;
  if (deployId === previousDeployId || receipt.value.evidenceType !== 'cnyos_staging_controller_draft_deploy_receipt' ||
    receipt.value.preflightEvidenceSha256 !== preflight.sha256 ||
    receipt.value.draftGateEvidenceSha256 !== context.gate.sha256 ||
    receipt.value.controllerRepository !== runtime.repository || receipt.value.controllerRef !== runtime.ref ||
    receipt.value.controllerCommit !== runtime.commit || receipt.value.controllerRunId !== runtime.runId ||
    receipt.value.dispatchNonce !== preflight.value.dispatchNonce ||
    receipt.value.artifact?.artifactSha256 !== bundle.manifest.artifactSha256 ||
    receipt.value.source?.commit !== bundle.manifest.candidateCommit ||
    receipt.value.source?.tree !== bundle.manifest.candidateTree ||
    receipt.value.previousDeployId !== previousDeployId || receipt.value.currentPublishedDeployId !== previousDeployId ||
    receipt.value.promotionAuthorization !== false || receipt.value.productionAuthorization !== false) fail('RECEIPT_INVALID');
  assertPolicyTarget(receipt.value.target, 'CNYOS_PRIVATE_DRAFT_TARGET_INVALID');
  const verifiedAt = recentCanonicalTimestamp(verification.value.verifiedAt, observedAt, AGE,
    'CNYOS_PRIVATE_DRAFT_VERIFICATION_STALE');
  assertDraftAccessBoundaryEvidence(boundary.value, { runtime, bundle, receipt, deployId,
    previousDeployId, observedAt, reviewedBoundary: reviewedDraftAccessBoundary() });
  const v = verification.value;
  if (v.evidenceType !== 'cnyos_staging_controller_draft_verification' || v.status !== 'passed' ||
    v.controllerRepository !== runtime.repository || v.controllerRef !== runtime.ref ||
    v.controllerCommit !== runtime.commit || v.controllerRunId !== runtime.runId ||
    v.dispatchNonce !== preflight.value.dispatchNonce || v.promotionAuthorization !== false ||
    v.productionAuthorization !== false || v.draftDeployId !== deployId ||
    v.currentPublishedDeployId !== previousDeployId || v.previousDeployId !== previousDeployId ||
    v.source?.commit !== bundle.manifest.candidateCommit || v.source?.tree !== bundle.manifest.candidateTree ||
    v.artifact?.artifactSha256 !== bundle.manifest.artifactSha256 ||
    v.artifact?.producerManifestSha256 !== bundle.manifestSha256 ||
    v.draftReceiptEvidenceSha256 !== receipt.sha256 || v.privateDraftAccessBoundaryEvidenceSha256 !== boundary.sha256 ||
    !isDeepStrictEqual(v.functionNames, EXPECTED_FUNCTION_NAMES) ||
    !isDeepStrictEqual(v.schedules, Object.entries(REQUIRED_SCHEDULES).map(([name, cron]) => ({ name, cron }))
      ) || v.functionByteAttestationAvailable !== false ||
    v.authenticatedDraftContentAccessVerified !== true || v.draftAccessCredentialConsumedOnlyAtBoundary !== true ||
    v.draftAccessCredentialForwardedToCandidateOrigin !== false ||
    v.draftContentAccessTokenSeparatedFromNetlifyPrincipalToken !== true || v.draftAccessTokenSerialized !== false) {
    fail('CONTENT_CHAIN_INVALID');
  }
  assertPolicyTarget(v.target, 'CNYOS_PRIVATE_DRAFT_TARGET_INVALID');
  assertDraftMetadataPromotionChain(metadata, verification, preflight, runtime, observedAt,
    'CNYOS_PRIVATE_DRAFT_METADATA_CHAIN_INVALID');
  validateNetlifyControlBehaviorEvidence(control.value, { runtime, bundle, previousDeployId, deployId,
    preflightEvidenceSha256: preflight.sha256, draftReceiptEvidenceSha256: receipt.sha256,
    draftAccessBoundaryEvidenceSha256: boundary.sha256, draftVerificationEvidenceSha256: verification.sha256,
    observedAt, notBefore: verifiedAt });
  return Object.freeze({ deployId, previousDeployId,
    origin: `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app` });
}

export async function verifyPrivateDraftLifecycle({ env = process.env, fetchImpl = fetch,
  now = () => new Date(), contextLoader = loadDraftMutationContext,
  chainValidator = validatePrivateDraftContentChain } = {}) {
  env = Object.freeze({ ...env });
  assertDraftCredentialIsolation(env, 'publisher');
  if (POLICY.publishing.privateDraftLifecycleContractRequired !== true) fail('POLICY_INVALID');
  const reviewedBoundary = reviewedDraftAccessBoundary();
  if (env.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL !== reviewedBoundary.origin) fail('BOUNDARY_ORIGIN_INVALID');
  const context = await contextLoader({ env, now });
  const intent = await validateStoredDraftIntent({ env, context, now });
  const evidence = {};
  for (const [key, pathName, hashName] of [
    ['receipt', 'DRAFT_RECEIPT', 'DRAFT_RECEIPT'], ['boundary', 'DRAFT_ACCESS_BOUNDARY', 'DRAFT_ACCESS_BOUNDARY'],
    ['verification', 'DRAFT_VERIFICATION', 'DRAFT_VERIFICATION'], ['metadata', 'DRAFT_METADATA', 'DRAFT_METADATA'],
    ['control', 'CONTROL_BEHAVIOR', 'CONTROL_BEHAVIOR']
  ]) evidence[key] = await loadEvidence(env[`CNYOS_CONTROLLER_${pathName}_EVIDENCE_PATH`],
    env[`CNYOS_EXPECTED_${hashName}_EVIDENCE_SHA256`], 'CNYOS_PRIVATE_DRAFT_INPUT_INVALID');
  if (evidence.receipt.value.draftIntentEvidenceSha256 !== intent.sha256 ||
    evidence.receipt.value.draftIntentId !== intent.value.intentId ||
    evidence.receipt.value.draftIntentGeneration !== intent.value.intentGeneration ||
    evidence.receipt.value.intentBindingScope !== 'signed_intent_and_provider_ownership_marker') {
    fail('RECEIPT_INTENT_BINDING_INVALID');
  }
  const { deployId, previousDeployId, origin } = chainValidator({ context, ...evidence, observedAt: nowDate(now) });
  const token = env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN;
  if (typeof token !== 'string' || token.length < 20 || token.length > 4096 || /[\s\0]/.test(token) ||
    (Object.hasOwn(env, 'NETLIFY_AUTH_TOKEN') && env.NETLIFY_AUTH_TOKEN !== token)) fail('TOKEN_INVALID');
  await exactSiteInventory(fetchImpl, token, intent.value.principalSubject);
  async function checkProvider() {
    const current = await netlifyJson(fetchImpl, token, `/sites/${POLICY.target.netlifySiteId}`);
    assertSite(current.value, previousDeployId);
    const deploy = await netlifyJson(fetchImpl, token, `/deploys/${deployId}`);
    assertDeploy(deploy.value, deployId, { expectedMarker: intent.value.deployMessage,
      expectedPublished: false, expectedDraft: true });
    if (canonicalIsoTimestamp(deploy.value.created_at, 'CNYOS_PRIVATE_DRAFT_CREATED_AT_INVALID') <
      canonicalIsoTimestamp(intent.value.recordedAt)) fail('DEPLOY_PRECEDES_INTENT');
  }
  await checkProvider();
  const observations = [];
  for (const probe of privateDraftProbeInventory(context.bundle)) {
    observations.push(await probeAnonymousPrivateDraft(fetchImpl, origin, probe));
  }
  await checkProvider();
  const verifiedAt = nowDate(now);
  assertFreshPreflight(context.preflight.value, context.runtime, verifiedAt);
  await validateStoredDraftIntent({ env, context, now: () => verifiedAt });
  chainValidator({ context, ...evidence, observedAt: verifiedAt });
  const receipt = Object.freeze({ schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_private_draft_lifecycle', status: 'passed',
    authorization: false, promotionAuthorization: false, scope: 'cnyos_staging_only',
    productionAuthorization: false, realPatientDataAuthorized: false, secretValuesSerialized: false,
    controllerRepository: context.runtime.repository, controllerRef: context.runtime.ref,
    controllerCommit: context.runtime.commit, controllerRunId: context.runtime.runId,
    dispatchNonce: context.preflight.value.dispatchNonce, source: context.preflight.value.source,
    artifact: context.preflight.value.artifact, target: POLICY.target, policySha256: POLICY_SHA256,
    currentPublishedDeployId: previousDeployId, draftDeployId: deployId, exactDraftDeployOrigin: origin,
    accessRestrictedToController: true, anonymousDraftAccessDenied: true,
    publicAnonymousFunctionAccessDenied: true, cleanupOnPrePromotionFailureArmed:
      intent.verified.result.cleanupOnPrePromotionFailureArmed,
    intentBindingScope: 'signed_intent_and_provider_ownership_marker',
    draftIntentEvidenceSha256: intent.sha256, draftIntentId: intent.value.intentId,
    draftIntentGeneration: intent.value.intentGeneration,
    preflightEvidenceSha256: context.preflight.sha256, draftReceiptEvidenceSha256: evidence.receipt.sha256,
    draftAccessBoundaryEvidenceSha256: evidence.boundary.sha256,
    draftVerificationEvidenceSha256: evidence.verification.sha256,
    draftMetadataEvidenceSha256: evidence.metadata.sha256, controlBehaviorEvidenceSha256: evidence.control.sha256,
    verifiedAt: verifiedAt.toISOString(), anonymousProbeCount: observations.length,
    observations: Object.freeze(observations) });
  const evidencePath = await writeJsonExclusive(env.CNYOS_CONTROLLER_PRIVATE_DRAFT_EVIDENCE_PATH, receipt);
  return Object.freeze({ evidence: receipt, evidencePath });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyPrivateDraftLifecycle().then(() => process.stdout.write('CNYOS private draft lifecycle: verified\n')).catch(error => {
    process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message :
      'CNYOS_PRIVATE_DRAFT_LIFECYCLE_FAILED'}\n`); process.exitCode = 1;
  });
}
