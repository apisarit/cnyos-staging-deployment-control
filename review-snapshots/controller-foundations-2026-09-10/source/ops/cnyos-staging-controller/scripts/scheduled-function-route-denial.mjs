import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  EXPECTED_FUNCTION_NAMES,
  POLICY,
  REQUIRED_SCHEDULES,
  assertControllerRuntime,
  assertExactKeys,
  assertPolicyTarget,
  canonicalIsoTimestamp,
  deploymentMarker,
  exactDeployId,
  exactSha40,
  exactSha256,
  fail,
  isPlainObject,
  parseJsonObject,
  readFileBounded,
  recentCanonicalTimestamp,
  required,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { verifyProducerBundle } from './verify-producer-bundle.mjs';

export const SCHEDULED_ROUTE_DENIAL_FUNCTIONS = Object.freeze([
  'database-backup',
  'database-backup-recovery'
]);

export const SCHEDULED_ROUTE_DENIAL_METHODS = Object.freeze(['GET', 'POST']);

export const SCHEDULED_ROUTE_DENIAL_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'DATABASE_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'PGPASSWORD',
  'POSTGRES_PASSWORD',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_SERVICE_ROLE_KEY'
]);

const MAXIMUM_EVIDENCE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_MANIFEST_BYTES = 64 * 1024;
const MAXIMUM_DENIAL_BODY_BYTES = 16 * 1024;
const REQUEST_TIMEOUT_MILLISECONDS = 10_000;
const DEPLOY_MANIFEST_MAXIMUM_AGE_MILLISECONDS =
  POLICY.authorization.maximumLifetimeMinutes * 60 * 1000;
const SOURCE_KEYS = Object.freeze(['repository', 'commit', 'tree', 'functionSourceTree']);
const AUTHORIZATION_ARTIFACT_KEYS = Object.freeze([
  'producerManifestSha256',
  'artifactSha256',
  'fileCount',
  'candidateBuildArtifactDigest',
  'staticReproducibilityEvidenceSha256',
  'staticArtifactSha256',
  'candidateDependencyLockSha256',
  'stagingConfigSha256',
  'productionDenylistConfigSha256',
  'functionBundleManifestSha256',
  'functionBundleDependencyLockSha256',
  'functionSourcesSha256',
  'producerRunId',
  'githubArtifactDigest'
]);
const PROMOTION_KEYS = Object.freeze([
  'schemaVersion',
  'evidenceType',
  'status',
  'authorization',
  'scope',
  'productionAuthorization',
  'promotedAt',
  'controllerRepository',
  'controllerRef',
  'controllerCommit',
  'controllerRunId',
  'dispatchNonce',
  'source',
  'artifact',
  'target',
  'previousDeployId',
  'promotedDeployId',
  'exactDeployOrigin',
  'currentPublishedDeployId',
  'deploy',
  'preflightEvidenceSha256',
  'liveGitHubPrecredentialBoundaryEvidenceSha256',
  'liveGitHubPrepromotionBoundaryEvidenceSha256',
  'promotionAttemptEvidenceSha256',
  'draftVerificationEvidenceSha256',
  'controlBehaviorEvidenceSha256',
  'privateDraftEvidenceSha256',
  'exclusivePublisherEvidenceSha256',
  'exclusivePublisherLeaseId'
]);
const POST_PROMOTION_KEYS = Object.freeze([
  'schemaVersion',
  'evidenceType',
  'status',
  'authorization',
  'scope',
  'productionAuthorization',
  'verifiedAt',
  'controllerRepository',
  'controllerRef',
  'controllerCommit',
  'controllerRunId',
  'dispatchNonce',
  'source',
  'artifact',
  'target',
  'netlifyDeployId',
  'exactDeployOrigin',
  'currentPublishedDeployId',
  'schedules',
  'functionNames',
  'functionByteAttestationAvailable',
  'verificationPhase',
  'promotionEvidenceSha256'
]);
const DEPLOY_KEYS = Object.freeze([
  'id', 'siteId', 'state', 'context', 'commitRef', 'title', 'exactDeployOrigin', 'publishedAt'
]);
const POST_PROMOTION_ARTIFACT_KEYS = Object.freeze([
  'producerManifestSha256',
  'artifactSha256',
  'fileCount',
  'closedWorldInventoryVerified',
  'inventorySha256'
]);

function assertCredentialIsolation(env) {
  for (const name of SCHEDULED_ROUTE_DENIAL_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) {
      fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_CREDENTIAL_ISOLATION_INVALID');
    }
  }
}

function exactImmutableOrigin(deployId) {
  return `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`;
}

function assertControllerIdentity(value, runtime, code) {
  if (!isPlainObject(value) || value.controllerRepository !== runtime.repository ||
    value.controllerRef !== runtime.ref || value.controllerCommit !== runtime.commit ||
    value.controllerRunId !== runtime.runId) fail(code);
}

function assertBoundSource(value, bundle, commit, tree, code) {
  assertExactKeys(value, SOURCE_KEYS, code);
  if (value.repository !== POLICY.sourceRepository || value.repository !== bundle.manifest.sourceRepository ||
    value.commit !== commit || value.commit !== bundle.manifest.candidateCommit ||
    value.tree !== tree || value.tree !== bundle.manifest.candidateTree ||
    value.functionSourceTree !== bundle.manifest.functionSourceTree) fail(code);
}

function assertBoundArtifact(value, bundle, runtime, code) {
  assertExactKeys(value, AUTHORIZATION_ARTIFACT_KEYS, code);
  const manifest = bundle.manifest;
  if (value.producerManifestSha256 !== bundle.manifestSha256 ||
    value.artifactSha256 !== manifest.artifactSha256 ||
    value.fileCount !== manifest.fileCount ||
    value.candidateBuildArtifactDigest !== manifest.candidateBuildArtifactDigest ||
    value.staticReproducibilityEvidenceSha256 !== manifest.staticReproducibilityEvidenceSha256 ||
    value.staticArtifactSha256 !== manifest.staticArtifactSha256 ||
    value.candidateDependencyLockSha256 !== manifest.candidateDependencyLockSha256 ||
    value.stagingConfigSha256 !== manifest.stagingConfigSha256 ||
    value.productionDenylistConfigSha256 !== manifest.productionDenylistConfigSha256 ||
    value.functionBundleManifestSha256 !== manifest.functionBundleManifestSha256 ||
    value.functionBundleDependencyLockSha256 !== manifest.functionBundleDependencyLockSha256 ||
    value.functionSourcesSha256 !== manifest.functionSourcesSha256 ||
    value.producerRunId !== runtime.runId) fail(code);
  exactSha256(value.githubArtifactDigest, code);
}

function assertBoundTarget(value, code) {
  assertExactKeys(value, Object.keys(POLICY.target), code);
  assertPolicyTarget(value, code);
}

async function loadEvidence(env, pathName, digestName, code) {
  const expectedDigest = exactSha256(env[digestName], `${code}_DIGEST_INVALID`);
  const filename = required(env[pathName], `${code}_PATH_REQUIRED`, 4096);
  const bytes = await readFileBounded(filename, MAXIMUM_EVIDENCE_BYTES, code);
  const digest = sha256(bytes);
  if (digest !== expectedDigest) fail(`${code}_DIGEST_MISMATCH`);
  return Object.freeze({
    value: parseJsonObject(bytes.toString('utf8'), code),
    sha256: digest
  });
}

function assertPreflight(preflight, bundle, runtime, commit, tree, observedAt) {
  const code = 'CNYOS_CONTROLLER_SCHEDULED_ROUTE_PREFLIGHT_INVALID';
  assertControllerIdentity(preflight, runtime, code);
  assertBoundSource(preflight.source, bundle, commit, tree, code);
  assertBoundArtifact(preflight.artifact, bundle, runtime, code);
  assertBoundTarget(preflight.target, code);
  const capturedAt = recentCanonicalTimestamp(
    preflight.capturedAt,
    observedAt,
    POLICY.authorization.maximumLifetimeMinutes * 60 * 1000,
    code
  );
  const expiryNames = [
    'authorizationExpiresAt',
    'deploymentControlBoundaryExpiresAt',
    'principalProofExpiresAt',
    'liveNetlifyAuthorityBoundaryExpiresAt'
  ];
  const expiries = expiryNames.map(name => canonicalIsoTimestamp(preflight[name], code));
  const previousDeployId = exactDeployId(preflight.previousPublishedDeploy?.id, code);
  const exclusion = preflight.targetSiteAndPublisherExclusion;
  const principal = preflight.principalProof;
  if (preflight.schemaVersion !== 1 ||
    preflight.evidenceType !== 'cnyos_staging_controller_preflight' ||
    preflight.authorization !== false || preflight.scope !== 'cnyos_staging_only' ||
    preflight.productionAuthorization !== false ||
    preflight.dispatchNonce !== bundle.manifest.dispatchNonce ||
    expiries.some(value => value <= observedAt || value <= capturedAt) ||
    preflight.protectedFunctionSecretPresenceVerified !== true ||
    preflight.backupEnabled !== false ||
    !isPlainObject(principal) || principal.inventoryComplete !== true ||
    principal.accessibleSiteCount !== 1 ||
    !Array.isArray(principal.accessibleSiteIds) || principal.accessibleSiteIds.length !== 1 ||
    principal.accessibleSiteIds[0] !== POLICY.target.netlifySiteId ||
    principal.nonStagingSiteAccess !== false ||
    !isPlainObject(exclusion) ||
    exclusion.productionNetlifySiteId !== POLICY.productionDenylist.netlifySiteId ||
    exclusion.productionNetlifyOrigin !== POLICY.productionDenylist.netlifyOrigin ||
    exclusion.targetSiteClassifiedStagingOnly !== true ||
    exclusion.realPatientDataAbsent !== true ||
    exclusion.legacyPublisherInventoryComplete !== true ||
    exclusion.candidateRepositoryProductionWorkflowTargetDenied !== true ||
    exclusion.candidateRepositoryPreviewWorkflowTargetDenied !== true ||
    exclusion.allAlternatePublisherCredentialsTargetDenied !== true ||
    exclusion.currentCnyosProductionMappingConflictResolved !== true) fail(code);
  for (const name of [
    'preReleaseReconciliationEvidenceSha256',
    'authorizationEvidenceSha256',
    'liveGitHubPrecredentialBoundaryEvidenceSha256',
    'rollbackAttestationDepositEvidenceSha256',
    'rollbackAttestationDepositReceiptSha256',
    'liveNetlifyAuthorityBoundaryEvidenceSha256',
    'functionEnvironmentEvidenceSha256',
    'functionEnvironmentExactValuesSha256',
    'runtimeCapabilityEvidenceSha256',
    'backupDisableEvidenceSha256',
    'knownGoodRollbackEvidenceSha256'
  ]) exactSha256(preflight[name], code);
  return Object.freeze({
    capturedAt,
    previousDeployId,
    expiresAt: new Date(Math.min(...expiries.map(value => value.getTime())))
  });
}

function assertPromotion(promotion, preflight, preflightSha256, bundle, runtime,
  commit, tree, deployId, immutableOrigin, preflightCapturedAt, observedAt) {
  const code = 'CNYOS_CONTROLLER_SCHEDULED_ROUTE_PROMOTION_INVALID';
  assertExactKeys(promotion, PROMOTION_KEYS, code);
  assertControllerIdentity(promotion, runtime, code);
  assertBoundSource(promotion.source, bundle, commit, tree, code);
  assertBoundArtifact(promotion.artifact, bundle, runtime, code);
  if (!isDeepStrictEqual(promotion.artifact, preflight.artifact)) fail(code);
  assertBoundTarget(promotion.target, code);
  assertExactKeys(promotion.deploy, DEPLOY_KEYS, code);
  const promotedAt = canonicalIsoTimestamp(promotion.promotedAt, code);
  const publishedAt = new Date(promotion.deploy.publishedAt);
  if (promotion.schemaVersion !== 1 ||
    promotion.evidenceType !== 'cnyos_staging_controller_exact_deploy_promotion' ||
    promotion.status !== 'passed' || promotion.authorization !== false ||
    promotion.scope !== 'cnyos_staging_only' || promotion.productionAuthorization !== false ||
    promotion.dispatchNonce !== bundle.manifest.dispatchNonce ||
    promotion.previousDeployId !== preflight.previousPublishedDeploy.id ||
    promotion.promotedDeployId !== deployId || promotion.exactDeployOrigin !== immutableOrigin ||
    promotion.currentPublishedDeployId !== deployId ||
    promotion.preflightEvidenceSha256 !== preflightSha256 ||
    promotedAt < preflightCapturedAt || promotedAt > observedAt ||
    promotion.deploy.id !== deployId || promotion.deploy.siteId !== POLICY.target.netlifySiteId ||
    promotion.deploy.state !== 'ready' || promotion.deploy.context !== 'production' ||
    promotion.deploy.commitRef !== commit || promotion.deploy.exactDeployOrigin !== immutableOrigin ||
    promotion.deploy.title !== deploymentMarker(runtime.runId, bundle.manifest.dispatchNonce, commit) ||
    typeof promotion.deploy.publishedAt !== 'string' || Number.isNaN(publishedAt.getTime()) ||
    publishedAt < promotedAt || publishedAt > observedAt ||
    required(promotion.exclusivePublisherLeaseId, code, 500).length < 16) fail(code);
  for (const name of [
    'liveGitHubPrecredentialBoundaryEvidenceSha256',
    'liveGitHubPrepromotionBoundaryEvidenceSha256',
    'promotionAttemptEvidenceSha256',
    'draftVerificationEvidenceSha256',
    'controlBehaviorEvidenceSha256',
    'privateDraftEvidenceSha256',
    'exclusivePublisherEvidenceSha256'
  ]) exactSha256(promotion[name], code);
  return promotedAt;
}

function expectedPublishedStaticInventory(bundle) {
  return bundle.manifest.files
    .filter(item => item.path.startsWith('payload/dist/') &&
      !['payload/dist/_headers', 'payload/dist/_redirects'].includes(item.path))
    .map(item => ({
      path: `/${item.path.slice('payload/dist/'.length)}`,
      size: item.size,
      sha256: item.sha256
    }));
}

function assertSchedules(value, code) {
  if (!Array.isArray(value)) fail(code);
  const observed = new Map();
  for (const item of value) {
    assertExactKeys(item, ['name', 'cron'], code);
    if (observed.has(item.name)) fail(code);
    observed.set(item.name, item.cron);
  }
  if (observed.size !== Object.keys(REQUIRED_SCHEDULES).length ||
    Object.entries(REQUIRED_SCHEDULES).some(([name, cron]) => observed.get(name) !== cron)) fail(code);
}

function assertPostPromotion(postPromotion, promotionSha256, bundle, runtime,
  commit, tree, deployId, immutableOrigin, promotedAt, observedAt) {
  const code = 'CNYOS_CONTROLLER_SCHEDULED_ROUTE_POST_PROMOTION_INVALID';
  assertExactKeys(postPromotion, POST_PROMOTION_KEYS, code);
  assertControllerIdentity(postPromotion, runtime, code);
  assertBoundSource(postPromotion.source, bundle, commit, tree, code);
  assertBoundTarget(postPromotion.target, code);
  assertExactKeys(postPromotion.artifact, POST_PROMOTION_ARTIFACT_KEYS, code);
  assertSchedules(postPromotion.schedules, code);
  const verifiedAt = canonicalIsoTimestamp(postPromotion.verifiedAt, code);
  const staticInventory = expectedPublishedStaticInventory(bundle);
  if (postPromotion.schemaVersion !== 1 ||
    postPromotion.evidenceType !== 'cnyos_staging_controller_post_promotion_verification' ||
    postPromotion.status !== 'passed' || postPromotion.authorization !== false ||
    postPromotion.scope !== 'cnyos_staging_only' ||
    postPromotion.productionAuthorization !== false ||
    postPromotion.dispatchNonce !== bundle.manifest.dispatchNonce ||
    postPromotion.artifact.producerManifestSha256 !== bundle.manifestSha256 ||
    postPromotion.artifact.artifactSha256 !== bundle.manifest.artifactSha256 ||
    postPromotion.artifact.fileCount !== staticInventory.length ||
    postPromotion.artifact.closedWorldInventoryVerified !== true ||
    postPromotion.artifact.inventorySha256 !== sha256(JSON.stringify(staticInventory)) ||
    postPromotion.netlifyDeployId !== deployId ||
    postPromotion.exactDeployOrigin !== immutableOrigin ||
    postPromotion.currentPublishedDeployId !== deployId ||
    !Array.isArray(postPromotion.functionNames) ||
    JSON.stringify(postPromotion.functionNames) !== JSON.stringify(EXPECTED_FUNCTION_NAMES) ||
    postPromotion.functionByteAttestationAvailable !== false ||
    postPromotion.verificationPhase !== 'before_authenticated_uat' ||
    postPromotion.promotionEvidenceSha256 !== promotionSha256 ||
    verifiedAt < promotedAt || verifiedAt > observedAt) fail(code);
  return verifiedAt;
}

function responseHeader(response, name, code) {
  try { return String(response?.headers?.get?.(name) || '').trim(); }
  catch { fail(code); }
}

async function readBoundedResponseBody(response, maximum, code) {
  const declaredLength = responseHeader(response, 'content-length', code);
  if (declaredLength && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximum)) fail(code);
  if (!response.body) return Buffer.alloc(0);
  let reader;
  try { reader = response.body.getReader(); }
  catch { fail(code); }
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (!isPlainObject(next) || typeof next.done !== 'boolean') fail(code);
      if (next.done) break;
      if (!(next.value instanceof Uint8Array)) fail(code);
      length += next.value.byteLength;
      if (length > maximum) {
        await reader.cancel().catch(() => {});
        fail(code);
      }
      chunks.push(Buffer.from(next.value));
    }
  } catch (error) {
    if (error?.message === code) throw error;
    fail(code);
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks, length);
}

async function credentialFreeRequest(fetchImpl, url, init, maximum, code) {
  if (typeof fetchImpl !== 'function') fail(code);
  let response;
  try {
    response = await fetchImpl(url, Object.freeze({
      ...init,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLISECONDS)
    }));
  } catch {
    fail(`${code}_REQUEST_FAILED`);
  }
  if (!response || !Number.isInteger(response.status) ||
    response.redirected !== false || response.url !== url) fail(`${code}_RESPONSE_INVALID`);
  return Object.freeze({
    status: response.status,
    body: await readBoundedResponseBody(response, maximum, `${code}_RESPONSE_INVALID`)
  });
}

function assertDeployManifest(value, commit, tree, observedAt) {
  const code = 'CNYOS_CONTROLLER_SCHEDULED_ROUTE_DEPLOY_MANIFEST_INVALID';
  assertExactKeys(value, ['schemaVersion', 'deploymentId', 'source', 'tenant', 'identity', 'build', 'safety'], code);
  assertExactKeys(value.source, ['verified', 'commit', 'tree'], code);
  assertExactKeys(value.tenant, ['expectedClinicId', 'expectedClinicCode'], code);
  assertExactKeys(value.identity, ['qrIssuer'], code);
  assertExactKeys(value.build, ['context', 'deploymentClass', 'timestamp'], code);
  assertExactKeys(value.safety,
    ['previewLocked', 'databaseLocked', 'stagingDatabaseExplicitlyAcknowledged'], code);
  const buildTimestamp = recentCanonicalTimestamp(
    value.build.timestamp,
    observedAt,
    DEPLOY_MANIFEST_MAXIMUM_AGE_MILLISECONDS,
    code
  );
  if (value.schemaVersion !== 1 || value.deploymentId !== POLICY.target.deploymentId ||
    value.source.verified !== true || value.source.commit !== commit || value.source.tree !== tree ||
    value.tenant.expectedClinicId !== POLICY.target.clinicId ||
    value.tenant.expectedClinicCode !== POLICY.target.clinicCode ||
    value.identity.qrIssuer !== POLICY.target.qrIssuer ||
    value.build.context !== 'production' || value.build.deploymentClass !== 'dedicated-staging' ||
    value.safety.previewLocked !== false || value.safety.databaseLocked !== false ||
    value.safety.stagingDatabaseExplicitlyAcknowledged !== true) fail(code);
  return buildTimestamp;
}

async function localDeployManifest(bundle, commit, tree, observedAt) {
  const code = 'CNYOS_CONTROLLER_SCHEDULED_ROUTE_DEPLOY_MANIFEST_INVALID';
  const matches = bundle.manifest.files.filter(item =>
    item?.path === 'payload/dist/deploy-manifest.json');
  if (matches.length !== 1) fail(code);
  const entry = matches[0];
  if (!Number.isSafeInteger(entry.size) || entry.size < 1 || entry.size > MAXIMUM_MANIFEST_BYTES ||
    !/^[0-9a-f]{64}$/.test(String(entry.sha256 || ''))) fail(code);
  const bytes = await readFileBounded(
    path.join(bundle.bundleDirectory, entry.path),
    MAXIMUM_MANIFEST_BYTES,
    code
  );
  if (bytes.byteLength !== entry.size || sha256(bytes) !== entry.sha256) fail(code);
  const value = parseJsonObject(bytes.toString('utf8'), code);
  const buildTimestamp = assertDeployManifest(value, commit, tree, observedAt);
  return Object.freeze({ bytes, buildTimestamp, sha256: entry.sha256 });
}

async function observeRemoteDeployManifest(fetchImpl, originKind, origin, phase, expectedManifest) {
  const url = `${origin}/deploy-manifest.json`;
  const result = await credentialFreeRequest(
    fetchImpl,
    url,
    { method: 'GET', headers: Object.freeze({ Accept: 'application/json' }) },
    MAXIMUM_MANIFEST_BYTES,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_MANIFEST'
  );
  if (result.status !== 200 || !result.body.equals(expectedManifest.bytes)) {
    fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_MANIFEST_MISMATCH');
  }
  return Object.freeze({
    phase,
    originKind,
    origin,
    status: result.status,
    bodyByteLength: result.body.byteLength,
    bodySha256: sha256(result.body),
    expectedArtifactBytesMatched: true,
    redirectFollowed: false,
    credentialForwarded: false
  });
}

function responseIsApplicationShaped(body) {
  const text = body.toString('utf8');
  if (text.includes('BACKUP_SCHEDULED_INVOCATION_REQUIRED')) return true;
  let value;
  try { value = JSON.parse(text); }
  catch { return false; }
  return isPlainObject(value) || Array.isArray(value);
}

async function probeScheduledRoute(fetchImpl, originKind, origin, functionName, method) {
  const routePath = `/.netlify/functions/${functionName}`;
  const url = `${origin}${routePath}`;
  const isPost = method === 'POST';
  const result = await credentialFreeRequest(
    fetchImpl,
    url,
    {
      method,
      headers: Object.freeze(isPost ? {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      } : { Accept: 'application/json' }),
      ...(isPost ? { body: '{' } : {})
    },
    MAXIMUM_DENIAL_BODY_BYTES,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_PROBE'
  );
  const responseApplicationShaped = responseIsApplicationShaped(result.body);
  if (![403, 404].includes(result.status) || responseApplicationShaped) {
    fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_PUBLICLY_REACHABLE');
  }
  return Object.freeze({
    originKind,
    origin,
    functionName,
    method,
    path: routePath,
    requestBodyKind: isPost ? 'deliberately_malformed_json' : 'none',
    status: result.status,
    responseApplicationShaped: false,
    redirectFollowed: false,
    credentialForwarded: false
  });
}

export async function verifyScheduledFunctionRouteDenial({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date(),
  verifyProducerBundleImpl = verifyProducerBundle
} = {}) {
  assertCredentialIsolation(env);
  if (JSON.stringify(Object.keys(REQUIRED_SCHEDULES)) !==
      JSON.stringify(SCHEDULED_ROUTE_DENIAL_FUNCTIONS) ||
    SCHEDULED_ROUTE_DENIAL_FUNCTIONS.some(name => !EXPECTED_FUNCTION_NAMES.includes(name))) {
    fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_POLICY_INVALID');
  }
  const runtime = assertControllerRuntime(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_TIME_INVALID');
  }
  const commit = exactSha40(
    env.CNYOS_EXPECTED_SOURCE_COMMIT,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_SOURCE_COMMIT_INVALID'
  );
  const tree = exactSha40(
    env.CNYOS_EXPECTED_SOURCE_TREE,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_SOURCE_TREE_INVALID'
  );
  const deployId = exactDeployId(
    env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_DEPLOY_ID_INVALID'
  );
  const expectedManifestSha256 = exactSha256(
    env.CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_PRODUCER_DIGEST_INVALID'
  );
  const bundle = await verifyProducerBundleImpl({ env });
  if (!isPlainObject(bundle) || !isPlainObject(bundle.manifest) ||
    bundle.manifestSha256 !== expectedManifestSha256 ||
    bundle.manifest.controllerRepository !== runtime.repository ||
    bundle.manifest.controllerRef !== runtime.ref ||
    bundle.manifest.controllerCommit !== runtime.commit ||
    bundle.manifest.controllerRunId !== runtime.runId ||
    bundle.manifest.sourceRepository !== POLICY.sourceRepository ||
    bundle.manifest.candidateCommit !== commit || bundle.manifest.candidateTree !== tree) {
    fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_PRODUCER_INVALID');
  }
  const [preflight, promotion, postPromotion] = await Promise.all([
    loadEvidence(
      env,
      'CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH',
      'CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256',
      'CNYOS_CONTROLLER_SCHEDULED_ROUTE_PREFLIGHT_EVIDENCE'
    ),
    loadEvidence(
      env,
      'CNYOS_CONTROLLER_PROMOTION_EVIDENCE_PATH',
      'CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256',
      'CNYOS_CONTROLLER_SCHEDULED_ROUTE_PROMOTION_EVIDENCE'
    ),
    loadEvidence(
      env,
      'CNYOS_CONTROLLER_POST_PROMOTION_EVIDENCE_PATH',
      'CNYOS_EXPECTED_POST_PROMOTION_EVIDENCE_SHA256',
      'CNYOS_CONTROLLER_SCHEDULED_ROUTE_POST_PROMOTION_EVIDENCE'
    )
  ]);
  const preflightContext = assertPreflight(
    preflight.value,
    bundle,
    runtime,
    commit,
    tree,
    observedAt
  );
  const immutableOrigin = exactImmutableOrigin(deployId);
  const promotedAt = assertPromotion(
    promotion.value,
    preflight.value,
    preflight.sha256,
    bundle,
    runtime,
    commit,
    tree,
    deployId,
    immutableOrigin,
    preflightContext.capturedAt,
    observedAt
  );
  const postPromotionVerifiedAt = assertPostPromotion(
    postPromotion.value,
    promotion.sha256,
    bundle,
    runtime,
    commit,
    tree,
    deployId,
    immutableOrigin,
    promotedAt,
    observedAt
  );
  const deployManifest = await localDeployManifest(bundle, commit, tree, observedAt);
  const origins = Object.freeze([
    Object.freeze({ originKind: 'immutable', origin: immutableOrigin }),
    Object.freeze({ originKind: 'canonical', origin: POLICY.target.netlifyOrigin })
  ]);
  const manifestObservations = [];
  for (const item of origins) {
    manifestObservations.push(await observeRemoteDeployManifest(
      fetchImpl,
      item.originKind,
      item.origin,
      'before_route_probes',
      deployManifest
    ));
  }
  const probes = [];
  for (const item of origins) {
    for (const functionName of SCHEDULED_ROUTE_DENIAL_FUNCTIONS) {
      if (!Object.hasOwn(REQUIRED_SCHEDULES, functionName)) {
        fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_POLICY_INVALID');
      }
      for (const method of SCHEDULED_ROUTE_DENIAL_METHODS) {
        probes.push(await probeScheduledRoute(
          fetchImpl,
          item.originKind,
          item.origin,
          functionName,
          method
        ));
      }
    }
  }
  for (const item of origins) {
    manifestObservations.push(await observeRemoteDeployManifest(
      fetchImpl,
      item.originKind,
      item.origin,
      'after_route_probes',
      deployManifest
    ));
  }
  const verifiedAt = now();
  if (!(verifiedAt instanceof Date) || Number.isNaN(verifiedAt.getTime()) ||
    verifiedAt < observedAt || verifiedAt < postPromotionVerifiedAt ||
    verifiedAt >= preflightContext.expiresAt) {
    fail('CNYOS_CONTROLLER_SCHEDULED_ROUTE_TIME_INVALID');
  }
  recentCanonicalTimestamp(
    deployManifest.buildTimestamp.toISOString(),
    verifiedAt,
    DEPLOY_MANIFEST_MAXIMUM_AGE_MILLISECONDS,
    'CNYOS_CONTROLLER_SCHEDULED_ROUTE_DEPLOY_MANIFEST_INVALID'
  );
  const evidence = Object.freeze({
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_scheduled_function_route_denial',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    startedAt: observedAt.toISOString(),
    verifiedAt: verifiedAt.toISOString(),
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerRunId: runtime.runId,
    source: Object.freeze({ repository: POLICY.sourceRepository, commit, tree }),
    target: POLICY.target,
    netlifyDeployId: deployId,
    immutableOrigin,
    canonicalOrigin: POLICY.target.netlifyOrigin,
    deployManifestSha256: deployManifest.sha256,
    publisherExactCurrentEvidence: Object.freeze({
      beforeProbes: Object.freeze({
        promotionEvidenceSha256: promotion.sha256,
        postPromotionEvidenceSha256: postPromotion.sha256,
        currentPublishedDeployId: postPromotion.value.currentPublishedDeployId,
        verifiedAt: postPromotionVerifiedAt.toISOString()
      }),
      afterProbes: null
    }),
    manifestObservations: Object.freeze(manifestObservations),
    probes: Object.freeze(probes)
  });
  const evidencePath = await writeJsonExclusive(
    required(
      env.CNYOS_CONTROLLER_SCHEDULED_ROUTE_DENIAL_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_SCHEDULED_ROUTE_EVIDENCE_PATH_REQUIRED',
      4096
    ),
    evidence
  );
  return Object.freeze({ evidence, evidencePath });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  verifyScheduledFunctionRouteDenial().then(({ evidence }) => {
    process.stdout.write(`${JSON.stringify({
      status: evidence.status,
      netlifyDeployId: evidence.netlifyDeployId,
      probeCount: evidence.probes.length
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message ||
      'CNYOS_CONTROLLER_SCHEDULED_ROUTE_DENIAL_FAILED')}\n`);
    process.exitCode = 1;
  });
}
