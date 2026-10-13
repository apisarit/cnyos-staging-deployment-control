import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

export const EXACT_STAGING_TARGET = Object.freeze({
  netlifySiteId: '887e058b-6e13-461f-b3c7-ae096b7046fe',
  netlifySiteName: 'cnyos-clinical-staging',
  origin: 'https://cnyos-clinical-staging.netlify.app',
  deploymentId: 'chananya-clinical-staging',
  supabaseProjectRef: 'hsmnjwxurlmsizndjlun',
  supabaseOrigin: 'https://hsmnjwxurlmsizndjlun.supabase.co',
  clinicId: '00000000-0000-4000-8000-00000000a001',
  clinicCode: 'CHANANYA-STG',
  qrIssuer: 'CHANANYA-STG'
});

// Both known production identities are denied. The historical Netlify ID is
// retained because a stale controller policy used it before the dedicated
// staging site was established.
export const EXACT_STAGING_PRODUCTION_DENYLIST = Object.freeze({
  netlifySiteIds: Object.freeze([
    '7da5e39e-580d-44f1-8623-605313e2fb2b',
    'f1a31624-f90b-4d72-be3d-e91b7e2b2f38'
  ]),
  supabaseProjectRefs: Object.freeze(['qptxnrldzzinlcabudjv']),
  origins: Object.freeze(['https://cnyos.cloud', 'https://cnyos.netlify.app',
    'https://chananya.netlify.app'])
});

export const EXACT_STAGING_WORKFLOW_PATH =
  '.github/workflows/cnyos-exact-staging-deploy-uat.yml';
export const EXACT_STAGING_ENVIRONMENT = 'cnyos-staging-publish';
export const EXACT_STAGING_SECRET_NAMES = Object.freeze([
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY',
  'CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD'
]);
export const EXACT_STAGING_FUNCTION_ENVIRONMENT = Object.freeze({
  SUPABASE_URL: EXACT_STAGING_TARGET.supabaseOrigin,
  CNYOS_OWNER_EXPECTED_PROJECT_REF: EXACT_STAGING_TARGET.supabaseProjectRef,
  BACKUP_EXPECTED_SUPABASE_PROJECT_REF: EXACT_STAGING_TARGET.supabaseProjectRef,
  CNYOS_RUNTIME_EXPECTED_CLINIC_ID: EXACT_STAGING_TARGET.clinicId,
  CNYOS_ACCOUNT_CLINIC_ID: EXACT_STAGING_TARGET.clinicId,
  CNYOS_ACCOUNT_CLINIC_CODE: EXACT_STAGING_TARGET.clinicCode,
  CNYOS_OWNER_CLINIC_CODES: EXACT_STAGING_TARGET.clinicCode,
  PATIENT_QR_ISSUER: EXACT_STAGING_TARGET.qrIssuer,
  CNYOS_OWNER_EXPECTED_NETLIFY_SITE_ID: EXACT_STAGING_TARGET.netlifySiteId,
  BACKUP_EXPECTED_NETLIFY_SITE_ID: EXACT_STAGING_TARGET.netlifySiteId,
  CNYOS_OWNER_EXPECTED_SITE_ORIGIN: EXACT_STAGING_TARGET.origin,
  BACKUP_EXPECTED_SITE_ORIGIN: EXACT_STAGING_TARGET.origin,
  BACKUP_ENVIRONMENT: 'staging',
  BACKUP_DEPLOYMENT_ID: EXACT_STAGING_TARGET.deploymentId
});
export const EXACT_STAGING_LIMITS = Object.freeze({
  authUsers: 7,
  syntheticCases: 1,
  browserOpdWrites: 2,
  totalMutations: 48,
  requestRetries: 0,
  requestTimeoutMs: 20_000,
  uatTimeoutMs: 25 * 60_000
});

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const DEPLOY_ID = /^[0-9a-f]{24}$/;
const RUN_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const REQUIRED_RUNTIME_FILES = Object.freeze([
  'index.html', 'login.html', 'auth-callback.html', 'owner-control.html',
  'clinical-v3.html', 'pharmacy.html', 'app.js', 'app.css', 'auth-config.js',
  'tenant-config.js', 'brand-config.js', 'deploy-manifest.json'
]);

export class ExactStagingReleaseError extends Error {
  constructor(code, { uncertain = false } = {}) {
    super(code);
    this.name = 'ExactStagingReleaseError';
    this.code = code;
    this.uncertain = uncertain;
  }
}

function fail(code, options) {
  throw new ExactStagingReleaseError(code, options);
}

function required(value, code, maximum = 4096) {
  const normalized = String(value ?? '').trim();
  if (!normalized || normalized.length > maximum) fail(code);
  return normalized;
}

function exact(value, pattern, code) {
  const normalized = required(value, code).toLowerCase();
  if (!pattern.test(normalized)) fail(code);
  return normalized;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (plainObject(value)) {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function loadExactStagingConfig(env = process.env) {
  const appCommit = exact(env.CNYOS_EXPECTED_SOURCE_COMMIT, SHA40,
    'CNYOS_EXACT_STAGING_SOURCE_COMMIT_INVALID');
  const appTree = exact(env.CNYOS_EXPECTED_SOURCE_TREE, SHA40,
    'CNYOS_EXACT_STAGING_SOURCE_TREE_INVALID');
  const rollbackDeployId = exact(env.CNYOS_EXPECTED_ROLLBACK_DEPLOY_ID, DEPLOY_ID,
    'CNYOS_EXACT_STAGING_ROLLBACK_DEPLOY_ID_INVALID');
  const runReference = required(env.CNYOS_STAGING_RUN_REFERENCE,
    'CNYOS_EXACT_STAGING_RUN_REFERENCE_INVALID', 96);
  if (!RUN_REFERENCE.test(runReference)) fail('CNYOS_EXACT_STAGING_RUN_REFERENCE_INVALID');
  const artifactDirectory = path.resolve(required(env.CNYOS_STAGING_ARTIFACT_DIRECTORY,
    'CNYOS_EXACT_STAGING_ARTIFACT_DIRECTORY_REQUIRED'));
  const workDirectory = path.resolve(required(env.CNYOS_EXACT_STAGING_WORK_DIRECTORY,
    'CNYOS_EXACT_STAGING_WORK_DIRECTORY_REQUIRED'));
  if (!path.isAbsolute(env.CNYOS_STAGING_ARTIFACT_DIRECTORY) ||
    !path.isAbsolute(env.CNYOS_EXACT_STAGING_WORK_DIRECTORY) ||
    artifactDirectory === path.parse(artifactDirectory).root ||
    workDirectory === path.parse(workDirectory).root) {
    fail('CNYOS_EXACT_STAGING_DIRECTORY_INVALID');
  }
  return Object.freeze({
    appCommit,
    appTree,
    rollbackDeployId,
    runReference,
    runId: `SYNTH-${sha256(runReference).slice(0, 24).toUpperCase()}`,
    artifactDirectory,
    distDirectory: path.join(artifactDirectory, 'dist'),
    functionsDirectory: path.join(artifactDirectory, 'functions'),
    functionManifestPath: path.join(artifactDirectory, 'function-input-manifest.json'),
    workDirectory,
    uploadDirectory: path.join(workDirectory, 'upload'),
    privateDirectory: path.join(workDirectory, 'private'),
    target: EXACT_STAGING_TARGET,
    limits: EXACT_STAGING_LIMITS
  });
}

async function safeFiles(directory, prefix = '') {
  const result = [];
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (!relative || relative.startsWith('/') || relative.includes('..') ||
      relative.includes('\\') || /[\u0000-\u001f\u007f]/u.test(relative)) {
      fail('CNYOS_EXACT_STAGING_ARTIFACT_PATH_INVALID');
    }
    const absolute = path.join(directory, entry.name);
    const stat = await fs.lstat(absolute);
    if (stat.isSymbolicLink()) fail('CNYOS_EXACT_STAGING_ARTIFACT_SYMLINK_FORBIDDEN');
    if (stat.isDirectory()) result.push(...await safeFiles(absolute, relative));
    else if (stat.isFile()) result.push(relative);
    else fail('CNYOS_EXACT_STAGING_ARTIFACT_ENTRY_INVALID');
  }
  return result.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

async function readJson(filename, code) {
  let bytes;
  try { bytes = await fs.readFile(filename); }
  catch { fail(code); }
  if (bytes.length < 2 || bytes.length > 4 * 1024 * 1024) fail(code);
  try {
    const value = JSON.parse(bytes.toString('utf8'));
    if (!plainObject(value)) fail(code);
    return { value, bytes };
  } catch { fail(code); }
}

function assertStagingDeployManifest(manifest, config) {
  if (manifest.schemaVersion !== 1 || manifest.deploymentId !== EXACT_STAGING_TARGET.deploymentId ||
    manifest?.source?.commit !== config.appCommit || manifest?.source?.tree !== config.appTree ||
    manifest?.source?.verified !== true || manifest?.build?.context !== 'production' ||
    manifest?.build?.deploymentClass !== 'dedicated-staging' ||
    manifest?.safety?.previewLocked !== false || manifest?.safety?.databaseLocked !== false ||
    manifest?.safety?.stagingDatabaseExplicitlyAcknowledged !== true ||
    manifest?.tenant?.expectedClinicId !== EXACT_STAGING_TARGET.clinicId ||
    manifest?.tenant?.expectedClinicCode !== EXACT_STAGING_TARGET.clinicCode ||
    manifest?.identity?.qrIssuer !== EXACT_STAGING_TARGET.qrIssuer) {
    fail('CNYOS_EXACT_STAGING_DEPLOY_MANIFEST_INVALID');
  }
}

export async function verifyExactStagingArtifact(config) {
  const distStatus = await fs.lstat(config.distDirectory).catch(() => null);
  const functionStatus = await fs.lstat(config.functionsDirectory).catch(() => null);
  if (!distStatus?.isDirectory() || distStatus.isSymbolicLink() ||
    !functionStatus?.isDirectory() || functionStatus.isSymbolicLink()) {
    fail('CNYOS_EXACT_STAGING_ARTIFACT_DIRECTORY_INVALID');
  }
  const { value: deployManifest, bytes: deployBytes } = await readJson(
    path.join(config.distDirectory, 'deploy-manifest.json'),
    'CNYOS_EXACT_STAGING_DEPLOY_MANIFEST_INVALID');
  assertStagingDeployManifest(deployManifest, config);
  const { value: runtimeManifest, bytes: runtimeBytes } = await readJson(
    path.join(config.distDirectory, 'runtime-publish-manifest.json'),
    'CNYOS_EXACT_STAGING_RUNTIME_MANIFEST_INVALID');
  if (runtimeManifest.schemaVersion !== 2 || runtimeManifest.integrityAlgorithm !== 'sha256' ||
    !Array.isArray(runtimeManifest.files) || !Array.isArray(runtimeManifest.integrity) ||
    runtimeManifest.fileCount !== runtimeManifest.files.length ||
    runtimeManifest.integrity.length !== runtimeManifest.files.length ||
    new Set(runtimeManifest.files).size !== runtimeManifest.files.length ||
    REQUIRED_RUNTIME_FILES.some(name => !runtimeManifest.files.includes(name))) {
    fail('CNYOS_EXACT_STAGING_RUNTIME_MANIFEST_INVALID');
  }
  const observedDist = await safeFiles(config.distDirectory);
  const expectedDist = [...runtimeManifest.files, 'runtime-publish-manifest.json'].sort();
  if (canonicalJson(observedDist) !== canonicalJson(expectedDist)) {
    fail('CNYOS_EXACT_STAGING_RUNTIME_CLOSED_WORLD_INVALID');
  }
  for (let index = 0; index < runtimeManifest.files.length; index += 1) {
    const filename = runtimeManifest.files[index];
    const integrity = runtimeManifest.integrity[index];
    if (!plainObject(integrity) || integrity.path !== filename ||
      !Number.isSafeInteger(integrity.size) || !SHA256.test(String(integrity.sha256 || ''))) {
      fail('CNYOS_EXACT_STAGING_RUNTIME_INTEGRITY_INVALID');
    }
    const content = await fs.readFile(path.join(config.distDirectory, filename));
    if (content.length !== integrity.size || sha256(content) !== integrity.sha256) {
      fail('CNYOS_EXACT_STAGING_RUNTIME_INTEGRITY_INVALID');
    }
  }
  const { value: functionManifest, bytes: functionManifestBytes } = await readJson(
    config.functionManifestPath, 'CNYOS_EXACT_STAGING_FUNCTION_MANIFEST_INVALID');
  const functionFiles = await safeFiles(config.functionsDirectory);
  if (functionManifest.schemaVersion !== 1 ||
    functionManifest.artifactType !== 'cnyos-staging-function-inputs' ||
    !SHA40.test(String(functionManifest?.source?.sourceTreeObjectId || '')) ||
    !Array.isArray(functionManifest.files) || functionManifest.files.length !== functionFiles.length ||
    functionManifest.fileCount !== functionFiles.length ||
    functionManifest?.source?.requestedRef !== config.appCommit ||
    !SHA256.test(String(functionManifest.manifestSha256 || '')) ||
    !SHA256.test(String(functionManifest.treeSha256 || ''))) {
    fail('CNYOS_EXACT_STAGING_FUNCTION_MANIFEST_INVALID');
  }
  const declaredFunctionFiles = functionManifest.files.map(item => item?.path);
  if (canonicalJson(declaredFunctionFiles) !== canonicalJson(functionFiles)) {
    fail('CNYOS_EXACT_STAGING_FUNCTION_CLOSED_WORLD_INVALID');
  }
  for (const item of functionManifest.files) {
    if (!plainObject(item) || !Number.isSafeInteger(item.size) ||
      !SHA256.test(String(item.sha256 || '')) || !['100644', '100755'].includes(item.mode)) {
      fail('CNYOS_EXACT_STAGING_FUNCTION_INTEGRITY_INVALID');
    }
    const content = await fs.readFile(path.join(config.functionsDirectory, item.path));
    if (content.length !== item.size || sha256(content) !== item.sha256) {
      fail('CNYOS_EXACT_STAGING_FUNCTION_INTEGRITY_INVALID');
    }
  }
  if (sha256(Buffer.from(JSON.stringify(functionManifest.files))) !==
      functionManifest.manifestSha256) {
    fail('CNYOS_EXACT_STAGING_FUNCTION_MANIFEST_DIGEST_INVALID');
  }
  const artifact = Object.freeze({
    source: Object.freeze({ commit: config.appCommit, tree: config.appTree }),
    deployManifestSha256: sha256(deployBytes),
    runtimeManifestSha256: sha256(runtimeBytes),
    functionManifestSha256: sha256(functionManifestBytes),
    functionTreeSha256: functionManifest.treeSha256,
    runtimeFileCount: runtimeManifest.fileCount,
    functionFileCount: functionManifest.fileCount
  });
  return Object.freeze({ artifact, deployManifest, runtimeManifest, functionManifest });
}

async function responseJson(response, code, maximum = 2 * 1024 * 1024) {
  let bytes;
  try { bytes = Buffer.from(await response.arrayBuffer()); }
  catch { fail(code); }
  if (bytes.length < 2 || bytes.length > maximum) fail(code);
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { fail(code); }
}

export async function captureRollbackBaseline(config, netlifyToken, fetchImpl = fetch) {
  required(netlifyToken, 'CNYOS_EXACT_STAGING_NETLIFY_TOKEN_REQUIRED', 8192);
  let response;
  try {
    response = await fetchImpl(
      `https://api.netlify.com/api/v1/sites/${EXACT_STAGING_TARGET.netlifySiteId}`,
      {
        headers: { Accept: 'application/json', Authorization: `Bearer ${netlifyToken}` },
        redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20_000)
      });
  } catch { fail('CNYOS_EXACT_STAGING_BASELINE_REQUEST_FAILED'); }
  if (response.status !== 200) fail('CNYOS_EXACT_STAGING_BASELINE_STATUS_INVALID');
  const site = await responseJson(response, 'CNYOS_EXACT_STAGING_BASELINE_RESPONSE_INVALID');
  const published = site?.published_deploy;
  if (String(site?.id || '').toLowerCase() !== EXACT_STAGING_TARGET.netlifySiteId ||
    site?.name !== EXACT_STAGING_TARGET.netlifySiteName ||
    site?.ssl_url !== EXACT_STAGING_TARGET.origin ||
    !plainObject(published) || String(published.id || '').toLowerCase() !== config.rollbackDeployId) {
    fail('CNYOS_EXACT_STAGING_BASELINE_IDENTITY_MISMATCH');
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_rollback_baseline',
    stagingOnly: true,
    siteId: EXACT_STAGING_TARGET.netlifySiteId,
    origin: EXACT_STAGING_TARGET.origin,
    deployId: config.rollbackDeployId,
    exactDeployOrigin:
      `https://${config.rollbackDeployId}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`,
    observedAt: new Date().toISOString()
  });
}

export function verifyExactStagingFunctionEnvironment(config, netlifyToken, {
  cliPath,
  env = process.env,
  execFileImpl = execFileSync
} = {}) {
  const token = required(netlifyToken, 'CNYOS_EXACT_STAGING_NETLIFY_TOKEN_REQUIRED', 8192);
  const executable = required(cliPath, 'CNYOS_EXACT_STAGING_NETLIFY_CLI_REQUIRED');
  if (config.target.netlifySiteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    config.target.supabaseProjectRef !== EXACT_STAGING_TARGET.supabaseProjectRef ||
    EXACT_STAGING_PRODUCTION_DENYLIST.netlifySiteIds.includes(config.target.netlifySiteId) ||
    EXACT_STAGING_PRODUCTION_DENYLIST.supabaseProjectRefs.includes(
      config.target.supabaseProjectRef)) {
    fail('CNYOS_EXACT_STAGING_FUNCTION_ENV_TARGET_INVALID');
  }
  const childEnvironment = {
    CI: 'true',
    NETLIFY_AUTH_TOKEN: token,
    NETLIFY_SITE_ID: EXACT_STAGING_TARGET.netlifySiteId,
    PATH: required(env.PATH, 'CNYOS_EXACT_STAGING_PATH_REQUIRED'),
    HOME: required(env.HOME, 'CNYOS_EXACT_STAGING_HOME_REQUIRED'),
    XDG_CONFIG_HOME: required(env.XDG_CONFIG_HOME,
      'CNYOS_EXACT_STAGING_XDG_CONFIG_REQUIRED'),
    XDG_CACHE_HOME: required(env.XDG_CACHE_HOME,
      'CNYOS_EXACT_STAGING_XDG_CACHE_REQUIRED')
  };
  const observed = [];
  for (const [name, expected] of Object.entries(EXACT_STAGING_FUNCTION_ENVIRONMENT)
    .sort(([left], [right]) => left.localeCompare(right))) {
    let value;
    try {
      value = String(execFileImpl(executable, [
        'env:get', name,
        `--site=${EXACT_STAGING_TARGET.netlifySiteId}`,
        '--context=production', '--scope=functions'
      ], {
        encoding: 'utf8', maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 30_000, windowsHide: true, env: childEnvironment
      })).replace(/\r?\n$/, '');
    } catch {
      fail('CNYOS_EXACT_STAGING_FUNCTION_ENV_READ_FAILED');
    }
    if (value !== expected) fail('CNYOS_EXACT_STAGING_FUNCTION_ENV_TARGET_MISMATCH');
    observed.push([name, value]);
  }
  return Object.freeze({
    validatedVariableNames: Object.freeze(observed.map(([name]) => name)),
    exactValuesSha256: sha256(JSON.stringify(observed)),
    productionDenylistConfirmed: true,
    valuesSerialized: false
  });
}

export function parseNetlifyDeployReceipt(value, config) {
  if (!plainObject(value)) fail('CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID');
  const deployId = exact(value.deploy_id || value.deployId || value.id, DEPLOY_ID,
    'CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID');
  const siteId = String(value.site_id || value.siteId || EXACT_STAGING_TARGET.netlifySiteId)
    .trim().toLowerCase();
  const url = String(value.url || value.deploy_url || value.deployUrl || '').trim();
  const expectedExactOrigin =
    `https://${deployId}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`;
  if (siteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    EXACT_STAGING_PRODUCTION_DENYLIST.netlifySiteIds.includes(siteId) ||
    (url && url !== expectedExactOrigin && url !== EXACT_STAGING_TARGET.origin) ||
    deployId === config.rollbackDeployId) {
    fail('CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID');
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_deploy_receipt',
    stagingOnly: true,
    siteId,
    deployId,
    canonicalOrigin: EXACT_STAGING_TARGET.origin,
    exactDeployOrigin: expectedExactOrigin,
    source: Object.freeze({ commit: config.appCommit, tree: config.appTree })
  });
}

export function assertSecretFreeEvidence(value, secretValues = []) {
  const serialized = Buffer.from(JSON.stringify(value));
  for (const secret of secretValues.filter(Boolean)) {
    const token = Buffer.from(String(secret));
    if (token.length && serialized.includes(token)) {
      fail('CNYOS_EXACT_STAGING_SECRET_SERIALIZATION_BLOCKED');
    }
  }
  return serialized;
}

export async function writeFresh0600(filename, value, secretValues = []) {
  await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  const bytes = assertSecretFreeEvidence(value, secretValues);
  await fs.writeFile(filename, Buffer.concat([bytes, Buffer.from('\n')]), {
    flag: 'wx', mode: 0o600
  });
  return sha256(bytes);
}
