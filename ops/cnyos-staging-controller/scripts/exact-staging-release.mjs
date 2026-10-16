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
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD'
]);
export const EXACT_STAGING_SYNTHETIC_HN_PATTERN = '^CHANANYASTG-[0-9]{8}$';
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
  totalMutations: 51,
  requestRetries: 0,
  requestTimeoutMs: 20_000,
  uatTimeoutMs: 25 * 60_000
});

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const DEPLOY_ID = /^[0-9a-f]{24}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RUN_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const REQUIRED_RUNTIME_FILES = Object.freeze([
  'index.html', 'login.html', 'auth-callback.html', 'owner-control.html',
  'clinical-v3.html', 'pharmacy.html', 'app.js', 'app.css', 'auth-config.js',
  'tenant-config.js', 'brand-config.js', 'deploy-manifest.json'
]);
export const EXACT_STAGING_DATABASE_FILES = Object.freeze([
  '20261013230000_staging_forward_reconciliation_ce4cee52.psql',
  '20261013230000_staging_forward_reconciliation_ce4cee52.sql',
  '20261013230000_staging_forward_reconciliation_manifest.json',
  '20261013230000_staging_forward_reconciliation_verify.sql',
  '20261017005000_audit_logs_governance_admin_read.sql'
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
  const controllerCommit = exact(env.CNYOS_EXPECTED_CONTROLLER_COMMIT, SHA40,
    'CNYOS_EXACT_STAGING_CONTROLLER_COMMIT_INVALID');
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
    controllerCommit,
    appCommit,
    appTree,
    rollbackDeployId,
    runReference,
    runId: `SYNTH-${sha256(runReference).slice(0, 24).toUpperCase()}`,
    artifactDirectory,
    distDirectory: path.join(artifactDirectory, 'dist'),
    functionsDirectory: path.join(artifactDirectory, 'functions'),
    functionManifestPath: path.join(artifactDirectory, 'function-input-manifest.json'),
    databaseDirectory: path.join(artifactDirectory, 'database'),
    databaseManifestPath: path.join(artifactDirectory, 'database-input-manifest.json'),
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
  const artifactStatus = await fs.lstat(config.artifactDirectory).catch(() => null);
  const distStatus = await fs.lstat(config.distDirectory).catch(() => null);
  const functionStatus = await fs.lstat(config.functionsDirectory).catch(() => null);
  const functionManifestStatus = await fs.lstat(config.functionManifestPath).catch(() => null);
  const databaseStatus = await fs.lstat(config.databaseDirectory).catch(() => null);
  const databaseManifestStatus = await fs.lstat(config.databaseManifestPath).catch(() => null);
  if (!artifactStatus?.isDirectory() || artifactStatus.isSymbolicLink() ||
    !distStatus?.isDirectory() || distStatus.isSymbolicLink() ||
    !functionStatus?.isDirectory() || functionStatus.isSymbolicLink() ||
    !databaseStatus?.isDirectory() || databaseStatus.isSymbolicLink()) {
    fail('CNYOS_EXACT_STAGING_ARTIFACT_DIRECTORY_INVALID');
  }
  if (!functionManifestStatus?.isFile() || functionManifestStatus.isSymbolicLink()) {
    fail('CNYOS_EXACT_STAGING_FUNCTION_MANIFEST_INVALID');
  }
  if (!databaseManifestStatus?.isFile() || databaseManifestStatus.isSymbolicLink()) {
    fail('CNYOS_EXACT_STAGING_DATABASE_MANIFEST_INVALID');
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
    functionManifest?.source?.resolvedRefObjectId !== config.appCommit ||
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
  const { value: databaseManifest, bytes: databaseManifestBytes } = await readJson(
    config.databaseManifestPath, 'CNYOS_EXACT_STAGING_DATABASE_MANIFEST_INVALID');
  const databaseFiles = await safeFiles(config.databaseDirectory);
  if (databaseManifest.schemaVersion !== 1 ||
    databaseManifest.artifactType !== 'cnyos-staging-database-inputs' ||
    databaseManifest?.source?.requestedRef !== config.appCommit ||
    databaseManifest?.source?.resolvedRefObjectId !== config.appCommit ||
    databaseManifest?.source?.sourceTreeObjectId !== config.appTree ||
    databaseManifest?.target?.projectRef !== EXACT_STAGING_TARGET.supabaseProjectRef ||
    databaseManifest?.target?.systemIdentifier !== '7666007964130682852' ||
    databaseManifest?.reconciliation?.legacyBundleSourceTree !==
      'ce4cee52f1ad7fed574cadf8a5e62e0f181d0d67' ||
    databaseManifest?.reconciliation?.finalAppTree !== config.appTree ||
    databaseManifest?.reconciliation?.generatorCheckRequired !== true ||
    databaseManifest?.reconciliation?.auditMigrationIncluded !== true ||
    databaseManifest?.safety?.stagingOnly !== true ||
    databaseManifest?.safety?.productionAuthorized !== false ||
    databaseManifest?.safety?.resetAllowed !== false ||
    databaseManifest?.safety?.containsPatientData !== false ||
    !Array.isArray(databaseManifest.files) ||
    databaseManifest.files.length !== EXACT_STAGING_DATABASE_FILES.length ||
    databaseManifest.fileCount !== databaseManifest.files.length ||
    !SHA256.test(String(databaseManifest.manifestSha256 || '')) ||
    canonicalJson(databaseFiles) !== canonicalJson([...EXACT_STAGING_DATABASE_FILES].sort()) ||
    canonicalJson(databaseManifest.files.map(item => item?.path)) !==
      canonicalJson([...EXACT_STAGING_DATABASE_FILES].sort())) {
    fail('CNYOS_EXACT_STAGING_DATABASE_MANIFEST_INVALID');
  }
  for (const item of databaseManifest.files) {
    if (!plainObject(item) || !Number.isSafeInteger(item.size) || item.size < 1 ||
      item.mode !== '100644' || !SHA256.test(String(item.sha256 || ''))) {
      fail('CNYOS_EXACT_STAGING_DATABASE_INTEGRITY_INVALID');
    }
    const content = await fs.readFile(path.join(config.databaseDirectory, item.path));
    if (content.length !== item.size || sha256(content) !== item.sha256) {
      fail('CNYOS_EXACT_STAGING_DATABASE_INTEGRITY_INVALID');
    }
  }
  if (sha256(Buffer.from(JSON.stringify(databaseManifest.files))) !==
      databaseManifest.manifestSha256) {
    fail('CNYOS_EXACT_STAGING_DATABASE_MANIFEST_DIGEST_INVALID');
  }
  const { value: reconciliationManifest } = await readJson(path.join(config.databaseDirectory,
    '20261013230000_staging_forward_reconciliation_manifest.json'),
  'CNYOS_EXACT_STAGING_DATABASE_RECONCILIATION_MANIFEST_INVALID');
  const databaseEntries = new Map(databaseManifest.files.map(item => [item.path, item]));
  if (reconciliationManifest.version !== '20261013230000' ||
    reconciliationManifest.stagingProjectRef !== EXACT_STAGING_TARGET.supabaseProjectRef ||
    reconciliationManifest.productionProjectRef !== 'qptxnrldzzinlcabudjv' ||
    reconciliationManifest.expectedSystemIdentifier !== '7666007964130682852' ||
    reconciliationManifest.historicalLedgerReplayed !== false ||
    reconciliationManifest.executeSqlExplicitTransactionRollbackProven !== true ||
    reconciliationManifest.artifact !==
      '20261013230000_staging_forward_reconciliation_ce4cee52.sql' ||
    reconciliationManifest.wrapper !==
      '20261013230000_staging_forward_reconciliation_ce4cee52.psql' ||
    reconciliationManifest.verifier !==
      '20261013230000_staging_forward_reconciliation_verify.sql' ||
    databaseEntries.get(reconciliationManifest.artifact)?.sha256 !==
      reconciliationManifest.artifactSha256 ||
    databaseEntries.get(reconciliationManifest.wrapper)?.sha256 !==
      reconciliationManifest.wrapperSha256 ||
    databaseEntries.get(reconciliationManifest.verifier)?.sha256 !==
      reconciliationManifest.verifierSha256) {
    fail('CNYOS_EXACT_STAGING_DATABASE_RECONCILIATION_MANIFEST_INVALID');
  }
  const observedArtifact = await safeFiles(config.artifactDirectory);
  const expectedArtifact = [
    ...observedDist.map(name => `dist/${name}`),
    ...functionFiles.map(name => `functions/${name}`),
    ...databaseFiles.map(name => `database/${name}`),
    'function-input-manifest.json', 'database-input-manifest.json'
  ].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  if (canonicalJson(observedArtifact) !== canonicalJson(expectedArtifact)) {
    fail('CNYOS_EXACT_STAGING_ARTIFACT_CLOSED_WORLD_INVALID');
  }
  const artifact = Object.freeze({
    source: Object.freeze({ commit: config.appCommit, tree: config.appTree }),
    deployManifestSha256: sha256(deployBytes),
    runtimeManifestSha256: sha256(runtimeBytes),
    functionManifestSha256: sha256(functionManifestBytes),
    functionTreeSha256: functionManifest.treeSha256,
    databaseManifestSha256: sha256(databaseManifestBytes),
    databaseTreeSha256: databaseManifest.manifestSha256,
    runtimeFileCount: runtimeManifest.fileCount,
    functionFileCount: functionManifest.fileCount,
    databaseFileCount: databaseManifest.fileCount
  });
  return Object.freeze({ artifact, deployManifest, runtimeManifest, functionManifest,
    databaseManifest, reconciliationManifest });
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

function normalizedIdentifierKey(key) {
  return String(key || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/^p_/, '');
}

function assertScopedIdentifier(value, expected, code) {
  if (typeof value !== 'string' || value.toLowerCase() !== expected) fail(code);
}

const SCOPED_IDENTIFIER_DOMAINS = Object.freeze([
  Object.freeze({ scope: 'encounter', aliases: Object.freeze(['encounter']) }),
  Object.freeze({ scope: 'patient', aliases: Object.freeze(['patient']) }),
  Object.freeze({
    scope: 'actor', aliases: Object.freeze(['actor', 'practitioner', 'user'])
  })
]);

function scopedIdentifierDomain(key, inheritedDomain = null) {
  const normalized = normalizedIdentifierKey(key);
  const tokens = normalized.split('_').filter(Boolean);
  if (normalized === 'created_by' || normalized === 'updated_by') return 'actor';
  if (inheritedDomain && ['id', 'uuid', 'identifier'].includes(normalized)) {
    return inheritedDomain;
  }
  for (const { scope, aliases } of SCOPED_IDENTIFIER_DOMAINS) {
    for (const alias of aliases) {
      if (tokens.includes(alias) && tokens.some(token => ['id', 'uuid', 'identifier'].includes(token))) {
        return scope;
      }
    }
  }
  return null;
}

function scopedContainerDomain(key) {
  const tokens = normalizedIdentifierKey(key).split('_').filter(Boolean);
  for (const { scope, aliases } of SCOPED_IDENTIFIER_DOMAINS) {
    if (aliases.some(alias => tokens.includes(alias))) return scope;
  }
  return null;
}

/**
 * Validate the exact browser mutation before Playwright can dispatch it.
 * The application currently sends only p_encounter_id and p_history. The
 * recursive identifier checks deliberately fail closed if a future candidate
 * adds patient or actor identifiers anywhere in the request body.
 */
export function assertScopedOpdWriteBody(postData, contentType, scope) {
  if (!plainObject(scope)) fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  const encounterId = exact(scope.encounterId, /^[0-9a-f-]{36}$/,
    'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  const patientId = exact(scope.patientId, /^[0-9a-f-]{36}$/,
    'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  const practitionerUserId = exact(scope.practitionerUserId, /^[0-9a-f-]{36}$/,
    'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  if (!UUID_PATTERN.test(encounterId) || !UUID_PATTERN.test(patientId) ||
    !UUID_PATTERN.test(practitionerUserId) ||
    !/^application\/json(?:\s*;|$)/i.test(String(contentType || '').trim())) {
    fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  }
  if (typeof postData !== 'string' || Buffer.byteLength(postData) < 2 ||
    Buffer.byteLength(postData) > 64 * 1024) {
    fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  }
  let body;
  try { body = JSON.parse(postData); }
  catch { fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID'); }
  if (!plainObject(body) || !plainObject(body.p_history) ||
    Object.keys(body).sort().join('\0') !== 'p_encounter_id\0p_history') {
    fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
  }
  assertScopedIdentifier(body.p_encounter_id, encounterId,
    'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');

  let visited = 0;
  const expectedByDomain = Object.freeze({
    encounter: encounterId, patient: patientId, actor: practitionerUserId
  });
  const visit = (value, depth = 0, inheritedDomain = null) => {
    if (depth > 8 || ++visited > 512) fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1, inheritedDomain);
      return;
    }
    if (!plainObject(value)) {
      if (typeof value === 'string' && UUID_PATTERN.test(value.toLowerCase())) {
        if (!inheritedDomain) fail('CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
        assertScopedIdentifier(value, expectedByDomain[inheritedDomain],
          'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
      }
      return;
    }
    for (const [key, nested] of Object.entries(value)) {
      const identifierDomain = scopedIdentifierDomain(key, inheritedDomain);
      if (identifierDomain) {
        assertScopedIdentifier(nested, expectedByDomain[identifierDomain],
          'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
      }
      const containerDomain = scopedContainerDomain(key) || inheritedDomain;
      if (!identifierDomain && scopedContainerDomain(key) && typeof nested === 'string' &&
        UUID_PATTERN.test(nested.toLowerCase())) {
        assertScopedIdentifier(nested, expectedByDomain[containerDomain],
          'CNYOS_EXACT_STAGING_OPD_WRITE_SCOPE_INVALID');
      }
      visit(nested, depth + 1, containerDomain);
    }
  };
  visit(body);
  return Object.freeze({
    encounterIdBound: true,
    patientIdentifiersBoundWhenPresent: true,
    actorIdentifiersBoundWhenPresent: true
  });
}

export function createScopedOpdWriteLedger(limit = EXACT_STAGING_LIMITS.browserOpdWrites) {
  if (!Number.isSafeInteger(limit) || limit !== EXACT_STAGING_LIMITS.browserOpdWrites) {
    fail('CNYOS_EXACT_STAGING_OPD_WRITE_LEDGER_INVALID');
  }
  const records = [];
  const reserve = contextOrdinal => {
    if (!Number.isSafeInteger(contextOrdinal) || contextOrdinal < 1 || contextOrdinal > 16) {
      fail('CNYOS_EXACT_STAGING_OPD_WRITE_LEDGER_INVALID');
    }
    if (records.length >= limit) fail('CNYOS_EXACT_STAGING_OPD_WRITE_BUDGET_EXCEEDED');
    const record = Object.freeze({
      ordinal: records.length + 1,
      contextOrdinal,
      rpc: 'save_ttm_opd_history',
      reservedBeforeFetch: true
    });
    records.push(record);
    return record;
  };
  const evidence = contextCount => {
    if (!Number.isSafeInteger(contextCount) || contextCount < 1 || contextCount > 16 ||
      records.some(record => record.contextOrdinal > contextCount)) {
      fail('CNYOS_EXACT_STAGING_OPD_WRITE_LEDGER_INVALID');
    }
    return Object.freeze({
      limit,
      dispatched: records.length,
      contextCount,
      perContext: Object.freeze(Array.from({ length: contextCount }, (_, index) => Object.freeze({
        contextOrdinal: index + 1,
        writes: records.filter(record => record.contextOrdinal === index + 1).length
      }))),
      records: Object.freeze([...records])
    });
  };
  return Object.freeze({ limit, reserve, count: () => records.length, evidence });
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
