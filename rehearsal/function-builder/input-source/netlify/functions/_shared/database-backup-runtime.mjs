import {
  createHmac,
  randomUUID as randomUuid,
  timingSafeEqual
} from 'node:crypto';
import {
  BACKUP_DOMAINS,
  BACKUP_REQUIRED_TABLES,
  BACKUP_SCHEMA_VERSION,
  backupFileName,
  countDomainRows,
  encryptBackup,
  fetchGoogleAccessToken,
  parseBackupEnvironment,
  parseEncryptionKey,
  supabaseRpc,
  upsertDriveFile
} from './database-backup.mjs';
import {
  googleServiceAccountWrapKeyReused,
  resolveGoogleServiceAccountCredential
} from './google-service-account-credential.mjs';
import { inspectDriveFolder } from './owner-drive.mjs';

const responseHeaders = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff'
});

const DRIVE_FOLDER_FIELDS = Object.freeze({
  patients: 'patients_folder_id',
  products: 'products_folder_id',
  pharmacy: 'pharmacy_folder_id',
  transactions: 'transactions_folder_id',
  manifests: 'manifests_folder_id'
});

const DRIVE_FOLDER_ID_PATTERN = /^[A-Za-z0-9_-]{10,200}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLINIC_CODE_PATTERN = /^[A-Z][A-Z0-9_-]{1,23}$/;
const OPAQUE_RUNTIME_ID_PATTERN = /^[A-Za-z0-9_-]{6,200}$/;
const SOURCE_COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const DEPLOYMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/;
const DISPATCH_SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;

export const BACKUP_BACKGROUND_FUNCTION_PATH = '/.netlify/functions/database-backup-background';
export const BACKUP_DISPATCH_VERSION = 1;
export const BACKUP_DISPATCH_MAX_AGE_MS = 30 * 60 * 1000;
export const BACKUP_DISPATCH_MAX_FUTURE_SKEW_MS = 60 * 1000;
export const BACKUP_DISPATCH_MAX_BODY_BYTES = 4096;
export const BACKUP_MAX_CLINICS_HARD_LIMIT = 25;
export const BACKUP_WORKER_BUDGET_MS = 14 * 60 * 1000;
export const BACKUP_FINALIZATION_RESERVE_MS = 90 * 1000;
export const BACKUP_RECOVERY_MIN_AGE_MS = 30 * 60 * 1000;
export const BACKUP_RECOVERY_MAX_AGE_MS = 6 * 60 * 60 * 1000;
export const BACKUP_SCHEDULED_EVENT_MAX_BODY_BYTES = 256;

const SCHEDULER_RPC_TIMEOUT_MS = 6000;
const DISPATCH_TIMEOUT_MS = 5000;
const WORKER_REQUEST_TIMEOUT_MS = 120000;
const FINALIZATION_TIMEOUT_MS = 60000;
const DISPATCH_CONCURRENCY = 10;

function defaultEnvGet(name) {
  return globalThis.Netlify?.env?.get(name) || '';
}

function envValue(getEnv, name) {
  return String(getEnv(name) || '').trim();
}

export function backupEnabled(getEnv = defaultEnvGet) {
  return envValue(getEnv, 'BACKUP_ENABLED') === 'true';
}

export function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: responseHeaders });
}

export function errorCode(error, fallback = 'BACKUP_OPERATION_FAILED') {
  const candidate = String(error?.message || '').toUpperCase();
  return /^[A-Z][A-Z0-9_]{2,79}$/.test(candidate) ? candidate : fallback;
}

// Netlify guarantees that a deployed Scheduled Function has no directly
// invocable URL. This shape check is defense-in-depth for platform-delivered
// schedule events and Netlify UI "Run now" events; it is not the caller-auth
// boundary. A post-deploy route-denial check remains mandatory before enable.
export async function assertScheduledInvocation(request) {
  if (request?.method !== 'POST') throw new Error('BACKUP_SCHEDULED_INVOCATION_REQUIRED');
  const declaredLength = String(request.headers?.get?.('content-length') || '');
  if (declaredLength
    && (!/^[0-9]+$/.test(declaredLength)
      || Number(declaredLength) > BACKUP_SCHEDULED_EVENT_MAX_BODY_BYTES)) {
    throw new Error('BACKUP_SCHEDULED_INVOCATION_REQUIRED');
  }
  const rawBody = await request.text();
  if (Buffer.byteLength(rawBody, 'utf8') > BACKUP_SCHEDULED_EVENT_MAX_BODY_BYTES) {
    throw new Error('BACKUP_SCHEDULED_INVOCATION_REQUIRED');
  }
  let event;
  try { event = JSON.parse(rawBody); }
  catch { throw new Error('BACKUP_SCHEDULED_INVOCATION_REQUIRED'); }
  if (!event
    || typeof event !== 'object'
    || Array.isArray(event)
    || JSON.stringify(Object.keys(event).sort()) !== JSON.stringify(['next_run'])
    || typeof event.next_run !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.000)?Z$/.test(event.next_run)
    || !Number.isFinite(Date.parse(event.next_run))) {
    throw new Error('BACKUP_SCHEDULED_INVOCATION_REQUIRED');
  }
  return Object.freeze({ nextRun: new Date(event.next_run).toISOString() });
}

function parseMaximumClinics(value) {
  const raw = String(value || '').trim();
  if (!raw) return 10;
  if (!/^[1-9][0-9]*$/.test(raw)) throw new Error('BACKUP_MAX_CLINICS_INVALID');
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed > BACKUP_MAX_CLINICS_HARD_LIMIT) {
    throw new Error('BACKUP_MAX_CLINICS_INVALID');
  }
  return parsed;
}

function assertExpectedSupabaseProject(url, expectedProjectRef) {
  const expected = String(expectedProjectRef || '').trim().toLowerCase();
  if (!/^[a-z]{20}$/.test(expected)) {
    throw new Error('BACKUP_EXPECTED_SUPABASE_PROJECT_REF_INVALID');
  }
  let parsed;
  try { parsed = new URL(url); }
  catch { throw new Error('BACKUP_SUPABASE_URL_INVALID'); }
  const actual = parsed.hostname.match(/^([a-z]{20})\.supabase\.co$/)?.[1] || '';
  if (parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.port
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
    || actual !== expected) {
    throw new Error('BACKUP_SUPABASE_PROJECT_MISMATCH');
  }
  return actual;
}

function parseProductionSupabaseOrigin(value) {
  if (!value) return '';
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error('BACKUP_PRODUCTION_SUPABASE_URL_INVALID'); }
  if (parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.port
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
    || !/^[a-z]{20}\.supabase\.co$/.test(parsed.hostname)) {
    throw new Error('BACKUP_PRODUCTION_SUPABASE_URL_INVALID');
  }
  return parsed.origin;
}

function parseExpectedSiteOrigin(value) {
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error('BACKUP_EXPECTED_SITE_ORIGIN_INVALID'); }
  if (parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.port
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(parsed.hostname)) {
    throw new Error('BACKUP_EXPECTED_SITE_ORIGIN_INVALID');
  }
  return parsed.origin;
}

function folderIdsComplete(folderIds) {
  return Object.keys(DRIVE_FOLDER_FIELDS).every(domain => String(folderIds?.[domain] || '').trim());
}

function assertUniqueFolderIds(folderIds) {
  if (Object.values(folderIds).some(value => !DRIVE_FOLDER_ID_PATTERN.test(String(value || '')))) {
    throw new Error('BACKUP_DRIVE_FOLDER_ID_INVALID');
  }
  if (new Set(Object.values(folderIds)).size !== Object.keys(DRIVE_FOLDER_FIELDS).length) {
    throw new Error('BACKUP_DRIVE_FOLDER_IDS_MUST_BE_UNIQUE');
  }
}

export function configuration(getEnv = defaultEnvGet) {
  const environment = parseBackupEnvironment(envValue(getEnv, 'BACKUP_ENVIRONMENT'));
  const deploymentId = envValue(getEnv, 'BACKUP_DEPLOYMENT_ID') || envValue(getEnv, 'SITE_NAME');
  const sourceRevision = (
    envValue(getEnv, 'CLINICAL_OS_SOURCE_COMMIT')
      || envValue(getEnv, 'COMMIT_REF')
      || envValue(getEnv, 'DEPLOY_ID')
  ).toLowerCase();
  const config = {
    environment,
    deploymentId,
    sourceRevision,
    supabaseUrl: envValue(getEnv, 'SUPABASE_URL'),
    expectedSupabaseProjectRef: envValue(getEnv, 'BACKUP_EXPECTED_SUPABASE_PROJECT_REF').toLowerCase(),
    productionSupabaseUrl: envValue(getEnv, 'BACKUP_PRODUCTION_SUPABASE_URL'),
    serviceRoleKey: envValue(getEnv, 'SUPABASE_SERVICE_ROLE_KEY'),
    serviceAccountDirectValue: envValue(getEnv, 'GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON'),
    serviceAccountWrapKeyId: envValue(getEnv, 'GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_ID'),
    serviceAccountWrapKeyValue: envValue(getEnv, 'GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_BASE64'),
    expectedServiceAccountEmail: envValue(getEnv, 'GOOGLE_DRIVE_EXPECTED_SERVICE_ACCOUNT_EMAIL').toLowerCase(),
    allowRestoreTestDirectJson: envValue(getEnv, 'GOOGLE_DRIVE_SERVICE_ACCOUNT_ALLOW_RESTORE_TEST_DIRECT_JSON') === 'true',
    encryptionKeyValue: envValue(getEnv, 'BACKUP_ENCRYPTION_KEY_BASE64'),
    dispatchSecret: envValue(getEnv, 'BACKUP_INTERNAL_DISPATCH_SECRET'),
    expectedNetlifySiteId: envValue(getEnv, 'BACKUP_EXPECTED_NETLIFY_SITE_ID').toLowerCase(),
    expectedSiteOrigin: envValue(getEnv, 'BACKUP_EXPECTED_SITE_ORIGIN').toLowerCase(),
    expectedDriveRootFolderId: envValue(getEnv, 'GOOGLE_DRIVE_EXPECTED_ROOT_FOLDER_ID'),
    maxClinics: parseMaximumClinics(envValue(getEnv, 'BACKUP_MAX_CLINICS_PER_RUN')),
    folderIds: Object.freeze({
      patients: envValue(getEnv, 'GOOGLE_DRIVE_PATIENTS_FOLDER_ID'),
      products: envValue(getEnv, 'GOOGLE_DRIVE_PRODUCTS_FOLDER_ID'),
      pharmacy: envValue(getEnv, 'GOOGLE_DRIVE_PHARMACY_FOLDER_ID'),
      transactions: envValue(getEnv, 'GOOGLE_DRIVE_TRANSACTIONS_FOLDER_ID'),
      manifests: envValue(getEnv, 'GOOGLE_DRIVE_MANIFESTS_FOLDER_ID')
    })
  };
  const missing = [];
  if (!config.supabaseUrl) missing.push('SUPABASE_URL');
  if (!config.expectedSupabaseProjectRef) missing.push('BACKUP_EXPECTED_SUPABASE_PROJECT_REF');
  if (!config.deploymentId) missing.push('BACKUP_DEPLOYMENT_ID or SITE_NAME');
  if (!config.sourceRevision) missing.push('CLINICAL_OS_SOURCE_COMMIT or COMMIT_REF');
  if (!config.serviceRoleKey) missing.push('SUPABASE_SERVICE_ROLE_KEY');
  if (!config.encryptionKeyValue) missing.push('BACKUP_ENCRYPTION_KEY_BASE64');
  if (!config.dispatchSecret) missing.push('BACKUP_INTERNAL_DISPATCH_SECRET');
  if (!config.expectedNetlifySiteId) missing.push('BACKUP_EXPECTED_NETLIFY_SITE_ID');
  if (!config.expectedSiteOrigin) missing.push('BACKUP_EXPECTED_SITE_ORIGIN');
  if (!config.expectedDriveRootFolderId) missing.push('GOOGLE_DRIVE_EXPECTED_ROOT_FOLDER_ID');
  if (!config.expectedServiceAccountEmail) missing.push('GOOGLE_DRIVE_EXPECTED_SERVICE_ACCOUNT_EMAIL');
  if (missing.length) {
    console.error('database backup configuration is incomplete', { missing });
    throw new Error('BACKUP_CONFIGURATION_INCOMPLETE');
  }

  if (!SOURCE_COMMIT_PATTERN.test(config.sourceRevision)) {
    throw new Error('BACKUP_SOURCE_COMMIT_INVALID');
  }
  if (!DEPLOYMENT_ID_PATTERN.test(config.deploymentId)) {
    throw new Error('BACKUP_DEPLOYMENT_ID_INVALID');
  }
  if (Buffer.byteLength(config.dispatchSecret, 'utf8') < 32
    || Buffer.byteLength(config.dispatchSecret, 'utf8') > 512) {
    throw new Error('BACKUP_INTERNAL_DISPATCH_SECRET_INVALID');
  }
  if (!UUID_PATTERN.test(config.expectedNetlifySiteId)) {
    throw new Error('BACKUP_EXPECTED_NETLIFY_SITE_ID_INVALID');
  }
  config.expectedSiteOrigin = parseExpectedSiteOrigin(config.expectedSiteOrigin);
  assertExpectedSupabaseProject(config.supabaseUrl, config.expectedSupabaseProjectRef);
  if (!DRIVE_FOLDER_ID_PATTERN.test(config.expectedDriveRootFolderId)) {
    throw new Error('BACKUP_DRIVE_ROOT_FOLDER_ID_INVALID');
  }

  const stagingMarker = /(?:^|[-_.])(staging|stage|nonprod|test)(?:$|[-_.])/i;
  const productionOrigin = parseProductionSupabaseOrigin(config.productionSupabaseUrl);
  if (config.environment === 'staging') {
    if (!stagingMarker.test(config.deploymentId)) throw new Error('BACKUP_STAGING_DEPLOYMENT_ID_REQUIRED');
    if (!productionOrigin) throw new Error('BACKUP_STAGING_PRODUCTION_DENYLIST_REQUIRED');
    if (productionOrigin && new URL(config.supabaseUrl).origin === productionOrigin) {
      throw new Error('BACKUP_STAGING_CANNOT_USE_PRODUCTION_DATABASE');
    }
  }
  if (config.environment === 'restore-test' && !stagingMarker.test(config.deploymentId)) {
    throw new Error('BACKUP_RESTORE_TEST_DEPLOYMENT_ID_REQUIRED');
  }
  if (config.environment === 'production' && stagingMarker.test(config.deploymentId)) {
    throw new Error('BACKUP_PRODUCTION_DEPLOYMENT_ID_INVALID');
  }

  if (config.environment === 'staging' || config.environment === 'production') {
    if (config.serviceAccountDirectValue) {
      throw new Error('BACKUP_GOOGLE_SERVICE_ACCOUNT_DIRECT_ENV_FORBIDDEN');
    }
    if (config.allowRestoreTestDirectJson) {
      throw new Error('BACKUP_GOOGLE_SERVICE_ACCOUNT_DIRECT_FLAG_FORBIDDEN');
    }
    if (!config.serviceAccountWrapKeyId) missing.push('GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_ID');
    if (!config.serviceAccountWrapKeyValue) missing.push('GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_BASE64');
    if (config.serviceAccountWrapKeyValue
      && (googleServiceAccountWrapKeyReused(config.serviceAccountWrapKeyValue, config.encryptionKeyValue)
        || googleServiceAccountWrapKeyReused(config.serviceAccountWrapKeyValue, config.dispatchSecret))) {
      throw new Error('BACKUP_CREDENTIAL_KEYS_MUST_BE_DISTINCT');
    }
  } else if (!config.allowRestoreTestDirectJson || !config.serviceAccountDirectValue) {
    missing.push('GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON + GOOGLE_DRIVE_SERVICE_ACCOUNT_ALLOW_RESTORE_TEST_DIRECT_JSON=true');
  }
  if (missing.length) {
    console.error('database backup credential configuration is incomplete', { missing });
    throw new Error('BACKUP_CONFIGURATION_INCOMPLETE');
  }
  const validatedEncryptionKey = parseEncryptionKey(config.encryptionKeyValue);
  validatedEncryptionKey.fill(0);

  const configuredFolderCount = Object.values(config.folderIds).filter(Boolean).length;
  if (config.environment === 'restore-test' && configuredFolderCount !== Object.keys(DRIVE_FOLDER_FIELDS).length) {
    throw new Error('BACKUP_RESTORE_TEST_DRIVE_FOLDER_IDS_REQUIRED');
  }
  if (config.environment !== 'restore-test' && configuredFolderCount > 0) {
    throw new Error('BACKUP_DRIVE_ENV_FALLBACK_NOT_ALLOWED');
  }
  if (config.environment === 'restore-test') assertUniqueFolderIds(config.folderIds);

  return Object.freeze({
    ...config,
    hasCompleteEnvFolderIds: configuredFolderCount === Object.keys(DRIVE_FOLDER_FIELDS).length
  });
}

export async function validateCredentialMaterial(config, runtime, deps = {}) {
  const credentialResolver = deps.credentialResolver || resolveGoogleServiceAccountCredential;
  const resolved = await credentialResolver({
    environment: config.environment,
    deploymentId: config.deploymentId,
    supabaseProjectRef: config.expectedSupabaseProjectRef,
    siteId: runtime.siteId,
    siteOrigin: runtime.siteOrigin,
    wrapKeyId: config.serviceAccountWrapKeyId,
    wrapKeyValue: config.serviceAccountWrapKeyValue,
    expectedServiceAccountEmail: config.expectedServiceAccountEmail,
    directJsonValue: config.serviceAccountDirectValue,
    allowRestoreTestDirectJson: config.allowRestoreTestDirectJson,
    ...(deps.credentialStoreFactory ? { storeFactory: deps.credentialStoreFactory } : {})
  });
  const serviceAccount = resolved.serviceAccount;
  const encryptionKey = parseEncryptionKey(config.encryptionKeyValue);
  let tokenUrl;
  try { tokenUrl = new URL(serviceAccount.tokenUri); }
  catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_TOKEN_URI_INVALID'); }
  if (tokenUrl.href !== 'https://oauth2.googleapis.com/token'
    || !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com$/.test(serviceAccount.clientEmail)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_IDENTITY_INVALID');
  }
  return Object.freeze({
    serviceAccount,
    encryptionKey,
    credentialSource: resolved.source,
    credentialKeyId: resolved.keyId
  });
}

function firstRow(value) {
  return Array.isArray(value) ? value[0] || null : value || null;
}

function sortedStrings(values) {
  return (Array.isArray(values) ? values : []).map(value => String(value)).sort();
}

export function assertBackupExportPayload(payload, clinic, domain) {
  if (payload?.format !== 'chananya-domain-export/v1'
    || payload?.schema_version !== BACKUP_SCHEMA_VERSION
    || payload?.clinic_id !== clinic.clinic_id
    || payload?.domain !== domain
    || !payload?.data
    || typeof payload.data !== 'object'
    || Array.isArray(payload.data)) {
    throw new Error('BACKUP_EXPORT_CONTRACT_MISMATCH');
  }
  const included = sortedStrings(payload.included_tables);
  const actual = Object.keys(payload.data).sort();
  const required = [...BACKUP_REQUIRED_TABLES[domain]].sort();
  if (required.some(table => !Array.isArray(payload.data[table]))) {
    throw new Error('BACKUP_EXPORT_REQUIRED_TABLE_MISSING');
  }
  if (JSON.stringify(included) !== JSON.stringify(required)
    || JSON.stringify(actual) !== JSON.stringify(required)) {
    throw new Error('BACKUP_EXPORT_INCLUDED_TABLES_MISMATCH');
  }
  return payload;
}

export function assertBackupDatabaseContract(value) {
  const health = firstRow(value);
  if (health?.ready !== true
    || health.schema_version !== BACKUP_SCHEMA_VERSION
    || Number(health.domain_count) !== BACKUP_DOMAINS.length
    || Number(health.patient_table_count) !== BACKUP_REQUIRED_TABLES.patients.length
    || Number(health.product_table_count) !== BACKUP_REQUIRED_TABLES.products.length
    || Number(health.pharmacy_table_count) !== BACKUP_REQUIRED_TABLES.pharmacy.length
    || Number(health.transaction_table_count) !== BACKUP_REQUIRED_TABLES.transactions.length) {
    throw new Error('BACKUP_DATABASE_CONTRACT_MISMATCH');
  }
  return health;
}

function assignmentFolderIds(assignment) {
  const source = assignment?.folder_ids && typeof assignment.folder_ids === 'object'
    ? assignment.folder_ids
    : assignment;
  return Object.freeze(Object.fromEntries(
    Object.entries(DRIVE_FOLDER_FIELDS).map(([domain, field]) => [
      domain,
      String(source?.[field] || source?.[domain] || '').trim()
    ])
  ));
}

function assertAssignmentTarget(assignment, config, clinic) {
  const clinicId = String(assignment?.clinic_id || assignment?.clinicId || '').trim();
  const clinicCode = String(assignment?.clinic_code || assignment?.clinicCode || '').trim().toUpperCase();
  const environment = String(assignment?.environment || '').trim().toLowerCase();
  if (clinicId !== clinic.clinic_id
    || clinicCode !== String(clinic.clinic_code || '').trim().toUpperCase()
    || environment !== config.environment) {
    throw new Error('BACKUP_DRIVE_DESTINATION_TARGET_MISMATCH');
  }
}

export async function resolveClinicDriveDestination(config, clinic, rpc = supabaseRpc) {
  if (config.environment === 'restore-test') {
    if (config.hasCompleteEnvFolderIds) {
      return Object.freeze({ folderIds: config.folderIds, assignmentVersion: 0 });
    }
    throw new Error('BACKUP_DRIVE_DESTINATION_NOT_ASSIGNED');
  }
  const assignment = firstRow(await rpc(config, 'get_clinic_drive_backup_destination', {
    p_clinic_id: clinic.clinic_id,
    p_environment: config.environment
  }));
  const assignedFolderIds = assignmentFolderIds(assignment);
  if (!assignment) throw new Error('BACKUP_DRIVE_DESTINATION_NOT_ASSIGNED');
  assertAssignmentTarget(assignment, config, clinic);
  if (!folderIdsComplete(assignedFolderIds)) throw new Error('BACKUP_DRIVE_DESTINATION_INVALID');
  assertUniqueFolderIds(assignedFolderIds);
  const assignmentVersion = Number(assignment.version);
  if (!Number.isSafeInteger(assignmentVersion) || assignmentVersion < 1) {
    throw new Error('BACKUP_DRIVE_DESTINATION_VERSION_INVALID');
  }
  return Object.freeze({ folderIds: assignedFolderIds, assignmentVersion });
}

export async function resolveClinicFolderIds(config, clinic, rpc = supabaseRpc) {
  return (await resolveClinicDriveDestination(config, clinic, rpc)).folderIds;
}

function normalizeClinic(value) {
  const clinicId = String(value?.clinic_id || '').trim().toLowerCase();
  const clinicCode = String(value?.clinic_code || '').trim().toUpperCase();
  if (!UUID_PATTERN.test(clinicId) || !CLINIC_CODE_PATTERN.test(clinicCode)) {
    throw new Error('BACKUP_CLINIC_LIST_INVALID');
  }
  return Object.freeze({ clinic_id: clinicId, clinic_code: clinicCode });
}

export function validateClinicList(value, maximum = 10) {
  if (!Array.isArray(value) || value.length === 0) throw new Error('BACKUP_CLINIC_LIST_EMPTY');
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > BACKUP_MAX_CLINICS_HARD_LIMIT) {
    throw new Error('BACKUP_MAX_CLINICS_INVALID');
  }
  if (value.length > maximum) throw new Error('BACKUP_CLINIC_LIST_EXCEEDS_LIMIT');
  const clinics = value.map(normalizeClinic);
  if (new Set(clinics.map(clinic => clinic.clinic_id)).size !== clinics.length
    || new Set(clinics.map(clinic => clinic.clinic_code)).size !== clinics.length) {
    throw new Error('BACKUP_CLINIC_LIST_DUPLICATE');
  }
  return Object.freeze(clinics);
}

function assertOpaqueRuntimeId(value, code) {
  const normalized = String(value || '').trim();
  if (!OPAQUE_RUNTIME_ID_PATTERN.test(normalized)) throw new Error(code);
  return normalized;
}

export function runtimeIdentity(config, context = {}, getEnv = defaultEnvGet) {
  const siteId = context.site?.id || envValue(getEnv, 'SITE_ID');
  const deployId = context.deploy?.id || envValue(getEnv, 'DEPLOY_ID');
  let actualSiteOrigin;
  try { actualSiteOrigin = new URL(context.site?.url || envValue(getEnv, 'URL')).origin; }
  catch { throw new Error('BACKUP_NETLIFY_SITE_ORIGIN_INVALID'); }
  if (String(siteId || '').toLowerCase() !== config.expectedNetlifySiteId) {
    throw new Error('BACKUP_NETLIFY_SITE_ID_MISMATCH');
  }
  if (actualSiteOrigin !== config.expectedSiteOrigin) {
    throw new Error('BACKUP_NETLIFY_SITE_ORIGIN_MISMATCH');
  }
  return Object.freeze({
    siteId: assertOpaqueRuntimeId(siteId, 'BACKUP_NETLIFY_SITE_ID_INVALID'),
    deployId: assertOpaqueRuntimeId(deployId, 'BACKUP_NETLIFY_DEPLOY_ID_INVALID'),
    siteOrigin: actualSiteOrigin
  });
}

function assertSlot(value) {
  const slot = String(value || '');
  const parsed = new Date(slot);
  if (!Number.isFinite(parsed.getTime())
    || parsed.toISOString() !== slot
    || parsed.getUTCHours() !== 20
    || parsed.getUTCMinutes() !== 0
    || parsed.getUTCSeconds() !== 0
    || parsed.getUTCMilliseconds() !== 0) {
    throw new Error('BACKUP_DISPATCH_SLOT_INVALID');
  }
  return slot;
}

const DISPATCH_KEYS = Object.freeze([
  'clinicCode',
  'clinicId',
  'deploymentId',
  'dispatchId',
  'environment',
  'netlifyDeployId',
  'netlifySiteId',
  'siteOrigin',
  'slot',
  'sourceRevision',
  'supabaseProjectRef',
  'version'
].sort());

export function createDispatchJob(config, clinic, slot, runtime, makeUuid = randomUuid) {
  const normalizedClinic = normalizeClinic(clinic);
  return Object.freeze({
    version: BACKUP_DISPATCH_VERSION,
    environment: config.environment,
    deploymentId: config.deploymentId,
    sourceRevision: config.sourceRevision,
    supabaseProjectRef: config.expectedSupabaseProjectRef,
    netlifySiteId: runtime.siteId,
    netlifyDeployId: runtime.deployId,
    siteOrigin: runtime.siteOrigin,
    slot: assertSlot(slot),
    dispatchId: makeUuid(),
    clinicId: normalizedClinic.clinic_id,
    clinicCode: normalizedClinic.clinic_code
  });
}

function signatureInput(timestamp, rawBody) {
  return `cnyos-backup-v1\n${timestamp}\n${rawBody}`;
}

export function signDispatchBody(secret, timestamp, rawBody) {
  return createHmac('sha256', secret).update(signatureInput(timestamp, rawBody)).digest('hex');
}

export function createSignedDispatch(config, clinic, slot, runtime, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
  const job = createDispatchJob(config, clinic, slot, runtime, options.makeUuid || randomUuid);
  const rawBody = JSON.stringify(job);
  const timestamp = String(Math.floor(now.getTime() / 1000));
  const signature = signDispatchBody(config.dispatchSecret, timestamp, rawBody);
  return Object.freeze({
    job,
    rawBody,
    headers: Object.freeze({
      'Content-Type': 'application/json',
      'X-CNYOS-Backup-Timestamp': timestamp,
      'X-CNYOS-Backup-Signature': signature
    })
  });
}

export function verifySignedDispatch(config, rawBody, headers, now = new Date()) {
  if (Buffer.byteLength(rawBody, 'utf8') > BACKUP_DISPATCH_MAX_BODY_BYTES) {
    throw new Error('BACKUP_DISPATCH_UNAUTHORIZED');
  }
  const timestamp = String(headers.get('x-cnyos-backup-timestamp') || '');
  const signature = String(headers.get('x-cnyos-backup-signature') || '').toLowerCase();
  if (!/^[0-9]{10,13}$/.test(timestamp) || !DISPATCH_SIGNATURE_PATTERN.test(signature)) {
    throw new Error('BACKUP_DISPATCH_UNAUTHORIZED');
  }
  const signedAt = Number(timestamp) * 1000;
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const ageMs = nowMs - signedAt;
  if (!Number.isFinite(signedAt)
    || !Number.isFinite(nowMs)
    || ageMs < -BACKUP_DISPATCH_MAX_FUTURE_SKEW_MS
    || ageMs > BACKUP_DISPATCH_MAX_AGE_MS) {
    throw new Error('BACKUP_DISPATCH_UNAUTHORIZED');
  }
  const expected = Buffer.from(signDispatchBody(config.dispatchSecret, timestamp, rawBody), 'hex');
  const supplied = Buffer.from(signature, 'hex');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new Error('BACKUP_DISPATCH_UNAUTHORIZED');
  }
  let job;
  try { job = JSON.parse(rawBody); }
  catch { throw new Error('BACKUP_DISPATCH_UNAUTHORIZED'); }
  if (!job || typeof job !== 'object' || Array.isArray(job)) {
    throw new Error('BACKUP_DISPATCH_UNAUTHORIZED');
  }
  return job;
}

export function assertDispatchBinding(job, config, runtime) {
  if (JSON.stringify(Object.keys(job).sort()) !== JSON.stringify(DISPATCH_KEYS)
    || job.version !== BACKUP_DISPATCH_VERSION
    || job.environment !== config.environment
    || job.deploymentId !== config.deploymentId
    || job.sourceRevision !== config.sourceRevision
    || job.supabaseProjectRef !== config.expectedSupabaseProjectRef
    || job.netlifySiteId !== runtime.siteId
    || job.netlifyDeployId !== runtime.deployId
    || job.siteOrigin !== runtime.siteOrigin
    || !UUID_V4_PATTERN.test(String(job.dispatchId || ''))) {
    throw new Error('BACKUP_DISPATCH_BINDING_MISMATCH');
  }
  assertSlot(job.slot);
  const clinic = normalizeClinic({ clinic_id: job.clinicId, clinic_code: job.clinicCode });
  return Object.freeze({ job, clinic });
}

function combineAbortSignals(primary, timeoutSignal) {
  if (!primary) return timeoutSignal;
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([primary, timeoutSignal]);
  return primary;
}

export function createTimedFetch(fetchImpl = fetch, timeoutMs = 8000, deadlineAt = Infinity, now = Date.now) {
  return async (input, init = {}) => {
    const remaining = deadlineAt === Infinity ? timeoutMs : deadlineAt - now();
    if (!Number.isFinite(remaining) || remaining <= 0) throw new Error('BACKUP_WORKER_DEADLINE_EXCEEDED');
    const boundedTimeout = Math.max(1, Math.min(timeoutMs, remaining));
    const timeoutSignal = AbortSignal.timeout(boundedTimeout);
    return fetchImpl(input, {
      ...init,
      signal: combineAbortSignals(init.signal, timeoutSignal)
    });
  };
}

async function callRpc(config, name, body, deps, timeoutMs, deadlineAt = Infinity) {
  const rpc = deps.rpc || supabaseRpc;
  const fetchImpl = createTimedFetch(deps.fetchImpl || fetch, timeoutMs, deadlineAt, deps.nowMs || Date.now);
  return rpc(config, name, body, fetchImpl);
}

async function finishRun(config, runId, status, counts, objects, code, deps, deadlineAt) {
  await callRpc(config, 'complete_backup_export_run', {
    p_run_id: runId,
    p_status: status,
    p_domain_counts: counts,
    p_object_manifest: objects,
    p_error_code: code
  }, deps, FINALIZATION_TIMEOUT_MS, deadlineAt);
}

function assertWorkerDeadline(deadlineAt, now = Date.now) {
  if (deadlineAt - now() < 5000) throw new Error('BACKUP_WORKER_DEADLINE_EXCEEDED');
}

export async function runBackupClinicJob({
  config,
  clinic,
  slot,
  requestId,
  credentials,
  deps = {}
}) {
  const nowMs = deps.nowMs || Date.now;
  const workerStartedAt = nowMs();
  const finalizationDeadlineAt = workerStartedAt + BACKUP_WORKER_BUDGET_MS;
  const workDeadlineAt = finalizationDeadlineAt - BACKUP_FINALIZATION_RESERVE_MS;
  const lease = firstRow(await callRpc(config, 'begin_backup_export_run', {
    p_clinic_id: clinic.clinic_id,
    p_scheduled_for: slot,
    p_request_id: requestId
  }, deps, WORKER_REQUEST_TIMEOUT_MS, workDeadlineAt));
  if (!lease?.acquired) {
    return { clinicCode: clinic.clinic_code, status: 'skipped', reason: 'slot_already_leased' };
  }
  if (!UUID_PATTERN.test(String(lease.run_id || ''))) {
    throw new Error('BACKUP_LEASE_RESPONSE_INVALID');
  }

  const rpcWithDeadline = (rpcConfig, name, body) => callRpc(
    rpcConfig,
    name,
    body,
    deps,
    WORKER_REQUEST_TIMEOUT_MS,
    workDeadlineAt
  );
  const networkFetch = createTimedFetch(
    deps.fetchImpl || fetch,
    WORKER_REQUEST_TIMEOUT_MS,
    workDeadlineAt,
    nowMs
  );

  let folderIds;
  let assignmentVersion;
  let accessToken;
  try {
    assertWorkerDeadline(workDeadlineAt, nowMs);
    const destination = await resolveClinicDriveDestination(config, clinic, rpcWithDeadline);
    folderIds = destination.folderIds;
    assignmentVersion = destination.assignmentVersion;
    accessToken = await (deps.fetchGoogleAccessToken || fetchGoogleAccessToken)(
      credentials.serviceAccount,
      networkFetch
    );
    await Promise.all(Object.values(folderIds).map(folderId => (
      (deps.inspectDriveFolder || inspectDriveFolder)({
        accessToken,
        folderId,
        expectedParentId: config.expectedDriveRootFolderId,
        fetchImpl: networkFetch
      })
    )));
  } catch (error) {
    const code = errorCode(error, 'BACKUP_DRIVE_DESTINATION_FAILED');
    await finishRun(config, lease.run_id, 'failed', {}, [], code, deps, finalizationDeadlineAt);
    return {
      clinicCode: clinic.clinic_code,
      status: 'failed',
      backedUpDomains: 0,
      failures: [{ domain: 'destination', code }]
    };
  }

  const counts = {};
  const objects = [];
  const failures = [];
  for (const domain of BACKUP_DOMAINS) {
    try {
      assertWorkerDeadline(workDeadlineAt, nowMs);
      const payload = await rpcWithDeadline(config, 'export_clinic_backup_domain', {
        p_clinic_id: clinic.clinic_id,
        p_domain: domain
      });
      assertBackupExportPayload(payload, clinic, domain);
      counts[domain] = countDomainRows(payload);
      const encrypted = (deps.encryptBackup || encryptBackup)(payload, credentials.encryptionKey, {
        environment: config.environment,
        deploymentId: config.deploymentId,
        sourceRevision: config.sourceRevision,
        clinicId: clinic.clinic_id,
        clinicCode: clinic.clinic_code,
        domain,
        slot
      });
      const name = backupFileName(clinic.clinic_code, domain, slot, 'cdb.json.enc', config.environment);
      const driveFile = await (deps.upsertDriveFile || upsertDriveFile)({
        accessToken,
        folderId: folderIds[domain],
        name,
        mimeType: 'application/vnd.chananya.backup+json',
        bytes: encrypted.bytes,
        fetchImpl: networkFetch
      });
      objects.push({
        environment: config.environment,
        domain,
        destination_folder_id: folderIds[domain],
        drive_root_folder_id: config.expectedDriveRootFolderId,
        drive_assignment_version: assignmentVersion,
        file_id: driveFile.id,
        file_name: name,
        operation: driveFile.operation,
        plaintext_bytes: encrypted.plaintextBytes,
        encrypted_bytes: encrypted.encryptedBytes,
        plaintext_sha256: encrypted.envelope.plaintext_sha256,
        ciphertext_sha256: encrypted.envelope.ciphertext_sha256,
        key_id: encrypted.envelope.key_id
      });
    } catch (error) {
      const code = errorCode(error, 'BACKUP_DOMAIN_FAILED');
      console.error('database backup domain failed', {
        requestId,
        clinicCode: clinic.clinic_code,
        domain,
        code
      });
      failures.push({ domain, code });
    }
  }

  const manifest = {
    format: 'chananya-backup-manifest/v2',
    environment: config.environment,
    deployment_id: config.deploymentId,
    source_revision: config.sourceRevision,
    clinic_id: clinic.clinic_id,
    clinic_code: clinic.clinic_code,
    slot,
    generated_at: new Date(nowMs()).toISOString(),
    drive_assignment: {
      version: assignmentVersion,
      root_folder_id: config.expectedDriveRootFolderId,
      folder_ids: folderIds
    },
    domains: objects.map(item => ({
      domain: item.domain,
      destination_folder_id: item.destination_folder_id,
      drive_assignment_version: item.drive_assignment_version,
      file_id: item.file_id,
      file_name: item.file_name,
      plaintext_bytes: item.plaintext_bytes,
      encrypted_bytes: item.encrypted_bytes,
      plaintext_sha256: item.plaintext_sha256,
      ciphertext_sha256: item.ciphertext_sha256,
      key_id: item.key_id,
      row_counts: counts[item.domain]
    })),
    failures
  };

  try {
    assertWorkerDeadline(workDeadlineAt, nowMs);
    const manifestName = backupFileName(
      clinic.clinic_code,
      'manifest',
      slot,
      'manifest.json',
      config.environment
    );
    const manifestFile = await (deps.upsertDriveFile || upsertDriveFile)({
      accessToken,
      folderId: folderIds.manifests,
      name: manifestName,
      mimeType: 'application/json',
      bytes: Buffer.from(JSON.stringify(manifest, null, 2)),
      fetchImpl: networkFetch
    });
    objects.push({
      domain: 'manifest',
      environment: config.environment,
      destination_folder_id: folderIds.manifests,
      drive_root_folder_id: config.expectedDriveRootFolderId,
      drive_assignment_version: assignmentVersion,
      file_id: manifestFile.id,
      file_name: manifestName,
      operation: manifestFile.operation
    });
  } catch (error) {
    failures.push({ domain: 'manifest', code: errorCode(error, 'BACKUP_MANIFEST_FAILED') });
  }

  const backedUpDomains = objects.filter(item => BACKUP_DOMAINS.includes(item.domain)).length;
  const status = failures.length === 0 && backedUpDomains === BACKUP_DOMAINS.length
    ? 'completed'
    : backedUpDomains > 0 ? 'partial' : 'failed';
  const code = failures.map(item => item.code).join(',').slice(0, 500) || null;
  await finishRun(config, lease.run_id, status, counts, objects, code, deps, finalizationDeadlineAt);
  return {
    clinicCode: clinic.clinic_code,
    status,
    backedUpDomains,
    failures: failures.map(item => ({ domain: item.domain, code: item.code }))
  };
}

async function mapWithConcurrency(values, concurrency, operation) {
  const results = new Array(values.length);
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < values.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await operation(values[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, worker));
  return results;
}

function schedulerDestination(config) {
  return new URL(BACKUP_BACKGROUND_FUNCTION_PATH, config.expectedSiteOrigin).href;
}

async function enqueueClinic({ request, context, config, clinic, slot, runtime, deps }) {
  const dispatch = createSignedDispatch(config, clinic, slot, runtime, {
    now: new Date((deps.nowMs || Date.now)()),
    makeUuid: deps.randomUuid || randomUuid
  });
  const fetchImpl = createTimedFetch(
    deps.fetchImpl || fetch,
    DISPATCH_TIMEOUT_MS,
    Infinity,
    deps.nowMs || Date.now
  );
  try {
    const response = await fetchImpl(schedulerDestination(config), {
      method: 'POST',
      headers: dispatch.headers,
      body: dispatch.rawBody,
      cache: 'no-store',
      redirect: 'error'
    });
    if (response.status !== 202) throw new Error('BACKUP_BACKGROUND_ENQUEUE_REJECTED');
    return { clinicCode: clinic.clinic_code, status: 'enqueued' };
  } catch (error) {
    return {
      clinicCode: clinic.clinic_code,
      status: 'failed',
      code: errorCode(error, 'BACKUP_BACKGROUND_ENQUEUE_FAILED')
    };
  }
}

export function mostRecentBackupSlot(value = new Date()) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error('BACKUP_RECOVERY_TIME_INVALID');
  let slotMs = Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
    20, 0, 0, 0
  );
  if (date.getTime() < slotMs) slotMs -= 24 * 60 * 60 * 1000;
  return new Date(slotMs).toISOString();
}

export async function listBackupSlotRuns(config, slot, maximum, deps = {}) {
  assertSlot(slot);
  if (!Number.isSafeInteger(maximum)
    || maximum < 1
    || maximum > BACKUP_MAX_CLINICS_HARD_LIMIT) {
    throw new Error('BACKUP_SLOT_RUN_QUERY_INVALID');
  }
  const url = new URL(`${config.supabaseUrl.replace(/\/$/, '')}/rest/v1/backup_export_runs`);
  url.searchParams.set('select', 'clinic_id,scheduled_for,started_at,status');
  url.searchParams.set('scheduled_for', `eq.${slot}`);
  url.searchParams.set('order', 'started_at.asc');
  url.searchParams.set('limit', String(maximum + 1));
  const fetchImpl = createTimedFetch(
    deps.fetchImpl || fetch,
    SCHEDULER_RPC_TIMEOUT_MS,
    Infinity,
    deps.nowMs || Date.now
  );
  const response = await fetchImpl(url, {
    method: 'GET',
    headers: {
      apikey: config.serviceRoleKey,
      Authorization: `Bearer ${config.serviceRoleKey}`,
      Accept: 'application/json'
    },
    cache: 'no-store',
    redirect: 'error'
  });
  const rows = await response.json().catch(() => null);
  if (!response.ok || !Array.isArray(rows)) throw new Error('BACKUP_SLOT_RUN_QUERY_FAILED');
  if (rows.length > maximum) throw new Error('BACKUP_SLOT_RUN_LIST_EXCEEDS_LIMIT');
  const normalized = rows.map(row => {
    const clinicId = String(row?.clinic_id || '').trim().toLowerCase();
    const scheduledFor = String(row?.scheduled_for || '');
    const startedAt = new Date(row?.started_at || '');
    const status = String(row?.status || '');
    if (!UUID_PATTERN.test(clinicId)
      || !['started', 'completed', 'partial', 'failed'].includes(status)
      || scheduledFor !== slot
      || !Number.isFinite(startedAt.getTime())) {
      throw new Error('BACKUP_SLOT_RUN_RESPONSE_INVALID');
    }
    return Object.freeze({ clinicId, slot: scheduledFor, startedAt: startedAt.toISOString(), status });
  });
  if (new Set(normalized.map(row => row.clinicId)).size !== normalized.length) {
    throw new Error('BACKUP_SLOT_RUN_RESPONSE_INVALID');
  }
  return Object.freeze(normalized);
}

export function classifyBackupSlotRuns(
  clinics,
  slotRuns,
  nowMs,
  staleAgeMs = BACKUP_RECOVERY_MIN_AGE_MS
) {
  if (!Array.isArray(clinics)
    || !Array.isArray(slotRuns)
    || !Number.isFinite(nowMs)
    || !Number.isFinite(staleAgeMs)
    || staleAgeMs < BACKUP_RECOVERY_MIN_AGE_MS) {
    throw new Error('BACKUP_SLOT_CLASSIFICATION_INVALID');
  }
  const cutoffMs = nowMs - staleAgeMs;
  const runsByClinicId = new Map(slotRuns.map(run => [run.clinicId, run]));
  const missingClinics = [];
  const staleClinics = [];
  const freshStartedClinics = [];
  const completedClinics = [];
  const terminalUnhealthy = [];
  for (const clinic of clinics) {
    const run = runsByClinicId.get(clinic.clinic_id);
    if (!run) {
      missingClinics.push(clinic);
    } else if (run.status === 'started' && Date.parse(run.startedAt) < cutoffMs) {
      staleClinics.push(clinic);
    } else if (run.status === 'started') {
      freshStartedClinics.push(clinic);
    } else if (run.status === 'completed') {
      completedClinics.push(clinic);
    } else if (run.status === 'partial' || run.status === 'failed') {
      terminalUnhealthy.push(Object.freeze({
        clinicCode: clinic.clinic_code,
        status: run.status
      }));
    } else {
      throw new Error('BACKUP_SLOT_RUN_RESPONSE_INVALID');
    }
  }
  return Object.freeze({
    missingClinics: Object.freeze(missingClinics),
    staleClinics: Object.freeze(staleClinics),
    freshStartedClinics: Object.freeze(freshStartedClinics),
    completedClinics: Object.freeze(completedClinics),
    terminalUnhealthy: Object.freeze(terminalUnhealthy),
    retryClinics: Object.freeze([...missingClinics, ...staleClinics])
  });
}

export async function handleScheduledBackup(request, context = {}, deps = {}) {
  const requestId = context.requestId || randomUuid();
  const getEnv = deps.getEnv || defaultEnvGet;
  try {
    await assertScheduledInvocation(request);
  } catch {
    return json({ ok: false, code: 'BACKUP_SCHEDULED_INVOCATION_REQUIRED' }, 401);
  }
  if (!backupEnabled(getEnv)) return json({ ok: true, enabled: false }, 200);
  try {
    const config = configuration(getEnv);
    const runtime = runtimeIdentity(config, context, getEnv);
    await validateCredentialMaterial(config, runtime, deps);
    const nowMs = (deps.nowMs || Date.now)();
    const slot = mostRecentBackupSlot(new Date(nowMs));
    const listSlotRuns = deps.listSlotRuns || listBackupSlotRuns;
    const [health, clinicRows, slotRuns] = await Promise.all([
      callRpc(config, 'backup_restore_contract_healthcheck', {}, deps, SCHEDULER_RPC_TIMEOUT_MS),
      callRpc(config, 'list_backup_export_clinics', {}, deps, SCHEDULER_RPC_TIMEOUT_MS),
      listSlotRuns(config, slot, config.maxClinics, deps)
    ]);
    assertBackupDatabaseContract(health);
    const clinics = validateClinicList(clinicRows, config.maxClinics);
    const candidates = classifyBackupSlotRuns(clinics, slotRuns, nowMs);
    const results = await mapWithConcurrency(
      candidates.retryClinics,
      DISPATCH_CONCURRENCY,
      clinic => enqueueClinic({ request, context, config, clinic, slot, runtime, deps })
    );
    const failures = results.filter(result => result.status !== 'enqueued');
    for (const failure of failures) {
      console.error('database backup enqueue failed', {
        requestId,
        clinicCode: failure.clinicCode,
        code: failure.code
      });
    }
    for (const unhealthy of candidates.terminalUnhealthy) {
      console.error('database backup exact slot is unhealthy', {
        requestId,
        clinicCode: unhealthy.clinicCode,
        status: unhealthy.status,
        code: unhealthy.status === 'partial' ? 'BACKUP_SLOT_PARTIAL' : 'BACKUP_SLOT_FAILED'
      });
    }
    const isHealthy = failures.length === 0 && candidates.terminalUnhealthy.length === 0;
    return json({
      ok: isHealthy,
      environment: config.environment,
      deploymentId: config.deploymentId,
      sourceRevision: config.sourceRevision,
      slot,
      observed: slotRuns.length,
      missing: candidates.missingClinics.length,
      stale: candidates.staleClinics.length,
      completed: candidates.completedClinics.length,
      pending: candidates.freshStartedClinics.length,
      partial: candidates.terminalUnhealthy.filter(run => run.status === 'partial').length,
      terminalFailed: candidates.terminalUnhealthy.filter(run => run.status === 'failed').length,
      unhealthy: candidates.terminalUnhealthy.length,
      enqueued: results.length - failures.length,
      failed: failures.length
    }, failures.length ? 502 : candidates.terminalUnhealthy.length ? 503 : 200);
  } catch (error) {
    const code = errorCode(error, 'BACKUP_SCHEDULER_FAILED');
    console.error('database backup scheduler failed', { requestId, code });
    return json({ ok: false, code }, 500);
  }
}

export async function handleBackupRecovery(request, context = {}, deps = {}) {
  const requestId = context.requestId || randomUuid();
  const getEnv = deps.getEnv || defaultEnvGet;
  try {
    await assertScheduledInvocation(request);
  } catch {
    return json({ ok: false, code: 'BACKUP_SCHEDULED_INVOCATION_REQUIRED' }, 401);
  }
  if (!backupEnabled(getEnv)) return json({ ok: true, enabled: false }, 200);
  try {
    const config = configuration(getEnv);
    const runtime = runtimeIdentity(config, context, getEnv);
    await validateCredentialMaterial(config, runtime, deps);
    const nowMs = (deps.nowMs || Date.now)();
    const slot = mostRecentBackupSlot(new Date(nowMs));
    const slotAgeMs = nowMs - Date.parse(slot);
    if (slotAgeMs <= BACKUP_RECOVERY_MIN_AGE_MS || slotAgeMs > BACKUP_RECOVERY_MAX_AGE_MS) {
      return json({
        ok: true,
        monitored: true,
        recoveryWindow: false,
        slot
      }, 200);
    }

    const listSlotRuns = deps.listSlotRuns || listBackupSlotRuns;
    const [health, clinicRows, slotRuns] = await Promise.all([
      callRpc(config, 'backup_restore_contract_healthcheck', {}, deps, SCHEDULER_RPC_TIMEOUT_MS),
      callRpc(config, 'list_backup_export_clinics', {}, deps, SCHEDULER_RPC_TIMEOUT_MS),
      listSlotRuns(config, slot, config.maxClinics, deps)
    ]);
    assertBackupDatabaseContract(health);
    const clinics = validateClinicList(clinicRows, config.maxClinics);
    const candidates = classifyBackupSlotRuns(clinics, slotRuns, nowMs);
    const results = await mapWithConcurrency(
      candidates.retryClinics,
      DISPATCH_CONCURRENCY,
      clinic => enqueueClinic({ request, context, config, clinic, slot, runtime, deps })
    );
    const failures = results.filter(result => result.status !== 'enqueued');
    for (const failure of failures) {
      console.error('database backup recovery enqueue failed', {
        requestId,
        clinicCode: failure.clinicCode,
        code: failure.code
      });
    }
    for (const unhealthy of candidates.terminalUnhealthy) {
      console.error('database backup exact slot is unhealthy', {
        requestId,
        clinicCode: unhealthy.clinicCode,
        status: unhealthy.status,
        code: unhealthy.status === 'partial' ? 'BACKUP_SLOT_PARTIAL' : 'BACKUP_SLOT_FAILED'
      });
    }
    const isHealthy = failures.length === 0 && candidates.terminalUnhealthy.length === 0;
    return json({
      ok: isHealthy,
      monitored: true,
      recoveryWindow: true,
      environment: config.environment,
      deploymentId: config.deploymentId,
      sourceRevision: config.sourceRevision,
      slot,
      observed: slotRuns.length,
      missing: candidates.missingClinics.length,
      stale: candidates.staleClinics.length,
      partial: candidates.terminalUnhealthy.filter(run => run.status === 'partial').length,
      terminalFailed: candidates.terminalUnhealthy.filter(run => run.status === 'failed').length,
      unhealthy: candidates.terminalUnhealthy.length,
      enqueued: results.length - failures.length,
      failed: failures.length
    }, failures.length ? 502 : candidates.terminalUnhealthy.length ? 503 : 200);
  } catch (error) {
    const code = errorCode(error, 'BACKUP_RECOVERY_SCHEDULER_FAILED');
    console.error('database backup recovery scheduler failed', { requestId, code });
    return json({ ok: false, code }, 500);
  }
}

export async function handleBackgroundBackup(request, context = {}, deps = {}) {
  const requestId = context.requestId || randomUuid();
  const getEnv = deps.getEnv || defaultEnvGet;
  if (!backupEnabled(getEnv)) return json({ ok: true, enabled: false }, 200);
  if (request.method !== 'POST') return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);
  try {
    const contentType = String(request.headers.get('content-type') || '').toLowerCase();
    if (!contentType.startsWith('application/json')) throw new Error('BACKUP_DISPATCH_UNAUTHORIZED');
    const config = configuration(getEnv);
    const rawBody = await request.text();
    const job = verifySignedDispatch(
      config,
      rawBody,
      request.headers,
      new Date((deps.nowMs || Date.now)())
    );
    const runtime = runtimeIdentity(config, context, getEnv);
    const bound = assertDispatchBinding(job, config, runtime);
    const credentials = await validateCredentialMaterial(config, runtime, deps);
    assertBackupDatabaseContract(await callRpc(
      config,
      'backup_restore_contract_healthcheck',
      {},
      deps,
      SCHEDULER_RPC_TIMEOUT_MS
    ));
    const result = await runBackupClinicJob({
      config,
      clinic: bound.clinic,
      slot: job.slot,
      requestId: job.dispatchId,
      credentials,
      deps
    });
    return json({
      ok: ['completed', 'skipped'].includes(result.status),
      environment: config.environment,
      deploymentId: config.deploymentId,
      slot: job.slot,
      clinicCode: result.clinicCode,
      status: result.status,
      backedUpDomains: result.backedUpDomains || 0
    }, ['completed', 'skipped'].includes(result.status) ? 200 : 500);
  } catch (error) {
    const code = errorCode(error, 'BACKUP_BACKGROUND_FAILED');
    const unauthorized = code === 'BACKUP_DISPATCH_UNAUTHORIZED';
    console.error('database backup background job failed', {
      requestId,
      code: unauthorized ? 'BACKUP_DISPATCH_UNAUTHORIZED' : code
    });
    return json({
      ok: false,
      code: unauthorized ? 'BACKUP_DISPATCH_UNAUTHORIZED' : code
    }, unauthorized ? 401 : 500);
  }
}
