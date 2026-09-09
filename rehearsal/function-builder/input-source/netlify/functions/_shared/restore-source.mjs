import { createHash, timingSafeEqual } from 'node:crypto';

export const RESTORE_SOURCE_FORMAT = 'chananya-exact-restore-source/v1';
export const RESTORE_DATA_DOMAINS = Object.freeze([
  'patients',
  'products',
  'pharmacy',
  'transactions'
]);
export const RESTORE_OBJECT_DOMAINS = Object.freeze([
  ...RESTORE_DATA_DOMAINS,
  'manifest'
]);
export const RESTORE_FOLDER_DOMAINS = Object.freeze([
  ...RESTORE_DATA_DOMAINS,
  'manifests'
]);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLINIC_CODE_PATTERN = /^[A-Z][A-Z0-9_-]{1,23}$/;
const DRIVE_ID_PATTERN = /^[A-Za-z0-9_-]{10,200}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const KEY_ID_PATTERN = /^[0-9a-f]{16}$/;
const PROJECT_REF_PATTERN = /^[a-z]{20}$/;
const API_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43,256}$/;
const NETLIFY_DEPLOY_ID_PATTERN = /^[A-Za-z0-9_-]{6,200}$/;

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function canonicalSlot(value) {
  const raw = String(value || '').trim();
  if (raw.length < 20 || raw.length > 40) throw new Error('RESTORE_SOURCE_SLOT_INVALID');
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) throw new Error('RESTORE_SOURCE_SLOT_INVALID');
  const slot = date.toISOString();
  if (date.getUTCHours() !== 20
      || date.getUTCMinutes() !== 0
      || date.getUTCSeconds() !== 0
      || date.getUTCMilliseconds() !== 0) {
    throw new Error('RESTORE_SOURCE_SLOT_INVALID');
  }
  return slot;
}

function clinicCode(value) {
  const normalized = String(value || '').trim().toUpperCase();
  if (!CLINIC_CODE_PATTERN.test(normalized)) throw new Error('RESTORE_SOURCE_CLINIC_CODE_INVALID');
  return normalized;
}

function environmentName(value) {
  const environment = String(value || '').trim().toLowerCase();
  if (!['staging', 'production'].includes(environment)) {
    throw new Error('RESTORE_SOURCE_ENVIRONMENT_INVALID');
  }
  return environment;
}

function driveId(value, code = 'RESTORE_SOURCE_DRIVE_ID_INVALID') {
  const id = String(value || '').trim();
  if (!DRIVE_ID_PATTERN.test(id)) throw new Error(code);
  return id;
}

function positiveInteger(value, code) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error(code);
  return number;
}

function rowCounts(value) {
  const counts = record(value);
  if (Object.keys(counts).length === 0) throw new Error('RESTORE_SOURCE_ROW_COUNTS_INVALID');
  const normalized = {};
  for (const [table, count] of Object.entries(counts)) {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(table)
        || !Number.isSafeInteger(Number(count))
        || Number(count) < 0) {
      throw new Error('RESTORE_SOURCE_ROW_COUNTS_INVALID');
    }
    normalized[table] = Number(count);
  }
  return Object.freeze(normalized);
}

function expectedFileName({ clinicCode: code, environment, domain, slot }) {
  const stamp = slot.replace(/[-:]/g, '').replace(/\.000Z$/, 'Z');
  const extension = domain === 'manifest' ? 'manifest.json' : 'cdb.json.enc';
  return `${environment.toUpperCase()}_${code}_${domain}_${stamp}.${extension}`;
}

export function normalizeRestoreSourceRequest(value) {
  const body = record(value);
  if (Object.hasOwn(body, 'environment')
      || Object.hasOwn(body, 'projectRef')
      || Object.hasOwn(body, 'sourceRevision')) {
    throw new Error('RESTORE_SOURCE_SERVER_BOUND_FIELD_DENIED');
  }
  return Object.freeze({
    clinicCode: clinicCode(body.clinicCode),
    slot: canonicalSlot(body.slot)
  });
}

export function normalizeRestoreEnvironment(value) {
  return environmentName(value);
}

export function normalizeRestoreClinicCodes(value) {
  const codes = [...new Set(String(value || '')
    .split(/[\s,;]+/)
    .filter(Boolean)
    .map(clinicCode))];
  if (codes.length === 0 || codes.length > 50) {
    throw new Error('RESTORE_SOURCE_CLINIC_CODES_INVALID');
  }
  return Object.freeze(codes);
}

export function normalizeRestoreRootFolderId(value) {
  return driveId(value, 'RESTORE_SOURCE_ROOT_FOLDER_INVALID');
}

export function assertRestoreSourceProject(urlValue, expectedProjectRef) {
  const expected = String(expectedProjectRef || '').trim().toLowerCase();
  if (!PROJECT_REF_PATTERN.test(expected)) throw new Error('RESTORE_SOURCE_PROJECT_REF_INVALID');
  let url;
  try { url = new URL(String(urlValue || '')); }
  catch { throw new Error('RESTORE_SOURCE_SUPABASE_URL_INVALID'); }
  const actual = url.hostname.match(/^([a-z]{20})\.supabase\.co$/)?.[1] || '';
  if (url.protocol !== 'https:'
      || url.pathname !== '/'
      || url.search
      || url.hash
      || url.username
      || url.password
      || actual !== expected) {
    throw new Error('RESTORE_SOURCE_PROJECT_MISMATCH');
  }
  return Object.freeze({ url: url.origin, projectRef: actual });
}

function restoreSourceSiteOrigin(value) {
  let url;
  try { url = new URL(String(value || '').trim().toLowerCase()); }
  catch { throw new Error('RESTORE_SOURCE_SITE_CONFIG_INVALID'); }
  if (url.protocol !== 'https:'
      || url.username
      || url.password
      || url.port
      || url.pathname !== '/'
      || url.search
      || url.hash
      || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(url.hostname)) {
    throw new Error('RESTORE_SOURCE_SITE_CONFIG_INVALID');
  }
  return url.origin;
}

export function assertRestoreSourceRuntime(request, context, expectedSiteId, expectedSiteOrigin) {
  const siteId = String(expectedSiteId || '').trim().toLowerCase();
  const siteOrigin = restoreSourceSiteOrigin(expectedSiteOrigin);
  if (!UUID_PATTERN.test(siteId)) throw new Error('RESTORE_SOURCE_SITE_CONFIG_INVALID');

  let requestOrigin;
  let runtimeOrigin;
  try {
    requestOrigin = new URL(request?.url).origin;
    runtimeOrigin = new URL(context?.site?.url).origin;
  } catch {
    throw new Error('RESTORE_SOURCE_RUNTIME_MISMATCH');
  }
  if (String(context?.site?.id || '').trim().toLowerCase() !== siteId
      || runtimeOrigin !== siteOrigin
      || requestOrigin !== siteOrigin) {
    throw new Error('RESTORE_SOURCE_RUNTIME_MISMATCH');
  }
  if (context?.deploy?.published !== true
      || context?.deploy?.context !== 'production'
      || !NETLIFY_DEPLOY_ID_PATTERN.test(String(context?.deploy?.id || ''))) {
    throw new Error('RESTORE_SOURCE_DEPLOY_CONTEXT_DENIED');
  }
  return Object.freeze({
    siteId,
    siteOrigin,
    deployId: context.deploy.id
  });
}

export function extractRestoreSourceApiToken(request) {
  const authorization = String(request?.headers?.get?.('authorization') || '');
  const match = authorization.match(/^Bearer\s+([^\s]+)$/i);
  if (!match || !API_TOKEN_PATTERN.test(match[1])) {
    throw new Error('RESTORE_SOURCE_API_TOKEN_REQUIRED');
  }
  return match[1];
}

export function assertRestoreSourceApiToken(token, expectedSha256) {
  if (!API_TOKEN_PATTERN.test(String(token || ''))
      || !SHA256_PATTERN.test(String(expectedSha256 || '').toLowerCase())) {
    throw new Error('RESTORE_SOURCE_API_TOKEN_INVALID');
  }
  const actual = createHash('sha256').update(token).digest();
  const expected = Buffer.from(String(expectedSha256).toLowerCase(), 'hex');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error('RESTORE_SOURCE_API_TOKEN_INVALID');
  }
  return true;
}

export function normalizeExactRestoreSource(value, expected = {}) {
  const source = record(value);
  if (source.format !== RESTORE_SOURCE_FORMAT) throw new Error('RESTORE_SOURCE_FORMAT_INVALID');
  const runId = String(source.run_id || '');
  const clinicId = String(source.clinic_id || '');
  const code = clinicCode(source.clinic_code);
  const environment = environmentName(source.environment);
  const slot = canonicalSlot(source.slot);
  const completedAt = new Date(String(source.completed_at || ''));
  if (!UUID_PATTERN.test(runId) || !UUID_PATTERN.test(clinicId)) {
    throw new Error('RESTORE_SOURCE_ID_INVALID');
  }
  if (Number.isNaN(completedAt.getTime()) || completedAt < new Date(slot)) {
    throw new Error('RESTORE_SOURCE_COMPLETION_INVALID');
  }
  if (expected.clinicCode && code !== clinicCode(expected.clinicCode)) {
    throw new Error('RESTORE_SOURCE_CLINIC_MISMATCH');
  }
  if (expected.environment && environment !== environmentName(expected.environment)) {
    throw new Error('RESTORE_SOURCE_ENVIRONMENT_MISMATCH');
  }
  if (expected.slot && slot !== canonicalSlot(expected.slot)) {
    throw new Error('RESTORE_SOURCE_SLOT_MISMATCH');
  }

  const assignment = record(source.drive_assignment);
  const version = positiveInteger(assignment.version, 'RESTORE_SOURCE_ASSIGNMENT_VERSION_INVALID');
  const rootFolderId = driveId(
    assignment.root_folder_id,
    'RESTORE_SOURCE_ROOT_FOLDER_INVALID'
  );
  if (expected.expectedRootFolderId
      && rootFolderId !== driveId(expected.expectedRootFolderId, 'RESTORE_SOURCE_ROOT_FOLDER_INVALID')) {
    throw new Error('RESTORE_SOURCE_ROOT_FOLDER_MISMATCH');
  }
  const folderInput = record(assignment.folder_ids);
  const folders = Object.fromEntries(RESTORE_FOLDER_DOMAINS.map(domain => [
    domain,
    driveId(folderInput[domain])
  ]));
  if (new Set(Object.values(folders)).size !== RESTORE_FOLDER_DOMAINS.length) {
    throw new Error('RESTORE_SOURCE_FOLDER_IDS_NOT_UNIQUE');
  }

  const objectInput = record(source.objects);
  if (Object.keys(objectInput).length !== RESTORE_OBJECT_DOMAINS.length
      || RESTORE_OBJECT_DOMAINS.some(domain => !Object.hasOwn(objectInput, domain))) {
    throw new Error('RESTORE_SOURCE_OBJECTS_INCOMPLETE');
  }
  const objects = {};
  for (const domain of RESTORE_OBJECT_DOMAINS) {
    const item = record(objectInput[domain]);
    const itemDomain = String(item.domain || '');
    const destinationFolderId = driveId(item.destination_folder_id);
    const expectedFolder = folders[domain === 'manifest' ? 'manifests' : domain];
    const fileId = driveId(item.file_id);
    const fileName = String(item.file_name || '');
    if (itemDomain !== domain
        || item.environment !== environment
        || destinationFolderId !== expectedFolder
        || item.drive_root_folder_id !== rootFolderId
        || Number(item.drive_assignment_version) !== version
        || fileName !== expectedFileName({ clinicCode: code, environment, domain, slot })) {
      throw new Error('RESTORE_SOURCE_OBJECT_BINDING_INVALID');
    }
    const normalized = {
      domain,
      destinationFolderId,
      driveRootFolderId: rootFolderId,
      driveAssignmentVersion: version,
      fileId,
      fileName
    };
    if (domain !== 'manifest') {
      normalized.plaintextBytes = positiveInteger(
        item.plaintext_bytes,
        'RESTORE_SOURCE_OBJECT_SIZE_INVALID'
      );
      normalized.encryptedBytes = positiveInteger(
        item.encrypted_bytes,
        'RESTORE_SOURCE_OBJECT_SIZE_INVALID'
      );
      normalized.plaintextSha256 = String(item.plaintext_sha256 || '');
      normalized.ciphertextSha256 = String(item.ciphertext_sha256 || '');
      normalized.keyId = String(item.key_id || '');
      if (!SHA256_PATTERN.test(normalized.plaintextSha256)
          || !SHA256_PATTERN.test(normalized.ciphertextSha256)
          || !KEY_ID_PATTERN.test(normalized.keyId)) {
        throw new Error('RESTORE_SOURCE_OBJECT_HASH_INVALID');
      }
      normalized.rowCounts = rowCounts(item.row_counts);
    }
    objects[domain] = Object.freeze(normalized);
  }
  if (new Set(Object.values(objects).map(item => item.fileId)).size !== RESTORE_OBJECT_DOMAINS.length) {
    throw new Error('RESTORE_SOURCE_FILE_IDS_NOT_UNIQUE');
  }

  return Object.freeze({
    format: RESTORE_SOURCE_FORMAT,
    runId,
    clinicId,
    clinicCode: code,
    environment,
    slot,
    completedAt: completedAt.toISOString(),
    assignmentVersion: version,
    rootFolderId,
    folders: Object.freeze(folders),
    objects: Object.freeze(objects)
  });
}

export function restoreSourcePublicError(error) {
  const candidate = String(error?.message || '');
  const safeCode = /^RESTORE_SOURCE_[A-Z0-9_]{3,100}$/.test(candidate)
    ? candidate
    : 'RESTORE_SOURCE_REQUEST_FAILED';
  const status = safeCode === 'RESTORE_SOURCE_API_TOKEN_REQUIRED'
    || safeCode === 'RESTORE_SOURCE_API_TOKEN_INVALID' ? 401
    : safeCode === 'RESTORE_SOURCE_CLINIC_NOT_ALLOWED' ? 403
      : safeCode === 'RESTORE_SOURCE_REQUEST_TOO_LARGE' ? 413
      : safeCode === 'RESTORE_SOURCE_CLINIC_NOT_FOUND'
        || safeCode === 'RESTORE_SOURCE_COMPLETED_RUN_NOT_FOUND' ? 404
    : safeCode === 'RESTORE_SOURCE_API_DISABLED'
          || safeCode === 'RESTORE_SOURCE_CONFIGURATION_INVALID'
          || safeCode === 'RESTORE_SOURCE_SITE_CONFIG_INVALID'
          || safeCode === 'RESTORE_SOURCE_RUNTIME_MISMATCH'
          || safeCode === 'RESTORE_SOURCE_PROJECT_REF_INVALID'
          || safeCode === 'RESTORE_SOURCE_SUPABASE_URL_INVALID'
          || safeCode === 'RESTORE_SOURCE_PROJECT_MISMATCH'
          || safeCode === 'RESTORE_SOURCE_PRODUCTION_DENYLIST_INVALID'
          || safeCode === 'RESTORE_SOURCE_PRODUCTION_TARGET_DENIED'
          || safeCode === 'RESTORE_SOURCE_ROOT_FOLDER_INVALID'
          || safeCode === 'RESTORE_SOURCE_CLINIC_CODES_INVALID' ? 503
          : safeCode === 'RESTORE_SOURCE_DEPLOY_CONTEXT_DENIED' ? 403
          : safeCode.includes('INVALID')
            || safeCode.includes('MISMATCH')
            || safeCode.includes('DENIED')
            || safeCode.includes('REQUIRED') ? 400
              : 500;
  return Object.freeze({ code: safeCode, status });
}
