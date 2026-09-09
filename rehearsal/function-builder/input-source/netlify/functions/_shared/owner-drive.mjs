const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLINIC_CODE_PATTERN = /^[A-Z][A-Z0-9_-]{1,23}$/;
const DRIVE_FOLDER_ID_PATTERN = /^[A-Za-z0-9_-]{10,200}$/;

export const OWNER_DRIVE_DOMAINS = Object.freeze([
  'patients',
  'products',
  'pharmacy',
  'transactions',
  'manifests'
]);

function inputObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function folderIdFromDriveUrl(value) {
  let url;
  try { url = new URL(value); }
  catch { return ''; }
  if (url.protocol !== 'https:' || url.hostname !== 'drive.google.com' || url.username || url.password) return '';

  const pathMatch = url.pathname.match(/^\/drive\/(?:u\/\d+\/)?folders\/([^/]+)\/?$/);
  const candidate = pathMatch?.[1] || (url.pathname === '/open' ? url.searchParams.get('id') : '');
  return String(candidate || '');
}

export function normalizeDriveFolderId(value) {
  const input = String(value || '').trim();
  const candidate = input.includes('://') ? folderIdFromDriveUrl(input) : input;
  if (!DRIVE_FOLDER_ID_PATTERN.test(candidate)) {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDER_INPUT_INVALID');
  }
  return candidate;
}

export function normalizeOwnerDriveRequest(value) {
  const body = inputObject(value);
  if (Object.hasOwn(body, 'environment')) {
    throw new Error('CNYOS_OWNER_DRIVE_ENVIRONMENT_INPUT_INVALID');
  }

  const requestId = String(body.requestId || '').trim();
  const clinicId = String(body.clinicId || '').trim();
  const clinicCode = String(body.clinicCode || '').trim().toUpperCase();
  const reason = String(body.reason || '').trim();
  const expectedVersion = body.expectedVersion;
  if (!UUID_V4_PATTERN.test(requestId) || !UUID_PATTERN.test(clinicId)) {
    throw new Error('CNYOS_OWNER_DRIVE_INPUT_INVALID');
  }
  if (!CLINIC_CODE_PATTERN.test(clinicCode)) {
    throw new Error('CNYOS_OWNER_DRIVE_CLINIC_CODE_INVALID');
  }
  if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
    throw new Error('CNYOS_OWNER_DRIVE_VERSION_INVALID');
  }
  if (reason.length < 8 || reason.length > 500) {
    throw new Error('CNYOS_OWNER_DRIVE_REASON_INVALID');
  }

  const suppliedFolders = inputObject(body.folders);
  const folders = Object.fromEntries(OWNER_DRIVE_DOMAINS.map(domain => [
    domain,
    normalizeDriveFolderId(suppliedFolders[domain])
  ]));
  if (new Set(Object.values(folders)).size !== OWNER_DRIVE_DOMAINS.length) {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDERS_NOT_UNIQUE');
  }

  return Object.freeze({
    requestId,
    clinicId,
    clinicCode,
    expectedVersion,
    reason,
    folders: Object.freeze(folders)
  });
}

export async function inspectDriveFolder({ accessToken, folderId, expectedParentId = '', fetchImpl = fetch }) {
  if (!accessToken || !DRIVE_FOLDER_ID_PATTERN.test(String(folderId || ''))) {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDER_CHECK_ARGUMENT_INVALID');
  }
  if (expectedParentId && !DRIVE_FOLDER_ID_PATTERN.test(String(expectedParentId))) {
    throw new Error('CNYOS_OWNER_DRIVE_ROOT_FOLDER_INVALID');
  }
  const url = new URL(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(folderId)}`);
  url.searchParams.set('fields', 'id,name,mimeType,parents,trashed,capabilities(canAddChildren)');
  url.searchParams.set('supportsAllDrives', 'true');
  const response = await fetchImpl(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json'
    },
    signal: AbortSignal.timeout(8000)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error('CNYOS_OWNER_DRIVE_FOLDER_ACCESS_FAILED');
  if (payload.id !== folderId) throw new Error('CNYOS_OWNER_DRIVE_FOLDER_ID_MISMATCH');
  if (payload.mimeType !== 'application/vnd.google-apps.folder') {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDER_TYPE_INVALID');
  }
  if (payload.trashed === true) throw new Error('CNYOS_OWNER_DRIVE_FOLDER_TRASHED');
  if (payload.capabilities?.canAddChildren !== true) {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDER_WRITE_DENIED');
  }
  if (expectedParentId && !Array.isArray(payload.parents)) {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDER_PARENT_UNVERIFIED');
  }
  if (expectedParentId && !payload.parents.includes(expectedParentId)) {
    throw new Error('CNYOS_OWNER_DRIVE_FOLDER_PARENT_MISMATCH');
  }
  return Object.freeze({
    id: folderId,
    name: String(payload.name || '').slice(0, 200),
    canAddChildren: true
  });
}

export function sanitizeOwnerDriveAssignment(value) {
  const row = inputObject(value);
  const clinicId = String(row.clinic_id || row.clinicId || '');
  const clinicCode = String(row.clinic_code || row.clinicCode || '').toUpperCase();
  const environment = String(row.environment || '').toLowerCase();
  const version = Number(row.version);
  if (!UUID_PATTERN.test(clinicId) || !CLINIC_CODE_PATTERN.test(clinicCode) || !Number.isSafeInteger(version) || version < 1) {
    return null;
  }

  const folderIds = {};
  try {
    for (const domain of OWNER_DRIVE_DOMAINS) {
      folderIds[domain] = normalizeDriveFolderId(row[`${domain}_folder_id`] || row[`${domain}FolderId`]);
    }
  } catch {
    return null;
  }

  return Object.freeze({
    clinic_id: clinicId,
    clinic_code: clinicCode,
    clinic_name_th: String(row.clinic_name_th || row.clinicNameTh || ''),
    clinic_name_en: String(row.clinic_name_en || row.clinicNameEn || ''),
    clinic_active: row.clinic_active ?? row.clinicActive ?? null,
    environment,
    patients_folder_id: folderIds.patients,
    products_folder_id: folderIds.products,
    pharmacy_folder_id: folderIds.pharmacy,
    transactions_folder_id: folderIds.transactions,
    manifests_folder_id: folderIds.manifests,
    version,
    updated_at: String(row.updated_at || row.updatedAt || ''),
    updated_by: String(row.updated_by || row.updatedBy || ''),
    reason: String(row.reason || '')
  });
}

export function ownerDrivePublicError(error) {
  const code = String(error?.message || '');
  const configurationErrors = new Set([
    'CNYOS_OWNER_DRIVE_DISABLED',
    'CNYOS_OWNER_DRIVE_SERVICE_ACCOUNT_MISSING',
    'CNYOS_OWNER_DRIVE_SERVICE_ACCOUNT_INVALID',
    'CNYOS_OWNER_DRIVE_AUTH_FAILED',
    'CNYOS_OWNER_DRIVE_ENVIRONMENT_INVALID',
    'CNYOS_OWNER_DRIVE_ROOT_FOLDER_INVALID',
    'CNYOS_OWNER_DRIVE_DEPLOYMENT_INVALID',
    'CNYOS_OWNER_DRIVE_PROJECT_GUARD_MISMATCH',
    'CNYOS_OWNER_DRIVE_SITE_GUARD_MISMATCH',
    'CNYOS_OWNER_DRIVE_CREDENTIAL_UNAVAILABLE',
    'CNYOS_OWNER_DRIVE_CREDENTIAL_KEY_INVALID',
    'CNYOS_OWNER_DRIVE_CREDENTIAL_KEY_REUSE',
    'CNYOS_OWNER_DRIVE_PRODUCTION_DENYLIST_REQUIRED',
    'CNYOS_OWNER_DRIVE_PRODUCTION_DENYLIST_INVALID',
    'CNYOS_OWNER_DRIVE_PRODUCTION_TARGET_DENIED',
    'CNYOS_OWNER_SERVICE_ROLE_REQUIRED'
  ]);
  const folderErrors = new Set([
    'CNYOS_OWNER_DRIVE_FOLDER_ACCESS_FAILED',
    'CNYOS_OWNER_DRIVE_FOLDER_ID_MISMATCH',
    'CNYOS_OWNER_DRIVE_FOLDER_TYPE_INVALID',
    'CNYOS_OWNER_DRIVE_FOLDER_TRASHED',
    'CNYOS_OWNER_DRIVE_FOLDER_WRITE_DENIED',
    'CNYOS_OWNER_DRIVE_FOLDER_PARENT_UNVERIFIED',
    'CNYOS_OWNER_DRIVE_FOLDER_PARENT_MISMATCH'
  ]);
  const databaseInputErrors = new Set([
    'CNYOS_DRIVE_CLINIC_ID_REQUIRED',
    'CNYOS_DRIVE_ENVIRONMENT_INVALID',
    'CNYOS_DRIVE_ASSIGNMENT_INPUT_REQUIRED',
    'CNYOS_DRIVE_REQUEST_ID_INVALID',
    'CNYOS_DRIVE_EXPECTED_VERSION_INVALID',
    'CNYOS_OWNER_REASON_INVALID',
    'CNYOS_OWNER_EMAIL_INVALID',
    'CNYOS_DRIVE_CLINIC_CONFIRMATION_REQUIRED',
    'CNYOS_DRIVE_FOLDER_ID_INVALID',
    'CNYOS_DRIVE_FOLDER_IDS_NOT_DISTINCT'
  ]);
  const databaseConflictErrors = new Set([
    'CNYOS_DRIVE_REQUEST_ID_CONFLICT',
    'CNYOS_DRIVE_CLINIC_INACTIVE',
    'CNYOS_OWNER_CLINIC_CONFIRMATION_MISMATCH',
    'CNYOS_DRIVE_VERSION_CONFLICT',
    'CNYOS_DRIVE_FOLDER_ALREADY_ASSIGNED',
    'CNYOS_DRIVE_BACKUP_RUN_ACTIVE'
  ]);
  const status = configurationErrors.has(code) ? 503
    : folderErrors.has(code) ? 422
      : databaseInputErrors.has(code) || code === 'CNYOS_OWNER_DRIVE_FOLDERS_NOT_UNIQUE' ? 400
        : databaseConflictErrors.has(code) ? 409
          : code === 'CNYOS_OWNER_CLINIC_NOT_FOUND' ? 404
            : code === 'CNYOS_OWNER_DRIVE_DATABASE_RESPONSE_INVALID' ? 502
              : null;
  const isKnownDatabaseError = configurationErrors.has(code)
    || databaseInputErrors.has(code)
    || databaseConflictErrors.has(code)
    || code === 'CNYOS_OWNER_CLINIC_NOT_FOUND';
  return Object.freeze({
    code: isKnownDatabaseError || /^CNYOS_OWNER_DRIVE_[A-Z0-9_]{3,80}$/.test(code)
      ? code
      : 'CNYOS_OWNER_DRIVE_FAILED',
    status
  });
}
