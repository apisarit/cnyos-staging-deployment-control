import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  randomBytes,
  sign as signBytes
} from 'node:crypto';

export const BACKUP_DOMAINS = Object.freeze(['patients', 'products', 'pharmacy', 'transactions']);
export const BACKUP_ENVIRONMENTS = Object.freeze(['staging', 'production', 'restore-test']);
export const BACKUP_FORMAT = 'chananya-encrypted-backup/v1';
export const BACKUP_SCHEMA_VERSION = '2026-09-01.1';
export const RESTORE_SET_FORMAT = 'chananya-restore-set-evidence/v1';
export const BACKUP_REQUIRED_TABLES = Object.freeze({
  patients: Object.freeze([
    'patients',
    'patient_allergies',
    'patient_user_links',
    'appointments',
    'practitioner_schedules',
    'clinic_appointments',
    'encounters',
    'vital_signs',
    'pain_assessments',
    'pain_markers',
    'intermediate_care_assessments',
    'barthel_assessments',
    'clinical_examination_findings',
    'ttm_opd_histories',
    'ttm_diagnostic_contexts',
    'ttm_structured_diagnoses',
    'ttm_encounter_concepts',
    'body_pain_points',
    'clinical_treatment_plans',
    'treatment_orders',
    'treatment_sessions',
    'clinical_treatment_sessions',
    'followups',
    'clinical_followup_notes',
    'clinical_record_signoffs',
    'patient_identity_links',
    'patient_identity_link_requests',
    'patient_qr_sessions',
    'encounter_identity_verifications',
    'line_oa_contacts',
    'line_oa_notification_preferences'
  ]),
  products: Object.freeze([
    'services',
    'price_lists',
    'price_list_items',
    'products',
    'suppliers',
    'inventory_lots',
    'stock_movements',
    'formulas',
    'formula_components',
    'production_requests',
    'production_orders',
    'production_material_issues',
    'production_qc',
    'finished_goods_receipts',
    'import_batches',
    'import_rows'
  ]),
  pharmacy: Object.freeze([
    'counter_sales',
    'counter_sale_items',
    'counter_allocations',
    'prescriptions',
    'prescription_items',
    'dispensing_orders',
    'dispensing_items'
  ]),
  transactions: Object.freeze([
    'audit_logs',
    'clinical_record_audit_events',
    'appointment_events',
    'patient_identity_events',
    'invoices',
    'invoice_items',
    'payments',
    'line_oa_webhook_events',
    'line_oa_notification_outbox',
    'line_oa_delivery_events',
    'clinic_subscription_control_events',
    'clinic_drive_destination_events'
  ])
});

const toBase64Url = value => Buffer.from(value)
  .toString('base64')
  .replace(/=/g, '')
  .replace(/\+/g, '-')
  .replace(/\//g, '_');

const sha256 = value => createHash('sha256').update(value).digest('hex');

function safeJson(value) {
  try { return JSON.parse(value); }
  catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON_INVALID'); }
}

export function parseServiceAccount(value) {
  const parsed = typeof value === 'string' ? safeJson(value) : value;
  if (!parsed?.client_email || !parsed?.private_key) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_FIELDS_MISSING');
  }
  return Object.freeze({
    clientEmail: String(parsed.client_email),
    privateKey: String(parsed.private_key).replace(/\\n/g, '\n'),
    tokenUri: String(parsed.token_uri || 'https://oauth2.googleapis.com/token')
  });
}

export function parseEncryptionKey(value) {
  const text = String(value || '');
  if (!text || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new Error('BACKUP_ENCRYPTION_KEY_INVALID');
  }
  let key;
  try { key = Buffer.from(text, 'base64'); }
  catch { throw new Error('BACKUP_ENCRYPTION_KEY_INVALID'); }
  if (key.toString('base64') !== text) {
    key.fill(0);
    throw new Error('BACKUP_ENCRYPTION_KEY_INVALID');
  }
  if (key.length !== 32) {
    key.fill(0);
    throw new Error('BACKUP_ENCRYPTION_KEY_MUST_BE_32_BYTES');
  }
  return key;
}

export function createServiceAccountAssertion(serviceAccount, now = Date.now()) {
  const issuedAt = Math.floor(now / 1000);
  const header = toBase64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = toBase64Url(JSON.stringify({
    iss: serviceAccount.clientEmail,
    scope: 'https://www.googleapis.com/auth/drive.file',
    aud: serviceAccount.tokenUri,
    iat: issuedAt,
    exp: issuedAt + 3600
  }));
  const unsigned = `${header}.${claims}`;
  const signature = signBytes('RSA-SHA256', Buffer.from(unsigned), createPrivateKey(serviceAccount.privateKey));
  return `${unsigned}.${toBase64Url(signature)}`;
}

export async function fetchGoogleAccessToken(serviceAccount, fetchImpl = fetch) {
  const assertion = createServiceAccountAssertion(serviceAccount);
  const response = await fetchImpl(serviceAccount.tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    }),
    signal: AbortSignal.timeout(8000)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.access_token) throw new Error('GOOGLE_OAUTH_TOKEN_FAILED');
  return payload.access_token;
}

function envelopeMetadata(payload, metadata) {
  return Object.freeze({
    environment: parseBackupEnvironment(metadata.environment),
    deployment_id: String(metadata.deploymentId),
    source_revision: String(metadata.sourceRevision),
    clinic_id: String(metadata.clinicId),
    clinic_code: String(metadata.clinicCode),
    domain: String(metadata.domain),
    slot: String(metadata.slot),
    source_format: String(payload?.format || 'unknown'),
    schema_version: String(payload?.schema_version || 'unknown')
  });
}

export function parseBackupEnvironment(value) {
  const environment = String(value || '').trim().toLowerCase();
  if (!BACKUP_ENVIRONMENTS.includes(environment)) {
    throw new Error('BACKUP_ENVIRONMENT_INVALID');
  }
  return environment;
}

export function encryptBackup(payload, key, metadata, options = {}) {
  if (!BACKUP_DOMAINS.includes(metadata?.domain)) throw new Error('BACKUP_DOMAIN_INVALID');
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('BACKUP_ENCRYPTION_KEY_MUST_BE_32_BYTES');
  const plaintext = Buffer.from(JSON.stringify(payload));
  const iv = options.iv || randomBytes(12);
  if (!Buffer.isBuffer(iv) || iv.length !== 12) throw new Error('BACKUP_IV_INVALID');
  const aadObject = envelopeMetadata(payload, metadata);
  const aad = Buffer.from(JSON.stringify(aadObject));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const createdAt = options.createdAt || new Date().toISOString();
  const envelope = {
    format: BACKUP_FORMAT,
    algorithm: 'AES-256-GCM',
    key_id: sha256(key).slice(0, 16),
    created_at: createdAt,
    metadata: aadObject,
    aad_sha256: sha256(aad),
    plaintext_sha256: sha256(plaintext),
    ciphertext_sha256: sha256(ciphertext),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
  return Object.freeze({
    envelope,
    bytes: Buffer.from(JSON.stringify(envelope)),
    plaintextBytes: plaintext.length,
    encryptedBytes: Buffer.byteLength(JSON.stringify(envelope))
  });
}

export function decryptBackup(envelope, key) {
  if (envelope?.format !== BACKUP_FORMAT || envelope?.algorithm !== 'AES-256-GCM') {
    throw new Error('BACKUP_ENVELOPE_UNSUPPORTED');
  }
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('BACKUP_ENCRYPTION_KEY_MUST_BE_32_BYTES');
  if (envelope.key_id !== sha256(key).slice(0, 16)) throw new Error('BACKUP_KEY_ID_MISMATCH');
  const aad = Buffer.from(JSON.stringify(envelope.metadata));
  if (sha256(aad) !== envelope.aad_sha256) throw new Error('BACKUP_AAD_INTEGRITY_FAILED');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  if (sha256(ciphertext) !== envelope.ciphertext_sha256) throw new Error('BACKUP_CIPHERTEXT_INTEGRITY_FAILED');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (sha256(plaintext) !== envelope.plaintext_sha256) throw new Error('BACKUP_PLAINTEXT_INTEGRITY_FAILED');
  return JSON.parse(plaintext.toString('utf8'));
}

function sortedValues(values) {
  return values.map(value => String(value)).sort();
}

function assertRestoreSet(condition, code) {
  if (!condition) throw new Error(code);
}

function validateDomainPayload(payload, metadata, domain) {
  assertRestoreSet(payload?.format === 'chananya-domain-export/v1', 'RESTORE_SET_SOURCE_FORMAT_INVALID');
  assertRestoreSet(payload?.schema_version === BACKUP_SCHEMA_VERSION, 'RESTORE_SET_SCHEMA_VERSION_INVALID');
  assertRestoreSet(payload?.clinic_id === metadata.clinic_id, 'RESTORE_SET_PAYLOAD_CLINIC_MISMATCH');
  assertRestoreSet(payload?.domain === domain, 'RESTORE_SET_PAYLOAD_DOMAIN_MISMATCH');
  assertRestoreSet(payload?.data && typeof payload.data === 'object' && !Array.isArray(payload.data), 'RESTORE_SET_DATA_INVALID');

  const dataTables = sortedValues(Object.keys(payload.data));
  const includedTables = sortedValues(Array.isArray(payload.included_tables) ? payload.included_tables : []);
  const requiredTables = [...BACKUP_REQUIRED_TABLES[domain]].sort();
  for (const table of requiredTables) {
    assertRestoreSet(Object.hasOwn(payload.data, table), `RESTORE_SET_REQUIRED_TABLE_MISSING_${table.toUpperCase()}`);
    assertRestoreSet(Array.isArray(payload.data[table]), `RESTORE_SET_TABLE_NOT_ARRAY_${table.toUpperCase()}`);
  }
  assertRestoreSet(
    JSON.stringify(dataTables) === JSON.stringify(requiredTables)
      && JSON.stringify(includedTables) === JSON.stringify(requiredTables),
    'RESTORE_SET_INCLUDED_TABLES_MISMATCH'
  );
}

export function verifyBackupSet(envelopes, key) {
  assertRestoreSet(Array.isArray(envelopes), 'RESTORE_SET_INPUT_INVALID');
  assertRestoreSet(envelopes.length === BACKUP_DOMAINS.length, 'RESTORE_SET_DOMAIN_COUNT_INVALID');

  const byDomain = new Map();
  const decrypted = new Map();
  for (const envelope of envelopes) {
    const domain = String(envelope?.metadata?.domain || '');
    assertRestoreSet(BACKUP_DOMAINS.includes(domain), 'RESTORE_SET_DOMAIN_INVALID');
    assertRestoreSet(!byDomain.has(domain), 'RESTORE_SET_DUPLICATE_DOMAIN');
    const payload = decryptBackup(envelope, key);
    validateDomainPayload(payload, envelope.metadata, domain);
    byDomain.set(domain, envelope);
    decrypted.set(domain, payload);
  }
  for (const domain of BACKUP_DOMAINS) {
    assertRestoreSet(byDomain.has(domain), `RESTORE_SET_DOMAIN_MISSING_${domain.toUpperCase()}`);
  }

  const reference = byDomain.get(BACKUP_DOMAINS[0]);
  const bindingFields = ['environment', 'deployment_id', 'source_revision', 'clinic_id', 'clinic_code', 'slot', 'schema_version'];
  for (const envelope of byDomain.values()) {
    assertRestoreSet(envelope.key_id === reference.key_id, 'RESTORE_SET_KEY_ID_MISMATCH');
    for (const field of bindingFields) {
      assertRestoreSet(envelope.metadata?.[field] === reference.metadata?.[field], `RESTORE_SET_${field.toUpperCase()}_MISMATCH`);
    }
  }

  const domains = {};
  let totalRows = 0;
  for (const domain of BACKUP_DOMAINS) {
    const envelope = byDomain.get(domain);
    const payload = decrypted.get(domain);
    const rowCounts = countDomainRows(payload);
    totalRows += Object.values(rowCounts).reduce((sum, count) => sum + count, 0);
    domains[domain] = {
      plaintext_sha256: envelope.plaintext_sha256,
      ciphertext_sha256: envelope.ciphertext_sha256,
      exported_at: payload.exported_at,
      row_counts: rowCounts,
      filtered_tables: payload.filtered_tables || {},
      excluded_tables: Array.isArray(payload.excluded_tables) ? payload.excluded_tables : []
    };
  }

  const digestInput = {
    environment: reference.metadata.environment,
    deployment_id: reference.metadata.deployment_id,
    source_revision: reference.metadata.source_revision,
    clinic_id: reference.metadata.clinic_id,
    clinic_code: reference.metadata.clinic_code,
    slot: reference.metadata.slot,
    schema_version: reference.metadata.schema_version,
    key_id: reference.key_id,
    domains: Object.fromEntries(BACKUP_DOMAINS.map(domain => [domain, {
      plaintext_sha256: domains[domain].plaintext_sha256,
      row_counts: domains[domain].row_counts
    }]))
  };

  return Object.freeze({
    valid: true,
    format: RESTORE_SET_FORMAT,
    environment: digestInput.environment,
    deployment_id: digestInput.deployment_id,
    source_revision: digestInput.source_revision,
    clinic_id: digestInput.clinic_id,
    clinic_code: digestInput.clinic_code,
    slot: digestInput.slot,
    schema_version: digestInput.schema_version,
    key_id: digestInput.key_id,
    total_rows: totalRows,
    requires_managed_database_restore: true,
    restore_set_sha256: sha256(JSON.stringify(digestInput)),
    domains
  });
}

function driveHeaders(accessToken, extra = {}) {
  return { Authorization: `Bearer ${accessToken}`, ...extra };
}

function escapeDriveQuery(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

export async function findDriveFile({ accessToken, folderId, name, fetchImpl = fetch }) {
  const query = `name = '${escapeDriveQuery(name)}' and '${escapeDriveQuery(folderId)}' in parents and trashed = false`;
  const url = new URL('https://www.googleapis.com/drive/v3/files');
  url.searchParams.set('q', query);
  url.searchParams.set('fields', 'files(id,name,size,modifiedTime)');
  url.searchParams.set('pageSize', '2');
  url.searchParams.set('supportsAllDrives', 'true');
  url.searchParams.set('includeItemsFromAllDrives', 'true');
  const response = await fetchImpl(url, { headers: driveHeaders(accessToken) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error('GOOGLE_DRIVE_LOOKUP_FAILED');
  return payload.files?.[0] || null;
}

export async function downloadDriveFile({ accessToken, fileId, fetchImpl = fetch }) {
  if (!accessToken || !fileId) throw new Error('GOOGLE_DRIVE_DOWNLOAD_ARGUMENT_MISSING');
  const response = await fetchImpl(
    `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`,
    { headers: driveHeaders(accessToken) }
  );
  if (!response.ok) throw new Error('GOOGLE_DRIVE_DOWNLOAD_FAILED');
  return Buffer.from(await response.arrayBuffer());
}

async function createDriveFile({ accessToken, folderId, name, mimeType, bytes, fetchImpl }) {
  const boundary = `chananya_${randomBytes(12).toString('hex')}`;
  const metadata = JSON.stringify({ name, parents: [folderId] });
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`),
    Buffer.from(bytes),
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);
  const response = await fetchImpl(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id,name,size,modifiedTime',
    {
      method: 'POST',
      headers: driveHeaders(accessToken, { 'Content-Type': `multipart/related; boundary=${boundary}` }),
      body
    }
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.id) throw new Error('GOOGLE_DRIVE_UPLOAD_FAILED');
  return payload;
}

async function updateDriveFile({ accessToken, fileId, mimeType, bytes, fetchImpl }) {
  const response = await fetchImpl(
    `https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(fileId)}?uploadType=media&supportsAllDrives=true&fields=id,name,size,modifiedTime`,
    {
      method: 'PATCH',
      headers: driveHeaders(accessToken, { 'Content-Type': mimeType }),
      body: Buffer.from(bytes)
    }
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.id) throw new Error('GOOGLE_DRIVE_UPDATE_FAILED');
  return payload;
}

export async function upsertDriveFile({
  accessToken,
  folderId,
  name,
  mimeType = 'application/octet-stream',
  bytes,
  fetchImpl = fetch
}) {
  if (!accessToken || !folderId || !name || !bytes) throw new Error('GOOGLE_DRIVE_UPLOAD_ARGUMENT_MISSING');
  const existing = await findDriveFile({ accessToken, folderId, name, fetchImpl });
  const result = existing
    ? await updateDriveFile({ accessToken, fileId: existing.id, mimeType, bytes, fetchImpl })
    : await createDriveFile({ accessToken, folderId, name, mimeType, bytes, fetchImpl });
  return Object.freeze({ ...result, operation: existing ? 'updated' : 'created' });
}

export async function supabaseRpc(config, name, body = {}, fetchImpl = fetch) {
  const response = await fetchImpl(`${config.supabaseUrl.replace(/\/$/, '')}/rest/v1/rpc/${encodeURIComponent(name)}`, {
    method: 'POST',
    headers: {
      apikey: config.serviceRoleKey,
      Authorization: `Bearer ${config.serviceRoleKey}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(body)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const code = String(payload?.message || payload?.code || 'SUPABASE_RPC_FAILED').replace(/[^A-Z0-9_]/gi, '_').slice(0, 80);
    throw new Error(code || 'SUPABASE_RPC_FAILED');
  }
  return payload;
}

export function backupSlot(date = new Date()) {
  return new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
    20, 0, 0, 0
  )).toISOString();
}

export function backupFileName(clinicCode, domain, slot, extension = 'cdb.json.enc', environment = 'production') {
  const safeEnvironment = parseBackupEnvironment(environment).toUpperCase().replace(/-/g, '_');
  const safeClinic = String(clinicCode || 'CLINIC').toUpperCase().replace(/[^A-Z0-9_-]/g, '').slice(0, 40) || 'CLINIC';
  const stamp = String(slot).replace(/[-:]/g, '').replace(/\.000Z$/, 'Z');
  return `${safeEnvironment}_${safeClinic}_${domain}_${stamp}.${extension}`;
}

export function countDomainRows(payload) {
  return Object.fromEntries(
    Object.entries(payload?.data || {}).map(([table, rows]) => [table, Array.isArray(rows) ? rows.length : 0])
  );
}
