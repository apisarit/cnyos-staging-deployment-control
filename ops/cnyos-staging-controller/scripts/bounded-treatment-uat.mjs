import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const BOUNDED_TREATMENT_TARGET = Object.freeze({
  origin: 'https://cnyos-clinical-staging.netlify.app',
  netlifySiteId: '887e058b-6e13-461f-b3c7-ae096b7046fe',
  netlifySiteName: 'cnyos-clinical-staging',
  supabaseProjectRef: 'hsmnjwxurlmsizndjlun',
  supabaseOrigin: 'https://hsmnjwxurlmsizndjlun.supabase.co',
  clinicId: '00000000-0000-4000-8000-00000000a001',
  clinicCode: 'CHANANYA-STG'
});

export const BOUNDED_TREATMENT_ACK =
  'I_AUTHORIZE_EXACTLY_TWO_SYNTHETIC_TREATMENT_WRITES';

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const DEPLOY_ID = /^[0-9a-f]{24}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const MAX_JSON_BYTES = 64 * 1024;
const LEDGER_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const NETLIFY_API = 'https://api.netlify.com/api/v1';
const TREATMENT_RPC_PATH = '/rest/v1/rpc/create_clinical_treatment_session';
const READ_ONLY_RPC_PATHS = new Set([
  '/rest/v1/rpc/current_access_context',
  '/rest/v1/rpc/hybrid_patient_identity_healthcheck',
  '/rest/v1/rpc/clinical_financial_handoffs_healthcheck'
]);
const APP_RESOURCE_QUERIES = new Map([
  ['/app-shell.js', new Set(['?v=clinical-os-ia1'])],
  ['/app.css', new Set(['?v=clinical-os-worklist1'])],
  ['/auth-config.js', new Set(['?v=login1', '?v=clinical-os-ia1'])],
  ['/auth-login.js', new Set(['?v=csp2'])],
  ['/body-pain-map.js', new Set(['?v=clinical-os-department1'])],
  ['/bodymap-figures.svg', new Set(['?v=clinical-os-department1'])],
  ['/chananya-runtime.js', new Set(['?v=clinical-os-department1'])],
  ['/clinical-context-guard.js', new Set(['?v=clinical-os-ia1'])],
  ['/clinical-signoff.js', new Set(['?v=clinical-os-ia1'])],
  ['/clinical-v3.js', new Set(['?v=clinical-os-worklist1'])],
  ['/clinical-worklist.js', new Set(['?v=clinical-os-worklist1'])],
  ['/diagnosis-atomic-bridge.js', new Set(['?v=clinical-os-ia1'])],
  ['/login.html', new Set([''])],
  ['/opd-workflow.js', new Set(['?v=opd-verified-save-20261001'])],
  ['/searchable-select.js', new Set(['?v=clinical-os-department1'])],
  ['/tenant-brand.js', new Set(['?v=white-label1', '?v=white-label2'])],
  ['/tenant-config.js', new Set(['?v=white-label1'])],
  ['/ttm-diagnosis-assistant.js', new Set(['?v=clinical-os-ia1'])]
]);
const SUPABASE_READ_TABLES = new Set([
  'body_pain_points',
  'clinical_examination_findings',
  'clinical_record_signoffs',
  'clinical_treatment_plans',
  'clinical_treatment_sessions',
  'encounters',
  'patient_allergies',
  'patients',
  'prescriptions',
  'products',
  'profiles',
  'ttm_diagnostic_knowledge',
  'ttm_opd_histories',
  'ttm_structured_diagnoses'
]);
const CDN_RESOURCE_PATH = '/npm/@supabase/supabase-js@2.112.4';
const SUPABASE_CLIENT_INFO = 'supabase-js/2.112.4; runtime=web';
const SUPABASE_AUTH_API_VERSION = '2024-01-01';
const BROWSER_LOCALE = 'en-US';
const CHROMIUM_PRIORITY_VALUES = new Map([
  ['document', new Set(['u=0, i'])],
  ['stylesheet', new Set(['u=0'])],
  ['script', new Set(['u=1'])],
  ['image', new Set(['u=2, i', 'i'])],
  ['fetch', new Set(['u=1, i'])]
]);
const PUBLISHABLE_KEY = /^sb_publishable_[A-Za-z0-9_-]{20,}$/;
const ACCESS_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const BROWSER_MANAGED_HEADERS = new Set([
  'accept', 'accept-encoding', 'accept-language', 'connection', 'content-length',
  'host', 'origin', 'referer', 'sec-ch-ua',
  'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode',
  'sec-fetch-site', 'sec-fetch-user', 'upgrade-insecure-requests', 'user-agent'
]);
const API_SEMANTIC_HEADERS = new Set([
  'accept-profile', 'apikey', 'authorization', 'content-profile', 'content-type',
  'prefer', 'x-client-info', 'x-supabase-api-version'
]);
const PREFLIGHT_HEADERS = new Set([
  'access-control-request-headers', 'access-control-request-method'
]);

export class BoundedTreatmentError extends Error {
  constructor(code, { uncertain = false } = {}) {
    super(code);
    this.name = 'BoundedTreatmentError';
    this.code = code;
    this.uncertain = uncertain;
  }
}

function fail(code, options) {
  throw new BoundedTreatmentError(code, options);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected, code) {
  if (!isPlainObject(value) ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) fail(code);
  return value;
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

function exactUuid(value, code) {
  const normalized = required(value, code).toLowerCase();
  if (!UUID.test(normalized)) fail(code);
  return normalized;
}

function nullableText(value, code, maximum = 512) {
  if (value === null) return null;
  if (typeof value !== 'string' || value.length > maximum || value !== value.trim()) fail(code);
  return value || null;
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function canonicalFixtureSha256(fixture) {
  return hash(Buffer.from(canonicalJson(fixture)));
}

function sha1(value) {
  return crypto.createHash('sha1').update(value).digest('hex');
}

function canonicalTimestamp(value, code) {
  const normalized = required(value, code, 64);
  const time = Date.parse(normalized);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== normalized) fail(code);
  return normalized;
}

function sessionPayload(session, encounterId) {
  return Object.freeze({
    p_encounter_id: encounterId,
    p_client_request_id: session.operationId,
    p_treatment_modalities: session.modalities,
    p_treatment_detail: session.treatmentDetail,
    p_procedure_referral: session.procedureReferral,
    p_procedure_referral_detail: session.procedureReferralDetail,
    p_precautions: session.precautions,
    p_pain_before: session.painBefore,
    p_pain_after: session.painAfter,
    p_outcome_summary: session.outcomeSummary,
    p_advice: session.advice
  });
}

function validateSession(value, index, runId) {
  const code = `CNYOS_BOUNDED_TREATMENT_FIXTURE_SESSION_${index + 1}_INVALID`;
  exactKeys(value, [
    'operationId', 'modalities', 'treatmentDetail', 'procedureReferral',
    'procedureReferralDetail', 'precautions', 'painBefore', 'painAfter',
    'outcomeSummary', 'advice'
  ], code);
  const operationId = exactUuid(value.operationId, code);
  if (!Array.isArray(value.modalities) || value.modalities.length !== 1 ||
    value.modalities[0] !== 'นวดไทย') fail(code);
  const treatmentDetail = required(value.treatmentDetail, code, 500);
  if (!treatmentDetail.includes(`SYNTHETIC ${runId}`) ||
    !treatmentDetail.includes('NOT FOR CLINICAL USE')) fail(code);
  if (value.procedureReferral !== false || !Number.isInteger(value.painBefore) ||
    !Number.isInteger(value.painAfter) || value.painBefore < 0 || value.painBefore > 10 ||
    value.painAfter < 0 || value.painAfter > 10) fail(code);
  return Object.freeze({
    operationId,
    modalities: Object.freeze([...value.modalities]),
    treatmentDetail,
    procedureReferral: false,
    procedureReferralDetail: nullableText(value.procedureReferralDetail, code),
    precautions: nullableText(value.precautions, code),
    painBefore: value.painBefore,
    painAfter: value.painAfter,
    outcomeSummary: nullableText(value.outcomeSummary, code),
    advice: nullableText(value.advice, code)
  });
}

export function validateTreatmentFixture(value, { runId, practitionerEmail }) {
  const code = 'CNYOS_BOUNDED_TREATMENT_FIXTURE_INVALID';
  exactKeys(value, [
    'schemaVersion', 'syntheticOnly', 'realPatientDataAuthorized',
    'clinic', 'practitioner', 'patient', 'encounter', 'sessions'
  ], code);
  if (value.schemaVersion !== 1 || value.syntheticOnly !== true ||
    value.realPatientDataAuthorized !== false) fail(code);

  exactKeys(value.clinic, ['id', 'code'], code);
  if (String(value.clinic.id).toLowerCase() !== BOUNDED_TREATMENT_TARGET.clinicId ||
    value.clinic.code !== BOUNDED_TREATMENT_TARGET.clinicCode) fail(code);

  exactKeys(value.practitioner,
    ['userId', 'email', 'role', 'syntheticMarkerVerified'], code);
  const userId = exactUuid(value.practitioner.userId, code);
  const email = required(value.practitioner.email, code, 320).toLowerCase();
  if (!EMAIL.test(email) || email !== practitionerEmail || value.practitioner.role !== 'practitioner' ||
    value.practitioner.syntheticMarkerVerified !== true) fail(code);

  exactKeys(value.patient, [
    'id', 'hn', 'paymentRight', 'syntheticMarkerVerified', 'realIdentifiersAbsent'
  ], code);
  const patientId = exactUuid(value.patient.id, code);
  const hn = required(value.patient.hn, code, 64);
  if (!/^[A-Za-z0-9._/-]+$/.test(hn) || value.patient.paymentRight !== 'SYNTHETIC-E2E' ||
    value.patient.syntheticMarkerVerified !== true || value.patient.realIdentifiersAbsent !== true) fail(code);

  exactKeys(value.encounter, [
    'id', 'patientId', 'practitionerUserId', 'status', 'baselineTreatmentSessionCount'
  ], code);
  const encounterId = exactUuid(value.encounter.id, code);
  if (exactUuid(value.encounter.patientId, code) !== patientId ||
    exactUuid(value.encounter.practitionerUserId, code) !== userId ||
    value.encounter.status !== 'draft' || value.encounter.baselineTreatmentSessionCount !== 0) fail(code);

  if (!Array.isArray(value.sessions) || value.sessions.length !== 2) fail(code);
  const sessions = value.sessions.map((session, index) => validateSession(session, index, runId));
  if (sessions[0].operationId === sessions[1].operationId) fail(code);
  return Object.freeze({
    schemaVersion: 1,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    clinic: Object.freeze({ ...value.clinic, id: BOUNDED_TREATMENT_TARGET.clinicId }),
    practitioner: Object.freeze({ ...value.practitioner, userId, email }),
    patient: Object.freeze({ ...value.patient, id: patientId, hn }),
    encounter: Object.freeze({ ...value.encounter, id: encounterId,
      patientId, practitionerUserId: userId }),
    sessions: Object.freeze(sessions)
  });
}

export function validateProtectedFixtureLedger(value, {
  fixture,
  sourceCommit,
  sourceTree,
  deployId,
  now = new Date()
}) {
  const code = 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_INVALID';
  exactKeys(value, [
    'schemaVersion', 'kind', 'entryId', 'fixtureSha256', 'verifiedAt', 'target', 'fixtureIds'
  ], code);
  if (value.schemaVersion !== 1 || value.kind !== 'protected_staging_fixture_ledger' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(value.entryId) ||
    !SHA256.test(String(value.fixtureSha256 || '').toLowerCase())) fail(code);
  const verifiedAt = canonicalTimestamp(value.verifiedAt, code);
  const observedNow = now instanceof Date ? now : new Date(now);
  const nowMs = observedNow.getTime();
  const verifiedMs = Date.parse(verifiedAt);
  if (!Number.isFinite(nowMs) || verifiedMs > nowMs || nowMs - verifiedMs > LEDGER_MAX_AGE_MS) {
    fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_TIMESTAMP_INVALID');
  }
  exactKeys(value.target,
    ['siteId', 'deployId', 'sourceCommit', 'sourceTree', 'clinicId'], code);
  if (String(value.target.siteId || '').toLowerCase() !== BOUNDED_TREATMENT_TARGET.netlifySiteId ||
    String(value.target.deployId || '').toLowerCase() !== deployId ||
    String(value.target.sourceCommit || '').toLowerCase() !== sourceCommit ||
    String(value.target.sourceTree || '').toLowerCase() !== sourceTree ||
    String(value.target.clinicId || '').toLowerCase() !== BOUNDED_TREATMENT_TARGET.clinicId) fail(code);
  exactKeys(value.fixtureIds,
    ['practitionerUserId', 'patientId', 'encounterId', 'operationIds'], code);
  if (String(value.fixtureIds.practitionerUserId || '').toLowerCase() !==
      fixture.practitioner.userId ||
    String(value.fixtureIds.patientId || '').toLowerCase() !== fixture.patient.id ||
    String(value.fixtureIds.encounterId || '').toLowerCase() !== fixture.encounter.id ||
    !Array.isArray(value.fixtureIds.operationIds) || value.fixtureIds.operationIds.length !== 2 ||
    value.fixtureIds.operationIds.some((id, index) =>
      String(id || '').toLowerCase() !== fixture.sessions[index].operationId) ||
    String(value.fixtureSha256).toLowerCase() !== canonicalFixtureSha256(fixture)) fail(code);
  return Object.freeze({
    schemaVersion: 1,
    kind: value.kind,
    entryId: value.entryId,
    fixtureSha256: String(value.fixtureSha256).toLowerCase(),
    verifiedAt,
    target: Object.freeze({ ...value.target }),
    fixtureIds: Object.freeze({
      ...value.fixtureIds,
      operationIds: Object.freeze([...value.fixtureIds.operationIds])
    }),
    inputSha256: hash(Buffer.from(canonicalJson(value)))
  });
}

async function readProtectedFixtureLedger(env) {
  const filename = required(env.CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH,
    'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_PATH_REQUIRED', 4096);
  if (!path.isAbsolute(filename)) {
    fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_PATH_INVALID');
  }
  const expectedFileSha256 = exact(env.CNYOS_EXPECTED_TREATMENT_FIXTURE_LEDGER_SHA256,
    SHA256, 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_DIGEST_REQUIRED');
  let handle;
  try {
    handle = await fs.open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 2 || stat.size > MAX_JSON_BYTES ||
      (stat.mode & 0o077) !== 0 || (stat.mode & 0o400) === 0) {
      fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_FILE_INVALID');
    }
    const bytes = await handle.readFile();
    if (bytes.length !== stat.size) {
      fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_FILE_INVALID');
    }
    const sourceFileSha256 = hash(bytes);
    if (!crypto.timingSafeEqual(Buffer.from(sourceFileSha256, 'hex'),
      Buffer.from(expectedFileSha256, 'hex'))) {
      fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_DIGEST_MISMATCH');
    }
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); }
    catch { fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_INVALID'); }
    return Object.freeze({ value, sourceFileSha256, expectedFileSha256 });
  } catch (error) {
    if (error instanceof BoundedTreatmentError) throw error;
    fail('CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_FILE_INVALID');
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function loadBoundedTreatmentConfig(env = process.env, { now = () => new Date() } = {}) {
  const runId = required(env.CNYOS_TREATMENT_UAT_RUN_ID,
    'CNYOS_BOUNDED_TREATMENT_RUN_ID_INVALID', 96);
  if (!RUN_ID.test(runId)) fail('CNYOS_BOUNDED_TREATMENT_RUN_ID_INVALID');
  const practitionerEmail = required(env.CNYOS_STAGING_PRACTITIONER_EMAIL,
    'CNYOS_BOUNDED_TREATMENT_EMAIL_INVALID', 320).toLowerCase();
  if (!EMAIL.test(practitionerEmail)) fail('CNYOS_BOUNDED_TREATMENT_EMAIL_INVALID');
  const publishableKey = required(env.CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY,
    'CNYOS_BOUNDED_TREATMENT_SUPABASE_KEY_REQUIRED', 4096);
  if (!PUBLISHABLE_KEY.test(publishableKey)) {
    fail('CNYOS_BOUNDED_TREATMENT_SUPABASE_KEY_INVALID');
  }
  const rawFixture = required(env.CNYOS_STAGING_TREATMENT_FIXTURE_JSON,
    'CNYOS_BOUNDED_TREATMENT_FIXTURE_REQUIRED', MAX_JSON_BYTES);
  let fixture;
  try { fixture = JSON.parse(rawFixture); }
  catch { fail('CNYOS_BOUNDED_TREATMENT_FIXTURE_INVALID'); }
  const ledgerFile = await readProtectedFixtureLedger(env);
  const config = {
    runId,
    sourceCommit: exact(env.CNYOS_EXPECTED_SOURCE_COMMIT, SHA40,
      'CNYOS_BOUNDED_TREATMENT_SOURCE_COMMIT_INVALID'),
    sourceTree: exact(env.CNYOS_EXPECTED_SOURCE_TREE, SHA40,
      'CNYOS_BOUNDED_TREATMENT_SOURCE_TREE_INVALID'),
    deployId: exact(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, DEPLOY_ID,
      'CNYOS_BOUNDED_TREATMENT_DEPLOY_ID_INVALID'),
    practitionerEmail,
    publishableKey,
    password: required(env.CNYOS_STAGING_TEST_PASSWORD,
      'CNYOS_BOUNDED_TREATMENT_PASSWORD_REQUIRED', 4096),
    netlifyToken: required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN,
      'CNYOS_BOUNDED_TREATMENT_NETLIFY_TOKEN_REQUIRED', 8192),
    evidencePath: path.resolve(required(env.CNYOS_CONTROLLER_UAT_EVIDENCE_PATH,
      'CNYOS_BOUNDED_TREATMENT_EVIDENCE_PATH_REQUIRED', 4096))
  };
  if (env.CNYOS_TREATMENT_UAT_ACK !== BOUNDED_TREATMENT_ACK) {
    fail('CNYOS_BOUNDED_TREATMENT_ACK_REQUIRED');
  }
  config.fixture = validateTreatmentFixture(fixture, { runId, practitionerEmail });
  config.immutableOrigin = `https://${config.deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`;
  const protectedLedger = validateProtectedFixtureLedger(ledgerFile.value, {
    fixture: config.fixture,
    sourceCommit: config.sourceCommit,
    sourceTree: config.sourceTree,
    deployId: config.deployId,
    now: now()
  });
  config.protectedLedger = Object.freeze({
    ...protectedLedger,
    sourceFileSha256: ledgerFile.sourceFileSha256,
    expectedFileSha256: ledgerFile.expectedFileSha256
  });
  return Object.freeze(config);
}

async function responseBytes(response, maximum, code) {
  if (!response?.body?.getReader) fail(code);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) { await reader.cancel().catch(() => {}); fail(code); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks);
}

async function jsonGet(fetchImpl, url, { token = null, maximum = MAX_JSON_BYTES } = {}) {
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET', redirect: 'error', cache: 'no-store',
      headers: { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      signal: AbortSignal.timeout(20_000)
    });
  } catch { fail('CNYOS_BOUNDED_TREATMENT_PREFLIGHT_REQUEST_FAILED'); }
  if (response.status !== 200) fail('CNYOS_BOUNDED_TREATMENT_PREFLIGHT_STATUS_INVALID');
  const bytes = await responseBytes(response, maximum,
    'CNYOS_BOUNDED_TREATMENT_PREFLIGHT_RESPONSE_TOO_LARGE');
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_BOUNDED_TREATMENT_PREFLIGHT_JSON_INVALID'); }
  return Object.freeze({ value, bytes });
}

function validateDeploymentManifest(manifest, config) {
  exactKeys(manifest, ['schemaVersion', 'deploymentId', 'tenant', 'identity', 'source', 'build', 'safety'],
    'CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_INVALID');
  exactKeys(manifest.source, ['commit', 'tree', 'verified'],
    'CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_INVALID');
  exactKeys(manifest.tenant, ['expectedClinicId', 'expectedClinicCode'],
    'CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_INVALID');
  exactKeys(manifest.safety,
    ['previewLocked', 'databaseLocked', 'stagingDatabaseExplicitlyAcknowledged'],
    'CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_INVALID');
  if (manifest.schemaVersion !== 1 || manifest.deploymentId !== 'chananya-clinical-staging' ||
    String(manifest.source.commit || '').toLowerCase() !== config.sourceCommit ||
    String(manifest.source.tree || '').toLowerCase() !== config.sourceTree ||
    manifest.source.verified !== true ||
    String(manifest.tenant.expectedClinicId || '').toLowerCase() !== BOUNDED_TREATMENT_TARGET.clinicId ||
    manifest.tenant.expectedClinicCode !== BOUNDED_TREATMENT_TARGET.clinicCode ||
    manifest.safety.previewLocked !== false || manifest.safety.databaseLocked !== false ||
    manifest.safety.stagingDatabaseExplicitlyAcknowledged !== true) {
    fail('CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_INVALID');
  }
  return manifest;
}

export async function preflightExactDeployment(config, { fetchImpl = fetch } = {}) {
  const site = (await jsonGet(fetchImpl,
    `${NETLIFY_API}/sites/${BOUNDED_TREATMENT_TARGET.netlifySiteId}`,
    { token: config.netlifyToken })).value;
  if (!isPlainObject(site) || String(site.id || '').toLowerCase() !==
    BOUNDED_TREATMENT_TARGET.netlifySiteId || site.name !== BOUNDED_TREATMENT_TARGET.netlifySiteName ||
    site.ssl_url !== BOUNDED_TREATMENT_TARGET.origin ||
    String(site.published_deploy?.id || '').toLowerCase() !== config.deployId) {
    fail('CNYOS_BOUNDED_TREATMENT_PUBLISHED_DEPLOY_MISMATCH');
  }

  const deploy = (await jsonGet(fetchImpl,
    `${NETLIFY_API}/deploys/${config.deployId}`, { token: config.netlifyToken })).value;
  if (!isPlainObject(deploy) || String(deploy.id || '').toLowerCase() !== config.deployId ||
    String(deploy.site_id || '').toLowerCase() !== BOUNDED_TREATMENT_TARGET.netlifySiteId ||
    deploy.state !== 'ready' || deploy.context !== 'production' ||
    (deploy.deploy_ssl_url || deploy.deploy_url) !== config.immutableOrigin ||
    !Number.isFinite(Date.parse(deploy.published_at || ''))) {
    fail('CNYOS_BOUNDED_TREATMENT_DEPLOY_METADATA_MISMATCH');
  }
  if (deploy.commit_ref != null && String(deploy.commit_ref).toLowerCase() !== config.sourceCommit) {
    fail('CNYOS_BOUNDED_TREATMENT_DEPLOY_COMMIT_MISMATCH');
  }

  const files = (await jsonGet(fetchImpl,
    `${NETLIFY_API}/deploys/${config.deployId}/files`,
    { token: config.netlifyToken, maximum: 2 * 1024 * 1024 })).value;
  if (!Array.isArray(files) || files.length < 1 || files.length > 10_000) {
    fail('CNYOS_BOUNDED_TREATMENT_DEPLOY_FILES_INVALID');
  }
  const manifestFile = files.find(file =>
    file?.path === '/deploy-manifest.json' || file?.path === 'deploy-manifest.json');
  if (!manifestFile || !/^[0-9a-f]{40}$/i.test(String(manifestFile.sha || ''))) {
    fail('CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_FILE_INVALID');
  }

  const manifestResult = await jsonGet(fetchImpl,
    `${config.immutableOrigin}/deploy-manifest.json`);
  if (sha1(manifestResult.bytes) !== String(manifestFile.sha).toLowerCase()) {
    fail('CNYOS_BOUNDED_TREATMENT_DEPLOY_MANIFEST_CROSS_BINDING_FAILED');
  }
  validateDeploymentManifest(manifestResult.value, config);
  return Object.freeze({
    siteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
    deployId: config.deployId,
    immutableOrigin: config.immutableOrigin,
    publishedAt: deploy.published_at,
    manifestFileSha1: String(manifestFile.sha).toLowerCase(),
    manifestSha256: hash(manifestResult.bytes),
    sourceCommit: config.sourceCommit,
    sourceTree: config.sourceTree
  });
}

export async function recheckCanonicalPublication(config, deployment, { fetchImpl = fetch } = {}) {
  const site = (await jsonGet(fetchImpl,
    `${NETLIFY_API}/sites/${BOUNDED_TREATMENT_TARGET.netlifySiteId}`,
    { token: config.netlifyToken })).value;
  if (!isPlainObject(site) || String(site.id || '').toLowerCase() !==
      BOUNDED_TREATMENT_TARGET.netlifySiteId || site.name !== BOUNDED_TREATMENT_TARGET.netlifySiteName ||
    site.ssl_url !== BOUNDED_TREATMENT_TARGET.origin ||
    String(site.published_deploy?.id || '').toLowerCase() !== deployment.deployId) {
    fail('CNYOS_BOUNDED_TREATMENT_CANONICAL_PUBLICATION_CHANGED');
  }
  const manifestResult = await jsonGet(fetchImpl,
    `${BOUNDED_TREATMENT_TARGET.origin}/deploy-manifest.json`);
  if (sha1(manifestResult.bytes) !== deployment.manifestFileSha1 ||
    hash(manifestResult.bytes) !== deployment.manifestSha256) {
    fail('CNYOS_BOUNDED_TREATMENT_CANONICAL_PUBLICATION_CHANGED');
  }
  validateDeploymentManifest(manifestResult.value, config);
  return Object.freeze({
    deployId: deployment.deployId,
    observedAt: new Date().toISOString(),
    manifestSha256: deployment.manifestSha256
  });
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function matchesExactSearch(parsed, expectedEntries) {
  const normalize = entries => entries.map(([key, value]) => `${key}\u0000${value}`).sort();
  return sameJson(normalize([...parsed.searchParams.entries()]), normalize(expectedEntries));
}

function exactEmptyObjectBody(postData) {
  let value;
  try { value = JSON.parse(postData || ''); }
  catch { return false; }
  return isPlainObject(value) && Object.keys(value).length === 0;
}

function exactPasswordLoginBody(postData, scope) {
  let value;
  try { value = JSON.parse(postData || ''); }
  catch { return false; }
  return isPlainObject(value) &&
    sameJson(Object.keys(value).sort(), ['email', 'gotrue_meta_security', 'password']) &&
    value.email === scope.practitionerEmail && value.password === scope.password &&
    isPlainObject(value.gotrue_meta_security) &&
    Object.keys(value.gotrue_meta_security).length === 0;
}

function normalizeRequestHeaders(headers) {
  const entries = Array.isArray(headers)
    ? headers.map(item => [item?.name, item?.value])
    : isPlainObject(headers) ? Object.entries(headers) : null;
  if (!entries || entries.length > 48) return null;
  const normalized = {};
  for (const [rawName, rawValue] of entries) {
    const name = String(rawName).toLowerCase();
    const value = String(rawValue);
    if (!/^[a-z0-9-]+$/.test(name) || name in normalized || value.length > 16_384 ||
      /[\r\n]/.test(value)) return null;
    normalized[name] = value;
  }
  return normalized;
}

function exactHeaderNameSet(value, expected) {
  if (typeof value !== 'string') return false;
  const names = value.split(',').map(item => item.trim().toLowerCase());
  return names.length === expected.size && new Set(names).size === names.length &&
    names.every(name => expected.has(name));
}

export class TreatmentWriteLedger {
  constructor(scope) {
    this.scope = scope;
    this.writes = [];
    this.expected = null;
    this.violation = null;
    this.records = new Map();
    this.anonKey = PUBLISHABLE_KEY.test(String(scope.publishableKey || ''))
      ? scope.publishableKey
      : null;
    this.accessTokenSha256 = null;
  }

  checkedHeaders(parsed, resourceType, headers, expectedResourceType, semanticHeaders,
    { preflight = false, api = false } = {}) {
    if (resourceType !== expectedResourceType) {
      this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_RESOURCE_TYPE_INVALID');
      return null;
    }
    const normalized = normalizeRequestHeaders(headers);
    if (!normalized) {
      this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      return null;
    }
    if (normalized['accept-language'] !== BROWSER_LOCALE) {
      this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      return null;
    }
    const allowedSemantic = new Set(semanticHeaders);
    for (const name of Object.keys(normalized)) {
      if (BROWSER_MANAGED_HEADERS.has(name) || allowedSemantic.has(name) ||
        (preflight && PREFLIGHT_HEADERS.has(name))) continue;
      this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      return null;
    }
    const observedSemantic = Object.keys(normalized).filter(name => API_SEMANTIC_HEADERS.has(name));
    if (observedSemantic.length !== allowedSemantic.size ||
      observedSemantic.some(name => !allowedSemantic.has(name))) {
      this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      return null;
    }
    if (normalized.host && normalized.host !== parsed.host) {
      this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      return null;
    }
    if (api) {
      if (normalized.origin !== this.scope.appOrigin || normalized.accept !== '*/*' ||
        normalized['sec-fetch-dest'] !== 'empty' ||
        normalized['sec-fetch-mode'] !== 'cors' ||
        normalized['sec-fetch-site'] !== 'cross-site') {
        this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
        return null;
      }
      if (normalized.referer && normalized.referer !== `${this.scope.appOrigin}/`) {
        this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
        return null;
      }
    }
    return normalized;
  }

  latchAnonKey(value) {
    if (value !== this.scope.publishableKey || !PUBLISHABLE_KEY.test(String(value || '')) ||
      String(value).length > 4096) {
      return this.block('CNYOS_BOUNDED_TREATMENT_SUPABASE_KEY_INVALID');
    }
    if (this.anonKey && this.anonKey !== value) {
      return this.block('CNYOS_BOUNDED_TREATMENT_SUPABASE_KEY_CHANGED');
    }
    this.anonKey = value;
    return null;
  }

  loginResponse(status, bodyBytes) {
    if (status < 200 || status >= 300 || bodyBytes == null) {
      return this.block('CNYOS_BOUNDED_TREATMENT_LOGIN_RESPONSE_INVALID');
    }
    const bytes = Buffer.from(bodyBytes);
    if (bytes.length < 2 || bytes.length > MAX_JSON_BYTES) {
      return this.block('CNYOS_BOUNDED_TREATMENT_LOGIN_RESPONSE_INVALID');
    }
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); }
    catch { return this.block('CNYOS_BOUNDED_TREATMENT_LOGIN_RESPONSE_INVALID'); }
    const accessToken = String(value?.access_token || '');
    if (!ACCESS_TOKEN.test(accessToken) || accessToken.length > 8192 ||
      String(value?.user?.id || '').toLowerCase() !== this.scope.practitionerUserId ||
      String(value?.user?.email || '').toLowerCase() !== this.scope.practitionerEmail) {
      return this.block('CNYOS_BOUNDED_TREATMENT_LOGIN_RESPONSE_INVALID');
    }
    this.accessTokenSha256 = hash(`Bearer ${accessToken}`);
    return null;
  }

  exactApiIdentityHeaders(headers) {
    const observedAuthorizationSha256 = hash(String(headers.authorization || ''));
    const expectedAuthorizationSha256 = this.accessTokenSha256;
    const authorizationMatches = Boolean(expectedAuthorizationSha256 &&
      crypto.timingSafeEqual(
        Buffer.from(observedAuthorizationSha256, 'hex'),
        Buffer.from(expectedAuthorizationSha256, 'hex')
      ));
    return Boolean(this.anonKey && authorizationMatches &&
      headers.apikey === this.anonKey && headers['x-client-info'] === SUPABASE_CLIENT_INFO);
  }

  begin(session, phase) {
    if (this.violation) fail(this.violation);
    if (this.expected || !session || !/^write-[12]$/.test(phase)) {
      fail('CNYOS_BOUNDED_TREATMENT_WRITE_PHASE_INVALID');
    }
    this.expected = Object.freeze({ session, phase });
  }

  finish() { this.expected = null; }

  inspect({ url, method, postData, headers = {}, resourceType }) {
    let parsed;
    try { parsed = new URL(url); }
    catch { return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_URL_INVALID'); }
    const normalizedMethod = String(method || '').toUpperCase();
    if (parsed.origin === this.scope.appOrigin) {
      const expectedClinicalQuery = [
        ['encounter', this.scope.encounterId],
        ['step', 'treatment']
      ];
      const staticQueries = APP_RESOURCE_QUERIES.get(parsed.pathname);
      const exactAppResource = staticQueries?.has(parsed.search) ||
        (parsed.pathname === '/clinical-v3.html' &&
          matchesExactSearch(parsed, expectedClinicalQuery));
      if (normalizedMethod === 'GET' && exactAppResource && !parsed.hash) {
        const expectedResourceType = parsed.pathname.endsWith('.html') ? 'document' :
          parsed.pathname.endsWith('.css') ? 'stylesheet' :
            parsed.pathname.endsWith('.svg') ? 'image' : 'script';
        if (!this.checkedHeaders(parsed, resourceType, headers, expectedResourceType, [])) {
          return Object.freeze({ allow: false, code: this.violation });
        }
        return Object.freeze({ allow: true, kind: 'immutable-app-resource' });
      }
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_RESOURCE_BLOCKED');
    }
    if (parsed.origin === 'https://cdn.jsdelivr.net') {
      if (normalizedMethod === 'GET' && parsed.pathname === CDN_RESOURCE_PATH &&
        !parsed.search && !parsed.hash) {
        const checked = this.checkedHeaders(parsed, resourceType, headers, 'script', []);
        if (!checked || checked.origin !== this.scope.appOrigin || checked.accept !== '*/*' ||
          checked['sec-fetch-dest'] !== 'script' || checked['sec-fetch-mode'] !== 'cors' ||
          checked['sec-fetch-site'] !== 'cross-site' ||
          (checked.referer && checked.referer !== `${this.scope.appOrigin}/`)) {
          this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
          return Object.freeze({ allow: false, code: this.violation });
        }
        return Object.freeze({ allow: true, kind: 'pinned-cdn-resource' });
      }
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_RESOURCE_BLOCKED');
    }
    if (parsed.origin !== BOUNDED_TREATMENT_TARGET.supabaseOrigin) {
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_ORIGIN_BLOCKED');
    }
    if (normalizedMethod === 'GET' && !parsed.search && parsed.pathname === '/auth/v1/settings') {
      const checked = this.checkedHeaders(parsed, resourceType, headers, 'fetch', ['apikey'],
        { api: true });
      if (!checked) return Object.freeze({ allow: false, code: this.violation });
      const keyFailure = this.latchAnonKey(checked.apikey);
      if (keyFailure) return keyFailure;
      return Object.freeze({ allow: true, kind: 'auth-read' });
    }
    if (['GET', 'HEAD'].includes(normalizedMethod) && parsed.pathname.startsWith('/rest/v1/')) {
      const table = parsed.pathname.slice('/rest/v1/'.length);
      if (!SUPABASE_READ_TABLES.has(table)) {
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_PATH_BLOCKED');
      }
      const semanticHeaders = ['accept-profile', 'apikey', 'authorization', 'x-client-info'];
      if (normalizedMethod === 'HEAD') semanticHeaders.push('prefer');
      const checked = this.checkedHeaders(parsed, resourceType, headers, 'fetch', semanticHeaders,
        { api: true });
      if (!checked || !this.exactApiIdentityHeaders(checked) ||
        checked['accept-profile'] !== 'public' ||
        (normalizedMethod === 'HEAD' ? checked.prefer !== 'count=exact' : 'prefer' in checked)) {
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      }
      const scoped = this.scopeRead(parsed, normalizedMethod);
      if (!scoped.allow) return scoped;
      return Object.freeze({ allow: true, kind: 'read', continueUrl: scoped.continueUrl });
    }
    if (normalizedMethod === 'OPTIONS') {
      if (postData != null && postData !== '') {
        return this.block('CNYOS_BOUNDED_TREATMENT_PREFLIGHT_BODY_INVALID');
      }
      const checked = this.checkedHeaders(parsed, resourceType, headers, 'fetch', [],
        { preflight: true, api: true });
      if (!checked) return Object.freeze({ allow: false, code: this.violation });
      const requestedMethod = String(checked['access-control-request-method'] || '').toUpperCase();
      const requestedHeaders = checked['access-control-request-headers'];
      if (parsed.pathname === '/auth/v1/token' &&
        matchesExactSearch(parsed, [['grant_type', 'password']])) {
        if (requestedMethod === 'POST' && exactHeaderNameSet(requestedHeaders, new Set([
          'apikey', 'authorization', 'content-type', 'x-client-info', 'x-supabase-api-version'
        ]))) return Object.freeze({ allow: true, kind: 'cors-preflight' });
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      }
      if (parsed.pathname === '/auth/v1/settings' && !parsed.search) {
        if (requestedMethod === 'GET' &&
          exactHeaderNameSet(requestedHeaders, new Set(['apikey']))) {
          return Object.freeze({ allow: true, kind: 'cors-preflight' });
        }
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      }
      if ((READ_ONLY_RPC_PATHS.has(parsed.pathname) || parsed.pathname === TREATMENT_RPC_PATH) &&
        !parsed.search) {
        if (requestedMethod === 'POST' && exactHeaderNameSet(requestedHeaders, new Set([
          'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info'
        ]))) return Object.freeze({ allow: true, kind: 'cors-preflight' });
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      }
      if (parsed.pathname.startsWith('/rest/v1/')) {
        const table = parsed.pathname.slice('/rest/v1/'.length);
        if (!SUPABASE_READ_TABLES.has(table)) {
          return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_PATH_BLOCKED');
        }
        if (!['GET', 'HEAD'].includes(requestedMethod)) {
          return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_PATH_BLOCKED');
        }
        const expectedHeaders = new Set([
          'accept-profile', 'apikey', 'authorization', 'x-client-info',
          ...(requestedMethod === 'HEAD' ? ['prefer'] : [])
        ]);
        if (!exactHeaderNameSet(requestedHeaders, expectedHeaders)) {
          return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
        }
        const scoped = this.scopeRead(parsed, requestedMethod);
        if (!scoped.allow) return scoped;
        return Object.freeze({ allow: true, kind: 'cors-preflight',
          continueUrl: scoped.continueUrl });
      }
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_PATH_BLOCKED');
    }
    if (normalizedMethod !== 'POST') {
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_MUTATION_BLOCKED');
    }
    if (parsed.pathname === '/auth/v1/token' &&
      matchesExactSearch(parsed, [['grant_type', 'password']])) {
      const checked = this.checkedHeaders(parsed, resourceType, headers, 'fetch', [
        'apikey', 'authorization', 'content-type', 'x-client-info', 'x-supabase-api-version'
      ], { api: true });
      if (!checked || !this.anonKey || checked.apikey !== this.anonKey ||
        checked.authorization !== `Bearer ${this.anonKey}` ||
        checked['content-type'].toLowerCase() !== 'application/json;charset=utf-8' ||
        checked['x-client-info'] !== SUPABASE_CLIENT_INFO ||
        checked['x-supabase-api-version'] !== SUPABASE_AUTH_API_VERSION) {
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      }
      return exactPasswordLoginBody(postData, this.scope)
        ? Object.freeze({ allow: true, kind: 'login' })
        : this.block('CNYOS_BOUNDED_TREATMENT_LOGIN_BODY_INVALID');
    }
    if (READ_ONLY_RPC_PATHS.has(parsed.pathname)) {
      const checked = this.checkedHeaders(parsed, resourceType, headers, 'fetch', [
        'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info'
      ], { api: true });
      if (!checked || !this.exactApiIdentityHeaders(checked) ||
        checked['content-profile'] !== 'public' ||
        checked['content-type'].toLowerCase() !== 'application/json') {
        return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      }
      if (!parsed.search && exactEmptyObjectBody(postData)) {
        return Object.freeze({ allow: true, kind: 'read-rpc' });
      }
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_RPC_INVALID');
    }
    if (parsed.pathname !== TREATMENT_RPC_PATH || parsed.search) {
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_RPC_BLOCKED');
    }
    const checked = this.checkedHeaders(parsed, resourceType, headers, 'fetch', [
      'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info'
    ], { api: true });
    if (!checked || !this.exactApiIdentityHeaders(checked) ||
      checked['content-profile'] !== 'public' ||
      checked['content-type'].toLowerCase() !== 'application/json') {
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
    }
    if (this.violation || !this.expected || this.writes.length >= 2) {
      return this.block('CNYOS_BOUNDED_TREATMENT_UNPLANNED_WRITE_BLOCKED');
    }
    let payload;
    try { payload = JSON.parse(postData || ''); }
    catch { return this.block('CNYOS_BOUNDED_TREATMENT_WRITE_PAYLOAD_INVALID'); }
    const expectedPayload = sessionPayload(this.expected.session,
      this.scope.encounterId);
    if (!sameJson(payload, expectedPayload) ||
      this.writes.some(write => write.operationId === payload.p_client_request_id)) {
      return this.block('CNYOS_BOUNDED_TREATMENT_WRITE_PAYLOAD_MISMATCH');
    }
    const record = {
      ordinal: this.writes.length + 1,
      phase: this.expected.phase,
      operationId: payload.p_client_request_id,
      payloadSha256: hash(Buffer.from(JSON.stringify(payload))),
      responseStatus: null,
      rowId: null,
      requestFailed: false
    };
    this.writes.push(record);
    this.records.set(payload.p_client_request_id, record);
    return Object.freeze({ allow: true, kind: 'treatment-write', record });
  }

  response(operationId, status, bodyBytes = null) {
    const record = this.records.get(operationId);
    if (!record) return;
    record.responseStatus = status;
    if (status < 200 || status >= 300 || bodyBytes == null) return;
    const bytes = Buffer.from(bodyBytes);
    if (bytes.length < 2 || bytes.length > MAX_JSON_BYTES) {
      return this.block('CNYOS_BOUNDED_TREATMENT_WRITE_RESPONSE_INVALID');
    }
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); }
    catch { return this.block('CNYOS_BOUNDED_TREATMENT_WRITE_RESPONSE_INVALID'); }
    const row = Array.isArray(value) && value.length === 1 ? value[0] : value;
    if (!isPlainObject(row) || !UUID.test(String(row.id || '')) ||
      String(row.encounter_id || '').toLowerCase() !== this.scope.encounterId ||
      String(row.client_request_id || '').toLowerCase() !== operationId ||
      String(row.practitioner_id || '').toLowerCase() !== this.scope.practitionerUserId) {
      return this.block('CNYOS_BOUNDED_TREATMENT_WRITE_RESPONSE_INVALID');
    }
    record.rowId = String(row.id).toLowerCase();
  }

  failed(operationId) {
    const record = this.records.get(operationId);
    if (record) record.requestFailed = true;
  }

  block(code) {
    this.violation ||= code;
    return Object.freeze({ allow: false, code });
  }

  scopeRead(parsed, method) {
    const table = parsed.pathname.slice('/rest/v1/'.length);
    const match = entries => matchesExactSearch(parsed, entries);
    const accept = (entries, code = 'CNYOS_BOUNDED_TREATMENT_BROWSER_READ_QUERY_INVALID') =>
      match(entries) ? Object.freeze({ allow: true, continueUrl: parsed.href }) : this.block(code);
    const scoped = (variants, filterName, filterValue, { inject = false, code, block = true } = {}) => {
      for (const variant of variants) {
        if (match([...variant, [filterName, `eq.${filterValue}`]])) {
          return Object.freeze({ allow: true, continueUrl: parsed.href });
        }
        if (inject && match(variant)) {
          const rewritten = new URL(parsed);
          rewritten.searchParams.set(filterName, `eq.${filterValue}`);
          return Object.freeze({ allow: true, continueUrl: rewritten.href });
        }
      }
      return block
        ? this.block(code || 'CNYOS_BOUNDED_TREATMENT_BROWSER_READ_QUERY_INVALID')
        : Object.freeze({ allow: false });
    };
    if (method === 'HEAD') {
      if (['clinical_examination_findings', 'clinical_treatment_plans',
        'clinical_treatment_sessions'].includes(table) &&
        match([['select', 'id'], ['encounter_id', `eq.${this.scope.encounterId}`]])) {
        return Object.freeze({ allow: true, continueUrl: parsed.href });
      }
      return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_QUERY_INVALID');
    }
    if (table === 'patients') {
      return scoped([
        [['select', '*'], ['order', 'created_at.desc'], ['limit', '500']],
        [['select', 'id,hn,national_id,phone,email,payment_right']],
        [['select', 'id,hn,prefix,first_name,last_name,date_of_birth,gender']]
      ], 'id', this.scope.patientId, { inject: true,
        code: 'CNYOS_BOUNDED_TREATMENT_PATIENT_READ_SCOPE_INVALID' });
    }
    if (table === 'encounters') {
      return scoped([
        [['select', 'id,encounter_no,patient_id,chief_complaint,thai_diagnosis,started_at,status'],
          ['order', 'started_at.desc'], ['limit', '250']],
        [['select', 'id,patient_id,status,practitioner_id,clinic_id']],
        [['select', 'id,encounter_no,patient_id,chief_complaint,red_flags,general_examination,started_at,status']]
      ], 'id', this.scope.encounterId, { inject: true,
        code: 'CNYOS_BOUNDED_TREATMENT_ENCOUNTER_READ_SCOPE_INVALID' });
    }
    if (table === 'profiles') {
      return scoped([[['select', 'id,role,system_role,full_name,email']]], 'id',
        this.scope.practitionerUserId, { code: 'CNYOS_BOUNDED_TREATMENT_PROFILE_READ_SCOPE_INVALID' });
    }
    if (table === 'patient_allergies') {
      return scoped([[['select', '*'], ['status', 'eq.active']]], 'patient_id',
        this.scope.patientId, { code: 'CNYOS_BOUNDED_TREATMENT_PATIENT_READ_SCOPE_INVALID' });
    }
    if (table === 'products') {
      return accept([['select', '*'], ['active', 'eq.true'], ['order', 'name_th.asc']]);
    }
    if (table === 'ttm_diagnostic_knowledge') {
      return accept([['select', '*'], ['active', 'eq.true'],
        ['order', 'domain.asc,rule_key.asc']]);
    }
    const encounterVariants = {
      body_pain_points: [
        [['select', '*'], ['order', 'recorded_at.asc']],
        [['select', '*'], ['order', 'recorded_at.desc']]
      ],
      clinical_examination_findings: [
        [['select', '*'], ['order', 'sequence_no.asc']]
      ],
      clinical_record_signoffs: [
        [['select', 'id,lock_record'], ['record_section', 'eq.complete_record']],
        [['select', 'signed_at,lock_record,signer_name'], ['record_section', 'eq.complete_record']],
        [['select', 'signer_name,professional_license_no,signed_at,lock_record,reason'],
          ['record_section', 'eq.complete_record']]
      ],
      clinical_treatment_plans: [
        [['select', '*'], ['order', 'created_at.desc'], ['limit', '1']],
        [['select', 'id'], ['order', 'created_at.desc'], ['limit', '1']]
      ],
      prescriptions: [[
        ['select', 'id,prescription_no,prescribed_at,status,clinical_notes,sent_to_pharmacy_at'],
        ['order', 'prescribed_at.desc'], ['limit', '1']
      ]],
      ttm_opd_histories: [[['select', 'id']], [['select', '*']]],
      ttm_structured_diagnoses: [[['select', '*']], [['select', 'id']],
        [['select', 'id'], ['limit', '1']]]
    };
    if (table === 'clinical_treatment_sessions') {
      const variants = [
        [['select', 'id']],
        [['select', 'id'], ['limit', '1']],
        [['select', 'id,client_request_id'], ['order', 'session_no.asc']],
        [['select', '*'], ['order', 'session_no.asc']]
      ];
      const scopedResult = scoped(variants, 'encounter_id', this.scope.encounterId, {
        code: 'CNYOS_BOUNDED_TREATMENT_ENCOUNTER_READ_SCOPE_INVALID', block: false
      });
      if (scopedResult.allow) return scopedResult;
      const operationIds = new Set([...this.records.keys()]);
      for (const operationId of operationIds) {
        if (match([['select', '*'], ['encounter_id', `eq.${this.scope.encounterId}`],
          ['client_request_id', `eq.${operationId}`]])) {
          return Object.freeze({ allow: true, continueUrl: parsed.href });
        }
      }
      const rowIds = new Set([...this.records.values()].map(record => record.rowId).filter(Boolean));
      for (const rowId of rowIds) {
        if (match([['select', '*'], ['encounter_id', `eq.${this.scope.encounterId}`],
          ['id', `eq.${rowId}`]])) {
          return Object.freeze({ allow: true, continueUrl: parsed.href });
        }
      }
      return this.block('CNYOS_BOUNDED_TREATMENT_ENCOUNTER_READ_SCOPE_INVALID');
    }
    if (encounterVariants[table]) {
      return scoped(encounterVariants[table], 'encounter_id', this.scope.encounterId, {
        code: 'CNYOS_BOUNDED_TREATMENT_ENCOUNTER_READ_SCOPE_INVALID'
      });
    }
    return this.block('CNYOS_BOUNDED_TREATMENT_BROWSER_READ_PATH_BLOCKED');
  }

  assertFinal() {
    if (this.violation) fail(this.violation);
    if (this.writes.length !== 2 ||
      this.writes[0].operationId === this.writes[1].operationId ||
      !this.writes.every((write, index) => write.ordinal === index + 1 &&
        write.phase === `write-${index + 1}`)) {
      fail('CNYOS_BOUNDED_TREATMENT_WRITE_COUNT_INVALID');
    }
    return true;
  }
}

function expectedRow(row, fixture, session, ordinal) {
  return isPlainObject(row) && exactUuid(row.encounter_id,
    'CNYOS_BOUNDED_TREATMENT_READBACK_INVALID') === fixture.encounter.id &&
    exactUuid(row.client_request_id,
      'CNYOS_BOUNDED_TREATMENT_READBACK_INVALID') === session.operationId &&
    exactUuid(row.practitioner_id,
      'CNYOS_BOUNDED_TREATMENT_READBACK_INVALID') === fixture.practitioner.userId &&
    Number(row.session_no) === ordinal &&
    sameJson(row.treatment_modalities, session.modalities) &&
    row.treatment_detail === session.treatmentDetail &&
    row.procedure_referral === session.procedureReferral &&
    (row.procedure_referral_detail ?? null) === session.procedureReferralDetail &&
    (row.precautions ?? null) === session.precautions &&
    Number(row.pain_before) === session.painBefore && Number(row.pain_after) === session.painAfter &&
    (row.outcome_summary ?? null) === session.outcomeSummary &&
    (row.advice ?? null) === session.advice;
}

export async function reconcileAmbiguousOperation({ readOnce, fixture, session, ordinal }) {
  try {
    const row = await readOnce(session.operationId);
    if (row == null) return Object.freeze({ result: 'NOT_FOUND', operationId: session.operationId });
    return Object.freeze({
      result: expectedRow(row, fixture, session, ordinal) ? 'APPLIED' : 'CONFLICT',
      operationId: session.operationId,
      rowId: typeof row.id === 'string' ? row.id : null
    });
  } catch {
    return Object.freeze({ result: 'UNKNOWN', operationId: session.operationId });
  }
}

async function browserRequestDescriptor(request) {
  const rawHeaders = await request.headersArray();
  if (!Array.isArray(rawHeaders)) {
    return Object.freeze({ valid: false, code: 'CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID' });
  }
  const priorityHeaders = rawHeaders.filter(header =>
    String(header?.name || '').toLowerCase() === 'priority');
  const resourceType = request.resourceType();
  const allowedPriorities = CHROMIUM_PRIORITY_VALUES.get(resourceType);
  if (priorityHeaders.length > 1 ||
    (priorityHeaders.length === 1 &&
      !allowedPriorities?.has(String(priorityHeaders[0]?.value || '')))) {
    return Object.freeze({ valid: false, code: 'CNYOS_BOUNDED_TREATMENT_PRIORITY_INVALID' });
  }
  const headers = rawHeaders.filter(header =>
    String(header?.name || '').toLowerCase() !== 'priority');
  const dispatchHeaders = Object.create(null);
  for (const header of headers) dispatchHeaders[String(header?.name || '')] = String(header?.value || '');
  return Object.freeze({
    valid: true,
    descriptor: Object.freeze({
      url: request.url(), method: request.method(), postData: request.postData(),
      headers, resourceType
    }),
    dispatchHeaders: Object.freeze(dispatchHeaders)
  });
}

export async function installNetworkGuard(context, ledger) {
  await context.addInitScript(() => {
    class BlockedWebSocket {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSING = 2;
      static CLOSED = 3;
      constructor() { throw new DOMException('WebSocket disabled for bounded UAT', 'SecurityError'); }
    }
    Object.defineProperty(globalThis, 'WebSocket', {
      value: BlockedWebSocket,
      configurable: false,
      enumerable: false,
      writable: false
    });
  });
  if (typeof context.routeWebSocket === 'function') {
    await context.routeWebSocket('**/*', webSocketRoute => {
      ledger.block('CNYOS_BOUNDED_TREATMENT_WEBSOCKET_BLOCKED');
      webSocketRoute.close();
    });
  }
  await context.route('**/*', async route => {
    let prepared;
    try { prepared = await browserRequestDescriptor(route.request()); }
    catch {
      ledger.block('CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
      await route.abort('blockedbyclient');
      return;
    }
    if (!prepared.valid) {
      ledger.block(prepared.code);
      await route.abort('blockedbyclient');
      return;
    }
    const decision = ledger.inspect(prepared.descriptor);
    if (!decision.allow) { await route.abort('blockedbyclient'); return; }
    if (decision.kind === 'login') {
      try {
        const response = await route.fetch({ headers: prepared.dispatchHeaders,
          maxRedirects: 0, maxRetries: 0 });
        const body = await response.body();
        ledger.loginResponse(response.status(), body);
        await route.fulfill({ response, body });
      } catch {
        ledger.block('CNYOS_BOUNDED_TREATMENT_LOGIN_RESPONSE_INVALID');
        await route.abort('failed');
      }
      return;
    }
    if (decision.kind === 'treatment-write') {
      const operationId = decision.record.operationId;
      try {
        const response = await route.fetch({ headers: prepared.dispatchHeaders,
          maxRedirects: 0, maxRetries: 0 });
        const body = await response.body();
        ledger.response(operationId, response.status(), body);
        await route.fulfill({ response, body });
      } catch {
        ledger.failed(operationId);
        await route.abort('failed');
      }
      return;
    }
    await route.continue({
      ...(decision.continueUrl ? { url: decision.continueUrl } : {}),
      headers: prepared.dispatchHeaders
    });
  });
  context.on('websocket', websocket => {
    ledger.block('CNYOS_BOUNDED_TREATMENT_WEBSOCKET_BLOCKED');
    if (typeof websocket.close === 'function') websocket.close();
  });
}

async function login(page, config) {
  await page.goto(`${config.immutableOrigin}/login.html`, {
    waitUntil: 'domcontentloaded', timeout: 30_000
  });
  await page.waitForFunction(() => Boolean(window.supabase && window.CHANANYA_AUTH), null,
    { timeout: 20_000 });
  const result = await page.evaluate(async ({ email, password, expectedOrigin }) => {
    const auth = window.CHANANYA_AUTH || {};
    const url = auth.url || auth.supabaseUrl;
    const key = auth.anonKey || auth.publishableKey;
    if (url !== expectedOrigin || !key) return { ok: false };
    const client = window.supabase.createClient(url, key, {
      auth: { flowType: 'pkce', persistSession: true, autoRefreshToken: false,
        detectSessionInUrl: false }
    });
    const signed = await client.auth.signInWithPassword({ email, password });
    if (signed.error || !signed.data?.user?.id) return { ok: false };
    const user = signed.data.user;
    return {
      ok: true, userId: user.id, email: user.email || null,
      userSynthetic: user.user_metadata?.synthetic_staging_only === true,
      appSynthetic: user.app_metadata?.synthetic_staging_only === true
    };
  }, {
    email: config.practitionerEmail,
    password: config.password,
    expectedOrigin: BOUNDED_TREATMENT_TARGET.supabaseOrigin
  });
  if (!result?.ok || String(result.userId).toLowerCase() !== config.fixture.practitioner.userId ||
    String(result.email || '').toLowerCase() !== config.practitionerEmail ||
    result.userSynthetic !== true || result.appSynthetic !== true) {
    fail('CNYOS_BOUNDED_TREATMENT_PRACTITIONER_LOGIN_INVALID');
  }
}

async function openClinicalContext(browser, config, ledger) {
  const context = await browser.newContext({
    baseURL: config.immutableOrigin,
    locale: BROWSER_LOCALE,
    acceptDownloads: false,
    serviceWorkers: 'block'
  });
  await installNetworkGuard(context, ledger);
  const page = await context.newPage();
  page.on('dialog', dialog => dialog.dismiss());
  await login(page, config);
  const clinicalUrl = `${config.immutableOrigin}/clinical-v3.html?encounter=${
    encodeURIComponent(config.fixture.encounter.id)}&step=treatment`;
  await page.goto(clinicalUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.waitForSelector('#app:not(.hidden)', { timeout: 30_000 });
  await page.waitForFunction(encounterId =>
    document.querySelector('#encounter')?.value === encounterId &&
    !document.querySelector('#opd-session-form')?.hasAttribute('inert'),
  config.fixture.encounter.id, { timeout: 30_000 });

  const identity = await page.evaluate(async () => {
    const runtime = window.ChananyaRuntime;
    const session = await runtime?.getSession();
    const profile = session?.user?.id ? await runtime.getProfile(session.user.id) : null;
    return {
      userId: session?.user?.id || null,
      email: session?.user?.email || null,
      clinicId: profile?.clinic_id || null,
      clinicRole: profile?.clinic_role || profile?.role || null,
      effectiveRole: profile ? runtime.roleOf(profile) : null,
      accessContextReady: profile?.access_context_ready === true
    };
  });
  if (String(identity.userId || '').toLowerCase() !== config.fixture.practitioner.userId ||
    String(identity.email || '').toLowerCase() !== config.practitionerEmail ||
    String(identity.clinicId || '').toLowerCase() !== BOUNDED_TREATMENT_TARGET.clinicId ||
    identity.clinicRole !== 'practitioner' || identity.effectiveRole !== 'practitioner' ||
    identity.accessContextReady !== true) fail('CNYOS_BOUNDED_TREATMENT_ROLE_INVALID');
  return { context, page, identity };
}

async function browserFixturePreflight(page, fixture) {
  const result = await page.evaluate(async ({ patientId, encounterId }) => {
    const db = window.ChananyaRuntime.getDb();
    const [patient, encounter, sessions, prescriptions] = await Promise.all([
      db.from('patients').select('id,hn,national_id,phone,email,payment_right').eq('id', patientId).maybeSingle(),
      db.from('encounters').select('id,patient_id,status,practitioner_id,clinic_id').eq('id', encounterId).maybeSingle(),
      db.from('clinical_treatment_sessions').select('id,client_request_id').eq('encounter_id', encounterId).order('session_no'),
      db.from('prescriptions').select('id,prescription_no,prescribed_at,status,clinical_notes,sent_to_pharmacy_at')
        .eq('encounter_id', encounterId).order('prescribed_at', { ascending: false }).limit(1)
    ]);
    if (patient.error || encounter.error || sessions.error || prescriptions.error) return { ok: false };
    return { ok: true, patient: patient.data, encounter: encounter.data,
      sessions: sessions.data || [], prescriptions: prescriptions.data || [] };
  }, { patientId: fixture.patient.id, encounterId: fixture.encounter.id });
  if (!result?.ok || !result.patient || !result.encounter ||
    String(result.patient.id).toLowerCase() !== fixture.patient.id || result.patient.hn !== fixture.patient.hn ||
    result.patient.payment_right !== fixture.patient.paymentRight || result.patient.national_id != null ||
    result.patient.phone != null || result.patient.email != null ||
    String(result.encounter.id).toLowerCase() !== fixture.encounter.id ||
    String(result.encounter.patient_id).toLowerCase() !== fixture.patient.id ||
    String(result.encounter.practitioner_id).toLowerCase() !== fixture.practitioner.userId ||
    String(result.encounter.clinic_id).toLowerCase() !== BOUNDED_TREATMENT_TARGET.clinicId ||
    result.encounter.status !== fixture.encounter.status || result.sessions.length !== 0 ||
    result.prescriptions.length !== 0) {
    fail('CNYOS_BOUNDED_TREATMENT_LIVE_FIXTURE_INVALID');
  }
}

async function readSessions(page, fixture) {
  const result = await page.evaluate(async encounterId => {
    const response = await window.ChananyaRuntime.getDb()
      .from('clinical_treatment_sessions').select('*')
      .eq('encounter_id', encounterId).order('session_no');
    return response.error ? { ok: false } : { ok: true, rows: response.data || [] };
  }, fixture.encounter.id);
  if (!result?.ok || !Array.isArray(result.rows)) fail('CNYOS_BOUNDED_TREATMENT_READBACK_FAILED');
  return result.rows;
}

async function readOperation(page, fixture, operationId) {
  const result = await page.evaluate(async ({ encounterId, operationId }) => {
    const response = await window.ChananyaRuntime.getDb()
      .from('clinical_treatment_sessions').select('*')
      .eq('encounter_id', encounterId).eq('client_request_id', operationId).maybeSingle();
    return response.error ? { ok: false } : { ok: true, row: response.data || null };
  }, { encounterId: fixture.encounter.id, operationId });
  if (!result?.ok) throw new Error('READ_FAILED');
  return result.row;
}

async function assertReadback(page, fixture, ordinal) {
  const rows = await readSessions(page, fixture);
  if (rows.length !== ordinal || !fixture.sessions.slice(0, ordinal)
    .every((session, index) => expectedRow(rows[index], fixture, session, index + 1))) {
    fail('CNYOS_BOUNDED_TREATMENT_READBACK_MISMATCH');
  }
  const ui = await page.locator('#opd-session-list').innerText();
  if (!fixture.sessions.slice(0, ordinal).every(session => ui.includes(session.treatmentDetail))) {
    fail('CNYOS_BOUNDED_TREATMENT_UI_READBACK_MISMATCH');
  }
  return rows;
}

function operationStorageKey(fixture) {
  return `cnyos:treatment-session-operation:v2:${encodeURIComponent(fixture.clinic.id)}:${
    encodeURIComponent(fixture.practitioner.userId)}:${encodeURIComponent(fixture.encounter.id)}`;
}

async function submitSession(page, config, ledger, session, ordinal) {
  await page.evaluate(({ key, operationId }) => sessionStorage.setItem(key, operationId), {
    key: operationStorageKey(config.fixture), operationId: session.operationId
  });
  await page.locator('input[name="opd-modality"][value="นวดไทย"]').check();
  await page.locator('#opd-pain-before').fill(String(session.painBefore));
  await page.locator('#opd-pain-after').fill(String(session.painAfter));
  await page.locator('#opd-treatment-detail').fill(session.treatmentDetail);
  await page.locator('#opd-procedure-referral').setChecked(false);
  await page.locator('#opd-procedure-detail').fill(session.procedureReferralDetail || '');
  await page.locator('#opd-precautions').fill(session.precautions || '');
  await page.locator('#opd-outcome').fill(session.outcomeSummary || '');
  await page.locator('#opd-advice').fill(session.advice || '');
  ledger.begin(session, `write-${ordinal}`);
  try {
    await page.locator('#opd-session-form button[type="submit"]').click({ timeout: 10_000 });
    await page.waitForFunction(() => {
      const text = document.querySelector('#opd-session-status')?.textContent || '';
      return text.includes('บันทึก Treatment Session และตรวจสอบผลแล้ว') ||
        text.includes('ยังยืนยันผลบันทึกไม่ได้') || text.includes('ยังไม่ได้บันทึก Treatment Session');
    }, null, { timeout: 30_000 });
  } catch {
    throw uncertainWriteError(session, ordinal);
  } finally { ledger.finish(); }
  const record = ledger.records.get(session.operationId);
  const statusText = await page.locator('#opd-session-status').innerText();
  if (!record || record.requestFailed || record.responseStatus == null) {
    throw uncertainWriteError(session, ordinal);
  }
  if (record.responseStatus < 200 || record.responseStatus >= 300 ||
    statusText.includes('ยังไม่ได้บันทึก Treatment Session')) {
    throw uncertainWriteError(session, ordinal);
  }
  if (!statusText.includes('บันทึก Treatment Session และตรวจสอบผลแล้ว')) {
    throw uncertainWriteError(session, ordinal);
  }
  return record;
}

function uncertainWriteError(session, ordinal) {
  const error = new BoundedTreatmentError('CNYOS_BOUNDED_TREATMENT_WRITE_UNCERTAIN',
    { uncertain: true });
  error.session = session;
  error.ordinal = ordinal;
  return error;
}

async function reconcileInFreshContext(browser, config, ledger, session, ordinal) {
  let opened;
  try {
    opened = await openClinicalContext(browser, config, ledger);
    return await reconcileAmbiguousOperation({
      readOnce: operationId => readOperation(opened.page, config.fixture, operationId),
      fixture: config.fixture, session, ordinal
    });
  } catch {
    return Object.freeze({ result: 'UNKNOWN', operationId: session.operationId });
  } finally { await opened?.context?.close().catch(() => {}); }
}

function sanitizedReadback(row, session) {
  return Object.freeze({
    rowId: row.id,
    operationId: session.operationId,
    sessionNo: Number(row.session_no),
    treatmentDetailSha256: hash(Buffer.from(session.treatmentDetail)),
    painBefore: session.painBefore,
    painAfter: session.painAfter
  });
}

export function classifyTreatmentFailure(error, state, ledger, fixture) {
  const verified = new Set((state.readbacks || []).map(item => item.operationId));
  let session = error?.session || null;
  let ordinal = Number(error?.ordinal) || null;
  if (!session) {
    const unresolved = ledger.writes.find(write => !verified.has(write.operationId));
    if (unresolved) {
      ordinal = unresolved.ordinal;
      session = fixture.sessions[ordinal - 1] || null;
    }
  }
  const uncertain = error?.uncertain === true || Boolean(session);
  return Object.freeze({
    status: uncertain ? 'UNCERTAIN' : 'FAIL',
    failureCode: uncertain && error?.uncertain !== true
      ? 'CNYOS_BOUNDED_TREATMENT_EXCEPTION_AFTER_DISPATCH'
      : error instanceof BoundedTreatmentError
        ? error.code
        : 'CNYOS_BOUNDED_TREATMENT_UAT_FAILED',
    session,
    ordinal
  });
}

export async function executeBoundedTreatmentUat(config, {
  fetchImpl = fetch,
  chromiumImpl = null,
  now = () => new Date()
} = {}) {
  const state = {
    startedAt: now().toISOString(),
    status: 'FAIL',
    failureCode: null,
    deployment: null,
    writes: [],
    readbacks: [],
    reconciliation: null,
    canonicalPublication: null,
    identity: null
  };
  let browser;
  const ledger = new TreatmentWriteLedger({
    encounterId: config.fixture.encounter.id,
    patientId: config.fixture.patient.id,
    practitionerUserId: config.fixture.practitioner.userId,
    practitionerEmail: config.practitionerEmail,
    password: config.password,
    publishableKey: config.publishableKey,
    appOrigin: config.immutableOrigin
  });
  try {
    state.deployment = await preflightExactDeployment(config, { fetchImpl });
    const chromium = chromiumImpl || (await import('playwright')).chromium;
    browser = await chromium.launch({ headless: true });

    let first = await openClinicalContext(browser, config, ledger);
    try {
      state.identity = first.identity;
      await browserFixturePreflight(first.page, config.fixture);
      state.writes.push(await submitSession(first.page, config, ledger,
        config.fixture.sessions[0], 1));
    } finally { await first.context.close(); }

    let second = await openClinicalContext(browser, config, ledger);
    try {
      const firstRows = await assertReadback(second.page, config.fixture, 1);
      state.readbacks.push(sanitizedReadback(firstRows[0], config.fixture.sessions[0]));
      state.writes.push(await submitSession(second.page, config, ledger,
        config.fixture.sessions[1], 2));
    } finally { await second.context.close(); }

    let third = await openClinicalContext(browser, config, ledger);
    try {
      const finalRows = await assertReadback(third.page, config.fixture, 2);
      state.readbacks = finalRows.map((row, index) =>
        sanitizedReadback(row, config.fixture.sessions[index]));
    } finally { await third.context.close(); }
    ledger.assertFinal();
    state.canonicalPublication = await recheckCanonicalPublication(config, state.deployment,
      { fetchImpl });
    state.status = 'PASS';
    return buildEvidence(config, state, ledger, now());
  } catch (error) {
    const classification = classifyTreatmentFailure(error, state, ledger, config.fixture);
    state.failureCode = classification.failureCode;
    state.status = classification.status;
    state.reconciliation = error?.reconciliation || null;
    if (classification.status === 'UNCERTAIN' && !state.reconciliation &&
      classification.session && classification.ordinal) {
      state.reconciliation = await reconcileInFreshContext(browser, config, ledger,
        classification.session, classification.ordinal);
    }
    return buildEvidence(config, state, ledger, now());
  } finally { await browser?.close().catch(() => {}); }
}

export function buildEvidence(config, state, ledger, observedAt = new Date()) {
  const status = ['PASS', 'FAIL', 'UNCERTAIN'].includes(state.status) ? state.status : 'FAIL';
  return Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_bounded_treatment_uat',
    status,
    runId: config.runId,
    startedAt: state.startedAt,
    observedAt: observedAt.toISOString(),
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    controllerOwnedRunner: true,
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployment: state.deployment,
    canonicalPublication: state.canonicalPublication,
    target: BOUNDED_TREATMENT_TARGET,
    fixture: Object.freeze({
      protectedLedgerEntryId: config.protectedLedger.entryId,
      protectedLedgerInputSha256: config.protectedLedger.inputSha256,
      protectedLedgerFileSha256: config.protectedLedger.sourceFileSha256,
      protectedLedgerExpectedSha256: config.protectedLedger.expectedFileSha256,
      canonicalFixtureSha256: config.protectedLedger.fixtureSha256,
      protectedLedgerVerifiedAt: config.protectedLedger.verifiedAt,
      practitionerUserId: config.fixture.practitioner.userId,
      practitionerEmailSha256: hash(Buffer.from(config.fixture.practitioner.email)),
      patientId: config.fixture.patient.id,
      patientHnSha256: hash(Buffer.from(config.fixture.patient.hn)),
      encounterId: config.fixture.encounter.id,
      baselineTreatmentSessionCount: 0
    }),
    writes: Object.freeze(ledger.writes.map(write => Object.freeze({
      ordinal: write.ordinal,
      operationId: write.operationId,
      payloadSha256: write.payloadSha256,
      responseStatus: write.responseStatus,
      requestFailed: write.requestFailed
    }))),
    readbacks: Object.freeze([...(state.readbacks || [])]),
    reconciliation: state.reconciliation,
    failureCode: status === 'PASS' ? null : state.failureCode,
    mutationLimit: Object.freeze({ allowed: 2, observed: ledger.writes.length,
      writeRetries: 0 }),
    cleanup: Object.freeze({ status: 'NOT_AUTHORIZED', attempted: false }),
    secretsSerialized: false
  });
}

export async function writeEvidenceExclusive(filename, evidence) {
  const target = path.resolve(required(filename,
    'CNYOS_BOUNDED_TREATMENT_EVIDENCE_PATH_REQUIRED', 4096));
  const parent = path.dirname(target);
  const stat = await fs.lstat(parent).catch(() => null);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) {
    fail('CNYOS_BOUNDED_TREATMENT_EVIDENCE_DIRECTORY_INVALID');
  }
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  const temp = path.join(parent,
    `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  let handle;
  try {
    handle = await fs.open(temp, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.link(temp, target);
    const mode = (await fs.stat(target)).mode & 0o777;
    if (mode !== 0o600) fail('CNYOS_BOUNDED_TREATMENT_EVIDENCE_MODE_INVALID');
    return Object.freeze({ path: target, sha256: hash(bytes), size: bytes.length });
  } catch (error) {
    if (error instanceof BoundedTreatmentError) throw error;
    fail('CNYOS_BOUNDED_TREATMENT_EVIDENCE_WRITE_FAILED');
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(temp).catch(() => {});
  }
}

function safeCode(error) {
  return error instanceof BoundedTreatmentError ? error.code :
    'CNYOS_BOUNDED_TREATMENT_UAT_FAILED';
}

async function main() {
  let config;
  try {
    config = await loadBoundedTreatmentConfig(process.env);
    const evidence = await executeBoundedTreatmentUat(config);
    await writeEvidenceExclusive(config.evidencePath, evidence);
    process.stderr.write(`CNYOS_BOUNDED_TREATMENT_UAT_${evidence.status}\n`);
    process.exitCode = evidence.status === 'PASS' ? 0 : evidence.status === 'UNCERTAIN' ? 2 : 1;
  } catch (error) {
    process.stderr.write(`${safeCode(error)}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();
