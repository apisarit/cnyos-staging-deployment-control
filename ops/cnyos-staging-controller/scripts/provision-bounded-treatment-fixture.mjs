import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_TREATMENT_TARGET,
  canonicalFixtureSha256,
  canonicalJson,
  validateTreatmentFixture
} from './bounded-treatment-uat.mjs';
import {
  LOCAL_CONTROLLER_ENTRYPOINT,
  assertVerifiedLocalControllerRuntime
} from './local-controller-runtime.mjs';
import { POLICY, POLICY_SHA256, assertControllerRuntime } from './policy.mjs';

export const SINGLE_FIXTURE_PROVISION_ACK =
  'I_AUTHORIZE_ONE_FRESH_SYNTHETIC_PRACTITIONER_PATIENT_AND_DRAFT_ENCOUNTER';

export const SINGLE_FIXTURE_AUTHORIZATION_DECISION =
  'authorize_one_fresh_synthetic_treatment_fixture';

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const DEPLOY_ID = /^[0-9a-f]{24}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const PUBLISHABLE_KEY = /^sb_publishable_[A-Za-z0-9_-]{20,}$/;
const ACCESS_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_AUTH_USER_PAGES = 50;
const AUTH_USER_PAGE_SIZE = 100;
const MAX_ADMISSION_LIFETIME_MS = 30 * 60 * 1000;
const CLIENT_INFO = 'cnyos-controller-single-fixture/1.0';
const LIVE_MODE = 'LIVE';
const configuredInstances = new WeakSet();

export class SingleFixtureProvisionError extends Error {
  constructor(code, { uncertain = false, operation = null } = {}) {
    super(code);
    this.name = 'SingleFixtureProvisionError';
    this.code = code;
    this.uncertain = uncertain;
    this.operation = operation;
  }
}

function fail(code, options) {
  throw new SingleFixtureProvisionError(code, options);
}

function uncertain(code, operation = null) {
  fail(code, { uncertain: true, operation });
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
  return exact(value, UUID, code);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalTimestamp(value, code) {
  const normalized = required(value, code, 64);
  const time = Date.parse(normalized);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== normalized) fail(code);
  return Object.freeze({ value: normalized, time });
}

function timingSafeHexEqual(left, right) {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function metadataMarkers(config) {
  return Object.freeze({
    synthetic_staging_only: true,
    expected_role: 'practitioner',
    fixture_run_id: config.fixtureRunId
  });
}

function markersMatch(value, expected) {
  return isPlainObject(value) && Object.entries(expected)
    .every(([key, expectedValue]) => value[key] === expectedValue);
}

function freezeConfig(config) {
  const value = Object.freeze(config);
  configuredInstances.add(value);
  return value;
}

function assertConfigured(config) {
  if (!configuredInstances.has(config)) fail('CNYOS_SINGLE_FIXTURE_CONFIG_INVALID');
}

export function loadSingleFixtureProvisioningConfig(env = process.env, {
  randomUUID = () => crypto.randomUUID(),
  controllerRuntime = null
} = {}) {
  if (env.CNYOS_SINGLE_FIXTURE_PROVISION_MODE !== LIVE_MODE) {
    fail('CNYOS_SINGLE_FIXTURE_LIVE_MODE_REQUIRED');
  }
  if (env.CNYOS_SINGLE_FIXTURE_PROVISION_ACK !== SINGLE_FIXTURE_PROVISION_ACK) {
    fail('CNYOS_SINGLE_FIXTURE_ACK_REQUIRED');
  }

  const runtime = controllerRuntime
    ? assertVerifiedLocalControllerRuntime(controllerRuntime)
    : assertControllerRuntime(env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath &&
    runtime.workflowPath !== LOCAL_CONTROLLER_ENTRYPOINT) {
    fail('CNYOS_SINGLE_FIXTURE_CONTROLLER_WORKFLOW_INVALID');
  }

  const fixtureRunId = required(env.CNYOS_TREATMENT_UAT_RUN_ID,
    'CNYOS_SINGLE_FIXTURE_RUN_ID_INVALID', 96);
  if (!RUN_ID.test(fixtureRunId)) fail('CNYOS_SINGLE_FIXTURE_RUN_ID_INVALID');
  const practitionerEmail = required(env.CNYOS_STAGING_PRACTITIONER_EMAIL,
    'CNYOS_SINGLE_FIXTURE_EMAIL_INVALID', 320).toLowerCase();
  if (!EMAIL.test(practitionerEmail)) fail('CNYOS_SINGLE_FIXTURE_EMAIL_INVALID');
  const practitionerFullName = required(env.CNYOS_STAGING_PRACTITIONER_FULL_NAME ||
    `Synthetic E2E Practitioner ${fixtureRunId}`, 'CNYOS_SINGLE_FIXTURE_NAME_INVALID', 200);
  if (!practitionerFullName.toUpperCase().includes('SYNTHETIC')) {
    fail('CNYOS_SINGLE_FIXTURE_NAME_INVALID');
  }

  const publishableKey = required(env.CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY,
    'CNYOS_SINGLE_FIXTURE_PUBLISHABLE_KEY_REQUIRED', 4096);
  if (!PUBLISHABLE_KEY.test(publishableKey)) {
    fail('CNYOS_SINGLE_FIXTURE_PUBLISHABLE_KEY_INVALID');
  }
  const serviceRoleKey = required(env.CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY,
    'CNYOS_SINGLE_FIXTURE_SERVICE_ROLE_KEY_REQUIRED', 8192);
  if (serviceRoleKey.length < 20 || serviceRoleKey === publishableKey) {
    fail('CNYOS_SINGLE_FIXTURE_SERVICE_ROLE_KEY_INVALID');
  }
  const password = required(env.CNYOS_STAGING_TEST_PASSWORD,
    'CNYOS_SINGLE_FIXTURE_PASSWORD_REQUIRED', 4096);
  if (password.length < 16 || password === serviceRoleKey || password === publishableKey) {
    fail('CNYOS_SINGLE_FIXTURE_PASSWORD_INVALID');
  }

  const outputDirectory = required(env.CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY,
    'CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_REQUIRED', 4096);
  if (!path.isAbsolute(outputDirectory)) {
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_INVALID');
  }

  const operationIds = [randomUUID(), randomUUID()].map(value =>
    exactUuid(value, 'CNYOS_SINGLE_FIXTURE_OPERATION_ID_INVALID'));
  if (operationIds[0] === operationIds[1]) {
    fail('CNYOS_SINGLE_FIXTURE_OPERATION_ID_INVALID');
  }

  return freezeConfig({
    runtime,
    fixtureRunId,
    sourceCommit: exact(env.CNYOS_EXPECTED_SOURCE_COMMIT, SHA40,
      'CNYOS_SINGLE_FIXTURE_SOURCE_COMMIT_INVALID'),
    sourceTree: exact(env.CNYOS_EXPECTED_SOURCE_TREE, SHA40,
      'CNYOS_SINGLE_FIXTURE_SOURCE_TREE_INVALID'),
    deployId: exact(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, DEPLOY_ID,
      'CNYOS_SINGLE_FIXTURE_DEPLOY_ID_INVALID'),
    practitionerEmail,
    practitionerFullName,
    publishableKey,
    serviceRoleKey,
    password,
    outputDirectory: path.resolve(outputDirectory),
    operationIds: Object.freeze(operationIds),
    target: BOUNDED_TREATMENT_TARGET
  });
}

export function buildSingleFixtureProvisioningPlan(config) {
  assertConfigured(config);
  const plan = Object.freeze({
    schemaVersion: 1,
    kind: 'single_bounded_treatment_fixture_provisioning_plan',
    controller: Object.freeze({
      repository: config.runtime.repository,
      ref: config.runtime.ref,
      commit: config.runtime.commit,
      workflowPath: config.runtime.workflowPath,
      runId: config.runtime.runId,
      runAttempt: 1
    }),
    policySha256: POLICY_SHA256,
    target: config.target,
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployId: config.deployId,
    fixtureRunId: config.fixtureRunId,
    practitioner: Object.freeze({
      email: config.practitionerEmail,
      fullName: config.practitionerFullName,
      role: 'practitioner',
      markers: metadataMarkers(config)
    }),
    patient: Object.freeze({
      paymentRight: 'SYNTHETIC-E2E',
      realIdentifiersAbsent: true,
      allergyRowsExpected: 0
    }),
    encounter: Object.freeze({
      status: 'draft',
      treatmentSessionRowsExpected: 0,
      prescriptionRowsExpected: 0,
      vitalSignRowsExpected: 0,
      painAssessmentRowsExpected: 0
    }),
    operationIds: config.operationIds,
    limits: Object.freeze({
      freshAuthUsers: 1,
      serviceRoleTableWrites: 2,
      authenticatedClinicalRpcWrites: 2,
      writeRetries: 0,
      cleanupAuthorized: false
    })
  });
  return Object.freeze({ plan, sha256: sha256(Buffer.from(canonicalJson(plan))) });
}

export async function authorizeSingleFixtureProvisioning(config, planRecord, authorizationHook, {
  now = () => new Date()
} = {}) {
  assertConfigured(config);
  if (typeof authorizationHook !== 'function') {
    fail('CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_HOOK_REQUIRED');
  }
  const receipt = await authorizationHook(Object.freeze({
    plan: planRecord.plan,
    planSha256: planRecord.sha256,
    runtime: config.runtime
  }));
  const code = 'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_INVALID';
  exactKeys(receipt, [
    'schemaVersion', 'kind', 'status', 'decision', 'controllerRepository',
    'controllerRef', 'controllerCommit', 'controllerWorkflowPath', 'controllerRunId',
    'policySha256', 'planSha256', 'sourceCommit', 'sourceTree', 'deployId',
    'fixtureRunId', 'targetSiteId', 'targetClinicId', 'authorizedAt', 'expiresAt',
    'authorizationEvidenceSha256', 'authorizationBundleSha256'
  ], code);
  const authorizedAt = canonicalTimestamp(receipt.authorizedAt, code);
  const expiresAt = canonicalTimestamp(receipt.expiresAt, code);
  const observed = now();
  const observedMs = observed instanceof Date ? observed.getTime() : Number.NaN;
  if (receipt.schemaVersion !== 1 ||
    receipt.kind !== 'controller_verified_single_fixture_admission' ||
    receipt.status !== 'authorized' || receipt.decision !== SINGLE_FIXTURE_AUTHORIZATION_DECISION ||
    receipt.controllerRepository !== config.runtime.repository ||
    receipt.controllerRef !== config.runtime.ref ||
    receipt.controllerCommit !== config.runtime.commit ||
    receipt.controllerWorkflowPath !== config.runtime.workflowPath ||
    String(receipt.controllerRunId) !== config.runtime.runId ||
    receipt.policySha256 !== POLICY_SHA256 ||
    !timingSafeHexEqual(receipt.planSha256, planRecord.sha256) ||
    receipt.sourceCommit !== config.sourceCommit || receipt.sourceTree !== config.sourceTree ||
    receipt.deployId !== config.deployId || receipt.fixtureRunId !== config.fixtureRunId ||
    receipt.targetSiteId !== config.target.netlifySiteId ||
    receipt.targetClinicId !== config.target.clinicId ||
    !SHA256.test(String(receipt.authorizationEvidenceSha256 || '')) ||
    !SHA256.test(String(receipt.authorizationBundleSha256 || '')) ||
    !Number.isFinite(observedMs) || authorizedAt.time > observedMs || expiresAt.time <= observedMs ||
    expiresAt.time <= authorizedAt.time ||
    expiresAt.time - authorizedAt.time > MAX_ADMISSION_LIFETIME_MS) fail(code);
  return Object.freeze({ ...receipt });
}

async function assertFreshOutputDestination(config) {
  const parent = path.dirname(config.outputDirectory);
  const parentStatus = await fs.lstat(parent).catch(() => null);
  if (!parentStatus?.isDirectory() || parentStatus.isSymbolicLink()) {
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_PARENT_INVALID');
  }
  const targetStatus = await fs.lstat(config.outputDirectory).catch(error => {
    if (error?.code === 'ENOENT') return null;
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_INVALID');
  });
  if (targetStatus) fail('CNYOS_SINGLE_FIXTURE_OUTPUT_ALREADY_EXISTS');
}

function serviceHeaders(config, body = false) {
  return {
    Accept: 'application/json',
    apikey: config.serviceRoleKey,
    Authorization: `Bearer ${config.serviceRoleKey}`,
    'X-Client-Info': CLIENT_INFO,
    ...(body ? { 'Content-Type': 'application/json' } : {})
  };
}

function publishableHeaders(config, body = false) {
  return {
    Accept: 'application/json',
    apikey: config.publishableKey,
    Authorization: `Bearer ${config.publishableKey}`,
    'X-Client-Info': CLIENT_INFO,
    ...(body ? { 'Content-Type': 'application/json' } : {})
  };
}

function practitionerHeaders(config, accessToken, body = false) {
  return {
    Accept: 'application/json',
    apikey: config.publishableKey,
    Authorization: `Bearer ${accessToken}`,
    'X-Client-Info': CLIENT_INFO,
    ...(body ? {
      'Content-Type': 'application/json',
      'Content-Profile': 'public'
    } : { 'Accept-Profile': 'public' })
  };
}

function supabaseUrl(config, pathname, query = null) {
  const url = new URL(pathname, `${config.target.supabaseOrigin}/`);
  if (query) {
    for (const [name, value] of query) url.searchParams.append(name, value);
  }
  if (url.origin !== config.target.supabaseOrigin) {
    fail('CNYOS_SINGLE_FIXTURE_REQUEST_TARGET_INVALID');
  }
  return url.href;
}

function assertAdmissionActive(state, operation = null) {
  const observed = state.now();
  const observedMs = observed instanceof Date ? observed.getTime() : Number.NaN;
  if (!Number.isFinite(observedMs) || observedMs >= state.authorizationExpiresAtMs) {
    if (state.mutations.some(record => record.dispatched)) {
      uncertain('CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_EXPIRED', operation);
    }
    fail('CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_EXPIRED');
  }
  return observed;
}

function mutationRecord(state, name, authority, resource) {
  assertAdmissionActive(state, name);
  const record = {
    ordinal: state.mutations.length + 1,
    name,
    authority,
    resource,
    dispatched: false,
    responseStatus: null,
    requestFailed: false
  };
  state.mutations.push(record);
  return record;
}

async function requestJson(fetchImpl, {
  url,
  method = 'GET',
  headers,
  body,
  accepted = [200],
  code,
  mutation = null,
  uncertainOnFailure = false
}) {
  let response;
  if (mutation) mutation.dispatched = true;
  try {
    response = await fetchImpl(url, {
      method,
      headers,
      redirect: 'error',
      cache: 'no-store',
      signal: AbortSignal.timeout(20_000),
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
  } catch {
    if (mutation) mutation.requestFailed = true;
    if (mutation || uncertainOnFailure) uncertain(`${code}_REQUEST_UNCERTAIN`, mutation?.name || null);
    fail(`${code}_REQUEST_FAILED`);
  }
  if (mutation) mutation.responseStatus = response.status;
  let bytes;
  try { bytes = Buffer.from(await response.arrayBuffer()); }
  catch {
    if (mutation || uncertainOnFailure) uncertain(`${code}_RESPONSE_UNCERTAIN`, mutation?.name || null);
    fail(`${code}_RESPONSE_INVALID`);
  }
  if (bytes.length > MAX_JSON_BYTES) {
    if (mutation || uncertainOnFailure) uncertain(`${code}_RESPONSE_UNCERTAIN`, mutation?.name || null);
    fail(`${code}_RESPONSE_TOO_LARGE`);
  }
  if (!accepted.includes(response.status)) {
    if (uncertainOnFailure ||
      (mutation && (response.status >= 500 || [408, 425, 429].includes(response.status)))) {
      uncertain(`${code}_STATUS_UNCERTAIN`, mutation?.name || null);
    }
    fail(`${code}_STATUS_INVALID`);
  }
  if (bytes.length === 0) {
    if (mutation || uncertainOnFailure) uncertain(`${code}_RESPONSE_UNCERTAIN`, mutation?.name || null);
    fail(`${code}_RESPONSE_INVALID`);
  }
  try { return JSON.parse(bytes.toString('utf8')); }
  catch {
    if (mutation || uncertainOnFailure) uncertain(`${code}_RESPONSE_UNCERTAIN`, mutation?.name || null);
    fail(`${code}_RESPONSE_INVALID`);
  }
}

function exactOneRow(value, code, { uncertainResult = false, operation = null } = {}) {
  const row = Array.isArray(value) && value.length === 1 ? value[0] :
    isPlainObject(value) ? value : null;
  if (!isPlainObject(row)) {
    if (uncertainResult) uncertain(code, operation);
    fail(code);
  }
  return row;
}

async function assertFreshAuthEmail(config, fetchImpl) {
  for (let page = 1; page <= MAX_AUTH_USER_PAGES; page += 1) {
    const value = await requestJson(fetchImpl, {
      url: supabaseUrl(config, '/auth/v1/admin/users', [
        ['page', String(page)], ['per_page', String(AUTH_USER_PAGE_SIZE)]
      ]),
      headers: serviceHeaders(config),
      code: 'CNYOS_SINGLE_FIXTURE_AUTH_USER_LIST'
    });
    const users = Array.isArray(value) ? value : value?.users;
    if (!Array.isArray(users) || users.length > AUTH_USER_PAGE_SIZE || users.some(user =>
      !isPlainObject(user) || (user.email != null && typeof user.email !== 'string'))) {
      fail('CNYOS_SINGLE_FIXTURE_AUTH_USER_LIST_INVALID');
    }
    if (users.some(user => String(user.email || '').toLowerCase() === config.practitionerEmail)) {
      fail('CNYOS_SINGLE_FIXTURE_EMAIL_COLLISION');
    }
    if (users.length < AUTH_USER_PAGE_SIZE) return;
  }
  fail('CNYOS_SINGLE_FIXTURE_AUTH_USER_LIST_LIMIT_EXCEEDED');
}

async function createAuthUser(config, fetchImpl, state) {
  const markers = metadataMarkers(config);
  const record = mutationRecord(state, 'create_auth_user', 'service_role', '/auth/v1/admin/users');
  const value = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/auth/v1/admin/users'),
    method: 'POST',
    headers: serviceHeaders(config, true),
    body: {
      email: config.practitionerEmail,
      password: config.password,
      email_confirm: true,
      user_metadata: { full_name: config.practitionerFullName, ...markers },
      app_metadata: markers
    },
    accepted: [200, 201],
    code: 'CNYOS_SINGLE_FIXTURE_AUTH_USER_CREATE',
    mutation: record
  });
  const user = isPlainObject(value?.user) ? value.user : value;
  if (!isPlainObject(user) || !UUID.test(String(user.id || '')) ||
    String(user.email || '').toLowerCase() !== config.practitionerEmail ||
    !markersMatch(user.user_metadata, markers) || !markersMatch(user.app_metadata, markers)) {
    uncertain('CNYOS_SINGLE_FIXTURE_AUTH_USER_CREATE_RESPONSE_INVALID', record.name);
  }
  state.ids.practitionerUserId = String(user.id).toLowerCase();
  return user;
}

async function writeProfile(config, fetchImpl, state) {
  const record = mutationRecord(state, 'upsert_profile', 'service_role', '/rest/v1/profiles');
  const value = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/rest/v1/profiles', [['on_conflict', 'id']]),
    method: 'POST',
    headers: {
      ...serviceHeaders(config, true),
      Prefer: 'resolution=merge-duplicates,return=representation'
    },
    body: [{
      id: state.ids.practitionerUserId,
      email: config.practitionerEmail,
      full_name: config.practitionerFullName,
      role: 'practitioner',
      system_role: 'staff',
      updated_at: state.startedAt
    }],
    accepted: [200, 201],
    code: 'CNYOS_SINGLE_FIXTURE_PROFILE_WRITE',
    mutation: record
  });
  const row = exactOneRow(value, 'CNYOS_SINGLE_FIXTURE_PROFILE_WRITE_RESPONSE_INVALID',
    { uncertainResult: true, operation: record.name });
  if (String(row.id || '').toLowerCase() !== state.ids.practitionerUserId ||
    String(row.email || '').toLowerCase() !== config.practitionerEmail ||
    row.role !== 'practitioner' || row.system_role !== 'staff') {
    uncertain('CNYOS_SINGLE_FIXTURE_PROFILE_WRITE_RESPONSE_INVALID', record.name);
  }
}

async function writeMembership(config, fetchImpl, state) {
  const record = mutationRecord(state, 'insert_clinic_membership', 'service_role',
    '/rest/v1/clinic_memberships');
  const value = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/rest/v1/clinic_memberships'),
    method: 'POST',
    headers: { ...serviceHeaders(config, true), Prefer: 'return=representation' },
    body: [{
      clinic_id: config.target.clinicId,
      profile_id: state.ids.practitionerUserId,
      clinic_role: 'practitioner',
      is_primary: true,
      active: true,
      updated_at: state.startedAt
    }],
    accepted: [200, 201],
    code: 'CNYOS_SINGLE_FIXTURE_MEMBERSHIP_WRITE',
    mutation: record
  });
  const row = exactOneRow(value, 'CNYOS_SINGLE_FIXTURE_MEMBERSHIP_WRITE_RESPONSE_INVALID',
    { uncertainResult: true, operation: record.name });
  if (String(row.clinic_id || '').toLowerCase() !== config.target.clinicId ||
    String(row.profile_id || '').toLowerCase() !== state.ids.practitionerUserId ||
    row.clinic_role !== 'practitioner' || row.is_primary !== true || row.active !== true) {
    uncertain('CNYOS_SINGLE_FIXTURE_MEMBERSHIP_WRITE_RESPONSE_INVALID', record.name);
  }
}

async function authenticatePractitioner(config, fetchImpl, state) {
  const value = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/auth/v1/token', [['grant_type', 'password']]),
    method: 'POST',
    headers: publishableHeaders(config, true),
    body: { email: config.practitionerEmail, password: config.password },
    code: 'CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN',
    uncertainOnFailure: true
  });
  const markers = metadataMarkers(config);
  const user = value?.user;
  let accessToken;
  try {
    accessToken = required(value?.access_token,
      'CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN_INVALID', 8192);
  } catch {
    uncertain('CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN_RESPONSE_UNCERTAIN',
      'practitioner_login');
  }
  if (!ACCESS_TOKEN.test(accessToken) || accessToken === config.publishableKey ||
    accessToken === config.serviceRoleKey || !isPlainObject(user) ||
    !UUID.test(String(user.id || '')) || typeof user.email !== 'string' ||
    !isPlainObject(user.user_metadata) || !isPlainObject(user.app_metadata)) {
    uncertain('CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN_RESPONSE_UNCERTAIN',
      'practitioner_login');
  }
  if (String(user.id).toLowerCase() !==
      state.ids.practitionerUserId ||
    user.email.toLowerCase() !== config.practitionerEmail ||
    !markersMatch(user.user_metadata, markers) || !markersMatch(user.app_metadata, markers)) {
    fail('CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN_INVALID');
  }
  state.practitionerAuthenticated = true;
  return accessToken;
}

async function verifyControlPlaneRows(config, fetchImpl, state) {
  const profile = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/rest/v1/profiles', [
      ['select', 'id,email,full_name,role,system_role'],
      ['id', `eq.${state.ids.practitionerUserId}`]
    ]),
    headers: serviceHeaders(config),
    code: 'CNYOS_SINGLE_FIXTURE_PROFILE_READBACK',
    uncertainOnFailure: true
  });
  const profileRow = exactOneRow(profile, 'CNYOS_SINGLE_FIXTURE_PROFILE_READBACK_INVALID');
  if (String(profileRow.id || '').toLowerCase() !== state.ids.practitionerUserId ||
    String(profileRow.email || '').toLowerCase() !== config.practitionerEmail ||
    profileRow.full_name !== config.practitionerFullName ||
    profileRow.role !== 'practitioner' || profileRow.system_role !== 'staff') {
    fail('CNYOS_SINGLE_FIXTURE_PROFILE_READBACK_INVALID');
  }

  const membership = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/rest/v1/clinic_memberships', [
      ['select', 'clinic_id,profile_id,clinic_role,is_primary,active'],
      ['clinic_id', `eq.${config.target.clinicId}`],
      ['profile_id', `eq.${state.ids.practitionerUserId}`]
    ]),
    headers: serviceHeaders(config),
    code: 'CNYOS_SINGLE_FIXTURE_MEMBERSHIP_READBACK',
    uncertainOnFailure: true
  });
  const membershipRow = exactOneRow(membership,
    'CNYOS_SINGLE_FIXTURE_MEMBERSHIP_READBACK_INVALID');
  if (String(membershipRow.clinic_id || '').toLowerCase() !== config.target.clinicId ||
    String(membershipRow.profile_id || '').toLowerCase() !== state.ids.practitionerUserId ||
    membershipRow.clinic_role !== 'practitioner' || membershipRow.is_primary !== true ||
    membershipRow.active !== true) fail('CNYOS_SINGLE_FIXTURE_MEMBERSHIP_READBACK_INVALID');
  state.controlPlaneReadbackVerified = true;
}

function patientPayload(config) {
  const suffix = sha256(Buffer.from(config.fixtureRunId)).slice(0, 12).toUpperCase();
  return Object.freeze({
    p_patient_id: null,
    p_prefix: 'TEST',
    p_first_name: 'SYNTHETIC',
    p_last_name: `E2E-${suffix}`,
    p_national_id: null,
    p_gender: null,
    p_date_of_birth: null,
    p_phone: null,
    p_address: 'SYNTHETIC STAGING ONLY - NOT FOR CLINICAL USE',
    p_payment_right: 'SYNTHETIC-E2E',
    p_emergency_contact_name: null,
    p_allergy: null
  });
}

function expectedPatientHn(config, value) {
  const clinicPrefix = config.target.clinicCode.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  return new RegExp(`^${clinicPrefix}-[0-9]{8,}$`).test(String(value || ''));
}

async function createPatient(config, fetchImpl, state, accessToken) {
  const record = mutationRecord(state, 'upsert_patient_registration', 'practitioner',
    '/rest/v1/rpc/upsert_patient_registration');
  const value = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/rest/v1/rpc/upsert_patient_registration'),
    method: 'POST',
    headers: practitionerHeaders(config, accessToken, true),
    body: patientPayload(config),
    code: 'CNYOS_SINGLE_FIXTURE_PATIENT_RPC',
    mutation: record
  });
  const row = exactOneRow(value, 'CNYOS_SINGLE_FIXTURE_PATIENT_RPC_RESPONSE_INVALID',
    { uncertainResult: true, operation: record.name });
  let patientId;
  let hn;
  try {
    patientId = exactUuid(row.id, 'CNYOS_SINGLE_FIXTURE_PATIENT_RPC_RESPONSE_INVALID');
    hn = required(row.hn, 'CNYOS_SINGLE_FIXTURE_PATIENT_RPC_RESPONSE_INVALID', 64);
  } catch {
    uncertain('CNYOS_SINGLE_FIXTURE_PATIENT_RPC_RESPONSE_INVALID', record.name);
  }
  if (!expectedPatientHn(config, hn) || row.payment_right !== 'SYNTHETIC-E2E' ||
    row.national_id != null || row.phone != null || row.email != null ||
    String(row.clinic_id || '').toLowerCase() !== config.target.clinicId ||
    String(row.created_by || '').toLowerCase() !== state.ids.practitionerUserId) {
    uncertain('CNYOS_SINGLE_FIXTURE_PATIENT_RPC_RESPONSE_INVALID', record.name);
  }
  state.ids.patientId = patientId;
  state.ids.patientHn = hn;
}

async function createEncounter(config, fetchImpl, state, accessToken) {
  const record = mutationRecord(state, 'start_manual_patient_encounter', 'practitioner',
    '/rest/v1/rpc/start_manual_patient_encounter');
  const value = await requestJson(fetchImpl, {
    url: supabaseUrl(config, '/rest/v1/rpc/start_manual_patient_encounter'),
    method: 'POST',
    headers: practitionerHeaders(config, accessToken, true),
    body: {
      p_patient_id: state.ids.patientId,
      p_verification_method: 'manual_hn',
      p_patient_present_confirmed: true,
      p_verification_note: `SYNTHETIC ${config.fixtureRunId} - NOT FOR CLINICAL USE`,
      p_chief_complaint: `SYNTHETIC ${config.fixtureRunId} - NOT FOR CLINICAL USE`,
      p_intake: {}
    },
    code: 'CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC',
    mutation: record
  });
  const row = exactOneRow(value, 'CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC_RESPONSE_INVALID',
    { uncertainResult: true, operation: record.name });
  let encounterId;
  let encounterNo;
  try {
    encounterId = exactUuid(row.encounter_id,
      'CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC_RESPONSE_INVALID');
    encounterNo = required(row.encounter_no,
      'CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC_RESPONSE_INVALID', 64);
  } catch {
    uncertain('CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC_RESPONSE_INVALID', record.name);
  }
  if (String(row.patient_id || '').toLowerCase() !== state.ids.patientId ||
    !encounterNo) {
    uncertain('CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC_RESPONSE_INVALID', record.name);
  }
  state.ids.encounterId = encounterId;
  state.ids.encounterNo = encounterNo;
}

async function tableRead(config, fetchImpl, accessToken, table, query, code) {
  return requestJson(fetchImpl, {
    url: supabaseUrl(config, `/rest/v1/${table}`, query),
    headers: practitionerHeaders(config, accessToken),
    code,
    uncertainOnFailure: true
  });
}

async function verifyClinicalReadback(config, fetchImpl, state, accessToken) {
  const patient = await tableRead(config, fetchImpl, accessToken, 'patients', [
    ['select', 'id,hn,national_id,phone,email,payment_right,clinic_id,created_by'],
    ['id', `eq.${state.ids.patientId}`]
  ], 'CNYOS_SINGLE_FIXTURE_PATIENT_READBACK');
  const patientRow = exactOneRow(patient, 'CNYOS_SINGLE_FIXTURE_PATIENT_READBACK_INVALID',
    { uncertainResult: true, operation: 'patient_readback' });
  if (String(patientRow.id || '').toLowerCase() !== state.ids.patientId ||
    patientRow.hn !== state.ids.patientHn || !expectedPatientHn(config, patientRow.hn) ||
    patientRow.payment_right !== 'SYNTHETIC-E2E' ||
    patientRow.national_id != null || patientRow.phone != null || patientRow.email != null ||
    String(patientRow.clinic_id || '').toLowerCase() !== config.target.clinicId ||
    String(patientRow.created_by || '').toLowerCase() !== state.ids.practitionerUserId) {
    uncertain('CNYOS_SINGLE_FIXTURE_PATIENT_READBACK_INVALID', 'patient_readback');
  }

  const encounter = await tableRead(config, fetchImpl, accessToken, 'encounters', [
    ['select', 'id,patient_id,status,encounter_type,practitioner_id,created_by,clinic_id'],
    ['id', `eq.${state.ids.encounterId}`]
  ], 'CNYOS_SINGLE_FIXTURE_ENCOUNTER_READBACK');
  const encounterRow = exactOneRow(encounter,
    'CNYOS_SINGLE_FIXTURE_ENCOUNTER_READBACK_INVALID',
    { uncertainResult: true, operation: 'encounter_readback' });
  if (String(encounterRow.id || '').toLowerCase() !== state.ids.encounterId ||
    String(encounterRow.patient_id || '').toLowerCase() !== state.ids.patientId ||
    encounterRow.status !== 'draft' || encounterRow.encounter_type !== 'opd' ||
    String(encounterRow.practitioner_id || '').toLowerCase() !==
      state.ids.practitionerUserId ||
    String(encounterRow.created_by || '').toLowerCase() !== state.ids.practitionerUserId ||
    String(encounterRow.clinic_id || '').toLowerCase() !== config.target.clinicId) {
    uncertain('CNYOS_SINGLE_FIXTURE_ENCOUNTER_READBACK_INVALID', 'encounter_readback');
  }

  const emptyChecks = [
    ['clinical_treatment_sessions', 'encounter_id', state.ids.encounterId,
      'CNYOS_SINGLE_FIXTURE_BASELINE_TREATMENT_SESSIONS_INVALID'],
    ['prescriptions', 'encounter_id', state.ids.encounterId,
      'CNYOS_SINGLE_FIXTURE_BASELINE_PRESCRIPTIONS_INVALID'],
    ['vital_signs', 'encounter_id', state.ids.encounterId,
      'CNYOS_SINGLE_FIXTURE_BASELINE_VITAL_SIGNS_INVALID'],
    ['pain_assessments', 'encounter_id', state.ids.encounterId,
      'CNYOS_SINGLE_FIXTURE_BASELINE_PAIN_ASSESSMENTS_INVALID'],
    ['patient_allergies', 'patient_id', state.ids.patientId,
      'CNYOS_SINGLE_FIXTURE_BASELINE_ALLERGIES_INVALID']
  ];
  for (const [table, field, id, code] of emptyChecks) {
    const rows = await tableRead(config, fetchImpl, accessToken, table, [
      ['select', 'id'], [field, `eq.${id}`], ['limit', '1']
    ], `${code}_READ`);
    if (!Array.isArray(rows)) uncertain(`${code}_READBACK_INVALID`, `${table}_readback`);
    if (rows.length !== 0) fail(code);
  }
  state.baselineVerified = true;
}

function assertMutationBoundary(state) {
  const expected = [
    ['create_auth_user', 'service_role', '/auth/v1/admin/users'],
    ['upsert_profile', 'service_role', '/rest/v1/profiles'],
    ['insert_clinic_membership', 'service_role', '/rest/v1/clinic_memberships'],
    ['upsert_patient_registration', 'practitioner',
      '/rest/v1/rpc/upsert_patient_registration'],
    ['start_manual_patient_encounter', 'practitioner',
      '/rest/v1/rpc/start_manual_patient_encounter']
  ];
  if (state.mutations.length !== expected.length || state.mutations.some((record, index) =>
    record.name !== expected[index][0] || record.authority !== expected[index][1] ||
    record.resource !== expected[index][2] || record.ordinal !== index + 1 ||
    record.dispatched !== true || record.responseStatus == null || record.requestFailed)) {
    fail('CNYOS_SINGLE_FIXTURE_MUTATION_BOUNDARY_INVALID');
  }
}

function buildTreatmentFixture(config, state) {
  const fixture = {
    schemaVersion: 1,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    clinic: { id: config.target.clinicId, code: config.target.clinicCode },
    practitioner: {
      userId: state.ids.practitionerUserId,
      email: config.practitionerEmail,
      role: 'practitioner',
      syntheticMarkerVerified: true
    },
    patient: {
      id: state.ids.patientId,
      hn: state.ids.patientHn,
      paymentRight: 'SYNTHETIC-E2E',
      syntheticMarkerVerified: true,
      realIdentifiersAbsent: true
    },
    encounter: {
      id: state.ids.encounterId,
      patientId: state.ids.patientId,
      practitionerUserId: state.ids.practitionerUserId,
      status: 'draft',
      baselineTreatmentSessionCount: 0
    },
    sessions: [
      {
        operationId: config.operationIds[0],
        modalities: ['นวดไทย'],
        treatmentDetail: `SYNTHETIC ${config.fixtureRunId} SESSION 1 - NOT FOR CLINICAL USE`,
        procedureReferral: false,
        procedureReferralDetail: null,
        precautions: 'synthetic fixture only',
        painBefore: 4,
        painAfter: 2,
        outcomeSummary: 'synthetic improvement',
        advice: 'synthetic follow-up only'
      },
      {
        operationId: config.operationIds[1],
        modalities: ['นวดไทย'],
        treatmentDetail: `SYNTHETIC ${config.fixtureRunId} SESSION 2 - NOT FOR CLINICAL USE`,
        procedureReferral: false,
        procedureReferralDetail: null,
        precautions: null,
        painBefore: 2,
        painAfter: 1,
        outcomeSummary: 'synthetic stable',
        advice: null
      }
    ]
  };
  return validateTreatmentFixture(fixture, {
    runId: config.fixtureRunId,
    practitionerEmail: config.practitionerEmail
  });
}

function buildProtectedLedger(config, state, fixture, verifiedAt) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'protected_staging_fixture_ledger',
    entryId: `fixture:treatment:${config.fixtureRunId}`,
    fixtureSha256: canonicalFixtureSha256(fixture),
    verifiedAt,
    target: Object.freeze({
      siteId: config.target.netlifySiteId,
      deployId: config.deployId,
      sourceCommit: config.sourceCommit,
      sourceTree: config.sourceTree,
      clinicId: config.target.clinicId
    }),
    fixtureIds: Object.freeze({
      practitionerUserId: state.ids.practitionerUserId,
      patientId: state.ids.patientId,
      encounterId: state.ids.encounterId,
      operationIds: config.operationIds
    })
  });
}

function serializedMutationEvidence(state) {
  return Object.freeze(state.mutations.map(record => Object.freeze({
    ordinal: record.ordinal,
    name: record.name,
    authority: record.authority,
    resource: record.resource,
    dispatched: record.dispatched,
    responseStatus: record.responseStatus,
    requestFailed: record.requestFailed
  })));
}

function baseEvidence(config, planRecord, admission, state, status, observedAt, error = null) {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_single_bounded_treatment_fixture_provisioning',
    status,
    startedAt: state.startedAt,
    observedAt,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    controllerOwnedRunner: true,
    controller: {
      repository: config.runtime.repository,
      ref: config.runtime.ref,
      commit: config.runtime.commit,
      workflowPath: config.runtime.workflowPath,
      runId: config.runtime.runId,
      runAttempt: 1
    },
    policySha256: POLICY_SHA256,
    planSha256: planRecord.sha256,
    authorization: {
      decision: admission.decision,
      authorizationEvidenceSha256: admission.authorizationEvidenceSha256,
      authorizationBundleSha256: admission.authorizationBundleSha256,
      authorizedAt: admission.authorizedAt,
      expiresAt: admission.expiresAt
    },
    target: config.target,
    source: { commit: config.sourceCommit, tree: config.sourceTree },
    deployId: config.deployId,
    fixtureRunId: config.fixtureRunId,
    practitionerEmailSha256: sha256(Buffer.from(config.practitionerEmail)),
    fixtureIds: {
      practitionerUserId: state.ids.practitionerUserId,
      patientId: state.ids.patientId,
      patientHnSha256: state.ids.patientHn ? sha256(Buffer.from(state.ids.patientHn)) : null,
      encounterId: state.ids.encounterId,
      operationIds: config.operationIds
    },
    invariants: {
      freshAuthUser: Boolean(state.ids.practitionerUserId),
      authoritativeSyntheticMetadataVerified: state.practitionerAuthenticated,
      controlPlaneReadbackVerified: state.controlPlaneReadbackVerified,
      exactClinicalReadbackVerified: state.baselineVerified,
      baselineTreatmentSessions: state.baselineVerified ? 0 : null,
      baselinePrescriptions: state.baselineVerified ? 0 : null,
      baselineVitalSigns: state.baselineVerified ? 0 : null,
      baselinePainAssessments: state.baselineVerified ? 0 : null,
      baselineAllergies: state.baselineVerified ? 0 : null
    },
    mutations: serializedMutationEvidence(state),
    mutationLimit: {
      freshAuthUsers: 1,
      serviceRoleTableWrites: 2,
      authenticatedClinicalRpcWrites: 2,
      writeRetries: 0,
      observedRetries: 0
    },
    failure: status === 'PASS' ? null : {
      code: error instanceof SingleFixtureProvisionError ? error.code :
        'CNYOS_SINGLE_FIXTURE_PROVISIONING_FAILED',
      operation: error instanceof SingleFixtureProvisionError ? error.operation : null,
      uncertain: status === 'UNCERTAIN'
    },
    cleanup: { status: 'NOT_AUTHORIZED', attempted: false },
    secretsSerialized: false
  };
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

async function createFreshPublicationDirectory(config) {
  const prefix = path.join(config.outputDirectory, '.unpublished-');
  let directory;
  try { directory = await fs.mkdtemp(prefix); }
  catch { fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_CREATE_FAILED'); }
  const status = await fs.lstat(directory).catch(() => null);
  if (!status?.isDirectory() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o700) {
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_CREATE_FAILED');
  }
  return directory;
}

async function reserveFreshOutputDirectory(config) {
  try { await fs.mkdir(config.outputDirectory, { mode: 0o700 }); }
  catch { fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_CREATE_FAILED'); }
  const status = await fs.lstat(config.outputDirectory).catch(() => null);
  if (!status?.isDirectory() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o700) {
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_CREATE_FAILED');
  }
}

async function writeFresh0600(filename, bytes) {
  let handle;
  try {
    handle = await fs.open(filename, fsConstants.O_WRONLY | fsConstants.O_CREAT |
      fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    const status = await fs.lstat(filename);
    if (!status.isFile() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o600 ||
      status.size !== bytes.length) fail('CNYOS_SINGLE_FIXTURE_OUTPUT_FILE_INVALID');
  } catch (error) {
    if (error instanceof SingleFixtureProvisionError) throw error;
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_WRITE_FAILED');
  } finally { await handle?.close().catch(() => {}); }
}

async function syncOutputDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, fsConstants.O_RDONLY);
    await handle.sync();
  } catch { fail('CNYOS_SINGLE_FIXTURE_OUTPUT_SYNC_FAILED'); }
  finally { await handle?.close().catch(() => {}); }
}

async function publishFreshDirectory(config, stagingDirectory) {
  const finalDirectory = path.join(config.outputDirectory, 'result');
  const existing = await fs.lstat(finalDirectory).catch(error => {
    if (error?.code === 'ENOENT') return null;
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_INVALID');
  });
  if (existing) fail('CNYOS_SINGLE_FIXTURE_OUTPUT_ALREADY_EXISTS');
  await syncOutputDirectory(stagingDirectory);
  const stagingStatus = await fs.lstat(stagingDirectory, { bigint: true }).catch(() => null);
  if (!stagingStatus?.isDirectory() || stagingStatus.isSymbolicLink() ||
    stagingStatus.mode !== BigInt(0o40700)) {
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_PUBLISH_FAILED');
  }
  try { await fs.rename(stagingDirectory, finalDirectory); }
  catch {
    // On a local filesystem an error normally means rename did not commit.  If
    // the runtime reports an error after committing, inode equality is the only
    // accepted reconciliation; never publish a second result over it.
    const observed = await fs.lstat(finalDirectory, { bigint: true }).catch(() => null);
    if (observed?.isDirectory() && !observed.isSymbolicLink() &&
      observed.dev === stagingStatus.dev && observed.ino === stagingStatus.ino) {
      return finalDirectory;
    }
    fail('CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_PUBLISH_FAILED');
  }
  // Rename is the commit point.  Every fallible validation and file fsync was
  // completed against the private staging inode before this call.
  return finalDirectory;
}

async function discardOwnedUnpublishedDirectory(config, stagingDirectory) {
  if (path.dirname(stagingDirectory) !== config.outputDirectory ||
    !path.basename(stagingDirectory).startsWith('.unpublished-')) return;
  await fs.rm(stagingDirectory, { recursive: true, force: true }).catch(() => {});
}

async function publishSuccess(config, planRecord, admission, state, publicationTime) {
  const verifiedAt = publicationTime.toISOString();
  const fixture = buildTreatmentFixture(config, state);
  const ledger = buildProtectedLedger(config, state, fixture, verifiedAt);
  const fixtureBytes = jsonBytes(fixture);
  const ledgerBytes = jsonBytes(ledger);
  const evidence = baseEvidence(config, planRecord, admission, state, 'PASS', verifiedAt);
  evidence.outputs = {
    fixture: { name: 'treatment-fixture.json', sha256: sha256(fixtureBytes), mode: '0600' },
    protectedLedger: {
      name: 'protected-treatment-fixture-ledger.json',
      sha256: sha256(ledgerBytes),
      mode: '0600'
    }
  };
  const evidenceBytes = jsonBytes(evidence);
  const stagingDirectory = await createFreshPublicationDirectory(config);
  let finalDirectory;
  try {
    await writeFresh0600(path.join(stagingDirectory, evidence.outputs.fixture.name), fixtureBytes);
    await writeFresh0600(path.join(stagingDirectory, evidence.outputs.protectedLedger.name), ledgerBytes);
    await writeFresh0600(path.join(stagingDirectory, 'provisioning-evidence.json'), evidenceBytes);
    finalDirectory = await publishFreshDirectory(config, stagingDirectory);
  } catch (error) {
    await discardOwnedUnpublishedDirectory(config, stagingDirectory);
    throw error;
  }
  const fixturePath = path.join(finalDirectory, evidence.outputs.fixture.name);
  const ledgerPath = path.join(finalDirectory, evidence.outputs.protectedLedger.name);
  const evidencePath = path.join(finalDirectory, 'provisioning-evidence.json');
  return Object.freeze({
    status: 'PASS', evidence: Object.freeze(evidence), fixture, ledger,
    fixturePath, ledgerPath, evidencePath,
    fixtureFileSha256: sha256(fixtureBytes),
    ledgerFileSha256: sha256(ledgerBytes),
    evidenceFileSha256: sha256(evidenceBytes)
  });
}

async function publishFailure(config, planRecord, admission, state, error, now) {
  const status = error?.uncertain === true ? 'UNCERTAIN' : 'FAIL';
  const evidence = baseEvidence(config, planRecord, admission, state, status,
    now().toISOString(), error);
  const evidenceBytes = jsonBytes(evidence);
  const stagingDirectory = await createFreshPublicationDirectory(config);
  let finalDirectory;
  try {
    await writeFresh0600(path.join(stagingDirectory, 'provisioning-evidence.json'), evidenceBytes);
    finalDirectory = await publishFreshDirectory(config, stagingDirectory);
  } catch (publicationError) {
    await discardOwnedUnpublishedDirectory(config, stagingDirectory);
    throw publicationError;
  }
  const evidencePath = path.join(finalDirectory, 'provisioning-evidence.json');
  return Object.freeze({
    status, evidence: Object.freeze(evidence), fixture: null, ledger: null,
    fixturePath: null, ledgerPath: null, evidencePath,
    fixtureFileSha256: null, ledgerFileSha256: null,
    evidenceFileSha256: sha256(evidenceBytes)
  });
}

async function executeProvisioning(config, fetchImpl, state) {
  await assertFreshAuthEmail(config, fetchImpl);
  await createAuthUser(config, fetchImpl, state);
  await writeProfile(config, fetchImpl, state);
  await writeMembership(config, fetchImpl, state);
  const accessToken = await authenticatePractitioner(config, fetchImpl, state);
  await verifyControlPlaneRows(config, fetchImpl, state);
  await createPatient(config, fetchImpl, state, accessToken);
  await createEncounter(config, fetchImpl, state, accessToken);
  await verifyClinicalReadback(config, fetchImpl, state, accessToken);
  assertMutationBoundary(state);
}

export async function runSingleFixtureProvisioning(env = process.env, {
  fetchImpl = fetch,
  authorizationHook = null,
  now = () => new Date(),
  randomUUID = () => crypto.randomUUID(),
  controllerRuntime = null
} = {}) {
  const config = loadSingleFixtureProvisioningConfig(env, { randomUUID, controllerRuntime });
  await assertFreshOutputDestination(config);
  const planRecord = buildSingleFixtureProvisioningPlan(config);
  const admission = await authorizeSingleFixtureProvisioning(config, planRecord,
    authorizationHook, { now });
  const state = {
    startedAt: now().toISOString(),
    now,
    authorizationExpiresAtMs: Date.parse(admission.expiresAt),
    mutations: [],
    practitionerAuthenticated: false,
    controlPlaneReadbackVerified: false,
    baselineVerified: false,
    ids: {
      practitionerUserId: null,
      patientId: null,
      patientHn: null,
      encounterId: null,
      encounterNo: null
    }
  };
  await reserveFreshOutputDirectory(config);
  try {
    await executeProvisioning(config, fetchImpl, state);
    const publicationTime = assertAdmissionActive(state, 'publish_success');
    return await publishSuccess(config, planRecord, admission, state, publicationTime);
  } catch (error) {
    const normalized = error instanceof SingleFixtureProvisionError ? error :
      new SingleFixtureProvisionError('CNYOS_SINGLE_FIXTURE_PROVISIONING_FAILED', {
        uncertain: state.mutations.some(record => record.dispatched)
      });
    return publishFailure(config, planRecord, admission, state, normalized, now);
  }
}

async function main() {
  // The live adapter intentionally does not exist here. A protected controller
  // entrypoint must import runSingleFixtureProvisioning and supply a hook that
  // has already validated its signed authorization bundle and scoped admission.
  process.stderr.write('CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_HOOK_REQUIRED\n');
  process.exitCode = 1;
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();
