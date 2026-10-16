import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import {
  EXACT_STAGING_SYNTHETIC_HN_PATTERN,
  EXACT_STAGING_TARGET,
  ExactStagingReleaseError,
  assertScopedOpdWriteBody,
  assertSecretFreeEvidence,
  createScopedOpdWriteLedger,
  loadExactStagingConfig,
  parseNetlifyDeployReceipt,
  sha256,
  verifyExactStagingArtifact,
  writeFresh0600
} from './exact-staging-release.mjs';

const MAX_BODY = 2 * 1024 * 1024;
const CONTROLLER_REPOSITORY = 'apisarit/cnyos-staging-deployment-control';
const CONTROLLER_WORKFLOW_PATH = '.github/workflows/cnyos-exact-staging-deploy-uat.yml';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ROLE_SPECS = Object.freeze([
  Object.freeze({ key: 'reception', profileRole: 'reception', systemRole: 'staff', clinicRole: 'reception' }),
  Object.freeze({ key: 'source_practitioner', profileRole: 'practitioner', systemRole: 'staff', clinicRole: 'practitioner' }),
  Object.freeze({ key: 'attending', profileRole: 'doctor', systemRole: 'staff', clinicRole: 'doctor' }),
  Object.freeze({ key: 'pharmacy_reviewer', profileRole: 'pharmacy', systemRole: 'staff', clinicRole: 'pharmacy' }),
  Object.freeze({ key: 'pharmacy_dispenser', profileRole: 'pharmacy', systemRole: 'staff', clinicRole: 'pharmacy' }),
  Object.freeze({ key: 'billing', profileRole: 'billing', systemRole: 'staff', clinicRole: 'billing' }),
  Object.freeze({ key: 'admin', profileRole: 'viewer', systemRole: 'admin', clinicRole: 'admin' })
]);
const OPD_FIELDS = Object.freeze([
  ['#opd-accident', 'synthetic accident'], ['#opd-surgery', 'synthetic surgery'],
  ['#opd-chronic', 'synthetic chronic'], ['#opd-family', 'synthetic family'],
  ['#opd-personal', 'synthetic personal'], ['#opd-food', 'synthetic food'],
  ['#opd-water', '2'], ['#opd-coffee', '0'], ['#opd-smoking', 'none'],
  ['#opd-alcohol', 'none'], ['#opd-urination', '4'], ['#opd-bowel', '1'],
  ['#opd-sleep', '7 hours'], ['#opd-posture', 'upright'], ['#opd-emotion', 'calm'],
  ['#opd-allergy', 'none known'], ['#opd-menstruation', 'synthetic only'],
  ['#opd-meds', 'synthetic supplement'], ['#opd-physical', 'synthetic baseline exam']
]);
const READ_ONLY_BROWSER_RPCS = new Set([
  'clinical_financial_handoffs_healthcheck', 'clinical_outcomes_summary',
  'current_access_context', 'department_persistence_healthcheck',
  'get_clinical_consult_request', 'get_ipd_admission',
  'hybrid_patient_identity_healthcheck', 'list_appointment_practitioners',
  'list_billable_treatment_encounters', 'list_clinic_product_price_completeness',
  'list_clinical_consult_receivers', 'list_ipd_attending_candidates',
  'list_patient_identity_links', 'list_spa_billing_routes', 'list_spa_services',
  'prescription_dispensing_healthcheck', 'production_execution_healthcheck',
  'quality_release_healthcheck', 'search_clinical_outcomes', 'search_patients_for_checkin'
]);

function fail(code, options) {
  throw new ExactStagingReleaseError(code, options);
}

function required(value, code, maximum = 8192) {
  const result = String(value ?? '').trim();
  if (!result || result.length > maximum) fail(code);
  return result;
}

function first(value, code) {
  const row = Array.isArray(value) && value.length === 1 ? value[0] : value;
  if (!row || typeof row !== 'object' || Array.isArray(row)) fail(code);
  return row;
}

function randomKey() {
  return crypto.randomUUID();
}

function controllerEvidence(config) {
  return Object.freeze({
    repository: CONTROLLER_REPOSITORY,
    commit: config.controllerCommit,
    workflowPath: CONTROLLER_WORKFLOW_PATH
  });
}

class MutationBudget {
  constructor(limit) {
    this.limit = limit;
    this.records = [];
  }
  dispatch(name, authority, resource) {
    if (this.records.length >= this.limit) fail('CNYOS_EXACT_STAGING_MUTATION_BUDGET_EXCEEDED');
    const record = {
      ordinal: this.records.length + 1, name, authority, resource,
      dispatched: true, status: null, uncertain: false
    };
    this.records.push(record);
    return record;
  }
  result(record, status) { record.status = status; }
  uncertain(record) { record.uncertain = true; }
}

async function requestJson(url, {
  method = 'GET', headers = {}, body, expected = [200], mutation = null,
  timeoutMs = 20_000
} = {}) {
  let response;
  try {
    response = await fetch(url, {
      method,
      headers: { Accept: 'application/json', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(timeoutMs)
    });
  } catch {
    if (mutation) {
      mutation.uncertain = true;
      fail('CNYOS_EXACT_STAGING_MUTATION_REQUEST_UNCERTAIN', { uncertain: true });
    }
    fail('CNYOS_EXACT_STAGING_REQUEST_FAILED');
  }
  if (mutation) mutation.status = response.status;
  let bytes;
  try { bytes = Buffer.from(await response.arrayBuffer()); }
  catch {
    if (mutation) fail('CNYOS_EXACT_STAGING_MUTATION_RESPONSE_UNCERTAIN', { uncertain: true });
    fail('CNYOS_EXACT_STAGING_RESPONSE_INVALID');
  }
  if (bytes.length > MAX_BODY) fail('CNYOS_EXACT_STAGING_RESPONSE_TOO_LARGE');
  if (!expected.includes(response.status)) {
    if (mutation && (response.status >= 500 || [408, 425, 429].includes(response.status))) {
      fail('CNYOS_EXACT_STAGING_MUTATION_STATUS_UNCERTAIN', { uncertain: true });
    }
    let message = '';
    try { message = JSON.parse(bytes.toString('utf8'))?.message || bytes.toString('utf8'); }
    catch { message = bytes.toString('utf8'); }
    fail(`CNYOS_EXACT_STAGING_STATUS_${response.status}:${message.slice(0, 200)}`);
  }
  if (!bytes.length) return null;
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_EXACT_STAGING_RESPONSE_JSON_INVALID'); }
}

function supabase(pathname) {
  const url = new URL(pathname, `${EXACT_STAGING_TARGET.supabaseOrigin}/`);
  if (url.origin !== EXACT_STAGING_TARGET.supabaseOrigin) fail('CNYOS_EXACT_STAGING_TARGET_INVALID');
  return url.href;
}

function serviceHeaders(serviceRoleKey, body = false) {
  return {
    apikey: serviceRoleKey,
    Authorization: `Bearer ${serviceRoleKey}`,
    ...(body ? { 'Content-Type': 'application/json' } : {})
  };
}

function userHeaders(publishableKey, token, body = false) {
  return {
    apikey: publishableKey,
    Authorization: `Bearer ${token}`,
    ...(body ? { 'Content-Type': 'application/json', 'Content-Profile': 'public' } :
      { 'Accept-Profile': 'public' })
  };
}

async function rpc({ publishableKey, token, budget, role }, name, body) {
  const record = budget.dispatch(name, role, `/rest/v1/rpc/${name}`);
  return requestJson(supabase(`/rest/v1/rpc/${name}`), {
    method: 'POST', headers: userHeaders(publishableKey, token, true), body,
    expected: [200], mutation: record
  });
}

async function listExistingEmails(serviceRoleKey, emails) {
  const wanted = new Set(emails);
  for (let page = 1; page <= 50; page += 1) {
    const value = await requestJson(supabase(`/auth/v1/admin/users?page=${page}&per_page=100`), {
      headers: serviceHeaders(serviceRoleKey)
    });
    const users = Array.isArray(value) ? value : value?.users;
    if (!Array.isArray(users) || users.length > 100) fail('CNYOS_EXACT_STAGING_AUTH_LIST_INVALID');
    for (const user of users) {
      if (wanted.has(String(user?.email || '').toLowerCase())) {
        fail('CNYOS_EXACT_STAGING_SYNTHETIC_EMAIL_COLLISION');
      }
    }
    if (users.length < 100) return;
  }
  fail('CNYOS_EXACT_STAGING_AUTH_LIST_LIMIT_EXCEEDED');
}

function identityEmail(runId, role) {
  const local = `${role.replaceAll('_', '-')}.${sha256(`${runId}:${role}`).slice(0, 20)}`;
  return `${local}@cnyos.invalid`;
}

async function provisionAccounts({ config, serviceRoleKey, password, budget }) {
  const accounts = Object.fromEntries(ROLE_SPECS.map(spec => [spec.key, {
    ...spec,
    email: identityEmail(config.runId, spec.key),
    fullName: `SYNTHETIC ${spec.key.toUpperCase().replaceAll('_', ' ')} ${config.runId}`
  }]));
  await listExistingEmails(serviceRoleKey, Object.values(accounts).map(account => account.email));
  for (const spec of ROLE_SPECS) {
    const account = accounts[spec.key];
    const markers = {
      synthetic_staging_only: true,
      expected_role: spec.key,
      fixture_run_id: config.runId
    };
    const authMutation = budget.dispatch('create_auth_user', 'service_role', '/auth/v1/admin/users');
    const created = await requestJson(supabase('/auth/v1/admin/users'), {
      method: 'POST', headers: serviceHeaders(serviceRoleKey, true),
      body: {
        email: account.email, password, email_confirm: true,
        user_metadata: { full_name: account.fullName, ...markers }, app_metadata: markers
      }, expected: [200, 201], mutation: authMutation
    });
    const user = created?.user || created;
    if (!UUID.test(String(user?.id || '')) ||
      String(user?.email || '').toLowerCase() !== account.email ||
      user?.user_metadata?.synthetic_staging_only !== true ||
      user?.app_metadata?.synthetic_staging_only !== true) {
      fail('CNYOS_EXACT_STAGING_AUTH_CREATE_UNCERTAIN', { uncertain: true });
    }
    account.userId = String(user.id).toLowerCase();
    const profileMutation = budget.dispatch('upsert_profile', 'service_role', '/rest/v1/profiles');
    const profile = await requestJson(supabase('/rest/v1/profiles?on_conflict=id'), {
      method: 'POST', headers: {
        ...serviceHeaders(serviceRoleKey, true),
        Prefer: 'resolution=merge-duplicates,return=representation'
      }, body: [{
        id: account.userId, email: account.email, full_name: account.fullName,
        role: account.profileRole, system_role: account.systemRole,
        updated_at: new Date().toISOString()
      }], expected: [200, 201], mutation: profileMutation
    });
    if (first(profile, 'CNYOS_EXACT_STAGING_PROFILE_RESPONSE_INVALID').id !== account.userId) {
      fail('CNYOS_EXACT_STAGING_PROFILE_RESPONSE_INVALID');
    }
    const membershipMutation = budget.dispatch('insert_clinic_membership', 'service_role',
      '/rest/v1/clinic_memberships');
    const membership = await requestJson(supabase('/rest/v1/clinic_memberships'), {
      method: 'POST', headers: { ...serviceHeaders(serviceRoleKey, true), Prefer: 'return=representation' },
      body: [{
        clinic_id: EXACT_STAGING_TARGET.clinicId, profile_id: account.userId,
        clinic_role: account.clinicRole, is_primary: true, active: true,
        updated_at: new Date().toISOString()
      }], expected: [200, 201], mutation: membershipMutation
    });
    const member = first(membership, 'CNYOS_EXACT_STAGING_MEMBERSHIP_RESPONSE_INVALID');
    if (member.profile_id !== account.userId || member.clinic_id !== EXACT_STAGING_TARGET.clinicId ||
      member.clinic_role !== account.clinicRole || member.active !== true) {
      fail('CNYOS_EXACT_STAGING_MEMBERSHIP_RESPONSE_INVALID');
    }
  }
  return accounts;
}

async function signInAccounts({ accounts, publishableKey, password }) {
  const identities = new Set();
  for (const spec of ROLE_SPECS) {
    const account = accounts[spec.key];
    const signed = await requestJson(supabase('/auth/v1/token?grant_type=password'), {
      method: 'POST', headers: { apikey: publishableKey, 'Content-Type': 'application/json' },
      body: { email: account.email, password }, expected: [200]
    });
    if (signed?.user?.id !== account.userId ||
      signed?.user?.user_metadata?.synthetic_staging_only !== true ||
      signed?.user?.app_metadata?.synthetic_staging_only !== true ||
      !required(signed?.access_token, 'CNYOS_EXACT_STAGING_LOGIN_INVALID')) {
      fail('CNYOS_EXACT_STAGING_LOGIN_INVALID');
    }
    account.token = signed.access_token;
    identities.add(account.userId);
  }
  if (identities.size !== ROLE_SPECS.length) fail('CNYOS_EXACT_STAGING_ACCOUNT_SEPARATION_INVALID');
  return accounts;
}

async function verifyHostedRelease(config, receipt, token, artifact) {
  const apiHeaders = { Authorization: `Bearer ${token}` };
  const deploy = await requestJson(`https://api.netlify.com/api/v1/deploys/${receipt.deployId}`, {
    headers: apiHeaders
  });
  if (String(deploy?.site_id || '').toLowerCase() !== EXACT_STAGING_TARGET.netlifySiteId ||
    deploy?.state !== 'ready') fail('CNYOS_EXACT_STAGING_DEPLOY_NOT_READY');
  const site = await requestJson(
    `https://api.netlify.com/api/v1/sites/${EXACT_STAGING_TARGET.netlifySiteId}`, {
      headers: apiHeaders
    });
  if (String(site?.published_deploy?.id || '').toLowerCase() !== receipt.deployId ||
    site?.ssl_url !== EXACT_STAGING_TARGET.origin) {
    fail('CNYOS_EXACT_STAGING_CANONICAL_DEPLOY_MISMATCH');
  }
  for (const origin of [receipt.exactDeployOrigin, receipt.canonicalOrigin]) {
    const manifest = await requestJson(`${origin}/deploy-manifest.json`);
    if (manifest?.source?.commit !== config.appCommit || manifest?.source?.tree !== config.appTree ||
      manifest?.deploymentId !== EXACT_STAGING_TARGET.deploymentId ||
      manifest?.tenant?.expectedClinicId !== EXACT_STAGING_TARGET.clinicId ||
      manifest?.safety?.stagingDatabaseExplicitlyAcknowledged !== true) {
      fail('CNYOS_EXACT_STAGING_SERVED_MANIFEST_MISMATCH');
    }
    const runtimeResponse = await fetch(`${origin}/runtime-publish-manifest.json`, {
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(20_000)
    });
    const runtimeBytes = Buffer.from(await runtimeResponse.arrayBuffer());
    if (runtimeResponse.status !== 200 || sha256(runtimeBytes) !== artifact.runtimeManifestSha256) {
      fail('CNYOS_EXACT_STAGING_SERVED_RUNTIME_MISMATCH');
    }
  }
}

async function installBrowserGuard(context, config, budget, scope, writeLedger) {
  const exactOrigin = config.exactOrigin;
  const browserState = { contextOrdinal: scope.contextOrdinal, opdWrites: 0, blocked: null };
  await context.route('**/*', async route => {
    const request = route.request();
    const method = request.method().toUpperCase();
    let url;
    try { url = new URL(request.url()); }
    catch { browserState.blocked = 'URL_INVALID'; return route.abort('blockedbyclient'); }
    if (method === 'OPTIONS') return route.continue();
    if ([exactOrigin, 'https://cdn.jsdelivr.net'].includes(url.origin)) {
      if (!['GET', 'HEAD'].includes(method)) {
        browserState.blocked = 'APP_MUTATION_BLOCKED';
        return route.abort('blockedbyclient');
      }
      return route.continue();
    }
    if (url.origin !== EXACT_STAGING_TARGET.supabaseOrigin) {
      browserState.blocked = 'ORIGIN_BLOCKED';
      return route.abort('blockedbyclient');
    }
    if (['GET', 'HEAD'].includes(method)) {
      if (url.pathname.startsWith('/rest/v1/')) {
        const table = url.pathname.slice('/rest/v1/'.length);
        const encounterTables = new Set([
          'body_pain_points', 'clinical_examination_findings', 'clinical_record_signoffs',
          'clinical_treatment_plans', 'clinical_treatment_sessions', 'prescriptions',
          'ttm_opd_histories', 'ttm_structured_diagnoses'
        ]);
        if (table === 'patients') url.searchParams.set('id', `eq.${scope.patientId}`);
        else if (table === 'encounters') url.searchParams.set('id', `eq.${scope.encounterId}`);
        else if (table === 'patient_allergies') {
          url.searchParams.set('patient_id', `eq.${scope.patientId}`);
        } else if (table === 'profiles') {
          url.searchParams.set('id', `eq.${scope.practitionerUserId}`);
        } else if (encounterTables.has(table)) {
          url.searchParams.set('encounter_id', `eq.${scope.encounterId}`);
        }
      }
      return route.continue({ url: url.href });
    }
    if (method === 'POST' && url.pathname === '/auth/v1/token' &&
      url.searchParams.get('grant_type') === 'password') return route.continue();
    if (method === 'POST' && url.pathname.startsWith('/rest/v1/rpc/')) {
      const rpcName = url.pathname.slice('/rest/v1/rpc/'.length);
      if (READ_ONLY_BROWSER_RPCS.has(rpcName)) return route.continue();
      if (rpcName === 'save_ttm_opd_history') {
        try {
          assertScopedOpdWriteBody(request.postData(), request.headers()['content-type'], scope);
        } catch {
          browserState.blocked = 'OPD_WRITE_SCOPE_INVALID';
          return route.abort('blockedbyclient');
        }
        try {
          writeLedger.reserve(scope.contextOrdinal);
        } catch {
          browserState.blocked = 'OPD_WRITE_BUDGET_EXCEEDED';
          return route.abort('blockedbyclient');
        }
        browserState.opdWrites += 1;
        const record = budget.dispatch('save_ttm_opd_history',
          'source_practitioner', url.pathname);
        try {
          const response = await route.fetch({ timeout: config.limits.requestTimeoutMs });
          const status = response.status();
          budget.result(record, status);
          if (status >= 500 || [408, 425, 429].includes(status)) {
            budget.uncertain(record);
            browserState.blocked = 'OPD_WRITE_STATUS_UNCERTAIN';
          }
          return route.fulfill({ response });
        } catch {
          budget.uncertain(record);
          browserState.blocked = 'OPD_WRITE_TRANSPORT_UNCERTAIN';
          return route.abort('failed');
        }
      }
    }
    browserState.blocked = 'SUPABASE_MUTATION_BLOCKED';
    return route.abort('blockedbyclient');
  });
  return browserState;
}

async function browserLogin(page, exactOrigin, account, password) {
  await page.goto(`${exactOrigin}/login.html`, {
    waitUntil: 'domcontentloaded', timeout: 30_000
  });
  await page.waitForFunction(() => Boolean(window.supabase && window.CHANANYA_AUTH), null,
    { timeout: 20_000 });
  const identity = await page.evaluate(async ({ email, password, expectedOrigin }) => {
    const auth = window.CHANANYA_AUTH || {};
    const url = auth.url || auth.supabaseUrl;
    const key = auth.anonKey || auth.publishableKey;
    if (url !== expectedOrigin || !key) return null;
    const client = window.supabase.createClient(url, key, {
      auth: { persistSession: true, autoRefreshToken: false, detectSessionInUrl: false }
    });
    const result = await client.auth.signInWithPassword({ email, password });
    return result.error ? null : {
      id: result.data.user?.id, email: result.data.user?.email,
      synthetic: result.data.user?.user_metadata?.synthetic_staging_only === true &&
        result.data.user?.app_metadata?.synthetic_staging_only === true
    };
  }, { email: account.email, password, expectedOrigin: EXACT_STAGING_TARGET.supabaseOrigin });
  if (identity?.id !== account.userId || identity?.email !== account.email || !identity.synthetic) {
    fail('CNYOS_EXACT_STAGING_BROWSER_LOGIN_INVALID');
  }
}

async function openOpd(browser, config, account, password, patientId, encounterId, budget,
  writeLedger, contextOrdinal) {
  const context = await browser.newContext({
    baseURL: config.exactOrigin, locale: 'en-US', serviceWorkers: 'block', acceptDownloads: false
  });
  const network = await installBrowserGuard(context, config, budget, {
    patientId, encounterId, practitionerUserId: account.userId, contextOrdinal
  }, writeLedger);
  const page = await context.newPage();
  page.on('dialog', dialog => dialog.dismiss());
  await browserLogin(page, config.exactOrigin, account, password);
  await page.goto(`${config.exactOrigin}/clinical-v3.html?encounter=${encounterId}&step=history`, {
    waitUntil: 'domcontentloaded', timeout: 30_000
  });
  await page.waitForSelector('#app:not(.hidden)', { timeout: 30_000 });
  await page.waitForFunction(id => document.querySelector('#encounter')?.value === id,
    encounterId, { timeout: 30_000 });
  await page.waitForFunction(() => /โหลด OPD|ยังไม่มี OPD/.test(
    document.querySelector('#opd-history-status')?.textContent || ''), null, { timeout: 30_000 });
  return { context, page, network };
}

async function submitOpd(page) {
  await page.locator('#opd-history-form').evaluate(form =>
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await page.waitForFunction(() => /บันทึก.*แล้ว/.test(
    document.querySelector('#opd-history-status')?.textContent || ''), null, { timeout: 30_000 });
}

async function runBrowserOpdProof({ config, account, password, patientId, encounterId, budget }) {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  const writeLedger = createScopedOpdWriteLedger(config.limits.browserOpdWrites);
  const evidence = { contexts: 0, saveReloadAmend: false, writes: 0, writeLedger: null };
  try {
    let opened = await openOpd(browser, config, account, password, patientId, encounterId, budget,
      writeLedger, 1);
    evidence.contexts += 1;
    try {
      for (const [selector, value] of OPD_FIELDS) await opened.page.locator(selector).fill(value);
      await submitOpd(opened.page);
      if (opened.network.blocked) fail(`CNYOS_EXACT_STAGING_BROWSER_${opened.network.blocked}`);
      evidence.writes += opened.network.opdWrites;
    } finally { await opened.context.close(); }

    opened = await openOpd(browser, config, account, password, patientId, encounterId, budget,
      writeLedger, 2);
    evidence.contexts += 1;
    try {
      for (const [selector, value] of OPD_FIELDS) {
        assert.equal(await opened.page.inputValue(selector), value,
          `CNYOS_EXACT_STAGING_OPD_RELOAD_MISMATCH:${selector}`);
      }
      await opened.page.locator('#opd-physical').fill('synthetic amended exam');
      await submitOpd(opened.page);
      if (opened.network.blocked) fail(`CNYOS_EXACT_STAGING_BROWSER_${opened.network.blocked}`);
      evidence.writes += opened.network.opdWrites;
    } finally { await opened.context.close(); }

    opened = await openOpd(browser, config, account, password, patientId, encounterId, budget,
      writeLedger, 3);
    evidence.contexts += 1;
    try {
      assert.equal(await opened.page.inputValue('#opd-physical'), 'synthetic amended exam');
      assert.equal(await opened.page.inputValue('#opd-accident'), 'synthetic accident');
      if (opened.network.blocked) fail(`CNYOS_EXACT_STAGING_BROWSER_${opened.network.blocked}`);
    } finally { await opened.context.close(); }
    evidence.writeLedger = writeLedger.evidence(evidence.contexts);
    if (evidence.writes !== config.limits.browserOpdWrites ||
      evidence.writeLedger.dispatched !== config.limits.browserOpdWrites ||
      evidence.writeLedger.perContext.length !== evidence.contexts) {
      fail('CNYOS_EXACT_STAGING_BROWSER_OPD_WRITE_COUNT_INVALID');
    }
    evidence.saveReloadAmend = true;
    return evidence;
  } finally { await browser.close().catch(() => {}); }
}

async function runClinicalJourney({ config, accounts, publishableKey, serviceRoleKey, password, budget }) {
  const as = role => ({
    publishableKey, token: accounts[role].token, budget, role
  });
  const suffix = config.runId.slice(-8);
  const product = first(await rpc(as('pharmacy_reviewer'), 'upsert_product_master', {
    p_product_id: null, p_sku: `E2E-${suffix}`, p_name_th: `ผลิตภัณฑ์สังเคราะห์ ${suffix}`,
    p_name_en: 'SYNTHETIC PRODUCT - NOT FOR CLINICAL USE', p_category: 'medicine',
    p_dosage_form: 'synthetic-e2e', p_purchase_unit: 'ขวด', p_stock_unit: 'ขวด',
    p_dispense_unit: 'ขวด', p_conversion_factor: 1, p_standard_cost: 25,
    p_min_stock: 0, p_reorder_level: 0
  }), 'CNYOS_EXACT_STAGING_PRODUCT_INVALID');
  const priced = first(await rpc(as('billing'), 'set_clinic_product_price', {
    p_product_id: product.id, p_unit_price: 150, p_currency: 'THB',
    p_reason: `Synthetic exact staging ${config.runId}`
  }), 'CNYOS_EXACT_STAGING_PRICE_INVALID');
  if (Number(priced.unit_price) !== 150) fail('CNYOS_EXACT_STAGING_PRICE_INVALID');
  const lotMutation = budget.dispatch('insert_inventory_lot', 'service_role', '/rest/v1/inventory_lots');
  const future = new Date(Date.now() + 180 * 86400_000).toISOString().slice(0, 10);
  const lot = first(await requestJson(supabase('/rest/v1/inventory_lots'), {
    method: 'POST', headers: { ...serviceHeaders(serviceRoleKey, true), Prefer: 'return=representation' },
    body: [{
      clinic_id: EXACT_STAGING_TARGET.clinicId, product_id: product.id,
      lot_number: `SYNTH-${suffix}-LOT`, expiry_date: future, received_quantity: 10,
      current_quantity: 10, unit: 'ขวด', purchase_cost: 25, status: 'active'
    }], expected: [200, 201], mutation: lotMutation
  }), 'CNYOS_EXACT_STAGING_LOT_INVALID');

  const patient = first(await rpc(as('reception'), 'upsert_patient_registration', {
    p_patient_id: null, p_prefix: 'TEST', p_first_name: 'SYNTHETIC',
    p_last_name: `E2E-${suffix}`, p_national_id: null, p_gender: null,
    p_date_of_birth: null, p_phone: null,
    p_address: 'SYNTHETIC ISOLATED STAGING ONLY - NOT FOR CLINICAL USE',
    p_payment_right: 'SYNTHETIC-E2E', p_emergency_contact_name: null,
    p_allergy: 'SYNTHETIC NONE'
  }), 'CNYOS_EXACT_STAGING_PATIENT_INVALID');
  if (!UUID.test(patient.id) ||
    !new RegExp(EXACT_STAGING_SYNTHETIC_HN_PATTERN).test(String(patient.hn || '')) ||
    String(patient.clinic_id || '').toLowerCase() !== EXACT_STAGING_TARGET.clinicId ||
    patient.payment_right !== 'SYNTHETIC-E2E' || patient.national_id != null ||
    patient.phone != null || patient.email != null ||
    String(patient.created_by || '').toLowerCase() !== accounts.reception.userId) {
    fail('CNYOS_EXACT_STAGING_PATIENT_INVALID');
  }
  const starts = new Date(Date.now() + 72 * 3600_000);
  starts.setUTCSeconds(0, 0);
  const ends = new Date(starts.getTime() + 60 * 60_000);
  const schedule = first(await rpc(as('reception'), 'create_practitioner_schedule', {
    p_practitioner_id: accounts.source_practitioner.userId,
    p_title: `Synthetic exact staging ${config.runId}`, p_starts_at: starts.toISOString(),
    p_ends_at: ends.toISOString(), p_branch_code: 'SYNTHETIC', p_room_code: 'E2E-01',
    p_max_patients: 1, p_slot_minutes: 60,
    p_notes: `Synthetic only ${config.runId}`
  }), 'CNYOS_EXACT_STAGING_SCHEDULE_INVALID');
  const appointment = first(await rpc(as('reception'), 'book_clinic_appointment', {
    p_patient_id: patient.id, p_schedule_id: schedule.id,
    p_chief_complaint: 'SYNTHETIC E2E FLOW - NOT CLINICAL ADVICE',
    p_notes: `Synthetic appointment ${config.runId}`, p_booking_source: 'staff'
  }), 'CNYOS_EXACT_STAGING_APPOINTMENT_INVALID');
  const encounter = first(await rpc(as('reception'), 'check_in_clinic_appointment', {
    p_appointment_id: appointment.id, p_patient_id: patient.id, p_qr_session_id: null,
    p_verification_method: 'manual_hn', p_patient_present_confirmed: true,
    p_verification_note: `Synthetic check-in ${config.runId}`,
    p_chief_complaint: 'SYNTHETIC E2E FLOW - NOT CLINICAL ADVICE',
    p_intake: { synthetic_only: true, staging_run_id: config.runId }
  }), 'CNYOS_EXACT_STAGING_CHECKIN_INVALID');
  await rpc(as('source_practitioner'), 'set_clinic_appointment_status', {
    p_appointment_id: appointment.id, p_new_status: 'in_service',
    p_note: `Synthetic source clinician handoff ${config.runId}`
  });

  const browser = await runBrowserOpdProof({
    config, account: accounts.source_practitioner, password,
    patientId: patient.id, encounterId: encounter.encounter_id, budget
  });

  const consult = first(await rpc(as('source_practitioner'), 'create_clinical_consult_request', {
    p_source_encounter_id: encounter.encounter_id, p_request_key: randomKey(),
    p_request_type: 'consult', p_receiving_service: 'SYNTHETIC IPD',
    p_reason: `Synthetic consult ${config.runId}`, p_urgency: 'routine',
    p_requested_receiver_id: accounts.attending.userId
  }), 'CNYOS_EXACT_STAGING_CONSULT_INVALID');
  const acknowledged = first(await rpc(as('attending'), 'transition_clinical_consult_request', {
    p_request_id: consult.request_id, p_action: 'acknowledge', p_expected_version: 1,
    p_request_key: randomKey(), p_reason: null, p_clinical_response: null
  }), 'CNYOS_EXACT_STAGING_CONSULT_ACK_INVALID');
  const accepted = first(await rpc(as('attending'), 'transition_clinical_consult_request', {
    p_request_id: consult.request_id, p_action: 'accept',
    p_expected_version: acknowledged.version, p_request_key: randomKey(),
    p_reason: null, p_clinical_response: null
  }), 'CNYOS_EXACT_STAGING_CONSULT_ACCEPT_INVALID');
  const completed = first(await rpc(as('attending'), 'transition_clinical_consult_request', {
    p_request_id: consult.request_id, p_action: 'complete',
    p_expected_version: accepted.version, p_request_key: randomKey(),
    p_reason: null, p_clinical_response: `Synthetic response ${config.runId}`
  }), 'CNYOS_EXACT_STAGING_CONSULT_COMPLETE_INVALID');
  if (completed.status !== 'completed') fail('CNYOS_EXACT_STAGING_CONSULT_COMPLETE_INVALID');

  const admission = first(await rpc(as('source_practitioner'), 'create_ipd_admission_request', {
    p_source_encounter_id: encounter.encounter_id,
    p_requested_attending_id: accounts.attending.userId,
    p_request_key: randomKey(), p_admission_reason: `Synthetic IPD request ${config.runId}`
  }), 'CNYOS_EXACT_STAGING_IPD_REQUEST_INVALID');
  const placed = first(await rpc(as('reception'), 'transition_ipd_admission', {
    p_admission_id: admission.admission_id, p_action: 'assign_bed',
    p_expected_version: admission.version, p_request_key: randomKey(),
    p_ward_code: 'SYNTH-A', p_bed_code: `BED-${suffix.slice(-2)}`, p_note: null
  }), 'CNYOS_EXACT_STAGING_IPD_PLACEMENT_INVALID');
  const admitted = first(await rpc(as('attending'), 'transition_ipd_admission', {
    p_admission_id: admission.admission_id, p_action: 'admit',
    p_expected_version: placed.version, p_request_key: randomKey(),
    p_ward_code: null, p_bed_code: null, p_note: `Synthetic admission ${config.runId}`
  }), 'CNYOS_EXACT_STAGING_IPD_ADMIT_INVALID');
  const note = first(await rpc(as('attending'), 'append_ipd_clinical_entry', {
    p_admission_id: admission.admission_id, p_entry_type: 'progress_note',
    p_content: `Synthetic progress note ${config.runId} - NOT CLINICAL ADVICE`,
    p_expected_version: admitted.version, p_request_key: randomKey(),
    p_supersedes_entry_id: null, p_related_entry_id: null
  }), 'CNYOS_EXACT_STAGING_IPD_NOTE_INVALID');

  const prescription = first(await rpc(as('source_practitioner'),
    'create_atomic_prescription_handoff', {
      p_request_key: randomKey(), p_encounter_id: encounter.encounter_id,
      p_clinical_notes: `Synthetic pharmacy handoff ${config.runId}`,
      p_items: [{
        product_id: product.id, quantity_prescribed: 1, unit: 'ขวด',
        dose: 'synthetic', frequency: 'demo only', duration: 'demo only',
        instructions: 'SYNTHETIC - NOT FOR CLINICAL USE'
      }]
    }), 'CNYOS_EXACT_STAGING_PRESCRIPTION_INVALID');
  const reviewed = await rpc(as('pharmacy_reviewer'),
    'transition_atomic_prescription_dispensing', {
      p_dispensing_order_id: prescription.dispensing_order_id, p_action: 'review',
      p_item_prices: [], p_reason: `Synthetic reviewer ${config.runId}`
    });
  const dispensed = await rpc(as('pharmacy_dispenser'),
    'transition_atomic_prescription_dispensing', {
      p_dispensing_order_id: prescription.dispensing_order_id, p_action: 'dispense',
      p_item_prices: [], p_reason: `Synthetic dispenser ${config.runId}`
    });
  const submitted = await rpc(as('pharmacy_dispenser'),
    'transition_atomic_prescription_dispensing', {
      p_dispensing_order_id: prescription.dispensing_order_id, p_action: 'submit_billing',
      p_item_prices: [], p_reason: `Synthetic billing handoff ${config.runId}`
    });
  if (reviewed.status !== 'reviewed' || dispensed.status !== 'dispensed' ||
    submitted.status !== 'submitted_to_billing') {
    fail('CNYOS_EXACT_STAGING_PHARMACY_TRANSITION_INVALID');
  }
  const invoice = first(await rpc(as('billing'), 'issue_atomic_dispensing_invoice', {
    p_dispensing_order_id: prescription.dispensing_order_id,
    p_service_fee: 650, p_discount: 0
  }), 'CNYOS_EXACT_STAGING_INVOICE_INVALID');
  if (Number(invoice.grand_total) !== 800) fail('CNYOS_EXACT_STAGING_INVOICE_TOTAL_INVALID');
  const payment = first(await rpc(as('billing'), 'record_atomic_invoice_payment', {
    p_request_key: randomKey(), p_invoice_id: invoice.invoice_id,
    p_amount: 800, p_channel: 'cash',
    p_reference_note: `Synthetic exact staging ${config.runId}`
  }), 'CNYOS_EXACT_STAGING_PAYMENT_INVALID');
  if (payment.invoice_status !== 'paid') fail('CNYOS_EXACT_STAGING_PAYMENT_INVALID');

  return {
    syntheticOnly: true,
    realPhiUsed: false,
    runId: config.runId,
    actorIds: Object.fromEntries(ROLE_SPECS.map(spec => [spec.key, accounts[spec.key].userId])),
    patient: {
      id: patient.id, hn: patient.hn, syntheticRunSuffix: suffix,
      hnGeneratedByServer: true, clinicId: EXACT_STAGING_TARGET.clinicId,
      paymentRight: 'SYNTHETIC-E2E', realIdentifiersAbsent: true
    },
    appointment: { id: appointment.id, number: appointment.appointment_no },
    encounter: { id: encounter.encounter_id, number: encounter.encounter_no },
    opdBrowserProof: browser,
    consult: { id: consult.request_id, status: completed.status, version: completed.version },
    admission: {
      id: admission.admission_id, status: admitted.status, versionAfterNote: note.admission_version,
      attendingActorId: accounts.attending.userId
    },
    pharmacy: {
      productId: product.id, lotId: lot.id, prescriptionId: prescription.prescription_id,
      dispensingOrderId: prescription.dispensing_order_id,
      reviewerActorId: accounts.pharmacy_reviewer.userId,
      dispenserActorId: accounts.pharmacy_dispenser.userId,
      separated: accounts.pharmacy_reviewer.userId !== accounts.pharmacy_dispenser.userId
    },
    billing: {
      invoiceId: invoice.invoice_id, invoiceNumber: invoice.invoice_number,
      grandTotal: Number(invoice.grand_total), paymentId: payment.payment_id,
      invoiceStatus: payment.invoice_status, actorId: accounts.billing.userId
    },
    admin: { actorId: accounts.admin.userId, separatelyAuthenticated: true }
  };
}

async function main() {
  const configBase = loadExactStagingConfig();
  const receiptPath = path.join(configBase.privateDirectory, 'netlify-deploy-receipt.json');
  let config = configBase;
  let receipt = null;
  const budget = new MutationBudget(configBase.limits.totalMutations);
  const started = Date.now();
  let secrets = [];
  let accounts;
  try {
    let receiptBytes;
    try {
      receiptBytes = await fs.readFile(receiptPath);
      const receiptRaw = JSON.parse(receiptBytes.toString('utf8'));
      receipt = parseNetlifyDeployReceipt(receiptRaw, configBase);
    } catch {
      const receiptError = {
        schemaVersion: 1, kind: 'cnyos_exact_staging_deploy_receipt_error',
        status: 'UNCERTAIN', stagingOnly: true, productionAuthorized: false,
        controller: controllerEvidence(configBase),
        source: { commit: configBase.appCommit, tree: configBase.appTree },
        rawByteLength: receiptBytes?.length ?? null,
        rawSha256: receiptBytes ? sha256(receiptBytes) : null,
        rawContentSerialized: false,
        failureCode: 'CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_UNCERTAIN'
      };
      await writeFresh0600(path.join(configBase.uploadDirectory,
        'deploy-receipt-error.json'), receiptError);
      fail('CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_UNCERTAIN', { uncertain: true });
    }
    config = Object.freeze({ ...configBase, exactOrigin: receipt.exactDeployOrigin });
    await writeFresh0600(path.join(config.uploadDirectory, 'deploy-receipt.json'), receipt);
    const netlifyToken = required(process.env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN,
      'CNYOS_EXACT_STAGING_NETLIFY_TOKEN_REQUIRED');
    const serviceRoleKey = required(process.env.CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY,
      'CNYOS_EXACT_STAGING_SERVICE_ROLE_KEY_REQUIRED');
    const publishableKey = required(process.env.CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY,
      'CNYOS_EXACT_STAGING_PUBLISHABLE_KEY_REQUIRED');
    const password = required(process.env.CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD,
      'CNYOS_EXACT_STAGING_PASSWORD_REQUIRED');
    if (!/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(publishableKey) ||
      password.length < 16 || serviceRoleKey.length < 20 || netlifyToken.length < 20 ||
      new Set([netlifyToken, serviceRoleKey, publishableKey, password]).size !== 4) {
      fail('CNYOS_EXACT_STAGING_SECRET_BOUNDARY_INVALID');
    }
    secrets = [netlifyToken, serviceRoleKey, publishableKey, password];
    const artifact = (await verifyExactStagingArtifact(config)).artifact;
    await verifyHostedRelease(config, receipt, netlifyToken, artifact);
    accounts = await provisionAccounts({ config, serviceRoleKey, password, budget });
    await signInAccounts({ accounts, publishableKey, password });
    const journey = await runClinicalJourney({
      config, accounts, publishableKey, serviceRoleKey, password, budget
    });
    if (Date.now() - started > config.limits.uatTimeoutMs) {
      fail('CNYOS_EXACT_STAGING_UAT_TIMEOUT_EXCEEDED');
    }
    const accountEvidence = Object.fromEntries(ROLE_SPECS.map(spec => [spec.key, {
      userId: accounts[spec.key].userId,
      emailSha256: sha256(accounts[spec.key].email),
      profileRole: spec.profileRole, systemRole: spec.systemRole, clinicRole: spec.clinicRole,
      syntheticMarkerVerified: true, authenticatedSessionVerified: true
    }]));
    const fixtureEvidence = {
      schemaVersion: 1, kind: 'cnyos_exact_staging_synthetic_fixture',
      status: 'PASS', syntheticOnly: true, realPhiUsed: false,
      controller: controllerEvidence(config),
      source: { commit: config.appCommit, tree: config.appTree },
      deployId: receipt.deployId, runId: config.runId,
      accounts: accountEvidence,
      distinctAccountCount: new Set(Object.values(accounts).map(value => value.userId)).size,
      patient: journey.patient,
      limits: config.limits
    };
    const uatEvidence = {
      schemaVersion: 1, kind: 'cnyos_exact_staging_role_separated_uat',
      status: 'PASS', stagingOnly: true, productionAuthorized: false,
      controller: controllerEvidence(config),
      source: { commit: config.appCommit, tree: config.appTree },
      deployment: receipt,
      target: {
        origin: EXACT_STAGING_TARGET.origin, siteId: EXACT_STAGING_TARGET.netlifySiteId,
        supabaseProjectRef: EXACT_STAGING_TARGET.supabaseProjectRef,
        clinicId: EXACT_STAGING_TARGET.clinicId
      },
      journey,
      mutationBudget: {
        limit: budget.limit, dispatched: budget.records.length,
        writeRetries: 0,
        records: budget.records
      },
      startedAt: new Date(started).toISOString(), completedAt: new Date().toISOString()
    };
    await writeFresh0600(path.join(config.uploadDirectory, 'fixture-evidence.json'), fixtureEvidence, secrets);
    await writeFresh0600(path.join(config.uploadDirectory, 'uat-evidence.json'), uatEvidence, secrets);
    const files = [
      'candidate-binding.json', 'rollback-baseline.json', 'publish-intent.json',
      'publish-attempt.json', 'publish-reconciliation.json', 'deploy-receipt.json',
      'fixture-evidence.json', 'uat-evidence.json'
    ];
    const entries = [];
    for (const name of files) {
      const bytes = await fs.readFile(path.join(config.uploadDirectory, name));
      assertSecretFreeEvidence(JSON.parse(bytes), secrets);
      entries.push({ name, size: bytes.length, sha256: sha256(bytes) });
    }
    const manifest = {
      schemaVersion: 1, kind: 'cnyos_exact_staging_evidence_manifest',
      status: 'PASS', stagingOnly: true, productionAuthorized: false,
      controller: controllerEvidence(config),
      source: { commit: config.appCommit, tree: config.appTree },
      deployId: receipt.deployId, rollbackDeployId: config.rollbackDeployId,
      evidence: entries
    };
    await writeFresh0600(path.join(config.uploadDirectory, 'evidence-manifest.json'), manifest, secrets);
    process.stdout.write(`Exact staging UAT PASS for ${config.appCommit} at ${receipt.deployId}\n`);
  } catch (error) {
    const status = error?.uncertain || budget.records.some(record => record.uncertain)
      ? 'UNCERTAIN' : 'FAIL';
    const failure = {
      schemaVersion: 1, kind: 'cnyos_exact_staging_role_separated_uat', status,
      stagingOnly: true, productionAuthorized: false,
      controller: controllerEvidence(config),
      source: { commit: config.appCommit, tree: config.appTree },
      deployId: receipt?.deployId ?? null,
      deployReceiptCaptured: receipt !== null,
      failureCode: String(error?.code || error?.message || 'CNYOS_EXACT_STAGING_UNKNOWN_FAILURE')
        .slice(0, 300),
      mutationBudget: { limit: budget.limit, dispatched: budget.records.length,
        writeRetries: 0, records: budget.records },
      stoppedWithoutRetry: true, completedAt: new Date().toISOString()
    };
    await writeFresh0600(path.join(config.uploadDirectory, 'uat-evidence.json'), failure, secrets)
      .catch(() => {});
    throw error;
  }
}

await main();
