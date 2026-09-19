import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createUatBrowserReadPolicy, UAT_BROWSER_WORKSPACE_PATHS } from '../scripts/controller-uat-browser-read-policy.mjs';
import { UAT_ACCESS_ROLES } from '../scripts/controller-uat-access-observations.mjs';

const siteOrigin = 'https://fixture-stage.example.invalid';
const supabaseOrigin = 'https://fixture-db.example.invalid';
const sessionUserId = '11111111-1111-4111-8111-111111111111';
const bootInstant = '2026-01-01T18:00:00.000Z'; // Jan2 Bangkok, Jan1 UTC
const base = { siteOrigin, supabaseOrigin, sessionUserId, bootInstant };
const policy = (workspace = 'operations', role = 'super_admin', changes = {}) => createUatBrowserReadPolicy({ ...base, workspace, role, ...changes });
const get = (url, resourceType = 'Fetch') => ({ url, method: 'GET', resourceType });
const rest = (table, pairs) => `${supabaseOrigin}/rest/v1/${table}?${new URLSearchParams(pairs)}`;
const rpc = (name, body = '{}') => ({ url: `${supabaseOrigin}/rest/v1/rpc/${name}`, method: 'POST', resourceType: 'Fetch', postData: body });
const accepted = (classify, request, kind = 'json') => {
  const decision = classify(request);
  assert.equal(decision.allowed, true, `expected allowed ${new URL(request.url).pathname}`);
  assert.equal(decision.responseKind, kind);
  assert.ok(Object.isFrozen(decision));
  assert.deepEqual(Object.keys(decision).sort(), ['allowed', 'maxResponseBytes', 'responseKind']);
  assert.ok(Number.isSafeInteger(decision.maxResponseBytes) && decision.maxResponseBytes > 0 && decision.maxResponseBytes <= 4 * 1024 * 1024);
};
const denied = (classify, request) => { assert.deepEqual(classify(request), { allowed: false }); assert.ok(Object.isFrozen(classify(request))); };
const profile = get(rest('profiles', [['select', 'id,role,system_role,full_name,email'], ['id', `eq.${sessionUserId}`]]));

// Every literal boot script/stylesheet in each actual page must have a matching
// positive case, rather than tests that merely inspect a mirrored policy list.
const appRoot = new URL('../test-support/candidate-source/', import.meta.url);
let assetCount = 0;
for (const [workspace, route] of Object.entries(UAT_BROWSER_WORKSPACE_PATHS)) {
  const classify = policy(workspace);
  const html = await fs.readFile(fileURLToPath(new URL(route === '/' ? 'index.html' : route.slice(1), appRoot)), 'utf8');
  accepted(classify, get(`${siteOrigin}${route}`, 'Document'), 'document');
  for (const match of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) {
    const url = new URL(match[1], `${siteOrigin}/`).href;
    accepted(classify, get(url, 'Script'), 'script'); assetCount++;
    denied(classify, get(`${url}&extra=1`, 'Script'));
    denied(classify, { ...get(url, 'Script'), method: 'POST', postData: '{}' });
  }
  for (const match of html.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*href="([^"]+)"/g)) {
    accepted(classify, get(new URL(match[1], `${siteOrigin}/`).href, 'Stylesheet'), 'style'); assetCount++;
  }
  for (const role of UAT_ACCESS_ROLES) {
    accepted(policy(workspace, role), profile);
    accepted(policy(workspace, role), rpc('current_access_context'));
  }
}
assert.ok(assetCount >= 90);

// Independent boot request fixtures, derived from app.js and the page loaders.
for (const [workspace, table, pairs] of [
  ['operations', 'patients', [['select', '*'], ['order', 'created_at.desc']]],
  ['operations', 'invoices', [['select', '*'], ['order', 'created_at.desc']]],
  ['appointments', 'patients', [['select', '*'], ['order', 'created_at.desc'], ['limit', '500']]],
  ['clinical', 'products', [['select', '*'], ['active', 'eq.true'], ['order', 'name_th.asc']]],
  ['clinical', 'encounters', [['select', 'id,encounter_no,patient_id,chief_complaint,thai_diagnosis,started_at,status'], ['order', 'started_at.desc'], ['limit', '250']]],
  ['pharmacy', 'pharmacy_counter_sales', [['select', '*'], ['order', 'created_at.desc']]],
  ['pharmacy', 'pharmacy_counter_sale_items', [['select', '*']]],
  ['production', 'finished_goods_receipts', [['select', '*'], ['order', 'received_at.desc']]],
  ['production', 'formula_components', [['select', '*']]],
  ['quality', 'production_qc', [['select', '*'], ['order', 'created_at.desc']]],
  ['admin', 'admin_task_summary', [['select', '*']]]
]) {
  const request = get(rest(table, pairs)); accepted(policy(workspace), request);
  denied(policy(workspace), { ...request, method: 'PATCH', postData: '{}' });
  denied(policy(workspace), get(`${request.url}&or=%28id.neq.null%29`));
}
for (const [workspace, names] of [
  ['operations', ['hybrid_patient_identity_healthcheck', 'clinical_financial_handoffs_healthcheck']],
  ['checkin', ['hybrid_patient_identity_healthcheck']], ['clinical', ['hybrid_patient_identity_healthcheck', 'clinical_financial_handoffs_healthcheck']],
  ['pharmacy', ['department_persistence_healthcheck', 'prescription_dispensing_healthcheck']],
  ['production', ['production_execution_healthcheck']], ['quality', ['quality_release_healthcheck']]
]) for (const name of names) { accepted(policy(workspace), rpc(name)); denied(policy(workspace), rpc(name, '{"extra":true}')); }

const schedules = get(rest('available_practitioner_schedules', [['select', '*'], ['available_capacity', 'gt.0'], ['order', 'starts_at.asc'],
  ['starts_at', 'gte.2025-12-31T17:00:00.000Z'], ['starts_at', 'lte.2026-01-15T16:59:59.000Z']]));
accepted(policy('appointments'), schedules);
denied(policy('appointments'), get(`${schedules.url}&starts_at=gte.2025-01-01T00%3A00%3A00.000Z`));
accepted(policy('appointments'), get(rest('clinic_appointments', [['select', '*'], ['order', 'scheduled_start.asc'],
  ['scheduled_start', 'gte.2025-12-31T17:00:00.000Z'], ['scheduled_start', 'lte.2026-01-01T16:59:59.000Z']])));
const outcomesRange = { p_from: '2025-10-04T17:00:00.000Z', p_to: '2026-01-02T17:00:00.000Z' };
accepted(policy('outcomes'), rpc('clinical_outcomes_summary', JSON.stringify(outcomesRange)));
accepted(policy('outcomes'), rpc('search_clinical_outcomes', JSON.stringify({ ...outcomesRange, p_query: null, p_limit: 100, p_offset: 0 })));
denied(policy('outcomes'), rpc('search_clinical_outcomes', JSON.stringify({ ...outcomesRange, p_query: 'private sentinel', p_limit: 100, p_offset: 0 })));
// Straddle Bangkok midnight while the UTC date remains unchanged.
const earlier = policy('outcomes', 'super_admin', { bootInstant: '2026-01-01T16:59:59.000Z' });
accepted(earlier, rpc('clinical_outcomes_summary', '{"p_from":"2025-10-03T17:00:00.000Z","p_to":"2026-01-01T17:00:00.000Z"}'));
denied(earlier, rpc('clinical_outcomes_summary', JSON.stringify(outcomesRange)));

const rulesPairs = [['select', '*'], ['active', 'eq.true'], ['order', 'domain.asc,rule_key.asc']];
accepted(policy('clinical', 'viewer'), get(rest('ttm_diagnostic_knowledge', rulesPairs))); // unconditional extension
for (const offset of ['0', '1000', '9000']) accepted(policy('foundation'), get(rest('ttm_diagnostic_knowledge', [...rulesPairs, ['offset', offset], ['limit', '1000']])));
for (const offset of ['1', '10000', '-1']) denied(policy('foundation'), get(rest('ttm_diagnostic_knowledge', [...rulesPairs, ['offset', offset], ['limit', '1000']])));
accepted(policy('pharmacy', 'viewer'), get(rest('dispensing_orders', [['select', 'id,status'], ['status', 'in.(dispensed,submitted_to_billing,billed)']])));
accepted(policy('pharmacy', 'viewer'), get(rest('pharmacy_counter_sales', [['select', 'id,status'], ['status', 'in.(dispensed,submitted_to_billing)']])));
denied(policy('pharmacy', 'viewer'), get(rest('dispensing_orders', [['select', '*'], ['order', 'created_at.desc']])));
denied(policy('clinical', 'viewer'), get(rest('patients', [['select', '*'], ['order', 'created_at.desc'], ['limit', '500']])));
denied(policy('operations', 'viewer'), get(rest('patients', [['select', '*'], ['order', 'created_at.desc']])));
accepted(policy('operations', 'billing'), get(rest('invoices', [['select', '*'], ['order', 'created_at.desc']])));
denied(policy('operations', 'billing'), get(rest('patient_allergies', [['select', '*']])));

const account = { url: `${siteOrigin}/api/account-access`, method: 'POST', resourceType: 'Fetch', postData: '{"action":"staff_list"}' };
accepted(policy('admin', 'admin'), account); denied(policy('admin', 'viewer'), account);
// Source accountStatus() conditionally UPSERTs profiles: never permit its fallback.
for (const workspace of Object.keys(UAT_BROWSER_WORKSPACE_PATHS)) denied(policy(workspace), { ...account, postData: '{"action":"status"}' });
accepted(policy('operations'), get(`${siteOrigin}/api/patient-identity`));
denied(policy('operations'), { ...get(`${siteOrigin}/api/patient-identity`), method: 'POST', postData: '{}' });

const preflight = { ...profile, method: 'OPTIONS', resourceType: 'Preflight', accessControlRequestMethod: 'GET', accessControlRequestHeaders: Object.freeze(['apikey', 'authorization', 'x-client-info']) };
accepted(policy(), preflight, 'empty');
for (const resourceType of ['XHR', 'Fetch']) accepted(policy(), { ...preflight, resourceType }, 'empty');
accepted(policy(), { ...rpc('current_access_context'), method: 'OPTIONS', postData: '', resourceType: 'Preflight',
  accessControlRequestMethod: 'POST', accessControlRequestHeaders: Object.freeze(['apikey', 'authorization', 'content-type', 'x-client-info']) }, 'empty');
for (const change of [{ accessControlRequestMethod: 'DELETE' }, { accessControlRequestHeaders: ['authorization'] },
  { accessControlRequestHeaders: ['apikey', 'authorization', 'x-client-info', 'cookie'] }, { accessControlRequestHeaders: ['apikey', 'authorization', 'x-client-info', 'apikey'] },
  { accessControlRequestHeaders: 'apikey,authorization,x-client-info' },
  { resourceType: 'Other' }, { postData: '{}' }]) denied(policy(), { ...preflight, ...change });
for (const resourceType of ['XHR', 'Fetch']) {
  denied(policy(), { ...preflight, resourceType, accessControlRequestMethod: undefined });
  denied(policy(), { ...preflight, resourceType, accessControlRequestHeaders: [] });
  denied(policy(), { ...preflight, resourceType, url: `${supabaseOrigin}/rest/v1/rpc/unknown` });
}

for (const name of ['book_clinic_appointment', 'resolve_patient_qr', 'confirm_patient_qr', 'search_patients_for_checkin',
  'start_manual_patient_encounter', 'upsert_patient_registration', 'create_atomic_prescription_handoff', 'record_atomic_invoice_payment',
  'quality_release_production_order', 'commit_production_import', 'admin_assign_staff_role', 'department_can', 'unknown']) {
  for (const workspace of Object.keys(UAT_BROWSER_WORKSPACE_PATHS)) denied(policy(workspace), rpc(name));
}
for (const url of [`${supabaseOrigin}/auth/v1/token?grant_type=refresh_token`, `${supabaseOrigin}/auth/v1/user`,
  `${supabaseOrigin}/rest/v1/profiles?select=*`, `${siteOrigin}/logo.png`, `${siteOrigin}/clinical-v3.html?encounter=${sessionUserId}`,
  'https://cdn.jsdelivr.net/npm/jsbarcode@3.11.6/dist/JsBarcode.all.min.js', `${siteOrigin}/login.html`]) denied(policy(), get(url));
for (const url of [profile.url.replace('/profiles?', '/%70rofiles?'), profile.url.replace('/profiles?', '/../v1/profiles?'),
  profile.url.replace('https://', 'https://user@'), profile.url.replace('fixture-db.', 'other.'), `${profile.url}#fragment`,
  `${profile.url}&select=*`, profile.url.replace('select=', 's%65lect='), profile.url.replace('id=eq.', 'id=neq.'),
  profile.url.replace(sessionUserId, '22222222-2222-4222-8222-222222222222')]) denied(policy(), get(url));
denied(policy(), rpc('current_access_context', '{"x":"' + 'x'.repeat(2048) + '"}'));
denied(policy(), rpc('current_access_context', '{"x":1,"x":2}'));
assert.deepEqual(policy()(null), { allowed: false });
assert.throws(() => policy('operations', 'unknown'), /INPUT_INVALID/);
assert.throws(() => policy('operations', 'viewer', { bootInstant: 'invalid private sentinel' }), /^Error: CNYOS_UAT_BROWSER_READ_POLICY_INPUT_INVALID$/);
console.log('CNYOS UAT browser read policy contract: passed');
