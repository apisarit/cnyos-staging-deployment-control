// Controller-selected REQUEST constraints, not target/identity authorization.
// Derived from the ten workspace HTML boot paths and their local scripts.
// Requires pre-provisioned profiles, fresh sessions and Asia/Bangkok timezone.
// Auth refresh and account-access/status are denied: status can UPSERT profiles.
// No interactive action, branding URL, print popup or arbitrary REST/RPC is allowed.
import { UAT_ACCESS_ROLES } from './controller-uat-access-observations.mjs';

export const UAT_BROWSER_WORKSPACE_PATHS = Object.freeze({ operations: '/', appointments: '/appointments.html',
  checkin: '/check-in.html', foundation: '/foundation.html', clinical: '/clinical-v3.html', outcomes: '/outcomes.html',
  pharmacy: '/pharmacy.html', production: '/production.html', quality: '/quality.html', admin: '/admin.html' });
const DENY = Object.freeze({ allowed: false });
const allow = (responseKind, maxResponseBytes) => Object.freeze({ allowed: true, responseKind, maxResponseBytes });
const JSON_RESPONSE = allow('json', 4 * 1024 * 1024);
const SCRIPT = allow('script', 4 * 1024 * 1024);
const STYLE = allow('style', 1024 * 1024);
const DOCUMENT = allow('document', 1024 * 1024);
const EMPTY = allow('empty', 1);
const SDK = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.112.4';
const XLSX = 'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js';
const roleWorkspaces = {
  practitioner: ['appointments', 'checkin', 'foundation', 'clinical', 'outcomes'],
  doctor: ['appointments', 'checkin', 'foundation', 'clinical', 'outcomes'], reception: ['appointments', 'checkin'],
  pharmacy: ['foundation', 'pharmacy'], production: ['foundation', 'production'], inventory: ['foundation', 'production'],
  quality: ['quality'], billing: [], admin: ['admin'], viewer: [], super_admin: Object.keys(UAT_BROWSER_WORKSPACE_PATHS)
};
// Exact asset versions from the checked-in HTML. Conditional scripts are listed
// only where boot loads them; QR/Barcode print libraries are intentionally absent.
const assetSpec = {
  operations: ['account-access1', 'white-label2', 'clinical-os-ia1', 'account-access1', 'clinical-os-ia1',
    ['searchable-select.js?clinical-os-department1', 'app.js?account-access1']],
  appointments: ['clinical-os-department1', 'white-label1', 'clinical-os-ia1', 'clinical-os-department1', 'clinical-os-ia1',
    ['searchable-select.js?clinical-os-department1', 'appointments.js?clinical-os-department1']],
  checkin: ['clinical-os-department1', 'white-label1', 'hybrid-identity1', 'clinical-os-department1', 'hybrid-identity1',
    ['searchable-select.js?clinical-os-department1', 'check-in.js?hybrid-identity1']],
  foundation: ['ttm-foundation-v2', 'white-label1', 'clinical-os-foundation1', 'clinical-os-department1', 'clinical-os-foundation1',
    ['searchable-select.js?clinical-os-department1', 'ttm-reasoning.js?ttm-foundation-v2', 'foundation.js?ttm-foundation-v2']],
  clinical: ['clinical-os-department1', 'white-label1', 'clinical-os-ia1', 'clinical-os-department1', 'clinical-os-ia1',
    ['searchable-select.js?clinical-os-department1', 'clinical-v3.js?clinical-os-department1', 'clinical-context-guard.js?clinical-os-ia1',
      'body-pain-map.js?clinical-os-department1', 'ttm-diagnosis-assistant.js?clinical-os-ia1', 'diagnosis-atomic-bridge.js?clinical-os-ia1',
      'opd-workflow.js?clinical-os-ia1', 'clinical-signoff.js?clinical-os-ia1']],
  outcomes: ['clinical-os-outcomes1', 'white-label1', 'clinical-os-outcomes1', 'clinical-os-department1', 'clinical-os-outcomes1', ['outcomes.js?clinical-os-outcomes1']],
  pharmacy: ['clinical-os-prescription-dispense1', 'white-label1', 'clinical-os-ia1', 'clinical-os-department1', 'clinical-os-ia1',
    ['searchable-select.js?clinical-os-production-atomic1', 'pharmacy.js?clinical-os-prescription-dispense1', 'pharmacy-sale-selector-fix.js?clinical-os-ia1',
      'pharmacy-labels.js?clinical-os-ia1', 'pharmacy-v33-tools.js?clinical-os-ia1']],
  production: ['clinical-os-production-atomic1', 'white-label1', 'clinical-os-ia1', 'clinical-os-department1', 'clinical-os-ia1',
    ['searchable-select.js?clinical-os-production-atomic1', 'production.js?clinical-os-production-atomic1']],
  quality: ['clinical-os-quality1', 'white-label1', 'clinical-os-quality1', 'clinical-os-quality1', 'clinical-os-quality1',
    ['searchable-select.js?clinical-os-quality1', 'quality.js?clinical-os-quality1']],
  admin: ['account-access1', 'white-label1', 'clinical-os-ia1', 'account-access1', 'clinical-os-ia1',
    ['searchable-select.js?clinical-os-department1', 'admin.js?account-access1', 'admin-clinical-audit.js?clinical-os-ia1']]
};
const fail = () => { throw new Error('CNYOS_UAT_BROWSER_READ_POLICY_INPUT_INVALID'); };
function origin(value) {
  const parsed = new URL(value);
  if (parsed.origin !== value || parsed.username || parsed.password ||
    !(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && parsed.hostname === '127.0.0.1'))) fail();
  return value;
}
const queryKey = pairs => JSON.stringify([...pairs].sort(([ak, av], [bk, bv]) => ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0));

export function createUatBrowserReadPolicy(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail();
  const { siteOrigin, supabaseOrigin, sessionUserId, workspace, role, bootInstant } = options;
  try { origin(siteOrigin); origin(supabaseOrigin); } catch { fail(); }
  if (siteOrigin === supabaseOrigin || !Object.hasOwn(UAT_BROWSER_WORKSPACE_PATHS, workspace) || !UAT_ACCESS_ROLES.includes(role) ||
    !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(sessionUserId) ||
    typeof bootInstant !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(bootInstant) ||
    !Number.isFinite(Date.parse(bootInstant)) || new Date(bootInstant).toISOString() !== bootInstant) fail();
  const [css, brand, auth, runtime, shell, extras] = assetSpec[workspace];
  const scripts = new Set(['tenant-config.js?white-label1', `tenant-brand.js?${brand}`, `auth-config.js?${auth}`,
    `chananya-runtime.js?${runtime}`, `app-shell.js?${shell}`, ...extras].map(item => `${siteOrigin}/${item.replace('?', '?v=')}`));
  const tableQueries = new Map();
  const rpcBodies = new Map([['current_access_context', '{}']]);
  const addTable = (table, select = '*', orderBy = null, extra = []) => {
    const queries = tableQueries.get(table) || new Set();
    queries.add(queryKey([['select', select], ...(orderBy ? [['order', orderBy]] : []), ...extra]));
    tableQueries.set(table, queries);
  };
  addTable('profiles', 'id,role,system_role,full_name,email', null, [['id', `eq.${sessionUserId}`]]);
  const health = (...names) => names.forEach(name => rpcBodies.set(name, '{}'));
  const mainAllowed = workspace === 'operations' || roleWorkspaces[role].includes(workspace);
  // Thailand has no DST. Match source defaults, not arbitrary date filters:
  // appointments uses the UTC date string, then parses it as Bangkok local time;
  // outcomes derives Bangkok's local calendar date before its 90-day window.
  const dayMs = 86400000;
  const utcDay = Date.parse(`${bootInstant.slice(0, 10)}T00:00:00.000Z`);
  const bangkokDay = Date.parse(`${new Date(Date.parse(bootInstant) + 7 * 3600000).toISOString().slice(0, 10)}T00:00:00.000Z`);
  const localIso = (day, offset = 0) => new Date(day + offset * dayMs - 7 * 3600000).toISOString();
  if (mainAllowed) {
    if (workspace === 'operations') {
      health('hybrid_patient_identity_healthcheck', 'clinical_financial_handoffs_healthcheck');
      const inRoles = roles => role === 'super_admin' || roles.includes(role);
      if (inRoles(['practitioner', 'doctor', 'reception', 'pharmacy', 'billing'])) addTable('patients', '*', 'created_at.desc');
      if (inRoles(['practitioner', 'doctor', 'reception', 'pharmacy'])) addTable('patient_allergies');
      if (inRoles(['practitioner', 'doctor', 'reception'])) addTable('appointments');
      if (inRoles(['practitioner', 'doctor', 'pharmacy', 'billing'])) {
        addTable('encounters', '*', 'started_at.desc'); addTable('prescriptions', '*', 'prescribed_at.desc');
        addTable('prescription_items'); addTable('products');
      }
      if (inRoles(['pharmacy', 'billing'])) { addTable('dispensing_orders', '*', 'created_at.desc'); addTable('dispensing_items'); }
      if (inRoles(['billing'])) { addTable('invoices', '*', 'created_at.desc'); addTable('payments'); }
      if (inRoles(['admin'])) addTable('audit_logs', '*', 'created_at.desc');
    } else if (workspace === 'appointments') {
      addTable('patients', '*', 'created_at.desc', [['limit', '500']]);
      addTable('available_practitioner_schedules', '*', 'starts_at.asc', [['available_capacity', 'gt.0'],
        ['starts_at', `gte.${localIso(utcDay)}`], ['starts_at', `lte.${new Date(utcDay + 15 * dayMs - 7 * 3600000 - 1000).toISOString()}`]]);
      addTable('clinic_appointments', '*', 'scheduled_start.asc', [['scheduled_start', `gte.${localIso(utcDay)}`],
        ['scheduled_start', `lte.${new Date(utcDay + dayMs - 7 * 3600000 - 1000).toISOString()}`]]);
    } else if (workspace === 'checkin') health('hybrid_patient_identity_healthcheck');
    else if (workspace === 'clinical') {
      health('hybrid_patient_identity_healthcheck', 'clinical_financial_handoffs_healthcheck');
      addTable('patients', '*', 'created_at.desc', [['limit', '500']]);
      addTable('products', '*', 'name_th.asc', [['active', 'eq.true']]);
      addTable('encounters', 'id,encounter_no,patient_id,chief_complaint,thai_diagnosis,started_at,status', 'started_at.desc', [['limit', '250']]);
    } else if (workspace === 'outcomes') {
      const range = { p_from: localIso(bangkokDay, -89), p_to: localIso(bangkokDay, 1) };
      rpcBodies.set('clinical_outcomes_summary', JSON.stringify(range));
      rpcBodies.set('search_clinical_outcomes', JSON.stringify({ ...range, p_query: null, p_limit: 100, p_offset: 0 }));
    } else if (workspace === 'foundation') {
      // Actual source paginates by1000. This policy caps boot at10 pages/table;
      // exceeding that is an explicit incomplete run, never an unbounded fallback.
      for (let offset = 0; offset < 10000; offset += 1000) {
        const pagination = [['offset', String(offset)], ['limit', '1000']];
        addTable('ttm_concepts', 'id,concept_code,concept_type,preferred_term_th,preferred_term_en,foundation_layer,definition,source_id,review_status,version,active,metadata', 'foundation_layer.asc,preferred_term_th.asc', [['active', 'eq.true'], ...pagination]);
        addTable('ttm_sources', 'id,source_code,title_th,title_en,source_type,citation,provenance,review_status,version,active,metadata', 'title_th.asc', [['active', 'eq.true'], ...pagination]);
        addTable('ttm_concept_relations', 'id,subject_concept_id,predicate,object_concept_id,source_id,evidence_note,qualifiers,review_status,version,active', null, [['active', 'eq.true'], ...pagination]);
        addTable('ttm_diagnostic_knowledge', '*', 'domain.asc,rule_key.asc', [['active', 'eq.true'], ...pagination]);
        addTable('sen_line_master', 'code,name_th,name_en,description,clinical_notes,is_active', 'code.asc', [['is_active', 'eq.true'], ...pagination]);
      }
    } else if (workspace === 'pharmacy') {
      health('department_persistence_healthcheck', 'prescription_dispensing_healthcheck');
      for (const [table, orderBy] of [['products', 'updated_at'], ['pharmacy_counter_sales', 'created_at'], ['pharmacy_counter_sale_items'], ['patients'],
        ['prescriptions', 'prescribed_at'], ['dispensing_orders', 'created_at'], ['prescription_items'], ['dispensing_items'], ['production_requests', 'requested_at']]) addTable(table, '*', orderBy ? `${orderBy}.desc` : null);
    } else if (workspace === 'production') {
      health('production_execution_healthcheck');
      for (const [table, orderBy] of [['products', 'updated_at'], ['inventory_lots', 'created_at'], ['formulas', 'updated_at'], ['formula_components'],
        ['production_requests', 'requested_at'], ['production_orders', 'created_at'], ['production_material_issues', 'issued_at'], ['production_qc', 'created_at'], ['finished_goods_receipts', 'received_at']]) addTable(table, '*', orderBy ? `${orderBy}.desc` : null);
    } else if (workspace === 'quality') {
      health('quality_release_healthcheck');
      for (const table of ['products', 'formulas', 'production_orders', 'production_qc']) addTable(table, '*', 'created_at.desc');
    } else if (workspace === 'admin') {
      addTable('approval_tasks', '*', 'requested_at.desc'); addTable('approval_actions', '*', 'acted_at.desc'); addTable('admin_task_summary');
    }
  }
  // These extensions run before/without the primary workspace role check.
  if (workspace === 'clinical') addTable('ttm_diagnostic_knowledge', '*', 'domain.asc,rule_key.asc', [['active', 'eq.true']]);
  if (workspace === 'pharmacy') {
    addTable('dispensing_orders', 'id,status', null, [['status', 'in.(dispensed,submitted_to_billing,billed)']]);
    addTable('pharmacy_counter_sales', 'id,status', null, [['status', 'in.(dispensed,submitted_to_billing)']]);
  }

  return Object.freeze(function classifyRequest(request) {
    try {
      const { url, method, resourceType, postData = '', accessControlRequestMethod, accessControlRequestHeaders } = request;
      if (typeof url !== 'string' || Buffer.byteLength(url) > 8192 || typeof postData !== 'string' || Buffer.byteLength(postData) > 2048 ||
        !['GET', 'POST', 'OPTIONS'].includes(method)) return DENY;
      const parsed = new URL(url);
      if (parsed.href !== url || parsed.username || parsed.password || parsed.hash || /%|\\/.test(parsed.pathname) ||
        parsed.search.slice(1) !== parsed.searchParams.toString()) return DENY;
      if (method === 'OPTIONS') {
        // Fetch.requestPaused reports real preflights as XHR on the project's
        // Chromium140 headless shell. The exact method/header/URL constraints,
        // not that resource label alone, establish the permitted preflight.
        if (!['Preflight', 'XHR', 'Fetch'].includes(resourceType) || postData !== '' || parsed.origin !== supabaseOrigin ||
          !['GET', 'POST'].includes(accessControlRequestMethod) || !Array.isArray(accessControlRequestHeaders) ||
          accessControlRequestHeaders.length > 4 || accessControlRequestHeaders.some(value => typeof value !== 'string' || !/^[a-z][a-z-]{0,31}$/.test(value))) return DENY;
        const headers = [...accessControlRequestHeaders].sort();
        const expected = accessControlRequestMethod === 'GET' ? ['apikey', 'authorization', 'x-client-info'] : ['apikey', 'authorization', 'content-type', 'x-client-info'];
        if (JSON.stringify(headers) !== JSON.stringify(expected)) return DENY;
        if (accessControlRequestMethod === 'GET') return parsed.pathname.startsWith('/rest/v1/') &&
          tableQueries.get(parsed.pathname.slice('/rest/v1/'.length))?.has(queryKey(parsed.searchParams)) ? EMPTY : DENY;
        // This permits only the preflight, not the later POST body. Every actual
        // POST is independently checked against the exact boot body below.
        return !parsed.search && parsed.pathname.startsWith('/rest/v1/rpc/') && rpcBodies.has(parsed.pathname.slice('/rest/v1/rpc/'.length)) ? EMPTY : DENY;
      }
      if (method === 'GET' && postData === '') {
        if (resourceType === 'Script' && (scripts.has(url) || url === SDK || (workspace === 'production' && url === XLSX))) return SCRIPT;
        if (resourceType === 'Stylesheet' && url === `${siteOrigin}/app.css?v=${css}`) return STYLE;
        if (resourceType === 'Document' && url === `${siteOrigin}${UAT_BROWSER_WORKSPACE_PATHS[workspace]}`) return DOCUMENT;
        if (!['Fetch', 'XHR'].includes(resourceType)) return DENY;
        if (workspace === 'operations' && url === `${siteOrigin}/api/patient-identity`) return JSON_RESPONSE;
        if (parsed.origin !== supabaseOrigin || !parsed.pathname.startsWith('/rest/v1/')) return DENY;
        const table = parsed.pathname.slice('/rest/v1/'.length);
        return tableQueries.get(table)?.has(queryKey(parsed.searchParams)) ? JSON_RESPONSE : DENY;
      }
      if (method !== 'POST' || !['Fetch', 'XHR'].includes(resourceType) || parsed.search || !postData) return DENY;
      // Exact JSON serializations are emitted by the source; reject duplicate
      // keys, additional values and alternate bodies rather than reparsing them.
      if (mainAllowed && workspace === 'admin' && url === `${siteOrigin}/api/account-access` && postData === '{"action":"staff_list"}') return JSON_RESPONSE;
      if (parsed.origin !== supabaseOrigin || !parsed.pathname.startsWith('/rest/v1/rpc/')) return DENY;
      return rpcBodies.get(parsed.pathname.slice('/rest/v1/rpc/'.length)) === postData ? JSON_RESPONSE : DENY;
    } catch { return DENY; }
  });
}
