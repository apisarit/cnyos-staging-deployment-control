// Controller-owned UI boot observation orchestration; NOT an authorization or
// authenticated UAT receipt. The protected CLI deliberately does not call this.
// A future protected lifecycle must supply independently authenticated, isolated
// session leases, an exclusively-owned bounded transport and protected retention.
// No candidate scripts, account provisioning, clicks, writes or token refresh.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { POLICY } from './policy.mjs';
import { UAT_ACCESS_ROLES } from './controller-uat-access-observations.mjs';
import { createUatBrowserReadPolicy, UAT_BROWSER_WORKSPACE_PATHS } from './controller-uat-browser-read-policy.mjs';

const grant = (...values) => Object.freeze(['operations', ...values]);
export const UAT_EXPECTED_WORKSPACES = Object.freeze({
  practitioner: grant('appointments', 'checkin', 'foundation', 'clinical', 'outcomes'),
  doctor: grant('appointments', 'checkin', 'foundation', 'clinical', 'outcomes'),
  reception: grant('appointments', 'checkin'), pharmacy: grant('foundation', 'pharmacy'),
  production: grant('foundation', 'production'), inventory: grant('foundation', 'production'),
  quality: grant('quality'), billing: grant(), admin: grant('admin'),
  super_admin: Object.freeze(Object.keys(UAT_BROWSER_WORKSPACE_PATHS)), viewer: grant()
});
export const UAT_NORMAL_BOOT_TEXT = Object.freeze({
  operations: 'กำลังตรวจสอบ session และสิทธิ์', appointments: 'กำลังตรวจสอบสิทธิ์',
  checkin: 'กำลังตรวจสอบ session, clinic และสิทธิ์', foundation: 'กำลังตรวจสอบกฎ ความสัมพันธ์ และหลักฐาน',
  clinical: 'กำลังตรวจสอบสิทธิ์และเวชระเบียน', outcomes: 'กำลังตรวจสอบ tenant, session และสิทธิ์ผู้รักษา',
  pharmacy: 'กำลังตรวจสอบสิทธิ์', production: 'กำลังตรวจสอบ session และสิทธิ์',
  quality: 'กำลังตรวจสอบ tenant, role และ Quality migration', admin: 'กำลังตรวจสอบ session และสิทธิ์'
});
export const UAT_DENIAL_BOOT_TEXT = Object.freeze({
  appointments: 'บัญชีนี้ไม่มีสิทธิ์ดูระบบนัดหมาย', checkin: 'บัญชีนี้ไม่มีสิทธิ์ยืนยันผู้รับบริการ',
  foundation: 'บัญชีนี้ไม่มีสิทธิ์อ่านรากวิชา', clinical: 'บัญชีนี้ไม่มีสิทธิ์บันทึกเวชระเบียน',
  outcomes: 'บัญชีนี้ไม่มีสิทธิ์อ่านผลลัพธ์ทางคลินิก — ข้อมูลผู้รับบริการเปิดเฉพาะผู้รักษาและ Super Admin',
  pharmacy: 'บัญชีนี้ไม่มีสิทธิ์ Pharmacy — แต่ละบัญชีเข้าได้เฉพาะแผนกของตน',
  production: 'บัญชีนี้ไม่มีสิทธิ์ Production Workstation — แต่ละบัญชีเข้าได้เฉพาะแผนกของตน',
  quality: 'บัญชีนี้ไม่มีสิทธิ์ Quality Workstation — แต่ละบัญชีเข้าได้เฉพาะแผนกของตน',
  admin: 'บัญชีนี้ไม่มีสิทธิ์ Admin Task Center'
});
const navigation = Object.freeze(['operations', 'appointments', 'checkin', 'foundation', 'luopan',
  'clinical', 'outcomes', 'pharmacy', 'production', 'quality', 'admin']);
const featureByRoute = Object.freeze({ appointments: 'appointments', foundation: 'knowledge', luopan: 'u-synthesise',
  clinical: 'clinical', outcomes: 'outcomes', pharmacy: 'pharmacy', production: 'production', quality: 'quality' });
// Closed, source-checked mirror of platform-config.js, not an import of
// executable candidate code into the protected controller.
const featureDependencies = Object.freeze({ core: [], appointments: ['core'], knowledge: ['core'], 'u-synthesise': ['core'],
  clinical: ['knowledge'], outcomes: ['clinical'], pharmacy: ['clinical'], production: ['pharmacy'], quality: ['production'] });
const featureNames = Object.freeze(Object.keys(featureDependencies));
const MAX_RUN_MS = 20 * 60 * 1000;
const SESSION_MARGIN_SECONDS = 300;
const MAX_POLLS = 100;
const knownErrors = new WeakSet();
const fail = code => { const error = new Error(`CNYOS_UAT_BROWSER_MATRIX_${code}`); knownErrors.add(error); throw error; };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value);
const delay = () => new Promise(resolve => setTimeout(resolve, 25));
const json = value => JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

function featuresOf(value) {
  // null explicitly means the reviewed tenant config OMITTED features. Never
  // infer the expected configuration from the page we are trying to check.
  if (value === null) return null;
  if (!Array.isArray(value) || value.length > featureNames.length ||
    value.some(item => !featureNames.includes(item)) || new Set(value).size !== value.length || !value.includes('core') ||
    value.some(item => featureDependencies[item].some(dependency => !value.includes(dependency))) ||
    JSON.stringify(value) !== JSON.stringify(featureNames.filter(item => value.includes(item)))) fail('FEATURES');
  return Object.freeze([...value]);
}
export function expectedUatNavigation(role, expectedFeatures) {
  if (!UAT_ACCESS_ROLES.includes(role)) fail('ROLE');
  const features = featuresOf(expectedFeatures);
  return Object.freeze(navigation.filter(key => (key === 'luopan' || UAT_EXPECTED_WORKSPACES[role].includes(key)) &&
    (features === null || !featureByRoute[key] || features.includes(featureByRoute[key])))
    .map(key => key === 'luopan' ? '/luopan.html' : UAT_BROWSER_WORKSPACE_PATHS[key]));
}
function sessionProjection(value, minimumExpiry) {
  // Structural consistency is NOT signature/identity verification. Deliberately
  // drop email and both metadata objects; roles come from server access context.
  if (!record(value) || !record(value.user) || !uuid(value.user.id) || value.token_type !== 'bearer' ||
    !Number.isSafeInteger(value.expires_at) || value.expires_at < minimumExpiry ||
    !Number.isSafeInteger(value.expires_in) || value.expires_in < 1 || value.expires_in > 86400 ||
    typeof value.access_token !== 'string' || value.access_token.length > 8192 ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value.access_token) ||
    typeof value.refresh_token !== 'string' || !/^[A-Za-z0-9_-]{8,2048}$/.test(value.refresh_token)) fail('SESSION');
  let claims;
  try { claims = JSON.parse(Buffer.from(value.access_token.split('.')[1], 'base64url').toString('utf8')); }
  catch { fail('SESSION'); }
  if (!record(claims) || claims.iss !== `${POLICY.target.supabaseOrigin}/auth/v1` ||
    claims.sub !== value.user.id || claims.role !== 'authenticated' || claims.aud !== 'authenticated' ||
    claims.exp !== value.expires_at) fail('SESSION');
  return Object.freeze({ access_token: value.access_token, refresh_token: value.refresh_token,
    expires_at: value.expires_at, expires_in: value.expires_in, token_type: 'bearer', user: Object.freeze({ id: value.user.id }) });
}
function sessionInitScript(session) {
  // Exact-origin + top-frame only; no setSession/getSession call, repair or
  // refresh. The storage value is not returned in observations or diagnostics.
  return `(() => { if (window !== window.top || location.origin !== ${json(POLICY.target.netlifyOrigin)}) return;
    localStorage.setItem(${json(`sb-${POLICY.target.supabaseProjectRef}-auth-token`)}, ${json(JSON.stringify(session))}); })()`;
}

// Runs in the owned page and emits one enum, never DOM/user/error text. This is
// UI observation only: an application can render a role without proving RLS.
function inspectWorkspace(expected) {
  const one = selector => {
    const nodes = document.querySelectorAll(selector);
    return nodes.length === 1 ? nodes[0] : null;
  };
  const shown = element => {
    if (!element || element.hidden || element.classList.contains('hidden')) return false;
    const css = getComputedStyle(element);
    return css.display !== 'none' && css.visibility === 'visible' && element.getClientRects().length > 0;
  };
  if (location.href !== expected.url || document.body?.dataset.page !== expected.workspace ||
    document.readyState !== 'complete') return 'DOCUMENT_MISMATCH';
  const config = window.CLINICAL_OS_CONFIG;
  if (!config || config.deploymentId !== expected.deploymentId || config.database?.url !== expected.supabaseOrigin ||
    config.tenant?.expectedClinicId !== expected.clinicId || config.tenant?.expectedClinicCode !== expected.clinicCode ||
    config.auth?.redirectOrigin !== expected.siteOrigin || config.safety?.previewLocked !== false ||
    (expected.features === null ? Object.hasOwn(config, 'features') : JSON.stringify(config.features) !== JSON.stringify(expected.features))) {
    return 'CONFIG_MISMATCH';
  }
  const app = one('#app'), boot = one('#boot'), bootError = one('#boot-error'), role = one('#role'), nav = one('#global-nav');
  if (!app || !boot || !bootError || !role || !nav) return 'DOM_SHAPE';
  const bootText = bootError.textContent;
  if (expected.allowed && bootText !== expected.normalBoot) return 'BOOT_ERROR';
  if (!expected.allowed && bootText !== expected.normalBoot && bootText !== expected.denialBoot) return 'BOOT_ERROR';
  const links = nav.querySelectorAll('a');
  if (links.length > 11) return 'NAVIGATION_MISMATCH';
  if (expected.allowed) {
    if (!shown(app) && shown(boot)) return 'PENDING';
    if (!shown(app) || shown(boot) || !boot.classList.contains('hidden')) return 'VISIBILITY_MISMATCH';
    if (role.textContent !== expected.role || role.dataset.effectiveRole !== expected.role ||
      role.dataset.systemRole !== expected.systemRole || role.dataset.operationalRole !== expected.operationalRole) return 'ROLE_MISMATCH';
    if (JSON.stringify(Array.from(links, link => link.getAttribute('href'))) !== JSON.stringify(expected.nav)) return 'NAVIGATION_MISMATCH';
    return 'READY_ALLOWED';
  }
  if (shown(app) || !app.classList.contains('hidden') || !shown(boot) || links.length !== 0 ||
    role.dataset.effectiveRole !== undefined || role.dataset.systemRole !== undefined || role.dataset.operationalRole !== undefined) return 'VISIBILITY_MISMATCH';
  return bootText === expected.denialBoot ? 'READY_DENIED' : 'PENDING';
}
const probeCodes = new Set(['READY_ALLOWED', 'READY_DENIED', 'PENDING', 'DOCUMENT_MISMATCH', 'CONFIG_MISMATCH',
  'DOM_SHAPE', 'BOOT_ERROR', 'ROLE_MISMATCH', 'NAVIGATION_MISMATCH', 'VISIBILITY_MISMATCH']);
function probeScript(role, workspace, features) {
  const allowed = UAT_EXPECTED_WORKSPACES[role].includes(workspace);
  const expected = { role, workspace, allowed, features, url: `${POLICY.target.netlifyOrigin}${UAT_BROWSER_WORKSPACE_PATHS[workspace]}`,
    deploymentId: POLICY.target.deploymentId, siteOrigin: POLICY.target.netlifyOrigin, supabaseOrigin: POLICY.target.supabaseOrigin,
    clinicId: POLICY.target.clinicId, clinicCode: POLICY.target.clinicCode, nav: expectedUatNavigation(role, features),
    normalBoot: UAT_NORMAL_BOOT_TEXT[workspace], denialBoot: UAT_DENIAL_BOOT_TEXT[workspace] || null,
    systemRole: role === 'super_admin' ? 'super_admin' : role === 'admin' ? 'admin' : 'staff',
    operationalRole: ['admin', 'super_admin'].includes(role) ? 'viewer' : role };
  return `(${inspectWorkspace.toString()})(${json(expected)})`;
}
const methods = Object.freeze(['addInitScript', 'navigateAndWait', 'evaluate', 'waitForIdle',
  'assertHealthy', 'getPageDiagnostics', 'captureScreenshot', 'close', 'getClosureStatus']);
function diagnosticsMatch(value, allowed) {
  return record(value) && Object.keys(value).sort().join(',') === 'consoleErrorCount,exceptionCount' &&
    value.exceptionCount === 0 && value.consoleErrorCount === (allowed ? 0 : 1);
}
function summary(observations) {
  return Object.freeze({ kind: 'controller_ui_boot_observations', observations: Object.freeze(observations),
    plannedCount: 110, observedCount: observations.length,
    allExpectedUiStatesObserved: observations.length === 110 && observations.every(item => item.code === 'MATCH'),
    navigationOnlyScope: Object.freeze(['luopan']), authorization: false, authenticatedIdentityVerified: false,
    crossTenantDenialsVerified: false, uatComplete: false, deploymentAllowed: false });
}

export async function runControllerBrowserMatrix(options) {
  // No CLI, env credential reads, caller-selected URLs/routes/scripts or implicit
  // factory. Test doubles can verify orchestration but cannot authorize anything.
  let sessions, features, createOwnedTransport, retainFailureScreenshot;
  const started = performance.now();
  try {
    if (!record(options) || Object.keys(options).sort().join(',') !==
      'createOwnedTransport,expectedFeatures,retainFailureScreenshot,sessionLeasesByRole') fail('INPUT');
    ({ createOwnedTransport, retainFailureScreenshot } = options);
    if (typeof createOwnedTransport !== 'function' || typeof retainFailureScreenshot !== 'function') fail('DEPENDENCIES');
    features = featuresOf(options.expectedFeatures);
    if (!record(options.sessionLeasesByRole) || Object.keys(options.sessionLeasesByRole).sort().join(',') !== [...UAT_ACCESS_ROLES].sort().join(',')) fail('SESSION_SET');
    const minimumExpiry = Math.ceil(Date.now() / 1000) + MAX_RUN_MS / 1000 + SESSION_MARGIN_SECONDS;
    sessions = Object.fromEntries(UAT_ACCESS_ROLES.map(role => [role, sessionProjection(options.sessionLeasesByRole[role], minimumExpiry)]));
    if (new Set(Object.values(sessions).map(session => session.user.id)).size !== UAT_ACCESS_ROLES.length) fail('SESSION_REUSE');
  } catch (error) { if (knownErrors.has(error)) throw error; fail('INPUT'); }
  const observations = [];
  const ownedTransports = new WeakSet();
  for (const role of UAT_ACCESS_ROLES) for (const workspace of Object.keys(UAT_BROWSER_WORKSPACE_PATHS)) {
    if (performance.now() - started > MAX_RUN_MS || sessions[role].expires_at < Math.ceil(Date.now() / 1000) + SESSION_MARGIN_SECONDS) fail('DEADLINE');
    const allowed = UAT_EXPECTED_WORKSPACES[role].includes(workspace);
    let transport, pendingScreenshot, code = 'TRANSPORT_FAILURE', failureScreenshot = null, screenshotState = 'not_required';
    try {
      // The factory must itself be controller-owned, deadline-bounded and kill
      // its runtime on setup failure. Every cell requires a fresh owned process.
      transport = await createOwnedTransport(Object.freeze({ role, workspace,
        classifyRequest: createUatBrowserReadPolicy({ siteOrigin: POLICY.target.netlifyOrigin,
          supabaseOrigin: POLICY.target.supabaseOrigin, sessionUserId: sessions[role].user.id,
          role, workspace, bootInstant: new Date().toISOString() }) }));
      if (!record(transport) || methods.some(method => typeof transport[method] !== 'function') || ownedTransports.has(transport)) fail('TRANSPORT_SHAPE');
      ownedTransports.add(transport);
      await transport.addInitScript(sessionInitScript(sessions[role]));
      const url = `${POLICY.target.netlifyOrigin}${UAT_BROWSER_WORKSPACE_PATHS[workspace]}`;
      const navigationResult = await transport.navigateAndWait(url);
      if (!record(navigationResult) || navigationResult.loaded !== true || navigationResult.url !== url) fail('NAVIGATION');
      const script = probeScript(role, workspace, features);
      let stable = 0;
      code = 'BOOT_TIMEOUT';
      for (let poll = 0; poll < MAX_POLLS; poll++) {
        await transport.waitForIdle();
        transport.assertHealthy();
        const observed = await transport.evaluate(script);
        if (!probeCodes.has(observed)) { code = 'PROBE_RESPONSE'; break; }
        if (observed === 'PENDING') stable = 0;
        else if (observed !== (allowed ? 'READY_ALLOWED' : 'READY_DENIED')) { code = observed; break; }
        else {
          if (!diagnosticsMatch(transport.getPageDiagnostics(), allowed)) { code = 'PAGE_DIAGNOSTICS'; break; }
          if (++stable === 2) { code = 'MATCH'; break; }
        }
        await delay();
      }
      // A second idle/DOM/diagnostics check follows readiness; app visibility by
      // itself never proves its awaited data load or a clinical workflow passed.
      if (code === 'MATCH') {
        await transport.waitForIdle();
        transport.assertHealthy();
        if (await transport.evaluate(script) !== (allowed ? 'READY_ALLOWED' : 'READY_DENIED')) code = 'FINAL_STATE_CHANGED';
        else if (!diagnosticsMatch(transport.getPageDiagnostics(), allowed)) code = 'PAGE_DIAGNOSTICS';
      }
    } catch { code = 'TRANSPORT_FAILURE'; }
    finally {
      if (code !== 'MATCH') {
        screenshotState = 'unavailable';
        try {
          transport.assertHealthy();
          const png = await transport.captureScreenshot();
          if (!record(png) || png.format !== 'png' || png.width !== 390 || png.height !== 844 ||
            typeof png.dataBase64 !== 'string' || png.dataBase64.length > 2796204) fail('SCREENSHOT');
          const bytes = Buffer.from(png.dataBase64, 'base64');
          if (bytes.length !== png.byteLength || bytes.length < 1 || bytes.length > 2 * 1024 * 1024 || bytes.toString('base64') !== png.dataBase64) fail('SCREENSHOT');
          const sha256 = createHash('sha256').update(bytes).digest('hex');
          const reference = `${role}/${workspace}/${sha256}.png`;
          pendingScreenshot = Object.freeze({ role, workspace, code, reference, sha256, png });
        } catch { /* Fail stays a fail, including a terminated transport or failed retention. */ }
      }
      // Never continue to another role after uncertain cleanup; do not leak a
      // dependency's raw exception/message in the public result or throw path.
      if (transport) {
        try {
          // close rethrows a prior policy refusal even after safe cleanup. Only
          // the transport's closure state can disambiguate; never parse errors.
          let closeRejected = false;
          try { await transport.close(); } catch { closeRejected = true; }
          const closure = transport.getClosureStatus();
          if (!record(closure) || Object.keys(closure).join(',') !== 'cleanupConfirmed' || closure.cleanupConfirmed !== true) fail('CLEANUP');
          if (closeRejected && code === 'MATCH') {
            // A late refusal may be latched after the final DOM check. Confirmed
            // shutdown does not erase that refusal or turn the case into a pass.
            code = 'TRANSPORT_FAILURE'; screenshotState = 'unavailable';
          }
        }
        catch { fail('CLEANUP'); }
      } else fail('SETUP');
    }
    // Retention never holds an authenticated browser open. A bounded sink can
    // still finish late; its late response cannot change this failed run.
    if (pendingScreenshot) {
      let retentionTimer;
      try {
        const retained = await Promise.race([
          Promise.resolve().then(() => retainFailureScreenshot(pendingScreenshot)),
          new Promise((_, reject) => { retentionTimer = setTimeout(() => reject(new Error('RETENTION_TIMEOUT')), 5000); })
        ]);
        if (!record(retained) || Object.keys(retained).sort().join(',') !== 'sha256,stored' ||
          retained.stored !== true || retained.sha256 !== pendingScreenshot.sha256) fail('SCREENSHOT_RETENTION');
        failureScreenshot = pendingScreenshot.reference;
        screenshotState = 'retained';
      } catch { /* Incomplete retention never becomes success. */ }
      finally { clearTimeout(retentionTimer); pendingScreenshot = undefined; }
    }
    observations.push(Object.freeze({ role, workspace, expected: allowed ? 'allow' : 'deny', code, screenshotState, failureScreenshot }));
    if (code !== 'MATCH') return summary(observations);
  }
  return summary(observations);
}
