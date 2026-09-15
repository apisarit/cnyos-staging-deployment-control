import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { POLICY, exactDeployId, parseJsonObject } from './policy.mjs';
import { loadEvidence } from './netlify-evidence.mjs';
import { executeRecoveryPlan, EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES } from './reconcile-netlify-release-state.mjs';

const fail = suffix => { throw new Error(`CNYOS_DRAFT_CLEANUP_${suffix}`); };
// This is a narrower entry point to the existing authenticated recovery executor,
// never an alternative source of deletion authority or a publisher-token cleanup.
export function assertDraftOnlyRecoveryPlan(value) {
  const result = value?.statement?.result;
  const core = result?.planCore;
  if (result?.recoveryDisposition !== 'recovery_required' || !core ||
    core.target?.netlifySiteId !== POLICY.target.netlifySiteId ||
    core.currentDeployId !== core.previousDeployId ||
    !Array.isArray(core.orderedActions) || !Array.isArray(core.draftIntents)) fail('PLAN_INVALID');
  const baseline = exactDeployId(core.previousDeployId, 'CNYOS_DRAFT_CLEANUP_BASELINE_INVALID');
  const seen = new Set();
  for (const action of core.orderedActions) {
    const id = exactDeployId(action?.deployId, 'CNYOS_DRAFT_CLEANUP_TARGET_INVALID');
    if (action.kind !== 'delete_run_owned_draft' || action.siteId !== POLICY.target.netlifySiteId ||
      id === baseline || seen.has(id)) fail('PLAN_NOT_DRAFT_ONLY');
    const intent = core.draftIntents.find(item => item?.intentId === action.intentId);
    if (!intent || intent.deployId !== id || intent.ownershipMarker !== action.requiredOwnershipMarker ||
      !['recorded', 'deploy_created'].includes(intent.status)) fail('OWNERSHIP_INVALID');
    seen.add(id);
  }
  return Object.freeze({ baseline, allowedDeployIds: Object.freeze([...seen]) });
}

// Defense in depth around the signed executor: no restore, site deletion, or
// arbitrary API mutation can pass this adapter. Recheck current immediately
// before each DELETE; the executor separately checks exact provider ownership.
export function draftCleanupFetchGuard(fetchImpl, plan) {
  const allowed = new Set(plan.allowedDeployIds);
  const deleted = new Set();
  return async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || 'GET';
    if (url.origin !== 'https://api.netlify.com' || url.username || url.password || url.hash ||
      !url.pathname.startsWith('/api/v1/') || !['GET', 'DELETE'].includes(method) ||
      init.redirect !== 'error' || init.credentials !== 'omit') fail('REQUEST_BOUNDARY_INVALID');
    if (method === 'DELETE') {
      const match = /^\/api\/v1\/deploys\/([0-9a-f]{24})$/.exec(url.pathname);
      const id = match?.[1];
      if (!id || url.search || !allowed.has(id) || id === plan.baseline || deleted.has(id)) fail('TARGET_INVALID');
      const siteUrl = `https://api.netlify.com/api/v1/sites/${POLICY.target.netlifySiteId}`;
      const response = await fetchImpl(new URL(siteUrl), { ...init, method: 'GET', body: undefined });
      if (response?.status !== 200 || response.redirected || response.url !== siteUrl ||
        !String(response.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) fail('CURRENT_UNVERIFIED');
      const reader = response.body?.getReader?.();
      if (!reader) fail('CURRENT_UNVERIFIED');
      const chunks = []; let length = 0;
      while (true) {
        const item = await reader.read(); if (item.done) break;
        length += item.value.byteLength;
        if (length > 65536) { await reader.cancel(); fail('CURRENT_UNVERIFIED'); }
        chunks.push(Buffer.from(item.value));
      }
      const site = parseJsonObject(Buffer.concat(chunks).toString('utf8'), 'CNYOS_DRAFT_CLEANUP_CURRENT_UNVERIFIED');
      const current = site.published_deploy?.id || site.published_deploy_id;
      if (site.id !== POLICY.target.netlifySiteId || current !== plan.baseline || current === id) fail('CURRENT_CONFLICT');
      // Mark before sending: an ambiguous response is never replayed by this adapter.
      deleted.add(id);
    }
    return fetchImpl(url, init);
  };
}

export async function cleanupNetlifyDraft({ env = process.env, fetchImpl = fetch,
  now = () => new Date(), watchdog = false, recoveryExecutor = executeRecoveryPlan } = {}) {
  env = Object.freeze({ ...env });
  for (const name of EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) fail('CREDENTIAL_ISOLATION_INVALID');
  }
  const stored = await loadEvidence(watchdog ? env.CNYOS_CONTROLLER_RECOVERY_PLAN_PATH :
    env.CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH,
  watchdog ? env.CNYOS_EXPECTED_RECOVERY_PLAN_SHA256 : env.CNYOS_EXPECTED_RECONCILIATION_PLAN_SHA256,
  'CNYOS_DRAFT_CLEANUP_PLAN_INVALID');
  const plan = assertDraftOnlyRecoveryPlan(stored.value);
  // The production executor independently reloads hashes, authenticates the
  // broker signature + immutable rollback chain, validates generation/run/nonce,
  // verifies the dedicated rollback principal, then verifies each deletion.
  return recoveryExecutor({ env, now, watchdog, fetchImpl: draftCleanupFetchGuard(fetchImpl, plan) });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cleanupNetlifyDraft().then(() => process.stdout.write('CNYOS draft cleanup: verified\n')).catch(error => {
    process.stderr.write(`${/^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message :
      'CNYOS_DRAFT_CLEANUP_FAILED'}\n`); process.exitCode = 1;
  });
}
