import { createHash } from 'node:crypto';
import { getStore } from '@netlify/blobs';
import {
  allowedOwnerOrigin, assertOwnerProject, assertOwnerRuntime, extractBearerToken,
  normalizeOwnerEmails, ownerPublicError, readOwnerJson, supabaseOwnerRequest,
  validateOwnerUserWithGoogleProof
} from './_shared/owner-control.mjs';
import {
  PLATFORM_FEATURES, normalizePlatformPlan, platformError, platformPreflight
} from '../../platform-config.js';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const REPOSITORY = 'apisarit/chananya-clinical-wellness-os';
const WORKFLOW = 'platform-preview-deploy.yml';
const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };
const json = (payload, status = 200) => new Response(JSON.stringify(payload), { status, headers });
const env = key => String(globalThis.Netlify?.env?.get?.(key) || process.env[key] || '').trim();
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

export function platformTargets(value) {
  let targets;
  try { targets = JSON.parse(value || '[]'); } catch { throw platformError('PLATFORM_REGISTRY_INVALID'); }
  if (!Array.isArray(targets) || targets.length > 50) throw platformError('PLATFORM_REGISTRY_INVALID');
  const keys = new Set(), sites = new Set(), projects = new Set();
  return targets.map(target => {
    if (!target || !/^[a-z][a-z0-9-]{1,59}$/.test(target.key) || !UUID.test(target.siteId)
      || !UUID.test(target.clinicId) || !/^[A-Z][A-Z0-9_-]{1,23}$/.test(target.clinicCode)
      || !/^[a-z]{20}$/.test(target.projectRef) || typeof target.label !== 'string' || target.label.length > 100
      || !/^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(target.siteOrigin)
      || !['staging', 'production'].includes(target.environment)
      || (target.driveRootId && !/^[A-Za-z0-9_-]{10,200}$/.test(target.driveRootId))
      || keys.has(target.key) || sites.has(target.siteId) || projects.has(target.projectRef)) {
      throw platformError('PLATFORM_REGISTRY_INVALID');
    }
    keys.add(target.key); sites.add(target.siteId); projects.add(target.projectRef);
    return { key: target.key, label: target.label, siteId: target.siteId, siteOrigin: target.siteOrigin,
      clinicId: target.clinicId, clinicCode: target.clinicCode, projectRef: target.projectRef,
      environment: target.environment, driveRootId: target.driveRootId || '' };
  });
}

function configuration(getEnv) {
  if (getEnv('CNYOS_OWNER_CONTROL_ENABLED') !== 'true' || getEnv('CNYOS_PLATFORM_CONTROL_ENABLED') !== 'true') {
    throw platformError('PLATFORM_DISABLED');
  }
  const supabaseUrl = getEnv('SUPABASE_URL');
  assertOwnerProject(supabaseUrl, getEnv('CNYOS_OWNER_EXPECTED_PROJECT_REF'));
  const owners = getEnv('CNYOS_PLATFORM_OWNER_USER_IDS').split(/[\s,;]+/).filter(Boolean);
  if (!owners.length || owners.length > 20 || owners.some(id => !UUID.test(id))) throw platformError('PLATFORM_OWNERS_UNCONFIGURED');
  const sourceCommit = getEnv('CLINICAL_OS_SOURCE_COMMIT');
  if (!/^[a-f0-9]{40}$/.test(sourceCommit)) throw platformError('PLATFORM_SOURCE_UNCONFIGURED');
  return { supabaseUrl, owners, sourceCommit, serviceRoleKey: getEnv('SUPABASE_SERVICE_ROLE_KEY'),
    ownerEmails: normalizeOwnerEmails(getEnv('CNYOS_OWNER_EMAILS')),
    siteId: getEnv('CNYOS_OWNER_EXPECTED_NETLIFY_SITE_ID'), siteOrigin: getEnv('CNYOS_OWNER_EXPECTED_SITE_ORIGIN'),
    targets: platformTargets(getEnv('CNYOS_PLATFORM_TARGETS_JSON')),
    githubToken: getEnv('CNYOS_PLATFORM_GITHUB_TOKEN') };
}

function freshOAuth(token, now) {
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  const time = claims.amr?.find(method => method?.method === 'oauth')?.timestamp;
  if (!Number.isFinite(time) || time * 1000 > now + 60000 || now - time * 1000 > 15 * 60000) {
    throw platformError('PLATFORM_RECENT_LOGIN_REQUIRED');
  }
}

function publicRecord(record) {
  return { id: record.id, hash: record.hash, plan: record.plan, createdAt: record.createdAt,
    actor: record.actor.email, events: record.events, deployment: record.deployment || null };
}

async function githubRequest(path, token, options, fetchImpl) {
  const response = await fetchImpl(`https://api.github.com/repos/${REPOSITORY}/actions/workflows/${WORKFLOW}${path}`, {
    ...options, headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
    redirect: 'error', signal: AbortSignal.timeout(10000)
  });
  return response;
}

async function deploymentStatus(record, config, fetchImpl) {
  if (!record.deployment || !config.githubToken) return record;
  try {
    const response = await githubRequest('/runs?event=workflow_dispatch&per_page=50', config.githubToken, { method: 'GET' }, fetchImpl);
    if (!response.ok) return record;
    const payload = await response.json();
    const title = `CNYOS preview ${record.deployment.requestId}`;
    const run = payload.workflow_runs?.find(item => item.display_title === title && item.head_sha === record.plan.sourceCommit
      && item.head_branch === 'main' && item.event === 'workflow_dispatch');
    if (run && Number.isSafeInteger(run.id)) return { ...record, deployment: { ...record.deployment,
      state: run.status === 'completed' ? (run.conclusion === 'success' ? 'workflow_succeeded' : 'workflow_failed') : 'running',
      // A successful workflow is not labelled as a published clinical release.
      runUrl: `https://github.com/${REPOSITORY}/actions/runs/${run.id}`, conclusion: run.conclusion || null } };
  } catch { /* Retain uncertain/queued state; never retry a dispatch as a read side effect. */ }
  return record;
}

export async function handlePlatformConsole(request, context, deps = {}) {
  if (!allowedOwnerOrigin(request)) return json({ ok: false, code: 'CNYOS_OWNER_ORIGIN_DENIED' }, 403);
  if (!['GET', 'POST'].includes(request.method)) return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);
  try {
    const config = configuration(deps.getEnv || env);
    assertOwnerRuntime(request, context, config.siteId, config.siteOrigin);
    const token = extractBearerToken(request);
    const user = await (deps.ownerRequest || supabaseOwnerRequest)({ url: config.supabaseUrl,
      serviceRoleKey: config.serviceRoleKey, resource: '/auth/v1/user', bearer: token });
    const owner = await validateOwnerUserWithGoogleProof({ request, user, allowedEmails: config.ownerEmails,
      verifiedAccessToken: token, fetchImpl: deps.googleFetch || fetch });
    // A clinic's admin/super_admin profile cannot grant platform access.
    if (!config.owners.includes(owner.id)) throw platformError('PLATFORM_OWNER_REQUIRED');
    const store = deps.store || getStore({ name: 'cnyos-platform-plans-v1', consistency: 'strong' });
    const now = deps.now ? deps.now() : Date.now();
    const timestamp = new Date(now).toISOString();
    const preflight = plan => platformPreflight(plan, config.targets, { dispatcherReady: Boolean(config.githubToken) });
    if (request.method === 'GET') {
      const planId = new URL(request.url).searchParams.get('planId');
      if (planId) {
        if (!UUID.test(planId)) throw platformError('PLATFORM_INPUT_INVALID');
        const record = await store.get(`plans/${planId}`, { type: 'json' });
        if (!record) throw platformError('PLATFORM_PLAN_NOT_FOUND');
        return json({ ok: true, record: publicRecord(await deploymentStatus(record, config, deps.githubFetch || fetch)), preflight: preflight(record.plan) });
      }
      const listed = await store.list({ prefix: 'plans/' });
      const records = (await Promise.all(listed.blobs.slice(0, 100).map(blob => store.get(blob.key, { type: 'json' }))))
        .filter(Boolean).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return json({ ok: true, actor: owner.email, role: 'platform_owner', sourceCommit: config.sourceCommit,
        targets: config.targets, features: PLATFORM_FEATURES, dispatcherReady: Boolean(config.githubToken),
        records: records.map(publicRecord), truncated: listed.blobs.length > 100 });
    }
    const body = await readOwnerJson(request, 16384);
    if (!body || typeof body !== 'object' || Array.isArray(body) || !UUID.test(body.requestId || '')) {
      throw platformError('PLATFORM_INPUT_INVALID');
    }
    if (body.action === 'save') {
      if (Object.keys(body).some(key => !['action', 'requestId', 'plan'].includes(key))) throw platformError('PLATFORM_UNKNOWN_FIELD_DENIED');
      const plan = { ...normalizePlatformPlan(body.plan), sourceCommit: config.sourceCommit };
      const hash = digest(plan);
      const record = { id: body.requestId, hash, plan, actor: owner, createdAt: timestamp,
        events: [{ action: 'plan_created', at: timestamp, actor: owner.email, hash }] };
      const key = `plans/${record.id}`;
      const result = await store.setJSON(key, record, { onlyIfNew: true });
      const saved = result.modified ? record : await store.get(key, { type: 'json' });
      if (!saved || saved.hash !== hash || saved.actor.id !== owner.id) throw platformError('PLATFORM_REQUEST_CONFLICT');
      return json({ ok: true, record: publicRecord(saved), preflight: preflight(saved.plan) });
    }
    if (body.action !== 'deploy-preview') throw platformError('PLATFORM_ACTION_DENIED');
    if (Object.keys(body).some(key => !['action', 'requestId', 'planId', 'planHash', 'confirmSlug'].includes(key))) {
      throw platformError('PLATFORM_UNKNOWN_FIELD_DENIED');
    }
    if (!UUID.test(body.planId || '')) throw platformError('PLATFORM_INPUT_INVALID');
    freshOAuth(token, now);
    const key = `plans/${body.planId}`;
    const current = await store.getWithMetadata(key, { type: 'json' });
    if (!current) throw platformError('PLATFORM_PLAN_NOT_FOUND');
    const record = current.data;
    if (body.planHash !== record.hash || body.confirmSlug !== record.plan.slug) throw platformError('PLATFORM_CONFIRMATION_MISMATCH');
    if (record.plan.sourceCommit !== config.sourceCommit) throw platformError('PLATFORM_SOURCE_CHANGED');
    if (record.deployment) return json({ ok: true, record: publicRecord(await deploymentStatus(record, config, deps.githubFetch || fetch)) });
    if (!preflight(record.plan).canDeployPreview) throw platformError('PLATFORM_DEPLOY_NOT_READY');
    const pending = { ...record, deployment: { requestId: body.requestId, state: 'dispatch_pending', at: timestamp },
      events: [...record.events, { action: 'preview_requested', actor: owner.email, at: timestamp, requestId: body.requestId, hash: record.hash }] };
    const lock = await store.setJSON(key, pending, { onlyIfMatch: current.etag });
    if (!lock.modified) throw platformError('PLATFORM_REQUEST_CONFLICT');
    let state = 'dispatch_unknown';
    try {
      const response = await githubRequest('/dispatches', config.githubToken, { method: 'POST', body: JSON.stringify({ ref: 'main',
        inputs: { plan_json: JSON.stringify(record.plan), plan_sha256: record.hash, request_id: body.requestId } }) }, deps.githubFetch || fetch);
      state = response.ok ? 'queued' : response.status >= 400 && response.status < 500 ? 'dispatch_rejected' : 'dispatch_unknown';
    } catch { /* The request may have reached GitHub. Do not dispatch it again. */ }
    const completed = { ...pending, deployment: { ...pending.deployment, state },
      events: [...pending.events, { action: state, at: new Date(deps.now ? deps.now() : Date.now()).toISOString(), actor: owner.email }] };
    const finalWrite = await store.setJSON(key, completed, { onlyIfMatch: lock.etag });
    if (!finalWrite.modified) throw platformError('PLATFORM_REQUEST_CONFLICT');
    return json({ ok: true, record: publicRecord(completed) }, state === 'dispatch_rejected' ? 200 : 202);
  } catch (error) {
    const code = String(error?.message || '');
    if (code.startsWith('CNYOS_OWNER_')) {
      const safe = ownerPublicError(error); return json({ ok: false, code: safe.code }, safe.status);
    }
    const known = /^PLATFORM_[A-Z_]{3,70}$/.test(code);
    const status = /OWNER_REQUIRED|RECENT_LOGIN_REQUIRED|ACTION_DENIED/.test(code) ? 403
      : /CONFLICT|CHANGED|MISMATCH/.test(code) ? 409 : /NOT_FOUND/.test(code) ? 404
        : /DISABLED|UNCONFIGURED|REGISTRY_INVALID|NOT_READY/.test(code) ? 503 : known ? 400 : 503;
    return json({ ok: false, code: known ? code : 'PLATFORM_SERVICE_UNAVAILABLE',
      field: ['name', 'slug', 'site', 'database', 'drive', 'nas', 'features', 'targetKey'].includes(error?.field) ? error.field : undefined }, status);
  }
}

export default async (request, context) => handlePlatformConsole(request, context);
export const config = { path: '/api/platform-console', method: ['GET', 'POST'] };
