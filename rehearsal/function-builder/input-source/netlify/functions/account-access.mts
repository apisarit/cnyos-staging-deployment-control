import { allowedOwnerOrigin, assertOwnerProject, assertOwnerRuntime, extractBearerToken } from './_shared/owner-control.mjs';

function reply(body, status = 200) {
  return Response.json(body, { status, headers: {
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff'
  } });
}

function failure(code, status) { return Object.assign(new Error(code), { status }); }

function configuration(request, context, getEnv) {
  const url = getEnv('SUPABASE_URL');
  assertOwnerProject(url, getEnv('CNYOS_OWNER_EXPECTED_PROJECT_REF'));
  assertOwnerRuntime(request, context, getEnv('CNYOS_OWNER_EXPECTED_NETLIFY_SITE_ID'), getEnv('CNYOS_OWNER_EXPECTED_SITE_ORIGIN'));
  const key = getEnv('SUPABASE_SERVICE_ROLE_KEY');
  const clinicId = getEnv('CNYOS_ACCOUNT_CLINIC_ID');
  const clinicCode = getEnv('CNYOS_ACCOUNT_CLINIC_CODE');
  if (!key || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(clinicId) || !/^[A-Z0-9_-]{2,32}$/.test(clinicCode)) {
    throw failure('ACCOUNT_SERVICE_UNAVAILABLE', 503);
  }
  return { url: url.replace(/\/$/, ''), key, clinicId, clinicCode };
}

async function database(config, resource, { bearer = config.key, method = 'GET', body, prefer } = {}, fetchImpl = fetch) {
  const response = await fetchImpl(config.url + resource, {
    method, headers: {
      apikey: config.key, Authorization: `Bearer ${bearer}`, Accept: 'application/json',
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(prefer ? { Prefer: prefer } : {})
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) {
    if (resource === '/auth/v1/user' && [401, 403].includes(response.status)) throw failure('ACCOUNT_SESSION_INVALID', 401);
    throw failure('ACCOUNT_SERVICE_UNAVAILABLE', 503);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

function verifiedUser(user) {
  if (!user || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(user.id)
      || user.aud !== 'authenticated' || user.is_anonymous === true
      || !user.email || !user.email_confirmed_at
      || (user.banned_until && Date.parse(user.banned_until) > Date.now())) {
    throw failure('ACCOUNT_SESSION_INVALID', 401);
  }
  return user;
}

// Identity-only fallback when the subscription boundary hides an unassigned
// user's profile. This never returns department grants or creates membership.
async function accountStatus(user, call) {
  let rows = await call(`/rest/v1/profiles?select=id,full_name,email&id=eq.${user.id}&limit=1`);
  if (!Array.isArray(rows)) throw failure('ACCOUNT_SERVICE_UNAVAILABLE', 503);
  if (!rows.length) {
    await call('/rest/v1/profiles?on_conflict=id', {
      method: 'POST', prefer: 'resolution=ignore-duplicates,return=minimal',
      body: {
        id: user.id, email: user.email,
        full_name: String(user.user_metadata?.full_name || user.user_metadata?.name || user.email).slice(0, 240),
        role: 'viewer', system_role: 'staff'
      }
    });
    rows = await call(`/rest/v1/profiles?select=id,full_name,email&id=eq.${user.id}&limit=1`);
  }
  if (!rows?.[0] || rows[0].id !== user.id) throw failure('ACCOUNT_SERVICE_UNAVAILABLE', 503);
  const memberships = await call(`/rest/v1/clinic_memberships?select=clinic_id&profile_id=eq.${user.id}&limit=1`);
  if (!Array.isArray(memberships)) throw failure('ACCOUNT_SERVICE_UNAVAILABLE', 503);
  const profile = rows[0];
  return { ok: true, status: memberships.length ? 'access_unavailable' : 'pending_approval',
    profile: { id: user.id, full_name: profile.full_name, email: profile.email } };
}

async function staffList(config, token, call) {
  // The user's current JWT, not metadata or the service key, determines access.
  const result = await call('/rest/v1/rpc/current_access_context', { method: 'POST', bearer: token, body: {} });
  const access = Array.isArray(result) ? result[0] : result;
  if (access?.ready !== true || access.clinic_id !== config.clinicId || access.clinic_code !== config.clinicCode
      || !(['admin', 'super_admin'].includes(access.system_role) || ['owner', 'admin'].includes(access.clinic_role))) {
    throw failure('ACCOUNT_GOVERNANCE_REQUIRED', 403);
  }
  const fields = 'id,full_name,email,role,system_role';
  const members = await call(`/rest/v1/profiles?select=${fields},clinic_memberships!inner(clinic_id,clinic_role,active)&clinic_memberships.clinic_id=eq.${config.clinicId}&order=full_name.asc&limit=501`);
  // Only the active Super Admin can see accounts never assigned to ANY clinic.
  // Existing members of other clinics, including inactive ones, are excluded.
  const pending = access.system_role === 'super_admin'
    ? await call(`/rest/v1/profiles?select=${fields},clinic_memberships(clinic_id)&clinic_memberships=is.null&order=created_at.desc&limit=501`)
    : [];
  if (!Array.isArray(members) || !Array.isArray(pending)) throw failure('ACCOUNT_SERVICE_UNAVAILABLE', 503);
  const users = [];
  const seen = new Set();
  for (const p of [...pending, ...members]) {
    const memberships = p.clinic_memberships;
    if (!Array.isArray(memberships)) continue;
    const membership = memberships.find(m => m.clinic_id === config.clinicId);
    if ((!membership && (memberships.length || access.system_role !== 'super_admin')) || seen.has(p.id)) continue;
    seen.add(p.id);
    const role = membership?.clinic_role || 'viewer';
    users.push({ id: p.id, full_name: p.full_name, email: p.email,
      role, system_role: p.system_role,
      effective_role: p.system_role === 'super_admin' ? 'super_admin' : p.system_role === 'admin' || ['owner', 'admin'].includes(role) ? 'admin' : role,
      access_status: !membership ? 'pending_approval' : membership.active ? 'active' : 'inactive' });
  }
  // Recheck suspension/role changes before releasing a privileged response.
  const again = await call('/rest/v1/rpc/current_access_context', { method: 'POST', bearer: token, body: {} });
  const current = Array.isArray(again) ? again[0] : again;
  if (current?.ready !== true || current.clinic_id !== config.clinicId || current.clinic_code !== config.clinicCode
      || current.system_role !== access.system_role || current.clinic_role !== access.clinic_role) {
    throw failure('ACCOUNT_GOVERNANCE_REQUIRED', 403);
  }
  return { ok: true, users: users.slice(0, 500), truncated: members.length > 500 || pending.length > 500 || users.length > 500 };
}

export async function handleAccountAccess(request, context, deps = {}) {
  if (!allowedOwnerOrigin(request)) return reply({ ok: false, code: 'ACCOUNT_ORIGIN_DENIED' }, 403);
  if (request.method !== 'POST') return reply({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);
  try {
    const config = configuration(request, context, deps.getEnv || (key => globalThis.Netlify?.env?.get(key) || ''));
    let token;
    try { token = extractBearerToken(request); } catch { throw failure('ACCOUNT_SESSION_INVALID', 401); }
    if (!/^application\/json(?:;|$)/i.test(request.headers.get('content-type') || '')) throw failure('ACCOUNT_REQUEST_INVALID', 400);
    if (Number(request.headers.get('content-length') || 0) > 256) throw failure('ACCOUNT_REQUEST_INVALID', 400);
    const text = await request.text();
    if (text.length > 256) throw failure('ACCOUNT_REQUEST_INVALID', 400);
    let input;
    try { input = JSON.parse(text); } catch { throw failure('ACCOUNT_REQUEST_INVALID', 400); }
    if (!input || Array.isArray(input) || Object.keys(input).join(',') !== 'action' || !['status', 'staff_list'].includes(input.action)) {
      throw failure('ACCOUNT_REQUEST_INVALID', 400);
    }
    const call = (path, options) => database(config, path, options, deps.fetchImpl || fetch);
    const user = verifiedUser(await call('/auth/v1/user', { bearer: token }));
    return reply(input.action === 'status' ? await accountStatus(user, call) : await staffList(config, token, call));
  } catch (error) {
    const code = /^ACCOUNT_[A-Z_]+$/.test(error?.message || '') ? error.message : 'ACCOUNT_SERVICE_UNAVAILABLE';
    return reply({ ok: false, code }, error?.status || 503);
  }
}

export default async (request, context) => handleAccountAccess(request, context);
export const config = { path: '/api/account-access' };
