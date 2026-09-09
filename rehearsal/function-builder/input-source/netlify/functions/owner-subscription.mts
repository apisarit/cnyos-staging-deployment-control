import {
  allowedOwnerOrigin,
  assertOwnerProject,
  assertOwnerRuntime,
  extractBearerToken,
  normalizeOwnerClinicCodes,
  normalizeOwnerEmails,
  normalizeSubscriptionRequest,
  ownerPublicError,
  readOwnerJson,
  supabaseOwnerRequest,
  validateOwnerUserWithGoogleProof
} from './_shared/owner-control.mjs';

const responseHeaders = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  'Content-Type': 'application/json; charset=utf-8',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
});

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: responseHeaders });
}

function env(name) {
  return globalThis.Netlify?.env?.get(name) || process.env[name] || '';
}

function configuration(getEnv = env) {
  if (getEnv('CNYOS_OWNER_CONTROL_ENABLED') !== 'true') {
    throw new Error('CNYOS_OWNER_CONTROL_DISABLED');
  }
  const supabaseUrl = getEnv('SUPABASE_URL');
  assertOwnerProject(supabaseUrl, getEnv('CNYOS_OWNER_EXPECTED_PROJECT_REF'));
  const environment = getEnv('BACKUP_ENVIRONMENT').trim().toLowerCase();
  if (!['staging', 'production'].includes(environment)) {
    throw new Error('CNYOS_OWNER_ENVIRONMENT_INVALID');
  }
  const deploymentId = getEnv('BACKUP_DEPLOYMENT_ID') || getEnv('SITE_NAME');
  const stagingMarker = /(?:^|[-_.])(staging|stage|nonprod|test)(?:$|[-_.])/i;
  if (!deploymentId
    || (environment === 'staging' && !stagingMarker.test(deploymentId))
    || (environment === 'production' && stagingMarker.test(deploymentId))) {
    throw new Error('CNYOS_OWNER_DEPLOYMENT_INVALID');
  }
  if (environment === 'staging') {
    const productionSupabaseUrl = getEnv('BACKUP_PRODUCTION_SUPABASE_URL');
    if (!productionSupabaseUrl) throw new Error('CNYOS_OWNER_PRODUCTION_DENYLIST_REQUIRED');
    let production;
    try { production = new URL(productionSupabaseUrl); }
    catch { throw new Error('CNYOS_OWNER_PRODUCTION_DENYLIST_INVALID'); }
    if (production.protocol !== 'https:'
      || !/^[a-z]{20}\.supabase\.co$/.test(production.hostname)
      || production.pathname !== '/'
      || production.search
      || production.hash
      || production.username
      || production.password) {
      throw new Error('CNYOS_OWNER_PRODUCTION_DENYLIST_INVALID');
    }
    if (production.origin === new URL(supabaseUrl).origin) {
      throw new Error('CNYOS_OWNER_PRODUCTION_TARGET_DENIED');
    }
  }
  return Object.freeze({
    supabaseUrl,
    serviceRoleKey: getEnv('SUPABASE_SERVICE_ROLE_KEY'),
    ownerEmails: normalizeOwnerEmails(getEnv('CNYOS_OWNER_EMAILS')),
    clinicCodes: normalizeOwnerClinicCodes(getEnv('CNYOS_OWNER_CLINIC_CODES')),
    environment,
    deploymentId,
    expectedNetlifySiteId: getEnv('CNYOS_OWNER_EXPECTED_NETLIFY_SITE_ID'),
    expectedSiteOrigin: getEnv('CNYOS_OWNER_EXPECTED_SITE_ORIGIN')
  });
}

async function authenticateOwner(request, config, ownerRequest = supabaseOwnerRequest, googleFetch = fetch) {
  const token = extractBearerToken(request);
  const user = await ownerRequest({
    url: config.supabaseUrl,
    serviceRoleKey: config.serviceRoleKey,
    resource: '/auth/v1/user',
    bearer: token
  });
  return validateOwnerUserWithGoogleProof({
    request, user, allowedEmails: config.ownerEmails, verifiedAccessToken: token, fetchImpl: googleFetch
  });
}

async function listClinics(config, ownerRequest = supabaseOwnerRequest) {
  const clinics = await ownerRequest({
    url: config.supabaseUrl,
    serviceRoleKey: config.serviceRoleKey,
    resource: '/rest/v1/rpc/list_owner_subscription_clinics',
    method: 'POST',
    body: {}
  });
  return Array.isArray(clinics)
    ? clinics.filter(clinic => config.clinicCodes.includes(String(clinic?.clinic_code || '').toUpperCase()))
    : [];
}

async function changeSubscription(request, config, owner, ownerRequest = supabaseOwnerRequest) {
  const input = normalizeSubscriptionRequest(await readOwnerJson(request));
  if (!config.clinicCodes.includes(input.clinicCode)) throw new Error('CNYOS_OWNER_CLINIC_NOT_ALLOWED');
  return ownerRequest({
    url: config.supabaseUrl,
    serviceRoleKey: config.serviceRoleKey,
    resource: '/rest/v1/rpc/set_clinic_subscription_state',
    method: 'POST',
    body: {
      p_request_id: input.requestId,
      p_clinic_id: input.clinicId,
      p_expected_clinic_code: input.clinicCode,
      p_enabled: input.enabled,
      p_expected_version: input.expectedVersion,
      p_reason: input.reason,
      p_actor_user_id: owner.id,
      p_actor_email: owner.email
    }
  });
}

export async function handleOwnerSubscription(request, context, deps = {}) {
  const requestId = context.requestId || crypto.randomUUID();
  if (!allowedOwnerOrigin(request)) return json({ ok: false, code: 'CNYOS_OWNER_ORIGIN_DENIED' }, 403);
  if (!['GET', 'POST'].includes(request.method)) return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);

  try {
    const config = configuration(deps.getEnv || env);
    assertOwnerRuntime(
      request,
      context,
      config.expectedNetlifySiteId,
      config.expectedSiteOrigin
    );
    const owner = await authenticateOwner(request, config, deps.ownerRequest, deps.googleFetch);
    if (request.method === 'GET') {
      return json({ ok: true, clinics: await listClinics(config, deps.ownerRequest) });
    }
    const result = await changeSubscription(request, config, owner, deps.ownerRequest);
    return json({ ok: true, result });
  } catch (error) {
    const safe = ownerPublicError(error);
    console.error('CNYOS owner subscription request failed', {
      requestId,
      code: safe.code
    });
    return json({ ok: false, code: safe.code }, safe.status);
  }
}

export default async (request, context) => handleOwnerSubscription(request, context);

export const config = {
  path: '/api/owner-subscription',
  method: ['GET', 'POST']
};
