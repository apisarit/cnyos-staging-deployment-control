const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLINIC_CODE_PATTERN = /^[A-Z][A-Z0-9_-]{1,23}$/;

export function normalizeOwnerEmails(value) {
  const emails = [...new Set(String(value || '')
    .split(/[\s,;]+/)
    .map(item => item.trim().toLowerCase())
    .filter(Boolean))];
  if (emails.length === 0 || emails.length > 20) throw new Error('CNYOS_OWNER_EMAILS_INVALID');
  if (emails.some(email => email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    throw new Error('CNYOS_OWNER_EMAILS_INVALID');
  }
  return Object.freeze(emails);
}

export function normalizeOwnerClinicCodes(value) {
  const codes = [...new Set(String(value || '')
    .split(/[\s,;]+/)
    .map(item => item.trim().toUpperCase())
    .filter(Boolean))];
  if (codes.length === 0 || codes.length > 50 || codes.some(code => !CLINIC_CODE_PATTERN.test(code))) {
    throw new Error('CNYOS_OWNER_CLINIC_CODES_INVALID');
  }
  return Object.freeze(codes);
}

export function assertOwnerProject(url, expectedProjectRef) {
  const expected = String(expectedProjectRef || '').trim().toLowerCase();
  if (!/^[a-z]{20}$/.test(expected)) throw new Error('CNYOS_OWNER_PROJECT_REF_INVALID');
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('CNYOS_OWNER_DATABASE_CONFIG_MISSING'); }
  const actual = parsed.hostname.match(/^([a-z]{20})\.supabase\.co$/)?.[1] || '';
  if (parsed.protocol !== 'https:' || actual !== expected) throw new Error('CNYOS_OWNER_PROJECT_MISMATCH');
  return actual;
}

export function extractBearerToken(request) {
  const value = String(request.headers.get('authorization') || '');
  const match = value.match(/^Bearer\s+([^\s]+)$/i);
  if (!match || match[1].length < 32 || match[1].length > 8192) {
    throw new Error('CNYOS_OWNER_SESSION_REQUIRED');
  }
  return match[1];
}

export function allowedOwnerOrigin(request) {
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');
  if (origin) return origin === requestOrigin;
  return fetchSite === 'same-origin';
}

function ownerSiteOrigin(value) {
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error('CNYOS_OWNER_SITE_CONFIG_INVALID'); }
  if (parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.port
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(parsed.hostname)) {
    throw new Error('CNYOS_OWNER_SITE_CONFIG_INVALID');
  }
  return parsed.origin;
}

export function assertOwnerRuntime(request, context, expectedSiteId, expectedSiteOrigin) {
  const siteId = String(expectedSiteId || '').trim().toLowerCase();
  const siteOrigin = ownerSiteOrigin(String(expectedSiteOrigin || '').trim().toLowerCase());
  if (!UUID_PATTERN.test(siteId)) throw new Error('CNYOS_OWNER_SITE_CONFIG_INVALID');

  let requestOrigin;
  let contextOrigin;
  try {
    requestOrigin = new URL(request.url).origin;
    contextOrigin = new URL(context?.site?.url).origin;
  } catch {
    throw new Error('CNYOS_OWNER_RUNTIME_MISMATCH');
  }
  if (String(context?.site?.id || '').trim().toLowerCase() !== siteId
    || contextOrigin !== siteOrigin
    || requestOrigin !== siteOrigin) {
    throw new Error('CNYOS_OWNER_RUNTIME_MISMATCH');
  }
  if (context?.deploy?.published !== true
    || context?.deploy?.context !== 'production'
    || !/^[A-Za-z0-9_-]{6,200}$/.test(String(context?.deploy?.id || ''))) {
    throw new Error('CNYOS_OWNER_DEPLOY_CONTEXT_DENIED');
  }
  return Object.freeze({
    siteId,
    siteOrigin,
    deployId: context.deploy.id
  });
}

function decodeOwnerAccessTokenClaims(accessToken) {
  const parts = String(accessToken || '').split('.');
  if (parts.length !== 3 || !parts[1]) throw new Error('CNYOS_OWNER_SESSION_INVALID');
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new Error('CNYOS_OWNER_SESSION_INVALID');
    }
    return claims;
  } catch {
    throw new Error('CNYOS_OWNER_SESSION_INVALID');
  }
}

class LinkedGoogleProofRequired extends Error {
  constructor() { super('CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED'); }
}

// Both user and verifiedAccessToken come from a successful Supabase /auth/v1/user
// request. The optional profile must come only from Google's authenticated UserInfo.
export function validateOwnerUser(user, allowedEmails, verifiedAccessToken, verifiedGoogleProfile = null) {
  const email = String(user?.email || '').trim().toLowerCase();
  const claims = decodeOwnerAccessTokenClaims(verifiedAccessToken);
  const providers = new Set([
    user?.app_metadata?.provider,
    ...(Array.isArray(user?.app_metadata?.providers) ? user.app_metadata.providers : []),
    ...(Array.isArray(user?.identities) ? user.identities.map(identity => identity?.provider) : [])
  ].map(value => String(value || '').trim().toLowerCase()).filter(Boolean));

  if (!UUID_PATTERN.test(String(user?.id || '')) || !email) throw new Error('CNYOS_OWNER_SESSION_INVALID');
  if (!user?.email_confirmed_at && !user?.confirmed_at) throw new Error('CNYOS_OWNER_EMAIL_UNCONFIRMED');
  if (String(claims.sub || '') !== user.id
    || String(claims.email || '').trim().toLowerCase() !== email) {
    throw new Error('CNYOS_OWNER_SESSION_INVALID');
  }
  const authenticationMethods = new Set((Array.isArray(claims.amr) ? claims.amr : [])
    .map(reference => typeof reference === 'string' ? reference : reference?.method)
    .map(value => String(value || '').trim().toLowerCase())
    .filter(Boolean));
  // OAuth AMR alone cannot distinguish Google from a linked GitHub login.
  if (authenticationMethods.size !== 1
    || !authenticationMethods.has('oauth')
    || !providers.has('google')) {
    throw new Error('CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED');
  }
  if (!allowedEmails.includes(email)) throw new Error('CNYOS_OWNER_NOT_AUTHORIZED');
  if (providers.size !== 1) {
    const googleSubjects = (Array.isArray(user.identities) ? user.identities : [])
      .filter(identity => identity?.provider === 'google')
      .map(identity => identity.identity_data?.sub)
      .filter(sub => typeof sub === 'string' && sub.length > 0 && sub.length <= 255);
    if (googleSubjects.length === 0) throw new Error('CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED');
    if (!verifiedGoogleProfile) throw new LinkedGoogleProofRequired();
    if (verifiedGoogleProfile.email_verified !== true
      || typeof verifiedGoogleProfile.sub !== 'string'
      || !googleSubjects.includes(verifiedGoogleProfile.sub)
      || String(verifiedGoogleProfile.email || '').trim().toLowerCase() !== email) {
      throw new Error('CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED');
    }
  }
  return Object.freeze({ id: user.id, email });
}

export async function validateOwnerUserWithGoogleProof({
  request, user, allowedEmails, verifiedAccessToken, fetchImpl = fetch
}) {
  try {
    return validateOwnerUser(user, allowedEmails, verifiedAccessToken);
  } catch (error) {
    if (!(error instanceof LinkedGoogleProofRequired)) throw error;
  }
  // Supabase may link Google and GitHub to the same account. Require a live
  // Google credential for that case; never infer its provider from user metadata.
  const providerToken = request.headers.get('x-owner-google-token') || '';
  if (!/^[A-Za-z0-9._~+\/-]{32,8192}={0,2}$/.test(providerToken)) {
    throw new Error('CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED');
  }
  let profile;
  try {
    const response = await fetchImpl('https://openidconnect.googleapis.com/v1/userinfo', {
      method: 'GET',
      headers: { Authorization: `Bearer ${providerToken}`, Accept: 'application/json' },
      redirect: 'error',
      cache: 'no-store',
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error('GOOGLE_PROOF_REJECTED');
    profile = await response.json();
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)) throw new Error('GOOGLE_PROOF_INVALID');
  } catch {
    // Never expose the provider token, Google's response or transport errors.
    throw new Error('CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED');
  }
  return validateOwnerUser(user, allowedEmails, verifiedAccessToken, profile);
}

export function normalizeSubscriptionRequest(value) {
  const body = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const requestId = String(body.requestId || '').trim();
  const clinicId = String(body.clinicId || '').trim();
  const clinicCode = String(body.clinicCode || '').trim().toUpperCase();
  const expectedVersion = body.expectedVersion;
  const reason = String(body.reason || '').trim();
  if (!UUID_PATTERN.test(requestId) || !UUID_PATTERN.test(clinicId)) {
    throw new Error('CNYOS_OWNER_CONTROL_INPUT_INVALID');
  }
  if (!CLINIC_CODE_PATTERN.test(clinicCode)) throw new Error('CNYOS_OWNER_CLINIC_CODE_INVALID');
  if (typeof body.enabled !== 'boolean') throw new Error('CNYOS_OWNER_STATE_INVALID');
  if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
    throw new Error('CNYOS_OWNER_SUBSCRIPTION_VERSION_INVALID');
  }
  if (reason.length < 8 || reason.length > 500) throw new Error('CNYOS_OWNER_REASON_INVALID');
  return Object.freeze({
    requestId,
    clinicId,
    clinicCode,
    enabled: body.enabled,
    expectedVersion,
    reason
  });
}

export async function readOwnerJson(request, maxBytes = 8192) {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > maxBytes) throw new Error('CNYOS_OWNER_REQUEST_TOO_LARGE');
  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('CNYOS_OWNER_REQUEST_TOO_LARGE');
  try { return JSON.parse(text || '{}'); }
  catch { throw new Error('CNYOS_OWNER_REQUEST_JSON_INVALID'); }
}

export async function supabaseOwnerRequest({
  url,
  serviceRoleKey,
  resource,
  method = 'GET',
  bearer = serviceRoleKey,
  body,
  fetchImpl = fetch
}) {
  if (!url || !serviceRoleKey) throw new Error('CNYOS_OWNER_DATABASE_CONFIG_MISSING');
  if (!/^\/(?:auth\/v1\/user|rest\/v1\/rpc\/[a-z][a-z0-9_]*)$/.test(resource)) {
    throw new Error('CNYOS_OWNER_DATABASE_RESOURCE_INVALID');
  }
  const response = await fetchImpl(`${url.replace(/\/$/, '')}${resource}`, {
    method,
    headers: {
      apikey: serviceRoleKey,
      Authorization: `Bearer ${bearer}`,
      Accept: 'application/json',
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' })
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(8000)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    if (resource === '/auth/v1/user' && [401, 403].includes(response.status)) {
      throw new Error('CNYOS_OWNER_SESSION_INVALID');
    }
    const databaseCode = /^CNYOS_[A-Z0-9_]{3,80}$/.test(String(payload?.message || ''))
      ? payload.message
      : 'CNYOS_OWNER_DATABASE_REQUEST_FAILED';
    throw new Error(databaseCode);
  }
  return payload;
}

export function ownerPublicError(error) {
  const code = String(error?.message || '');
  const status = code === 'CNYOS_OWNER_SESSION_REQUIRED' || code === 'CNYOS_OWNER_SESSION_INVALID' ? 401
    : code === 'CNYOS_OWNER_NOT_AUTHORIZED' || code === 'CNYOS_OWNER_GOOGLE_SIGN_IN_REQUIRED' || code === 'CNYOS_OWNER_EMAIL_UNCONFIRMED' || code === 'CNYOS_OWNER_CLINIC_NOT_ALLOWED' ? 403
      : code === 'CNYOS_OWNER_REQUEST_TOO_LARGE' ? 413
        : code === 'CNYOS_OWNER_SUBSCRIPTION_VERSION_CONFLICT' || code === 'CNYOS_OWNER_REQUEST_ID_CONFLICT' ? 409
        : code === 'CNYOS_OWNER_DEPLOY_CONTEXT_DENIED' ? 403
        : code === 'CNYOS_OWNER_CONTROL_DISABLED' || code === 'CNYOS_OWNER_DATABASE_CONFIG_MISSING' || code === 'CNYOS_OWNER_EMAILS_INVALID' || code === 'CNYOS_OWNER_CLINIC_CODES_INVALID' || code === 'CNYOS_OWNER_PROJECT_REF_INVALID' || code === 'CNYOS_OWNER_PROJECT_MISMATCH' || code === 'CNYOS_OWNER_ENVIRONMENT_INVALID' || code === 'CNYOS_OWNER_DEPLOYMENT_INVALID' || code === 'CNYOS_OWNER_PRODUCTION_DENYLIST_REQUIRED' || code === 'CNYOS_OWNER_PRODUCTION_DENYLIST_INVALID' || code === 'CNYOS_OWNER_PRODUCTION_TARGET_DENIED' || code === 'CNYOS_OWNER_SITE_CONFIG_INVALID' || code === 'CNYOS_OWNER_RUNTIME_MISMATCH' ? 503
        : code.includes('INPUT') || code.includes('INVALID') || code.includes('MISMATCH') || code.includes('REASON') ? 400
          : 500;
  const safeCode = /^CNYOS_OWNER_[A-Z0-9_]{3,80}$/.test(code) ? code : 'CNYOS_OWNER_CONTROL_FAILED';
  return Object.freeze({ code: safeCode, status });
}
