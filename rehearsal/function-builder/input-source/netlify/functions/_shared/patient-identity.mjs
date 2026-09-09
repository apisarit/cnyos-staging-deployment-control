import { createHash, createHmac, randomBytes, randomInt } from 'node:crypto';

const LINE_VERIFY_URL = 'https://api.line.me/oauth2/v2.1/verify';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLINIC_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LINK_CODE_PATTERN = /^[0-9A-F]{12}$/;

export function sha256(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

export function hmacSha256(value, secret) {
  if (!secret || secret.length < 32) throw new Error('PATIENT_IDENTITY_HMAC_SECRET_INVALID');
  return createHmac('sha256', secret).update(String(value), 'utf8').digest('hex');
}

export function normalizeLinkCode(value) {
  const normalized = String(value || '').toUpperCase().replace(/[^0-9A-F]/g, '');
  if (!LINK_CODE_PATTERN.test(normalized)) throw new Error('LINK_CODE_FORMAT_INVALID');
  return normalized;
}

export function normalizePatientId(value) {
  const normalized = String(value || '').trim();
  if (!UUID_PATTERN.test(normalized)) throw new Error('PATIENT_ID_INVALID');
  return normalized;
}

export function normalizeClinicId(value) {
  const normalized = String(value || '').trim();
  if (!CLINIC_UUID_PATTERN.test(normalized)) throw new Error('CNYOS_EXPECTED_CLINIC_ID_INVALID');
  return normalized;
}

export function createOneTimeCredential(issuer = 'CHANANYA') {
  const normalizedIssuer = String(issuer || '').trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_-]{1,23}$/.test(normalizedIssuer)) throw new Error('PATIENT_QR_ISSUER_INVALID');
  const token = randomBytes(32).toString('base64url');
  const displayCode = String(randomInt(0, 1_000_000)).padStart(6, '0');
  return Object.freeze({
    token,
    displayCode,
    payload: `${normalizedIssuer}:PT1:${token}`,
    tokenHash: sha256(token),
    displayCodeHash: sha256(displayCode)
  });
}

export function validateLineIdentity(payload, expectedChannelId, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!payload || typeof payload !== 'object') throw new Error('LINE_ID_TOKEN_INVALID');
  if (payload.iss !== 'https://access.line.me') throw new Error('LINE_ID_TOKEN_ISSUER_INVALID');
  if (String(payload.aud || '') !== String(expectedChannelId || '')) throw new Error('LINE_ID_TOKEN_AUDIENCE_INVALID');
  if (!payload.sub || typeof payload.sub !== 'string') throw new Error('LINE_ID_TOKEN_SUBJECT_MISSING');
  if (!Number.isFinite(Number(payload.exp)) || Number(payload.exp) <= nowSeconds) throw new Error('LINE_ID_TOKEN_EXPIRED');
  if (Number.isFinite(Number(payload.iat)) && Number(payload.iat) > nowSeconds + 60) throw new Error('LINE_ID_TOKEN_IAT_INVALID');
  return Object.freeze({ subject: payload.sub, expiresAt: Number(payload.exp) });
}

export async function verifyLineIdToken(idToken, channelId, fetchImpl = fetch) {
  if (!idToken || typeof idToken !== 'string' || idToken.length < 80 || idToken.length > 8192) {
    throw new Error('LINE_ID_TOKEN_FORMAT_INVALID');
  }
  if (!channelId) throw new Error('LINE_LOGIN_CHANNEL_ID_MISSING');

  const response = await fetchImpl(LINE_VERIFY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ id_token: idToken, client_id: channelId }),
    signal: AbortSignal.timeout(8000)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error('LINE_ID_TOKEN_VERIFICATION_FAILED');
  return validateLineIdentity(payload, channelId);
}

export async function supabaseRpc({ url, serviceRoleKey, name, body, fetchImpl = fetch }) {
  if (!url || !serviceRoleKey) throw new Error('IDENTITY_DATABASE_CONFIG_MISSING');
  if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error('RPC_NAME_INVALID');

  const response = await fetchImpl(`${url.replace(/\/$/, '')}/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: {
      apikey: serviceRoleKey,
      Authorization: `Bearer ${serviceRoleKey}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(body || {}),
    signal: AbortSignal.timeout(8000)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const databaseCode = /^[A-Z][A-Z0-9_]{2,80}$/.test(String(payload?.message || ''))
      ? payload.message
      : 'IDENTITY_DATABASE_REQUEST_FAILED';
    const error = new Error(databaseCode);
    error.cause = { status: response.status, code: payload?.code || null };
    throw error;
  }
  return payload;
}

export function allowedRequestOrigin(request) {
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get('origin');
  if (!origin) return false;
  return origin === requestOrigin;
}

export async function readJsonBody(request, maxBytes = 16_384) {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > maxBytes) throw new Error('REQUEST_TOO_LARGE');
  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('REQUEST_TOO_LARGE');
  try { return JSON.parse(text || '{}'); }
  catch { throw new Error('REQUEST_JSON_INVALID'); }
}

export function publicError(error) {
  const known = new Set([
    'LINK_CODE_FORMAT_INVALID',
    'LINK_CODE_INVALID_OR_EXPIRED',
    'LINE_ID_ALREADY_LINKED',
    'LINE_PATIENT_ALREADY_LINKED',
    'LINE_ID_TOKEN_EXPIRED',
    'LINE_ID_TOKEN_VERIFICATION_FAILED',
    'CONSENT_REQUIRED',
    'PATIENT_ID_INVALID',
    'PATIENT_IDENTITY_NOT_LINKED',
    'CNYOS_SUBSCRIPTION_SUSPENDED',
    'RATE_LIMITED'
  ]);
  const code = known.has(error?.message) ? error.message : 'PATIENT_IDENTITY_REQUEST_FAILED';
  const status = code === 'RATE_LIMITED' ? 429
    : code === 'CNYOS_SUBSCRIPTION_SUSPENDED' ? 503
    : code.includes('TOKEN') ? 401
      : code.includes('INVALID') || code.includes('LINKED') || code === 'CONSENT_REQUIRED' ? 400
        : 500;
  return Object.freeze({ code, status });
}
