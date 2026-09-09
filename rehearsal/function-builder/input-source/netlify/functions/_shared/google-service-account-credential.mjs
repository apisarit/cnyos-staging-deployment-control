import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  randomBytes,
  timingSafeEqual
} from 'node:crypto';
import { getStore } from '@netlify/blobs';

export const GOOGLE_SERVICE_ACCOUNT_BLOB_STORE = 'cnyos-functions-secrets';
export const GOOGLE_SERVICE_ACCOUNT_BLOB_FORMAT = 'cnyos-google-service-account-credential/v1';
export const GOOGLE_SERVICE_ACCOUNT_BLOB_PREFIX = 'google-drive-service-account/v1/';
export const GOOGLE_SERVICE_ACCOUNT_MAX_PLAINTEXT_BYTES = 16 * 1024;
export const GOOGLE_SERVICE_ACCOUNT_MAX_BLOB_BYTES = 32 * 1024;

const ALGORITHM = 'AES-256-GCM';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROJECT_REF_PATTERN = /^[a-z]{20}$/;
const DEPLOYMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$/;
const GCP_PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const SERVICE_ACCOUNT_EMAIL_PATTERN = /^[a-z0-9][a-z0-9._-]{2,98}@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/;
const PRIVATE_KEY_ID_PATTERN = /^[a-f0-9]{16,128}$/i;
const CLIENT_ID_PATTERN = /^[0-9]{6,32}$/;
const CANONICAL_BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

const SERVICE_ACCOUNT_KEYS = Object.freeze([
  'auth_provider_x509_cert_url',
  'auth_uri',
  'client_email',
  'client_id',
  'client_x509_cert_url',
  'private_key',
  'private_key_id',
  'project_id',
  'token_uri',
  'type',
  'universe_domain'
].sort());

const REQUIRED_SERVICE_ACCOUNT_KEYS = Object.freeze([
  'auth_provider_x509_cert_url',
  'auth_uri',
  'client_email',
  'client_id',
  'client_x509_cert_url',
  'private_key',
  'private_key_id',
  'project_id',
  'token_uri',
  'type'
].sort());

const BINDING_KEYS = Object.freeze([
  'deployment_id',
  'environment',
  'format',
  'netlify_site_id',
  'service_account_client_email',
  'site_origin',
  'supabase_project_ref',
  'wrap_key_id'
].sort());

const ENVELOPE_KEYS = Object.freeze([
  'algorithm',
  'binding',
  'ciphertext',
  'created_at',
  'format',
  'iv',
  'tag'
].sort());

function exactKeys(value, expected, required = expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  return required.every(key => actual.includes(key)) && actual.every(key => expected.includes(key));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function equalJson(left, right) {
  const a = createHash('sha256').update(canonicalJson(left)).digest();
  const b = createHash('sha256').update(canonicalJson(right)).digest();
  return timingSafeEqual(a, b);
}

function decodeCanonicalBase64(value, code) {
  const text = String(value || '');
  if (!text || text.length % 4 !== 0 || !CANONICAL_BASE64_PATTERN.test(text)) throw new Error(code);
  let decoded;
  try { decoded = Buffer.from(text, 'base64'); }
  catch { throw new Error(code); }
  if (decoded.toString('base64') !== text) throw new Error(code);
  return decoded;
}

function parseNetlifyOrigin(value) {
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_SITE_ORIGIN_INVALID'); }
  if (parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.port
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(parsed.hostname)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_SITE_ORIGIN_INVALID');
  }
  return parsed.origin;
}

function assertIsoTimestamp(value) {
  const text = String(value || '');
  const parsed = new Date(text);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== text) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_CREATED_AT_INVALID');
  }
  return text;
}

function parseServiceAccountJson(value) {
  if (Buffer.isBuffer(value) && value.length > GOOGLE_SERVICE_ACCOUNT_MAX_PLAINTEXT_BYTES) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_TOO_LARGE');
  }
  const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value || '');
  if (Buffer.byteLength(text, 'utf8') > GOOGLE_SERVICE_ACCOUNT_MAX_PLAINTEXT_BYTES) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_TOO_LARGE');
  }
  try { return JSON.parse(text); }
  catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_JSON_INVALID'); }
}

function assertGoogleUrl(value, expected, code) {
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error(code); }
  if (parsed.href !== expected) throw new Error(code);
}

function assertGoogleCertificateUrl(value, host, pathPattern, code) {
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error(code); }
  if (parsed.protocol !== 'https:'
    || parsed.hostname !== host
    || parsed.username
    || parsed.password
    || parsed.port
    || parsed.search
    || parsed.hash
    || !pathPattern.test(parsed.pathname)) {
    throw new Error(code);
  }
}

export function validateGoogleServiceAccountDocument(value) {
  const document = typeof value === 'string' || Buffer.isBuffer(value) ? parseServiceAccountJson(value) : value;
  if (!exactKeys(document, SERVICE_ACCOUNT_KEYS, REQUIRED_SERVICE_ACCOUNT_KEYS)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_SCHEMA_INVALID');
  }
  if (document.type !== 'service_account'
    || !GCP_PROJECT_ID_PATTERN.test(String(document.project_id || ''))
    || !PRIVATE_KEY_ID_PATTERN.test(String(document.private_key_id || ''))
    || !SERVICE_ACCOUNT_EMAIL_PATTERN.test(String(document.client_email || ''))
    || !CLIENT_ID_PATTERN.test(String(document.client_id || ''))
    || (document.universe_domain !== undefined && document.universe_domain !== 'googleapis.com')) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_IDENTITY_INVALID');
  }
  const emailProject = String(document.client_email).split('@')[1]?.replace(/\.iam\.gserviceaccount\.com$/, '');
  if (emailProject !== document.project_id) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_PROJECT_MISMATCH');
  }
  assertGoogleUrl(
    document.auth_uri,
    'https://accounts.google.com/o/oauth2/auth',
    'GOOGLE_SERVICE_ACCOUNT_AUTH_URI_INVALID'
  );
  assertGoogleUrl(
    document.token_uri,
    'https://oauth2.googleapis.com/token',
    'GOOGLE_SERVICE_ACCOUNT_TOKEN_URI_INVALID'
  );
  assertGoogleCertificateUrl(
    document.auth_provider_x509_cert_url,
    'www.googleapis.com',
    /^\/oauth2\/v1\/certs$/,
    'GOOGLE_SERVICE_ACCOUNT_CERT_URI_INVALID'
  );
  assertGoogleCertificateUrl(
    document.client_x509_cert_url,
    'www.googleapis.com',
    /^\/robot\/v1\/metadata\/x509\/[A-Za-z0-9%._~+-]+$/,
    'GOOGLE_SERVICE_ACCOUNT_CLIENT_CERT_URI_INVALID'
  );
  const privateKey = String(document.private_key || '').replace(/\\n/g, '\n');
  if (Buffer.byteLength(privateKey, 'utf8') > 8192
    || !/^-----BEGIN PRIVATE KEY-----\n[\s\S]+\n-----END PRIVATE KEY-----\n?$/.test(privateKey)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_INVALID');
  }
  let parsedKey;
  try { parsedKey = createPrivateKey(privateKey); }
  catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_INVALID'); }
  if (parsedKey.type !== 'private' || parsedKey.asymmetricKeyType !== 'rsa') {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_INVALID');
  }

  return Object.freeze({
    clientEmail: document.client_email,
    privateKey,
    tokenUri: document.token_uri,
    projectId: document.project_id,
    privateKeyId: document.private_key_id
  });
}

export function parseGoogleServiceAccountWrapKey(value) {
  const key = decodeCanonicalBase64(value, 'GOOGLE_SERVICE_ACCOUNT_WRAP_KEY_INVALID');
  if (key.length !== 32) throw new Error('GOOGLE_SERVICE_ACCOUNT_WRAP_KEY_INVALID');
  return key;
}

function decodeComparableBase64(value) {
  const text = String(value || '').trim();
  if (!text || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  let decoded;
  try { decoded = Buffer.from(text, 'base64'); }
  catch { return null; }
  if (decoded.length !== 32
    || decoded.toString('base64').replace(/=+$/, '') !== text.replace(/=+$/, '')) {
    decoded.fill(0);
    return null;
  }
  return decoded;
}

export function googleServiceAccountWrapKeyReused(wrapKeyValue, candidateValue) {
  if (!wrapKeyValue || !candidateValue) return false;
  const wrapKey = parseGoogleServiceAccountWrapKey(wrapKeyValue);
  const candidateKey = decodeComparableBase64(candidateValue);
  try {
    if (candidateKey) return timingSafeEqual(wrapKey, candidateKey);
    const left = Buffer.from(String(wrapKeyValue));
    const right = Buffer.from(String(candidateValue));
    return left.length === right.length && timingSafeEqual(left, right);
  } finally {
    wrapKey.fill(0);
    candidateKey?.fill(0);
  }
}

function normalizeExpectedServiceAccountEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!SERVICE_ACCOUNT_EMAIL_PATTERN.test(email)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_EXPECTED_EMAIL_INVALID');
  }
  return email;
}

export function createGoogleServiceAccountBinding({
  siteId,
  siteOrigin,
  supabaseProjectRef,
  deploymentId,
  environment,
  wrapKeyId,
  expectedServiceAccountEmail
}) {
  const normalized = {
    format: GOOGLE_SERVICE_ACCOUNT_BLOB_FORMAT,
    netlify_site_id: String(siteId || '').trim().toLowerCase(),
    site_origin: parseNetlifyOrigin(String(siteOrigin || '').trim().toLowerCase()),
    supabase_project_ref: String(supabaseProjectRef || '').trim().toLowerCase(),
    deployment_id: String(deploymentId || '').trim(),
    environment: String(environment || '').trim().toLowerCase(),
    service_account_client_email: normalizeExpectedServiceAccountEmail(expectedServiceAccountEmail),
    wrap_key_id: String(wrapKeyId || '').trim()
  };
  if (!UUID_PATTERN.test(normalized.netlify_site_id)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_SITE_ID_INVALID');
  }
  if (!PROJECT_REF_PATTERN.test(normalized.supabase_project_ref)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_PROJECT_INVALID');
  }
  if (!DEPLOYMENT_ID_PATTERN.test(normalized.deployment_id)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_DEPLOYMENT_INVALID');
  }
  if (!['staging', 'production'].includes(normalized.environment)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_ENVIRONMENT_INVALID');
  }
  if (!KEY_ID_PATTERN.test(normalized.wrap_key_id)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_WRAP_KEY_ID_INVALID');
  }
  return Object.freeze(normalized);
}

export function googleServiceAccountBlobKey(wrapKeyId) {
  const keyId = String(wrapKeyId || '').trim();
  if (!KEY_ID_PATTERN.test(keyId)) throw new Error('GOOGLE_SERVICE_ACCOUNT_WRAP_KEY_ID_INVALID');
  return `${GOOGLE_SERVICE_ACCOUNT_BLOB_PREFIX}${keyId}`;
}

function canonicalServiceAccountPlaintext(serviceAccount, source) {
  const document = typeof source === 'string' || Buffer.isBuffer(source) ? parseServiceAccountJson(source) : source;
  return Buffer.from(JSON.stringify({
    type: 'service_account',
    project_id: serviceAccount.projectId,
    private_key_id: serviceAccount.privateKeyId,
    private_key: serviceAccount.privateKey,
    client_email: serviceAccount.clientEmail,
    client_id: String(document.client_id),
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: String(document.auth_provider_x509_cert_url),
    client_x509_cert_url: String(document.client_x509_cert_url),
    ...(document.universe_domain === undefined ? {} : { universe_domain: document.universe_domain })
  }));
}

export function encryptGoogleServiceAccountCredential(value, wrapKey, binding, options = {}) {
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== 32) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_WRAP_KEY_INVALID');
  }
  const expectedBinding = createGoogleServiceAccountBinding({
    siteId: binding?.netlify_site_id,
    siteOrigin: binding?.site_origin,
    supabaseProjectRef: binding?.supabase_project_ref,
    deploymentId: binding?.deployment_id,
    environment: binding?.environment,
    wrapKeyId: binding?.wrap_key_id,
    expectedServiceAccountEmail: binding?.service_account_client_email
  });
  if (!exactKeys(binding, BINDING_KEYS) || !equalJson(binding, expectedBinding)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BINDING_INVALID');
  }
  const createdAt = assertIsoTimestamp(options.createdAt || new Date().toISOString());
  const serviceAccount = validateGoogleServiceAccountDocument(value);
  if (serviceAccount.clientEmail.toLowerCase() !== expectedBinding.service_account_client_email) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_EXPECTED_IDENTITY_MISMATCH');
  }
  const plaintext = canonicalServiceAccountPlaintext(serviceAccount, value);
  if (plaintext.length > GOOGLE_SERVICE_ACCOUNT_MAX_PLAINTEXT_BYTES) {
    plaintext.fill(0);
    throw new Error('GOOGLE_SERVICE_ACCOUNT_DOCUMENT_TOO_LARGE');
  }
  const iv = options.iv || randomBytes(12);
  if (!Buffer.isBuffer(iv) || iv.length !== 12) {
    plaintext.fill(0);
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_IV_INVALID');
  }
  const aad = Buffer.from(canonicalJson({ binding: expectedBinding, created_at: createdAt }));
  const cipher = createCipheriv('aes-256-gcm', wrapKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  plaintext.fill(0);
  const envelope = Object.freeze({
    format: GOOGLE_SERVICE_ACCOUNT_BLOB_FORMAT,
    algorithm: ALGORITHM,
    created_at: createdAt,
    binding: expectedBinding,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  });
  if (Buffer.byteLength(JSON.stringify(envelope), 'utf8') > GOOGLE_SERVICE_ACCOUNT_MAX_BLOB_BYTES) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_TOO_LARGE');
  }
  return envelope;
}

export function decryptGoogleServiceAccountCredential(value, wrapKey, expectedBinding) {
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== 32) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_WRAP_KEY_INVALID');
  }
  const text = typeof value === 'string' ? value : JSON.stringify(value || null);
  if (Buffer.byteLength(text, 'utf8') > GOOGLE_SERVICE_ACCOUNT_MAX_BLOB_BYTES) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_TOO_LARGE');
  }
  let envelope;
  try { envelope = JSON.parse(text); }
  catch { throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_JSON_INVALID'); }
  if (!exactKeys(envelope, ENVELOPE_KEYS)
    || envelope.format !== GOOGLE_SERVICE_ACCOUNT_BLOB_FORMAT
    || envelope.algorithm !== ALGORITHM) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_SCHEMA_INVALID');
  }
  if (!exactKeys(envelope.binding, BINDING_KEYS) || !equalJson(envelope.binding, expectedBinding)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_BINDING_MISMATCH');
  }
  assertIsoTimestamp(envelope.created_at);
  const iv = decodeCanonicalBase64(envelope.iv, 'GOOGLE_SERVICE_ACCOUNT_BLOB_IV_INVALID');
  const tag = decodeCanonicalBase64(envelope.tag, 'GOOGLE_SERVICE_ACCOUNT_BLOB_TAG_INVALID');
  const ciphertext = decodeCanonicalBase64(envelope.ciphertext, 'GOOGLE_SERVICE_ACCOUNT_BLOB_CIPHERTEXT_INVALID');
  if (iv.length !== 12) throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_IV_INVALID');
  if (tag.length !== 16) throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_TAG_INVALID');
  if (ciphertext.length === 0 || ciphertext.length > GOOGLE_SERVICE_ACCOUNT_MAX_PLAINTEXT_BYTES) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_CIPHERTEXT_INVALID');
  }

  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', wrapKey, iv);
    decipher.setAAD(Buffer.from(canonicalJson({
      binding: expectedBinding,
      created_at: envelope.created_at
    })));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_DECRYPT_FAILED');
  }
  try {
    const serviceAccount = validateGoogleServiceAccountDocument(plaintext);
    if (serviceAccount.clientEmail.toLowerCase() !== expectedBinding.service_account_client_email) {
      throw new Error('GOOGLE_SERVICE_ACCOUNT_EXPECTED_IDENTITY_MISMATCH');
    }
    return serviceAccount;
  } finally {
    plaintext.fill(0);
  }
}

function expectedBlobMetadata(binding) {
  return Object.freeze({
    format: GOOGLE_SERVICE_ACCOUNT_BLOB_FORMAT,
    keyId: binding.wrap_key_id,
    siteId: binding.netlify_site_id,
    projectRef: binding.supabase_project_ref,
    deploymentId: binding.deployment_id,
    environment: binding.environment,
    serviceAccountEmail: binding.service_account_client_email
  });
}

function assertBlobMetadata(value, binding) {
  const expected = expectedBlobMetadata(binding);
  if (!exactKeys(value, Object.keys(expected).sort()) || !equalJson(value, expected)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_METADATA_MISMATCH');
  }
}

export async function resolveGoogleServiceAccountCredential({
  environment,
  deploymentId,
  supabaseProjectRef,
  siteId,
  siteOrigin,
  wrapKeyId,
  wrapKeyValue,
  expectedServiceAccountEmail,
  directJsonValue = '',
  allowRestoreTestDirectJson = false,
  storeFactory = getStore
}) {
  const normalizedEnvironment = String(environment || '').trim().toLowerCase();
  const normalizedExpectedEmail = normalizeExpectedServiceAccountEmail(expectedServiceAccountEmail);
  if (normalizedEnvironment === 'restore-test') {
    if (allowRestoreTestDirectJson !== true || !directJsonValue) {
      throw new Error('GOOGLE_SERVICE_ACCOUNT_RESTORE_TEST_DIRECT_JSON_REQUIRED');
    }
    const serviceAccount = validateGoogleServiceAccountDocument(directJsonValue);
    if (serviceAccount.clientEmail.toLowerCase() !== normalizedExpectedEmail) {
      throw new Error('GOOGLE_SERVICE_ACCOUNT_EXPECTED_IDENTITY_MISMATCH');
    }
    return Object.freeze({
      serviceAccount,
      source: 'restore-test-direct',
      keyId: ''
    });
  }
  if (!['staging', 'production'].includes(normalizedEnvironment)) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_ENVIRONMENT_INVALID');
  }
  if (directJsonValue) throw new Error('GOOGLE_SERVICE_ACCOUNT_DIRECT_ENV_FORBIDDEN');
  const binding = createGoogleServiceAccountBinding({
    siteId,
    siteOrigin,
    supabaseProjectRef,
    deploymentId,
    environment: normalizedEnvironment,
    wrapKeyId,
    expectedServiceAccountEmail: normalizedExpectedEmail
  });
  const wrapKey = parseGoogleServiceAccountWrapKey(wrapKeyValue);
  const blobKey = googleServiceAccountBlobKey(binding.wrap_key_id);
  let stored;
  try {
    const store = storeFactory({ name: GOOGLE_SERVICE_ACCOUNT_BLOB_STORE, consistency: 'strong' });
    stored = await store.getWithMetadata(blobKey, { type: 'text', consistency: 'strong' });
  } catch {
    wrapKey.fill(0);
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_READ_FAILED');
  }
  if (!stored || typeof stored.data !== 'string') {
    wrapKey.fill(0);
    throw new Error('GOOGLE_SERVICE_ACCOUNT_BLOB_MISSING');
  }
  try {
    assertBlobMetadata(stored.metadata, binding);
    return Object.freeze({
      serviceAccount: decryptGoogleServiceAccountCredential(stored.data, wrapKey, binding),
      source: 'netlify-blob',
      keyId: binding.wrap_key_id
    });
  } finally {
    wrapKey.fill(0);
  }
}

export function googleServiceAccountBlobMetadata(binding) {
  return expectedBlobMetadata(binding);
}
