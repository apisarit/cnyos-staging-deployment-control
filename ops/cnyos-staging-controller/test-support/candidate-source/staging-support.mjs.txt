import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateTenantConfig } from './generate-tenant-config.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const stagingMarker = /(?:^|[-_.])(staging|stage|nonprod|test)(?:$|[-_.])/i;
const emailDomain = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export const STAGING_ROLES = Object.freeze([
  'practitioner',
  'doctor',
  'reception',
  'pharmacy',
  'production',
  'inventory',
  'quality',
  'billing',
  'admin',
  'super_admin',
  'viewer'
]);

export const DATABASE_CAPABILITIES = Object.freeze([
  'governance',
  'patient_read',
  'patient_registry',
  'clinical',
  'pharmacy',
  'product_read',
  'product_write',
  'inventory',
  'production_read',
  'production',
  'quality',
  'billing'
]);

const granted = (...capabilities) => Object.freeze(capabilities);
export const EXPECTED_DATABASE_CAPABILITIES = Object.freeze({
  practitioner: granted('patient_read', 'patient_registry', 'clinical', 'product_read'),
  doctor: granted('patient_read', 'patient_registry', 'clinical', 'product_read'),
  reception: granted('patient_read', 'patient_registry'),
  pharmacy: granted('patient_read', 'pharmacy', 'product_read', 'product_write', 'inventory'),
  production: granted('product_read', 'product_write', 'inventory', 'production_read', 'production'),
  inventory: granted('product_read', 'product_write', 'inventory', 'production_read', 'production'),
  quality: granted('product_read', 'production_read', 'quality'),
  billing: granted('patient_read', 'billing'),
  admin: granted('governance'),
  super_admin: granted(...DATABASE_CAPABILITIES),
  viewer: granted()
});

export const WORKSPACE_ROUTES = Object.freeze({
  operations: '/',
  appointments: '/appointments.html',
  checkin: '/check-in.html',
  foundation: '/foundation.html',
  clinical: '/clinical-v3.html',
  outcomes: '/outcomes.html',
  pharmacy: '/pharmacy.html',
  production: '/production.html',
  quality: '/quality.html',
  admin: '/admin.html'
});

const workspaces = (...keys) => Object.freeze(['operations', ...keys]);
export const EXPECTED_WORKSPACES = Object.freeze({
  practitioner: workspaces('appointments', 'checkin', 'foundation', 'clinical', 'outcomes'),
  doctor: workspaces('appointments', 'checkin', 'foundation', 'clinical', 'outcomes'),
  reception: workspaces('appointments', 'checkin'),
  pharmacy: workspaces('foundation', 'pharmacy'),
  production: workspaces('foundation', 'production'),
  inventory: workspaces('foundation', 'production'),
  quality: workspaces('quality'),
  billing: workspaces(),
  admin: workspaces('admin'),
  super_admin: Object.freeze(Object.keys(WORKSPACE_ROUTES)),
  viewer: workspaces()
});

function readJson(target) {
  return JSON.parse(fs.readFileSync(target, 'utf8'));
}

function origin(value, field) {
  let parsed;
  try { parsed = new URL(String(value || '').trim()); } catch { throw new Error(`${field} must be a valid HTTPS origin`); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error(`${field} must be a credential-free HTTPS origin`);
  }
  if ((parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    throw new Error(`${field} must not include a path, query or fragment`);
  }
  return parsed.origin;
}

function sameOrigin(left, right) {
  return new URL(left).origin.toLowerCase() === new URL(right).origin.toLowerCase();
}

export function requiredEnv(env, key, { min = 1, max = 4096 } = {}) {
  const value = String(env[key] || '').trim();
  if (value.length < min || value.length > max) throw new Error(`${key} is required`);
  return value;
}

export function loadStagingTarget({ env = process.env, cwd = root } = {}) {
  if (env.CLINICAL_OS_STAGING_ACK !== 'STAGING_ONLY') {
    throw new Error('CLINICAL_OS_STAGING_ACK=STAGING_ONLY is required');
  }
  if (!env.CLINICAL_OS_STAGING_CONFIG_JSON && !env.CLINICAL_OS_STAGING_CONFIG_PATH) {
    throw new Error('An explicit CLINICAL_OS_STAGING_CONFIG_JSON or CLINICAL_OS_STAGING_CONFIG_PATH is required');
  }
  if (!env.CLINICAL_OS_PRODUCTION_CONFIG_JSON && !env.CLINICAL_OS_PRODUCTION_CONFIG_PATH) {
    throw new Error('An explicit Production config denylist is required for staging verification');
  }

  const input = env.CLINICAL_OS_STAGING_CONFIG_JSON
    ? JSON.parse(env.CLINICAL_OS_STAGING_CONFIG_JSON)
    : readJson(path.resolve(cwd, env.CLINICAL_OS_STAGING_CONFIG_PATH));
  const config = validateTenantConfig(input);
  const productionInput = env.CLINICAL_OS_PRODUCTION_CONFIG_JSON
    ? JSON.parse(env.CLINICAL_OS_PRODUCTION_CONFIG_JSON)
    : readJson(path.resolve(cwd, env.CLINICAL_OS_PRODUCTION_CONFIG_PATH));
  const production = validateTenantConfig(productionInput);
  const siteUrl = origin(requiredEnv(env, 'STAGING_SITE_URL', { max: 240 }), 'STAGING_SITE_URL');

  if (!stagingMarker.test(config.deploymentId)) {
    throw new Error('The staging deploymentId must contain staging, stage, nonprod or test');
  }
  if (sameOrigin(config.database.url, production.database.url)) {
    throw new Error('Staging database resolves to the Production Supabase project');
  }
  if (sameOrigin(siteUrl, production.auth.redirectOrigin)) {
    throw new Error('Staging site resolves to the Production site');
  }
  if (origin(config.auth.redirectOrigin, 'auth.redirectOrigin') !== siteUrl) {
    throw new Error('Staging auth.redirectOrigin must exactly match STAGING_SITE_URL');
  }
  if (config.tenant.expectedClinicCode === production.tenant.expectedClinicCode) {
    throw new Error('Staging clinic code must differ from the Production clinic code');
  }
  if (config.tenant.expectedClinicId === production.tenant.expectedClinicId) {
    throw new Error('Staging clinic UUID must differ from the Production clinic UUID');
  }
  if (config.identity.qrIssuer === production.identity.qrIssuer) {
    throw new Error('Staging QR issuer must differ from the Production issuer');
  }

  const projectRef = new URL(config.database.url).hostname.split('.')[0];
  if (!projectRef || projectRef === new URL(production.database.url).hostname.split('.')[0]) {
    throw new Error('A distinct staging Supabase project is required');
  }

  return Object.freeze({ config, production, siteUrl, projectRef });
}

export function loadStagingCredentials(env = process.env) {
  const serviceRoleKey = requiredEnv(env, 'STAGING_SUPABASE_SERVICE_ROLE_KEY', { min: 20, max: 4096 });
  const password = requiredEnv(env, 'STAGING_TEST_PASSWORD', { min: 16, max: 256 });
  const domain = requiredEnv(env, 'STAGING_TEST_EMAIL_DOMAIN', { min: 3, max: 253 }).toLowerCase();
  if (!emailDomain.test(domain)) throw new Error('STAGING_TEST_EMAIL_DOMAIN must be a valid domain');
  const prefix = String(env.STAGING_TEST_EMAIL_PREFIX || 'clinical-os-e2e').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{2,39}$/.test(prefix)) {
    throw new Error('STAGING_TEST_EMAIL_PREFIX must be 3-40 lowercase letters, digits or hyphens');
  }
  return Object.freeze({ serviceRoleKey, password, domain, prefix });
}

export function stagingIdentity(role, env = process.env) {
  if (!STAGING_ROLES.includes(role)) throw new Error(`Unknown staging role: ${role}`);
  const { domain, prefix } = loadStagingCredentials(env);
  return Object.freeze({
    role,
    email: `${prefix}-${role.replaceAll('_', '-')}@${domain}`,
    fullName: `Synthetic E2E ${role}`,
    clinicRole: ['admin', 'super_admin'].includes(role) ? 'viewer' : role,
    profileRole: ['admin', 'super_admin'].includes(role) ? 'viewer' : role,
    systemRole: role === 'super_admin' ? 'super_admin' : role === 'admin' ? 'admin' : 'staff',
    effectiveRole: role
  });
}

export async function requestJson(url, {
  key,
  bearer = key,
  method = 'GET',
  body,
  headers = {},
  timeoutMs = 30000,
  expected = null
} = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, {
      method,
      signal: controller.signal,
      headers: {
        apikey: key,
        Authorization: `Bearer ${bearer}`,
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...headers
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
  } finally {
    clearTimeout(timer);
  }
  const raw = await response.text();
  let data = null;
  if (raw) {
    try { data = JSON.parse(raw); } catch { data = raw; }
  }
  const accepted = expected ? expected.includes(response.status) : response.ok;
  if (!accepted) {
    const detail = typeof data === 'string' ? data : data?.message || data?.error_description || data?.error || JSON.stringify(data);
    const error = new Error(`HTTP ${response.status}: ${String(detail || 'request failed').slice(0, 600)}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

export function supabaseUrl(target, resource) {
  return `${target.config.database.url.replace(/\/$/, '')}${resource}`;
}

export async function signInStagingRole(target, role, env = process.env) {
  const identity = stagingIdentity(role, env);
  const credentials = loadStagingCredentials(env);
  const session = await requestJson(supabaseUrl(target, '/auth/v1/token?grant_type=password'), {
    key: target.config.database.publishableKey,
    bearer: target.config.database.publishableKey,
    method: 'POST',
    body: { email: identity.email, password: credentials.password }
  });
  if (!session?.access_token || !session?.refresh_token || !session?.user?.id) {
    throw new Error(`Staging sign-in did not return a complete session for ${role}`);
  }
  return Object.freeze({ identity, session });
}

export async function rpc(target, token, name, body = {}) {
  return requestJson(supabaseUrl(target, `/rest/v1/rpc/${encodeURIComponent(name)}`), {
    key: target.config.database.publishableKey,
    bearer: token,
    method: 'POST',
    body
  });
}

export function sourceCommit(env = process.env) {
  if (env.GITHUB_SHA) return env.GITHUB_SHA;
  try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
}

export function evidenceDirectory(env = process.env) {
  const directory = path.resolve(root, env.STAGING_EVIDENCE_DIR || 'artifacts/staging-e2e');
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

export function writeEvidence(name, payload, env = process.env) {
  const directory = evidenceDirectory(env);
  const target = path.join(directory, name);
  fs.writeFileSync(target, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  return target;
}
