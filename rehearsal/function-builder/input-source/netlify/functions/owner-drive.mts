import {
  allowedOwnerOrigin,
  assertOwnerProject,
  assertOwnerRuntime,
  extractBearerToken,
  normalizeOwnerClinicCodes,
  normalizeOwnerEmails,
  ownerPublicError,
  readOwnerJson,
  supabaseOwnerRequest,
  validateOwnerUserWithGoogleProof
} from './_shared/owner-control.mjs';
import {
  fetchGoogleAccessToken,
  parseBackupEnvironment,
  parseEncryptionKey
} from './_shared/database-backup.mjs';
import {
  googleServiceAccountWrapKeyReused,
  resolveGoogleServiceAccountCredential
} from './_shared/google-service-account-credential.mjs';
import {
  inspectDriveFolder,
  normalizeDriveFolderId,
  normalizeOwnerDriveRequest,
  OWNER_DRIVE_DOMAINS,
  ownerDrivePublicError,
  sanitizeOwnerDriveAssignment
} from './_shared/owner-drive.mjs';

const responseHeaders = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  'Content-Type': 'application/json; charset=utf-8',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
});

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: responseHeaders });
}

function readEnv(name) {
  const netlify = Reflect.get(globalThis, 'Netlify');
  const value = netlify?.env?.get?.(name);
  return String(value || process.env[name] || '').trim();
}

function configuration(getEnv = readEnv) {
  if (getEnv('CNYOS_OWNER_CONTROL_ENABLED') !== 'true') {
    throw new Error('CNYOS_OWNER_CONTROL_DISABLED');
  }
  if (getEnv('CNYOS_OWNER_DRIVE_ENABLED') !== 'true') {
    throw new Error('CNYOS_OWNER_DRIVE_DISABLED');
  }
  const supabaseUrl = getEnv('SUPABASE_URL');
  const projectRef = assertOwnerProject(supabaseUrl, getEnv('CNYOS_OWNER_EXPECTED_PROJECT_REF'));
  if (getEnv('BACKUP_EXPECTED_SUPABASE_PROJECT_REF') !== projectRef) {
    throw new Error('CNYOS_OWNER_DRIVE_PROJECT_GUARD_MISMATCH');
  }
  let expectedRootFolderId;
  try { expectedRootFolderId = normalizeDriveFolderId(getEnv('GOOGLE_DRIVE_EXPECTED_ROOT_FOLDER_ID')); }
  catch { throw new Error('CNYOS_OWNER_DRIVE_ROOT_FOLDER_INVALID'); }

  let environment;
  try { environment = parseBackupEnvironment(getEnv('BACKUP_ENVIRONMENT')); }
  catch { throw new Error('CNYOS_OWNER_DRIVE_ENVIRONMENT_INVALID'); }
  if (!['staging', 'production'].includes(environment)) {
    throw new Error('CNYOS_OWNER_DRIVE_ENVIRONMENT_INVALID');
  }
  const deploymentId = getEnv('BACKUP_DEPLOYMENT_ID') || getEnv('SITE_NAME');
  const stagingMarker = /(?:^|[-_.])(staging|stage|nonprod|test)(?:$|[-_.])/i;
  if (!deploymentId
    || (environment === 'staging' && !stagingMarker.test(deploymentId))
    || (environment === 'production' && stagingMarker.test(deploymentId))) {
    throw new Error('CNYOS_OWNER_DRIVE_DEPLOYMENT_INVALID');
  }
  const productionSupabaseUrl = getEnv('BACKUP_PRODUCTION_SUPABASE_URL');
  if (environment === 'staging') {
    if (!productionSupabaseUrl) {
      throw new Error('CNYOS_OWNER_DRIVE_PRODUCTION_DENYLIST_REQUIRED');
    }
    let production;
    try { production = new URL(productionSupabaseUrl); }
    catch { throw new Error('CNYOS_OWNER_DRIVE_PRODUCTION_DENYLIST_INVALID'); }
    if (production.protocol !== 'https:'
      || !/^[a-z]{20}\.supabase\.co$/.test(production.hostname)
      || production.pathname !== '/'
      || production.search
      || production.hash
      || production.username
      || production.password) {
      throw new Error('CNYOS_OWNER_DRIVE_PRODUCTION_DENYLIST_INVALID');
    }
    if (production.origin === new URL(supabaseUrl).origin) {
      throw new Error('CNYOS_OWNER_DRIVE_PRODUCTION_TARGET_DENIED');
    }
  }

  const expectedNetlifySiteId = getEnv('CNYOS_OWNER_EXPECTED_NETLIFY_SITE_ID').toLowerCase();
  const expectedSiteOrigin = getEnv('CNYOS_OWNER_EXPECTED_SITE_ORIGIN').toLowerCase();
  if (getEnv('BACKUP_EXPECTED_NETLIFY_SITE_ID').toLowerCase() !== expectedNetlifySiteId
    || getEnv('BACKUP_EXPECTED_SITE_ORIGIN').toLowerCase() !== expectedSiteOrigin) {
    throw new Error('CNYOS_OWNER_DRIVE_SITE_GUARD_MISMATCH');
  }
  const credentialWrapKeyValue = getEnv('GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_BASE64');
  const expectedServiceAccountEmail = getEnv('GOOGLE_DRIVE_EXPECTED_SERVICE_ACCOUNT_EMAIL').toLowerCase();
  if (!credentialWrapKeyValue
    || !getEnv('GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_ID')
    || !expectedServiceAccountEmail) {
    throw new Error('CNYOS_OWNER_DRIVE_CREDENTIAL_UNAVAILABLE');
  }
  const backupEncryptionKeyValue = getEnv('BACKUP_ENCRYPTION_KEY_BASE64');
  if (googleServiceAccountWrapKeyReused(credentialWrapKeyValue, backupEncryptionKeyValue)
    || googleServiceAccountWrapKeyReused(credentialWrapKeyValue, getEnv('BACKUP_INTERNAL_DISPATCH_SECRET'))) {
    throw new Error('CNYOS_OWNER_DRIVE_CREDENTIAL_KEY_REUSE');
  }
  if (backupEncryptionKeyValue) {
    try {
      const backupEncryptionKey = parseEncryptionKey(backupEncryptionKeyValue);
      backupEncryptionKey.fill(0);
    } catch {
      throw new Error('CNYOS_OWNER_DRIVE_CREDENTIAL_KEY_INVALID');
    }
  }

  return Object.freeze({
    supabaseUrl,
    projectRef,
    serviceRoleKey: getEnv('SUPABASE_SERVICE_ROLE_KEY'),
    ownerEmails: normalizeOwnerEmails(getEnv('CNYOS_OWNER_EMAILS')),
    clinicCodes: normalizeOwnerClinicCodes(getEnv('CNYOS_OWNER_CLINIC_CODES')),
    environment,
    deploymentId,
    expectedRootFolderId,
    expectedNetlifySiteId,
    expectedSiteOrigin,
    credentialWrapKeyId: getEnv('GOOGLE_DRIVE_SERVICE_ACCOUNT_WRAP_KEY_ID'),
    credentialWrapKeyValue,
    expectedServiceAccountEmail,
    serviceAccountDirectValue: getEnv('GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON')
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

async function listAssignments(config, ownerRequest = supabaseOwnerRequest) {
  const rows = await ownerRequest({
    url: config.supabaseUrl,
    serviceRoleKey: config.serviceRoleKey,
    resource: '/rest/v1/rpc/list_owner_drive_assignments',
    method: 'POST',
    body: {}
  });
  if (!Array.isArray(rows)) return [];
  return rows
    .map(sanitizeOwnerDriveAssignment)
    .filter(Boolean)
    .filter(row => row.environment === config.environment && config.clinicCodes.includes(row.clinic_code));
}

async function serviceAccountAccessToken(serviceAccount, fetchAccessToken = fetchGoogleAccessToken) {
  try { return await fetchAccessToken(serviceAccount); }
  catch { throw new Error('CNYOS_OWNER_DRIVE_AUTH_FAILED'); }
}

async function resolveServiceAccount(config, runtime, credentialResolver = resolveGoogleServiceAccountCredential) {
  try {
    return (await credentialResolver({
      environment: config.environment,
      deploymentId: config.deploymentId,
      supabaseProjectRef: config.projectRef,
      siteId: runtime.siteId,
      siteOrigin: runtime.siteOrigin,
      wrapKeyId: config.credentialWrapKeyId,
      wrapKeyValue: config.credentialWrapKeyValue,
      expectedServiceAccountEmail: config.expectedServiceAccountEmail,
      directJsonValue: config.serviceAccountDirectValue
    })).serviceAccount;
  } catch {
    throw new Error('CNYOS_OWNER_DRIVE_CREDENTIAL_UNAVAILABLE');
  }
}

async function inspectAssignedFolders(input, accessToken, expectedRootFolderId, inspectFolder = inspectDriveFolder) {
  return Promise.all(OWNER_DRIVE_DOMAINS.map(async domain => {
    try {
      const folder = await inspectFolder({
        accessToken,
        folderId: input.folders[domain],
        expectedParentId: expectedRootFolderId
      });
      return Object.freeze({ domain, ...folder });
    } catch (error) {
      const candidate = String(error?.message || '');
      const code = /^CNYOS_OWNER_DRIVE_FOLDER_[A-Z0-9_]{3,60}$/.test(candidate)
        ? candidate
        : 'CNYOS_OWNER_DRIVE_FOLDER_ACCESS_FAILED';
      const wrapped = new Error(code);
      Reflect.set(wrapped, 'field', domain);
      throw wrapped;
    }
  }));
}

async function saveAssignment(request, config, owner, serviceAccount, deps = {}) {
  const input = normalizeOwnerDriveRequest(await readOwnerJson(request, 16384));
  if (!config.clinicCodes.includes(input.clinicCode)) throw new Error('CNYOS_OWNER_CLINIC_NOT_ALLOWED');

  const accessToken = await serviceAccountAccessToken(serviceAccount, deps.fetchAccessToken);
  const checkedFolders = await inspectAssignedFolders(
    input,
    accessToken,
    config.expectedRootFolderId,
    deps.inspectFolder
  );
  const databaseResult = await (deps.ownerRequest || supabaseOwnerRequest)({
    url: config.supabaseUrl,
    serviceRoleKey: config.serviceRoleKey,
    resource: '/rest/v1/rpc/set_clinic_drive_assignment',
    method: 'POST',
    body: {
      p_request_id: input.requestId,
      p_clinic_id: input.clinicId,
      p_expected_clinic_code: input.clinicCode,
      p_environment: config.environment,
      p_patients_folder_id: input.folders.patients,
      p_products_folder_id: input.folders.products,
      p_pharmacy_folder_id: input.folders.pharmacy,
      p_transactions_folder_id: input.folders.transactions,
      p_manifests_folder_id: input.folders.manifests,
      p_expected_version: input.expectedVersion,
      p_reason: input.reason,
      p_actor_user_id: owner.id,
      p_actor_email: owner.email
    }
  });
  const assignment = sanitizeOwnerDriveAssignment(databaseResult);
  if (!assignment
    || assignment.clinic_id !== input.clinicId
    || assignment.clinic_code !== input.clinicCode
    || assignment.environment !== config.environment
    || OWNER_DRIVE_DOMAINS.some(domain => assignment[`${domain}_folder_id`] !== input.folders[domain])) {
    throw new Error('CNYOS_OWNER_DRIVE_DATABASE_RESPONSE_INVALID');
  }
  const result = Object.freeze({
    ...assignment,
    changed: databaseResult?.changed === true,
    idempotent: databaseResult?.idempotent === true
  });
  return Object.freeze({ result, checkedFolders });
}

export async function handleOwnerDrive(request, context, deps = {}) {
  const requestId = context.requestId || crypto.randomUUID();
  if (!allowedOwnerOrigin(request)) return json({ ok: false, code: 'CNYOS_OWNER_ORIGIN_DENIED' }, 403);
  if (!['GET', 'POST'].includes(request.method)) return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);

  try {
    const config = configuration(deps.getEnv || readEnv);
    const runtime = assertOwnerRuntime(
      request,
      context,
      config.expectedNetlifySiteId,
      config.expectedSiteOrigin
    );
    const owner = await authenticateOwner(request, config, deps.ownerRequest, deps.googleFetch);
    const serviceAccount = await resolveServiceAccount(config, runtime, deps.credentialResolver);
    if (request.method === 'GET') {
      return json({
        ok: true,
        environment: config.environment,
        deploymentId: config.deploymentId,
        projectRef: config.projectRef,
        serviceAccountEmail: serviceAccount.clientEmail,
        rootFolderId: config.expectedRootFolderId,
        assignments: await listAssignments(config, deps.ownerRequest)
      });
    }
    const { result, checkedFolders } = await saveAssignment(
      request,
      config,
      owner,
      serviceAccount,
      deps
    );
    return json({ ok: true, environment: config.environment, result, checkedFolders });
  } catch (error) {
    const driveError = ownerDrivePublicError(error);
    const safe = driveError.status === null ? ownerPublicError(error) : driveError;
    const field = OWNER_DRIVE_DOMAINS.includes(Reflect.get(error || {}, 'field'))
      ? Reflect.get(error, 'field')
      : undefined;
    console.error('CNYOS owner Drive assignment request failed', {
      requestId,
      code: safe.code,
      ...(field ? { field } : {})
    });
    return json({ ok: false, code: safe.code, ...(field ? { field } : {}) }, safe.status);
  }
}

export default async (request, context) => handleOwnerDrive(request, context);

export const config = {
  path: '/api/owner-drive',
  method: ['GET', 'POST']
};
