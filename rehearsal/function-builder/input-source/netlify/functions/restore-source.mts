import {
  assertRestoreSourceApiToken,
  assertRestoreSourceProject,
  assertRestoreSourceRuntime,
  extractRestoreSourceApiToken,
  normalizeExactRestoreSource,
  normalizeRestoreClinicCodes,
  normalizeRestoreEnvironment,
  normalizeRestoreRootFolderId,
  normalizeRestoreSourceRequest,
  RESTORE_OBJECT_DOMAINS,
  restoreSourcePublicError
} from './_shared/restore-source.mjs';

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
  return String(Netlify.env.get(name) || '').trim();
}

export function configuration() {
  if (env('RESTORE_SOURCE_API_ENABLED') !== 'true') {
    throw new Error('RESTORE_SOURCE_API_DISABLED');
  }
  const project = assertRestoreSourceProject(
    env('SUPABASE_URL'),
    env('BACKUP_EXPECTED_SUPABASE_PROJECT_REF')
  );
  const environment = normalizeRestoreEnvironment(env('BACKUP_ENVIRONMENT'));
  const deploymentId = env('BACKUP_DEPLOYMENT_ID') || env('SITE_NAME');
  const stagingMarker = /(?:^|[-_.])(staging|stage|nonprod|test)(?:$|[-_.])/i;
  if (!deploymentId
      || (environment === 'staging' && !stagingMarker.test(deploymentId))
      || (environment === 'production' && stagingMarker.test(deploymentId))) {
    throw new Error('RESTORE_SOURCE_CONFIGURATION_INVALID');
  }
  let productionProjectRef = '';
  if (environment === 'staging') {
    let productionProject;
    try {
      productionProject = assertRestoreSourceProject(
        env('BACKUP_PRODUCTION_SUPABASE_URL'),
        env('RESTORE_SOURCE_EXPECTED_PRODUCTION_PROJECT_REF')
      );
    } catch {
      throw new Error('RESTORE_SOURCE_PRODUCTION_DENYLIST_INVALID');
    }
    if (productionProject.url === project.url) {
      throw new Error('RESTORE_SOURCE_PRODUCTION_TARGET_DENIED');
    }
    productionProjectRef = productionProject.projectRef;
  }
  const serviceRoleKey = env('SUPABASE_SERVICE_ROLE_KEY');
  const apiTokenSha256 = env('RESTORE_SOURCE_API_TOKEN_SHA256').toLowerCase();
  if (serviceRoleKey.length < 32
      || serviceRoleKey.length > 8192
      || !/^[0-9a-f]{64}$/.test(apiTokenSha256)) {
    throw new Error('RESTORE_SOURCE_CONFIGURATION_INVALID');
  }
  return Object.freeze({
    supabaseUrl: project.url,
    projectRef: project.projectRef,
    serviceRoleKey,
    environment,
    deploymentId,
    productionProjectRef,
    expectedNetlifySiteId: env('BACKUP_EXPECTED_NETLIFY_SITE_ID'),
    expectedSiteOrigin: env('BACKUP_EXPECTED_SITE_ORIGIN'),
    rootFolderId: normalizeRestoreRootFolderId(env('GOOGLE_DRIVE_EXPECTED_ROOT_FOLDER_ID')),
    clinicCodes: normalizeRestoreClinicCodes(env('RESTORE_SOURCE_CLINIC_CODES')),
    apiTokenSha256
  });
}

async function readRequest(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(request.headers.get('content-type') || ''))) {
    throw new Error('RESTORE_SOURCE_REQUEST_CONTENT_TYPE_INVALID');
  }
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > 4096) {
    throw new Error('RESTORE_SOURCE_REQUEST_TOO_LARGE');
  }
  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > 4096) throw new Error('RESTORE_SOURCE_REQUEST_TOO_LARGE');
  try { return normalizeRestoreSourceRequest(JSON.parse(text || '{}')); }
  catch (error) {
    if (String(error?.message || '').startsWith('RESTORE_SOURCE_')) throw error;
    throw new Error('RESTORE_SOURCE_REQUEST_JSON_INVALID');
  }
}

async function exactSource(config, input, fetchImpl = fetch) {
  const response = await fetchImpl(`${config.supabaseUrl}/rest/v1/rpc/get_exact_backup_restore_source`, {
    method: 'POST',
    headers: {
      apikey: config.serviceRoleKey,
      Authorization: `Bearer ${config.serviceRoleKey}`,
      Accept: 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      p_clinic_code: input.clinicCode,
      p_scheduled_for: input.slot,
      p_environment: config.environment
    }),
    redirect: 'error',
    signal: AbortSignal.timeout(8000)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const candidate = String(payload?.message || '');
    throw new Error(/^RESTORE_SOURCE_[A-Z0-9_]{3,100}$/.test(candidate)
      ? candidate
      : 'RESTORE_SOURCE_DATABASE_REQUEST_FAILED');
  }
  return normalizeExactRestoreSource(payload, {
    clinicCode: input.clinicCode,
    environment: config.environment,
    slot: input.slot,
    expectedRootFolderId: config.rootFolderId
  });
}

function publicSource(source) {
  const objects = Object.fromEntries(RESTORE_OBJECT_DOMAINS.map(domain => {
    const item = source.objects[domain];
    return [domain, {
      domain,
      environment: source.environment,
      destination_folder_id: item.destinationFolderId,
      drive_root_folder_id: item.driveRootFolderId,
      drive_assignment_version: item.driveAssignmentVersion,
      file_id: item.fileId,
      file_name: item.fileName,
      ...(domain === 'manifest' ? {} : {
        plaintext_bytes: item.plaintextBytes,
        encrypted_bytes: item.encryptedBytes,
        plaintext_sha256: item.plaintextSha256,
        ciphertext_sha256: item.ciphertextSha256,
        key_id: item.keyId,
        row_counts: item.rowCounts
      })
    }];
  }));
  return Object.freeze({
    format: source.format,
    run_id: source.runId,
    clinic_id: source.clinicId,
    clinic_code: source.clinicCode,
    environment: source.environment,
    slot: source.slot,
    completed_at: source.completedAt,
    drive_assignment: {
      version: source.assignmentVersion,
      root_folder_id: source.rootFolderId,
      folder_ids: source.folders
    },
    objects
  });
}

export default async (request, context) => {
  const requestId = context.requestId || crypto.randomUUID();
  if (request.method !== 'POST') return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);

  try {
    const config = configuration();
    assertRestoreSourceRuntime(
      request,
      context,
      config.expectedNetlifySiteId,
      config.expectedSiteOrigin
    );
    assertRestoreSourceApiToken(
      extractRestoreSourceApiToken(request),
      config.apiTokenSha256
    );
    const input = await readRequest(request);
    if (!config.clinicCodes.includes(input.clinicCode)) {
      throw new Error('RESTORE_SOURCE_CLINIC_NOT_ALLOWED');
    }
    const source = await exactSource(config, input);
    return json({ ok: true, source: publicSource(source) });
  } catch (error) {
    const safe = restoreSourcePublicError(error);
    console.error('exact restore source request failed', { requestId, code: safe.code });
    return json({ ok: false, code: safe.code }, safe.status);
  }
};

export const config = {
  path: '/api/restore-source',
  method: ['POST']
};
