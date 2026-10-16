import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  EXACT_STAGING_FUNCTION_ENVIRONMENT,
  EXACT_STAGING_PRODUCTION_DENYLIST,
  EXACT_STAGING_SYNTHETIC_HN_PATTERN,
  EXACT_STAGING_TARGET,
  assertSecretFreeEvidence,
  loadExactStagingConfig,
  parseNetlifyDeployReceipt,
  sha256,
  writeFresh0600
} from './exact-staging-release.mjs';

const DEPLOY_ID = /^[0-9a-f]{24}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TERMINAL_DEPLOY_FAILURE_STATES = new Set(['error', 'failed', 'canceled', 'cancelled']);
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const RECONCILIATION_ATTEMPTS = 6;
const RECONCILIATION_DELAY_MS = 5_000;
const CONTROLLER_REPOSITORY = 'apisarit/cnyos-staging-deployment-control';
const CONTROLLER_WORKFLOW_PATH = '.github/workflows/cnyos-exact-staging-deploy-uat.yml';
const ARTIFACT_DIGEST_KEYS = Object.freeze([
  'deployManifestSha256', 'runtimeManifestSha256',
  'functionManifestSha256', 'functionTreeSha256',
  'databaseManifestSha256', 'databaseTreeSha256'
]);
const RECONCILIATION_RESULTS = Object.freeze({
  PASS: Object.freeze(['APPLIED_VERIFIED']),
  FAIL: Object.freeze(['ATTEMPT_READY_NOT_CANONICAL', 'ATTEMPT_TERMINAL_FAILURE']),
  UNCERTAIN: Object.freeze([
    'CANONICAL_STATE_UNKNOWN', 'CANONICAL_DEPLOY_DRIFT',
    'ATTEMPT_DEPLOY_ID_UNKNOWN', 'ATTEMPT_DEPLOY_STATE_UNKNOWN'
  ])
});
const EVIDENCE_MANIFEST_FILES = Object.freeze([
  'candidate-binding.json', 'rollback-baseline.json', 'publish-intent.json',
  'publish-attempt.json', 'publish-reconciliation.json', 'deploy-receipt.json',
  'database-reconciliation.json', 'fixture-evidence.json', 'uat-evidence.json'
]);
const UAT_ROLE_SPECS = Object.freeze({
  reception: Object.freeze(['reception', 'staff', 'reception']),
  source_practitioner: Object.freeze(['practitioner', 'staff', 'practitioner']),
  attending: Object.freeze(['doctor', 'staff', 'doctor']),
  pharmacy_reviewer: Object.freeze(['pharmacy', 'staff', 'pharmacy']),
  pharmacy_dispenser: Object.freeze(['pharmacy', 'staff', 'pharmacy']),
  billing: Object.freeze(['billing', 'staff', 'billing']),
  admin: Object.freeze(['viewer', 'admin', 'admin'])
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function expectedMutationLedger(roleKeys) {
  const records = [];
  const add = (name, authority, resource, statuses = [200]) => {
    records.push({ name, authority, resource, statuses });
  };
  for (const role of roleKeys) {
    add('create_auth_user', 'service_role', '/auth/v1/admin/users', [200, 201]);
    add('upsert_profile', 'service_role', '/rest/v1/profiles', [200, 201]);
    add('insert_clinic_membership', 'service_role', '/rest/v1/clinic_memberships', [200, 201]);
  }
  add('upsert_product_master', 'pharmacy_reviewer',
    '/rest/v1/rpc/upsert_product_master');
  add('set_clinic_product_price', 'billing', '/rest/v1/rpc/set_clinic_product_price');
  add('insert_inventory_lot', 'service_role', '/rest/v1/inventory_lots', [200, 201]);
  add('upsert_patient_registration', 'reception',
    '/rest/v1/rpc/upsert_patient_registration');
  add('create_practitioner_schedule', 'reception',
    '/rest/v1/rpc/create_practitioner_schedule');
  add('book_clinic_appointment', 'reception', '/rest/v1/rpc/book_clinic_appointment');
  add('check_in_clinic_appointment', 'reception',
    '/rest/v1/rpc/check_in_clinic_appointment');
  add('set_clinic_appointment_status', 'source_practitioner',
    '/rest/v1/rpc/set_clinic_appointment_status');
  add('save_ttm_opd_history', 'source_practitioner', '/rest/v1/rpc/save_ttm_opd_history');
  add('save_ttm_opd_history', 'source_practitioner', '/rest/v1/rpc/save_ttm_opd_history');
  add('create_clinical_consult_request', 'source_practitioner',
    '/rest/v1/rpc/create_clinical_consult_request');
  add('transition_clinical_consult_request', 'source_practitioner',
    '/rest/v1/rpc/transition_clinical_consult_request', [400]);
  for (let index = 0; index < 3; index += 1) {
    add('transition_clinical_consult_request', 'attending',
      '/rest/v1/rpc/transition_clinical_consult_request');
  }
  add('create_ipd_admission_request', 'source_practitioner',
    '/rest/v1/rpc/create_ipd_admission_request');
  add('transition_ipd_admission', 'source_practitioner',
    '/rest/v1/rpc/transition_ipd_admission', [400]);
  add('transition_ipd_admission', 'reception', '/rest/v1/rpc/transition_ipd_admission');
  add('transition_ipd_admission', 'attending', '/rest/v1/rpc/transition_ipd_admission');
  for (let index = 0; index < 3; index += 1) {
    add('append_ipd_clinical_entry', 'attending',
      '/rest/v1/rpc/append_ipd_clinical_entry');
  }
  add('transition_ipd_admission', 'attending', '/rest/v1/rpc/transition_ipd_admission');
  add('transition_ipd_admission', 'reception', '/rest/v1/rpc/transition_ipd_admission');
  add('create_atomic_prescription_handoff', 'source_practitioner',
    '/rest/v1/rpc/create_atomic_prescription_handoff');
  add('transition_atomic_prescription_dispensing', 'pharmacy_reviewer',
    '/rest/v1/rpc/transition_atomic_prescription_dispensing');
  add('transition_atomic_prescription_dispensing', 'pharmacy_dispenser',
    '/rest/v1/rpc/transition_atomic_prescription_dispensing');
  add('transition_atomic_prescription_dispensing', 'pharmacy_dispenser',
    '/rest/v1/rpc/transition_atomic_prescription_dispensing');
  add('issue_atomic_dispensing_invoice', 'billing',
    '/rest/v1/rpc/issue_atomic_dispensing_invoice');
  add('record_atomic_invoice_payment', 'billing',
    '/rest/v1/rpc/record_atomic_invoice_payment');
  return records;
}

function exactMutationLedger(value, roleKeys) {
  if (!Array.isArray(value)) return false;
  const expected = expectedMutationLedger(roleKeys);
  const keys = ['authority', 'dispatched', 'name', 'ordinal', 'resource', 'status', 'uncertain'];
  return value.length === expected.length && value.every((record, index) => {
    const wanted = expected[index];
    return plainObject(record) &&
      JSON.stringify(Object.keys(record).sort()) === JSON.stringify(keys) &&
      record.ordinal === index + 1 && record.name === wanted.name &&
      record.authority === wanted.authority && record.resource === wanted.resource &&
      record.dispatched === true && wanted.statuses.includes(record.status) &&
      record.uncertain === false;
  });
}

function required(value, code, maximum = 8192) {
  const result = String(value ?? '').trim();
  if (!result || result.length > maximum) fail(code);
  return result;
}

async function readJson(filename, code, { optional = false } = {}) {
  let bytes;
  try { bytes = await fs.readFile(filename); }
  catch (error) {
    if (optional && error?.code === 'ENOENT') return null;
    fail(code);
  }
  if (bytes.length < 2 || bytes.length > 4 * 1024 * 1024) fail(code);
  try {
    const value = JSON.parse(bytes.toString('utf8'));
    if (!plainObject(value)) fail(code);
    return { value, bytes };
  } catch { fail(code); }
}

function assertFixedTarget(config) {
  if (config.target.netlifySiteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    config.target.origin !== EXACT_STAGING_TARGET.origin ||
    config.target.supabaseProjectRef !== EXACT_STAGING_TARGET.supabaseProjectRef ||
    EXACT_STAGING_PRODUCTION_DENYLIST.netlifySiteIds.includes(config.target.netlifySiteId) ||
    EXACT_STAGING_PRODUCTION_DENYLIST.origins.includes(config.target.origin)) {
    fail('CNYOS_EXACT_STAGING_PUBLISH_TARGET_INVALID');
  }
}

function exactControllerBinding(config, controller) {
  return controller?.repository === CONTROLLER_REPOSITORY &&
    controller?.commit === config.controllerCommit &&
    controller?.workflowPath === CONTROLLER_WORKFLOW_PATH;
}

function exactSourceBinding(config, source) {
  return source?.commit === config.appCommit && source?.tree === config.appTree;
}

function exactTargetBinding(target, { requireClinicalScope = false } = {}) {
  return target?.siteId === EXACT_STAGING_TARGET.netlifySiteId &&
    target?.origin === EXACT_STAGING_TARGET.origin &&
    target?.supabaseProjectRef === EXACT_STAGING_TARGET.supabaseProjectRef &&
    (!requireClinicalScope || (
      target?.deploymentId === EXACT_STAGING_TARGET.deploymentId &&
      target?.clinicId === EXACT_STAGING_TARGET.clinicId
    ));
}

function exactArtifactBinding(left, right) {
  return ARTIFACT_DIGEST_KEYS.every(key =>
    SHA256.test(String(left?.[key] || '')) && left?.[key] === right?.[key]);
}

function validIsoTimestamp(value) {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function validOutputDigest(byteLength, digest) {
  return Number.isInteger(byteLength) && byteLength >= 0 && byteLength <= MAX_OUTPUT_BYTES &&
    (byteLength === 0 ? digest === null : SHA256.test(String(digest || '')));
}

function validAttemptOutcome(attempt) {
  const outcome = attempt?.cliOutcome;
  const exitCode = attempt?.exitCode;
  const outcomeValid = outcome === 'EXIT_ZERO' ? exitCode === 0 :
    outcome === 'EXIT_NONZERO' ? Number.isSafeInteger(exitCode) && exitCode !== 0 :
      ['TIMEOUT', 'SPAWN_FAILED'].includes(outcome) ? exitCode === null : false;
  const signalValid = attempt?.signal === null ||
    (typeof attempt?.signal === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(attempt.signal));
  return outcomeValid && signalValid &&
    validOutputDigest(attempt?.stdoutByteLength, attempt?.stdoutSha256) &&
    validOutputDigest(attempt?.stderrByteLength, attempt?.stderrSha256) &&
    typeof attempt?.rawReceiptCaptured === 'boolean' &&
    validIsoTimestamp(attempt?.startedAt) && validIsoTimestamp(attempt?.completedAt) &&
    Date.parse(attempt.completedAt) >= Date.parse(attempt.startedAt);
}

function assertCandidateBinding(config, binding, baseline) {
  const expectedFunctionNames = Object.keys(EXACT_STAGING_FUNCTION_ENVIRONMENT).sort();
  const expectedFunctionValuesSha256 = sha256(JSON.stringify(
    Object.entries(EXACT_STAGING_FUNCTION_ENVIRONMENT)
      .sort(([left], [right]) => left.localeCompare(right))));
  const observedFunctionNames = binding?.functionEnvironment?.validatedVariableNames;
  const limitsValid = plainObject(binding?.limits) &&
    Object.keys(config.limits).every(key => binding.limits[key] === config.limits[key]) &&
    Object.keys(binding.limits).length === Object.keys(config.limits).length;
  if (binding?.kind !== 'cnyos_exact_staging_candidate_binding' ||
    binding?.schemaVersion !== 1 ||
    binding?.stagingOnly !== true || binding?.productionAuthorized !== false ||
    !exactControllerBinding(config, binding?.controller) ||
    !exactSourceBinding(config, binding?.source) ||
    !exactTargetBinding(binding?.target, { requireClinicalScope: true }) ||
    binding?.rollbackBaselineDeployId !== config.rollbackDeployId ||
    !exactSourceBinding(config, binding?.artifact?.source) ||
    !SHA256.test(String(binding?.artifact?.deployManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.runtimeManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.functionManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.functionTreeSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.databaseManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.databaseTreeSha256 || '')) ||
    !Number.isSafeInteger(binding?.artifact?.runtimeFileCount) ||
    binding.artifact.runtimeFileCount < 1 || binding.artifact.runtimeFileCount > 100_000 ||
    !Number.isSafeInteger(binding?.artifact?.functionFileCount) ||
    binding.artifact.functionFileCount < 1 || binding.artifact.functionFileCount > 100_000 ||
    !Number.isSafeInteger(binding?.artifact?.databaseFileCount) ||
    binding.artifact.databaseFileCount !== 5 ||
    JSON.stringify(observedFunctionNames) !== JSON.stringify(expectedFunctionNames) ||
    binding?.functionEnvironment?.exactValuesSha256 !== expectedFunctionValuesSha256 ||
    binding?.functionEnvironment?.productionDenylistConfirmed !== true ||
    binding?.functionEnvironment?.valuesSerialized !== false || !limitsValid ||
    !validIsoTimestamp(binding?.preparedAt) ||
    baseline?.schemaVersion !== 1 ||
    baseline?.kind !== 'cnyos_exact_staging_rollback_baseline' ||
    baseline?.stagingOnly !== true ||
    baseline?.siteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    baseline?.origin !== EXACT_STAGING_TARGET.origin ||
    baseline?.deployId !== config.rollbackDeployId ||
    baseline?.exactDeployOrigin !==
      `https://${config.rollbackDeployId}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app` ||
    !validIsoTimestamp(baseline?.observedAt) ||
    Date.parse(baseline.observedAt) > Date.parse(binding.preparedAt)) {
    fail('CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  }
}

function assertPublishChain(config, binding, baseline, intentFile, attempt) {
  assertCandidateBinding(config, binding, baseline);
  const intent = intentFile.value;
  const intentHashValid = attempt?.intentSha256 === sha256(intentFile.bytes) ||
    attempt?.intentSha256 === sha256(Buffer.from(JSON.stringify(intent)));
  if (intent?.schemaVersion !== 1 || intent?.kind !== 'cnyos_exact_staging_publish_intent' ||
    intent?.status !== 'READY_FOR_AUTHORIZED_STEP' || intent?.stagingOnly !== true ||
    intent?.productionAuthorized !== false || intent?.automaticRollbackAuthorized !== false ||
    intent?.automaticRollbackAttempted !== false ||
    !exactControllerBinding(config, intent?.controller) ||
    !exactSourceBinding(config, intent?.source) || !exactTargetBinding(intent?.target) ||
    intent?.rollbackBaselineDeployId !== config.rollbackDeployId ||
    !exactArtifactBinding(binding?.artifact, intent?.artifact) ||
    intent?.operation?.publisher !== 'netlify-cli/23.1.2' ||
    intent?.operation?.commandClass !== 'deploy --prod' ||
    intent?.operation?.cliTimeoutSeconds !== 120 ||
    intent?.operation?.processTimeoutSeconds !== 150 ||
    intent?.operation?.retryCount !== 0 ||
    intent?.operation?.canonicalMutationMayBeNonAtomic !== true ||
    intent?.operation?.reconciliationRequired !== true ||
    intent?.run?.runReferenceSha256 !== sha256(config.runReference) ||
    !/^\d{1,30}$/.test(String(intent?.run?.workflowRunId || '')) ||
    !validIsoTimestamp(intent?.createdAt) ||
    attempt?.schemaVersion !== 1 ||
    attempt?.kind !== 'cnyos_exact_staging_publish_attempt' ||
    attempt?.status !== 'UNKNOWN_PENDING_RECONCILIATION' ||
    attempt?.stagingOnly !== true || attempt?.productionAuthorized !== false ||
    !exactControllerBinding(config, attempt?.controller) ||
    !exactSourceBinding(config, attempt?.source) || !exactTargetBinding(attempt?.target) ||
    attempt?.rollbackBaselineDeployId !== config.rollbackDeployId ||
    attempt?.outputSerialized !== false || attempt?.outputSecretBoundaryViolated !== false ||
    attempt?.canonicalDeployAssumed !== false || attempt?.automaticRollbackAttempted !== false ||
    attempt?.retryCount !== 0 || !validAttemptOutcome(attempt) ||
    Date.parse(attempt.startedAt) < Date.parse(intent.createdAt) || !intentHashValid) {
    fail('CNYOS_EXACT_STAGING_PUBLISH_CHAIN_INVALID');
  }
  return intent;
}

export function createExactStagingPublishIntent(config, binding, baseline, {
  now = new Date().toISOString(), workflowRunId = null
} = {}) {
  assertFixedTarget(config);
  assertCandidateBinding(config, binding, baseline);
  return Object.freeze({
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_publish_intent',
    status: 'READY_FOR_AUTHORIZED_STEP',
    stagingOnly: true,
    productionAuthorized: false,
    automaticRollbackAuthorized: false,
    automaticRollbackAttempted: false,
    controller: binding.controller,
    source: Object.freeze({ commit: config.appCommit, tree: config.appTree }),
    target: Object.freeze({
      siteId: EXACT_STAGING_TARGET.netlifySiteId,
      origin: EXACT_STAGING_TARGET.origin,
      supabaseProjectRef: EXACT_STAGING_TARGET.supabaseProjectRef
    }),
    artifact: Object.freeze({
      deployManifestSha256: binding.artifact.deployManifestSha256,
      runtimeManifestSha256: binding.artifact.runtimeManifestSha256,
      functionManifestSha256: binding.artifact.functionManifestSha256,
      functionTreeSha256: binding.artifact.functionTreeSha256,
      databaseManifestSha256: binding.artifact.databaseManifestSha256,
      databaseTreeSha256: binding.artifact.databaseTreeSha256
    }),
    rollbackBaselineDeployId: config.rollbackDeployId,
    operation: Object.freeze({
      publisher: 'netlify-cli/23.1.2',
      commandClass: 'deploy --prod',
      cliTimeoutSeconds: 120,
      processTimeoutSeconds: 150,
      retryCount: 0,
      canonicalMutationMayBeNonAtomic: true,
      reconciliationRequired: true
    }),
    run: Object.freeze({
      runReferenceSha256: sha256(config.runReference),
      workflowRunId: workflowRunId && /^\d{1,30}$/.test(String(workflowRunId))
        ? String(workflowRunId) : null
    }),
    createdAt: now
  });
}

function buffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value == null) return Buffer.alloc(0);
  return Buffer.from(String(value));
}

function outputContainsSecret(bytes, secrets) {
  return secrets.filter(Boolean).some(secret => bytes.includes(Buffer.from(String(secret))));
}

export function createExactStagingPublishAttempt(intent, result, stdoutValue, stderrValue, {
  startedAt, completedAt, receiptCaptured, outputSecretBoundaryViolated
}) {
  const stdout = buffer(stdoutValue);
  const stderr = buffer(stderrValue);
  const timedOut = result?.error?.code === 'ETIMEDOUT';
  const exitCode = Number.isInteger(result?.status) ? result.status : null;
  const cliOutcome = timedOut ? 'TIMEOUT' : exitCode === 0 ? 'EXIT_ZERO' :
    exitCode !== null ? 'EXIT_NONZERO' : 'SPAWN_FAILED';
  return Object.freeze({
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_publish_attempt',
    status: 'UNKNOWN_PENDING_RECONCILIATION',
    stagingOnly: true,
    productionAuthorized: false,
    controller: intent.controller,
    source: intent.source,
    target: intent.target,
    intentSha256: sha256(Buffer.from(JSON.stringify(intent))),
    rollbackBaselineDeployId: intent.rollbackBaselineDeployId,
    cliOutcome,
    exitCode,
    signal: typeof result?.signal === 'string' ? result.signal.slice(0, 32) : null,
    stdoutByteLength: stdout.length,
    stdoutSha256: stdout.length ? sha256(stdout) : null,
    stderrByteLength: stderr.length,
    stderrSha256: stderr.length ? sha256(stderr) : null,
    outputSerialized: false,
    outputSecretBoundaryViolated: Boolean(outputSecretBoundaryViolated),
    rawReceiptCaptured: Boolean(receiptCaptured),
    canonicalDeployAssumed: false,
    automaticRollbackAttempted: false,
    retryCount: 0,
    startedAt,
    completedAt
  });
}

export async function executeExactStagingPublishAttempt(config, token, {
  env = process.env,
  spawnSyncImpl = spawnSync,
  now = () => new Date().toISOString(),
  cliPath = path.resolve(process.cwd(), '..', 'cnyos-staging-publisher',
    'node_modules', '.bin', 'netlify'),
  candidateDirectory = path.resolve(required(env.GITHUB_WORKSPACE,
    'CNYOS_EXACT_STAGING_GITHUB_WORKSPACE_REQUIRED'))
} = {}) {
  const secret = required(token, 'CNYOS_EXACT_STAGING_NETLIFY_TOKEN_REQUIRED');
  const bindingFile = await readJson(path.join(config.uploadDirectory, 'candidate-binding.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  const baselineFile = await readJson(path.join(config.uploadDirectory, 'rollback-baseline.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  const intent = createExactStagingPublishIntent(config, bindingFile.value, baselineFile.value, {
    now: now(), workflowRunId: env.GITHUB_RUN_ID
  });
  await writeFresh0600(path.join(config.uploadDirectory, 'publish-intent.json'), intent, [secret]);

  const startedAt = now();
  const result = spawnSyncImpl(required(cliPath, 'CNYOS_EXACT_STAGING_NETLIFY_CLI_REQUIRED'), [
    'deploy', '--prod', '--no-build', '--json', '--context', 'production',
    '--site', EXACT_STAGING_TARGET.netlifySiteId,
    '--dir', config.distDirectory,
    '--functions', config.functionsDirectory,
    '--skip-functions-cache',
    '--message', `cnyos-exact-staging:${config.appCommit}:${required(env.GITHUB_RUN_ID,
      'CNYOS_EXACT_STAGING_GITHUB_RUN_ID_REQUIRED', 30)}`,
    '--timeout', '120'
  ], {
    cwd: candidateDirectory,
    encoding: null,
    maxBuffer: MAX_OUTPUT_BYTES,
    timeout: 150_000,
    killSignal: 'SIGTERM',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      CI: 'true',
      NETLIFY_AUTH_TOKEN: secret,
      NETLIFY_SITE_ID: EXACT_STAGING_TARGET.netlifySiteId,
      PATH: required(env.PATH, 'CNYOS_EXACT_STAGING_PATH_REQUIRED'),
      HOME: required(env.HOME, 'CNYOS_EXACT_STAGING_HOME_REQUIRED'),
      XDG_CONFIG_HOME: required(env.XDG_CONFIG_HOME,
        'CNYOS_EXACT_STAGING_XDG_CONFIG_REQUIRED'),
      XDG_CACHE_HOME: required(env.XDG_CACHE_HOME,
        'CNYOS_EXACT_STAGING_XDG_CACHE_REQUIRED')
    }
  });
  const stdout = buffer(result?.stdout);
  const stderr = buffer(result?.stderr);
  const oversized = stdout.length > MAX_OUTPUT_BYTES || stderr.length > MAX_OUTPUT_BYTES;
  const leaked = outputContainsSecret(stdout, [secret]) || outputContainsSecret(stderr, [secret]);
  let receiptCaptured = false;
  if (stdout.length && !oversized && !leaked) {
    await fs.writeFile(path.join(config.privateDirectory, 'netlify-deploy-receipt.raw.json'), stdout,
      { flag: 'wx', mode: 0o600 });
    receiptCaptured = true;
  }
  const attempt = createExactStagingPublishAttempt(intent, result, stdout, stderr, {
    startedAt,
    completedAt: now(),
    receiptCaptured,
    outputSecretBoundaryViolated: leaked
  });
  await writeFresh0600(path.join(config.uploadDirectory, 'publish-attempt.json'), attempt, [secret]);
  return attempt;
}

async function responseBytes(fetchImpl, url, options, code) {
  let response;
  try { response = await fetchImpl(url, options); }
  catch { fail(code); }
  if (response.status !== 200) fail(code);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 2 || bytes.length > MAX_OUTPUT_BYTES) fail(code);
  return bytes;
}

async function responseObject(fetchImpl, url, options, code) {
  const bytes = await responseBytes(fetchImpl, url, options, code);
  try {
    const value = JSON.parse(bytes.toString('utf8'));
    if (!plainObject(value)) fail(code);
    return value;
  } catch { fail(code); }
}

export async function observeExactStagingCanonical(config, token, expectedRuntimeSha256, {
  fetchImpl = fetch
} = {}) {
  const headers = { Accept: 'application/json', Authorization: `Bearer ${token}` };
  const options = {
    headers, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20_000)
  };
  const site = await responseObject(fetchImpl,
    `https://api.netlify.com/api/v1/sites/${EXACT_STAGING_TARGET.netlifySiteId}`,
    options, 'CNYOS_EXACT_STAGING_RECONCILIATION_SITE_UNAVAILABLE');
  const currentDeployId = String(site?.published_deploy?.id || '').toLowerCase();
  if (String(site?.id || '').toLowerCase() !== EXACT_STAGING_TARGET.netlifySiteId ||
    site?.name !== EXACT_STAGING_TARGET.netlifySiteName ||
    site?.ssl_url !== EXACT_STAGING_TARGET.origin || !DEPLOY_ID.test(currentDeployId)) {
    fail('CNYOS_EXACT_STAGING_RECONCILIATION_SITE_INVALID');
  }
  const deploy = await responseObject(fetchImpl,
    `https://api.netlify.com/api/v1/deploys/${currentDeployId}`, options,
    'CNYOS_EXACT_STAGING_RECONCILIATION_DEPLOY_UNAVAILABLE');
  const deployState = String(deploy?.state || '').toLowerCase();
  if (String(deploy?.id || '').toLowerCase() !== currentDeployId ||
    String(deploy?.site_id || '').toLowerCase() !== EXACT_STAGING_TARGET.netlifySiteId) {
    fail('CNYOS_EXACT_STAGING_RECONCILIATION_DEPLOY_INVALID');
  }
  let candidateMatches = false;
  if (currentDeployId !== config.rollbackDeployId && deployState === 'ready') {
    candidateMatches = true;
    for (const origin of [
      EXACT_STAGING_TARGET.origin,
      `https://${currentDeployId}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`
    ]) {
      const manifest = await responseObject(fetchImpl, `${origin}/deploy-manifest.json`, {
        redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20_000)
      }, 'CNYOS_EXACT_STAGING_RECONCILIATION_MANIFEST_UNAVAILABLE');
      const runtimeBytes = await responseBytes(fetchImpl,
        `${origin}/runtime-publish-manifest.json`, {
          redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20_000)
        }, 'CNYOS_EXACT_STAGING_RECONCILIATION_RUNTIME_UNAVAILABLE');
      if (manifest?.source?.commit !== config.appCommit ||
        manifest?.source?.tree !== config.appTree ||
        manifest?.deploymentId !== EXACT_STAGING_TARGET.deploymentId ||
        manifest?.tenant?.expectedClinicId !== EXACT_STAGING_TARGET.clinicId ||
        manifest?.safety?.stagingDatabaseExplicitlyAcknowledged !== true ||
        sha256(runtimeBytes) !== expectedRuntimeSha256) candidateMatches = false;
    }
  }
  return Object.freeze({ currentDeployId, deployState, candidateMatches });
}

export function classifyExactStagingPublishReconciliation({
  baselineDeployId, receiptDeployId = null, attemptedDeployState = null, observation = null
}) {
  if (!observation || !DEPLOY_ID.test(String(observation.currentDeployId || ''))) {
    return Object.freeze({ status: 'UNCERTAIN', result: 'CANONICAL_STATE_UNKNOWN' });
  }
  if (observation.candidateMatches === true) {
    return Object.freeze({ status: 'PASS', result: 'APPLIED_VERIFIED' });
  }
  if (observation.currentDeployId !== baselineDeployId) {
    return Object.freeze({ status: 'UNCERTAIN', result: 'CANONICAL_DEPLOY_DRIFT' });
  }
  if (!receiptDeployId) {
    return Object.freeze({ status: 'UNCERTAIN', result: 'ATTEMPT_DEPLOY_ID_UNKNOWN' });
  }
  const state = String(attemptedDeployState || '').toLowerCase();
  if (state === 'ready') {
    return Object.freeze({ status: 'FAIL', result: 'ATTEMPT_READY_NOT_CANONICAL' });
  }
  if (TERMINAL_DEPLOY_FAILURE_STATES.has(state)) {
    return Object.freeze({ status: 'FAIL', result: 'ATTEMPT_TERMINAL_FAILURE' });
  }
  return Object.freeze({ status: 'UNCERTAIN', result: 'ATTEMPT_DEPLOY_STATE_UNKNOWN' });
}

async function observeAttemptDeploy(receipt, token, fetchImpl) {
  if (!receipt) return null;
  try {
    const value = await responseObject(fetchImpl,
      `https://api.netlify.com/api/v1/deploys/${receipt.deployId}`, {
        headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
        redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20_000)
      }, 'CNYOS_EXACT_STAGING_RECONCILIATION_ATTEMPT_UNAVAILABLE');
    if (String(value?.id || '').toLowerCase() !== receipt.deployId ||
      String(value?.site_id || '').toLowerCase() !== EXACT_STAGING_TARGET.netlifySiteId) return null;
    return Object.freeze({ deployId: receipt.deployId, state: String(value.state || '').toLowerCase() });
  } catch { return null; }
}

function wait(delay) {
  return new Promise(resolve => setTimeout(resolve, delay));
}

async function writeGithubOutput(env, name, value) {
  if (!env.GITHUB_OUTPUT) return;
  await fs.appendFile(env.GITHUB_OUTPUT, `${name}=${value}\n`, { encoding: 'utf8' });
}

export async function reconcileExactStagingPublish(config, token, {
  env = process.env,
  fetchImpl = fetch,
  waitImpl = wait,
  attempts = RECONCILIATION_ATTEMPTS,
  delayMs = RECONCILIATION_DELAY_MS,
  now = () => new Date().toISOString()
} = {}) {
  const secret = required(token, 'CNYOS_EXACT_STAGING_NETLIFY_TOKEN_REQUIRED');
  assertFixedTarget(config);
  const intentFile = await readJson(path.join(config.uploadDirectory, 'publish-intent.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_INTENT_INVALID');
  const attemptFile = await readJson(path.join(config.uploadDirectory, 'publish-attempt.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_ATTEMPT_INVALID');
  const bindingFile = await readJson(path.join(config.uploadDirectory, 'candidate-binding.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  const baselineFile = await readJson(path.join(config.uploadDirectory, 'rollback-baseline.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  const attempt = attemptFile.value;
  const intent = assertPublishChain(config, bindingFile.value, baselineFile.value,
    intentFile, attempt);

  let receipt = null;
  const rawReceiptPath = path.join(config.privateDirectory, 'netlify-deploy-receipt.raw.json');
  const rawReceiptStat = await fs.lstat(rawReceiptPath).catch(() => null);
  const rawReceiptCaptured = Boolean(rawReceiptStat?.isFile() && !rawReceiptStat.isSymbolicLink());
  const rawReceiptFile = rawReceiptCaptured ? await readJson(rawReceiptPath,
    'CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID').catch(() => null) : null;
  if (rawReceiptFile) {
    try { receipt = parseNetlifyDeployReceipt(rawReceiptFile.value, config); }
    catch { receipt = null; }
  }

  let observation = null;
  let successfulObservations = 0;
  const observationFailures = [];
  for (let index = 0; index < attempts; index += 1) {
    try {
      observation = await observeExactStagingCanonical(config, secret,
        intent.artifact.runtimeManifestSha256, { fetchImpl });
      successfulObservations += 1;
      if (observation.candidateMatches) break;
    } catch (error) {
      observationFailures.push(String(error?.code || 'OBSERVATION_FAILED').slice(0, 100));
    }
    if (index + 1 < attempts) await waitImpl(delayMs);
  }
  const attemptedDeploy = await observeAttemptDeploy(receipt, secret, fetchImpl);
  const decision = classifyExactStagingPublishReconciliation({
    baselineDeployId: config.rollbackDeployId,
    receiptDeployId: receipt?.deployId || null,
    attemptedDeployState: attemptedDeploy?.state || null,
    observation
  });
  let normalizedReceipt = null;
  if (decision.status === 'PASS') {
    normalizedReceipt = parseNetlifyDeployReceipt({
      deploy_id: observation.currentDeployId,
      site_id: EXACT_STAGING_TARGET.netlifySiteId,
      deploy_url:
        `https://${observation.currentDeployId}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`
    }, config);
    await writeFresh0600(path.join(config.privateDirectory, 'netlify-deploy-receipt.json'),
      normalizedReceipt, [secret]);
  }
  const evidence = {
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_publish_reconciliation',
    status: decision.status,
    result: decision.result,
    stagingOnly: true,
    productionAuthorized: false,
    controller: intent.controller,
    source: { commit: config.appCommit, tree: config.appTree },
    target: {
      siteId: EXACT_STAGING_TARGET.netlifySiteId,
      origin: EXACT_STAGING_TARGET.origin,
      supabaseProjectRef: EXACT_STAGING_TARGET.supabaseProjectRef
    },
    rollbackBaselineDeployId: config.rollbackDeployId,
    cliOutcome: attempt.cliOutcome,
    rawReceiptCaptured,
    rawReceiptParsed: receipt !== null,
    receiptDeployId: receipt?.deployId || null,
    attemptedDeploy: attemptedDeploy ? {
      deployId: attemptedDeploy.deployId, state: attemptedDeploy.state
    } : null,
    canonicalObservation: observation ? {
      deployId: observation.currentDeployId,
      state: observation.deployState,
      candidateMatches: observation.candidateMatches
    } : null,
    canonicalObservationAttempts: attempts,
    canonicalObservationSuccesses: successfulObservations,
    observationFailureCodes: [...new Set(observationFailures)].sort(),
    normalizedDeployId: normalizedReceipt?.deployId || null,
    automaticRollbackAuthorized: false,
    automaticRollbackAttempted: false,
    retryAuthorized: false,
    reconciledAt: now()
  };
  await writeFresh0600(path.join(config.uploadDirectory, 'publish-reconciliation.json'),
    evidence, [secret]);
  await writeGithubOutput(env, 'publish_reconciled', decision.status === 'PASS' ? 'true' : 'false');
  await writeGithubOutput(env, 'reconciliation_status', decision.status);
  return evidence;
}

function assertReconciliationEvidence(config, reconciliation, attempt) {
  const allowedResults = RECONCILIATION_RESULTS[reconciliation?.status];
  const receiptDeployId = reconciliation?.receiptDeployId;
  const receiptValid = receiptDeployId === null || DEPLOY_ID.test(String(receiptDeployId || ''));
  const attemptedDeploy = reconciliation?.attemptedDeploy;
  const attemptedDeployValid = attemptedDeploy === null || (
    plainObject(attemptedDeploy) && attemptedDeploy.deployId === receiptDeployId &&
    DEPLOY_ID.test(String(attemptedDeploy.deployId || '')) &&
    typeof attemptedDeploy.state === 'string' && attemptedDeploy.state.length > 0 &&
    attemptedDeploy.state.length <= 64
  );
  const observation = reconciliation?.canonicalObservation;
  const observationValid = observation === null || (
    plainObject(observation) && DEPLOY_ID.test(String(observation.deployId || '')) &&
    typeof observation.state === 'string' && observation.state.length > 0 &&
    observation.state.length <= 64 && typeof observation.candidateMatches === 'boolean'
  );
  const classified = classifyExactStagingPublishReconciliation({
    baselineDeployId: config.rollbackDeployId,
    receiptDeployId,
    attemptedDeployState: attemptedDeploy?.state || null,
    observation: observation ? {
      currentDeployId: observation.deployId,
      candidateMatches: observation.candidateMatches
    } : null
  });
  const observationFailureCodesValid = Array.isArray(reconciliation?.observationFailureCodes) &&
    reconciliation.observationFailureCodes.every(code =>
      typeof code === 'string' && /^[A-Z0-9_]{1,100}$/.test(code)) &&
    new Set(reconciliation.observationFailureCodes).size ===
      reconciliation.observationFailureCodes.length;
  if (reconciliation?.schemaVersion !== 1 ||
    reconciliation?.kind !== 'cnyos_exact_staging_publish_reconciliation' ||
    reconciliation?.stagingOnly !== true || reconciliation?.productionAuthorized !== false ||
    !exactControllerBinding(config, reconciliation?.controller) ||
    !exactSourceBinding(config, reconciliation?.source) ||
    !exactTargetBinding(reconciliation?.target) ||
    reconciliation?.rollbackBaselineDeployId !== config.rollbackDeployId ||
    !allowedResults?.includes(reconciliation?.result) ||
    reconciliation?.status !== classified.status || reconciliation?.result !== classified.result ||
    reconciliation?.cliOutcome !== attempt?.cliOutcome ||
    reconciliation?.rawReceiptCaptured !== attempt?.rawReceiptCaptured ||
    typeof reconciliation?.rawReceiptParsed !== 'boolean' || !receiptValid ||
    reconciliation.rawReceiptParsed !== (receiptDeployId !== null) ||
    !attemptedDeployValid || !observationValid || !observationFailureCodesValid ||
    !Number.isInteger(reconciliation?.canonicalObservationAttempts) ||
    reconciliation.canonicalObservationAttempts < 1 ||
    reconciliation.canonicalObservationAttempts > RECONCILIATION_ATTEMPTS ||
    !Number.isInteger(reconciliation?.canonicalObservationSuccesses) ||
    reconciliation.canonicalObservationSuccesses < 0 ||
    reconciliation.canonicalObservationSuccesses > reconciliation.canonicalObservationAttempts ||
    reconciliation?.automaticRollbackAuthorized !== false ||
    reconciliation?.automaticRollbackAttempted !== false ||
    reconciliation?.retryAuthorized !== false ||
    !validIsoTimestamp(reconciliation?.reconciledAt)) {
    fail('CNYOS_EXACT_STAGING_RECONCILIATION_EVIDENCE_INVALID');
  }
  if (reconciliation.status === 'PASS') {
    if (!DEPLOY_ID.test(String(reconciliation.normalizedDeployId || '')) ||
      reconciliation.normalizedDeployId === config.rollbackDeployId ||
      reconciliation?.canonicalObservation?.deployId !== reconciliation.normalizedDeployId ||
      reconciliation?.canonicalObservation?.state !== 'ready' ||
      reconciliation?.canonicalObservation?.candidateMatches !== true ||
      reconciliation.canonicalObservationSuccesses < 1) {
      fail('CNYOS_EXACT_STAGING_RECONCILIATION_EVIDENCE_INVALID');
    }
    return reconciliation.normalizedDeployId;
  }
  if (reconciliation.normalizedDeployId !== null) {
    fail('CNYOS_EXACT_STAGING_RECONCILIATION_EVIDENCE_INVALID');
  }
  return null;
}

function assertDeployReceiptEvidence(config, receipt, expectedDeployId) {
  let normalized;
  try { normalized = parseNetlifyDeployReceipt(receipt, config); }
  catch { fail('CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID'); }
  if (receipt?.schemaVersion !== 1 || receipt?.kind !== 'cnyos_exact_staging_deploy_receipt' ||
    receipt?.stagingOnly !== true || !exactSourceBinding(config, receipt?.source) ||
    receipt?.siteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    receipt?.canonicalOrigin !== EXACT_STAGING_TARGET.origin ||
    receipt?.exactDeployOrigin !== normalized.exactDeployOrigin ||
    normalized.deployId !== expectedDeployId) {
    fail('CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID');
  }
  return normalized;
}

function assertUatEvidence(config, uat, receipt, expectedDeployId) {
  if (uat?.schemaVersion !== 1 ||
    uat?.kind !== 'cnyos_exact_staging_role_separated_uat' ||
    !['PASS', 'FAIL', 'UNCERTAIN'].includes(uat?.status) ||
    uat?.stagingOnly !== true || uat?.productionAuthorized !== false ||
    !exactControllerBinding(config, uat?.controller) ||
    !exactSourceBinding(config, uat?.source)) {
    fail('CNYOS_EXACT_STAGING_UAT_EVIDENCE_INVALID');
  }
  if (uat.status === 'PASS') {
    const roleKeys = Object.keys(UAT_ROLE_SPECS);
    const actorKeys = plainObject(uat?.journey?.actorIds)
      ? Object.keys(uat.journey.actorIds).sort() : [];
    const actorIds = roleKeys.map(key => uat?.journey?.actorIds?.[key]);
    const browser = uat?.journey?.opdBrowserProof;
    const expectedPerContext = [
      { contextOrdinal: 1, writes: 1 },
      { contextOrdinal: 2, writes: 1 },
      { contextOrdinal: 3, writes: 0 }
    ];
    const expectedWriteRecords = [
      { ordinal: 1, contextOrdinal: 1, rpc: 'save_ttm_opd_history', reservedBeforeFetch: true },
      { ordinal: 2, contextOrdinal: 2, rpc: 'save_ttm_opd_history', reservedBeforeFetch: true }
    ];
    const expectedConsultEvents = ['requested', 'acknowledged', 'accepted', 'completed'];
    const expectedIpdEntries = [
      'admission_request', 'admission_note', 'progress_note',
      'medication_reconciliation', 'discharge_summary'
    ];
    const expectedIpdEvents = [
      'requested', 'bed_assigned', 'admitted', 'entry_appended', 'entry_appended',
      'entry_appended', 'discharge_ready', 'discharged'
    ];
    const expectedAuditCounts = {
      create_clinical_consult_request: 1,
      transition_clinical_consult_request: 3,
      create_ipd_admission_request: 1,
      transition_ipd_admission: 4,
      append_ipd_clinical_entry: 3
    };
    const consult = uat?.journey?.consult;
    const expectedConsultEventDetails = [
      {
        eventType: 'requested', fromStatus: null, toStatus: 'requested',
        resultingVersion: 1, actorId: uat?.journey?.actorIds?.source_practitioner
      },
      {
        eventType: 'acknowledged', fromStatus: 'requested', toStatus: 'acknowledged',
        resultingVersion: 2, actorId: uat?.journey?.actorIds?.attending
      },
      {
        eventType: 'accepted', fromStatus: 'acknowledged', toStatus: 'accepted',
        resultingVersion: 3, actorId: uat?.journey?.actorIds?.attending
      },
      {
        eventType: 'completed', fromStatus: 'accepted', toStatus: 'completed',
        resultingVersion: 4, actorId: uat?.journey?.actorIds?.attending
      }
    ];
    const admission = uat?.journey?.admission;
    const entryDetails = Array.isArray(admission?.entryDetails) ? admission.entryDetails : [];
    const entryIds = entryDetails.map(entry => entry?.entryId);
    const entryIdsValid = entryIds.length === 5 &&
      entryIds.every(id => Number.isSafeInteger(Number(id)) && Number(id) > 0) &&
      new Set(entryIds.map(String)).size === entryIds.length;
    const expectedEntryDetails = [
      {
        entryId: entryIds[0], entryType: 'admission_request',
        authorId: uat?.journey?.actorIds?.source_practitioner, admissionVersion: 1
      },
      {
        entryId: entryIds[1], entryType: 'admission_note',
        authorId: uat?.journey?.actorIds?.attending, admissionVersion: 3
      },
      {
        entryId: entryIds[2], entryType: 'progress_note',
        authorId: uat?.journey?.actorIds?.attending, admissionVersion: 4
      },
      {
        entryId: entryIds[3], entryType: 'medication_reconciliation',
        authorId: uat?.journey?.actorIds?.attending, admissionVersion: 5
      },
      {
        entryId: entryIds[4], entryType: 'discharge_summary',
        authorId: uat?.journey?.actorIds?.attending, admissionVersion: 6
      }
    ];
    const eventDetails = Array.isArray(admission?.eventDetails) ? admission.eventDetails : [];
    const eventIds = eventDetails.map(event => event?.eventId);
    const eventIdsValid = eventIds.length === 8 &&
      eventIds.every(id => Number.isSafeInteger(Number(id)) && Number(id) > 0) &&
      new Set(eventIds.map(String)).size === eventIds.length;
    const expectedEventDetails = [
      {
        eventId: eventIds[0], eventType: 'requested', fromStatus: null,
        toStatus: 'requested', resultingVersion: 1,
        actorId: uat?.journey?.actorIds?.source_practitioner, clinicalEntryId: entryIds[0]
      },
      {
        eventId: eventIds[1], eventType: 'bed_assigned', fromStatus: 'requested',
        toStatus: 'bed_assigned', resultingVersion: 2,
        actorId: uat?.journey?.actorIds?.reception, clinicalEntryId: null
      },
      {
        eventId: eventIds[2], eventType: 'admitted', fromStatus: 'bed_assigned',
        toStatus: 'admitted', resultingVersion: 3,
        actorId: uat?.journey?.actorIds?.attending, clinicalEntryId: entryIds[1]
      },
      ...[
        [3, 2, 4], [4, 3, 5], [5, 4, 6]
      ].map(([eventIndex, entryIndex, version]) => ({
        eventId: eventIds[eventIndex], eventType: 'entry_appended', fromStatus: 'admitted',
        toStatus: 'admitted', resultingVersion: version,
        actorId: uat?.journey?.actorIds?.attending, clinicalEntryId: entryIds[entryIndex]
      })),
      {
        eventId: eventIds[6], eventType: 'discharge_ready', fromStatus: 'admitted',
        toStatus: 'discharge_ready', resultingVersion: 7,
        actorId: uat?.journey?.actorIds?.attending, clinicalEntryId: null
      },
      {
        eventId: eventIds[7], eventType: 'discharged', fromStatus: 'discharge_ready',
        toStatus: 'discharged', resultingVersion: 8,
        actorId: uat?.journey?.actorIds?.reception, clinicalEntryId: null
      }
    ];
    const started = Date.parse(uat?.startedAt);
    const completed = Date.parse(uat?.completedAt);
    const expectedRunSuffix = config.runId.slice(-8);
    const expectedHn = new RegExp(EXACT_STAGING_SYNTHETIC_HN_PATTERN);
    assertDeployReceiptEvidence(config, uat.deployment, expectedDeployId);
    if (!exactTargetBinding(uat?.target, { requireClinicalScope: false }) ||
      uat?.target?.clinicId !== EXACT_STAGING_TARGET.clinicId ||
      uat?.journey?.syntheticOnly !== true || uat?.journey?.realPhiUsed !== false ||
      uat?.journey?.runId !== config.runId ||
      JSON.stringify(actorKeys) !== JSON.stringify([...roleKeys].sort()) ||
      actorIds.some(value => !UUID.test(String(value || ''))) ||
      new Set(actorIds).size !== roleKeys.length ||
      !UUID.test(String(uat?.journey?.patient?.id || '')) ||
      !expectedHn.test(String(uat?.journey?.patient?.hn || '')) ||
      uat?.journey?.patient?.syntheticRunSuffix !== expectedRunSuffix ||
      uat?.journey?.patient?.hnGeneratedByServer !== true ||
      uat?.journey?.patient?.clinicId !== EXACT_STAGING_TARGET.clinicId ||
      uat?.journey?.patient?.paymentRight !== 'SYNTHETIC-E2E' ||
      uat?.journey?.patient?.realIdentifiersAbsent !== true ||
      browser?.contexts !== 3 || browser?.saveReloadAmend !== true ||
      browser?.writes !== config.limits.browserOpdWrites ||
      browser?.writeLedger?.limit !== config.limits.browserOpdWrites ||
      browser?.writeLedger?.dispatched !== config.limits.browserOpdWrites ||
      browser?.writeLedger?.contextCount !== 3 ||
      !Array.isArray(browser?.writeLedger?.records) ||
      JSON.stringify(browser.writeLedger.records) !== JSON.stringify(expectedWriteRecords) ||
      !Array.isArray(browser?.writeLedger?.perContext) ||
      JSON.stringify(browser.writeLedger.perContext) !== JSON.stringify(expectedPerContext) ||
      !UUID.test(String(consult?.id || '')) || consult?.version !== 4 ||
      uat?.journey?.consult?.status !== 'completed' ||
      uat?.journey?.consult?.senderActorId !== uat?.journey?.actorIds?.source_practitioner ||
      uat?.journey?.consult?.receiverActorId !== uat?.journey?.actorIds?.attending ||
      uat?.journey?.consult?.wrongRole?.status !== 'DENIED' ||
      uat?.journey?.consult?.wrongRole?.expectedError !==
        'CONSULT_RECEIVER_MUST_DIFFER_FROM_SENDER' ||
      uat?.journey?.consult?.wrongRole?.noMutationReadbackVerified !== true ||
      uat?.journey?.consult?.participantDetailReadbackVerified !== true ||
      uat?.journey?.consult?.eventTimelineReadbackVerified !== true ||
      JSON.stringify(uat?.journey?.consult?.eventTypes) !== JSON.stringify(expectedConsultEvents) ||
      JSON.stringify(consult?.eventDetails) !== JSON.stringify(expectedConsultEventDetails) ||
      !UUID.test(String(admission?.id || '')) || admission?.version !== 8 ||
      uat?.journey?.admission?.status !== 'discharged' ||
      uat?.journey?.admission?.sourceActorId !== uat?.journey?.actorIds?.source_practitioner ||
      uat?.journey?.admission?.attendingActorId !== uat?.journey?.actorIds?.attending ||
      uat?.journey?.admission?.placementAndDischargeActorId !==
        uat?.journey?.actorIds?.reception ||
      uat?.journey?.admission?.wrongRole?.status !== 'DENIED' ||
      uat?.journey?.admission?.wrongRole?.expectedError !== 'RECEPTION_ROLE_REQUIRED' ||
      uat?.journey?.admission?.wrongRole?.noMutationReadbackVerified !== true ||
      uat?.journey?.admission?.timelineReadbackVerified !== true ||
      uat?.journey?.admission?.sourceAdmissionRequestOnlyVerified !== true ||
      uat?.journey?.admission?.receptionClinicalEntriesAndActorIdsRedacted !== true ||
      JSON.stringify(uat?.journey?.admission?.entryTypes) !== JSON.stringify(expectedIpdEntries) ||
      JSON.stringify(uat?.journey?.admission?.eventTypes) !== JSON.stringify(expectedIpdEvents) ||
      !entryIdsValid || JSON.stringify(entryDetails) !== JSON.stringify(expectedEntryDetails) ||
      !eventIdsValid || JSON.stringify(eventDetails) !== JSON.stringify(expectedEventDetails) ||
      uat?.journey?.pharmacy?.separated !== true ||
      uat?.journey?.pharmacy?.reviewerActorId !== uat?.journey?.actorIds?.pharmacy_reviewer ||
      uat?.journey?.pharmacy?.dispenserActorId !== uat?.journey?.actorIds?.pharmacy_dispenser ||
      uat?.journey?.billing?.grandTotal !== 800 ||
      uat?.journey?.billing?.invoiceStatus !== 'paid' ||
      uat?.journey?.billing?.actorId !== uat?.journey?.actorIds?.billing ||
      uat?.journey?.admin?.actorId !== uat?.journey?.actorIds?.admin ||
      uat?.journey?.admin?.separatelyAuthenticated !== true ||
      uat?.journey?.admin?.auditHistoryReadbackVerified !== true ||
      uat?.journey?.admin?.auditPhiRedacted !== true ||
      uat?.journey?.admin?.auditClinicalPayloadRedacted !== true ||
      uat?.journey?.admin?.auditActorAndTransitionReadbackVerified !== true ||
      uat?.journey?.admin?.auditRowCount !== 12 ||
      JSON.stringify(uat?.journey?.admin?.auditActionCounts) !==
        JSON.stringify(expectedAuditCounts) ||
      uat?.mutationBudget?.limit !== config.limits.totalMutations ||
      !Number.isInteger(uat?.mutationBudget?.dispatched) ||
      uat.mutationBudget.dispatched !== config.limits.totalMutations ||
      uat?.mutationBudget?.writeRetries !== 0 ||
      !exactMutationLedger(uat?.mutationBudget?.records, roleKeys) ||
      uat.mutationBudget.records.length !== uat.mutationBudget.dispatched ||
      !validIsoTimestamp(uat?.startedAt) || !validIsoTimestamp(uat?.completedAt) ||
      completed < started || completed - started > config.limits.uatTimeoutMs ||
      uat.deployment.deployId !== receipt.deployId) {
      fail('CNYOS_EXACT_STAGING_UAT_EVIDENCE_INVALID');
    }
  } else if (uat?.deployReceiptCaptured !== true || uat?.deployId !== expectedDeployId) {
    fail('CNYOS_EXACT_STAGING_UAT_EVIDENCE_INVALID');
  }
}

function assertFixtureEvidence(config, fixture, uat, expectedDeployId) {
  const accountEntries = plainObject(fixture?.accounts) ? Object.entries(fixture.accounts) : [];
  const expectedRoleKeys = Object.keys(UAT_ROLE_SPECS).sort();
  const accountIds = accountEntries.map(([, account]) => account?.userId);
  const limitsValid = plainObject(fixture?.limits) &&
    Object.keys(config.limits).every(key => fixture.limits[key] === config.limits[key]) &&
    Object.keys(fixture.limits).length === Object.keys(config.limits).length;
  const accountsValid = accountEntries.length === expectedRoleKeys.length &&
    JSON.stringify(accountEntries.map(([key]) => key).sort()) === JSON.stringify(expectedRoleKeys) &&
    accountEntries.every(([key, account]) => {
      const roles = UAT_ROLE_SPECS[key];
      return roles && UUID.test(String(account?.userId || '')) &&
        SHA256.test(String(account?.emailSha256 || '')) &&
        account?.profileRole === roles[0] && account?.systemRole === roles[1] &&
        account?.clinicRole === roles[2] && account?.syntheticMarkerVerified === true &&
        account?.authenticatedSessionVerified === true &&
        uat?.journey?.actorIds?.[key] === account.userId;
    });
  if (fixture?.schemaVersion !== 1 ||
    fixture?.kind !== 'cnyos_exact_staging_synthetic_fixture' || fixture?.status !== 'PASS' ||
    fixture?.syntheticOnly !== true || fixture?.realPhiUsed !== false ||
    !exactControllerBinding(config, fixture?.controller) ||
    !exactSourceBinding(config, fixture?.source) || fixture?.deployId !== expectedDeployId ||
    fixture?.runId !== config.runId || fixture?.distinctAccountCount !== config.limits.authUsers ||
    !accountsValid || new Set(accountIds).size !== config.limits.authUsers ||
    fixture?.patient?.realIdentifiersAbsent !== true ||
    fixture?.patient?.id !== uat?.journey?.patient?.id ||
    fixture?.patient?.hn !== uat?.journey?.patient?.hn ||
    fixture?.patient?.syntheticRunSuffix !== uat?.journey?.patient?.syntheticRunSuffix ||
    fixture?.patient?.hnGeneratedByServer !== true ||
    fixture?.patient?.clinicId !== EXACT_STAGING_TARGET.clinicId ||
    fixture?.patient?.paymentRight !== 'SYNTHETIC-E2E' ||
    !limitsValid) {
    fail('CNYOS_EXACT_STAGING_FIXTURE_EVIDENCE_INVALID');
  }
}

function assertEvidenceManifest(config, manifest, files, expectedDeployId) {
  if (manifest?.schemaVersion !== 1 ||
    manifest?.kind !== 'cnyos_exact_staging_evidence_manifest' || manifest?.status !== 'PASS' ||
    manifest?.stagingOnly !== true || manifest?.productionAuthorized !== false ||
    !exactControllerBinding(config, manifest?.controller) ||
    !exactSourceBinding(config, manifest?.source) || manifest?.deployId !== expectedDeployId ||
    manifest?.rollbackDeployId !== config.rollbackDeployId || !Array.isArray(manifest?.evidence) ||
    manifest.evidence.length !== EVIDENCE_MANIFEST_FILES.length) {
    fail('CNYOS_EXACT_STAGING_EVIDENCE_MANIFEST_INVALID');
  }
  const entries = new Map();
  for (const entry of manifest.evidence) {
    if (!plainObject(entry) || typeof entry.name !== 'string' || entries.has(entry.name) ||
      !EVIDENCE_MANIFEST_FILES.includes(entry.name) || !Number.isInteger(entry.size) ||
      entry.size < 2 || !SHA256.test(String(entry.sha256 || ''))) {
      fail('CNYOS_EXACT_STAGING_EVIDENCE_MANIFEST_INVALID');
    }
    entries.set(entry.name, entry);
  }
  for (const name of EVIDENCE_MANIFEST_FILES) {
    const observed = files.get(name);
    const declared = entries.get(name);
    if (!observed || !declared || declared.size !== observed.size ||
      declared.sha256 !== observed.sha256) {
      fail('CNYOS_EXACT_STAGING_EVIDENCE_MANIFEST_INVALID');
    }
  }
}

function validDatabaseCommandEvidence(value, requireSuccess = true) {
  const outcomeValid = requireSuccess
    ? value?.exitCode === 0 && value?.signal === null
    : (Number.isSafeInteger(value?.exitCode) || value?.exitCode === null) &&
      (value?.signal === null || (typeof value?.signal === 'string' &&
        /^[A-Za-z0-9_-]{1,32}$/.test(value.signal)));
  return plainObject(value) && outcomeValid &&
    Number.isInteger(value.stdoutBytes) && value.stdoutBytes >= 0 &&
    Number.isInteger(value.stderrBytes) && value.stderrBytes >= 0 &&
    (value.stdoutBytes === 0 ? value.stdoutSha256 === null :
      SHA256.test(String(value.stdoutSha256 || ''))) &&
    (value.stderrBytes === 0 ? value.stderrSha256 === null :
      SHA256.test(String(value.stderrSha256 || '')));
}

function assertDatabaseReconciliationEvidence(config, database, binding) {
  const passPhaseSets = {
    APPLIED_VERIFIED: [
      ['receiptProbe', 'cleanupProbe', 'forwardApply', 'forwardVerify',
        'auditApply', 'auditReceipt', 'auditVerify'],
      ['receiptProbe', 'cleanupProbe', 'cleanupPreflight', 'cleanupApply',
        'forwardApply', 'forwardVerify', 'auditApply', 'auditReceipt', 'auditVerify']
    ],
    RESUMED_AUDIT_APPLIED_VERIFIED: [[
      'receiptProbe', 'priorForwardReceipt', 'priorForwardVerify', 'priorAuditReceipt',
      'auditApply', 'auditReceipt', 'auditVerify'
    ]],
    PRIOR_APPLIED_VERIFIED: [[
      'receiptProbe', 'priorForwardReceipt', 'priorForwardVerify',
      'priorAuditReceipt', 'priorAuditVerify'
    ]]
  };
  const failureTerminalPhase = {
    CNYOS_EXACT_STAGING_DATABASE_IDENTITY_PROBE_FAILED: 'receiptProbe',
    CNYOS_EXACT_STAGING_DATABASE_RECEIPT_PROBE_INVALID: 'receiptProbe',
    CNYOS_EXACT_STAGING_DATABASE_PRIOR_RECEIPT_VERIFY_FAILED: 'priorForwardReceipt',
    CNYOS_EXACT_STAGING_DATABASE_FOREIGN_RECEIPT_STATE: 'priorForwardReceipt',
    CNYOS_EXACT_STAGING_DATABASE_PRIOR_RECEIPT_INVALID: 'priorForwardReceipt',
    CNYOS_EXACT_STAGING_DATABASE_PRIOR_FORWARD_VERIFY_FAILED: 'priorForwardVerify',
    CNYOS_EXACT_STAGING_DATABASE_PRIOR_AUDIT_RECEIPT_VERIFY_FAILED: 'priorAuditReceipt',
    CNYOS_EXACT_STAGING_DATABASE_PRIOR_AUDIT_RECEIPT_INVALID: 'priorAuditReceipt',
    CNYOS_EXACT_STAGING_DATABASE_PRIOR_AUDIT_VERIFY_FAILED: 'priorAuditVerify',
    CNYOS_EXACT_STAGING_CLEANUP_PROBE_FAILED: 'cleanupProbe',
    CNYOS_EXACT_STAGING_CLEANUP_UNKNOWN_DRIFT: 'cleanupProbe',
    CNYOS_EXACT_STAGING_CLEANUP_PREFLIGHT_FAILED: 'cleanupPreflight',
    CNYOS_EXACT_STAGING_CLEANUP_APPLY_FAILED: 'cleanupApply',
    CNYOS_EXACT_STAGING_DATABASE_FORWARD_APPLY_FAILED: 'forwardApply',
    CNYOS_EXACT_STAGING_DATABASE_FORWARD_VERIFY_FAILED: 'forwardVerify',
    CNYOS_EXACT_STAGING_DATABASE_AUDIT_APPLY_FAILED: 'auditApply',
    CNYOS_EXACT_STAGING_DATABASE_AUDIT_RECEIPT_FAILED: 'auditReceipt',
    CNYOS_EXACT_STAGING_DATABASE_AUDIT_VERIFY_FAILED: 'auditVerify'
  };
  const phasePaths = [
    ...Object.values(passPhaseSets).flat()
  ];
  const phaseNames = plainObject(database?.phases) ? Object.keys(database.phases) : [];
  const expectedPassPhaseSets = passPhaseSets[database?.result] || [];
  const passShape = database?.status === 'PASS' &&
    expectedPassPhaseSets.some(expected =>
      JSON.stringify(phaseNames) === JSON.stringify(expected)) &&
    phaseNames.every(name => validDatabaseCommandEvidence(database.phases[name]));
  const failurePhase = failureTerminalPhase[database?.result];
  const failureCommandOutcomeValid = !String(database?.result || '').endsWith('_FAILED') ||
    (failurePhase && !validDatabaseCommandEvidence(database?.phases?.[failurePhase]));
  const failurePrefix = database?.status === 'FAIL' &&
    /^CNYOS_[A-Z0-9_]+$/.test(String(database?.result || '')) &&
    (phaseNames.length === 0 || phasePaths.some(candidate =>
      phaseNames.every((name, index) => candidate[index] === name))) &&
    phaseNames.every(name => validDatabaseCommandEvidence(database.phases[name], false)) &&
    (!failurePhase || phaseNames.at(-1) === failurePhase) && failureCommandOutcomeValid;
  if (database?.schemaVersion !== 1 ||
    database?.kind !== 'cnyos_exact_staging_database_reconciliation' ||
    (!passShape && !failurePrefix) ||
    database?.stagingOnly !== true || database?.productionAuthorized !== false ||
    database?.resetAttempted !== false || database?.historicalLedgerReplayed !== false ||
    database?.realPatientDataRead !== false ||
    database?.automaticRollbackAttempted !== false ||
    database?.forwardRemediationRequiredOnFailure !== true ||
    database?.nonAtomicPhaseBoundary !== true ||
    !exactControllerBinding(config, {
      repository: CONTROLLER_REPOSITORY, commit: database?.controller?.commit,
      workflowPath: CONTROLLER_WORKFLOW_PATH
    }) || !exactSourceBinding(config, database?.source) ||
    database?.target?.projectRef !== EXACT_STAGING_TARGET.supabaseProjectRef ||
    database?.target?.systemIdentifier !== '7666007964130682852' ||
    database?.target?.database !== 'postgres' ||
    database?.artifact?.databaseManifestSha256 !==
      binding?.artifact?.databaseManifestSha256 ||
    database?.artifact?.databaseTreeSha256 !== binding?.artifact?.databaseTreeSha256 ||
    !SHA256.test(String(database?.artifact?.reconciliationArtifactSha256 || '')) ||
    !SHA256.test(String(database?.artifact?.auditMigrationSha256 || '')) ||
    database?.artifact?.cleanupArtifactSha256 !==
      'd9c89e85d740b8d5fc0d7542d033688dca090f07083f8dd41d1c84c6821e7d15' ||
    !UUID.test(String(database?.attemptId || '')) ||
    !UUID.test(String(database?.forwardAttemptId || '')) ||
    !UUID.test(String(database?.auditAttemptId || '')) ||
    database?.attemptId !== database?.forwardAttemptId ||
    database?.forwardAttemptId === database?.auditAttemptId ||
    !validIsoTimestamp(database?.startedAt) || !validIsoTimestamp(database?.completedAt) ||
    Date.parse(database.completedAt) < Date.parse(database.startedAt)) {
    fail('CNYOS_EXACT_STAGING_DATABASE_RECONCILIATION_INVALID');
  }
}

async function observeEvidenceSet(config, expected) {
  const actual = (await fs.readdir(config.uploadDirectory))
    .filter(name => name !== 'terminal-evidence.json').sort();
  let valid = JSON.stringify(actual) === JSON.stringify(expected);
  const entries = [];
  const observedFiles = new Map();
  for (const name of actual) {
    const filename = path.join(config.uploadDirectory, name);
    const stat = await fs.lstat(filename);
    let jsonValid = false;
    let bytes = Buffer.alloc(0);
    if (stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o600) {
      bytes = await fs.readFile(filename);
      try { jsonValid = plainObject(JSON.parse(bytes.toString('utf8'))); }
      catch { jsonValid = false; }
    }
    if (!jsonValid) valid = false;
    const entry = { name, size: bytes.length, sha256: sha256(bytes), jsonValid };
    entries.push(entry);
    observedFiles.set(name, entry);
  }
  return { actual, valid, entries, observedFiles };
}

function expectedEvidenceNames(reconciliation, uat) {
  const base = [
    'candidate-binding.json', 'publish-attempt.json', 'publish-intent.json',
    'publish-reconciliation.json', 'rollback-baseline.json', 'database-reconciliation.json'
  ];
  if (reconciliation.status !== 'PASS') return base.sort();
  const withUat = [...base, 'deploy-receipt.json', 'uat-evidence.json'];
  if (uat?.status === 'PASS') withUat.push('evidence-manifest.json', 'fixture-evidence.json');
  return withUat.sort();
}

export function deriveExactStagingTerminalStatus(reconciliationStatus, uatStatus,
  evidenceSetValid = true) {
  if (reconciliationStatus === 'UNCERTAIN') return 'UNCERTAIN';
  if (reconciliationStatus !== 'PASS') return 'FAIL';
  if (uatStatus === 'UNCERTAIN') return 'UNCERTAIN';
  if (uatStatus !== 'PASS' || !evidenceSetValid) return 'FAIL';
  return 'PASS';
}

export async function finalizeExactStagingEvidence(config, { now = () => new Date().toISOString() } = {}) {
  assertFixedTarget(config);
  const bindingFile = await readJson(path.join(config.uploadDirectory, 'candidate-binding.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  const baselineFile = await readJson(path.join(config.uploadDirectory, 'rollback-baseline.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  assertCandidateBinding(config, bindingFile.value, baselineFile.value);
  const databaseFile = await readJson(
    path.join(config.uploadDirectory, 'database-reconciliation.json'),
    'CNYOS_EXACT_STAGING_DATABASE_RECONCILIATION_INVALID');
  const database = databaseFile.value;
  assertDatabaseReconciliationEvidence(config, database, bindingFile.value);
  if (database.status !== 'PASS') {
    const expected = [
      'candidate-binding.json', 'database-reconciliation.json', 'rollback-baseline.json'
    ].sort();
    const observed = await observeEvidenceSet(config, expected);
    const terminal = {
      schemaVersion: 1,
      kind: 'cnyos_exact_staging_terminal_evidence',
      status: 'FAIL',
      stagingOnly: true,
      productionAuthorized: false,
      controller: bindingFile.value.controller,
      source: { commit: config.appCommit, tree: config.appTree },
      target: { siteId: EXACT_STAGING_TARGET.netlifySiteId, origin: EXACT_STAGING_TARGET.origin },
      publishReconciliation: {
        status: 'NOT_RUN', result: 'DATABASE_RECONCILIATION_FAILED', deployId: null
      },
      databaseReconciliation: { status: database.status, result: database.result,
        attemptId: database.attemptId },
      uatStatus: 'NOT_RUN',
      evidenceSetValid: observed.valid,
      expectedEvidenceNames: expected,
      evidence: observed.entries,
      automaticRollbackAuthorized: false,
      automaticRollbackAttempted: false,
      completedAt: now()
    };
    assertSecretFreeEvidence(terminal);
    await writeFresh0600(path.join(config.uploadDirectory, 'terminal-evidence.json'), terminal);
    return terminal;
  }
  const intentFile = await readJson(path.join(config.uploadDirectory, 'publish-intent.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_INTENT_INVALID');
  const attemptFile = await readJson(path.join(config.uploadDirectory, 'publish-attempt.json'),
    'CNYOS_EXACT_STAGING_PUBLISH_ATTEMPT_INVALID');
  assertPublishChain(config, bindingFile.value, baselineFile.value, intentFile, attemptFile.value);
  const reconciliationFile = await readJson(
    path.join(config.uploadDirectory, 'publish-reconciliation.json'),
    'CNYOS_EXACT_STAGING_RECONCILIATION_EVIDENCE_MISSING');
  const reconciliation = reconciliationFile.value;
  const reconciledDeployId = assertReconciliationEvidence(config, reconciliation, attemptFile.value);
  let receipt = null;
  let uat = null;
  let fixture = null;
  let manifest = null;
  if (reconciliation.status === 'PASS') {
    const receiptFile = await readJson(path.join(config.uploadDirectory, 'deploy-receipt.json'),
      'CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID');
    receipt = receiptFile.value;
    assertDeployReceiptEvidence(config, receipt, reconciledDeployId);
    const uatFile = await readJson(path.join(config.uploadDirectory, 'uat-evidence.json'),
      'CNYOS_EXACT_STAGING_UAT_EVIDENCE_INVALID');
    uat = uatFile.value;
    assertUatEvidence(config, uat, receipt, reconciledDeployId);
    if (uat.status === 'PASS') {
      const fixtureFile = await readJson(path.join(config.uploadDirectory, 'fixture-evidence.json'),
        'CNYOS_EXACT_STAGING_FIXTURE_EVIDENCE_INVALID');
      fixture = fixtureFile.value;
      assertFixtureEvidence(config, fixture, uat, reconciledDeployId);
      const manifestFile = await readJson(path.join(config.uploadDirectory,
        'evidence-manifest.json'), 'CNYOS_EXACT_STAGING_EVIDENCE_MANIFEST_INVALID');
      manifest = manifestFile.value;
    }
  }
  const expected = expectedEvidenceNames(reconciliation, uat);
  const observed = await observeEvidenceSet(config, expected);
  let evidenceSetValid = observed.valid;
  if (manifest) assertEvidenceManifest(config, manifest, observed.observedFiles, reconciledDeployId);
  const status = deriveExactStagingTerminalStatus(reconciliation.status, uat?.status || null,
    evidenceSetValid);
  const terminal = {
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_terminal_evidence',
    status,
    stagingOnly: true,
    productionAuthorized: false,
    controller: reconciliation.controller,
    source: { commit: config.appCommit, tree: config.appTree },
    target: { siteId: EXACT_STAGING_TARGET.netlifySiteId, origin: EXACT_STAGING_TARGET.origin },
    publishReconciliation: {
      status: reconciliation.status,
      result: reconciliation.result,
      deployId: reconciliation.normalizedDeployId || null
    },
    databaseReconciliation: { status: database.status, result: database.result,
      attemptId: database.attemptId },
    uatStatus: uat?.status || 'NOT_RUN',
    evidenceSetValid,
    expectedEvidenceNames: expected,
    evidence: observed.entries,
    automaticRollbackAuthorized: false,
    automaticRollbackAttempted: false,
    completedAt: now()
  };
  assertSecretFreeEvidence(terminal);
  await writeFresh0600(path.join(config.uploadDirectory, 'terminal-evidence.json'), terminal);
  return terminal;
}

async function main() {
  const action = process.argv[2];
  const config = loadExactStagingConfig();
  if (action === 'attempt') {
    await executeExactStagingPublishAttempt(config,
      process.env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN);
    return;
  }
  if (action === 'reconcile') {
    const evidence = await reconcileExactStagingPublish(config,
      process.env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN);
    process.stdout.write(`Exact staging publish reconciliation: ${evidence.status}\n`);
    return;
  }
  if (action === 'finalize') {
    const terminal = await finalizeExactStagingEvidence(config);
    process.stdout.write(`Exact staging terminal evidence: ${terminal.status}\n`);
    if (terminal.status !== 'PASS') process.exitCode = 1;
    return;
  }
  fail('CNYOS_EXACT_STAGING_PUBLISH_ACTION_INVALID');
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();
