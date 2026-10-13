import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  EXACT_STAGING_PRODUCTION_DENYLIST,
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
const TERMINAL_DEPLOY_FAILURE_STATES = new Set(['error', 'failed', 'canceled', 'cancelled']);
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const RECONCILIATION_ATTEMPTS = 6;
const RECONCILIATION_DELAY_MS = 5_000;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
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

function assertCandidateBinding(config, binding, baseline) {
  if (binding?.kind !== 'cnyos_exact_staging_candidate_binding' ||
    binding?.stagingOnly !== true || binding?.productionAuthorized !== false ||
    binding?.source?.commit !== config.appCommit || binding?.source?.tree !== config.appTree ||
    binding?.target?.siteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    binding?.target?.origin !== EXACT_STAGING_TARGET.origin ||
    binding?.target?.supabaseProjectRef !== EXACT_STAGING_TARGET.supabaseProjectRef ||
    binding?.rollbackBaselineDeployId !== config.rollbackDeployId ||
    !SHA256.test(String(binding?.artifact?.deployManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.runtimeManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.functionManifestSha256 || '')) ||
    !SHA256.test(String(binding?.artifact?.functionTreeSha256 || '')) ||
    baseline?.kind !== 'cnyos_exact_staging_rollback_baseline' ||
    baseline?.siteId !== EXACT_STAGING_TARGET.netlifySiteId ||
    baseline?.deployId !== config.rollbackDeployId) {
    fail('CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID');
  }
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
      functionTreeSha256: binding.artifact.functionTreeSha256
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
    'CNYOS_EXACT_STAGING_GITHUB_WORKSPACE_REQUIRED'), 'candidate-source')
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
  const intent = intentFile.value;
  const attempt = attemptFile.value;
  const intentHashValid = attempt?.intentSha256 === sha256(intentFile.bytes) ||
    attempt?.intentSha256 === sha256(Buffer.from(JSON.stringify(intent)));
  if (intent?.kind !== 'cnyos_exact_staging_publish_intent' ||
    attempt?.kind !== 'cnyos_exact_staging_publish_attempt' ||
    intent?.source?.commit !== config.appCommit || intent?.source?.tree !== config.appTree ||
    attempt?.source?.commit !== config.appCommit || attempt?.source?.tree !== config.appTree ||
    !intentHashValid) {
    fail('CNYOS_EXACT_STAGING_PUBLISH_CHAIN_INVALID');
  }

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
        bindingFile.value.artifact.runtimeManifestSha256, { fetchImpl });
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

function expectedEvidenceNames(reconciliation, uat) {
  const base = [
    'candidate-binding.json', 'publish-attempt.json', 'publish-intent.json',
    'publish-reconciliation.json', 'rollback-baseline.json'
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
  const reconciliationFile = await readJson(
    path.join(config.uploadDirectory, 'publish-reconciliation.json'),
    'CNYOS_EXACT_STAGING_RECONCILIATION_EVIDENCE_MISSING');
  const reconciliation = reconciliationFile.value;
  const uatFile = await readJson(path.join(config.uploadDirectory, 'uat-evidence.json'),
    'CNYOS_EXACT_STAGING_UAT_EVIDENCE_INVALID', { optional: true }).catch(() => null);
  const uat = uatFile?.value || null;
  const expected = expectedEvidenceNames(reconciliation, uat);
  const actual = (await fs.readdir(config.uploadDirectory))
    .filter(name => name !== 'terminal-evidence.json').sort();
  let evidenceSetValid = JSON.stringify(actual) === JSON.stringify(expected);
  const entries = [];
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
    if (!jsonValid) evidenceSetValid = false;
    entries.push({ name, size: bytes.length, sha256: sha256(bytes), jsonValid });
  }
  const status = deriveExactStagingTerminalStatus(reconciliation.status, uat?.status || null,
    evidenceSetValid);
  const terminal = {
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_terminal_evidence',
    status,
    stagingOnly: true,
    productionAuthorized: false,
    source: { commit: config.appCommit, tree: config.appTree },
    target: { siteId: EXACT_STAGING_TARGET.netlifySiteId, origin: EXACT_STAGING_TARGET.origin },
    publishReconciliation: {
      status: reconciliation.status,
      result: reconciliation.result,
      deployId: reconciliation.normalizedDeployId || null
    },
    uatStatus: uat?.status || 'NOT_RUN',
    evidenceSetValid,
    expectedEvidenceNames: expected,
    evidence: entries,
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
