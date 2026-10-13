import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  BOUNDED_TREATMENT_ACK,
  BOUNDED_TREATMENT_TARGET,
  canonicalFixtureSha256,
  canonicalJson,
  executeBoundedTreatmentUat,
  loadBoundedTreatmentConfig,
  preflightExactDeployment,
  readDeploymentBindingEvidence,
  validateBoundedTreatmentRunAuthorization,
  writeEvidenceExclusive
} from './bounded-treatment-uat.mjs';
import {
  LOCAL_CONTROLLER_KIND,
  assertLocalExactRemotePrHeadControllerRuntime
} from './local-controller-runtime.mjs';
import { POLICY_SHA256 } from './policy.mjs';
import {
  SINGLE_FIXTURE_AUTHORIZATION_DECISION,
  SINGLE_FIXTURE_PROVISION_ACK,
  runSingleFixtureProvisioning
} from './provision-bounded-treatment-fixture.mjs';

export const LOCAL_UAT_ACK = 'I_AUTHORIZE_ONE_FIXTURE_AND_EXACTLY_TWO_TREATMENT_WRITES';

const RUN_AUTHORIZATION_DECISION = 'authorize_exactly_two_synthetic_treatment_writes';
const MAX_JSON_BYTES = 1024 * 1024;
const AUTHORIZATION_LIFETIME_MS = 25 * 60 * 1000;
const SHA40 = /^[0-9a-f]{40}$/;
const NETLIFY_DEPLOY_ID = /^[0-9a-f]{24}$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE_BIN = process.execPath;
const NPM_BIN = path.join(path.dirname(NODE_BIN), 'npm');
const ARTIFACT_NAMES = Object.freeze([
  'local-controller-admission.json',
  'local-controller-authorization-bundle.json',
  'provisioning-evidence.json',
  'treatment-run-authorization.json',
  'uat-evidence.json',
  'evidence-manifest.json'
]);
const MUTATION_PHASES = Object.freeze([
  'no_dispatch',
  'fixture_dispatch_started',
  'fixture_passed',
  'treatment_write_1_dispatched',
  'treatment_write_2_dispatched'
]);
const FIXTURE_MUTATION_PATHS = new Set([
  '/auth/v1/admin/users',
  '/rest/v1/profiles',
  '/rest/v1/clinic_memberships',
  '/rest/v1/rpc/upsert_patient_registration',
  '/rest/v1/rpc/start_manual_patient_encounter'
]);

export class LocalBoundedTreatmentError extends Error {
  constructor(code) {
    super(code);
    this.name = 'LocalBoundedTreatmentError';
    this.code = code;
  }
}

function fail(code) {
  throw new LocalBoundedTreatmentError(code);
}

function required(value, code, maximum = 4096) {
  const normalized = String(value ?? '').trim();
  if (!normalized || normalized.length > maximum) fail(code);
  return normalized;
}

function exactLowercase(value, pattern, code, maximum) {
  const normalized = required(value, code, maximum).toLowerCase();
  if (!pattern.test(normalized)) fail(code);
  return normalized;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

async function runCleanDependencyCommand(filename, args, cwd, runtimeRoot) {
  const home = path.join(runtimeRoot, 'home');
  const cache = path.join(runtimeRoot, 'npm-cache');
  const browsers = path.join(runtimeRoot, 'playwright-browsers');
  for (const directory of [home, cache, browsers]) {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    await fs.chmod(directory, 0o700);
  }
  const env = {
    HOME: home,
    PATH: `${path.dirname(NODE_BIN)}:/usr/bin:/bin`,
    TMPDIR: runtimeRoot,
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_ignore_scripts: 'true',
    npm_config_update_notifier: 'false',
    npm_config_userconfig: '/dev/null',
    PLAYWRIGHT_BROWSERS_PATH: browsers
  };
  try {
    await promisify(execFile)(filename, args, {
      cwd, env, encoding: 'utf8', timeout: 10 * 60_000,
      maxBuffer: MAX_JSON_BYTES, windowsHide: true
    });
  } catch {
    fail('CNYOS_LOCAL_UAT_LOCKED_RUNTIME_INSTALL_FAILED');
  }
  return browsers;
}

async function installFreshLockedChromium(workDirectory) {
  const runtimeRoot = path.join(workDirectory, 'locked-runtime');
  await createFresh0700Directory(runtimeRoot, 'CNYOS_LOCAL_UAT_LOCKED_RUNTIME_INVALID');
  for (const name of ['package.json', 'package-lock.json']) {
    const source = path.join(PACKAGE_ROOT, name);
    const destination = path.join(runtimeRoot, name);
    const bytes = await fs.readFile(source);
    await writeFresh0600(destination, bytes);
  }
  const npmRealPath = await fs.realpath(NPM_BIN)
    .catch(() => fail('CNYOS_LOCAL_UAT_NPM_INVALID'));
  const nodePrefix = await fs.realpath(path.resolve(path.dirname(NODE_BIN), '..'))
    .catch(() => fail('CNYOS_LOCAL_UAT_NPM_INVALID'));
  if (!npmRealPath.startsWith(`${nodePrefix}${path.sep}`)) fail('CNYOS_LOCAL_UAT_NPM_INVALID');
  const browsers = await runCleanDependencyCommand(NPM_BIN,
    ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], runtimeRoot, runtimeRoot);
  await runCleanDependencyCommand(NODE_BIN,
    [path.join(runtimeRoot, 'node_modules/playwright/cli.js'), 'install', 'chromium'],
    runtimeRoot, runtimeRoot);
  const requireFromRuntime = createRequire(path.join(runtimeRoot, 'package.json'));
  const resolved = await fs.realpath(requireFromRuntime.resolve('playwright'))
    .catch(() => fail('CNYOS_LOCAL_UAT_PLAYWRIGHT_INVALID'));
  const nodeModulesRoot = await fs.realpath(path.join(runtimeRoot, 'node_modules'))
    .catch(() => fail('CNYOS_LOCAL_UAT_PLAYWRIGHT_INVALID'));
  if (!resolved.startsWith(`${nodeModulesRoot}${path.sep}`)) {
    fail('CNYOS_LOCAL_UAT_PLAYWRIGHT_INVALID');
  }
  process.env.PLAYWRIGHT_BROWSERS_PATH = browsers;
  const playwright = requireFromRuntime('playwright');
  if (!playwright?.chromium?.launch) fail('CNYOS_LOCAL_UAT_PLAYWRIGHT_INVALID');
  return playwright.chromium;
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`);
}

function runtimeEvidence(runtime) {
  return Object.freeze({
    kind: LOCAL_CONTROLLER_KIND,
    repository: runtime.repository,
    ref: runtime.ref,
    commit: runtime.commit,
    tree: runtime.tree,
    entrypoint: runtime.workflowPath,
    runId: runtime.runId,
    pullRequestNumber: runtime.pullRequestNumber,
    requiredChecks: runtime.requiredChecks,
    policySha256: runtime.policySha256,
    sourceManifestSha256: runtime.sourceManifestSha256,
    packageLockSha256: runtime.packageLockSha256,
    operatorIdentitySha256: runtime.operatorIdentitySha256,
    independentReviewerApproval: false,
    productionAuthorization: false
  });
}

export function buildExpectedLocalProvisioningPlan(config, operationIds) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'single_bounded_treatment_fixture_provisioning_plan',
    controller: Object.freeze({
      repository: config.runtime.repository,
      ref: config.runtime.ref,
      commit: config.runtime.commit,
      workflowPath: config.runtime.workflowPath,
      runId: config.runtime.runId,
      runAttempt: 1
    }),
    policySha256: POLICY_SHA256,
    target: BOUNDED_TREATMENT_TARGET,
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployId: config.deployId,
    fixtureRunId: config.fixtureRunId,
    practitioner: Object.freeze({
      email: config.practitionerEmail,
      fullName: config.practitionerFullName,
      role: 'practitioner',
      markers: Object.freeze({
        synthetic_staging_only: true,
        expected_role: 'practitioner',
        fixture_run_id: config.fixtureRunId
      })
    }),
    patient: Object.freeze({
      paymentRight: 'SYNTHETIC-E2E',
      realIdentifiersAbsent: true,
      allergyRowsExpected: 0
    }),
    encounter: Object.freeze({
      status: 'draft',
      treatmentSessionRowsExpected: 0,
      prescriptionRowsExpected: 0,
      vitalSignRowsExpected: 0,
      painAssessmentRowsExpected: 0
    }),
    operationIds: Object.freeze([...operationIds]),
    limits: Object.freeze({
      freshAuthUsers: 1,
      serviceRoleTableWrites: 2,
      authenticatedClinicalRpcWrites: 2,
      writeRetries: 0,
      cleanupAuthorized: false
    })
  });
}

export function validateLocalProvisioningAdmissionRequest(config, request) {
  let requestPlanCanonical = null;
  try { requestPlanCanonical = canonicalJson(request?.plan); }
  catch { requestPlanCanonical = null; }
  const operationIds = request?.plan?.operationIds;
  const operationsValid = Array.isArray(operationIds) && operationIds.length === 2 &&
    operationIds.every(value => typeof value === 'string' && value === value.toLowerCase() &&
      UUID_V4.test(value)) && new Set(operationIds).size === 2;
  const expectedPlanCanonical = operationsValid
    ? canonicalJson(buildExpectedLocalProvisioningPlan(config, operationIds))
    : null;
  const observedPlanSha256 = typeof requestPlanCanonical === 'string'
    ? sha256(Buffer.from(requestPlanCanonical))
    : null;
  if (!request || request.runtime !== config.runtime ||
    request.planSha256 !== observedPlanSha256 ||
    requestPlanCanonical !== expectedPlanCanonical) {
    fail('CNYOS_LOCAL_UAT_ADMISSION_REQUEST_INVALID');
  }
  return true;
}

async function createFresh0700Directory(filename, code) {
  const parent = path.dirname(filename);
  const parentStatus = await fs.lstat(parent).catch(() => null);
  if (!parentStatus?.isDirectory() || parentStatus.isSymbolicLink()) fail(code);
  const existing = await fs.lstat(filename).catch(error => {
    if (error?.code === 'ENOENT') return null;
    fail(code);
  });
  if (existing) fail(code);
  await fs.mkdir(filename, { mode: 0o700 });
  const status = await fs.lstat(filename);
  if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o700) {
    fail(code);
  }
}

async function writeFresh0600(filename, bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_JSON_BYTES) {
    fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID');
  }
  let handle;
  try {
    handle = await fs.open(filename, fsConstants.O_WRONLY | fsConstants.O_CREAT |
      fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    const status = await fs.lstat(filename);
    if (!status.isFile() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o600 ||
      status.size !== bytes.length) fail('CNYOS_LOCAL_UAT_EVIDENCE_WRITE_INVALID');
  } catch (error) {
    if (error instanceof LocalBoundedTreatmentError) throw error;
    fail('CNYOS_LOCAL_UAT_EVIDENCE_WRITE_FAILED');
  } finally {
    await handle?.close().catch(() => {});
  }
  return Object.freeze({ name: path.basename(filename), sha256: sha256(bytes),
    bytes: bytes.length });
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, fsConstants.O_RDONLY);
    await handle.sync();
  } catch { fail('CNYOS_LOCAL_UAT_PHASE_SYNC_FAILED'); }
  finally { await handle?.close().catch(() => {}); }
}

export async function createLocalMutationPhaseJournal(workDirectory, {
  now = () => new Date()
} = {}) {
  const directory = path.join(workDirectory, 'mutation-phases');
  await createFresh0700Directory(directory, 'CNYOS_LOCAL_UAT_PHASE_DIRECTORY_INVALID');
  let index = 0;
  let terminal = false;
  const write = async (name, value) => {
    const record = await writeFresh0600(path.join(directory, name), canonicalBytes(value));
    await syncDirectory(directory);
    return record;
  };
  const phaseValue = (phase, details = {}) => Object.freeze({
    schemaVersion: 1,
    kind: 'cnyos_local_bounded_treatment_mutation_phase',
    phase,
    phaseOrdinal: MUTATION_PHASES.indexOf(phase),
    observedAt: now().toISOString(),
    syntheticOnly: true,
    productionAuthorization: false,
    ...details,
    secretsSerialized: false
  });
  await write('00-no_dispatch.json', phaseValue('no_dispatch'));
  return Object.freeze({
    directory,
    get phase() { return MUTATION_PHASES[index]; },
    get hasDispatch() { return index >= 1; },
    get treatmentWritesDispatched() { return Math.max(0, index - 2); },
    async advance(phase, details = {}) {
      const next = MUTATION_PHASES.indexOf(phase);
      if (terminal || next < 1 || next >= MUTATION_PHASES.length || next < index ||
        next > index + 1) fail('CNYOS_LOCAL_UAT_PHASE_TRANSITION_INVALID');
      if (next === index) return;
      await write(`${String(next).padStart(2, '0')}-${phase}.json`,
        phaseValue(phase, details));
      index = next;
    },
    async finish(value) {
      if (terminal) fail('CNYOS_LOCAL_UAT_TERMINAL_EVIDENCE_EXISTS');
      await write(`90-terminal-${String(value.status || '').toLowerCase()}.json`, value);
      terminal = true;
    }
  });
}

function assertNoSecrets(bytes, secrets) {
  const text = bytes.toString('utf8');
  let value;
  try { value = JSON.parse(text); }
  catch { fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID'); }
  const strings = [];
  const visit = item => {
    if (typeof item === 'string') strings.push(item);
    else if (Array.isArray(item)) item.forEach(visit);
    else if (item && typeof item === 'object') Object.entries(item).forEach(([key, child]) => {
      strings.push(key);
      visit(child);
    });
  };
  visit(value);
  if (secrets.some(secret => secret &&
    (text.includes(secret) || strings.some(item => item.includes(secret))))) {
    fail('CNYOS_LOCAL_UAT_SECRET_SERIALIZATION_BLOCKED');
  }
}

async function writeSecretFree(filename, value, secrets) {
  if (value?.secretsSerialized !== false) fail('CNYOS_LOCAL_UAT_SECRET_MARKER_INVALID');
  const bytes = canonicalBytes(value);
  assertNoSecrets(bytes, secrets);
  return writeFresh0600(filename, bytes);
}

async function copySecretFreeEvidence(source, destination, secrets) {
  let handle;
  let bytes;
  try {
    handle = await fs.open(source, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const linked = await fs.lstat(source, { bigint: true });
    if (!before.isFile() || !linked.isFile() || linked.isSymbolicLink() ||
      before.dev !== linked.dev || before.ino !== linked.ino || before.size < 2n ||
      before.size > BigInt(MAX_JSON_BYTES)) fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID');
    bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
      bytes.length !== Number(before.size)) fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID');
  } catch (error) {
    if (error instanceof LocalBoundedTreatmentError) throw error;
    fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID');
  } finally {
    await handle?.close().catch(() => {});
  }
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID'); }
  if (value?.secretsSerialized !== false) fail('CNYOS_LOCAL_UAT_SECRET_MARKER_INVALID');
  assertNoSecrets(bytes, secrets);
  const record = await writeFresh0600(destination, bytes);
  return Object.freeze({ ...record, status: value.status || null });
}

function createLocalAdmissionHook(config, records) {
  let used = false;
  return async request => {
    if (used) fail('CNYOS_LOCAL_UAT_ADMISSION_REPLAYED');
    used = true;
    validateLocalProvisioningAdmissionRequest(config, request);
    const admission = Object.freeze({
      schemaVersion: 1,
      evidenceType: 'cnyos_local_exact_remote_pr_head_staging_admission',
      status: 'authorized',
      decision: SINGLE_FIXTURE_AUTHORIZATION_DECISION,
      scope: 'one_fresh_synthetic_practitioner_patient_draft_encounter',
      syntheticOnly: true,
      realPatientDataAuthorized: false,
      productionAuthorization: false,
      independentReviewerApproval: false,
      authorityBasis: 'sole_operator_explicit_staging_authorization',
      authorizedAt: config.authorizedAt,
      expiresAt: config.expiresAt,
      controller: runtimeEvidence(config.runtime),
      target: BOUNDED_TREATMENT_TARGET,
      exactDeploymentPreflight: config.deploymentPreflight,
      planSha256: request.planSha256,
      source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
      deployId: config.deployId,
      fixtureRunId: config.fixtureRunId,
      practitionerEmailSha256: sha256(Buffer.from(config.practitionerEmail)),
      secretsSerialized: false
    });
    const admissionRecord = await writeSecretFree(path.join(config.evidenceDirectory,
      'local-controller-admission.json'), admission, config.secrets);
    records.push(Object.freeze({ ...admissionRecord, status: 'authorized' }));
    const bundle = Object.freeze({
      schemaVersion: 1,
      kind: 'local_exact_remote_pr_head_single_fixture_authorization_bundle',
      status: 'authorized',
      controller: runtimeEvidence(config.runtime),
      policySha256: POLICY_SHA256,
      planSha256: request.planSha256,
      admissionEvidenceSha256: admissionRecord.sha256,
      targetSha256: sha256(Buffer.from(canonicalJson(BOUNDED_TREATMENT_TARGET))),
      authorizedAt: config.authorizedAt,
      expiresAt: config.expiresAt,
      syntheticOnly: true,
      independentReviewerApproval: false,
      productionAuthorization: false,
      secretsSerialized: false
    });
    const bundleRecord = await writeSecretFree(path.join(config.evidenceDirectory,
      'local-controller-authorization-bundle.json'), bundle, config.secrets);
    records.push(Object.freeze({ ...bundleRecord, status: 'authorized' }));
    return Object.freeze({
      schemaVersion: 1,
      kind: 'controller_verified_single_fixture_admission',
      status: 'authorized',
      decision: SINGLE_FIXTURE_AUTHORIZATION_DECISION,
      controllerRepository: config.runtime.repository,
      controllerRef: config.runtime.ref,
      controllerCommit: config.runtime.commit,
      controllerWorkflowPath: config.runtime.workflowPath,
      controllerRunId: config.runtime.runId,
      policySha256: POLICY_SHA256,
      planSha256: request.planSha256,
      sourceCommit: config.sourceCommit,
      sourceTree: config.sourceTree,
      deployId: config.deployId,
      fixtureRunId: config.fixtureRunId,
      targetSiteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
      targetClinicId: BOUNDED_TREATMENT_TARGET.clinicId,
      authorizedAt: config.authorizedAt,
      expiresAt: config.expiresAt,
      authorizationEvidenceSha256: admissionRecord.sha256,
      authorizationBundleSha256: bundleRecord.sha256
    });
  };
}

function buildRunAuthorization(config, fixture) {
  const value = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_bounded_treatment_run_authorization',
    status: 'authorized',
    decision: RUN_AUTHORIZATION_DECISION,
    scope: 'cnyos_staging_only',
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    authorizedAt: config.authorizedAt,
    expiresAt: config.expiresAt,
    policySha256: POLICY_SHA256,
    controller: Object.freeze({
      repository: config.runtime.repository,
      ref: config.runtime.ref,
      commit: config.runtime.commit,
      workflowPath: config.runtime.workflowPath,
      workflowRef: config.runtime.workflowRef,
      runId: config.runtime.runId,
      runAttempt: 1
    }),
    target: BOUNDED_TREATMENT_TARGET,
    run: Object.freeze({
      runId: config.fixtureRunId,
      sourceCommit: config.sourceCommit,
      sourceTree: config.sourceTree,
      deployId: config.deployId,
      fixtureSha256: canonicalFixtureSha256(fixture)
    })
  });
  validateBoundedTreatmentRunAuthorization(value, {
    runtime: config.runtime,
    runId: config.fixtureRunId,
    sourceCommit: config.sourceCommit,
    sourceTree: config.sourceTree,
    deployId: config.deployId,
    fixture,
    now: new Date(config.authorizedAt)
  });
  return value;
}

async function assertArtifactInventory(config) {
  const entries = await fs.readdir(config.evidenceDirectory, { withFileTypes: true });
  const names = entries.map(entry => entry.name).sort();
  const expected = [...ARTIFACT_NAMES].sort();
  if (entries.some(entry => !entry.isFile() || entry.isSymbolicLink()) ||
    names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    fail('CNYOS_LOCAL_UAT_ARTIFACT_INVENTORY_INVALID');
  }
}

async function writeManifest(config, records, status) {
  const manifest = Object.freeze({
    schemaVersion: 1,
    kind: 'local_exact_remote_pr_head_bounded_treatment_evidence_manifest',
    status,
    controller: runtimeEvidence(config.runtime),
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployId: config.deployId,
    fixtureRunId: config.fixtureRunId,
    files: Object.freeze(records.map(record => Object.freeze({
      name: record.name,
      sha256: record.sha256,
      bytes: record.bytes,
      status: record.status ?? null
    })).sort((left, right) => left.name.localeCompare(right.name))),
    fixtureAndLedgerPublished: false,
    cleanup: Object.freeze({ status: 'NOT_AUTHORIZED', attempted: false }),
    syntheticOnly: true,
    independentReviewerApproval: false,
    productionAuthorization: false,
    secretsSerialized: false
  });
  return writeSecretFree(path.join(config.evidenceDirectory, 'evidence-manifest.json'),
    manifest, config.secrets);
}

export function buildLocalUncertainRecoveryEvidence(config, phaseJournal, error, {
  provisioning = null
} = {}) {
  const fixtureCreated = provisioning?.status === 'PASS' ||
    MUTATION_PHASES.indexOf(phaseJournal.phase) >= MUTATION_PHASES.indexOf('fixture_passed');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'local_bounded_treatment_incomplete_outcome_recovery',
    status: 'UNCERTAIN',
    safeErrorCode: safeCode(error),
    controller: runtimeEvidence(config.runtime),
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployId: config.deployId,
    fixtureRunId: config.fixtureRunId,
    durableMutationPhase: phaseJournal.phase,
    fixtureCreated,
    treatmentWritesDispatched: phaseJournal.treatmentWritesDispatched,
    reconciliationRequired: true,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    cleanup: Object.freeze({ status: 'NOT_AUTHORIZED', attempted: false }),
    observedAt: new Date().toISOString(),
    secretsSerialized: false
  });
}

async function evidenceFileRecord(config, name) {
  const filename = path.join(config.evidenceDirectory, name);
  let bytes;
  try { bytes = await fs.readFile(filename); }
  catch { return null; }
  assertNoSecrets(bytes, config.secrets);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID'); }
  const status = await fs.lstat(filename);
  if (!status.isFile() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o600) {
    fail('CNYOS_LOCAL_UAT_EVIDENCE_INVALID');
  }
  return Object.freeze({ name, sha256: sha256(bytes), bytes: bytes.length,
    status: value.status ?? null });
}

async function writeRecoveryPlaceholder(config, name, recovery) {
  const existing = await evidenceFileRecord(config, name);
  if (existing) return existing;
  const value = name === 'uat-evidence.json' ? recovery : Object.freeze({
    schemaVersion: 1,
    kind: `local_${name.replace(/\.json$/, '').replaceAll('-', '_')}_unavailable`,
    status: 'UNCERTAIN',
    reason: 'workflow_exception_after_dispatch',
    durableMutationPhase: recovery.durableMutationPhase,
    reconciliationRequired: true,
    syntheticOnly: true,
    productionAuthorization: false,
    secretsSerialized: false
  });
  const record = await writeSecretFree(path.join(config.evidenceDirectory, name), value,
    config.secrets);
  return Object.freeze({ ...record, status: 'UNCERTAIN' });
}

async function finalizeLocalUncertainRecovery(config, recovery, {
  provisioning = null
} = {}) {
  const provisioningTarget = path.join(config.evidenceDirectory, 'provisioning-evidence.json');
  if (!(await evidenceFileRecord(config, 'provisioning-evidence.json')) &&
    provisioning?.evidencePath) {
    await copySecretFreeEvidence(provisioning.evidencePath, provisioningTarget,
      config.secrets).catch(() => null);
  }
  const records = [];
  for (const name of ARTIFACT_NAMES.filter(name => name !== 'evidence-manifest.json')) {
    records.push(await writeRecoveryPlaceholder(config, name, recovery));
  }
  if (!(await evidenceFileRecord(config, 'evidence-manifest.json'))) {
    await writeManifest(config, records, 'UNCERTAIN');
  }
  await assertArtifactInventory(config);
}

export async function runLocalBoundedTreatmentWorkflow(env = process.env) {
  const now = () => new Date();
  const fetchImpl = fetch;
  if (env.CNYOS_LOCAL_UAT_ACK !== LOCAL_UAT_ACK) fail('CNYOS_LOCAL_UAT_ACK_REQUIRED');
  // Verify once before preparing any disposable runtime, then re-verify after
  // dependency installation and deployment preflight immediately before the
  // authorization clock begins and the first staging write can occur.
  await assertLocalExactRemotePrHeadControllerRuntime(env);
  const workDirectoryInput = required(env.CNYOS_LOCAL_UAT_WORK_DIRECTORY,
    'CNYOS_LOCAL_UAT_WORK_DIRECTORY_REQUIRED', 4096);
  if (!path.isAbsolute(workDirectoryInput)) fail('CNYOS_LOCAL_UAT_WORK_DIRECTORY_INVALID');
  const workDirectory = path.resolve(workDirectoryInput);
  if (workDirectory === path.parse(workDirectory).root) fail('CNYOS_LOCAL_UAT_WORK_DIRECTORY_INVALID');
  await createFresh0700Directory(workDirectory, 'CNYOS_LOCAL_UAT_WORK_DIRECTORY_NOT_FRESH');
  const evidenceDirectory = path.join(workDirectory, 'evidence');
  await createFresh0700Directory(evidenceDirectory, 'CNYOS_LOCAL_UAT_EVIDENCE_DIRECTORY_INVALID');
  const phaseJournal = await createLocalMutationPhaseJournal(workDirectory, { now });
  const lockedChromium = await installFreshLockedChromium(workDirectory);
  const fixtureDirectory = path.join(workDirectory, 'fixture');
  const uatEvidencePath = path.join(workDirectory, 'uat-evidence.private.json');
  const serviceRoleKey = required(env.CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY,
    'CNYOS_LOCAL_UAT_SERVICE_ROLE_KEY_REQUIRED', 8192);
  const publishableKey = required(env.CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY,
    'CNYOS_LOCAL_UAT_PUBLISHABLE_KEY_REQUIRED', 4096);
  const password = required(env.CNYOS_STAGING_TEST_PASSWORD,
    'CNYOS_LOCAL_UAT_PASSWORD_REQUIRED', 4096);
  const netlifyToken = required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN,
    'CNYOS_LOCAL_UAT_NETLIFY_TOKEN_REQUIRED', 8192);
  const githubToken = required(env.CNYOS_LOCAL_CONTROLLER_GITHUB_READ_TOKEN,
    'CNYOS_LOCAL_CONTROLLER_GITHUB_TOKEN_REQUIRED', 8192);
  const sourceCommit = exactLowercase(env.CNYOS_EXPECTED_SOURCE_COMMIT, SHA40,
    'CNYOS_LOCAL_UAT_SOURCE_COMMIT_INVALID', 40);
  const sourceTree = exactLowercase(env.CNYOS_EXPECTED_SOURCE_TREE, SHA40,
    'CNYOS_LOCAL_UAT_SOURCE_TREE_INVALID', 40);
  const deployId = exactLowercase(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, NETLIFY_DEPLOY_ID,
    'CNYOS_LOCAL_UAT_DEPLOY_ID_INVALID', 24);
  const deploymentBindingEvidence = await readDeploymentBindingEvidence(env, {
    sourceCommit,
    sourceTree,
    deployId
  }, now());
  const practitionerEmail = required(env.CNYOS_STAGING_PRACTITIONER_EMAIL,
    'CNYOS_LOCAL_UAT_PRACTITIONER_EMAIL_REQUIRED', 320).toLowerCase();
  if (!/^synthetic[A-Za-z0-9._+-]*@[A-Za-z0-9.-]+\.invalid$/.test(practitionerEmail)) {
    fail('CNYOS_LOCAL_UAT_SYNTHETIC_EMAIL_REQUIRED');
  }
  const fixtureRunId = required(env.CNYOS_TREATMENT_UAT_RUN_ID,
    'CNYOS_LOCAL_UAT_RUN_ID_INVALID', 96);
  if (!RUN_ID.test(fixtureRunId)) fail('CNYOS_LOCAL_UAT_RUN_ID_INVALID');
  const deploymentPreflight = await preflightExactDeployment(Object.freeze({
    sourceCommit,
    sourceTree,
    deployId,
    netlifyToken,
    deploymentBindingEvidence,
    immutableOrigin:
      `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`
  }), { fetchImpl, now });
  const runtime = await assertLocalExactRemotePrHeadControllerRuntime(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_LOCAL_UAT_TIME_INVALID');
  }
  const authorizedAt = observedAt.toISOString();
  const expiresAt = new Date(observedAt.getTime() + AUTHORIZATION_LIFETIME_MS).toISOString();
  const config = Object.freeze({
    runtime,
    workDirectory,
    evidenceDirectory,
    fixtureDirectory,
    uatEvidencePath,
    authorizedAt,
    expiresAt,
    fixtureRunId,
    sourceCommit,
    sourceTree,
    deployId,
    deploymentPreflight,
    practitionerEmail,
    practitionerFullName: `Synthetic E2E Practitioner ${fixtureRunId}`,
    secrets: Object.freeze([
      serviceRoleKey,
      publishableKey,
      password,
      netlifyToken,
      githubToken
    ])
  });
  const records = [];
  let provisioning = null;
  let uat = null;
  const fixtureFetch = async (input, options = {}) => {
    let parsed;
    try { parsed = new URL(input); }
    catch { return fetchImpl(input, options); }
    if (String(options.method || 'GET').toUpperCase() === 'POST' &&
      FIXTURE_MUTATION_PATHS.has(parsed.pathname)) {
      await phaseJournal.advance('fixture_dispatch_started', {
        requestPath: parsed.pathname
      });
    }
    return fetchImpl(input, options);
  };
  try {
    provisioning = await runSingleFixtureProvisioning({
      ...env,
      CNYOS_SINGLE_FIXTURE_PROVISION_MODE: 'LIVE',
      CNYOS_SINGLE_FIXTURE_PROVISION_ACK: SINGLE_FIXTURE_PROVISION_ACK,
      CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY: fixtureDirectory,
      CNYOS_STAGING_PRACTITIONER_FULL_NAME: config.practitionerFullName
    }, {
      fetchImpl: fixtureFetch,
      authorizationHook: createLocalAdmissionHook(config, records),
      now,
      randomUUID: () => crypto.randomUUID(),
      controllerRuntime: runtime
    });
    const expectedProvisioningEvidencePath = path.join(fixtureDirectory, 'result',
      'provisioning-evidence.json');
    if (path.resolve(provisioning.evidencePath || '') !== expectedProvisioningEvidencePath) {
      fail('CNYOS_LOCAL_UAT_PROVISIONING_EVIDENCE_PATH_INVALID');
    }
    records.push(await copySecretFreeEvidence(provisioning.evidencePath,
      path.join(evidenceDirectory, 'provisioning-evidence.json'), config.secrets));
    if (provisioning.status !== 'PASS') {
      // Preserve an exact six-file inventory even on a provisioning refusal. The
      // two downstream records explicitly state that no treatment run occurred.
      const skippedAuthorization = Object.freeze({ schemaVersion: 1,
        kind: 'local_treatment_run_not_authorized', status: 'SKIPPED',
        reason: 'fixture_provisioning_not_passed', secretsSerialized: false });
      records.push(Object.freeze({ ...(await writeSecretFree(path.join(evidenceDirectory,
        'treatment-run-authorization.json'), skippedAuthorization, config.secrets)),
      status: 'SKIPPED' }));
      const skippedUat = Object.freeze({ schemaVersion: 1, kind: 'bounded_treatment_uat_not_run',
        status: 'SKIPPED', reason: 'fixture_provisioning_not_passed', secretsSerialized: false });
      records.push(Object.freeze({ ...(await writeSecretFree(path.join(evidenceDirectory,
        'uat-evidence.json'), skippedUat, config.secrets)), status: 'SKIPPED' }));
      await writeManifest(config, records, provisioning.status);
      await assertArtifactInventory(config);
      await phaseJournal.finish(Object.freeze({
        schemaVersion: 1, kind: 'cnyos_local_bounded_treatment_terminal_outcome',
        status: provisioning.status, durableMutationPhase: phaseJournal.phase,
        reconciliationRequired: provisioning.status === 'UNCERTAIN',
        syntheticOnly: true, productionAuthorization: false, secretsSerialized: false
      }));
      return Object.freeze({ status: provisioning.status, provisioning, uat: null,
        evidenceDirectory });
    }

    await phaseJournal.advance('fixture_passed');
    const authorization = buildRunAuthorization(config, provisioning.fixture);
    const authorizationRaw = JSON.stringify(authorization);
    const authorizationBytes = Buffer.from(`${authorizationRaw}\n`);
    assertNoSecrets(authorizationBytes, config.secrets);
    const authorizationRecord = await writeFresh0600(path.join(evidenceDirectory,
      'treatment-run-authorization.json'), authorizationBytes);
    records.push(Object.freeze({ ...authorizationRecord, status: 'authorized' }));
    const uatEnv = {
      ...env,
      CNYOS_TREATMENT_UAT_ACK: BOUNDED_TREATMENT_ACK,
      CNYOS_STAGING_TREATMENT_FIXTURE_JSON: JSON.stringify(provisioning.fixture),
      CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH: provisioning.ledgerPath,
      CNYOS_EXPECTED_TREATMENT_FIXTURE_LEDGER_SHA256: provisioning.ledgerFileSha256,
      CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON: authorizationRaw,
      CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256:
        sha256(Buffer.from(authorizationRaw)),
      CNYOS_CONTROLLER_UAT_EVIDENCE_PATH: uatEvidencePath
    };
    const uatConfig = await loadBoundedTreatmentConfig(uatEnv, { now, controllerRuntime: runtime });
    uat = await executeBoundedTreatmentUat(uatConfig, {
      fetchImpl,
      chromiumImpl: lockedChromium,
      now,
      onTreatmentWriteDispatch: async record => {
        await phaseJournal.advance(`treatment_write_${record.ordinal}_dispatched`, {
          operationId: record.operationId,
          payloadSha256: record.payloadSha256
        });
      }
    });
    await writeEvidenceExclusive(uatEvidencePath, uat);
    records.push(await copySecretFreeEvidence(uatEvidencePath,
      path.join(evidenceDirectory, 'uat-evidence.json'), config.secrets));
    await writeManifest(config, records, uat.status);
    await assertArtifactInventory(config);
    await phaseJournal.finish(Object.freeze({
      schemaVersion: 1, kind: 'cnyos_local_bounded_treatment_terminal_outcome',
      status: uat.status, durableMutationPhase: phaseJournal.phase,
      reconciliationRequired: uat.status === 'UNCERTAIN',
      syntheticOnly: true, productionAuthorization: false, secretsSerialized: false
    }));
    return Object.freeze({ status: uat.status, provisioning, uat, evidenceDirectory });
  } catch (error) {
    if (!phaseJournal.hasDispatch) throw error;
    const recovery = buildLocalUncertainRecoveryEvidence(config, phaseJournal, error,
      { provisioning });
    await phaseJournal.finish(recovery).catch(() => {});
    await finalizeLocalUncertainRecovery(config, recovery, { provisioning }).catch(() => {});
    return Object.freeze({ status: 'UNCERTAIN', provisioning, uat,
      evidenceDirectory, recovery });
  }
}

function safeCode(error) {
  const value = String(error?.code || error?.message || '');
  return /^CNYOS_[A-Z0-9_:.-]+$/.test(value) ? value : 'CNYOS_LOCAL_UAT_FAILED';
}

async function main() {
  try {
    const result = await runLocalBoundedTreatmentWorkflow(process.env);
    process.stderr.write(`CNYOS_LOCAL_UAT_${result.status}\n`);
    process.exitCode = result.status === 'PASS' ? 0 : result.status === 'UNCERTAIN' ? 2 : 1;
  } catch (error) {
    process.stderr.write(`${safeCode(error)}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();
