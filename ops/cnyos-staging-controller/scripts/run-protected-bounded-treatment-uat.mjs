import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_TREATMENT_ACK,
  BOUNDED_TREATMENT_TARGET,
  canonicalFixtureSha256,
  canonicalJson,
  executeBoundedTreatmentUat,
  loadBoundedTreatmentConfig,
  preflightExactDeployment,
  validateBoundedTreatmentRunAuthorization,
  writeEvidenceExclusive
} from './bounded-treatment-uat.mjs';
import {
  SINGLE_FIXTURE_AUTHORIZATION_DECISION,
  SINGLE_FIXTURE_PROVISION_ACK,
  runSingleFixtureProvisioning
} from './provision-bounded-treatment-fixture.mjs';
import { POLICY, POLICY_SHA256, assertControllerRuntime } from './policy.mjs';

export const PROTECTED_FIXTURE_WORKFLOW_PATH = '.github/workflows/cnyos-staging-release.yml';
export const PROTECTED_FIXTURE_GITHUB_ENVIRONMENT = 'cnyos-staging-publish';
export const PROTECTED_FIXTURE_SECRET_NAMES = Object.freeze([
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY',
  'CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);

const RUN_AUTHORIZATION_DECISION = 'authorize_exactly_two_synthetic_treatment_writes';
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const DEPLOY_ID = /^[0-9a-f]{24}$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_JSON_BYTES = 1024 * 1024;
const AUTHORIZATION_LIFETIME_MS = 25 * 60 * 1000;
const ARTIFACT_FILES = Object.freeze([
  'controller-admission-evidence.json',
  'controller-authorization-bundle.json',
  'evidence-manifest.json',
  'provisioning-evidence.json',
  'treatment-run-authorization.json',
  'uat-evidence.json'
]);
const configuredInstances = new WeakSet();

export class ProtectedFixtureWorkflowError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProtectedFixtureWorkflowError';
    this.code = code;
  }
}

function fail(code) {
  throw new ProtectedFixtureWorkflowError(code);
}

function required(value, code, maximum = 4096) {
  const normalized = String(value ?? '').trim();
  if (!normalized || normalized.length > maximum) fail(code);
  return normalized;
}

function exact(value, pattern, code) {
  const normalized = required(value, code).toLowerCase();
  if (!pattern.test(normalized)) fail(code);
  return normalized;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function protectedSyntheticPractitionerEmail(fixtureRunId) {
  const normalized = required(fixtureRunId, 'CNYOS_PROTECTED_FIXTURE_RUN_ID_INVALID', 96);
  if (!RUN_ID.test(normalized)) fail('CNYOS_PROTECTED_FIXTURE_RUN_ID_INVALID');
  return `synthetic-${sha256(Buffer.from(normalized)).slice(0, 24)}@cnyos.invalid`;
}

export function protectedSyntheticFixtureRunId(runReference) {
  const normalized = required(runReference,
    'CNYOS_PROTECTED_FIXTURE_RUN_REFERENCE_INVALID', 96);
  if (!RUN_ID.test(normalized)) fail('CNYOS_PROTECTED_FIXTURE_RUN_REFERENCE_INVALID');
  return `synthetic-run-${sha256(Buffer.from(normalized)).slice(0, 32)}`;
}

function timingSafeEqualHex(left, right) {
  return SHA256.test(left) && SHA256.test(right) && crypto.timingSafeEqual(
    Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function timestamp(value, code) {
  const observed = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(observed.getTime())) fail(code);
  return observed;
}

function assertConfigured(config) {
  if (!configuredInstances.has(config)) fail('CNYOS_PROTECTED_FIXTURE_CONFIG_INVALID');
}

function secretValues(config) {
  return [config.serviceRoleKey, config.publishableKey, config.password, config.netlifyToken];
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys, code) {
  if (!isPlainObject(value) ||
    canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) fail(code);
}

function allowedKeys(value, allowed, required, code) {
  if (!isPlainObject(value) || Object.keys(value).some(key => !allowed.includes(key)) ||
    required.some(key => !Object.hasOwn(value, key))) fail(code);
}

function expectedProvisioningPlan(config, operationIds) {
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

function controllerEvidence(runtime) {
  return Object.freeze({
    repository: runtime.repository,
    ref: runtime.ref,
    commit: runtime.commit,
    workflowPath: runtime.workflowPath,
    workflowRef: runtime.workflowRef,
    workflowSha: runtime.commit,
    runId: runtime.runId,
    runAttempt: 1,
    actor: runtime.actor
  });
}

export function loadProtectedFixtureWorkflowConfig(env = process.env, {
  now = () => new Date()
} = {}) {
  const runtime = assertControllerRuntime(env);
  if (runtime.workflowPath !== PROTECTED_FIXTURE_WORKFLOW_PATH ||
    runtime.workflowPath !== POLICY.controller.releaseWorkflowPath) {
    fail('CNYOS_PROTECTED_FIXTURE_WORKFLOW_PATH_INVALID');
  }
  if (env.GITHUB_EVENT_NAME !== 'workflow_dispatch') {
    fail('CNYOS_PROTECTED_FIXTURE_EVENT_INVALID');
  }
  if (env.CNYOS_CONTROLLER_ENVIRONMENT !== PROTECTED_FIXTURE_GITHUB_ENVIRONMENT) {
    fail('CNYOS_PROTECTED_FIXTURE_ENVIRONMENT_INVALID');
  }
  if (env.ACTIONS_ID_TOKEN_REQUEST_URL || env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    fail('CNYOS_PROTECTED_FIXTURE_OIDC_CAPABILITY_FORBIDDEN');
  }
  const workflowSha = exact(env.GITHUB_WORKFLOW_SHA, SHA40,
    'CNYOS_PROTECTED_FIXTURE_WORKFLOW_SHA_INVALID');
  if (workflowSha !== runtime.commit) fail('CNYOS_PROTECTED_FIXTURE_WORKFLOW_SHA_MISMATCH');

  const observedAt = timestamp(now(), 'CNYOS_PROTECTED_FIXTURE_TIME_INVALID');
  const authorizedAt = observedAt.toISOString();
  const expiresAt = new Date(observedAt.getTime() + AUTHORIZATION_LIFETIME_MS).toISOString();
  // The dispatch reference may originate outside this controller.  It is never
  // copied into clinical rows or published evidence; only this deterministic,
  // bounded pseudonymous derivative crosses the fixture boundary.
  const fixtureRunId = protectedSyntheticFixtureRunId(
    env.CNYOS_TREATMENT_UAT_RUN_REFERENCE);
  const practitionerEmail = required(env.CNYOS_STAGING_PRACTITIONER_EMAIL,
    'CNYOS_PROTECTED_FIXTURE_EMAIL_INVALID', 320).toLowerCase();
  if (!EMAIL.test(practitionerEmail) ||
    practitionerEmail !== protectedSyntheticPractitionerEmail(fixtureRunId)) {
    fail('CNYOS_PROTECTED_FIXTURE_EMAIL_INVALID');
  }

  const workDirectory = path.resolve(required(env.CNYOS_PROTECTED_UAT_WORK_DIRECTORY,
    'CNYOS_PROTECTED_FIXTURE_WORK_DIRECTORY_REQUIRED', 4096));
  if (!path.isAbsolute(env.CNYOS_PROTECTED_UAT_WORK_DIRECTORY) ||
    workDirectory === path.parse(workDirectory).root) {
    fail('CNYOS_PROTECTED_FIXTURE_WORK_DIRECTORY_INVALID');
  }

  const publishableKey = required(env.CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY,
    'CNYOS_PROTECTED_FIXTURE_PUBLISHABLE_KEY_REQUIRED', 4096);
  const serviceRoleKey = required(env.CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY,
    'CNYOS_PROTECTED_FIXTURE_SERVICE_ROLE_KEY_REQUIRED', 8192);
  const password = required(env.CNYOS_STAGING_TEST_PASSWORD,
    'CNYOS_PROTECTED_FIXTURE_PASSWORD_REQUIRED', 4096);
  const netlifyToken = required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN,
    'CNYOS_PROTECTED_FIXTURE_NETLIFY_TOKEN_REQUIRED', 8192);
  if (!/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(publishableKey) ||
    serviceRoleKey.length < 20 || password.length < 16 || netlifyToken.length < 20 ||
    new Set([publishableKey, serviceRoleKey, password, netlifyToken]).size !== 4) {
    fail('CNYOS_PROTECTED_FIXTURE_SECRET_BOUNDARY_INVALID');
  }

  const config = Object.freeze({
    runtime,
    authorizedAt,
    expiresAt,
    fixtureRunId,
    sourceCommit: exact(env.CNYOS_EXPECTED_SOURCE_COMMIT, SHA40,
      'CNYOS_PROTECTED_FIXTURE_SOURCE_COMMIT_INVALID'),
    sourceTree: exact(env.CNYOS_EXPECTED_SOURCE_TREE, SHA40,
      'CNYOS_PROTECTED_FIXTURE_SOURCE_TREE_INVALID'),
    deployId: exact(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, DEPLOY_ID,
      'CNYOS_PROTECTED_FIXTURE_DEPLOY_ID_INVALID'),
    practitionerEmail,
    practitionerFullName: `Synthetic E2E Practitioner ${fixtureRunId}`,
    publishableKey,
    serviceRoleKey,
    password,
    netlifyToken,
    immutableOrigin:
      `https://${exact(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, DEPLOY_ID,
        'CNYOS_PROTECTED_FIXTURE_DEPLOY_ID_INVALID')}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`,
    workDirectory,
    fixtureDirectory: path.join(workDirectory, 'fixture'),
    uploadDirectory: path.join(workDirectory, 'upload'),
    mutationJournalPath: path.join(workDirectory,
      'treatment-mutation-journal.private.jsonl'),
    uatEvidencePath: path.join(workDirectory, 'uat-evidence.private.json')
  });
  configuredInstances.add(config);
  return config;
}

async function assertFreshDirectory(filename, code) {
  const parent = path.dirname(filename);
  const parentStatus = await fs.lstat(parent).catch(() => null);
  if (!parentStatus?.isDirectory() || parentStatus.isSymbolicLink()) fail(code);
  const existing = await fs.lstat(filename).catch(error => {
    if (error?.code === 'ENOENT') return null;
    fail(code);
  });
  if (existing) fail(code);
  await fs.mkdir(filename, { mode: 0o700 });
  const status = await fs.lstat(filename).catch(() => null);
  if (!status?.isDirectory() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o700) {
    fail(code);
  }
}

export async function prepareProtectedFixtureWorkDirectory(config) {
  assertConfigured(config);
  await assertFreshDirectory(config.workDirectory,
    'CNYOS_PROTECTED_FIXTURE_WORK_DIRECTORY_NOT_FRESH');
  await assertFreshDirectory(config.uploadDirectory,
    'CNYOS_PROTECTED_FIXTURE_UPLOAD_DIRECTORY_INVALID');
}

async function writeBytesExclusive(filename, bytes) {
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
      status.size !== bytes.length) fail('CNYOS_PROTECTED_FIXTURE_EVIDENCE_WRITE_INVALID');
  } catch (error) {
    if (error instanceof ProtectedFixtureWorkflowError) throw error;
    fail('CNYOS_PROTECTED_FIXTURE_EVIDENCE_WRITE_FAILED');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function syncParentDirectory(filename) {
  let handle;
  try {
    handle = await fs.open(path.dirname(filename), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    await handle.sync();
  } catch (error) {
    // Some supported filesystems do not permit fsync on a directory. The file
    // itself is still synchronously persisted before a write may be dispatched.
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error?.code)) {
      fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_SYNC_FAILED');
    }
  } finally {
    await handle?.close().catch(() => {});
  }
}

function validateMutationJournalEntry(entry, fixture, expectedOrdinal) {
  const session = fixture?.sessions?.[expectedOrdinal - 1];
  const latchedAtMs = Date.parse(String(entry?.latchedAt || ''));
  if (!isPlainObject(entry) || !session || entry.schemaVersion !== 1 ||
    entry.kind !== 'protected_bounded_treatment_write_dispatch' ||
    entry.ordinal !== expectedOrdinal || entry.operationId !== session.operationId ||
    entry.payloadSha256 !== expectedTreatmentPayloadSha256(fixture, session) ||
    !Number.isFinite(latchedAtMs) || entry.latchedAt !== new Date(latchedAtMs).toISOString()) {
    fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_INVALID');
  }
  return entry;
}

async function createMutationJournal(config, fixture, startedAt, now) {
  const filename = config.mutationJournalPath;
  const header = Object.freeze({
    schemaVersion: 1,
    kind: 'protected_bounded_treatment_mutation_journal',
    runId: config.fixtureRunId,
    startedAt,
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployId: config.deployId,
    secretsSerialized: false
  });
  let handle;
  try {
    handle = await fs.open(filename, fsConstants.O_WRONLY | fsConstants.O_CREAT |
      fsConstants.O_EXCL | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(canonicalBytes(header));
    await handle.sync();
    await syncParentDirectory(filename);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error instanceof ProtectedFixtureWorkflowError) throw error;
    fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_CREATE_FAILED');
  }

  const entries = [];
  let writeChain = Promise.resolve();
  let closed = false;
  const latch = candidate => {
    const operation = writeChain.then(async () => {
      if (closed) fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_CLOSED');
      const entry = validateMutationJournalEntry(Object.freeze({
        schemaVersion: 1,
        kind: 'protected_bounded_treatment_write_dispatch',
        ordinal: candidate?.ordinal,
        operationId: candidate?.operationId,
        payloadSha256: candidate?.payloadSha256,
        latchedAt: now().toISOString()
      }), fixture, entries.length + 1);
      const bytes = canonicalBytes(entry);
      assertNoSecrets(bytes, config);
      await handle.writeFile(bytes);
      // This completes before route.fetch. A thrown sync error therefore blocks
      // dispatch instead of allowing an unjournaled staging mutation.
      await handle.sync();
      entries.push(entry);
    });
    // Keep the internal serialization chain usable for close/readback while
    // still rejecting the individual callback so route.fetch is not reached.
    writeChain = operation.catch(() => {});
    return operation;
  };
  const close = async () => {
    if (closed) return;
    await writeChain;
    closed = true;
    await handle.sync();
    await handle.close();
    handle = null;
  };
  return Object.freeze({ filename, header, entries, latch, close });
}

async function readMutationJournal(journal, config, fixture) {
  await journal.close();
  let handle;
  let bytes;
  try {
    handle = await fs.open(journal.filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const linked = await fs.lstat(journal.filename, { bigint: true });
    if (!before.isFile() || !linked.isFile() || linked.isSymbolicLink() ||
      before.dev !== linked.dev || before.ino !== linked.ino || before.size < 2n ||
      before.size > BigInt(MAX_JSON_BYTES) || (before.mode & 0o777n) !== 0o600n) {
      fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_INVALID');
    }
    bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
      bytes.length !== Number(before.size)) {
      fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_INVALID');
    }
  } catch (error) {
    if (error instanceof ProtectedFixtureWorkflowError) throw error;
    fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_INVALID');
  } finally {
    await handle?.close().catch(() => {});
  }
  if (secretValues(config).some(secret => bytes.includes(Buffer.from(secret)))) {
    fail('CNYOS_PROTECTED_FIXTURE_SECRET_SERIALIZATION_BLOCKED');
  }
  const lines = bytes.toString('utf8').split('\n').filter(Boolean);
  let values;
  try { values = lines.map(line => JSON.parse(line)); }
  catch { fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_INVALID'); }
  if (values.some(value => valueContainsSecret(value, secretValues(config)))) {
    fail('CNYOS_PROTECTED_FIXTURE_SECRET_SERIALIZATION_BLOCKED');
  }
  if (values.length < 1 || canonicalJson(values[0]) !== canonicalJson(journal.header) ||
    values.length > fixture.sessions.length + 1) {
    fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_INVALID');
  }
  return Object.freeze(values.slice(1).map((entry, index) =>
    Object.freeze(validateMutationJournalEntry(entry, fixture, index + 1))));
}

async function readPrivateJsonExact(filename, expectedPath, expectedSha256, code) {
  if (typeof filename !== 'string' || path.resolve(filename) !== expectedPath ||
    path.dirname(filename) !== path.dirname(expectedPath)) fail(code);
  const parent = await fs.lstat(path.dirname(expectedPath)).catch(() => null);
  if (!parent?.isDirectory() || parent.isSymbolicLink()) fail(code);
  let handle;
  try {
    handle = await fs.open(expectedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const linked = await fs.lstat(expectedPath, { bigint: true });
    if (!before.isFile() || !linked.isFile() || linked.isSymbolicLink() ||
      before.dev !== linked.dev || before.ino !== linked.ino || before.size < 2n ||
      before.size > BigInt(MAX_JSON_BYTES) || (before.mode & 0o077n) !== 0n ||
      (before.mode & 0o400n) === 0n) fail(code);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
      bytes.length !== Number(before.size)) fail(code);
    const observedSha256 = sha256(bytes);
    if (expectedSha256 != null &&
      (!SHA256.test(String(expectedSha256)) ||
        !timingSafeEqualHex(observedSha256, String(expectedSha256)))) fail(code);
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); }
    catch { fail(code); }
    return Object.freeze({ bytes, value, sha256: observedSha256 });
  } catch (error) {
    if (error instanceof ProtectedFixtureWorkflowError) throw error;
    fail(code);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`);
}

function valueContainsSecret(value, secrets) {
  if (typeof value === 'string') return secrets.some(secret => value.includes(secret));
  if (Array.isArray(value)) return value.some(item => valueContainsSecret(item, secrets));
  if (!isPlainObject(value)) return false;
  return Object.entries(value).some(([key, item]) =>
    secrets.some(secret => key.includes(secret)) || valueContainsSecret(item, secrets));
}

export function assertSecretFreeJsonEvidence(bytes, secretsInput) {
  const text = bytes.toString('utf8');
  const secrets = [...secretsInput].filter(Boolean);
  let value;
  try { value = JSON.parse(text); }
  catch { fail('CNYOS_PROTECTED_FIXTURE_EVIDENCE_INVALID'); }
  if (secrets.some(secret => text.includes(secret)) || valueContainsSecret(value, secrets)) {
    fail('CNYOS_PROTECTED_FIXTURE_SECRET_SERIALIZATION_BLOCKED');
  }
  return value;
}

function assertNoSecrets(bytes, config) {
  return assertSecretFreeJsonEvidence(bytes, secretValues(config));
}

async function writeSecretFreeCanonical(filename, value, config) {
  const bytes = canonicalBytes(value);
  if (value?.secretsSerialized !== false) {
    fail('CNYOS_PROTECTED_FIXTURE_EVIDENCE_SECRET_MARKER_INVALID');
  }
  assertNoSecrets(bytes, config);
  await writeBytesExclusive(filename, bytes);
  return Object.freeze({ filename, sha256: sha256(bytes), bytes: bytes.length });
}

export function createProtectedFixtureAdmissionHook(config, {
  writeArtifact = writeSecretFreeCanonical
} = {}) {
  assertConfigured(config);
  let used = false;
  return async request => {
    if (used) fail('CNYOS_PROTECTED_FIXTURE_ADMISSION_REPLAYED');
    used = true;
    let requestPlanCanonical = null;
    try { requestPlanCanonical = canonicalJson(request?.plan); }
    catch { requestPlanCanonical = null; }
    const operationIds = request?.plan?.operationIds;
    const operationsValid = Array.isArray(operationIds) && operationIds.length === 2 &&
      operationIds.every(value => typeof value === 'string' && value === value.toLowerCase() &&
        UUID_V4.test(value)) && new Set(operationIds).size === 2;
    const expectedPlanCanonical = operationsValid
      ? canonicalJson(expectedProvisioningPlan(config, operationIds))
      : null;
    if (!request || request.runtime?.repository !== config.runtime.repository ||
      request.runtime?.runId !== config.runtime.runId ||
      request.runtime?.ref !== config.runtime.ref ||
      request.runtime?.commit !== config.runtime.commit ||
      request.runtime?.workflowPath !== config.runtime.workflowPath ||
      request.runtime?.workflowRef !== config.runtime.workflowRef ||
      request.runtime?.actor !== config.runtime.actor ||
      typeof requestPlanCanonical !== 'string' ||
      !timingSafeEqualHex(String(request.planSha256 || ''),
        sha256(Buffer.from(requestPlanCanonical))) ||
      requestPlanCanonical !== expectedPlanCanonical) {
      fail('CNYOS_PROTECTED_FIXTURE_ADMISSION_REQUEST_INVALID');
    }

    const evidence = Object.freeze({
      schemaVersion: 1,
      evidenceType: 'cnyos_staging_single_fixture_environment_admission',
      status: 'authorized',
      decision: SINGLE_FIXTURE_AUTHORIZATION_DECISION,
      scope: 'one_fresh_synthetic_practitioner_patient_draft_encounter',
      syntheticOnly: true,
      realPatientDataAuthorized: false,
      productionAuthorization: false,
      environment: PROTECTED_FIXTURE_GITHUB_ENVIRONMENT,
      authorizedAt: config.authorizedAt,
      expiresAt: config.expiresAt,
      policySha256: POLICY_SHA256,
      controller: controllerEvidence(config.runtime),
      target: BOUNDED_TREATMENT_TARGET,
      planSha256: request.planSha256,
      source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
      deployId: config.deployId,
      fixtureRunId: config.fixtureRunId,
      practitionerEmailSha256: sha256(Buffer.from(config.practitionerEmail)),
      admissionBasis: 'github_environment_job_started',
      secretsSerialized: false
    });
    const evidenceRecord = await writeArtifact(path.join(config.uploadDirectory,
      'controller-admission-evidence.json'), evidence, config);
    const bundle = Object.freeze({
      schemaVersion: 1,
      kind: 'protected_controller_single_fixture_authorization_bundle',
      status: 'authorized',
      environment: PROTECTED_FIXTURE_GITHUB_ENVIRONMENT,
      controller: controllerEvidence(config.runtime),
      policySha256: POLICY_SHA256,
      planSha256: request.planSha256,
      authorizationEvidenceSha256: evidenceRecord.sha256,
      targetSha256: sha256(Buffer.from(canonicalJson(BOUNDED_TREATMENT_TARGET))),
      authorizedAt: config.authorizedAt,
      expiresAt: config.expiresAt,
      syntheticOnly: true,
      productionAuthorization: false,
      secretsSerialized: false
    });
    const bundleRecord = await writeArtifact(path.join(config.uploadDirectory,
      'controller-authorization-bundle.json'), bundle, config);
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
      authorizationEvidenceSha256: evidenceRecord.sha256,
      authorizationBundleSha256: bundleRecord.sha256
    });
  };
}

export function buildProtectedTreatmentRunAuthorization(config, fixture, {
  now = () => new Date()
} = {}) {
  assertConfigured(config);
  const observedAt = timestamp(now(), 'CNYOS_PROTECTED_FIXTURE_TIME_INVALID');
  const authorizedAt = observedAt.toISOString();
  const expiresAt = new Date(observedAt.getTime() + AUTHORIZATION_LIFETIME_MS).toISOString();
  const value = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_bounded_treatment_run_authorization',
    status: 'authorized',
    decision: RUN_AUTHORIZATION_DECISION,
    scope: 'cnyos_staging_only',
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    authorizedAt,
    expiresAt,
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
    now: observedAt
  });
  return value;
}

function assertEvidenceEnvelope(value, config, {
  evidenceType, expectedStatus, allowed, required, code
}) {
  allowedKeys(value, allowed, required, code);
  exactKeys(value.controller,
    evidenceType === 'cnyos_single_bounded_treatment_fixture_provisioning'
      ? ['repository', 'ref', 'commit', 'workflowPath', 'runId', 'runAttempt']
      : ['repository', 'ref', 'commit', 'workflowPath', 'workflowRef', 'runId',
        'runAttempt', 'policySha256'], code);
  exactKeys(value.source, ['commit', 'tree'], code);
  exactKeys(value.cleanup, ['status', 'attempted'], code);
  if (value.schemaVersion !== 1 || value.evidenceType !== evidenceType ||
    value.status !== expectedStatus || !['PASS', 'FAIL', 'UNCERTAIN'].includes(value.status) ||
    value.syntheticOnly !== true || value.realPatientDataAuthorized !== false ||
    value.productionAuthorization !== false || value.controllerOwnedRunner !== true ||
    value.controller.repository !== config.runtime.repository ||
    value.controller.ref !== config.runtime.ref || value.controller.commit !== config.runtime.commit ||
    value.controller.workflowPath !== config.runtime.workflowPath ||
    value.controller.runId !== config.runtime.runId || value.controller.runAttempt !== 1 ||
    value.source.commit !== config.sourceCommit || value.source.tree !== config.sourceTree ||
    value.cleanup.status !== 'NOT_AUTHORIZED' || value.cleanup.attempted !== false ||
    value.secretsSerialized !== false) fail(code);
}

function assertCanonicalTimestampWindow(value, minimum, maximum, code) {
  const parsed = Date.parse(String(value || ''));
  const min = Date.parse(String(minimum || ''));
  const max = Date.parse(String(maximum || ''));
  if (!Number.isFinite(parsed) || !Number.isFinite(min) || !Number.isFinite(max) ||
    String(value) !== new Date(parsed).toISOString() || parsed < min || parsed > max) fail(code);
}

function assertCanonicalTimestampAtOrAfter(value, minimum, code) {
  const parsed = Date.parse(String(value || ''));
  const min = Date.parse(String(minimum || ''));
  if (!Number.isFinite(parsed) || !Number.isFinite(min) ||
    String(value) !== new Date(parsed).toISOString() || parsed < min) fail(code);
}

function successfulMutation(mutation) {
  return mutation?.dispatched === true && mutation.requestFailed === false &&
    Number.isInteger(mutation.responseStatus) && mutation.responseStatus >= 200 &&
    mutation.responseStatus < 300;
}

function assertProvisioningPhaseState(value, mutationContract, expectedStatus, code) {
  const mutations = value.mutations;
  const firstNonSuccess = mutations.findIndex(mutation => !successfulMutation(mutation));
  if (firstNonSuccess !== -1 && firstNonSuccess !== mutations.length - 1) fail(code);

  const practitionerPresent = value.fixtureIds.practitionerUserId !== null;
  const patientPresent = value.fixtureIds.patientId !== null;
  const patientHnPresent = value.fixtureIds.patientHnSha256 !== null;
  const encounterPresent = value.fixtureIds.encounterId !== null;
  const firstThreeSucceeded = mutations.length >= 3 && mutations.slice(0, 3)
    .every(successfulMutation);
  const allFiveSucceeded = mutations.length === 5 && mutations.every(successfulMutation);

  if (value.invariants.freshAuthUser !== practitionerPresent ||
    (practitionerPresent && (mutations.length < 1 || !successfulMutation(mutations[0]))) ||
    (!practitionerPresent && mutations.length >= 2) ||
    patientPresent !== patientHnPresent ||
    (patientPresent && (mutations.length < 4 || !successfulMutation(mutations[3]))) ||
    (!patientPresent && mutations.length >= 5) ||
    (encounterPresent && (!patientPresent || mutations.length < 5 ||
      !successfulMutation(mutations[4]))) ||
    (value.invariants.authoritativeSyntheticMetadataVerified &&
      (!practitionerPresent || !firstThreeSucceeded)) ||
    (value.invariants.controlPlaneReadbackVerified &&
      !value.invariants.authoritativeSyntheticMetadataVerified) ||
    (mutations.length >= 4 &&
      (!value.invariants.authoritativeSyntheticMetadataVerified ||
        !value.invariants.controlPlaneReadbackVerified)) ||
    (value.invariants.exactClinicalReadbackVerified &&
      (!value.invariants.controlPlaneReadbackVerified || !encounterPresent ||
        !allFiveSucceeded))) fail(code);

  const baselineCounts = [
    value.invariants.baselineTreatmentSessions,
    value.invariants.baselinePrescriptions,
    value.invariants.baselineVitalSigns,
    value.invariants.baselinePainAssessments,
    value.invariants.baselineAllergies
  ];
  if (value.invariants.exactClinicalReadbackVerified
    ? baselineCounts.some(count => count !== 0)
    : baselineCounts.some(count => count !== null)) fail(code);

  const operationIndex = mutationContract.findIndex(expected =>
    expected[0] === value.failure?.operation);
  if (operationIndex !== -1 &&
    (operationIndex < mutations.length - 1 || operationIndex > mutations.length)) fail(code);
  const postMutationOperation = value.failure?.operation;
  if (postMutationOperation === 'practitioner_login' &&
    (mutations.length !== 3 || !firstThreeSucceeded)) fail(code);
  if (['patient_readback', 'encounter_readback',
    'clinical_treatment_sessions_readback', 'prescriptions_readback',
    'vital_signs_readback', 'pain_assessments_readback',
    'patient_allergies_readback'].includes(postMutationOperation) &&
    (!allFiveSucceeded || !encounterPresent)) fail(code);
  if (postMutationOperation === 'publish_success' &&
    (!allFiveSucceeded || !value.invariants.exactClinicalReadbackVerified)) fail(code);

  const last = mutations.at(-1);
  const lastImpliesUncertainty = last?.dispatched === true &&
    (last.requestFailed === true || last.responseStatus === null ||
      last.responseStatus >= 500 || [408, 425, 429].includes(last.responseStatus));
  if (lastImpliesUncertainty && expectedStatus !== 'UNCERTAIN') fail(code);
}

function expectedTreatmentPayloadSha256(fixture, session) {
  return sha256(Buffer.from(JSON.stringify({
    p_encounter_id: fixture.encounter.id,
    p_client_request_id: session.operationId,
    p_treatment_modalities: session.modalities,
    p_treatment_detail: session.treatmentDetail,
    p_procedure_referral: session.procedureReferral,
    p_procedure_referral_detail: session.procedureReferralDetail,
    p_precautions: session.precautions,
    p_pain_before: session.painBefore,
    p_pain_after: session.painAfter,
    p_outcome_summary: session.outcomeSummary,
    p_advice: session.advice
  })));
}

export function validateProvisioningEvidence(value, config, expectedStatus, context = {}) {
  const code = 'CNYOS_PROTECTED_FIXTURE_PROVISIONING_EVIDENCE_INVALID';
  const allowed = [
    'schemaVersion', 'evidenceType', 'status', 'startedAt', 'observedAt', 'syntheticOnly',
    'realPatientDataAuthorized', 'productionAuthorization', 'controllerOwnedRunner',
    'controller', 'policySha256', 'planSha256', 'authorization', 'target', 'source',
    'deployId', 'fixtureRunId', 'practitionerEmailSha256', 'fixtureIds', 'invariants',
    'mutations', 'mutationLimit', 'failure', 'cleanup', 'secretsSerialized', 'outputs'
  ];
  assertEvidenceEnvelope(value, config, {
    evidenceType: 'cnyos_single_bounded_treatment_fixture_provisioning', expectedStatus,
    allowed, required: allowed.filter(key => key !== 'outputs'), code
  });
  exactKeys(value.authorization, [
    'decision', 'authorizationEvidenceSha256', 'authorizationBundleSha256',
    'authorizedAt', 'expiresAt'
  ], code);
  exactKeys(value.mutationLimit, [
    'freshAuthUsers', 'serviceRoleTableWrites', 'authenticatedClinicalRpcWrites',
    'writeRetries', 'observedRetries'
  ], code);
  exactKeys(value.fixtureIds, [
    'practitionerUserId', 'patientId', 'patientHnSha256', 'encounterId', 'operationIds'
  ], code);
  exactKeys(value.invariants, [
    'freshAuthUser', 'authoritativeSyntheticMetadataVerified',
    'controlPlaneReadbackVerified', 'exactClinicalReadbackVerified',
    'baselineTreatmentSessions', 'baselinePrescriptions', 'baselineVitalSigns',
    'baselinePainAssessments', 'baselineAllergies'
  ], code);
  exactKeys(value.cleanup, ['status', 'attempted'], code);
  const admission = context.admission;
  const operationIds = value.fixtureIds.operationIds;
  const operationIdsValid = Array.isArray(operationIds) && operationIds.length === 2 &&
    operationIds.every(id => typeof id === 'string' && id === id.toLowerCase() && UUID_V4.test(id)) &&
    new Set(operationIds).size === 2;
  const expectedPlanSha256 = operationIdsValid
    ? sha256(Buffer.from(canonicalJson(expectedProvisioningPlan(config, operationIds))))
    : null;
  const nullableUuid = value => value === null ||
    (typeof value === 'string' && value === value.toLowerCase() && UUID_V4.test(value));
  const nullableSha256 = value => value === null || SHA256.test(String(value || ''));
  const postMutationFailureOperations = new Set([
    'practitioner_login', 'patient_readback', 'encounter_readback',
    'clinical_treatment_sessions_readback', 'prescriptions_readback',
    'vital_signs_readback', 'pain_assessments_readback', 'patient_allergies_readback',
    'publish_success'
  ]);
  if (!isPlainObject(admission) || value.policySha256 !== POLICY_SHA256 ||
    canonicalJson(value.target) !==
      canonicalJson(BOUNDED_TREATMENT_TARGET) || value.deployId !== config.deployId ||
    value.fixtureRunId !== config.fixtureRunId || value.practitionerEmailSha256 !==
      sha256(Buffer.from(config.practitionerEmail)) ||
    value.planSha256 !== expectedPlanSha256 ||
    value.authorization.decision !== SINGLE_FIXTURE_AUTHORIZATION_DECISION ||
    value.authorization.authorizationEvidenceSha256 !== admission.authorizationEvidenceSha256 ||
    value.authorization.authorizationBundleSha256 !== admission.authorizationBundleSha256 ||
    value.authorization.authorizedAt !== admission.authorizedAt ||
    value.authorization.expiresAt !== admission.expiresAt ||
    value.mutationLimit.freshAuthUsers !== 1 || value.mutationLimit.serviceRoleTableWrites !== 2 ||
    value.mutationLimit.authenticatedClinicalRpcWrites !== 2 ||
    value.mutationLimit.writeRetries !== 0 || value.mutationLimit.observedRetries !== 0 ||
    !Array.isArray(value.mutations) || value.mutations.length > 5 ||
    (expectedStatus === 'PASS' && value.mutations.length !== 5) || !operationIdsValid ||
    !nullableUuid(value.fixtureIds.practitionerUserId) ||
    !nullableUuid(value.fixtureIds.patientId) || !nullableUuid(value.fixtureIds.encounterId) ||
    !nullableSha256(value.fixtureIds.patientHnSha256)) fail(code);
  assertCanonicalTimestampWindow(value.startedAt, admission.authorizedAt, admission.expiresAt, code);
  if (expectedStatus === 'PASS') {
    assertCanonicalTimestampWindow(value.observedAt, value.startedAt, admission.expiresAt, code);
  } else {
    // Expiry is a mutation cutoff, not a reason to lose terminal recovery evidence.
    // The provisioner checks the admission before every mutation; once it stops,
    // writing the immutable FAIL/UNCERTAIN receipt may finish after expiry.
    assertCanonicalTimestampAtOrAfter(value.observedAt, value.startedAt, code);
  }
  const mutationContract = [
    ['create_auth_user', 'service_role', '/auth/v1/admin/users'],
    ['upsert_profile', 'service_role', '/rest/v1/profiles'],
    ['insert_clinic_membership', 'service_role', '/rest/v1/clinic_memberships'],
    ['upsert_patient_registration', 'practitioner', '/rest/v1/rpc/upsert_patient_registration'],
    ['start_manual_patient_encounter', 'practitioner',
      '/rest/v1/rpc/start_manual_patient_encounter']
  ];
  for (const [index, mutation] of value.mutations.entries()) {
    exactKeys(mutation, [
      'ordinal', 'name', 'authority', 'resource', 'dispatched', 'responseStatus',
      'requestFailed'
    ], code);
    const expected = mutationContract[index];
    const progressValid = typeof mutation.dispatched === 'boolean' &&
      typeof mutation.requestFailed === 'boolean' &&
      (mutation.responseStatus === null || Number.isInteger(mutation.responseStatus)) &&
      (mutation.dispatched || (mutation.responseStatus === null && mutation.requestFailed === false)) &&
      (!mutation.requestFailed || (mutation.dispatched && mutation.responseStatus === null));
    if (mutation.ordinal !== index + 1 || mutation.name !== expected[0] ||
      mutation.authority !== expected[1] || mutation.resource !== expected[2] || !progressValid) fail(code);
  }
  const invariantBooleans = [
    value.invariants.freshAuthUser,
    value.invariants.authoritativeSyntheticMetadataVerified,
    value.invariants.controlPlaneReadbackVerified,
    value.invariants.exactClinicalReadbackVerified
  ];
  const invariantCounts = [
    value.invariants.baselineTreatmentSessions,
    value.invariants.baselinePrescriptions,
    value.invariants.baselineVitalSigns,
    value.invariants.baselinePainAssessments,
    value.invariants.baselineAllergies
  ];
  if (invariantBooleans.some(item => typeof item !== 'boolean') ||
    invariantCounts.some(item => item !== null && item !== 0)) fail(code);
  if (expectedStatus !== 'PASS') {
    assertProvisioningPhaseState(value, mutationContract, expectedStatus, code);
  }
  if (expectedStatus === 'PASS') {
    const { fixture, ledger, fixtureFileSha256, ledgerFileSha256 } = context;
    if (!isPlainObject(fixture) || !isPlainObject(ledger)) fail(code);
    const expectedFixtureIds = {
      practitionerUserId: fixture.practitioner?.userId,
      patientId: fixture.patient?.id,
      patientHnSha256: sha256(Buffer.from(String(fixture.patient?.hn || ''))),
      encounterId: fixture.encounter?.id,
      operationIds
    };
    const expectedInvariants = {
      freshAuthUser: true,
      authoritativeSyntheticMetadataVerified: true,
      controlPlaneReadbackVerified: true,
      exactClinicalReadbackVerified: true,
      baselineTreatmentSessions: 0,
      baselinePrescriptions: 0,
      baselineVitalSigns: 0,
      baselinePainAssessments: 0,
      baselineAllergies: 0
    };
    exactKeys(value.outputs, ['fixture', 'protectedLedger'], code);
    exactKeys(value.outputs.fixture, ['name', 'sha256', 'mode'], code);
    exactKeys(value.outputs.protectedLedger, ['name', 'sha256', 'mode'], code);
    if (value.failure !== null || value.outputs.fixture.name !== 'treatment-fixture.json' ||
      value.outputs.protectedLedger.name !== 'protected-treatment-fixture-ledger.json' ||
      value.outputs.fixture.mode !== '0600' || value.outputs.protectedLedger.mode !== '0600' ||
      canonicalJson(value.fixtureIds) !== canonicalJson(expectedFixtureIds) ||
      canonicalJson(value.invariants) !== canonicalJson(expectedInvariants) ||
      value.mutations.some(mutation => mutation.dispatched !== true ||
        mutation.requestFailed !== false || !Number.isInteger(mutation.responseStatus) ||
        mutation.responseStatus < 200 || mutation.responseStatus >= 300) ||
      value.outputs.fixture.sha256 !== fixtureFileSha256 ||
      value.outputs.protectedLedger.sha256 !== ledgerFileSha256 ||
      ledger.entryId !== `fixture:treatment:${config.fixtureRunId}` ||
      ledger.fixtureSha256 !== canonicalFixtureSha256(fixture) ||
      canonicalJson(ledger.fixtureIds) !== canonicalJson({
        practitionerUserId: fixture.practitioner.userId,
        patientId: fixture.patient.id,
        encounterId: fixture.encounter.id,
        operationIds
      }) || canonicalJson(ledger.target) !== canonicalJson({
        siteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
        deployId: config.deployId,
        sourceCommit: config.sourceCommit,
        sourceTree: config.sourceTree,
        clinicId: BOUNDED_TREATMENT_TARGET.clinicId
      })) fail(code);
  } else {
    exactKeys(value.failure, ['code', 'operation', 'uncertain'], code);
    if (Object.hasOwn(value, 'outputs') ||
      !/^CNYOS_[A-Z0-9_]+$/.test(String(value.failure.code || '')) ||
      value.failure.uncertain !== (expectedStatus === 'UNCERTAIN') ||
      (value.failure.operation !== null &&
        !mutationContract.some(expected => expected[0] === value.failure.operation) &&
        !postMutationFailureOperations.has(value.failure.operation))) fail(code);
  }
  return value;
}

function successfulTreatmentWrite(write) {
  return write?.requestFailed === false && Number.isInteger(write.responseStatus) &&
    write.responseStatus >= 200 && write.responseStatus < 300;
}

function assertUatRecoveryState(value, fixture, preflight, expectedStatus, code) {
  const writeCount = value.writes.length;
  const readbackCount = value.readbacks.length;
  if (readbackCount > writeCount || value.canonicalPublication !== null ||
    (writeCount > 0 && canonicalJson(value.deployment) !== canonicalJson(preflight)) ||
    value.readbacks.some((_, index) => !successfulTreatmentWrite(value.writes[index]))) {
    fail(code);
  }

  if (expectedStatus === 'FAIL') {
    // A definite failure cannot leave a dispatched write without an exact
    // readback. The executor classifies that state as UNCERTAIN.
    if (writeCount !== readbackCount || value.writes.some(write =>
      !successfulTreatmentWrite(write)) || value.reconciliation !== null) fail(code);
    return;
  }

  const protectedProcessRecovery =
    value.failureCode === 'CNYOS_PROTECTED_FIXTURE_EXCEPTION_AFTER_DISPATCH' &&
    readbackCount === 0 && writeCount >= 1 && writeCount <= fixture.sessions.length &&
    value.writes.every(write => write.requestFailed === true && write.responseStatus === null) &&
    isPlainObject(value.reconciliation) && value.reconciliation.result === 'UNKNOWN' &&
    value.reconciliation.operationId === fixture.sessions[writeCount - 1].operationId &&
    !Object.hasOwn(value.reconciliation, 'rowId');
  if (expectedStatus === 'UNCERTAIN' && protectedProcessRecovery) return;

  if (expectedStatus !== 'UNCERTAIN' || readbackCount >= fixture.sessions.length ||
    writeCount < readbackCount || writeCount > readbackCount + 1 ||
    !isPlainObject(value.reconciliation)) fail(code);

  const unresolvedSession = fixture.sessions[readbackCount];
  if (value.reconciliation.operationId !== unresolvedSession.operationId ||
    (writeCount === readbackCount + 1 &&
      value.writes[readbackCount].operationId !== unresolvedSession.operationId)) fail(code);

  const hasRowId = Object.hasOwn(value.reconciliation, 'rowId');
  if (value.reconciliation.result === 'APPLIED') {
    if (!hasRowId || !UUID_V4.test(String(value.reconciliation.rowId || ''))) fail(code);
  } else if (['NOT_FOUND', 'UNKNOWN'].includes(value.reconciliation.result)) {
    if (hasRowId) fail(code);
  } else if (value.reconciliation.result === 'CONFLICT') {
    if (hasRowId && value.reconciliation.rowId !== null &&
      !UUID_V4.test(String(value.reconciliation.rowId || ''))) fail(code);
  } else fail(code);
}

export function validateUatEvidence(value, config, expectedStatus, context = {}) {
  const code = 'CNYOS_PROTECTED_FIXTURE_UAT_EVIDENCE_INVALID';
  const keys = [
    'schemaVersion', 'evidenceType', 'status', 'runId', 'startedAt', 'observedAt',
    'syntheticOnly', 'realPatientDataAuthorized', 'productionAuthorization',
    'controllerOwnedRunner', 'controller', 'runAuthorization', 'source', 'deployment',
    'canonicalPublication', 'target', 'fixture', 'writes', 'readbacks', 'reconciliation',
    'failureCode', 'mutationLimit', 'cleanup', 'secretsSerialized'
  ];
  assertEvidenceEnvelope(value, config, {
    evidenceType: 'cnyos_staging_bounded_treatment_uat', expectedStatus,
    allowed: keys, required: keys, code
  });
  exactKeys(value.runAuthorization, [
    'evidenceType', 'status', 'decision', 'authorizedAt', 'expiresAt', 'inputSha256',
    'expectedSha256', 'targetSha256', 'fixtureSha256'
  ], code);
  exactKeys(value.mutationLimit, ['allowed', 'observed', 'writeRetries'], code);
  exactKeys(value.fixture, [
    'protectedLedgerEntryId', 'protectedLedgerInputSha256', 'protectedLedgerFileSha256',
    'protectedLedgerExpectedSha256', 'canonicalFixtureSha256', 'protectedLedgerVerifiedAt',
    'practitionerUserId', 'practitionerEmailSha256', 'patientId', 'patientHnSha256',
    'encounterId', 'baselineTreatmentSessionCount'
  ], code);
  if (value.deployment !== null) exactKeys(value.deployment, [
    'siteId', 'deployId', 'immutableOrigin', 'publishedAt', 'manifestFileSha1',
    'manifestSha256', 'sourceCommit', 'sourceTree'
  ], code);
  if (value.canonicalPublication !== null) exactKeys(value.canonicalPublication,
    ['deployId', 'observedAt', 'manifestSha256'], code);
  if (value.reconciliation !== null) {
    allowedKeys(value.reconciliation, ['result', 'operationId', 'rowId'],
      ['result', 'operationId'], code);
  }
  const { fixture, ledger, ledgerFileSha256, runAuthorization,
    runAuthorizationSha256, preflight } = context;
  if (!isPlainObject(fixture) || !isPlainObject(ledger) || !isPlainObject(runAuthorization) ||
    !isPlainObject(preflight) || !SHA256.test(String(runAuthorizationSha256 || '')) ||
    !SHA256.test(String(ledgerFileSha256 || ''))) fail(code);
  const fixtureSha256 = canonicalFixtureSha256(fixture);
  const ledgerInputSha256 = sha256(Buffer.from(canonicalJson(ledger)));
  const expectedFixture = {
    protectedLedgerEntryId: ledger.entryId,
    protectedLedgerInputSha256: ledgerInputSha256,
    protectedLedgerFileSha256: ledgerFileSha256,
    protectedLedgerExpectedSha256: ledgerFileSha256,
    canonicalFixtureSha256: fixtureSha256,
    protectedLedgerVerifiedAt: ledger.verifiedAt,
    practitionerUserId: fixture.practitioner.userId,
    practitionerEmailSha256: sha256(Buffer.from(fixture.practitioner.email)),
    patientId: fixture.patient.id,
    patientHnSha256: sha256(Buffer.from(fixture.patient.hn)),
    encounterId: fixture.encounter.id,
    baselineTreatmentSessionCount: 0
  };
  const authorizationMatches = value.runAuthorization.authorizedAt ===
      runAuthorization.authorizedAt && value.runAuthorization.expiresAt ===
      runAuthorization.expiresAt && value.runAuthorization.inputSha256 ===
      runAuthorizationSha256 && value.runAuthorization.expectedSha256 ===
      runAuthorizationSha256 && value.runAuthorization.targetSha256 ===
      sha256(Buffer.from(canonicalJson(BOUNDED_TREATMENT_TARGET))) &&
      value.runAuthorization.fixtureSha256 === fixtureSha256;
  if (value.runId !== config.fixtureRunId || value.controller.workflowRef !==
      config.runtime.workflowRef || value.controller.policySha256 !== POLICY_SHA256 ||
    value.runAuthorization.evidenceType !== 'cnyos_staging_bounded_treatment_run_authorization' ||
    value.runAuthorization.status !== 'authorized' ||
    value.runAuthorization.decision !== RUN_AUTHORIZATION_DECISION ||
    canonicalJson(value.target) !== canonicalJson(BOUNDED_TREATMENT_TARGET) ||
    !Array.isArray(value.writes) || value.writes.length > 2 ||
    !Array.isArray(value.readbacks) || value.readbacks.length > 2 ||
    value.mutationLimit.allowed !== 2 || value.mutationLimit.observed !== value.writes.length ||
    value.mutationLimit.writeRetries !== 0 || !authorizationMatches ||
    canonicalJson(value.fixture) !== canonicalJson(expectedFixture) ||
    (value.deployment !== null && canonicalJson(value.deployment) !== canonicalJson(preflight))) {
    fail(code);
  }
  assertCanonicalTimestampWindow(value.startedAt, runAuthorization.authorizedAt,
    runAuthorization.expiresAt, code);
  if (expectedStatus === 'PASS') {
    assertCanonicalTimestampWindow(value.observedAt, value.startedAt,
      runAuthorization.expiresAt, code);
  } else {
    // No treatment write is admitted after expiry, but recovery/readback and
    // durable evidence publication must still be able to close the run.
    assertCanonicalTimestampAtOrAfter(value.observedAt, value.startedAt, code);
  }
  for (const [index, write] of value.writes.entries()) {
    exactKeys(write, [
      'ordinal', 'operationId', 'payloadSha256', 'responseStatus', 'requestFailed'
    ], code);
    const statusValid = write.responseStatus === null || Number.isInteger(write.responseStatus);
    if (write.ordinal !== index + 1 || write.operationId !== fixture.sessions[index].operationId ||
      write.payloadSha256 !== expectedTreatmentPayloadSha256(fixture, fixture.sessions[index]) ||
      typeof write.requestFailed !== 'boolean' || !statusValid ||
      (write.requestFailed && write.responseStatus !== null)) fail(code);
  }
  for (const [index, readback] of value.readbacks.entries()) {
    exactKeys(readback, [
      'rowId', 'operationId', 'sessionNo', 'treatmentDetailSha256', 'painBefore', 'painAfter'
    ], code);
    if (!UUID_V4.test(String(readback.rowId || '')) ||
      readback.operationId !== fixture.sessions[index].operationId ||
      readback.sessionNo !== index + 1 || readback.treatmentDetailSha256 !==
        sha256(Buffer.from(fixture.sessions[index].treatmentDetail)) ||
      readback.painBefore !== fixture.sessions[index].painBefore ||
      readback.painAfter !== fixture.sessions[index].painAfter) fail(code);
  }
  if (new Set(value.readbacks.map(readback => readback.rowId)).size !== value.readbacks.length) {
    fail(code);
  }
  if (value.canonicalPublication !== null) {
    if (value.canonicalPublication.deployId !== config.deployId ||
      value.canonicalPublication.manifestSha256 !== preflight.manifestSha256) fail(code);
    assertCanonicalTimestampWindow(value.canonicalPublication.observedAt,
      runAuthorization.authorizedAt, value.observedAt, code);
  }
  if (value.reconciliation !== null) {
    if (!['APPLIED', 'NOT_FOUND', 'CONFLICT', 'UNKNOWN'].includes(value.reconciliation.result) ||
      !fixture.sessions.some(session => session.operationId === value.reconciliation.operationId) ||
      (Object.hasOwn(value.reconciliation, 'rowId') &&
        value.reconciliation.rowId !== null &&
        !UUID_V4.test(String(value.reconciliation.rowId || '')))) fail(code);
  }
  if (expectedStatus === 'PASS' && (value.writes.length !== 2 || value.readbacks.length !== 2 ||
    value.failureCode !== null || !isPlainObject(value.deployment) ||
    !isPlainObject(value.canonicalPublication) || value.reconciliation !== null ||
    value.writes.some(write => write.requestFailed !== false ||
      !Number.isInteger(write.responseStatus) || write.responseStatus < 200 ||
      write.responseStatus >= 300))) fail(code);
  if (expectedStatus !== 'PASS' && !/^CNYOS_[A-Z0-9_]+$/.test(String(value.failureCode || ''))) {
    fail(code);
  }
  if (expectedStatus === 'PASS') {
    if (canonicalJson(value.deployment) !== canonicalJson(preflight)) fail(code);
  } else {
    assertUatRecoveryState(value, fixture, preflight, expectedStatus, code);
  }
  return value;
}

function buildTerminalRecoveryEvidence(config, {
  provisioning,
  runAuthorization,
  runAuthorizationSha256,
  preflight,
  journalEntries,
  startedAt,
  observedAt
}) {
  const fixture = provisioning.fixture;
  const ledger = provisioning.ledger;
  const uncertain = journalEntries.length > 0;
  const status = uncertain ? 'UNCERTAIN' : 'FAIL';
  const value = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_bounded_treatment_uat',
    status,
    runId: config.fixtureRunId,
    startedAt,
    observedAt: observedAt.toISOString(),
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    controllerOwnedRunner: true,
    controller: Object.freeze({
      repository: config.runtime.repository,
      ref: config.runtime.ref,
      commit: config.runtime.commit,
      workflowPath: config.runtime.workflowPath,
      workflowRef: config.runtime.workflowRef,
      runId: config.runtime.runId,
      runAttempt: 1,
      policySha256: POLICY_SHA256
    }),
    runAuthorization: Object.freeze({
      evidenceType: runAuthorization.evidenceType,
      status: runAuthorization.status,
      decision: runAuthorization.decision,
      authorizedAt: runAuthorization.authorizedAt,
      expiresAt: runAuthorization.expiresAt,
      inputSha256: runAuthorizationSha256,
      expectedSha256: runAuthorizationSha256,
      targetSha256: sha256(Buffer.from(canonicalJson(BOUNDED_TREATMENT_TARGET))),
      fixtureSha256: canonicalFixtureSha256(fixture)
    }),
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployment: preflight,
    canonicalPublication: null,
    target: BOUNDED_TREATMENT_TARGET,
    fixture: Object.freeze({
      protectedLedgerEntryId: ledger.entryId,
      protectedLedgerInputSha256: sha256(Buffer.from(canonicalJson(ledger))),
      protectedLedgerFileSha256: provisioning.ledgerFileSha256,
      protectedLedgerExpectedSha256: provisioning.ledgerFileSha256,
      canonicalFixtureSha256: canonicalFixtureSha256(fixture),
      protectedLedgerVerifiedAt: ledger.verifiedAt,
      practitionerUserId: fixture.practitioner.userId,
      practitionerEmailSha256: sha256(Buffer.from(fixture.practitioner.email)),
      patientId: fixture.patient.id,
      patientHnSha256: sha256(Buffer.from(fixture.patient.hn)),
      encounterId: fixture.encounter.id,
      baselineTreatmentSessionCount: 0
    }),
    writes: Object.freeze(journalEntries.map(entry => Object.freeze({
      ordinal: entry.ordinal,
      operationId: entry.operationId,
      payloadSha256: entry.payloadSha256,
      responseStatus: null,
      requestFailed: true
    }))),
    readbacks: Object.freeze([]),
    reconciliation: uncertain ? Object.freeze({
      result: 'UNKNOWN',
      operationId: journalEntries.at(-1).operationId
    }) : null,
    failureCode: uncertain
      ? 'CNYOS_PROTECTED_FIXTURE_EXCEPTION_AFTER_DISPATCH'
      : 'CNYOS_PROTECTED_FIXTURE_EXCEPTION_BEFORE_DISPATCH',
    mutationLimit: Object.freeze({ allowed: 2, observed: journalEntries.length,
      writeRetries: 0 }),
    cleanup: Object.freeze({ status: 'NOT_AUTHORIZED', attempted: false }),
    secretsSerialized: false
  });
  validateUatEvidence(value, config, status, {
    fixture,
    ledger,
    ledgerFileSha256: provisioning.ledgerFileSha256,
    runAuthorization,
    runAuthorizationSha256,
    preflight
  });
  return value;
}

async function publishPrivateEvidence(sourcePath, expectedPath, expectedSha256, artifactName,
  config, { expectedStatus, expectedValue, kind, context }) {
  const record = await readPrivateJsonExact(sourcePath, expectedPath, expectedSha256,
    'CNYOS_PROTECTED_FIXTURE_EVIDENCE_INVALID');
  const { bytes, value } = record;
  if (expectedValue != null && canonicalJson(value) !== canonicalJson(expectedValue)) {
    fail('CNYOS_PROTECTED_FIXTURE_EVIDENCE_RETURN_MISMATCH');
  }
  if (kind === 'provisioning') {
    validateProvisioningEvidence(value, config, expectedStatus, context);
  } else if (kind === 'uat') validateUatEvidence(value, config, expectedStatus, context);
  else fail('CNYOS_PROTECTED_FIXTURE_EVIDENCE_INVALID');
  assertNoSecrets(bytes, config);
  const target = path.join(config.uploadDirectory, artifactName);
  await writeBytesExclusive(target, bytes);
  return Object.freeze({ name: artifactName, sha256: sha256(bytes), bytes: bytes.length,
    status: value.status || null });
}

async function writeRunAuthorizationArtifact(config, authorization) {
  const raw = JSON.stringify(authorization);
  const bytes = Buffer.from(`${raw}\n`);
  assertNoSecrets(bytes, config);
  const filename = path.join(config.uploadDirectory, 'treatment-run-authorization.json');
  await writeBytesExclusive(filename, bytes);
  return Object.freeze({ raw, sha256: sha256(Buffer.from(raw)), filename,
    fileSha256: sha256(bytes), bytes: bytes.length });
}

async function writeEvidenceManifest(config, records, status) {
  const manifest = Object.freeze({
    schemaVersion: 1,
    kind: 'protected_bounded_treatment_evidence_manifest',
    status,
    controller: controllerEvidence(config.runtime),
    source: Object.freeze({ commit: config.sourceCommit, tree: config.sourceTree }),
    deployId: config.deployId,
    fixtureRunId: config.fixtureRunId,
    files: Object.freeze(records.map(record => Object.freeze({
      name: record.name,
      sha256: record.sha256,
      bytes: record.bytes,
      status: record.status ?? null
    })).sort((left, right) => left.name.localeCompare(right.name))),
    uploadedFixtureOrLedger: false,
    cleanup: Object.freeze({ status: 'NOT_AUTHORIZED', attempted: false }),
    secretsSerialized: false
  });
  return writeSecretFreeCanonical(path.join(config.uploadDirectory,
    'evidence-manifest.json'), manifest, config);
}

async function assertArtifactDirectory(config, expectedNames) {
  const entries = await fs.readdir(config.uploadDirectory, { withFileTypes: true });
  const actual = entries.map(entry => entry.name).sort();
  const expected = [...expectedNames].sort();
  if (entries.some(entry => !entry.isFile() || entry.isSymbolicLink()) ||
    actual.length !== expected.length || actual.some((name, index) => name !== expected[index]) ||
    actual.some(name => !ARTIFACT_FILES.includes(name))) {
    fail('CNYOS_PROTECTED_FIXTURE_ARTIFACT_INVENTORY_INVALID');
  }
}

async function validateProvisioningResult(provisioning, config) {
  const code = 'CNYOS_PROTECTED_FIXTURE_PROVISIONING_RESULT_INVALID';
  if (!isPlainObject(provisioning) ||
    !['PASS', 'FAIL', 'UNCERTAIN'].includes(provisioning.status)) fail(code);
  const resultDirectory = path.join(config.fixtureDirectory, 'result');
  for (const directory of [config.fixtureDirectory, resultDirectory]) {
    const status = await fs.lstat(directory).catch(() => null);
    if (!status?.isDirectory() || status.isSymbolicLink() || (status.mode & 0o077) !== 0) {
      fail(code);
    }
  }
  const evidencePath = path.join(resultDirectory, 'provisioning-evidence.json');
  const evidenceRecord = await readPrivateJsonExact(provisioning.evidencePath, evidencePath,
    provisioning.evidenceFileSha256, code);
  if (canonicalJson(evidenceRecord.value) !== canonicalJson(provisioning.evidence)) fail(code);
  if (provisioning.status !== 'PASS') {
    if (provisioning.fixture !== null || provisioning.ledger !== null ||
      provisioning.fixturePath !== null || provisioning.ledgerPath !== null ||
      provisioning.fixtureFileSha256 !== null || provisioning.ledgerFileSha256 !== null) fail(code);
    return Object.freeze({ ...provisioning, evidencePath, evidence: evidenceRecord.value });
  }
  const fixturePath = path.join(resultDirectory, 'treatment-fixture.json');
  const ledgerPath = path.join(resultDirectory, 'protected-treatment-fixture-ledger.json');
  const fixtureRecord = await readPrivateJsonExact(provisioning.fixturePath, fixturePath,
    provisioning.fixtureFileSha256, code);
  const ledgerRecord = await readPrivateJsonExact(provisioning.ledgerPath, ledgerPath,
    provisioning.ledgerFileSha256, code);
  if (canonicalJson(fixtureRecord.value) !== canonicalJson(provisioning.fixture) ||
    canonicalJson(ledgerRecord.value) !== canonicalJson(provisioning.ledger)) fail(code);
  return Object.freeze({
    ...provisioning,
    evidencePath,
    evidence: evidenceRecord.value,
    fixturePath,
    fixture: fixtureRecord.value,
    ledgerPath,
    ledger: ledgerRecord.value,
    fixtureFileSha256: fixtureRecord.sha256,
    ledgerFileSha256: ledgerRecord.sha256
  });
}

export async function runProtectedBoundedTreatmentWorkflow(env = process.env, {
  fetchImpl = fetch,
  chromiumImpl = null,
  now = () => new Date(),
  randomUUID = () => crypto.randomUUID(),
  preflightImpl = preflightExactDeployment,
  provisionImpl = runSingleFixtureProvisioning,
  loadUatConfigImpl = loadBoundedTreatmentConfig,
  executeUatImpl = executeBoundedTreatmentUat,
  writeUatEvidenceImpl = writeEvidenceExclusive
} = {}) {
  const config = loadProtectedFixtureWorkflowConfig(env, { now });
  await prepareProtectedFixtureWorkDirectory(config);
  const preflight = await preflightImpl(config, { fetchImpl });
  const protectedAdmissionHook = createProtectedFixtureAdmissionHook(config);
  let admission = null;
  const admissionHook = async request => {
    admission = await protectedAdmissionHook(request);
    return admission;
  };
  const provisioningResult = await provisionImpl({
    ...env,
    CNYOS_TREATMENT_UAT_RUN_ID: config.fixtureRunId,
    CNYOS_SINGLE_FIXTURE_PROVISION_MODE: 'LIVE',
    CNYOS_SINGLE_FIXTURE_PROVISION_ACK: SINGLE_FIXTURE_PROVISION_ACK,
    CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY: config.fixtureDirectory,
    CNYOS_STAGING_PRACTITIONER_FULL_NAME: config.practitionerFullName
  }, { fetchImpl, authorizationHook: admissionHook, now, randomUUID });
  const provisioning = await validateProvisioningResult(provisioningResult, config);
  const evidenceRecords = [
    await publishPrivateEvidence(provisioning.evidencePath,
      path.join(config.fixtureDirectory, 'result', 'provisioning-evidence.json'),
      provisioning.evidenceFileSha256, 'provisioning-evidence.json', config, {
        expectedStatus: provisioning.status,
        expectedValue: provisioning.evidence,
        kind: 'provisioning',
        context: {
          fixture: provisioning.fixture,
          ledger: provisioning.ledger,
          fixtureFileSha256: provisioning.fixtureFileSha256,
          ledgerFileSha256: provisioning.ledgerFileSha256,
          admission
        }
      })
  ];
  const admissionNames = [
    'controller-admission-evidence.json',
    'controller-authorization-bundle.json'
  ];
  for (const name of admissionNames) {
    const bytes = await fs.readFile(path.join(config.uploadDirectory, name));
    evidenceRecords.push(Object.freeze({ name, sha256: sha256(bytes), bytes: bytes.length,
      status: 'authorized' }));
  }
  if (provisioning.status !== 'PASS') {
    await writeEvidenceManifest(config, evidenceRecords, provisioning.status);
    await assertArtifactDirectory(config, [...admissionNames, 'provisioning-evidence.json',
      'evidence-manifest.json']);
    return Object.freeze({ status: provisioning.status, provisioning, uat: null });
  }

  const runAuthorization = buildProtectedTreatmentRunAuthorization(config, provisioning.fixture,
    { now });
  const authorizationRecord = await writeRunAuthorizationArtifact(config, runAuthorization);
  evidenceRecords.push(Object.freeze({
    name: 'treatment-run-authorization.json',
    sha256: authorizationRecord.fileSha256,
    bytes: authorizationRecord.bytes,
    status: 'authorized'
  }));
  const uatEnv = {
    ...env,
    CNYOS_TREATMENT_UAT_RUN_ID: config.fixtureRunId,
    CNYOS_TREATMENT_UAT_ACK: BOUNDED_TREATMENT_ACK,
    CNYOS_STAGING_TREATMENT_FIXTURE_JSON: JSON.stringify(provisioning.fixture),
    CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH: provisioning.ledgerPath,
    CNYOS_EXPECTED_TREATMENT_FIXTURE_LEDGER_SHA256: provisioning.ledgerFileSha256,
    CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON: authorizationRecord.raw,
    CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256: authorizationRecord.sha256,
    CNYOS_CONTROLLER_UAT_EVIDENCE_PATH: config.uatEvidencePath
  };
  const uatStartedAt = now().toISOString();
  const mutationJournal = await createMutationJournal(config, provisioning.fixture,
    uatStartedAt, now);
  try {
    const uatConfig = await loadUatConfigImpl(uatEnv, { now });
    const uat = await executeUatImpl(uatConfig, {
      fetchImpl,
      chromiumImpl,
      now,
      onTreatmentWriteDispatch: mutationJournal.latch
    });
    const journalEntries = await readMutationJournal(mutationJournal, config,
      provisioning.fixture);
    if (journalEntries.length !== uat.writes?.length || journalEntries.some((entry, index) =>
      entry.ordinal !== uat.writes[index]?.ordinal ||
      entry.operationId !== uat.writes[index]?.operationId ||
      entry.payloadSha256 !== uat.writes[index]?.payloadSha256)) {
      fail('CNYOS_PROTECTED_FIXTURE_MUTATION_JOURNAL_MISMATCH');
    }
    await writeUatEvidenceImpl(config.uatEvidencePath, uat);
    evidenceRecords.push(await publishPrivateEvidence(config.uatEvidencePath,
      config.uatEvidencePath, null, 'uat-evidence.json', config, {
        expectedStatus: uat.status,
        expectedValue: uat,
        kind: 'uat',
        context: {
          fixture: provisioning.fixture,
          ledger: provisioning.ledger,
          ledgerFileSha256: provisioning.ledgerFileSha256,
          runAuthorization,
          runAuthorizationSha256: authorizationRecord.sha256,
          preflight
        }
      }));
    await writeEvidenceManifest(config, evidenceRecords, uat.status);
    await assertArtifactDirectory(config, ARTIFACT_FILES);
    return Object.freeze({ status: uat.status, provisioning, uat });
  } catch {
    const journalEntries = await readMutationJournal(mutationJournal, config,
      provisioning.fixture);
    const uat = buildTerminalRecoveryEvidence(config, {
      provisioning,
      runAuthorization,
      runAuthorizationSha256: authorizationRecord.sha256,
      preflight,
      journalEntries,
      startedAt: uatStartedAt,
      observedAt: now()
    });
    const terminalRecord = await writeSecretFreeCanonical(path.join(config.uploadDirectory,
      'uat-evidence.json'), uat, config);
    evidenceRecords.push(Object.freeze({
      name: 'uat-evidence.json',
      sha256: terminalRecord.sha256,
      bytes: terminalRecord.bytes,
      status: uat.status
    }));
    await writeEvidenceManifest(config, evidenceRecords, uat.status);
    await assertArtifactDirectory(config, ARTIFACT_FILES);
    return Object.freeze({ status: uat.status, provisioning, uat });
  } finally {
    await mutationJournal.close().catch(() => {});
  }
}

function safeCode(error) {
  const value = String(error?.code || error?.message || '');
  return /^CNYOS_[A-Z0-9_:.-]+$/.test(value)
    ? value
    : 'CNYOS_PROTECTED_FIXTURE_WORKFLOW_FAILED';
}

async function main() {
  try {
    const result = await runProtectedBoundedTreatmentWorkflow(process.env);
    process.stderr.write(`CNYOS_PROTECTED_FIXTURE_WORKFLOW_${result.status}\n`);
    process.exitCode = result.status === 'PASS' ? 0 : result.status === 'UNCERTAIN' ? 2 : 1;
  } catch (error) {
    process.stderr.write(`${safeCode(error)}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();
