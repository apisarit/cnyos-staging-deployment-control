import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_TREATMENT_TARGET,
  canonicalFixtureSha256,
  canonicalJson,
  validateBoundedTreatmentRunAuthorization,
  validateTreatmentFixture
} from '../scripts/bounded-treatment-uat.mjs';
import { POLICY, POLICY_SHA256 } from '../scripts/policy.mjs';
import {
  buildSingleFixtureProvisioningPlan,
  loadSingleFixtureProvisioningConfig
} from '../scripts/provision-bounded-treatment-fixture.mjs';
import {
  PROTECTED_FIXTURE_GITHUB_ENVIRONMENT,
  PROTECTED_FIXTURE_SECRET_NAMES,
  PROTECTED_FIXTURE_WORKFLOW_PATH,
  ProtectedFixtureWorkflowError,
  assertSecretFreeJsonEvidence,
  buildProtectedTreatmentRunAuthorization,
  createProtectedFixtureAdmissionHook,
  loadProtectedFixtureWorkflowConfig,
  prepareProtectedFixtureWorkDirectory,
  protectedSyntheticFixtureRunId,
  protectedSyntheticPractitionerEmail,
  runProtectedBoundedTreatmentWorkflow,
  validateProvisioningEvidence,
  validateUatEvidence
} from '../scripts/run-protected-bounded-treatment-uat.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(packageRoot, '..', '..');
const workflow = await fs.readFile(path.join(repositoryRoot,
  '.github/workflows/cnyos-staging-release.yml'), 'utf8');
const testRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-protected-fixture-workflow-'));
const nowValue = new Date('2026-10-08T10:00:00.000Z');
const sourceCommit = 'b'.repeat(40);
const sourceTree = 'c'.repeat(40);
const controllerCommit = 'd'.repeat(40);
const deployId = 'a'.repeat(24);
const runReference = 'external-treatment-run-20261008';
const fixtureRunId = protectedSyntheticFixtureRunId(runReference);
const practitionerEmail = protectedSyntheticPractitionerEmail(fixtureRunId);
const publishableKey = `sb_publishable_${'P'.repeat(24)}`;
const serviceRoleKey = 'SERVICE-ROLE-DO-NOT-SERIALIZE-1234567890';
const password = 'PASSWORD-DO-NOT-SERIALIZE-1234567890';
const netlifyToken = 'NETLIFY-TOKEN-DO-NOT-SERIALIZE-1234567890';
const operationIds = [
  '44444444-4444-4444-8444-444444444444',
  '55555555-5555-4555-8555-555555555555'
];

function envFor(workDirectory) {
  return {
    GITHUB_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: '91000018',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: controllerCommit,
    GITHUB_WORKFLOW_SHA: controllerCommit,
    GITHUB_WORKFLOW_REF:
      `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@` +
      POLICY.controller.protectedRef,
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_ACTOR: 'fixture-operator',
    GITHUB_TRIGGERING_ACTOR: 'fixture-operator',
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
    CNYOS_CONTROLLER_ENVIRONMENT: PROTECTED_FIXTURE_GITHUB_ENVIRONMENT,
    CNYOS_PROTECTED_UAT_WORK_DIRECTORY: workDirectory,
    CNYOS_TREATMENT_UAT_RUN_REFERENCE: runReference,
    CNYOS_EXPECTED_SOURCE_COMMIT: sourceCommit,
    CNYOS_EXPECTED_SOURCE_TREE: sourceTree,
    CNYOS_EXPECTED_NETLIFY_DEPLOY_ID: deployId,
    CNYOS_STAGING_PRACTITIONER_EMAIL: practitionerEmail,
    CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY: publishableKey,
    CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: serviceRoleKey,
    CNYOS_STAGING_TEST_PASSWORD: password,
    CNYOS_STAGING_NETLIFY_AUTH_TOKEN: netlifyToken
  };
}

function fixtureValue() {
  return validateTreatmentFixture({
    schemaVersion: 1,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    clinic: { id: BOUNDED_TREATMENT_TARGET.clinicId, code: BOUNDED_TREATMENT_TARGET.clinicCode },
    practitioner: {
      userId: '11111111-1111-4111-8111-111111111111',
      email: practitionerEmail,
      role: 'practitioner',
      syntheticMarkerVerified: true
    },
    patient: {
      id: '22222222-2222-4222-8222-222222222222',
      hn: 'SYNTHETIC-HN-20261008',
      paymentRight: 'SYNTHETIC-E2E',
      syntheticMarkerVerified: true,
      realIdentifiersAbsent: true
    },
    encounter: {
      id: '33333333-3333-4333-8333-333333333333',
      patientId: '22222222-2222-4222-8222-222222222222',
      practitionerUserId: '11111111-1111-4111-8111-111111111111',
      status: 'draft',
      baselineTreatmentSessionCount: 0
    },
    sessions: operationIds.map((operationId, index) => ({
      operationId,
      modalities: ['นวดไทย'],
      treatmentDetail:
        `SYNTHETIC ${fixtureRunId} SESSION ${index + 1} - NOT FOR CLINICAL USE`,
      procedureReferral: false,
      procedureReferralDetail: null,
      precautions: index === 0 ? 'synthetic fixture only' : null,
      painBefore: index === 0 ? 4 : 2,
      painAfter: index === 0 ? 2 : 1,
      outcomeSummary: index === 0 ? 'synthetic improvement' : 'synthetic stable',
      advice: index === 0 ? 'synthetic follow-up only' : null
    }))
  }, { runId: fixtureRunId, practitionerEmail });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function expectedPayloadSha256(session) {
  return crypto.createHash('sha256').update(JSON.stringify({
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
  })).digest('hex');
}

function assertCode(fn, code) {
  assert.throws(fn, error => (error instanceof ProtectedFixtureWorkflowError &&
    error.code === code) || error?.message === code);
}

for (const escapedSecret of [
  'PASSWORD-"QUOTED-SECRET-1234567890',
  'PASSWORD-\\BACKSLASH-SECRET-1234567890',
  'PASSWORD-NEWLINE\nSECRET-1234567890'
]) {
  assertCode(() => assertSecretFreeJsonEvidence(Buffer.from(JSON.stringify({
    schemaVersion: 1,
    nested: { leaked: `prefix:${escapedSecret}:suffix` }
  })), [escapedSecret]), 'CNYOS_PROTECTED_FIXTURE_SECRET_SERIALIZATION_BLOCKED');
}

assert.equal(PROTECTED_FIXTURE_WORKFLOW_PATH, POLICY.controller.releaseWorkflowPath);
assert.equal(PROTECTED_FIXTURE_GITHUB_ENVIRONMENT, 'cnyos-staging-publish');
assert.deepEqual(PROTECTED_FIXTURE_SECRET_NAMES, [
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY',
  'CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.match(workflow, /^on:\n  workflow_dispatch:\n/m);
assert.doesNotMatch(workflow, /^\s+(?:pull_request|push|workflow_run|schedule):/m);
const boundedJobEnvironment = workflow.match(/\n  bounded-treatment:\n[\s\S]*?\n    env:\n([\s\S]*?)\n    steps:\n/);
assert.ok(boundedJobEnvironment, 'bounded treatment job environment must be present');
assert.doesNotMatch(boundedJobEnvironment[1], /\$\{\{\s*runner\./,
  'GitHub cannot resolve the runner context in a job-level environment');
const initializeWorkDirectory = workflow.match(
  /\n    steps:\n      - name: Initialize protected work directory\n        shell: bash\n        run: \|\n((?:          .*\n)+)/);
assert.ok(initializeWorkDirectory,
  'initialize the shared directory before any bounded treatment job step can fail');
const initializeScript = initializeWorkDirectory[1].replace(/^          /gm, '');
assert.doesNotMatch(initializeScript, /\$\{\{/,
  'directory initialization must use runner-provided shell variables');
const runnerTemp = path.join(testRoot, 'runner temp');
await fs.mkdir(runnerTemp);
for (const runId of ['91000018', '91000019']) {
  const environmentFile = path.join(testRoot, `github-env-${runId}`);
  const initialized = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', initializeScript], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin', RUNNER_TEMP: runnerTemp,
      GITHUB_RUN_ID: runId, GITHUB_ENV: environmentFile }
  });
  assert.equal(initialized.status, 0, initialized.stderr);
  assert.equal(initialized.stdout, '', 'initialization must not print runtime environment values');
  const workDirectory = `${runnerTemp}/cnyos-protected-bounded-treatment-${runId}`;
  assert.equal(await fs.readFile(environmentFile, 'utf8'),
    `CNYOS_PROTECTED_UAT_WORK_DIRECTORY=${workDirectory}\n`);
  await assert.rejects(fs.stat(workDirectory), { code: 'ENOENT' },
    'the runner must remain responsible for creating its private work directory');
  const uploadPaths = [...workflow.matchAll(/^            (\$\{\{ runner\.temp \}\}\/.*)$/gm)]
    .map(match => match[1].replace('${{ runner.temp }}', runnerTemp)
      .replace('${{ github.run_id }}', runId));
  assert.equal(uploadPaths.length, 6);
  assert.ok(uploadPaths.every(filename => path.dirname(filename) === `${workDirectory}/upload`),
    'every explicit evidence upload must use the initialized work directory');
}
for (const missing of ['RUNNER_TEMP', 'GITHUB_RUN_ID', 'GITHUB_ENV']) {
  const environmentFile = path.join(testRoot, `missing-${missing}`);
  const env = { PATH: '/usr/bin:/bin', RUNNER_TEMP: runnerTemp,
    GITHUB_RUN_ID: '91000018', GITHUB_ENV: environmentFile };
  delete env[missing];
  const initialized = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', initializeScript], {
    encoding: 'utf8', env
  });
  assert.notEqual(initialized.status, 0, `${missing} must not default to an unsafe directory`);
  await assert.rejects(fs.stat(environmentFile), { code: 'ENOENT' });
}
for (const input of ['app_commit', 'app_tree', 'netlify_deploy_id', 'run_id',
  'practitioner_email']) {
  assert.match(workflow, new RegExp(`^      ${input}:$`, 'm'));
}
assert.match(workflow, /^  admit-controller-runtime:$/m);
assert.match(workflow, /^    needs: admit-controller-runtime$/m);
assert.match(workflow,
  /Reject every non-protected or non-initial main dispatch[\s\S]*test "\$GITHUB_REF" = "refs\/heads\/main"[\s\S]*test "\$GITHUB_REF_PROTECTED" = "true"/);
assert.doesNotMatch(workflow, /^\s+if:.*github\.ref_protected/m,
  'invalid refs must execute a failing admission job, not skip green');
assert.match(workflow,
  /CNYOS_TREATMENT_UAT_RUN_REFERENCE: \$\{\{ inputs\.run_id \}\}/);
assert.doesNotMatch(workflow, /CNYOS_TREATMENT_UAT_RUN_ID:/);
assert.match(workflow, /environment:\n\s+name: cnyos-staging-publish/);
assert.match(workflow, /permissions:\n  contents: read/);
assert.doesNotMatch(workflow, /id-token:\s*write/);
assert.match(workflow, /node-version: 24/);
assert.match(workflow, /GITHUB_REF_PROTECTED/);
assert.match(workflow, /GITHUB_WORKFLOW_SHA.*GITHUB_SHA/);
assert.match(workflow, /GITHUB_RUN_ATTEMPT.*1/);
assert.match(workflow, /npx --no-install playwright install --with-deps chromium/);
assert.match(workflow, /node scripts\/run-protected-bounded-treatment-uat\.mjs/);
assert.match(workflow, /retention-days: 3/);
assert.match(workflow,
  new RegExp(`group: cnyos-bounded-treatment-${BOUNDED_TREATMENT_TARGET.netlifySiteId}`),
  'all runs against the one policy-bound staging site must share a stable concurrency group');
assert.doesNotMatch(workflow, /group:.*github\.run_id/,
  'a per-run concurrency group cannot serialize writers to the shared staging target');
assert.match(workflow,
  /name: Require the complete secret-free terminal evidence set[\s\S]*id: terminal-evidence[\s\S]*if: \$\{\{ always\(\) \}\}/);
assert.match(workflow,
  /mapfile -t actual[\s\S]*find "\$upload_dir" -mindepth 1 -maxdepth 1 -printf[\s\S]*test "\$\{#actual\[@\]\}" -eq "\$\{#expected_sorted\[@\]\}"/,
  'terminal evidence validation must reject partial and additional evidence sets');
assert.match(workflow, /stat -c '%a'.*evidence_path.*= "600"/,
  'terminal evidence must remain owner-readable only');
assert.match(workflow, /JSON\.parse\(fs\.readFileSync\(filename, "utf8"\)\)/,
  'terminal evidence must be parseable JSON before artifact publication');
assert.match(workflow,
  /if: \$\{\{ always\(\) && steps\.terminal-evidence\.outcome == 'success' \}\}[\s\S]*if-no-files-found: error/,
  'artifact publication must require the complete terminal evidence gate');
assert.doesNotMatch(workflow, /if-no-files-found:\s*warn/);
for (const artifact of [
  'controller-admission-evidence.json',
  'controller-authorization-bundle.json',
  'evidence-manifest.json',
  'provisioning-evidence.json',
  'treatment-run-authorization.json',
  'uat-evidence.json'
]) {
  assert.equal((workflow.match(new RegExp(`/upload/${artifact.replace('.', '\\.')}\\n`, 'g')) ||
    []).length, 1, `${artifact} must be the only explicitly uploaded occurrence`);
}
assert.doesNotMatch(workflow, /\/upload\s*$/m,
  'the artifact action must never upload the whole directory');
for (const reference of [
  'actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd',
  'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
  'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
]) assert.ok(workflow.includes(reference));
assert.doesNotMatch(workflow, /uses:\s*[^\n]+@(?![0-9a-f]{40}(?:\s|#|$))/);
assert.doesNotMatch(workflow, /\$\{\{\s*vars\./);
assert.doesNotMatch(workflow, /CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY:\s*\$\{\{ inputs\./);
assert.doesNotMatch(workflow, /(?:rm|truncate|delete|cleanup)[ -]/i);
for (const name of PROTECTED_FIXTURE_SECRET_NAMES) {
  assert.match(workflow, new RegExp(`secrets\\.${name}`));
  assert.equal((workflow.match(new RegExp(`secrets\\.${name}`, 'g')) || []).length, 1,
    `${name} must be exposed to exactly one step`);
}
const credentialedStepStart = workflow.indexOf(
  '      - name: Provision one fixture and run exactly two treatment writes');
const credentialedStepEnd = workflow.indexOf(
  '      - name: Upload secret-free bounded evidence', credentialedStepStart);
assert.ok(credentialedStepStart > 0 && credentialedStepEnd > credentialedStepStart);
assert.doesNotMatch(workflow.slice(0, credentialedStepStart), /\$\{\{\s*secrets\./,
  'checkout and install steps must not receive staging credentials');
assert.doesNotMatch(workflow.slice(credentialedStepEnd), /\$\{\{\s*secrets\./,
  'artifact upload must not receive staging credentials');

const baseEnv = envFor(path.join(testRoot, 'base'));
const baseConfig = loadProtectedFixtureWorkflowConfig(baseEnv, { now: () => nowValue });
assert.equal(baseConfig.runtime.ref, POLICY.controller.protectedRef);
assert.equal(baseConfig.runtime.commit, controllerCommit);
assert.equal(baseConfig.sourceCommit, sourceCommit);
assert.equal(baseConfig.sourceTree, sourceTree);
assert.equal(baseConfig.deployId, deployId);
assert.equal(baseConfig.fixtureRunId, protectedSyntheticFixtureRunId(runReference));
assert.notEqual(baseConfig.fixtureRunId, runReference);
assert.equal(baseConfig.practitionerFullName.includes(runReference), false);
assert.equal(baseConfig.authorizedAt, nowValue.toISOString());
assert.equal(baseConfig.expiresAt, '2026-10-08T10:25:00.000Z');

for (const [patch, code] of [
  [{ GITHUB_EVENT_NAME: 'pull_request' }, 'CNYOS_PROTECTED_FIXTURE_EVENT_INVALID'],
  [{ GITHUB_REF_PROTECTED: 'false' }, 'CNYOS_CONTROLLER_REF_NOT_PROTECTED'],
  [{ GITHUB_REF: 'refs/heads/feature' }, 'CNYOS_CONTROLLER_REF_MISMATCH'],
  [{ GITHUB_RUN_ATTEMPT: '2' }, 'CNYOS_CONTROLLER_RERUN_REJECTED'],
  [{ GITHUB_WORKFLOW_SHA: 'e'.repeat(40) },
    'CNYOS_PROTECTED_FIXTURE_WORKFLOW_SHA_MISMATCH'],
  [{ CNYOS_CONTROLLER_ENVIRONMENT: 'staging' },
    'CNYOS_PROTECTED_FIXTURE_ENVIRONMENT_INVALID'],
  [{ ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.invalid/token' },
    'CNYOS_PROTECTED_FIXTURE_OIDC_CAPABILITY_FORBIDDEN'],
  [{ CNYOS_STAGING_PRACTITIONER_EMAIL: 'real.person@example.com' },
    'CNYOS_PROTECTED_FIXTURE_EMAIL_INVALID'],
  [{ CNYOS_CONTROLLER_WORKFLOW_PATH: '.github/workflows/untrusted.yml' },
    'CNYOS_CONTROLLER_WORKFLOW_PATH_INVALID'],
  [{ GITHUB_ACTOR: 'other-operator' }, 'CNYOS_CONTROLLER_ACTOR_MISMATCH']
]) {
  assertCode(() => loadProtectedFixtureWorkflowConfig({ ...baseEnv, ...patch },
    { now: () => nowValue }), code);
}
for (const secretName of [
  'CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]) {
  assertCode(() => loadProtectedFixtureWorkflowConfig({ ...baseEnv, [secretName]: '' },
    { now: () => nowValue }), `CNYOS_PROTECTED_FIXTURE_${
      secretName === 'CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY' ? 'PUBLISHABLE_KEY' :
      secretName === 'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY' ? 'SERVICE_ROLE_KEY' :
      secretName === 'CNYOS_STAGING_TEST_PASSWORD' ? 'PASSWORD' : 'NETLIFY_TOKEN'}_REQUIRED`);
}

const admissionEnv = envFor(path.join(testRoot, 'admission'));
const admissionConfig = loadProtectedFixtureWorkflowConfig(admissionEnv,
  { now: () => nowValue });
await prepareProtectedFixtureWorkDirectory(admissionConfig);
const singleConfig = loadSingleFixtureProvisioningConfig({
  ...admissionEnv,
  CNYOS_TREATMENT_UAT_RUN_ID: admissionConfig.fixtureRunId,
  CNYOS_SINGLE_FIXTURE_PROVISION_MODE: 'LIVE',
  CNYOS_SINGLE_FIXTURE_PROVISION_ACK:
    'I_AUTHORIZE_ONE_FRESH_SYNTHETIC_PRACTITIONER_PATIENT_AND_DRAFT_ENCOUNTER',
  CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY: admissionConfig.fixtureDirectory,
  CNYOS_STAGING_PRACTITIONER_FULL_NAME: admissionConfig.practitionerFullName
}, { randomUUID: (() => {
  let index = 0;
  return () => operationIds[index++];
})() });
const planRecord = buildSingleFixtureProvisioningPlan(singleConfig);
const hook = createProtectedFixtureAdmissionHook(admissionConfig);
const receipt = await hook({
  plan: planRecord.plan,
  planSha256: planRecord.sha256,
  runtime: singleConfig.runtime
});
assert.equal(receipt.status, 'authorized');
assert.equal(receipt.controllerCommit, controllerCommit);
assert.equal(receipt.sourceCommit, sourceCommit);
assert.equal(receipt.targetSiteId, BOUNDED_TREATMENT_TARGET.netlifySiteId);
assert.match(receipt.authorizationEvidenceSha256, /^[0-9a-f]{64}$/);
assert.match(receipt.authorizationBundleSha256, /^[0-9a-f]{64}$/);
for (const mutate of [
  plan => { plan.target.netlifySiteName = 'attacker-controlled-staging'; },
  plan => { plan.policySha256 = '0'.repeat(64); },
  plan => { plan.controller.repository = 'attacker/controller'; },
  plan => { plan.controller.ref = 'refs/heads/attacker'; },
  plan => { plan.controller.workflowPath = '.github/workflows/attacker.yml'; },
  plan => { plan.controller.runId = '99999999'; },
  plan => { plan.limits.cleanupAuthorized = true; },
  plan => { plan.limits.serviceRoleTableWrites = 999; },
  plan => { plan.practitioner.email = 'real.person@example.com'; },
  plan => { plan.operationIds[0] = '44444444-4444-1444-8444-444444444444'; },
  plan => { plan.operationIds[1] = plan.operationIds[0].toUpperCase(); }
]) {
  const tamperedPlan = clone(planRecord.plan);
  mutate(tamperedPlan);
  const tamperedPlanSha256 = crypto.createHash('sha256')
    .update(canonicalJson(tamperedPlan)).digest('hex');
  await assert.rejects(() => createProtectedFixtureAdmissionHook(admissionConfig)({
    plan: tamperedPlan,
    planSha256: tamperedPlanSha256,
    runtime: singleConfig.runtime
  }), /CNYOS_PROTECTED_FIXTURE_ADMISSION_REQUEST_INVALID/);
}
await assert.rejects(() => hook({
  plan: planRecord.plan,
  planSha256: planRecord.sha256,
  runtime: singleConfig.runtime
}), /CNYOS_PROTECTED_FIXTURE_ADMISSION_REPLAYED/);
for (const name of ['controller-admission-evidence.json',
  'controller-authorization-bundle.json']) {
  const bytes = await fs.readFile(path.join(admissionConfig.uploadDirectory, name));
  assert.ok(!bytes.includes(Buffer.from(serviceRoleKey)));
  assert.ok(!bytes.includes(Buffer.from(password)));
  assert.ok(!bytes.includes(Buffer.from(netlifyToken)));
  assert.equal((await fs.stat(path.join(admissionConfig.uploadDirectory, name))).mode & 0o777,
    0o600);
}

const fixture = fixtureValue();
const runAuthorization = buildProtectedTreatmentRunAuthorization(admissionConfig, fixture,
  { now: () => nowValue });
assert.equal(runAuthorization.policySha256, POLICY_SHA256);
assert.equal(runAuthorization.run.fixtureSha256, canonicalFixtureSha256(fixture));
validateBoundedTreatmentRunAuthorization(runAuthorization, {
  runtime: admissionConfig.runtime,
  runId: fixtureRunId,
  sourceCommit,
  sourceTree,
  deployId,
  fixture,
  now: nowValue
});

const orchestrationEnv = envFor(path.join(testRoot, 'orchestration'));
let observedUatEnv;
let observedAdmission;
let observedProvisioningEvidence;
let observedUatEvidence;
const phases = [];
const preflightEvidence = {
  siteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
  deployId,
  immutableOrigin:
    `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`,
  publishedAt: nowValue.toISOString(),
  manifestFileSha1: 'e'.repeat(40),
  manifestSha256: 'f'.repeat(64),
  sourceCommit,
  sourceTree
};
const ledger = {
  schemaVersion: 1,
  kind: 'protected_staging_fixture_ledger',
  entryId: `fixture:treatment:${fixtureRunId}`,
  fixtureSha256: canonicalFixtureSha256(fixture),
  verifiedAt: nowValue.toISOString(),
  target: {
    siteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
    deployId,
    sourceCommit,
    sourceTree,
    clinicId: BOUNDED_TREATMENT_TARGET.clinicId
  },
  fixtureIds: {
    practitionerUserId: fixture.practitioner.userId,
    patientId: fixture.patient.id,
    encounterId: fixture.encounter.id,
    operationIds
  }
};
const fixtureBytes = Buffer.from(`${JSON.stringify(fixture)}\n`);
const ledgerBytes = Buffer.from(`${JSON.stringify(ledger)}\n`);
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function provisioningEvidenceValue(plan, admission) {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_single_bounded_treatment_fixture_provisioning',
    status: 'PASS',
    startedAt: nowValue.toISOString(),
    observedAt: nowValue.toISOString(),
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    controllerOwnedRunner: true,
    controller: {
      repository: POLICY.controller.repository,
      ref: POLICY.controller.protectedRef,
      commit: controllerCommit,
      workflowPath: POLICY.controller.releaseWorkflowPath,
      runId: '91000018',
      runAttempt: 1
    },
    policySha256: POLICY_SHA256,
    planSha256: crypto.createHash('sha256').update(canonicalJson(plan)).digest('hex'),
    authorization: {
      decision: admission.decision,
      authorizationEvidenceSha256: admission.authorizationEvidenceSha256,
      authorizationBundleSha256: admission.authorizationBundleSha256,
      authorizedAt: admission.authorizedAt,
      expiresAt: admission.expiresAt
    },
    target: BOUNDED_TREATMENT_TARGET,
    source: { commit: sourceCommit, tree: sourceTree },
    deployId,
    fixtureRunId,
    practitionerEmailSha256: digest(Buffer.from(practitionerEmail)),
    fixtureIds: {
      practitionerUserId: fixture.practitioner.userId,
      patientId: fixture.patient.id,
      patientHnSha256: digest(Buffer.from(fixture.patient.hn)),
      encounterId: fixture.encounter.id,
      operationIds
    },
    invariants: {
      freshAuthUser: true,
      authoritativeSyntheticMetadataVerified: true,
      controlPlaneReadbackVerified: true,
      exactClinicalReadbackVerified: true,
      baselineTreatmentSessions: 0,
      baselinePrescriptions: 0,
      baselineVitalSigns: 0,
      baselinePainAssessments: 0,
      baselineAllergies: 0
    },
    mutations: [
      ['create_auth_user', 'service_role', '/auth/v1/admin/users'],
      ['upsert_profile', 'service_role', '/rest/v1/profiles'],
      ['insert_clinic_membership', 'service_role', '/rest/v1/clinic_memberships'],
      ['upsert_patient_registration', 'practitioner',
        '/rest/v1/rpc/upsert_patient_registration'],
      ['start_manual_patient_encounter', 'practitioner',
        '/rest/v1/rpc/start_manual_patient_encounter']
    ].map(([name, authority, resource], index) => ({
      ordinal: index + 1, name, authority, resource, dispatched: true,
      responseStatus: 200, requestFailed: false
    })),
    mutationLimit: {
      freshAuthUsers: 1, serviceRoleTableWrites: 2, authenticatedClinicalRpcWrites: 2,
      writeRetries: 0, observedRetries: 0
    },
    failure: null,
    cleanup: { status: 'NOT_AUTHORIZED', attempted: false },
    secretsSerialized: false,
    outputs: {
      fixture: { name: 'treatment-fixture.json', sha256: digest(fixtureBytes), mode: '0600' },
      protectedLedger: {
        name: 'protected-treatment-fixture-ledger.json',
        sha256: digest(ledgerBytes), mode: '0600'
      }
    }
  };
}

function uatEvidenceValue(environment) {
  const authorization = JSON.parse(environment.CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON);
  const sha = preflightEvidence.manifestSha256;
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_bounded_treatment_uat',
    status: 'PASS',
    runId: fixtureRunId,
    startedAt: nowValue.toISOString(),
    observedAt: nowValue.toISOString(),
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    controllerOwnedRunner: true,
    controller: {
      repository: POLICY.controller.repository, ref: POLICY.controller.protectedRef,
      commit: controllerCommit, workflowPath: POLICY.controller.releaseWorkflowPath,
      workflowRef: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}` +
        `@${POLICY.controller.protectedRef}`,
      runId: '91000018', runAttempt: 1, policySha256: POLICY_SHA256
    },
    runAuthorization: {
      evidenceType: authorization.evidenceType, status: authorization.status,
      decision: authorization.decision, authorizedAt: authorization.authorizedAt,
      expiresAt: authorization.expiresAt,
      inputSha256: environment.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256,
      expectedSha256: environment.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256,
      targetSha256: digest(Buffer.from(canonicalJson(BOUNDED_TREATMENT_TARGET))),
      fixtureSha256: canonicalFixtureSha256(fixture)
    },
    source: { commit: sourceCommit, tree: sourceTree },
    deployment: preflightEvidence,
    canonicalPublication: { deployId, observedAt: nowValue.toISOString(), manifestSha256: sha },
    target: BOUNDED_TREATMENT_TARGET,
    fixture: {
      protectedLedgerEntryId: ledger.entryId,
      protectedLedgerInputSha256: digest(Buffer.from(canonicalJson(ledger))),
      protectedLedgerFileSha256: digest(ledgerBytes),
      protectedLedgerExpectedSha256: digest(ledgerBytes),
      canonicalFixtureSha256: canonicalFixtureSha256(fixture),
      protectedLedgerVerifiedAt: ledger.verifiedAt,
      practitionerUserId: fixture.practitioner.userId,
      practitionerEmailSha256: digest(Buffer.from(practitionerEmail)),
      patientId: fixture.patient.id, patientHnSha256: digest(Buffer.from(fixture.patient.hn)),
      encounterId: fixture.encounter.id, baselineTreatmentSessionCount: 0
    },
    writes: operationIds.map((operationId, index) => ({
      ordinal: index + 1, operationId,
      payloadSha256: expectedPayloadSha256(fixture.sessions[index]),
      responseStatus: 200, requestFailed: false
    })),
    readbacks: operationIds.map((operationId, index) => ({
      rowId: `${index + 6}6666666-6666-4666-8666-666666666666`, operationId,
      sessionNo: index + 1,
      treatmentDetailSha256: digest(Buffer.from(fixture.sessions[index].treatmentDetail)),
      painBefore: fixture.sessions[index].painBefore, painAfter: fixture.sessions[index].painAfter
    })),
    reconciliation: null,
    failureCode: null,
    mutationLimit: { allowed: 2, observed: 2, writeRetries: 0 },
    cleanup: { status: 'NOT_AUTHORIZED', attempted: false },
    secretsSerialized: false
  };
}
const orchestration = await runProtectedBoundedTreatmentWorkflow(orchestrationEnv, {
  now: () => nowValue,
  preflightImpl: async () => {
    phases.push('preflight');
    return preflightEvidence;
  },
  provisionImpl: async (environment, options) => {
    assert.deepEqual(phases, ['preflight']);
    phases.push('provision');
    const fixtureDirectory = environment.CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY;
    await fs.mkdir(fixtureDirectory, { mode: 0o700 });
    const resultDirectory = path.join(fixtureDirectory, 'result');
    await fs.mkdir(resultDirectory, { mode: 0o700 });
    const provisioningPath = path.join(resultDirectory, 'provisioning-evidence.json');
    const fixturePath = path.join(resultDirectory, 'treatment-fixture.json');
    const ledgerPath = path.join(resultDirectory, 'protected-treatment-fixture-ledger.json');
    await fs.writeFile(fixturePath, fixtureBytes, { mode: 0o600 });
    await fs.writeFile(ledgerPath, ledgerBytes, { mode: 0o600 });
    const localConfig = loadSingleFixtureProvisioningConfig(environment, {
      randomUUID: (() => {
        let index = 0;
        return () => operationIds[index++];
      })()
    });
    const localPlan = buildSingleFixtureProvisioningPlan(localConfig);
    const admission = await options.authorizationHook({
      plan: localPlan.plan,
      planSha256: localPlan.sha256,
      runtime: localConfig.runtime
    });
    observedAdmission = admission;
    const provisioningEvidence = provisioningEvidenceValue(localPlan.plan, admission);
    observedProvisioningEvidence = provisioningEvidence;
    const evidenceBytes = Buffer.from(`${JSON.stringify(provisioningEvidence)}\n`);
    await fs.writeFile(provisioningPath, evidenceBytes, { mode: 0o600 });
    return {
      status: 'PASS',
      evidence: provisioningEvidence,
      evidencePath: provisioningPath,
      evidenceFileSha256: digest(evidenceBytes),
      fixture,
      fixturePath,
      fixtureFileSha256: digest(fixtureBytes),
      ledger,
      ledgerPath,
      ledgerFileSha256: digest(ledgerBytes)
    };
  },
  loadUatConfigImpl: async environment => {
    observedUatEnv = environment;
    return { testOnly: true, environment };
  },
  executeUatImpl: async (config, options) => {
    for (const [index, session] of fixture.sessions.entries()) {
      await options.onTreatmentWriteDispatch({
        ordinal: index + 1,
        operationId: session.operationId,
        payloadSha256: expectedPayloadSha256(session)
      });
    }
    observedUatEvidence = uatEvidenceValue(config.environment);
    return observedUatEvidence;
  },
  writeUatEvidenceImpl: async (filename, value) => {
    await fs.writeFile(filename, `${JSON.stringify(value)}\n`, { mode: 0o600, flag: 'wx' });
  }
});
assert.equal(orchestration.status, 'PASS');
assert.deepEqual(phases, ['preflight', 'provision']);
assert.deepEqual(JSON.parse(observedUatEnv.CNYOS_STAGING_TREATMENT_FIXTURE_JSON), fixture);
assert.equal(observedUatEnv.CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH,
  path.join(orchestrationEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY, 'fixture',
    'result', 'protected-treatment-fixture-ledger.json'));
assert.equal(observedUatEnv.CNYOS_TREATMENT_UAT_ACK,
  'I_AUTHORIZE_EXACTLY_TWO_SYNTHETIC_TREATMENT_WRITES');
assert.equal(crypto.createHash('sha256')
  .update(observedUatEnv.CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON).digest('hex'),
observedUatEnv.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256);

const orchestrationConfig = loadProtectedFixtureWorkflowConfig(orchestrationEnv,
  { now: () => nowValue });
const provisioningValidationContext = {
  fixture,
  ledger,
  fixtureFileSha256: digest(fixtureBytes),
  ledgerFileSha256: digest(ledgerBytes),
  admission: observedAdmission
};
validateProvisioningEvidence(observedProvisioningEvidence, orchestrationConfig, 'PASS',
  provisioningValidationContext);
for (const mutate of [
  value => { value.invariants.freshAuthUser = false; },
  value => { value.mutations[0].requestFailed = true; value.mutations[0].responseStatus = 500; },
  value => { value.fixtureIds.patientId = '77777777-7777-4777-8777-777777777777'; },
  value => { value.outputs.fixture.sha256 = '0'.repeat(64); }
]) {
  const tampered = clone(observedProvisioningEvidence);
  mutate(tampered);
  assertCode(() => validateProvisioningEvidence(tampered, orchestrationConfig, 'PASS',
    provisioningValidationContext), 'CNYOS_PROTECTED_FIXTURE_PROVISIONING_EVIDENCE_INVALID');
}
const failedProvisioningEvidence = clone(observedProvisioningEvidence);
failedProvisioningEvidence.status = 'FAIL';
failedProvisioningEvidence.failure = {
  code: 'CNYOS_SINGLE_FIXTURE_PROFILE_WRITE_STATUS_INVALID',
  operation: 'upsert_profile',
  uncertain: false
};
failedProvisioningEvidence.mutations = failedProvisioningEvidence.mutations.slice(0, 2);
failedProvisioningEvidence.mutations[1].responseStatus = 400;
failedProvisioningEvidence.fixtureIds.patientId = null;
failedProvisioningEvidence.fixtureIds.patientHnSha256 = null;
failedProvisioningEvidence.fixtureIds.encounterId = null;
failedProvisioningEvidence.invariants.authoritativeSyntheticMetadataVerified = false;
failedProvisioningEvidence.invariants.controlPlaneReadbackVerified = false;
failedProvisioningEvidence.invariants.exactClinicalReadbackVerified = false;
failedProvisioningEvidence.invariants.baselineTreatmentSessions = null;
failedProvisioningEvidence.invariants.baselinePrescriptions = null;
failedProvisioningEvidence.invariants.baselineVitalSigns = null;
failedProvisioningEvidence.invariants.baselinePainAssessments = null;
failedProvisioningEvidence.invariants.baselineAllergies = null;
delete failedProvisioningEvidence.outputs;
validateProvisioningEvidence(failedProvisioningEvidence, orchestrationConfig, 'FAIL', {
  admission: observedAdmission
});
for (const mutate of [
  value => { value.planSha256 = '0'.repeat(64); },
  value => { value.authorization.authorizationBundleSha256 = '0'.repeat(64); },
  value => { value.fixtureIds.operationIds[0] = '77777777-7777-4777-8777-777777777777'; }
]) {
  const tampered = clone(failedProvisioningEvidence);
  mutate(tampered);
  assertCode(() => validateProvisioningEvidence(tampered, orchestrationConfig, 'FAIL', {
    admission: observedAdmission
  }), 'CNYOS_PROTECTED_FIXTURE_PROVISIONING_EVIDENCE_INVALID');
}
const uncertainProvisioningEvidence = clone(failedProvisioningEvidence);
uncertainProvisioningEvidence.status = 'UNCERTAIN';
uncertainProvisioningEvidence.failure.uncertain = true;
uncertainProvisioningEvidence.failure.code =
  'CNYOS_SINGLE_FIXTURE_PROFILE_WRITE_REQUEST_UNCERTAIN';
uncertainProvisioningEvidence.mutations[1].requestFailed = true;
uncertainProvisioningEvidence.mutations[1].responseStatus = null;
validateProvisioningEvidence(uncertainProvisioningEvidence, orchestrationConfig, 'UNCERTAIN', {
  admission: observedAdmission
});
const malformedAuthResponseEvidence = clone(failedProvisioningEvidence);
malformedAuthResponseEvidence.status = 'UNCERTAIN';
malformedAuthResponseEvidence.failure = {
  code: 'CNYOS_SINGLE_FIXTURE_AUTH_USER_CREATE_RESPONSE_INVALID',
  operation: 'create_auth_user',
  uncertain: true
};
malformedAuthResponseEvidence.mutations = malformedAuthResponseEvidence.mutations.slice(0, 1);
malformedAuthResponseEvidence.mutations[0].responseStatus = 201;
malformedAuthResponseEvidence.fixtureIds.practitionerUserId = null;
malformedAuthResponseEvidence.invariants.freshAuthUser = false;
validateProvisioningEvidence(malformedAuthResponseEvidence, orchestrationConfig, 'UNCERTAIN', {
  admission: observedAdmission
});
for (const mutate of [
  value => { value.fixtureIds.patientId = fixture.patient.id; },
  value => { value.fixtureIds.patientHnSha256 = digest(Buffer.from(fixture.patient.hn)); },
  value => { value.fixtureIds.encounterId = fixture.encounter.id; },
  value => {
    value.invariants.exactClinicalReadbackVerified = true;
    value.invariants.baselineTreatmentSessions = 0;
    value.invariants.baselinePrescriptions = 0;
    value.invariants.baselineVitalSigns = 0;
    value.invariants.baselinePainAssessments = 0;
    value.invariants.baselineAllergies = 0;
  },
  value => {
    value.mutations.push(clone(observedProvisioningEvidence.mutations[2]));
  },
  value => { value.fixtureIds.practitionerUserId = null; value.invariants.freshAuthUser = false; }
]) {
  const tampered = clone(failedProvisioningEvidence);
  mutate(tampered);
  assertCode(() => validateProvisioningEvidence(tampered, orchestrationConfig, 'FAIL', {
    admission: observedAdmission
  }), 'CNYOS_PROTECTED_FIXTURE_PROVISIONING_EVIDENCE_INVALID');
}
const expiredFailedProvisioningEvidence = clone(failedProvisioningEvidence);
expiredFailedProvisioningEvidence.observedAt = '2026-10-08T10:30:00.000Z';
validateProvisioningEvidence(expiredFailedProvisioningEvidence, orchestrationConfig, 'FAIL', {
  admission: observedAdmission
});
const expiredPassProvisioningEvidence = clone(observedProvisioningEvidence);
expiredPassProvisioningEvidence.observedAt = '2026-10-08T10:30:00.000Z';
assertCode(() => validateProvisioningEvidence(expiredPassProvisioningEvidence,
  orchestrationConfig, 'PASS', provisioningValidationContext),
'CNYOS_PROTECTED_FIXTURE_PROVISIONING_EVIDENCE_INVALID');
const runAuthorizationValue = JSON.parse(
  observedUatEnv.CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON);
const uatValidationContext = {
  fixture,
  ledger,
  ledgerFileSha256: digest(ledgerBytes),
  runAuthorization: runAuthorizationValue,
  runAuthorizationSha256:
    observedUatEnv.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256,
  preflight: preflightEvidence
};
validateUatEvidence(observedUatEvidence, orchestrationConfig, 'PASS', uatValidationContext);
for (const mutate of [
  value => { value.deployment.deployId = '0'.repeat(24); },
  value => { value.runAuthorization.inputSha256 = '0'.repeat(64); },
  value => { value.fixture.patientId = '77777777-7777-4777-8777-777777777777'; },
  value => { value.writes[0].requestFailed = true; value.writes[0].responseStatus = 500; },
  value => { value.writes[1].payloadSha256 = '0'.repeat(64); },
  value => { value.readbacks[1].operationId = value.readbacks[0].operationId; },
  value => { value.readbacks[1].rowId = value.readbacks[0].rowId; },
  value => { value.reconciliation = {
    result: 'APPLIED', operationId: value.writes[1].operationId,
    rowId: value.readbacks[1].rowId
  }; },
  value => { value.canonicalPublication.observedAt = '2026-10-08T11:00:00.000Z'; }
]) {
  const tampered = clone(observedUatEvidence);
  mutate(tampered);
  assertCode(() => validateUatEvidence(tampered, orchestrationConfig, 'PASS',
    uatValidationContext), 'CNYOS_PROTECTED_FIXTURE_UAT_EVIDENCE_INVALID');
}
const failedUatEvidence = clone(observedUatEvidence);
failedUatEvidence.status = 'FAIL';
failedUatEvidence.failureCode = 'CNYOS_BOUNDED_TREATMENT_RUN_AUTHORIZATION_EXPIRED';
failedUatEvidence.writes = failedUatEvidence.writes.slice(0, 1);
failedUatEvidence.readbacks = failedUatEvidence.readbacks.slice(0, 1);
failedUatEvidence.mutationLimit.observed = 1;
failedUatEvidence.canonicalPublication = null;
validateUatEvidence(failedUatEvidence, orchestrationConfig, 'FAIL', uatValidationContext);
for (const mutate of [
  value => { value.runAuthorization.fixtureSha256 = '0'.repeat(64); },
  value => { value.fixture.encounterId = '77777777-7777-4777-8777-777777777777'; },
  value => { value.writes[0].operationId = operationIds[1]; }
]) {
  const tampered = clone(failedUatEvidence);
  mutate(tampered);
  assertCode(() => validateUatEvidence(tampered, orchestrationConfig, 'FAIL',
    uatValidationContext), 'CNYOS_PROTECTED_FIXTURE_UAT_EVIDENCE_INVALID');
}
const uncertainUatEvidence = clone(observedUatEvidence);
uncertainUatEvidence.status = 'UNCERTAIN';
uncertainUatEvidence.failureCode = 'CNYOS_BOUNDED_TREATMENT_WRITE_REQUEST_UNCERTAIN';
uncertainUatEvidence.writes[1].requestFailed = true;
uncertainUatEvidence.writes[1].responseStatus = null;
uncertainUatEvidence.readbacks = uncertainUatEvidence.readbacks.slice(0, 1);
uncertainUatEvidence.canonicalPublication = null;
uncertainUatEvidence.reconciliation = {
  result: 'UNKNOWN', operationId: operationIds[1]
};
validateUatEvidence(uncertainUatEvidence, orchestrationConfig, 'UNCERTAIN',
  uatValidationContext);
for (const mutate of [
  value => { value.readbacks = []; },
  value => { value.reconciliation = {
    result: 'UNKNOWN', operationId: operationIds[1]
  }; },
  value => { value.writes[0].requestFailed = true; value.writes[0].responseStatus = null; }
]) {
  const tampered = clone(failedUatEvidence);
  mutate(tampered);
  assertCode(() => validateUatEvidence(tampered, orchestrationConfig, 'FAIL',
    uatValidationContext), 'CNYOS_PROTECTED_FIXTURE_UAT_EVIDENCE_INVALID');
}
for (const mutate of [
  value => { value.reconciliation = null; },
  value => { value.reconciliation.operationId = operationIds[0]; },
  value => { value.readbacks.push(clone(observedUatEvidence.readbacks[1])); },
  value => { value.reconciliation = {
    result: 'APPLIED', operationId: operationIds[1]
  }; },
  value => { value.reconciliation = {
    result: 'NOT_FOUND', operationId: operationIds[1],
    rowId: observedUatEvidence.readbacks[1].rowId
  }; }
]) {
  const tampered = clone(uncertainUatEvidence);
  mutate(tampered);
  assertCode(() => validateUatEvidence(tampered, orchestrationConfig, 'UNCERTAIN',
    uatValidationContext), 'CNYOS_PROTECTED_FIXTURE_UAT_EVIDENCE_INVALID');
}
const appliedUncertainUatEvidence = clone(uncertainUatEvidence);
appliedUncertainUatEvidence.reconciliation = {
  result: 'APPLIED', operationId: operationIds[1],
  rowId: observedUatEvidence.readbacks[1].rowId
};
validateUatEvidence(appliedUncertainUatEvidence, orchestrationConfig, 'UNCERTAIN',
  uatValidationContext);
const expiredUncertainUatEvidence = clone(uncertainUatEvidence);
expiredUncertainUatEvidence.observedAt = '2026-10-08T10:30:00.000Z';
validateUatEvidence(expiredUncertainUatEvidence, orchestrationConfig, 'UNCERTAIN',
  uatValidationContext);
const expiredPassUatEvidence = clone(observedUatEvidence);
expiredPassUatEvidence.observedAt = '2026-10-08T10:30:00.000Z';
assertCode(() => validateUatEvidence(expiredPassUatEvidence, orchestrationConfig, 'PASS',
  uatValidationContext), 'CNYOS_PROTECTED_FIXTURE_UAT_EVIDENCE_INVALID');
const artifactNames = (await fs.readdir(path.join(
  orchestrationEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY, 'upload'))).sort();
assert.deepEqual(artifactNames, [
  'controller-admission-evidence.json',
  'controller-authorization-bundle.json',
  'evidence-manifest.json',
  'provisioning-evidence.json',
  'treatment-run-authorization.json',
  'uat-evidence.json'
]);
for (const name of artifactNames) {
  const bytes = await fs.readFile(path.join(
    orchestrationEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY, 'upload', name));
  for (const secret of [publishableKey, serviceRoleKey, password, netlifyToken]) {
    assert.ok(!bytes.includes(Buffer.from(secret)), `${name} serialized ${secret.slice(0, 8)}`);
  }
  assert.ok(!bytes.includes(Buffer.from(runReference)),
    `${name} serialized the external run reference`);
}

async function passingProvisionStub(environment, options) {
  const fixtureDirectory = environment.CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY;
  await fs.mkdir(fixtureDirectory, { mode: 0o700 });
  const resultDirectory = path.join(fixtureDirectory, 'result');
  await fs.mkdir(resultDirectory, { mode: 0o700 });
  const provisioningPath = path.join(resultDirectory, 'provisioning-evidence.json');
  const fixturePath = path.join(resultDirectory, 'treatment-fixture.json');
  const ledgerPath = path.join(resultDirectory, 'protected-treatment-fixture-ledger.json');
  await fs.writeFile(fixturePath, fixtureBytes, { mode: 0o600 });
  await fs.writeFile(ledgerPath, ledgerBytes, { mode: 0o600 });
  const localConfig = loadSingleFixtureProvisioningConfig(environment, {
    randomUUID: (() => {
      let index = 0;
      return () => operationIds[index++];
    })()
  });
  const localPlan = buildSingleFixtureProvisioningPlan(localConfig);
  const admission = await options.authorizationHook({
    plan: localPlan.plan,
    planSha256: localPlan.sha256,
    runtime: localConfig.runtime
  });
  const evidence = provisioningEvidenceValue(localPlan.plan, admission);
  const evidenceBytes = Buffer.from(`${JSON.stringify(evidence)}\n`);
  await fs.writeFile(provisioningPath, evidenceBytes, { mode: 0o600 });
  return {
    status: 'PASS', evidence, evidencePath: provisioningPath,
    evidenceFileSha256: digest(evidenceBytes), fixture, fixturePath,
    fixtureFileSha256: digest(fixtureBytes), ledger, ledgerPath,
    ledgerFileSha256: digest(ledgerBytes)
  };
}

const postDispatchEnv = envFor(path.join(testRoot, 'post-dispatch-exception'));
const postDispatchResult = await runProtectedBoundedTreatmentWorkflow(postDispatchEnv, {
  now: () => nowValue,
  preflightImpl: async () => preflightEvidence,
  provisionImpl: passingProvisionStub,
  loadUatConfigImpl: async environment => ({ environment }),
  executeUatImpl: async (_config, options) => {
    for (const [index, session] of fixture.sessions.entries()) {
      await options.onTreatmentWriteDispatch({
        ordinal: index + 1,
        operationId: session.operationId,
        payloadSha256: expectedPayloadSha256(session)
      });
    }
    throw new Error(`unexpected process failure ${serviceRoleKey}`);
  }
});
assert.equal(postDispatchResult.status, 'UNCERTAIN');
assert.equal(postDispatchResult.uat.failureCode,
  'CNYOS_PROTECTED_FIXTURE_EXCEPTION_AFTER_DISPATCH');
assert.equal(postDispatchResult.uat.writes.length, 2);
assert.deepEqual(postDispatchResult.uat.readbacks, []);
assert.deepEqual(postDispatchResult.uat.reconciliation, {
  result: 'UNKNOWN', operationId: operationIds[1]
});
const postDispatchUpload = path.join(
  postDispatchEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY, 'upload');
const postDispatchUatBytes = await fs.readFile(path.join(postDispatchUpload,
  'uat-evidence.json'));
const postDispatchManifestBytes = await fs.readFile(path.join(postDispatchUpload,
  'evidence-manifest.json'));
assert.equal(JSON.parse(postDispatchUatBytes).status, 'UNCERTAIN');
assert.equal(JSON.parse(postDispatchManifestBytes).status, 'UNCERTAIN');
for (const secret of [publishableKey, serviceRoleKey, password, netlifyToken]) {
  assert.ok(!postDispatchUatBytes.includes(Buffer.from(secret)));
  assert.ok(!postDispatchManifestBytes.includes(Buffer.from(secret)));
}
const journalPath = path.join(postDispatchEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY,
  'treatment-mutation-journal.private.jsonl');
const journalBytes = await fs.readFile(journalPath);
assert.equal((await fs.stat(journalPath)).mode & 0o777, 0o600);
assert.equal(journalBytes.toString('utf8').trim().split('\n').length, 3,
  'journal must durably contain one header plus both pre-dispatch latches');
for (const secret of [publishableKey, serviceRoleKey, password, netlifyToken]) {
  assert.ok(!journalBytes.includes(Buffer.from(secret)));
}

const noDispatchEnv = envFor(path.join(testRoot, 'no-dispatch-exception'));
const noDispatchResult = await runProtectedBoundedTreatmentWorkflow(noDispatchEnv, {
  now: () => nowValue,
  preflightImpl: async () => preflightEvidence,
  provisionImpl: passingProvisionStub,
  loadUatConfigImpl: async environment => ({ environment }),
  executeUatImpl: async () => {
    throw new Error(`deterministic pre-dispatch failure ${password}`);
  }
});
assert.equal(noDispatchResult.status, 'FAIL');
assert.equal(noDispatchResult.uat.failureCode,
  'CNYOS_PROTECTED_FIXTURE_EXCEPTION_BEFORE_DISPATCH');
assert.deepEqual(noDispatchResult.uat.writes, []);
assert.equal(noDispatchResult.uat.reconciliation, null);
const noDispatchUpload = path.join(noDispatchEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY, 'upload');
assert.equal(JSON.parse(await fs.readFile(path.join(noDispatchUpload,
  'uat-evidence.json'))).status, 'FAIL');
assert.equal(JSON.parse(await fs.readFile(path.join(noDispatchUpload,
  'evidence-manifest.json'))).status, 'FAIL');

const rejectedJournalEnv = envFor(path.join(testRoot, 'rejected-journal-entry'));
const rejectedJournalResult = await runProtectedBoundedTreatmentWorkflow(rejectedJournalEnv, {
  now: () => nowValue,
  preflightImpl: async () => preflightEvidence,
  provisionImpl: passingProvisionStub,
  loadUatConfigImpl: async environment => ({ environment }),
  executeUatImpl: async (_config, options) => {
    await options.onTreatmentWriteDispatch({
      ordinal: 1,
      operationId: operationIds[1],
      payloadSha256: expectedPayloadSha256(fixture.sessions[0])
    });
    throw new Error('must not reach dispatch');
  }
});
assert.equal(rejectedJournalResult.status, 'FAIL');
assert.equal(rejectedJournalResult.uat.failureCode,
  'CNYOS_PROTECTED_FIXTURE_EXCEPTION_BEFORE_DISPATCH');
assert.equal((await fs.readFile(path.join(
  rejectedJournalEnv.CNYOS_PROTECTED_UAT_WORK_DIRECTORY,
  'treatment-mutation-journal.private.jsonl'), 'utf8')).trim().split('\n').length, 1,
'a rejected journal candidate must not create a dispatch latch');

let provisionCalledAfterRejectedPreflight = false;
await assert.rejects(() => runProtectedBoundedTreatmentWorkflow(
  envFor(path.join(testRoot, 'preflight-rejected')), {
    now: () => nowValue,
    preflightImpl: async () => {
      throw new ProtectedFixtureWorkflowError('CNYOS_TEST_EXACT_DEPLOY_REJECTED');
    },
    provisionImpl: async () => {
      provisionCalledAfterRejectedPreflight = true;
      throw new Error('must not run');
    }
  }), /CNYOS_TEST_EXACT_DEPLOY_REJECTED/);
assert.equal(provisionCalledAfterRejectedPreflight, false,
  'no fixture mutation may begin before exact-deploy preflight passes');

await fs.rm(testRoot, { recursive: true, force: true });
console.log('protected bounded treatment workflow contract: ok');
