import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  LOCAL_UAT_ACK,
  LocalBoundedTreatmentError,
  buildLocalUncertainRecoveryEvidence,
  buildExpectedLocalProvisioningPlan,
  createLocalMutationPhaseJournal,
  validateLocalProvisioningAdmissionRequest,
  runLocalBoundedTreatmentWorkflow
} from '../scripts/run-local-bounded-treatment-uat.mjs';
import { canonicalJson } from '../scripts/bounded-treatment-uat.mjs';
import { POLICY } from '../scripts/policy.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = await fs.readFile(path.join(packageRoot,
  'scripts/run-local-bounded-treatment-uat.mjs'), 'utf8');
const launcherSource = await fs.readFile(path.join(packageRoot,
  'scripts/run-local-bounded-treatment-uat.sh'), 'utf8');

assert.equal(LOCAL_UAT_ACK, 'I_AUTHORIZE_ONE_FIXTURE_AND_EXACTLY_TWO_TREATMENT_WRITES');
await assert.rejects(() => runLocalBoundedTreatmentWorkflow({}), error =>
  error instanceof LocalBoundedTreatmentError && error.code === 'CNYOS_LOCAL_UAT_ACK_REQUIRED');

const runtime = Object.freeze({
  repository: POLICY.controller.repository,
  ref: 'refs/heads/codex/pr69-netlify-staging-controller',
  commit: 'a'.repeat(40),
  workflowPath: 'ops/cnyos-staging-controller/scripts/run-local-bounded-treatment-uat.mjs',
  runId: 'local-contract-run'
});
const admissionConfig = Object.freeze({
  runtime,
  sourceCommit: 'b'.repeat(40),
  sourceTree: 'c'.repeat(40),
  deployId: 'd'.repeat(24),
  fixtureRunId: 'synthetic-contract-run',
  practitionerEmail: 'synthetic-contract@cnyos.invalid',
  practitionerFullName: 'Synthetic E2E Practitioner synthetic-contract-run'
});
const operationIds = Object.freeze([
  '123e4567-e89b-42d3-a456-426614174000',
  '123e4567-e89b-42d3-b456-426614174001'
]);
const validPlan = buildExpectedLocalProvisioningPlan(admissionConfig, operationIds);
const requestFor = plan => Object.freeze({
  runtime,
  plan,
  planSha256: crypto.createHash('sha256').update(canonicalJson(plan)).digest('hex')
});
assert.equal(validateLocalProvisioningAdmissionRequest(admissionConfig,
  requestFor(validPlan)), true);
const rejectAdmission = plan => assert.throws(
  () => validateLocalProvisioningAdmissionRequest(admissionConfig, requestFor(plan)),
  error => error instanceof LocalBoundedTreatmentError &&
    error.code === 'CNYOS_LOCAL_UAT_ADMISSION_REQUEST_INVALID'
);
for (const mutate of [
  plan => { plan.practitioner.email = 'attacker@example.invalid'; },
  plan => { plan.practitioner.fullName = 'Synthetic Other Operator'; },
  plan => { plan.practitioner.markers.extra = true; },
  plan => { plan.operationIds[1] = plan.operationIds[0]; },
  plan => { plan.operationIds[1] = 'not-a-uuid'; },
  plan => { plan.target.netlifySiteId = '00000000-0000-4000-8000-000000000000'; },
  plan => { plan.limits.authenticatedClinicalRpcWrites = 3; },
  plan => { plan.extra = true; }
]) {
  const changed = structuredClone(validPlan);
  mutate(changed);
  rejectAdmission(changed);
}

const phaseRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-local-phase-contract-'));
const phaseClock = () => new Date('2026-10-08T12:00:00.000Z');
const phaseJournal = await createLocalMutationPhaseJournal(phaseRoot, { now: phaseClock });
assert.equal(phaseJournal.phase, 'no_dispatch');
assert.equal(phaseJournal.hasDispatch, false);
await assert.rejects(() => phaseJournal.advance('treatment_write_1_dispatched'), error =>
  error instanceof LocalBoundedTreatmentError &&
  error.code === 'CNYOS_LOCAL_UAT_PHASE_TRANSITION_INVALID');
await phaseJournal.advance('fixture_dispatch_started', {
  requestPath: '/auth/v1/admin/users'
});
assert.equal(phaseJournal.hasDispatch, true);
await phaseJournal.advance('fixture_passed');
await phaseJournal.advance('treatment_write_1_dispatched', {
  operationId: operationIds[0], payloadSha256: 'e'.repeat(64)
});
const recoveryRuntime = Object.freeze({
  ...runtime,
  tree: 'f'.repeat(40),
  workflowRef: `${POLICY.controller.repository}/${runtime.workflowPath}@${runtime.ref}`,
  pullRequestNumber: 17,
  requiredChecks: Object.freeze([]),
  policySha256: '1'.repeat(64),
  sourceManifestSha256: '2'.repeat(64),
  packageLockSha256: '3'.repeat(64),
  operatorIdentitySha256: '4'.repeat(64)
});
const recovery = buildLocalUncertainRecoveryEvidence(Object.freeze({
  runtime: recoveryRuntime,
  sourceCommit: admissionConfig.sourceCommit,
  sourceTree: admissionConfig.sourceTree,
  deployId: admissionConfig.deployId,
  fixtureRunId: admissionConfig.fixtureRunId
}), phaseJournal, new LocalBoundedTreatmentError('CNYOS_LOCAL_UAT_EVIDENCE_WRITE_FAILED'), {
  provisioning: { status: 'PASS' }
});
assert.equal(recovery.status, 'UNCERTAIN');
assert.equal(recovery.safeErrorCode, 'CNYOS_LOCAL_UAT_EVIDENCE_WRITE_FAILED');
assert.equal(recovery.durableMutationPhase, 'treatment_write_1_dispatched');
assert.equal(recovery.fixtureCreated, true);
assert.equal(recovery.treatmentWritesDispatched, 1);
assert.equal(recovery.reconciliationRequired, true);
assert.equal(recovery.cleanup.attempted, false);
await phaseJournal.finish(recovery);
assert.deepEqual((await fs.readdir(path.join(phaseRoot, 'mutation-phases'))).sort(), [
  '00-no_dispatch.json',
  '01-fixture_dispatch_started.json',
  '02-fixture_passed.json',
  '03-treatment_write_1_dispatched.json',
  '90-terminal-uncertain.json'
]);
await assert.rejects(() => phaseJournal.advance('treatment_write_2_dispatched'), error =>
  error instanceof LocalBoundedTreatmentError &&
  error.code === 'CNYOS_LOCAL_UAT_PHASE_TRANSITION_INVALID');

for (const fragment of [
  'assertLocalExactRemotePrHeadControllerRuntime(env)',
  'await preflightExactDeployment(Object.freeze({',
  'await installFreshLockedChromium(workDirectory)',
  'exactLowercase(env.CNYOS_EXPECTED_SOURCE_COMMIT, SHA40',
  'exactLowercase(env.CNYOS_EXPECTED_SOURCE_TREE, SHA40',
  'exactLowercase(env.CNYOS_EXPECTED_NETLIFY_DEPLOY_ID, NETLIFY_DEPLOY_ID',
  "['ci', '--ignore-scripts', '--no-audit', '--no-fund']",
  'controllerRuntime: runtime',
  'authorizationHook: createLocalAdmissionHook(config, records)',
  'validateLocalProvisioningAdmissionRequest(config, request)',
  'CNYOS_SINGLE_FIXTURE_PROVISION_ACK: SINGLE_FIXTURE_PROVISION_ACK',
  'CNYOS_TREATMENT_UAT_ACK: BOUNDED_TREATMENT_ACK',
  'CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH: provisioning.ledgerPath',
  'loadBoundedTreatmentConfig(uatEnv, { now, controllerRuntime: runtime })',
  'chromiumImpl: lockedChromium',
  'onTreatmentWriteDispatch: async record =>',
  "await phaseJournal.advance('fixture_dispatch_started'",
  "return Object.freeze({ status: 'UNCERTAIN'",
  'independentReviewerApproval: false',
  'productionAuthorization: false',
  "cleanup: Object.freeze({ status: 'NOT_AUTHORIZED', attempted: false })",
  'fixtureAndLedgerPublished: false',
  'secretsSerialized: false'
]) assert.ok(source.includes(fragment), `missing local fail-closed fragment: ${fragment}`);

assert.equal((source.match(/assertLocalExactRemotePrHeadControllerRuntime\(env\)/g) || []).length, 2,
  'controller PR head, checks and repository state must be reverified before writes');
assert.ok(source.indexOf('await installFreshLockedChromium(workDirectory)') <
  source.indexOf('const serviceRoleKey = required('),
  'locked dependencies must be installed before staging secrets are read');
assert.ok(source.indexOf('const deploymentPreflight = await preflightExactDeployment(') <
  source.indexOf('const authorizedAt = observedAt.toISOString();'),
  'authorization lifetime must begin after exact deployment preflight');

assert.ok(!source.includes(POLICY.productionDenylist.netlifyOrigin));
assert.ok(!source.includes(POLICY.productionDenylist.netlifySiteId));
assert.ok(!source.includes(POLICY.productionDenylist.supabaseProjectRef));
assert.ok(!source.includes('GITHUB_REF_PROTECTED'));
assert.ok(!source.includes('refs/heads/main'));
assert.ok(!source.includes('cleanupUser'));
assert.ok(!source.includes('deleteUser'));
assert.ok(!source.includes('service_role_key:'));

assert.ok(launcherSource.includes('/bin/pwd -P'),
  'credential-bearing launcher must use an absolute trusted pwd binary');
assert.ok(!launcherSource.includes('dirname'),
  'credential-bearing launcher must not resolve dirname through PATH');

console.log('local bounded treatment workflow contract: ok');
