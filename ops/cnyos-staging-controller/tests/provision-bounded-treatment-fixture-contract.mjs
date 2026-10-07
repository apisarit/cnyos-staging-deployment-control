import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_TREATMENT_TARGET,
  validateProtectedFixtureLedger,
  validateTreatmentFixture
} from '../scripts/bounded-treatment-uat.mjs';
import { POLICY, POLICY_SHA256 } from '../scripts/policy.mjs';
import {
  SINGLE_FIXTURE_AUTHORIZATION_DECISION,
  SINGLE_FIXTURE_PROVISION_ACK,
  SingleFixtureProvisionError,
  buildSingleFixtureProvisioningPlan,
  loadSingleFixtureProvisioningConfig,
  runSingleFixtureProvisioning
} from '../scripts/provision-bounded-treatment-fixture.mjs';

const testRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-single-fixture-contract-'));
const nowValue = new Date('2026-10-08T08:00:00.000Z');
const userId = '11111111-1111-4111-8111-111111111111';
const patientId = '22222222-2222-4222-8222-222222222222';
const encounterId = '33333333-3333-4333-8333-333333333333';
const operationIds = [
  '44444444-4444-4444-8444-444444444444',
  '55555555-5555-4555-8555-555555555555'
];
const practitionerEmail = 'synthetic-practitioner-123456@example.invalid';
const serviceRoleKey = 'service-role-DO-NOT-SERIALIZE-1234567890';
const publishableKey = `sb_publishable_${'A'.repeat(24)}`;
const password = 'PASSWORD-DO-NOT-SERIALIZE-123456';
const accessToken = 'ACCESS-TOKEN.DO-NOT-SERIALIZE.123456';
const sourceCommit = 'b'.repeat(40);
const sourceTree = 'c'.repeat(40);
const deployId = 'a'.repeat(24);
const controllerCommit = 'd'.repeat(40);
const fixtureRunId = 'treatment-fixture-123456';

function validEnv(outputDirectory) {
  const workflowPath = POLICY.controller.releaseWorkflowPath;
  return {
    CNYOS_SINGLE_FIXTURE_PROVISION_MODE: 'LIVE',
    CNYOS_SINGLE_FIXTURE_PROVISION_ACK: SINGLE_FIXTURE_PROVISION_ACK,
    CNYOS_TREATMENT_UAT_RUN_ID: fixtureRunId,
    CNYOS_EXPECTED_SOURCE_COMMIT: sourceCommit,
    CNYOS_EXPECTED_SOURCE_TREE: sourceTree,
    CNYOS_EXPECTED_NETLIFY_DEPLOY_ID: deployId,
    CNYOS_STAGING_PRACTITIONER_EMAIL: practitionerEmail,
    CNYOS_STAGING_PRACTITIONER_FULL_NAME: 'Synthetic E2E Practitioner Fixture',
    CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY: publishableKey,
    CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: serviceRoleKey,
    CNYOS_STAGING_TEST_PASSWORD: password,
    CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY: outputDirectory,
    GITHUB_REPOSITORY: POLICY.controller.repository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: '123456',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    GITHUB_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: controllerCommit,
    CNYOS_CONTROLLER_WORKFLOW_PATH: workflowPath,
    GITHUB_WORKFLOW_REF:
      `${POLICY.controller.repository}/${workflowPath}@${POLICY.controller.protectedRef}`,
    GITHUB_ACTOR: 'fixture-operator',
    GITHUB_TRIGGERING_ACTOR: 'fixture-operator'
  };
}

function uuidFactory() {
  let index = 0;
  return () => operationIds[index++];
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function requestBody(options) {
  return options.body === undefined ? null : JSON.parse(options.body);
}

function admissionHook(overrides = {}) {
  return async ({ planSha256, runtime }) => ({
    schemaVersion: 1,
    kind: 'controller_verified_single_fixture_admission',
    status: 'authorized',
    decision: SINGLE_FIXTURE_AUTHORIZATION_DECISION,
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerWorkflowPath: runtime.workflowPath,
    controllerRunId: runtime.runId,
    policySha256: POLICY_SHA256,
    planSha256,
    sourceCommit,
    sourceTree,
    deployId,
    fixtureRunId,
    targetSiteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
    targetClinicId: BOUNDED_TREATMENT_TARGET.clinicId,
    authorizedAt: '2026-10-08T07:55:00.000Z',
    expiresAt: '2026-10-08T08:15:00.000Z',
    authorizationEvidenceSha256: 'e'.repeat(64),
    authorizationBundleSha256: 'f'.repeat(64),
    ...overrides
  });
}

function successFetch({ collision = false, throwOnPatient = false, patientStatus = 200,
  malformedPatient = false, malformedEncounter = false, patientReadbackStatus = 200,
  malformedLogin = false, loginMarkerMismatch = false, baselineSessions = false } = {}) {
  const calls = [];
  const markers = {
    synthetic_staging_only: true,
    expected_role: 'practitioner',
    fixture_run_id: fixtureRunId
  };
  const fetchImpl = async (input, options = {}) => {
    const url = new URL(input);
    const method = options.method || 'GET';
    const body = requestBody(options);
    calls.push({ url, method, headers: options.headers || {}, body });

    if (url.pathname === '/auth/v1/admin/users' && method === 'GET') {
      assert.equal(url.searchParams.get('page'), '1');
      assert.equal(url.searchParams.get('per_page'), '100');
      return json({ users: collision ? [{ id: userId, email: practitionerEmail }] : [] });
    }
    if (url.pathname === '/auth/v1/admin/users' && method === 'POST') {
      assert.equal(body.email, practitionerEmail);
      assert.equal(body.password, password);
      assert.equal(body.email_confirm, true);
      assert.deepEqual(body.app_metadata, markers);
      assert.equal(body.user_metadata.full_name, 'Synthetic E2E Practitioner Fixture');
      assert.deepEqual({ ...body.user_metadata, full_name: undefined },
        { ...markers, full_name: undefined });
      return json({ user: {
        id: userId, email: practitionerEmail,
        user_metadata: body.user_metadata, app_metadata: body.app_metadata
      } }, 201);
    }
    if (url.pathname === '/rest/v1/profiles' && method === 'POST') {
      assert.equal(url.searchParams.get('on_conflict'), 'id');
      assert.equal(body.length, 1);
      assert.deepEqual(body[0], {
        id: userId,
        email: practitionerEmail,
        full_name: 'Synthetic E2E Practitioner Fixture',
        role: 'practitioner',
        system_role: 'staff',
        updated_at: nowValue.toISOString()
      });
      return json([body[0]], 201);
    }
    if (url.pathname === '/rest/v1/clinic_memberships' && method === 'POST') {
      assert.equal(url.search, '');
      assert.equal(body.length, 1);
      assert.equal(body[0].profile_id, userId);
      assert.equal(body[0].clinic_id, BOUNDED_TREATMENT_TARGET.clinicId);
      assert.equal(body[0].clinic_role, 'practitioner');
      assert.equal(body[0].is_primary, true);
      assert.equal(body[0].active, true);
      return json([body[0]], 201);
    }
    if (url.pathname === '/auth/v1/token' && method === 'POST') {
      assert.equal(url.searchParams.get('grant_type'), 'password');
      assert.deepEqual(body, { email: practitionerEmail, password });
      if (malformedLogin) return json({ access_token: null, user: null });
      const loginMarkers = loginMarkerMismatch ?
        { ...markers, synthetic_staging_only: false } : markers;
      return json({
        access_token: accessToken,
        user: {
          id: userId,
          email: practitionerEmail,
          user_metadata: { full_name: 'Synthetic E2E Practitioner Fixture', ...loginMarkers },
          app_metadata: loginMarkers
        }
      });
    }
    if (url.pathname === '/rest/v1/profiles' && method === 'GET') {
      assert.equal(url.searchParams.get('id'), `eq.${userId}`);
      return json([{
        id: userId,
        email: practitionerEmail,
        full_name: 'Synthetic E2E Practitioner Fixture',
        role: 'practitioner',
        system_role: 'staff'
      }]);
    }
    if (url.pathname === '/rest/v1/clinic_memberships' && method === 'GET') {
      assert.equal(url.searchParams.get('profile_id'), `eq.${userId}`);
      assert.equal(url.searchParams.get('clinic_id'), `eq.${BOUNDED_TREATMENT_TARGET.clinicId}`);
      return json([{
        clinic_id: BOUNDED_TREATMENT_TARGET.clinicId,
        profile_id: userId,
        clinic_role: 'practitioner',
        is_primary: true,
        active: true
      }]);
    }
    if (url.pathname === '/rest/v1/rpc/upsert_patient_registration' && method === 'POST') {
      assert.equal(body.p_patient_id, null);
      assert.equal(body.p_payment_right, 'SYNTHETIC-E2E');
      assert.equal(body.p_national_id, null);
      assert.equal(body.p_phone, null);
      assert.equal(body.p_allergy, null);
      if (throwOnPatient) throw new Error('simulated lost response');
      if (patientStatus !== 200) {
        return json({ message: 'ambiguous upstream failure' }, patientStatus);
      }
      if (malformedPatient) {
        return json([{ id: 'not-a-uuid', hn: null }]);
      }
      return json([{
        id: patientId,
        hn: 'CHANANYASTG-00000001',
        clinic_id: BOUNDED_TREATMENT_TARGET.clinicId,
        payment_right: 'SYNTHETIC-E2E',
        national_id: null,
        phone: null,
        email: null,
        created_by: userId
      }]);
    }
    if (url.pathname === '/rest/v1/rpc/start_manual_patient_encounter' && method === 'POST') {
      assert.equal(body.p_patient_id, patientId);
      assert.equal(body.p_verification_method, 'manual_hn');
      assert.equal(body.p_patient_present_confirmed, true);
      assert.deepEqual(body.p_intake, {});
      if (malformedEncounter) {
        return json([{ encounter_id: 'not-a-uuid', encounter_no: null, patient_id: patientId }]);
      }
      return json([{
        encounter_id: encounterId,
        encounter_no: 'OPD-20261008-0001',
        patient_id: patientId
      }]);
    }
    if (url.pathname === '/rest/v1/patients' && method === 'GET') {
      assert.equal(url.searchParams.get('id'), `eq.${patientId}`);
      if (patientReadbackStatus !== 200) {
        return json({ message: 'readback unavailable' }, patientReadbackStatus);
      }
      return json([{
        id: patientId,
        hn: 'CHANANYASTG-00000001',
        clinic_id: BOUNDED_TREATMENT_TARGET.clinicId,
        payment_right: 'SYNTHETIC-E2E',
        national_id: null,
        phone: null,
        email: null,
        created_by: userId
      }]);
    }
    if (url.pathname === '/rest/v1/encounters' && method === 'GET') {
      assert.equal(url.searchParams.get('id'), `eq.${encounterId}`);
      return json([{
        id: encounterId,
        patient_id: patientId,
        status: 'draft',
        encounter_type: 'opd',
        practitioner_id: userId,
        created_by: userId,
        clinic_id: BOUNDED_TREATMENT_TARGET.clinicId
      }]);
    }
    if (url.pathname === '/rest/v1/clinical_treatment_sessions' && method === 'GET') {
      assert.equal(url.searchParams.get('encounter_id'), `eq.${encounterId}`);
      return json(baselineSessions ? [{ id: operationIds[0] }] : []);
    }
    if (['/rest/v1/prescriptions', '/rest/v1/vital_signs', '/rest/v1/pain_assessments']
      .includes(url.pathname) && method === 'GET') {
      assert.equal(url.searchParams.get('encounter_id'), `eq.${encounterId}`);
      return json([]);
    }
    if (url.pathname === '/rest/v1/patient_allergies' && method === 'GET') {
      assert.equal(url.searchParams.get('patient_id'), `eq.${patientId}`);
      return json([]);
    }
    assert.fail(`unexpected request: ${method} ${url.href}`);
  };
  return { fetchImpl, calls };
}

function assertCode(fn, code) {
  assert.throws(fn, error => error instanceof SingleFixtureProvisionError &&
    error.code === code);
}

async function assertRejectCode(fn, code) {
  await assert.rejects(fn, error => String(error?.message || '') === code);
}

try {
  const scriptPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    '../scripts/provision-bounded-treatment-fixture.mjs');
  const cli = spawnSync(process.execPath, [scriptPath], {
    env: { PATH: process.env.PATH },
    encoding: 'utf8'
  });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, '');
  assert.equal(cli.stderr,
    'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_HOOK_REQUIRED\n');

  assertCode(() => loadSingleFixtureProvisioningConfig({}),
    'CNYOS_SINGLE_FIXTURE_LIVE_MODE_REQUIRED');
  assertCode(() => loadSingleFixtureProvisioningConfig({
    CNYOS_SINGLE_FIXTURE_PROVISION_MODE: 'LIVE'
  }), 'CNYOS_SINGLE_FIXTURE_ACK_REQUIRED');

  const invalidSourceEnv = validEnv(path.join(testRoot, 'invalid-source'));
  invalidSourceEnv.CNYOS_EXPECTED_SOURCE_COMMIT = 'not-a-commit';
  assertCode(() => loadSingleFixtureProvisioningConfig(invalidSourceEnv, {
    randomUUID: uuidFactory()
  }), 'CNYOS_SINGLE_FIXTURE_SOURCE_COMMIT_INVALID');

  const wrongRuntimeEnv = validEnv(path.join(testRoot, 'wrong-runtime'));
  wrongRuntimeEnv.GITHUB_REF_PROTECTED = 'false';
  assert.throws(() => loadSingleFixtureProvisioningConfig(wrongRuntimeEnv, {
    randomUUID: uuidFactory()
  }), /CNYOS_CONTROLLER_REF_NOT_PROTECTED/);

  const planOutput = path.join(testRoot, 'plan-only');
  const planConfig = loadSingleFixtureProvisioningConfig(validEnv(planOutput), {
    randomUUID: uuidFactory()
  });
  const planRecord = buildSingleFixtureProvisioningPlan(planConfig);
  assert.equal(planRecord.plan.limits.freshAuthUsers, 1);
  assert.equal(planRecord.plan.limits.serviceRoleTableWrites, 2);
  assert.equal(planRecord.plan.limits.authenticatedClinicalRpcWrites, 2);
  assert.equal(planRecord.plan.limits.writeRetries, 0);
  assert.equal(planRecord.plan.limits.cleanupAuthorized, false);
  assert(!JSON.stringify(planRecord).includes(serviceRoleKey));
  assert(!JSON.stringify(planRecord).includes(password));
  assert(!JSON.stringify(planRecord).includes(publishableKey));

  const missingHookCalls = [];
  await assertRejectCode(() => runSingleFixtureProvisioning(
    validEnv(path.join(testRoot, 'missing-hook')), {
      fetchImpl: async (...args) => { missingHookCalls.push(args); return json({}); },
      authorizationHook: null,
      now: () => nowValue,
      randomUUID: uuidFactory()
    }), 'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_HOOK_REQUIRED');
  assert.equal(missingHookCalls.length, 0);

  const badAdmissionCalls = [];
  await assertRejectCode(() => runSingleFixtureProvisioning(
    validEnv(path.join(testRoot, 'bad-admission')), {
      fetchImpl: async (...args) => { badAdmissionCalls.push(args); return json({}); },
      authorizationHook: admissionHook({ planSha256: '0'.repeat(64) }),
      now: () => nowValue,
      randomUUID: uuidFactory()
    }), 'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_INVALID');
  assert.equal(badAdmissionCalls.length, 0);

  const existingOutput = path.join(testRoot, 'existing-output');
  await fs.mkdir(existingOutput);
  let existingHookCalled = false;
  const existingFetchCalls = [];
  await assertRejectCode(() => runSingleFixtureProvisioning(validEnv(existingOutput), {
    fetchImpl: async (...args) => { existingFetchCalls.push(args); return json({}); },
    authorizationHook: async input => {
      existingHookCalled = true;
      return admissionHook()(input);
    },
    now: () => nowValue,
    randomUUID: uuidFactory()
  }), 'CNYOS_SINGLE_FIXTURE_OUTPUT_ALREADY_EXISTS');
  assert.equal(existingHookCalled, false);
  assert.equal(existingFetchCalls.length, 0);

  const racedOutput = path.join(testRoot, 'raced-output');
  const racedFetchCalls = [];
  await assertRejectCode(() => runSingleFixtureProvisioning(validEnv(racedOutput), {
    fetchImpl: async (...args) => { racedFetchCalls.push(args); return json({}); },
    authorizationHook: async input => {
      await fs.mkdir(racedOutput, { mode: 0o700 });
      return admissionHook()(input);
    },
    now: () => nowValue,
    randomUUID: uuidFactory()
  }), 'CNYOS_SINGLE_FIXTURE_OUTPUT_DIRECTORY_CREATE_FAILED');
  assert.equal(racedFetchCalls.length, 0);
  assert.deepEqual(await fs.readdir(racedOutput), []);

  const collisionOutput = path.join(testRoot, 'collision');
  const collisionNetwork = successFetch({ collision: true });
  const collision = await runSingleFixtureProvisioning(validEnv(collisionOutput), {
    fetchImpl: collisionNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(collision.status, 'FAIL');
  assert.equal(collision.evidence.failure.code, 'CNYOS_SINGLE_FIXTURE_EMAIL_COLLISION');
  assert.equal(collisionNetwork.calls.length, 1);
  assert.equal(collisionNetwork.calls[0].method, 'GET');
  assert.equal(collision.fixturePath, null);
  assert.equal(collision.ledgerPath, null);
  assert.equal((await fs.stat(collision.evidencePath)).mode & 0o777, 0o600);

  const markerOutput = path.join(testRoot, 'marker-mismatch');
  const markerNetwork = successFetch({ loginMarkerMismatch: true });
  const markerFailure = await runSingleFixtureProvisioning(validEnv(markerOutput), {
    fetchImpl: markerNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(markerFailure.status, 'FAIL');
  assert.equal(markerFailure.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN_INVALID');
  assert.equal(markerNetwork.calls.filter(call => call.url.pathname.startsWith('/rest/v1/rpc/')).length,
    0);

  const malformedLoginOutput = path.join(testRoot, 'malformed-login');
  const malformedLoginNetwork = successFetch({ malformedLogin: true });
  const malformedLogin = await runSingleFixtureProvisioning(validEnv(malformedLoginOutput), {
    fetchImpl: malformedLoginNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(malformedLogin.status, 'UNCERTAIN');
  assert.equal(malformedLogin.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_PRACTITIONER_LOGIN_RESPONSE_UNCERTAIN');
  assert.equal(malformedLoginNetwork.calls.filter(call =>
    call.url.pathname.startsWith('/rest/v1/rpc/')).length, 0);

  const ambiguousOutput = path.join(testRoot, 'ambiguous-patient');
  const ambiguousNetwork = successFetch({ throwOnPatient: true });
  const ambiguous = await runSingleFixtureProvisioning(validEnv(ambiguousOutput), {
    fetchImpl: ambiguousNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(ambiguous.status, 'UNCERTAIN');
  assert.equal(ambiguous.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_PATIENT_RPC_REQUEST_UNCERTAIN');
  assert.equal(ambiguousNetwork.calls.filter(call =>
    call.url.pathname === '/rest/v1/rpc/upsert_patient_registration').length, 1);
  assert.equal(ambiguousNetwork.calls.filter(call =>
    call.url.pathname === '/rest/v1/rpc/start_manual_patient_encounter').length, 0);
  assert.equal(ambiguous.fixturePath, null);
  assert.equal(ambiguous.ledgerPath, null);
  assert(!JSON.stringify(ambiguous.evidence).includes(serviceRoleKey));
  assert(!JSON.stringify(ambiguous.evidence).includes(password));
  assert(!JSON.stringify(ambiguous.evidence).includes(accessToken));

  const ambiguousStatusOutput = path.join(testRoot, 'ambiguous-patient-status');
  const ambiguousStatusNetwork = successFetch({ patientStatus: 503 });
  const ambiguousStatus = await runSingleFixtureProvisioning(validEnv(ambiguousStatusOutput), {
    fetchImpl: ambiguousStatusNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(ambiguousStatus.status, 'UNCERTAIN');
  assert.equal(ambiguousStatus.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_PATIENT_RPC_STATUS_UNCERTAIN');
  assert.equal(ambiguousStatusNetwork.calls.filter(call =>
    call.url.pathname === '/rest/v1/rpc/upsert_patient_registration').length, 1);
  assert.equal(ambiguousStatusNetwork.calls.filter(call =>
    call.url.pathname === '/rest/v1/rpc/start_manual_patient_encounter').length, 0);

  const malformedPatientOutput = path.join(testRoot, 'malformed-patient-response');
  const malformedPatientNetwork = successFetch({ malformedPatient: true });
  const malformedPatient = await runSingleFixtureProvisioning(validEnv(malformedPatientOutput), {
    fetchImpl: malformedPatientNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(malformedPatient.status, 'UNCERTAIN');
  assert.equal(malformedPatient.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_PATIENT_RPC_RESPONSE_INVALID');
  assert.equal(malformedPatientNetwork.calls.filter(call =>
    call.url.pathname === '/rest/v1/rpc/upsert_patient_registration').length, 1);
  assert.equal(malformedPatientNetwork.calls.filter(call =>
    call.url.pathname === '/rest/v1/rpc/start_manual_patient_encounter').length, 0);

  const malformedEncounterOutput = path.join(testRoot, 'malformed-encounter-response');
  const malformedEncounterNetwork = successFetch({ malformedEncounter: true });
  const malformedEncounter = await runSingleFixtureProvisioning(
    validEnv(malformedEncounterOutput), {
      fetchImpl: malformedEncounterNetwork.fetchImpl,
      authorizationHook: admissionHook(),
      now: () => nowValue,
      randomUUID: uuidFactory()
    });
  assert.equal(malformedEncounter.status, 'UNCERTAIN');
  assert.equal(malformedEncounter.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_ENCOUNTER_RPC_RESPONSE_INVALID');
  assert.deepEqual(malformedEncounterNetwork.calls.filter(call =>
    call.url.pathname.startsWith('/rest/v1/rpc/')).map(call => call.url.pathname), [
    '/rest/v1/rpc/upsert_patient_registration',
    '/rest/v1/rpc/start_manual_patient_encounter'
  ]);

  const unavailableReadbackOutput = path.join(testRoot, 'unavailable-patient-readback');
  const unavailableReadbackNetwork = successFetch({ patientReadbackStatus: 503 });
  const unavailableReadback = await runSingleFixtureProvisioning(
    validEnv(unavailableReadbackOutput), {
      fetchImpl: unavailableReadbackNetwork.fetchImpl,
      authorizationHook: admissionHook(),
      now: () => nowValue,
      randomUUID: uuidFactory()
    });
  assert.equal(unavailableReadback.status, 'UNCERTAIN');
  assert.equal(unavailableReadback.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_PATIENT_READBACK_STATUS_UNCERTAIN');
  assert.deepEqual(unavailableReadbackNetwork.calls.filter(call =>
    call.url.pathname.startsWith('/rest/v1/rpc/')).map(call => call.url.pathname), [
    '/rest/v1/rpc/upsert_patient_registration',
    '/rest/v1/rpc/start_manual_patient_encounter'
  ]);

  let clockReads = 0;
  const expiredBeforeEncounterClock = () => {
    clockReads += 1;
    return clockReads >= 7 ? new Date('2026-10-08T08:16:00.000Z') : nowValue;
  };
  const expiredOutput = path.join(testRoot, 'expired-before-encounter');
  const expiredNetwork = successFetch();
  const expired = await runSingleFixtureProvisioning(validEnv(expiredOutput), {
    fetchImpl: expiredNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: expiredBeforeEncounterClock,
    randomUUID: uuidFactory()
  });
  assert.equal(expired.status, 'UNCERTAIN');
  assert.equal(expired.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_EXPIRED');
  assert.deepEqual(expiredNetwork.calls.filter(call =>
    call.url.pathname.startsWith('/rest/v1/rpc/')).map(call => call.url.pathname), [
    '/rest/v1/rpc/upsert_patient_registration'
  ]);

  let prewriteClockReads = 0;
  const expiredBeforeFirstWriteClock = () => {
    prewriteClockReads += 1;
    return prewriteClockReads >= 3 ? new Date('2026-10-08T08:16:00.000Z') : nowValue;
  };
  const prewriteExpiryOutput = path.join(testRoot, 'expired-before-first-write');
  const prewriteExpiryNetwork = successFetch();
  const prewriteExpiry = await runSingleFixtureProvisioning(validEnv(prewriteExpiryOutput), {
    fetchImpl: prewriteExpiryNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: expiredBeforeFirstWriteClock,
    randomUUID: uuidFactory()
  });
  assert.equal(prewriteExpiry.status, 'FAIL');
  assert.equal(prewriteExpiry.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_EXPIRED');
  assert.deepEqual(prewriteExpiryNetwork.calls.map(call => [call.method, call.url.pathname]), [
    ['GET', '/auth/v1/admin/users']
  ]);

  let prepublishClockReads = 0;
  const expiredBeforePublishClock = () => {
    prepublishClockReads += 1;
    return prepublishClockReads >= 8 ? new Date('2026-10-08T08:16:00.000Z') : nowValue;
  };
  const prepublishExpiryOutput = path.join(testRoot, 'expired-before-publish');
  const prepublishExpiryNetwork = successFetch();
  const prepublishExpiry = await runSingleFixtureProvisioning(validEnv(prepublishExpiryOutput), {
    fetchImpl: prepublishExpiryNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: expiredBeforePublishClock,
    randomUUID: uuidFactory()
  });
  assert.equal(prepublishExpiry.status, 'UNCERTAIN');
  assert.equal(prepublishExpiry.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_CONTROLLER_AUTHORIZATION_EXPIRED');
  assert.equal(prepublishExpiry.evidence.failure.operation, 'publish_success');
  assert.equal(prepublishExpiry.evidence.mutations.length, 5);
  assert.deepEqual(await fs.readdir(path.dirname(prepublishExpiry.evidencePath)), [
    'provisioning-evidence.json'
  ]);

  const baselineOutput = path.join(testRoot, 'baseline-session');
  const baselineNetwork = successFetch({ baselineSessions: true });
  const baselineFailure = await runSingleFixtureProvisioning(validEnv(baselineOutput), {
    fetchImpl: baselineNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(baselineFailure.status, 'FAIL');
  assert.equal(baselineFailure.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_BASELINE_TREATMENT_SESSIONS_INVALID');
  assert.equal(baselineFailure.fixturePath, null);
  assert.equal(baselineFailure.ledgerPath, null);

  const successOutput = path.join(testRoot, 'success');
  const successNetwork = successFetch();
  const success = await runSingleFixtureProvisioning(validEnv(successOutput), {
    fetchImpl: successNetwork.fetchImpl,
    authorizationHook: admissionHook(),
    now: () => nowValue,
    randomUUID: uuidFactory()
  });
  assert.equal(success.status, 'PASS');
  assert.equal((await fs.stat(successOutput)).mode & 0o777, 0o700);
  assert.deepEqual(await fs.readdir(successOutput), ['result']);
  for (const filename of [success.fixturePath, success.ledgerPath, success.evidencePath]) {
    assert.equal((await fs.stat(filename)).mode & 0o777, 0o600);
  }

  const fixture = JSON.parse(await fs.readFile(success.fixturePath, 'utf8'));
  const ledger = JSON.parse(await fs.readFile(success.ledgerPath, 'utf8'));
  const evidence = JSON.parse(await fs.readFile(success.evidencePath, 'utf8'));
  const validatedFixture = validateTreatmentFixture(fixture, {
    runId: fixtureRunId,
    practitionerEmail
  });
  validateProtectedFixtureLedger(ledger, {
    fixture: validatedFixture,
    sourceCommit,
    sourceTree,
    deployId,
    now: nowValue
  });
  assert.equal(success.ledgerFileSha256,
    crypto.createHash('sha256').update(await fs.readFile(success.ledgerPath)).digest('hex'));
  assert.equal(evidence.status, 'PASS');
  assert.equal(evidence.secretsSerialized, false);
  assert.equal(evidence.cleanup.status, 'NOT_AUTHORIZED');
  assert.equal(evidence.cleanup.attempted, false);
  assert.equal(evidence.invariants.baselineTreatmentSessions, 0);
  assert.equal(evidence.invariants.baselinePrescriptions, 0);
  assert.equal(evidence.invariants.baselineVitalSigns, 0);
  assert.equal(evidence.invariants.baselinePainAssessments, 0);
  assert.equal(evidence.invariants.baselineAllergies, 0);

  const evidenceText = JSON.stringify(evidence);
  for (const secret of [serviceRoleKey, publishableKey, password, accessToken]) {
    assert.equal(evidenceText.includes(secret), false);
  }
  const allOutputBytes = Buffer.concat(await Promise.all([
    success.fixturePath, success.ledgerPath, success.evidencePath
  ].map(filename => fs.readFile(filename)))).toString('utf8');
  for (const secret of [serviceRoleKey, publishableKey, password, accessToken]) {
    assert.equal(allOutputBytes.includes(secret), false);
  }

  const writeCalls = successNetwork.calls.filter(call =>
    !['GET'].includes(call.method) && call.url.pathname !== '/auth/v1/token');
  assert.deepEqual(writeCalls.map(call => call.url.pathname), [
    '/auth/v1/admin/users',
    '/rest/v1/profiles',
    '/rest/v1/clinic_memberships',
    '/rest/v1/rpc/upsert_patient_registration',
    '/rest/v1/rpc/start_manual_patient_encounter'
  ]);
  const serviceRoleTableWrites = successNetwork.calls.filter(call =>
    call.method === 'POST' && call.headers.Authorization === `Bearer ${serviceRoleKey}` &&
    call.url.pathname.startsWith('/rest/v1/'));
  assert.deepEqual(serviceRoleTableWrites.map(call => call.url.pathname), [
    '/rest/v1/profiles', '/rest/v1/clinic_memberships'
  ]);
  const clinicalRpcWrites = successNetwork.calls.filter(call =>
    call.method === 'POST' && call.url.pathname.startsWith('/rest/v1/rpc/'));
  assert.deepEqual(clinicalRpcWrites.map(call => call.url.pathname), [
    '/rest/v1/rpc/upsert_patient_registration',
    '/rest/v1/rpc/start_manual_patient_encounter'
  ]);
  assert(clinicalRpcWrites.every(call =>
    call.headers.Authorization === `Bearer ${accessToken}`));
  assert(successNetwork.calls.every(call => !['DELETE', 'PATCH', 'PUT'].includes(call.method)));
  assert.equal(evidence.mutations.length, 5);
  assert.equal(evidence.mutationLimit.observedRetries, 0);

  const publicationFailureOutput = path.join(testRoot, 'publication-failure');
  const publicationFailureNetwork = successFetch();
  const originalOpen = fs.open;
  fs.open = async (filename, ...args) => {
    if (path.basename(String(filename)) === 'protected-treatment-fixture-ledger.json') {
      throw new Error('simulated ledger publication failure');
    }
    return originalOpen(filename, ...args);
  };
  let publicationFailure;
  try {
    publicationFailure = await runSingleFixtureProvisioning(
      validEnv(publicationFailureOutput), {
        fetchImpl: publicationFailureNetwork.fetchImpl,
        authorizationHook: admissionHook(),
        now: () => nowValue,
        randomUUID: uuidFactory()
      });
  } finally {
    fs.open = originalOpen;
  }
  assert.equal(publicationFailure.status, 'FAIL');
  assert.equal(publicationFailure.evidence.failure.code,
    'CNYOS_SINGLE_FIXTURE_OUTPUT_WRITE_FAILED');
  assert.deepEqual(await fs.readdir(publicationFailureOutput), ['result']);
  assert.deepEqual(await fs.readdir(path.dirname(publicationFailure.evidencePath)), [
    'provisioning-evidence.json'
  ]);
  assert.equal(publicationFailure.fixturePath, null);
  assert.equal(publicationFailure.ledgerPath, null);

  const postRenameOutput = path.join(testRoot, 'post-rename-error');
  const postRenameNetwork = successFetch();
  const originalRename = fs.rename;
  fs.rename = async (...args) => {
    await originalRename(...args);
    throw new Error('simulated error reported after committed rename');
  };
  let reconciledPublication;
  try {
    reconciledPublication = await runSingleFixtureProvisioning(validEnv(postRenameOutput), {
      fetchImpl: postRenameNetwork.fetchImpl,
      authorizationHook: admissionHook(),
      now: () => nowValue,
      randomUUID: uuidFactory()
    });
  } finally {
    fs.rename = originalRename;
  }
  assert.equal(reconciledPublication.status, 'PASS');
  assert.deepEqual(await fs.readdir(postRenameOutput), ['result']);
  assert.equal((await fs.stat(reconciledPublication.evidencePath)).mode & 0o777, 0o600);

  console.log('single bounded treatment fixture provisioner contract: ok');
} finally {
  await fs.rm(testRoot, { recursive: true, force: true });
}
