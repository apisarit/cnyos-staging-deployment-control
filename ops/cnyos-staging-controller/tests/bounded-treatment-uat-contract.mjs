import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  BOUNDED_TREATMENT_ACK,
  BOUNDED_TREATMENT_TARGET,
  BoundedTreatmentError,
  TreatmentWriteLedger,
  buildEvidence,
  canonicalFixtureSha256,
  classifyTreatmentFailure,
  installNetworkGuard,
  loadBoundedTreatmentConfig,
  preflightExactDeployment,
  reconcileAmbiguousOperation,
  recheckCanonicalPublication,
  validateBoundedTreatmentPolicyTarget,
  validateProtectedFixtureLedger,
  validateTreatmentFixture,
  writeEvidenceExclusive
} from '../scripts/bounded-treatment-uat.mjs';
import { POLICY, POLICY_SHA256 } from '../scripts/policy.mjs';

const runId = 'treatment-uat-20261007';
const practitionerEmail = 'synthetic.practitioner@example.invalid';
const sourceCommit = 'b'.repeat(40);
const sourceTree = 'c'.repeat(40);
const deployId = 'a'.repeat(24);
const controllerCommit = 'd'.repeat(40);
const controllerRunId = '91000017';
const password = 'DO_NOT_SERIALIZE_PASSWORD';
const netlifyToken = 'DO_NOT_SERIALIZE_NETLIFY_TOKEN';
const publishableKey = `sb_publishable_${'A'.repeat(24)}`;
const accessToken = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.signature';
const clientInfo = 'supabase-js/2.112.4; runtime=web';
const nowValue = new Date('2026-10-07T12:05:00.000Z');

function fixtureValue() {
  return {
    schemaVersion: 1,
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    clinic: {
      id: BOUNDED_TREATMENT_TARGET.clinicId,
      code: BOUNDED_TREATMENT_TARGET.clinicCode
    },
    practitioner: {
      userId: '11111111-1111-4111-8111-111111111111',
      email: practitionerEmail,
      role: 'practitioner',
      syntheticMarkerVerified: true
    },
    patient: {
      id: '22222222-2222-4222-8222-222222222222',
      hn: 'SYNTHETIC-HN-20261007',
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
    sessions: [
      {
        operationId: '44444444-4444-4444-8444-444444444444',
        modalities: ['นวดไทย'],
        treatmentDetail: `SYNTHETIC ${runId} SESSION 1 - NOT FOR CLINICAL USE`,
        procedureReferral: false,
        procedureReferralDetail: null,
        precautions: 'synthetic fixture only',
        painBefore: 4,
        painAfter: 2,
        outcomeSummary: 'synthetic improvement',
        advice: 'synthetic follow-up only'
      },
      {
        operationId: '55555555-5555-4555-8555-555555555555',
        modalities: ['นวดไทย'],
        treatmentDetail: `SYNTHETIC ${runId} SESSION 2 - NOT FOR CLINICAL USE`,
        procedureReferral: false,
        procedureReferralDetail: null,
        precautions: null,
        painBefore: 2,
        painAfter: 1,
        outcomeSummary: 'synthetic stable',
        advice: null
      }
    ]
  };
}

function protectedLedgerValue(fixture, overrides = {}) {
  const normalized = validateTreatmentFixture(fixture, { runId, practitionerEmail });
  const value = {
    schemaVersion: 1,
    kind: 'protected_staging_fixture_ledger',
    entryId: 'fixture:treatment:20261007',
    fixtureSha256: canonicalFixtureSha256(normalized),
    verifiedAt: '2026-10-07T12:00:00.000Z',
    target: {
      siteId: BOUNDED_TREATMENT_TARGET.netlifySiteId,
      deployId,
      sourceCommit,
      sourceTree,
      clinicId: BOUNDED_TREATMENT_TARGET.clinicId
    },
    fixtureIds: {
      practitionerUserId: normalized.practitioner.userId,
      patientId: normalized.patient.id,
      encounterId: normalized.encounter.id,
      operationIds: normalized.sessions.map(session => session.operationId)
    }
  };
  return { ...value, ...overrides };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function runAuthorizationValue(fixture) {
  const normalized = validateTreatmentFixture(fixture, { runId, practitionerEmail });
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_bounded_treatment_run_authorization',
    status: 'authorized',
    decision: 'authorize_exactly_two_synthetic_treatment_writes',
    scope: 'cnyos_staging_only',
    syntheticOnly: true,
    realPatientDataAuthorized: false,
    productionAuthorization: false,
    authorizedAt: '2026-10-07T12:00:00.000Z',
    expiresAt: '2026-10-07T12:30:00.000Z',
    policySha256: POLICY_SHA256,
    controller: {
      repository: POLICY.controller.repository,
      ref: POLICY.controller.protectedRef,
      commit: controllerCommit,
      workflowPath: POLICY.controller.releaseWorkflowPath,
      workflowRef: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
      runId: controllerRunId,
      runAttempt: 1
    },
    target: clone(BOUNDED_TREATMENT_TARGET),
    run: {
      runId,
      sourceCommit,
      sourceTree,
      deployId,
      fixtureSha256: canonicalFixtureSha256(normalized)
    }
  };
}

function assertCode(fn, code) {
  assert.throws(fn, error => error instanceof BoundedTreatmentError && error.code === code);
}

async function assertRejectCode(fn, code) {
  await assert.rejects(fn, error => error instanceof BoundedTreatmentError && error.code === code);
}

function assertBounded(fn) {
  assert.throws(fn, error => error instanceof BoundedTreatmentError);
}

function envFor(fixture, ledgerPath, ledgerSha256,
  evidencePath = '/tmp/cnyos-bounded-treatment-evidence.json') {
  const runAuthorization = JSON.stringify(runAuthorizationValue(fixture));
  return {
    GITHUB_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: controllerRunId,
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: controllerCommit,
    GITHUB_WORKFLOW_REF: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
    CNYOS_TREATMENT_UAT_RUN_ID: runId,
    CNYOS_EXPECTED_SOURCE_COMMIT: sourceCommit,
    CNYOS_EXPECTED_SOURCE_TREE: sourceTree,
    CNYOS_EXPECTED_NETLIFY_DEPLOY_ID: deployId,
    CNYOS_STAGING_PRACTITIONER_EMAIL: practitionerEmail,
    CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY: publishableKey,
    CNYOS_STAGING_TEST_PASSWORD: password,
    CNYOS_STAGING_NETLIFY_AUTH_TOKEN: netlifyToken,
    CNYOS_CONTROLLER_UAT_EVIDENCE_PATH: evidencePath,
    CNYOS_TREATMENT_UAT_ACK: BOUNDED_TREATMENT_ACK,
    CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON: runAuthorization,
    CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256:
      crypto.createHash('sha256').update(runAuthorization).digest('hex'),
    CNYOS_STAGING_TREATMENT_FIXTURE_JSON: JSON.stringify(fixture),
    CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH: ledgerPath,
    CNYOS_EXPECTED_TREATMENT_FIXTURE_LEDGER_SHA256: ledgerSha256
  };
}

function withRunAuthorization(environment, mutate) {
  const authorization = JSON.parse(environment.CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON);
  mutate(authorization);
  const raw = JSON.stringify(authorization);
  return {
    ...environment,
    CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON: raw,
    CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256:
      crypto.createHash('sha256').update(raw).digest('hex')
  };
}

function fetchHeaders(extra = {}) {
  return {
    accept: '*/*',
    'accept-language': 'en-US',
    origin: `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`,
    referer: `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app/`,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    ...extra
  };
}

function rawLedgerFor(fixture) {
  return new TreatmentWriteLedger({
    encounterId: fixture.encounter.id,
    patientId: fixture.patient.id,
    practitionerUserId: fixture.practitioner.userId,
    practitionerEmail,
    password,
    publishableKey,
    appOrigin: `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`
  });
}

function ledgerFor(fixture) {
  const ledger = rawLedgerFor(fixture);
  const settings = ledger.inspect({
    url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/auth/v1/settings`,
    method: 'GET', postData: null, resourceType: 'fetch',
    headers: fetchHeaders({ apikey: publishableKey })
  });
  assert.equal(settings.allow, true);
  const login = ledger.inspect({
    url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/auth/v1/token?grant_type=password`,
    method: 'POST', resourceType: 'fetch',
    headers: fetchHeaders({
      apikey: publishableKey,
      authorization: `Bearer ${publishableKey}`,
      'content-type': 'application/json;charset=UTF-8',
      'x-client-info': clientInfo,
      'x-supabase-api-version': '2024-01-01'
    }),
    postData: JSON.stringify({ email: practitionerEmail, password,
      gotrue_meta_security: {} })
  });
  assert.equal(login.allow, true);
  ledger.loginResponse(200, Buffer.from(JSON.stringify({
    access_token: accessToken,
    user: { id: fixture.practitioner.userId, email: practitionerEmail }
  })));
  assert.equal(ledger.violation, null);
  assert.equal('accessToken' in ledger, false);
  assert.match(ledger.accessTokenSha256, /^[0-9a-f]{64}$/);
  assert.notEqual(ledger.accessTokenSha256, accessToken);
  return ledger;
}

function tableHeaders(method = 'GET') {
  return fetchHeaders({
    apikey: publishableKey,
    authorization: `Bearer ${accessToken}`,
    'x-client-info': clientInfo,
    'accept-profile': 'public',
    ...(method === 'HEAD' ? { prefer: 'count=exact' } : {})
  });
}

function rpcHeaders() {
  return fetchHeaders({
    apikey: publishableKey,
    authorization: `Bearer ${accessToken}`,
    'x-client-info': clientInfo,
    'content-profile': 'public',
    'content-type': 'application/json'
  });
}

function preflightHeaders(method, names) {
  return fetchHeaders({
    'access-control-request-method': method,
    'access-control-request-headers': names.join(',')
  });
}

function browserRequest({ url, method = 'GET', postData = null, headers = {},
  resourceType = 'fetch', priority = null }) {
  return {
    url: () => url,
    method: () => method,
    postData: () => postData,
    headersArray: async () => [
      ...Object.entries(headers).map(([name, value]) => ({ name, value })),
      ...(priority == null ? [] : [{ name: 'Priority', value: priority }])
    ],
    resourceType: () => resourceType
  };
}

async function captureRequestHandler(ledger) {
  let handler = null;
  await installNetworkGuard({
    addInitScript: async () => {},
    routeWebSocket: async () => {},
    route: async (_pattern, callback) => { handler = callback; },
    on: () => {}
  }, ledger);
  assert.equal(typeof handler, 'function');
  return handler;
}

function hasHeader(headers, expectedName) {
  return Object.keys(headers || {}).some(name => name.toLowerCase() === expectedName.toLowerCase());
}

function payloadFor(fixture, session) {
  return {
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
  };
}

function expectedRow(fixture, session, ordinal) {
  return {
    id: `${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}-${ordinal}${ordinal}${ordinal}${ordinal}-4${ordinal}${ordinal}${ordinal}-8${ordinal}${ordinal}${ordinal}-${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}${ordinal}`,
    encounter_id: fixture.encounter.id,
    client_request_id: session.operationId,
    practitioner_id: fixture.practitioner.userId,
    session_no: ordinal,
    treatment_modalities: session.modalities,
    treatment_detail: session.treatmentDetail,
    procedure_referral: session.procedureReferral,
    procedure_referral_detail: session.procedureReferralDetail,
    precautions: session.precautions,
    pain_before: session.painBefore,
    pain_after: session.painAfter,
    outcome_summary: session.outcomeSummary,
    advice: session.advice
  };
}

assert.deepEqual(BOUNDED_TREATMENT_TARGET, POLICY.boundedTreatmentUatTarget);
assert.equal(BOUNDED_TREATMENT_TARGET.origin, 'https://cnyos-clinical-staging.netlify.app');
assert.equal(BOUNDED_TREATMENT_TARGET.netlifySiteId,
  '887e058b-6e13-461f-b3c7-ae096b7046fe');
assert.notEqual(BOUNDED_TREATMENT_TARGET.origin, POLICY.target.netlifyOrigin);
assert.notEqual(BOUNDED_TREATMENT_TARGET.netlifySiteId, POLICY.target.netlifySiteId);
assert.notEqual(BOUNDED_TREATMENT_TARGET.origin, 'https://cnyos.cloud');
const oldPrimaryTarget = clone(BOUNDED_TREATMENT_TARGET);
oldPrimaryTarget.origin = POLICY.target.netlifyOrigin;
oldPrimaryTarget.netlifySiteId = POLICY.target.netlifySiteId;
oldPrimaryTarget.netlifySiteName = POLICY.target.netlifySiteName;
oldPrimaryTarget.deploymentId = POLICY.target.deploymentId;
assertCode(() => validateBoundedTreatmentPolicyTarget(oldPrimaryTarget),
  'CNYOS_BOUNDED_TREATMENT_POLICY_TARGET_INVALID');

const validated = validateTreatmentFixture(fixtureValue(), { runId, practitionerEmail });
assert.equal(validated.sessions.length, 2);
assert.notEqual(validated.sessions[0].operationId, validated.sessions[1].operationId);
assert(Object.isFrozen(validated));
const protectedLedger = validateProtectedFixtureLedger(protectedLedgerValue(fixtureValue()), {
  fixture: validated,
  sourceCommit,
  sourceTree,
  deployId,
  now: nowValue
});
assert.equal(protectedLedger.fixtureSha256, canonicalFixtureSha256(validated));
assert.equal(protectedLedger.fixtureIds.operationIds.length, 2);

for (const mutate of [
  value => { value.extra = true; },
  value => { value.syntheticOnly = false; },
  value => { value.realPatientDataAuthorized = true; },
  value => { value.patient.realIdentifiersAbsent = false; },
  value => { value.encounter.baselineTreatmentSessionCount = 1; },
  value => { value.sessions[1].operationId = value.sessions[0].operationId; },
  value => { value.sessions[0].treatmentDetail = 'ordinary clinical text'; },
  value => { value.practitioner.role = 'admin'; },
  value => { value.clinic.id = '99999999-9999-4999-8999-999999999999'; }
]) {
  const invalid = fixtureValue();
  mutate(invalid);
  assertBounded(() => validateTreatmentFixture(invalid, { runId, practitionerEmail }));
}

const fixtureWithCallerEvidence = fixtureValue();
fixtureWithCallerEvidence.registryEvidence = { assertedBy: 'caller' };
assertBounded(() => validateTreatmentFixture(fixtureWithCallerEvidence,
  { runId, practitionerEmail }));

for (const [ledger, code] of [
  [{ ...protectedLedgerValue(fixtureValue()), fixtureSha256: '0'.repeat(64) },
    'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_INVALID'],
  [{ ...protectedLedgerValue(fixtureValue()), verifiedAt: '2026-10-06T12:04:59.999Z' },
    'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_TIMESTAMP_INVALID'],
  [{ ...protectedLedgerValue(fixtureValue()), verifiedAt: '2026-10-07T12:05:00.001Z' },
    'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_TIMESTAMP_INVALID'],
  [{ ...protectedLedgerValue(fixtureValue()), fixtureIds: {
    ...protectedLedgerValue(fixtureValue()).fixtureIds,
    patientId: '99999999-9999-4999-8999-999999999999'
  } }, 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_INVALID']
]) {
  assertCode(() => validateProtectedFixtureLedger(ledger, {
    fixture: validated,
    sourceCommit,
    sourceTree,
    deployId,
    now: nowValue
  }), code);
}

const ledgerDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-treatment-ledger-'));
const ledgerPath = path.join(ledgerDirectory, 'protected-ledger.json');
const ledgerBytes = Buffer.from(`${JSON.stringify(protectedLedgerValue(fixtureValue()))}\n`);
await fs.writeFile(ledgerPath, ledgerBytes, { mode: 0o600 });
const ledgerFileSha256 = crypto.createHash('sha256').update(ledgerBytes).digest('hex');
const baseEnvironment = envFor(fixtureValue(), ledgerPath, ledgerFileSha256);
const config = await loadBoundedTreatmentConfig(baseEnvironment, { now: () => nowValue });
assert.equal(config.password, password);
assert.equal(config.netlifyToken, netlifyToken);
assert.equal(config.publishableKey, publishableKey);
assert.equal(config.controllerRuntime.repository, POLICY.controller.repository);
assert.equal(config.controllerRuntime.ref, POLICY.controller.protectedRef);
assert.equal(config.controllerRuntime.commit, controllerCommit);
assert.equal(config.controllerRuntime.runId, controllerRunId);
assert.equal(config.runAuthorization.status, 'authorized');
assert.equal(config.runAuthorization.controller.commit, controllerCommit);
assert.equal(config.runAuthorization.run.fixtureSha256, canonicalFixtureSha256(config.fixture));
assert.equal(config.runAuthorization.inputSha256,
  baseEnvironment.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256);
assert.equal(config.fixture.practitioner.role, 'practitioner');
assert.equal(config.protectedLedger.entryId, 'fixture:treatment:20261007');
assert.equal(config.protectedLedger.sourceFileSha256, ledgerFileSha256);
assert.equal(config.protectedLedger.expectedFileSha256, ledgerFileSha256);
assert.equal(config.immutableOrigin,
  `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`);
await assertRejectCode(() => loadBoundedTreatmentConfig({
  ...baseEnvironment, CNYOS_TREATMENT_UAT_ACK: 'yes'
}, { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_ACK_REQUIRED');
await assertRejectCode(() => loadBoundedTreatmentConfig({
  ...baseEnvironment, CNYOS_EXPECTED_SUPABASE_PUBLISHABLE_KEY: 'caller-selected-key'
}, { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_SUPABASE_KEY_INVALID');
await assertRejectCode(() => loadBoundedTreatmentConfig({
  ...baseEnvironment, GITHUB_REF: 'refs/pull/17/merge'
}, { now: () => nowValue }), 'CNYOS_CONTROLLER_REF_MISMATCH');
await assertRejectCode(() => loadBoundedTreatmentConfig(withRunAuthorization(baseEnvironment,
  value => { value.controller.commit = 'e'.repeat(40); }), { now: () => nowValue }),
  'CNYOS_BOUNDED_TREATMENT_RUN_AUTHORIZATION_INVALID');
await assertRejectCode(() => loadBoundedTreatmentConfig(withRunAuthorization(baseEnvironment,
  value => {
    value.target.origin = POLICY.target.netlifyOrigin;
    value.target.netlifySiteId = POLICY.target.netlifySiteId;
    value.target.netlifySiteName = POLICY.target.netlifySiteName;
    value.target.deploymentId = POLICY.target.deploymentId;
  }), { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_RUN_AUTHORIZATION_INVALID');
const missingRunAuthorizationEnvironment = { ...baseEnvironment };
delete missingRunAuthorizationEnvironment.CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON;
await assertRejectCode(() => loadBoundedTreatmentConfig(missingRunAuthorizationEnvironment,
  { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_RUN_AUTHORIZATION_REQUIRED');
const invalidRunAuthorizationRaw = '{}';
await assertRejectCode(() => loadBoundedTreatmentConfig({
  ...baseEnvironment,
  CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON: invalidRunAuthorizationRaw,
  CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256:
    crypto.createHash('sha256').update(invalidRunAuthorizationRaw).digest('hex')
}, { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_RUN_AUTHORIZATION_INVALID');
await assertRejectCode(() => loadBoundedTreatmentConfig({
  ...baseEnvironment,
  CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256: '0'.repeat(64)
}, { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_RUN_AUTHORIZATION_DIGEST_MISMATCH');
const missingLedgerEnvironment = { ...baseEnvironment };
delete missingLedgerEnvironment.CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH;
await assertRejectCode(() => loadBoundedTreatmentConfig(missingLedgerEnvironment,
  { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_PATH_REQUIRED');
await assertRejectCode(() => loadBoundedTreatmentConfig({
  ...baseEnvironment,
  CNYOS_EXPECTED_TREATMENT_FIXTURE_LEDGER_SHA256: '0'.repeat(64)
}, { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_DIGEST_MISMATCH');
await fs.chmod(ledgerPath, 0o644);
await assertRejectCode(() => loadBoundedTreatmentConfig(baseEnvironment,
  { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_FILE_INVALID');
await fs.chmod(ledgerPath, 0o600);
const jsonOnlyEnvironment = { ...baseEnvironment,
  CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_JSON: ledgerBytes.toString('utf8') };
delete jsonOnlyEnvironment.CNYOS_PROTECTED_TREATMENT_FIXTURE_LEDGER_PATH;
await assertRejectCode(() => loadBoundedTreatmentConfig(jsonOnlyEnvironment,
  { now: () => nowValue }), 'CNYOS_BOUNDED_TREATMENT_PROTECTED_LEDGER_PATH_REQUIRED');

const fixture = config.fixture;
const ledger = ledgerFor(fixture);
assert.equal(ledger.inspect({
  url: `${config.immutableOrigin}/clinical-v3.html?encounter=${fixture.encounter.id}&step=treatment`,
  method: 'GET', postData: null, resourceType: 'document',
  headers: { 'accept-language': 'en-US' }
}).allow, true);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.origin}/clinical-v3.html`, method: 'GET', postData: null,
  resourceType: 'document', headers: {}
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: 'https://cnyos.cloud/clinical-v3.html', method: 'GET', postData: null,
  resourceType: 'document', headers: {}
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${config.immutableOrigin}/unexpected.js`, method: 'GET', postData: null,
  resourceType: 'script', headers: {}
}).allow, false);
const secretQueryLedger = ledgerFor(fixture);
assert.equal(secretQueryLedger.inspect({
  url: `${config.immutableOrigin}/app.css?secret`, method: 'GET', postData: null,
  resourceType: 'stylesheet', headers: {}
}).allow, false);
assertCode(() => secretQueryLedger.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_BROWSER_RESOURCE_BLOCKED');
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/private_unknown_table`,
  method: 'GET', postData: null, resourceType: 'fetch', headers: tableHeaders()
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/dispensing_orders?select=*`,
  method: 'GET', postData: null, resourceType: 'fetch', headers: tableHeaders()
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/unlisted_rpc`,
  method: 'OPTIONS', postData: null, resourceType: 'fetch',
  headers: preflightHeaders('POST', [
    'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info'
  ])
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context`,
  method: 'POST', postData: '{}', resourceType: 'fetch', headers: rpcHeaders()
}).allow, true);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context`,
  method: 'OPTIONS', postData: null,
  resourceType: 'fetch', headers: preflightHeaders('POST', [
    'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info'
  ])
}).allow, true);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context`,
  method: 'OPTIONS', postData: null,
  resourceType: 'fetch', headers: preflightHeaders('GET', [
    'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info'
  ])
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/auth/v1/token?grant_type=password`,
  method: 'POST', postData: JSON.stringify({ email: practitionerEmail, password,
    gotrue_meta_security: {} }), resourceType: 'fetch', headers: fetchHeaders({
    apikey: publishableKey,
    authorization: `Bearer ${publishableKey}`,
    'content-type': 'application/json;charset=UTF-8',
    'x-client-info': clientInfo,
    'x-supabase-api-version': '2024-01-01'
  })
}).allow, true);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/auth/v1/token?grant_type=password`,
  method: 'POST', postData: JSON.stringify({ email: practitionerEmail, password: 'wrong',
    gotrue_meta_security: {} }), resourceType: 'fetch', headers: fetchHeaders({
    apikey: publishableKey,
    authorization: `Bearer ${publishableKey}`,
    'content-type': 'application/json;charset=UTF-8',
    'x-client-info': clientInfo,
    'x-supabase-api-version': '2024-01-01'
  })
}).allow, false);
const invalidReadRpc = ledgerFor(fixture);
assert.equal(invalidReadRpc.inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context?x=1`,
  method: 'POST', postData: JSON.stringify({ arbitrary: true }),
  resourceType: 'fetch', headers: rpcHeaders()
}).allow, false);
assertCode(() => invalidReadRpc.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_BROWSER_READ_RPC_INVALID');

const broadPatientRead = ledger.inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/patients?select=*&order=created_at.desc&limit=500`,
  method: 'GET', postData: null, resourceType: 'fetch', headers: tableHeaders()
});
assert.equal(broadPatientRead.allow, true);
assert.equal(new URL(broadPatientRead.continueUrl).searchParams.get('id'), `eq.${fixture.patient.id}`);
assert.equal(ledger.inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/encounters?id=eq.99999999-9999-4999-8999-999999999999`,
  method: 'GET', postData: null, resourceType: 'fetch', headers: tableHeaders()
}).allow, false);

const xhrCssLeak = ledgerFor(fixture);
assert.equal(xhrCssLeak.inspect({
  url: `${config.immutableOrigin}/app.css?v=clinical-os-worklist1`,
  method: 'GET', postData: null, resourceType: 'xhr',
  headers: { 'x-cnyos-leak': 'do-not-exfiltrate' }
}).allow, false);
assertCode(() => xhrCssLeak.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_BROWSER_RESOURCE_TYPE_INVALID');

assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/products?select=*&active=eq.true&order=name_th.asc`,
  method: 'GET', postData: null, resourceType: 'document',
  headers: { ...tableHeaders(), 'x-client-info': 'secret-exfiltration' }
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/products?select=*&active=eq.true&order=name_th.asc`,
  method: 'GET', postData: null, resourceType: 'fetch',
  headers: { ...tableHeaders(), 'x-client-info': 'secret-exfiltration' }
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context`,
  method: 'POST', postData: '{}', resourceType: 'image',
  headers: { ...rpcHeaders(), 'content-profile': 'private' }
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context`,
  method: 'POST', postData: '{}', resourceType: 'fetch',
  headers: { ...rpcHeaders(), 'content-profile': 'private' }
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${config.immutableOrigin}/app.css?v=clinical-os-worklist1`,
  method: 'GET', postData: null, resourceType: 'stylesheet',
  headers: { 'accept-language': 'en-US', 'x-cnyos-leak': 'do-not-exfiltrate' }
}).allow, false);
const languageLeak = ledgerFor(fixture);
assert.equal(languageLeak.inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/products?select=*&active=eq.true&order=name_th.asc`,
  method: 'GET', postData: null, resourceType: 'fetch',
  headers: { ...tableHeaders(), 'accept-language': `token-${'a'.repeat(40)}` }
}).allow, false);
assertCode(() => languageLeak.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/products?select=*&active=eq.true&order=name_th.asc`,
  method: 'GET', postData: null, resourceType: 'fetch',
  headers: { ...tableHeaders(), 'cache-control': 'token-leak' }
}).allow, false);
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/products?select=*&active=eq.true&order=name_th.asc`,
  method: 'GET', postData: null, resourceType: 'fetch',
  headers: { ...tableHeaders(), authorization: 'Bearer forged.header.signature' }
}).allow, false);
const extraPreflightHeader = ledgerFor(fixture);
assert.equal(extraPreflightHeader.inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/current_access_context`,
  method: 'OPTIONS', postData: null, resourceType: 'fetch',
  headers: preflightHeaders('POST', [
    'apikey', 'authorization', 'content-profile', 'content-type', 'x-client-info',
    'x-cnyos-leak'
  ])
}).allow, false);
assertCode(() => extraPreflightHeader.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_BROWSER_HEADERS_INVALID');
assert.equal(ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/auth/v1/settings`,
  method: 'GET', postData: null, resourceType: 'fetch',
  headers: [
    ...Object.entries(fetchHeaders()).map(([name, value]) => ({ name, value })),
    { name: 'apikey', value: publishableKey },
    { name: 'ApiKey', value: publishableKey }
  ]
}).allow, false);

let initScript = null;
let webSocketHandler = null;
let requestHandler = null;
const listeners = new Map();
const guardedLedger = ledgerFor(fixture);
await installNetworkGuard({
  addInitScript: async callback => { initScript = callback; },
  routeWebSocket: async (pattern, callback) => {
    assert.equal(pattern, '**/*');
    webSocketHandler = callback;
  },
  route: async (pattern, callback) => {
    assert.equal(pattern, '**/*');
    requestHandler = callback;
  },
  on: (event, callback) => listeners.set(event, callback)
}, guardedLedger);
assert.equal(typeof initScript, 'function');
assert.match(String(initScript), /WebSocket disabled for bounded UAT/);
assert.equal(typeof requestHandler, 'function');
assert.equal(typeof webSocketHandler, 'function');
const productsUrl = `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/products?select=*&active=eq.true&order=name_th.asc`;
let continuedRequest = null;
let continuedAbort = null;
await requestHandler({
  request: () => browserRequest({ url: productsUrl, headers: tableHeaders(),
    priority: 'u=1, i' }),
  continue: async options => { continuedRequest = options; },
  abort: async reason => { continuedAbort = reason; }
});
assert.equal(continuedAbort, null);
assert(continuedRequest);
assert.equal(hasHeader(continuedRequest.headers, 'priority'), false);

const priorityLeakLedger = ledgerFor(fixture);
const priorityLeakHandler = await captureRequestHandler(priorityLeakLedger);
let priorityLeakAbort = null;
await priorityLeakHandler({
  request: () => browserRequest({ url: productsUrl, headers: tableHeaders(),
    priority: 'token-priority' }),
  continue: async () => assert.fail('invalid Priority must not continue'),
  abort: async reason => { priorityLeakAbort = reason; }
});
assert.equal(priorityLeakAbort, 'blockedbyclient');
assert.equal(priorityLeakLedger.violation, 'CNYOS_BOUNDED_TREATMENT_PRIORITY_INVALID');
assertCode(() => priorityLeakLedger.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_PRIORITY_INVALID');

let webSocketClosed = false;
webSocketHandler({ close: () => { webSocketClosed = true; } });
assert.equal(webSocketClosed, true);
assert.equal(guardedLedger.violation, 'CNYOS_BOUNDED_TREATMENT_WEBSOCKET_BLOCKED');
assertCode(() => guardedLedger.begin(fixture.sessions[0], 'write-1'),
  'CNYOS_BOUNDED_TREATMENT_WEBSOCKET_BLOCKED');
assert.equal(typeof listeners.get('websocket'), 'function');

const routedAuthLedger = rawLedgerFor(fixture);
const routedAuthHandler = await captureRequestHandler(routedAuthLedger);
let authFetchOptions = null;
let authFulfilled = false;
const authResponseBody = Buffer.from(JSON.stringify({
  access_token: accessToken,
  user: { id: fixture.practitioner.userId, email: practitionerEmail }
}));
await routedAuthHandler({
  request: () => browserRequest({
    url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/auth/v1/token?grant_type=password`,
    method: 'POST', resourceType: 'fetch', priority: 'u=1, i',
    headers: fetchHeaders({
      apikey: publishableKey,
      authorization: `Bearer ${publishableKey}`,
      'content-type': 'application/json;charset=UTF-8',
      'x-client-info': clientInfo,
      'x-supabase-api-version': '2024-01-01'
    }),
    postData: JSON.stringify({ email: practitionerEmail, password,
      gotrue_meta_security: {} })
  }),
  fetch: async options => {
    authFetchOptions = options;
    return { status: () => 200, body: async () => authResponseBody };
  },
  fulfill: async () => { authFulfilled = true; },
  abort: async () => assert.fail('valid auth request must not abort')
});
assert.equal(authFulfilled, true);
assert.equal(hasHeader(authFetchOptions.headers, 'priority'), false);
assert.match(routedAuthLedger.accessTokenSha256, /^[0-9a-f]{64}$/);

const writeUrl = `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/rpc/create_clinical_treatment_session`;
assert.equal(ledger.inspect({
  url: writeUrl, method: 'POST', postData: '{}', resourceType: 'fetch', headers: rpcHeaders()
}).allow, false);

const routedWriteLedger = ledgerFor(fixture);
routedWriteLedger.begin(fixture.sessions[0], 'write-1');
const routedWriteHandler = await captureRequestHandler(routedWriteLedger);
let writeFetchOptions = null;
let writeFulfilled = false;
const routedWriteBody = Buffer.from(JSON.stringify(expectedRow(fixture,
  fixture.sessions[0], 1)));
await routedWriteHandler({
  request: () => browserRequest({
    url: writeUrl, method: 'POST', resourceType: 'fetch', priority: 'u=1, i',
    headers: rpcHeaders(),
    postData: JSON.stringify(payloadFor(fixture, fixture.sessions[0]))
  }),
  fetch: async options => {
    writeFetchOptions = options;
    return { status: () => 200, body: async () => routedWriteBody };
  },
  fulfill: async () => { writeFulfilled = true; },
  abort: async () => assert.fail('valid treatment write must not abort')
});
assert.equal(writeFulfilled, true);
assert.equal(hasHeader(writeFetchOptions.headers, 'priority'), false);
assert.equal(routedWriteLedger.writes.length, 1);

const writeLedger = ledgerFor(fixture);
writeLedger.begin(fixture.sessions[0], 'write-1');
const firstWrite = writeLedger.inspect({
  url: writeUrl, method: 'POST', postData: JSON.stringify(payloadFor(fixture, fixture.sessions[0])),
  resourceType: 'fetch', headers: rpcHeaders()
});
assert.equal(firstWrite.allow, true);
writeLedger.response(fixture.sessions[0].operationId, 200,
  Buffer.from(JSON.stringify(expectedRow(fixture, fixture.sessions[0], 1))));
assert.equal(writeLedger.inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/clinical_treatment_sessions?select=*&encounter_id=eq.${fixture.encounter.id}&id=eq.${expectedRow(fixture, fixture.sessions[0], 1).id}`,
  method: 'GET', postData: null, resourceType: 'fetch', headers: tableHeaders()
}).allow, true);
writeLedger.finish();
writeLedger.begin(fixture.sessions[1], 'write-2');
const secondWrite = writeLedger.inspect({
  url: writeUrl, method: 'POST', postData: JSON.stringify(payloadFor(fixture, fixture.sessions[1])),
  resourceType: 'fetch', headers: rpcHeaders()
});
assert.equal(secondWrite.allow, true);
writeLedger.response(fixture.sessions[1].operationId, 200,
  Buffer.from(JSON.stringify(expectedRow(fixture, fixture.sessions[1], 2))));
writeLedger.finish();
assert.equal(writeLedger.assertFinal(), true);
assert.equal(writeLedger.inspect({
  url: writeUrl, method: 'POST', postData: JSON.stringify(payloadFor(fixture, fixture.sessions[0])),
  resourceType: 'fetch', headers: rpcHeaders()
}).allow, false);

const directTableMutation = ledgerFor(fixture).inspect({
  url: `${BOUNDED_TREATMENT_TARGET.supabaseOrigin}/rest/v1/clinical_treatment_sessions`,
  method: 'POST', postData: '{}', resourceType: 'fetch', headers: rpcHeaders()
});
assert.equal(directTableMutation.allow, false);

const dispatchedLedger = ledgerFor(fixture);
dispatchedLedger.begin(fixture.sessions[0], 'write-1');
assert.equal(dispatchedLedger.inspect({
  url: writeUrl,
  method: 'POST',
  postData: JSON.stringify(payloadFor(fixture, fixture.sessions[0])),
  resourceType: 'fetch', headers: rpcHeaders()
}).allow, true);
dispatchedLedger.finish();
const afterDispatch = classifyTreatmentFailure(new Error('context closed'), {
  readbacks: []
}, dispatchedLedger, fixture);
assert.equal(afterDispatch.status, 'UNCERTAIN');
assert.equal(afterDispatch.session.operationId, fixture.sessions[0].operationId);
assert.equal(afterDispatch.ordinal, 1);
assert.equal(afterDispatch.failureCode, 'CNYOS_BOUNDED_TREATMENT_EXCEPTION_AFTER_DISPATCH');
const afterExactFreshReadback = classifyTreatmentFailure(new Error('canonical recheck failed'), {
  readbacks: [{ operationId: fixture.sessions[0].operationId }]
}, dispatchedLedger, fixture);
assert.equal(afterExactFreshReadback.status, 'FAIL');
assert.equal(afterExactFreshReadback.session, null);
const secondDispatched = classifyTreatmentFailure(new Error('second context failed'), {
  readbacks: [{ operationId: fixture.sessions[0].operationId }]
}, writeLedger, fixture);
assert.equal(secondDispatched.status, 'UNCERTAIN');
assert.equal(secondDispatched.session.operationId, fixture.sessions[1].operationId);
assert.equal(secondDispatched.ordinal, 2);

let reads = 0;
const applied = await reconcileAmbiguousOperation({
  readOnce: async () => { reads += 1; return expectedRow(fixture, fixture.sessions[0], 1); },
  fixture, session: fixture.sessions[0], ordinal: 1
});
assert.equal(applied.result, 'APPLIED');
assert.equal(reads, 1);
const absent = await reconcileAmbiguousOperation({
  readOnce: async () => null, fixture, session: fixture.sessions[0], ordinal: 1
});
assert.equal(absent.result, 'NOT_FOUND');
const conflicting = await reconcileAmbiguousOperation({
  readOnce: async () => ({ ...expectedRow(fixture, fixture.sessions[0], 1), pain_after: 9 }),
  fixture, session: fixture.sessions[0], ordinal: 1
});
assert.equal(conflicting.result, 'CONFLICT');
const unknown = await reconcileAmbiguousOperation({
  readOnce: async () => { throw new Error('network'); },
  fixture, session: fixture.sessions[0], ordinal: 1
});
assert.equal(unknown.result, 'UNKNOWN');

const manifest = {
  schemaVersion: 1,
  deploymentId: 'chananya-clinical-staging',
  tenant: {
    expectedClinicId: BOUNDED_TREATMENT_TARGET.clinicId,
    expectedClinicCode: BOUNDED_TREATMENT_TARGET.clinicCode
  },
  identity: { runtime: 'staging' },
  source: { commit: sourceCommit, tree: sourceTree, verified: true },
  build: { context: 'production' },
  safety: {
    previewLocked: false,
    databaseLocked: false,
    stagingDatabaseExplicitlyAcknowledged: true
  }
};
const manifestBytes = Buffer.from(JSON.stringify(manifest));
const manifestSha1 = crypto.createHash('sha1').update(manifestBytes).digest('hex');
const fetchedUrls = [];
const mockFetch = async url => {
  const value = String(url);
  fetchedUrls.push(value);
  if (value.endsWith(`/sites/${BOUNDED_TREATMENT_TARGET.netlifySiteId}`)) {
    return Response.json({
      id: BOUNDED_TREATMENT_TARGET.netlifySiteId,
      name: BOUNDED_TREATMENT_TARGET.netlifySiteName,
      ssl_url: BOUNDED_TREATMENT_TARGET.origin,
      published_deploy: { id: deployId }
    });
  }
  if (value.endsWith(`/deploys/${deployId}`)) {
    return Response.json({
      id: deployId,
      site_id: BOUNDED_TREATMENT_TARGET.netlifySiteId,
      state: 'ready',
      context: 'production',
      deploy_ssl_url: `https://${deployId}--${BOUNDED_TREATMENT_TARGET.netlifySiteName}.netlify.app`,
      published_at: '2026-10-07T12:05:00.000Z',
      commit_ref: sourceCommit
    });
  }
  if (value.endsWith(`/deploys/${deployId}/files`)) {
    return Response.json([{ path: '/deploy-manifest.json', sha: manifestSha1 }]);
  }
  if (value === `${config.immutableOrigin}/deploy-manifest.json` ||
    value === `${BOUNDED_TREATMENT_TARGET.origin}/deploy-manifest.json`) {
    return new Response(manifestBytes, { status: 200,
      headers: { 'content-type': 'application/json' } });
  }
  return new Response('not found', { status: 404 });
};

const deployment = await preflightExactDeployment(config, { fetchImpl: mockFetch });
assert.equal(deployment.deployId, deployId);
assert.equal(deployment.sourceCommit, sourceCommit);
assert.equal(deployment.sourceTree, sourceTree);
assert.equal(deployment.immutableOrigin, config.immutableOrigin);
assert(fetchedUrls.includes(`${config.immutableOrigin}/deploy-manifest.json`));
assert(!fetchedUrls.includes(`${BOUNDED_TREATMENT_TARGET.origin}/deploy-manifest.json`));

const canonicalPublication = await recheckCanonicalPublication(config, deployment,
  { fetchImpl: mockFetch });
assert.equal(canonicalPublication.deployId, deployId);
assert(fetchedUrls.includes(`${BOUNDED_TREATMENT_TARGET.origin}/deploy-manifest.json`));
await assert.rejects(() => recheckCanonicalPublication(config, deployment, {
  fetchImpl: async url => {
    if (String(url).endsWith(`/sites/${BOUNDED_TREATMENT_TARGET.netlifySiteId}`)) {
      return Response.json({
        id: BOUNDED_TREATMENT_TARGET.netlifySiteId,
        name: BOUNDED_TREATMENT_TARGET.netlifySiteName,
        ssl_url: BOUNDED_TREATMENT_TARGET.origin,
        published_deploy: { id: 'f'.repeat(24) }
      });
    }
    return mockFetch(url);
  }
}), error => error instanceof BoundedTreatmentError &&
  error.code === 'CNYOS_BOUNDED_TREATMENT_CANONICAL_PUBLICATION_CHANGED');

const evidenceLedger = ledgerFor(fixture);
const evidence = buildEvidence(config, {
  startedAt: '2026-10-07T12:06:00.000Z',
  status: 'FAIL',
  failureCode: 'EXPECTED_TEST_FAILURE',
  deployment,
  canonicalPublication,
  writes: [],
  readbacks: [],
  reconciliation: null
}, evidenceLedger, new Date('2026-10-07T12:07:00.000Z'));
const serialized = JSON.stringify(evidence);
assert(!serialized.includes(password));
assert(!serialized.includes(netlifyToken));
assert(!serialized.includes(publishableKey));
assert(!serialized.includes(accessToken));
assert(!serialized.includes(ledgerPath));
assert.equal(evidence.status, 'FAIL');
assert.equal(evidence.productionAuthorization, false);
assert.equal(evidence.controller.repository, POLICY.controller.repository);
assert.equal(evidence.controller.ref, POLICY.controller.protectedRef);
assert.equal(evidence.controller.commit, controllerCommit);
assert.equal(evidence.controller.runId, controllerRunId);
assert.equal(evidence.controller.policySha256, POLICY_SHA256);
assert.equal(evidence.runAuthorization.status, 'authorized');
assert.equal(evidence.runAuthorization.inputSha256,
  baseEnvironment.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256);
assert.equal(evidence.runAuthorization.expectedSha256,
  baseEnvironment.CNYOS_EXPECTED_TREATMENT_UAT_RUN_AUTHORIZATION_SHA256);
assert.equal(evidence.runAuthorization.fixtureSha256, canonicalFixtureSha256(fixture));
assert.equal(serialized.includes('CNYOS_TREATMENT_UAT_RUN_AUTHORIZATION_JSON'), false);
assert.equal(evidence.fixture.protectedLedgerEntryId, 'fixture:treatment:20261007');
assert.equal(evidence.fixture.protectedLedgerFileSha256, ledgerFileSha256);
assert.equal(evidence.fixture.protectedLedgerExpectedSha256, ledgerFileSha256);
assert.equal(evidence.fixture.canonicalFixtureSha256, canonicalFixtureSha256(fixture));
assert(!serialized.includes('registryEvidence'));
assert.equal(evidence.cleanup.status, 'NOT_AUTHORIZED');
assert.equal(evidence.mutationLimit.allowed, 2);
assert.equal(evidence.mutationLimit.writeRetries, 0);

const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-treatment-contract-'));
try {
  const evidencePath = path.join(temporaryDirectory, 'bounded-treatment-evidence.json');
  await writeEvidenceExclusive(evidencePath, evidence);
  assert.equal((await fs.stat(evidencePath)).mode & 0o777, 0o600);
  const written = await fs.readFile(evidencePath, 'utf8');
  assert(!written.includes(password));
  assert(!written.includes(netlifyToken));
  await assert.rejects(() => writeEvidenceExclusive(evidencePath, evidence), error =>
    error instanceof BoundedTreatmentError &&
      error.code === 'CNYOS_BOUNDED_TREATMENT_EVIDENCE_WRITE_FAILED');
} finally {
  await fs.rm(temporaryDirectory, { recursive: true, force: true });
}

await fs.rm(ledgerDirectory, { recursive: true, force: true });

console.log('bounded treatment UAT contract: ok');
