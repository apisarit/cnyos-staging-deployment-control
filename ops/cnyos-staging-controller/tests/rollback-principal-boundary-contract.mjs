import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  POLICY,
  deploymentMarker,
  sha256
} from '../scripts/policy.mjs';
import { rollbackPublishedDeployment } from '../scripts/netlify-evidence.mjs';

assert.notEqual(
  process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE,
  'true',
  'rollback-principal activation contract must remain credential-free'
);

const targetRunId = '800001';
const watchdogRunId = '900001';
const targetControllerCommit = 'b'.repeat(40);
const watchdogCommit = 'a'.repeat(40);
const candidateCommit = 'c'.repeat(40);
const candidateTree = 'd'.repeat(40);
const artifactSha256 = 'e'.repeat(64);
const liveGitHubPrecredentialBoundaryEvidenceSha256 = '8'.repeat(64);
const liveGitHubPrepromotionBoundaryEvidenceSha256 = '9'.repeat(64);
const previousDeployId = '1'.repeat(24);
const controllerDeployId = '2'.repeat(24);
const foreignDeployId = '3'.repeat(24);
const dispatchNonce = Buffer.alloc(32, 0x7b).toString('base64url');
const publishSubject = 'netlify:offline-publish-principal';
const rollbackSubject = 'netlify:offline-rollback-principal';
const rollbackToken = 'offline-rollback-token-never-sent-to-a-network';
const expectedDeployMessage = deploymentMarker(
  targetRunId,
  dispatchNonce,
  candidateCommit
);

const watchdogRuntime = Object.freeze({
  GITHUB_REPOSITORY: POLICY.controller.repository,
  CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
  GITHUB_RUN_ID: watchdogRunId,
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_REF_PROTECTED: 'true',
  CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
  GITHUB_REF: POLICY.controller.protectedRef,
  GITHUB_SHA: watchdogCommit,
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.rollbackWorkflowPath,
  GITHUB_WORKFLOW_REF:
    `${POLICY.controller.repository}/${POLICY.controller.rollbackWorkflowPath}@${POLICY.controller.protectedRef}`
});
const primaryReleaseRuntime = Object.freeze({
  ...watchdogRuntime,
  GITHUB_RUN_ID: targetRunId,
  GITHUB_SHA: targetControllerCommit,
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
  GITHUB_WORKFLOW_REF:
    `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`
});

const temporaryRoot = await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-rollback-principal-contract-')
);
let fixtureSequence = 0;
let globalFetchCalls = 0;
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => {
  globalFetchCalls += 1;
  throw new Error('CNYOS_TEST_FORBIDS_GLOBAL_NETWORK');
};

function preflightFixture() {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_preflight',
    productionAuthorization: false,
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: targetControllerCommit,
    controllerRunId: targetRunId,
    dispatchNonce,
    source: {
      repository: POLICY.sourceRepository,
      commit: candidateCommit,
      tree: candidateTree
    },
    artifact: { artifactSha256 },
    liveGitHubPrecredentialBoundaryEvidenceSha256,
    target: structuredClone(POLICY.target),
    targetSiteAndPublisherExclusion: {
      productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin
    },
    netlifyPrincipalSubject: publishSubject,
    rollbackNetlifyPrincipalSubject: rollbackSubject,
    previousPublishedDeploy: { id: previousDeployId }
  };
}

function promotionAttemptFixture(preflightEvidenceSha256) {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_promotion_attempt',
    productionAuthorization: false,
    promotionAuthorization: true,
    controllerRepository: POLICY.controller.repository,
    controllerRef: POLICY.controller.protectedRef,
    controllerCommit: targetControllerCommit,
    controllerRunId: targetRunId,
    dispatchNonce,
    source: {
      repository: POLICY.sourceRepository,
      commit: candidateCommit,
      tree: candidateTree
    },
    artifact: { artifactSha256 },
    target: structuredClone(POLICY.target),
    preflightEvidenceSha256,
    liveGitHubPrecredentialBoundaryEvidenceSha256,
    liveGitHubPrepromotionBoundaryEvidenceSha256,
    rollbackReadinessEvidenceSha256: '4'.repeat(64),
    draftGateEvidenceSha256: '5'.repeat(64),
    previousDeployId,
    draftDeployId: controllerDeployId,
    deployMessage: expectedDeployMessage
  };
}

function rollbackChainFixture(preflightEvidenceSha256, promotionAttemptEvidenceSha256) {
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_rollback_authorization_chain',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    artifactProvenanceAuthenticated: true,
    authorizationSignaturesVerified: true,
    protectedApproverRegistryVerified: true,
    knownGoodEvidenceVerified: true,
    targetControllerRepository: POLICY.controller.repository,
    targetControllerRunId: targetRunId,
    targetControllerCommit,
    preflightEvidenceSha256,
    promotionAttemptEvidenceSha256,
    previousDeployId,
    draftDeployId: controllerDeployId,
    rollbackNetlifyPrincipalSubject: rollbackSubject
  };
}

async function writeEvidence(directory, filename, value) {
  const bytes = Buffer.from(JSON.stringify(value));
  const filenameAbsolute = path.join(directory, filename);
  await fs.writeFile(filenameAbsolute, bytes, { flag: 'wx', mode: 0o600 });
  return Object.freeze({
    path: filenameAbsolute,
    sha256: sha256(bytes)
  });
}

async function createFixture({
  mutatePreflight = () => {},
  mutateAttempt = () => {},
  mutateRollbackChain = () => {},
  runtime = watchdogRuntime,
  targetOverrides = true
} = {}) {
  fixtureSequence += 1;
  const directory = path.join(temporaryRoot, `case-${fixtureSequence}`);
  await fs.mkdir(directory, { mode: 0o700 });

  const preflight = preflightFixture();
  mutatePreflight(preflight);
  const preflightFile = await writeEvidence(directory, 'preflight.json', preflight);

  const attempt = promotionAttemptFixture(preflightFile.sha256);
  mutateAttempt(attempt);
  const attemptFile = await writeEvidence(directory, 'promotion-attempt.json', attempt);

  const rollbackChain = rollbackChainFixture(preflightFile.sha256, attemptFile.sha256);
  mutateRollbackChain(rollbackChain);
  const rollbackChainFile = await writeEvidence(
    directory,
    'rollback-authorization-chain.json',
    rollbackChain
  );
  const outputPath = path.join(directory, 'rollback.json');

  return Object.freeze({
    directory,
    outputPath,
    preflight,
    attempt,
    rollbackChain,
    env: Object.freeze({
      ...runtime,
      CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE: 'false',
      ...(targetOverrides ? {
        CNYOS_TARGET_CONTROLLER_RUN_ID: targetRunId,
        CNYOS_TARGET_CONTROLLER_COMMIT: targetControllerCommit
      } : {}),
      CNYOS_CONTROLLER_ROLLBACK_ACK: 'RESTORE_EXACT_CNYOS_STAGING_PREVIOUS_DEPLOY',
      CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.path,
      CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.sha256,
      CNYOS_CONTROLLER_PUBLISH_ATTEMPT_EVIDENCE_PATH: attemptFile.path,
      CNYOS_EXPECTED_PUBLISH_ATTEMPT_EVIDENCE_SHA256: attemptFile.sha256,
      CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH: rollbackChainFile.path,
      CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256: rollbackChainFile.sha256,
      CNYOS_CONTROLLER_ROLLBACK_EVIDENCE_PATH: outputPath
    })
  });
}

function withTrackedRollbackToken(env, value = rollbackToken) {
  let readCount = 0;
  const tracked = { ...env };
  Object.defineProperty(tracked, 'CNYOS_STAGING_NETLIFY_AUTH_TOKEN', {
    enumerable: true,
    configurable: false,
    get() {
      readCount += 1;
      return value;
    }
  });
  return Object.freeze({
    env: Object.freeze(tracked),
    readCount: () => readCount
  });
}

function stagingSite(publishedDeployId) {
  return {
    id: POLICY.target.netlifySiteId,
    name: POLICY.target.netlifySiteName,
    ssl_url: POLICY.target.netlifyOrigin,
    published_deploy: { id: publishedDeployId }
  };
}

function productionSite(publishedDeployId = foreignDeployId) {
  return {
    id: POLICY.productionDenylist.netlifySiteId,
    name: 'chananya',
    ssl_url: POLICY.productionDenylist.netlifyOrigin,
    published_deploy: { id: publishedDeployId }
  };
}

function deploy(deployId, { title = null } = {}) {
  return {
    id: deployId,
    site_id: POLICY.target.netlifySiteId,
    state: 'ready',
    context: 'production',
    deploy_ssl_url: `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`,
    commit_ref: candidateCommit,
    title,
    published_at: '2026-09-08T11:59:00.000Z',
    draft: false
  };
}

function jsonResponse(value, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'content-type': 'application/json',
      ...headers
    }
  });
}

function rollbackFetch({
  principalSubject = rollbackSubject,
  siteInventory = null,
  siteInventoryHeaders = {},
  currentDeployId = controllerDeployId,
  currentDeployTitle = expectedDeployMessage,
  siteAfterDeployId = previousDeployId,
  restoreStatus = 200
} = {}) {
  const calls = [];
  let siteReads = 0;
  const fetchImpl = async (url, options = {}) => {
    const parsed = new URL(url);
    const call = Object.freeze({
      url,
      pathname: parsed.pathname,
      search: parsed.search,
      method: options.method,
      redirect: options.redirect,
      authorization: options.headers?.Authorization,
      body: options.body ?? null
    });
    calls.push(call);
    assert.equal(parsed.origin, 'https://api.netlify.com');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers?.Authorization, `Bearer ${rollbackToken}`);

    if (parsed.pathname === '/api/v1/user' && parsed.search === '') {
      assert.equal(options.method, 'GET');
      return jsonResponse({ id: principalSubject });
    }
    if (parsed.pathname === '/api/v1/sites' && parsed.search === '?per_page=100&page=1') {
      assert.equal(options.method, 'GET');
      return jsonResponse(siteInventory || [stagingSite(currentDeployId)], {
        headers: siteInventoryHeaders
      });
    }
    if (parsed.pathname === `/api/v1/sites/${POLICY.target.netlifySiteId}` &&
      parsed.search === '') {
      assert.equal(options.method, 'GET');
      siteReads += 1;
      return jsonResponse(stagingSite(siteReads === 1 ? currentDeployId : siteAfterDeployId));
    }
    if (parsed.pathname === `/api/v1/deploys/${currentDeployId}` &&
      currentDeployId !== previousDeployId && parsed.search === '') {
      assert.equal(options.method, 'GET');
      return jsonResponse(deploy(currentDeployId, { title: currentDeployTitle }));
    }
    if (parsed.pathname === `/api/v1/sites/${POLICY.target.netlifySiteId}` +
      `/deploys/${previousDeployId}/restore` && parsed.search === '') {
      assert.equal(options.method, 'POST');
      assert.equal(options.headers?.['Content-Type'], 'application/json');
      return new Response(null, { status: restoreStatus });
    }
    if (parsed.pathname === `/api/v1/deploys/${previousDeployId}` && parsed.search === '') {
      assert.equal(options.method, 'GET');
      return jsonResponse(deploy(previousDeployId));
    }
    throw new Error(`UNEXPECTED_OFFLINE_NETLIFY_REQUEST:${parsed.pathname}${parsed.search}`);
  };
  return Object.freeze({ fetchImpl, calls });
}

function restoreCalls(calls) {
  return calls.filter(call => call.method === 'POST');
}

function assertNoSecretSerialization(calls) {
  for (const call of calls) {
    assert.equal(call.url.includes(rollbackToken), false);
    assert.equal(String(call.body || '').includes(rollbackToken), false);
    assert.equal(call.body, null, 'rollback API requests must not serialize a request body');
  }
}

async function assertNoOutput(filename) {
  await assert.rejects(
    fs.access(filename),
    error => error?.code === 'ENOENT',
    'failed rollback must not emit success evidence'
  );
}

async function assertPreTokenFailure({ fixture, error, env = fixture.env }) {
  const tracked = withTrackedRollbackToken(env);
  const boundary = rollbackFetch();
  await assert.rejects(
    rollbackPublishedDeployment({ env: tracked.env, fetchImpl: boundary.fetchImpl }),
    error
  );
  assert.equal(tracked.readCount(), 0, 'local evidence failure must precede token access');
  assert.equal(boundary.calls.length, 0, 'local evidence failure must precede provider access');
  await assertNoOutput(fixture.outputPath);
}

const rollbackEvidenceKeys = [
  'schemaVersion',
  'evidenceType',
  'status',
  'authorization',
  'scope',
  'productionAuthorization',
  'rolledBackAt',
  'watchdogRepository',
  'watchdogRef',
  'watchdogCommit',
  'watchdogRunId',
  'targetControllerRunId',
  'dispatchNonce',
  'target',
  'action',
  'restoredFromDeployId',
  'restoredToDeployId',
  'restoredDeploy',
  'preflightEvidenceSha256',
  'publishAttemptEvidenceSha256',
  'rollbackAuthorizationChainEvidenceSha256'
].sort();
const restoredDeployKeys = [
  'id',
  'siteId',
  'state',
  'context',
  'commitRef',
  'title',
  'exactDeployOrigin',
  'publishedAt'
].sort();

async function assertExactRollbackEvidence({
  fixture,
  result,
  runtime,
  action,
  restoredFromDeployId
}) {
  const evidence = result.evidence;
  assert.deepEqual(Object.keys(evidence).sort(), rollbackEvidenceKeys);
  assert.deepEqual(Object.keys(evidence.restoredDeploy).sort(), restoredDeployKeys);
  assert.equal(result.evidencePath, fixture.outputPath);
  assert.equal(evidence.schemaVersion, 1);
  assert.equal(evidence.evidenceType, 'cnyos_staging_controller_rollback');
  assert.equal(evidence.status, 'passed');
  assert.equal(evidence.authorization, false);
  assert.equal(evidence.scope, 'cnyos_staging_only');
  assert.equal(evidence.productionAuthorization, false);
  assert.equal(evidence.rolledBackAt, '2026-09-08T12:00:00.000Z');
  assert.equal(evidence.watchdogRepository, runtime.GITHUB_REPOSITORY);
  assert.equal(evidence.watchdogRef, runtime.GITHUB_REF);
  assert.equal(evidence.watchdogCommit, runtime.GITHUB_SHA);
  assert.equal(evidence.watchdogRunId, runtime.GITHUB_RUN_ID);
  assert.equal(evidence.targetControllerRunId, targetRunId);
  assert.equal(evidence.dispatchNonce, dispatchNonce);
  assert.deepEqual(evidence.target, POLICY.target);
  assert.equal(evidence.action, action);
  assert.equal(evidence.restoredFromDeployId, restoredFromDeployId);
  assert.equal(evidence.restoredToDeployId, previousDeployId);
  assert.deepEqual(evidence.restoredDeploy, {
    id: previousDeployId,
    siteId: POLICY.target.netlifySiteId,
    state: 'ready',
    context: 'production',
    commitRef: candidateCommit,
    title: null,
    exactDeployOrigin:
      `https://${previousDeployId}--${POLICY.target.netlifySiteName}.netlify.app`,
    publishedAt: '2026-09-08T11:59:00.000Z'
  });
  assert.equal(
    evidence.preflightEvidenceSha256,
    fixture.env.CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256
  );
  assert.equal(
    evidence.publishAttemptEvidenceSha256,
    fixture.env.CNYOS_EXPECTED_PUBLISH_ATTEMPT_EVIDENCE_SHA256
  );
  assert.equal(
    evidence.rollbackAuthorizationChainEvidenceSha256,
    fixture.env.CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256
  );
  const output = await fs.readFile(fixture.outputPath, 'utf8');
  assert.deepEqual(JSON.parse(output), evidence);
  assert.equal(output.includes(rollbackToken), false);
}

async function assertProviderFailure({
  fixture,
  boundary,
  error,
  expectedRestoreCalls = 0
}) {
  const tracked = withTrackedRollbackToken(fixture.env);
  await assert.rejects(
    rollbackPublishedDeployment({ env: tracked.env, fetchImpl: boundary.fetchImpl }),
    error
  );
  assert.equal(tracked.readCount(), 1, 'validated chain must read the rollback token once');
  assert.equal(restoreCalls(boundary.calls).length, expectedRestoreCalls);
  assertNoSecretSerialization(boundary.calls);
  await assertNoOutput(fixture.outputPath);
}

try {
  {
    const fixture = await createFixture();
    await assertPreTokenFailure({
      fixture,
      env: { ...fixture.env, CNYOS_CONTROLLER_ROLLBACK_ACK: 'WRONG_ACK' },
      error: /CNYOS_CONTROLLER_ROLLBACK_ACK_REQUIRED/
    });
  }

  {
    const fixture = await createFixture();
    await assertPreTokenFailure({
      fixture,
      env: { ...fixture.env, GITHUB_REF_PROTECTED: 'false' },
      error: /CNYOS_CONTROLLER_REF_NOT_PROTECTED/
    });
  }

  for (const [digestName, error] of [
    ['CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256',
      /CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_INVALID_DIGEST_MISMATCH/],
    ['CNYOS_EXPECTED_PUBLISH_ATTEMPT_EVIDENCE_SHA256',
      /CNYOS_CONTROLLER_PUBLISH_ATTEMPT_EVIDENCE_INVALID_DIGEST_MISMATCH/],
    ['CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256',
      /CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_INVALID_DIGEST_MISMATCH/]
  ]) {
    const fixture = await createFixture();
    await assertPreTokenFailure({
      fixture,
      env: { ...fixture.env, [digestName]: '0'.repeat(64) },
      error
    });
  }

  for (const mutateAttempt of [
    value => { value.promotionAuthorization = false; },
    value => { value.liveGitHubPrecredentialBoundaryEvidenceSha256 = '6'.repeat(64); },
    value => { delete value.liveGitHubPrepromotionBoundaryEvidenceSha256; },
    value => { value.deployMessage = 'foreign-controller-marker'; }
  ]) {
    const fixture = await createFixture({ mutateAttempt });
    await assertPreTokenFailure({
      fixture,
      error: /CNYOS_CONTROLLER_PUBLISH_CHAIN_INVALID/
    });
  }

  {
    const fixture = await createFixture({
      mutatePreflight: value => {
        delete value.liveGitHubPrecredentialBoundaryEvidenceSha256;
      },
      mutateAttempt: value => {
        delete value.liveGitHubPrecredentialBoundaryEvidenceSha256;
      }
    });
    await assertPreTokenFailure({
      fixture,
      error: /CNYOS_CONTROLLER_PUBLISH_CHAIN_INVALID/
    });
  }

  {
    const malformedDigest = 'g'.repeat(64);
    const fixture = await createFixture({
      mutatePreflight: value => {
        value.liveGitHubPrecredentialBoundaryEvidenceSha256 = malformedDigest;
      },
      mutateAttempt: value => {
        value.liveGitHubPrecredentialBoundaryEvidenceSha256 = malformedDigest;
      }
    });
    await assertPreTokenFailure({
      fixture,
      error: /CNYOS_CONTROLLER_PUBLISH_CHAIN_INVALID/
    });
  }

  for (const malformedDigest of ['g'.repeat(64), 'G'.repeat(64)]) {
    const fixture = await createFixture({
      mutateAttempt: value => {
        value.liveGitHubPrepromotionBoundaryEvidenceSha256 = malformedDigest;
      }
    });
    await assertPreTokenFailure({
      fixture,
      error: /CNYOS_CONTROLLER_PUBLISH_CHAIN_INVALID/
    });
  }

  for (const mutateRollbackChain of [
    value => { value.status = 'failed'; },
    value => { value.productionAuthorization = true; },
    value => { value.artifactProvenanceAuthenticated = false; },
    value => { value.authorizationSignaturesVerified = false; },
    value => { value.protectedApproverRegistryVerified = false; },
    value => { value.knownGoodEvidenceVerified = false; },
    value => { value.targetControllerCommit = 'f'.repeat(40); },
    value => { value.preflightEvidenceSha256 = '6'.repeat(64); },
    value => { value.promotionAttemptEvidenceSha256 = '7'.repeat(64); },
    value => { value.rollbackNetlifyPrincipalSubject = publishSubject; }
  ]) {
    const fixture = await createFixture({ mutateRollbackChain });
    await assertPreTokenFailure({
      fixture,
      error: /CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_INVALID/
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({ principalSubject: publishSubject }),
      error: /CNYOS_CONTROLLER_NETLIFY_PRINCIPAL_SUBJECT_MISMATCH/
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({ siteInventory: [productionSite()] }),
      error: /CNYOS_CONTROLLER_NETLIFY_SITE_MISMATCH/
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({
        siteInventory: [stagingSite(controllerDeployId), productionSite()]
      }),
      error: /CNYOS_CONTROLLER_NETLIFY_PRINCIPAL_NOT_STAGING_ONLY/
    });
  }

  for (const siteInventoryHeaders of [
    { 'x-next-page': '2' },
    { link: '<https://api.netlify.com/api/v1/sites?page=2>; rel="next"' },
    { 'x-page-count': '2' }
  ]) {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({ siteInventoryHeaders }),
      error: /CNYOS_CONTROLLER_NETLIFY_SITE_INVENTORY_PAGINATED/
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({
        currentDeployId: foreignDeployId,
        currentDeployTitle: expectedDeployMessage
      }),
      error: /CNYOS_CONTROLLER_ROLLBACK_CURRENT_DEPLOY_NOT_OWNED/
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({ currentDeployTitle: 'foreign-controller-marker' }),
      error: /CNYOS_CONTROLLER_ROLLBACK_CURRENT_DEPLOY_NOT_OWNED/
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({ restoreStatus: 500 }),
      error: /CNYOS_CONTROLLER_NETLIFY_RESTORE_STATUS_500/,
      expectedRestoreCalls: 1
    });
  }

  {
    const fixture = await createFixture();
    await assertProviderFailure({
      fixture,
      boundary: rollbackFetch({ siteAfterDeployId: controllerDeployId }),
      error: /CNYOS_CONTROLLER_NETLIFY_PUBLISHED_DEPLOY_MISMATCH/,
      expectedRestoreCalls: 1
    });
  }

  {
    const fixture = await createFixture();
    const boundary = rollbackFetch();
    const tracked = withTrackedRollbackToken(fixture.env);
    const result = await rollbackPublishedDeployment({
      env: tracked.env,
      fetchImpl: boundary.fetchImpl,
      now: () => new Date('2026-09-08T12:00:00.000Z')
    });
    assert.equal(tracked.readCount(), 1);
    assert.equal(restoreCalls(boundary.calls).length, 1);
    assert.equal(restoreCalls(boundary.calls)[0].body, null);
    assertNoSecretSerialization(boundary.calls);
    await assertExactRollbackEvidence({
      fixture,
      result,
      runtime: watchdogRuntime,
      action: 'restored_previous_deploy',
      restoredFromDeployId: controllerDeployId
    });
  }

  {
    const fixture = await createFixture({
      runtime: primaryReleaseRuntime,
      targetOverrides: false
    });
    const boundary = rollbackFetch({
      currentDeployId: previousDeployId,
      siteAfterDeployId: previousDeployId
    });
    const tracked = withTrackedRollbackToken(fixture.env);
    const result = await rollbackPublishedDeployment({
      env: tracked.env,
      fetchImpl: boundary.fetchImpl,
      now: () => new Date('2026-09-08T12:00:00.000Z')
    });
    assert.equal(tracked.readCount(), 1);
    assert.equal(restoreCalls(boundary.calls).length, 0);
    assertNoSecretSerialization(boundary.calls);
    await assertExactRollbackEvidence({
      fixture,
      result,
      runtime: primaryReleaseRuntime,
      action: 'already_restored',
      restoredFromDeployId: previousDeployId
    });
  }

  assert.equal(globalFetchCalls, 0, 'contract must not make a live network request');
} finally {
  globalThis.fetch = originalFetch;
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

process.stdout.write('CNYOS activation contract rollback-principal-boundary: passed\n');
