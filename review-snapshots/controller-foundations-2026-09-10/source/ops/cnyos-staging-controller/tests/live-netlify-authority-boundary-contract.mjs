import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

assert.notEqual(process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE, 'true');
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-authority-contract-'));
const root = await fs.realpath(temporaryRoot);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const NOW = new Date('2030-01-01T00:10:00.000Z');
const EXPIRES = '2030-01-01T00:15:00.000Z';
const TOKEN = 'offline-authority-oidc-canary-no-live-credential';
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const sourcePolicy = JSON.parse(await fs.readFile(path.join(packageRoot, 'controller-policy.json'), 'utf8'));
const policy = structuredClone(sourcePolicy);
policy.netlifyAuthorityBoundary = {
  ...policy.netlifyAuthorityBoundary,
  origin: 'https://authority.test', operationPath: '/v1/observe',
  operationDomain: 'cnyos_staging_netlify_authority', policyId: 'fixture-authority-v1',
  policySha256: '1'.repeat(64), signingKeyId: 'fixture-authority-key-v1',
  signingPublicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  signingKeySpkiSha256: hash(publicKey.export({ type: 'spki', format: 'der' })),
  oidcAudience: 'https://authority.test/oidc', maximumAgeMinutes: 10, maximumResponseBytes: 262144
};
const policyRaw = JSON.stringify(policy);
try {
  await fs.cp(path.join(packageRoot, 'scripts'), path.join(root, 'scripts'), { recursive: true });
  await fs.writeFile(path.join(root, 'controller-policy.json'), policyRaw, { flag: 'wx' });
  const module = await import(pathToFileURL(path.join(root, 'scripts/verify-live-netlify-authority-boundary.mjs')));
  const common = await import(pathToFileURL(path.join(root, 'scripts/reconcile-netlify-release-state.mjs')));
  const evidenceModule = await import(pathToFileURL(path.join(root, 'scripts/netlify-evidence.mjs')));
  const isolatedPolicy = await import(pathToFileURL(path.join(root, 'scripts/policy.mjs')));
  const original = await import('../scripts/verify-live-netlify-authority-boundary.mjs');
  const runtime = {
    controllerRepository: policy.controller.repository, controllerRef: policy.controller.protectedRef,
    controllerCommit: 'a'.repeat(40), controllerRunId: '700001', controllerRunAttempt: 1
  };
  const authorization = {
    schemaVersion: 1, evidenceType: 'cnyos_staging_controller_authorization_validation',
    status: 'authorized', scope: 'cnyos_staging_only', productionAuthorization: false,
    realPatientDataAuthorized: false, ...runtime,
    target: policy.target, policySha256: hash(policyRaw),
    dispatchNonce: Buffer.alloc(32, 1).toString('base64url'),
    source: { repository: policy.sourceRepository, commit: 'b'.repeat(40), tree: 'c'.repeat(40) },
    artifact: { artifactSha256: 'd'.repeat(64) }, previousDeployId: '0123456789abcdef01234567',
    targetSiteAndPublisherExclusion: {
      productionNetlifySiteId: policy.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: policy.productionDenylist.netlifyOrigin
    },
    authorizationExpiresAt: '2030-01-01T00:30:00.000Z',
    deploymentControlBoundaryExpiresAt: '2030-01-01T00:30:00.000Z',
    netlifyPrincipalSubject: 'fixture-publisher', netlifyPrincipalBoundary: { membershipRole: 'Publisher' }
  };
  const deposit = {
    schemaVersion: 1, evidenceType: 'cnyos_staging_rollback_attestation_deposit_validation',
    status: 'passed', scope: 'cnyos_staging_only', productionAuthorization: false,
    realPatientDataAuthorized: false, secretValuesSerialized: false, ...runtime,
    controllerWorkflowPath: policy.controller.releaseWorkflowPath,
    policySha256: hash(policyRaw), dispatchNonce: authorization.dispatchNonce,
    source: authorization.source, artifact: authorization.artifact,
    previousDeployId: authorization.previousDeployId,
    target: {
      netlifySiteId: policy.target.netlifySiteId, netlifyOrigin: policy.target.netlifyOrigin,
      supabaseProjectRef: policy.target.supabaseProjectRef,
      databaseSystemIdentifier: policy.target.databaseSystemIdentifier,
      targetSha256: hash(JSON.stringify(policy.target)), previousDeployId: authorization.previousDeployId
    },
    immutableAppendOnlyDepositVerified: true, exactRunNonceRetrievalBoundaryVerified: true,
    completeRecoveryMaterialStoredVerified: true, rawPayloadArtifactExposure: false,
    verifiedAt: NOW.toISOString(), depositedAt: NOW.toISOString(), retentionUntil: '2031-01-02T00:10:00.000Z'
  };
  const authPath = path.join(root, 'authorization.json');
  const depositPath = path.join(root, 'deposit.json');
  const authRaw = JSON.stringify(authorization), depositRaw = JSON.stringify(deposit);
  await fs.writeFile(authPath, authRaw, { flag: 'wx' });
  await fs.writeFile(depositPath, depositRaw, { flag: 'wx' });
  const baseEnv = {
    GITHUB_REPOSITORY: policy.controller.repository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: policy.controller.repository,
    GITHUB_RUN_ID: runtime.controllerRunId, GITHUB_RUN_ATTEMPT: '1', GITHUB_REF_PROTECTED: 'true',
    CNYOS_CONTROLLER_PROTECTED_REF: policy.controller.protectedRef, GITHUB_REF: policy.controller.protectedRef,
    GITHUB_SHA: runtime.controllerCommit, CNYOS_CONTROLLER_WORKFLOW_PATH: policy.controller.releaseWorkflowPath,
    GITHUB_WORKFLOW_REF: `${policy.controller.repository}/${policy.controller.releaseWorkflowPath}@${policy.controller.protectedRef}`,
    GITHUB_ACTOR: 'FixtureActor', GITHUB_TRIGGERING_ACTOR: 'FixtureActor',
    CNYOS_DISPATCH_NONCE: authorization.dispatchNonce,
    CNYOS_NETLIFY_AUTHORITY_BROKER_URL: 'https://authority.test/v1/observe',
    CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: authPath,
    CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: hash(authRaw),
    CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH: depositPath,
    CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256: hash(depositRaw)
  };
  function measurements() {
    const permission = (action, resourceId, decision) => ({ action, subject: authorization.netlifyPrincipalSubject,
      resourceId, decision, decisionReceiptSha256: hash(action), observedAt: NOW.toISOString() });
    return {
      principal: { subject: authorization.netlifyPrincipalSubject, membershipRole: 'Publisher', teamRoles: [],
        accessibleSiteIds: [policy.target.netlifySiteId], inventoryRevision: 'inventory-v1', observedAt: NOW.toISOString() },
      projects: [
        { id: policy.target.netlifySiteId, origin: policy.target.netlifyOrigin, classification: 'staging',
          realPatientDataPresent: false, gitPublishingEnabled: false, buildHookCount: 0, manualPublishingAllowed: false,
          inventoryRevision: 'staging-v1', observedAt: NOW.toISOString() },
        { id: policy.productionDenylist.netlifySiteId, origin: policy.productionDenylist.netlifyOrigin, classification: 'production',
          realPatientDataPresent: true, gitPublishingEnabled: true, buildHookCount: 0, manualPublishingAllowed: true,
          inventoryRevision: 'production-v1', observedAt: NOW.toISOString() }
      ],
      permissions: [permission('account_configuration', 'account', 'deny'),
        permission('production_deployment', policy.productionDenylist.netlifySiteId, 'deny'),
        permission('staging_deployment', policy.target.netlifySiteId, 'allow'),
        permission('team_administration', 'team', 'deny')],
      publisherInventory: { siteId: policy.target.netlifySiteId, revision: 'publishers-v1', complete: true,
        publishers: [], observedAt: NOW.toISOString() },
      enforcement: { mechanism: 'independent_server_side_policy', policyId: policy.netlifyAuthorityBoundary.policyId,
        policySha256: policy.netlifyAuthorityBoundary.policySha256, revision: 'enforcement-v1',
        publisherInventoryRevision: 'publishers-v1', observedAt: NOW.toISOString(),
        rules: module.AUTHORITY_DENIED_PUBLISHER_KINDS.map(publisherKind => ({ publisherKind,
          targetSiteId: policy.target.netlifySiteId, decision: 'deny', decisionReceiptSha256: hash(publisherKind) })) }
    };
  }
  let invocation = 0;
  async function run({ envPatch = {}, changeResult = () => {}, changeEnvelope = () => {},
    changeResponse = response => response, originalModule = false,
    changeAuthorization, changeDeposit } = {}) {
    const output = path.join(root, `output-${++invocation}.json`);
    const env = { ...baseEnv, CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH: output, ...envPatch };
    for (const [mutate, value, pathKey, digestKey] of [
      [changeAuthorization, authorization, 'CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH', 'CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256'],
      [changeDeposit, deposit, 'CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH', 'CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256']
    ]) if (mutate) {
      const changed = structuredClone(value); mutate(changed);
      const raw = JSON.stringify(changed); const filename = `${output}.${pathKey}.json`;
      await fs.writeFile(filename, raw, { flag: 'wx' }); env[pathKey] = filename; env[digestKey] = hash(raw);
    }
    let oidcCalls = 0, networkCalls = 0;
    const promise = (originalModule ? original : module).verifyLiveNetlifyAuthorityBoundary({ env, now: () => NOW,
      oidcTokenProvider: async ({ audience }) => { oidcCalls++; assert.equal(audience, policy.netlifyAuthorityBoundary.oidcAudience); return TOKEN; },
      fetchImpl: async (url, options) => {
        networkCalls++;
        assert.equal(url.href, baseEnv.CNYOS_NETLIFY_AUTHORITY_BROKER_URL);
        assert.equal(options.method, 'POST'); assert.equal(options.redirect, 'error');
        assert.equal(options.credentials, 'omit'); assert.equal(options.headers.Authorization, `Bearer ${TOKEN}`);
        assert.ok(!options.body.includes(TOKEN));
        const request = JSON.parse(options.body);
        assert.equal(request.operation, module.LIVE_AUTHORITY_OPERATION);
        const measured = measurements();
        const result = { schemaVersion: 1, controllerPolicySha256: hash(policyRaw),
          authorizationEvidenceSha256: hash(authRaw), rollbackAttestationDepositEvidenceSha256: hash(depositRaw),
          target: request.target, source: structuredClone(authorization.source), artifactSha256: authorization.artifact.artifactSha256,
          observedAt: NOW.toISOString(), expiresAt: EXPIRES, measurements: measured,
          retainedProof: { reference: `https://authority.test/evidence/${hash(JSON.stringify(measured))}`,
            measurementsSha256: hash(JSON.stringify(measured)), immutable: true, retentionUntil: '2031-01-02T00:10:00.000Z' } };
        changeResult(result);
        const statement = { schemaVersion: 1, operationDomain: request.operationDomain, operation: request.operation,
          policyId: request.policyId, policySha256: request.policySha256, requestSha256: hash(options.body),
          issuedAt: NOW.toISOString(), expiresAt: EXPIRES, result };
        const signature = crypto.sign(null, Buffer.from(JSON.stringify(statement)), privateKey);
        const envelope = { schemaVersion: 1, evidenceType: 'cnyos_staging_reconciliation_broker_envelope', statement,
          brokerSignature: { algorithm: 'Ed25519', keyId: policy.netlifyAuthorityBoundary.signingKeyId,
            statementSha256: hash(JSON.stringify(statement)), signatureBase64: signature.toString('base64'), signatureSha256: hash(signature) } };
        changeEnvelope(envelope);
        const response = new Response(JSON.stringify(envelope), { headers: { 'content-type': 'application/json' } });
        Object.defineProperty(response, 'url', { value: url.href, configurable: true });
        return changeResponse(response);
      }
    });
    return { promise, output, counts: () => ({ oidcCalls, networkCalls }) };
  }
  const positive = await run();
  const result = await positive.promise;
  assert.equal(result.evidence.status, 'passed');
  assert.equal(result.evidence.publishPrincipal.membershipLiveVerified, true);
  assert.equal(result.evidence.deploymentBoundary.buildHooksDisabled, true);
  assert.deepEqual(positive.counts(), { oidcCalls: 1, networkCalls: 1 });
  assert.doesNotMatch(await fs.readFile(positive.output, 'utf8'), /offline-authority-oidc/);
  const attestation = result.evidence.brokerAttestation;
  assert.equal(typeof attestation.signedBrokerEnvelope, 'string');
  const retained = JSON.parse(attestation.signedBrokerEnvelope);
  assert.equal(JSON.stringify(retained), attestation.signedBrokerEnvelope);
  assert.equal(attestation.signedBrokerStatementSha256, retained.brokerSignature.statementSha256);
  assert.notEqual(attestation.normalizedStatementSha256, attestation.signedBrokerStatementSha256);
  assert.equal(attestation.authorizationEvidenceSha256, hash(authRaw));
  assert.equal(attestation.rollbackAttestationDepositEvidenceSha256, hash(depositRaw));
  const consumerOptions = { runtime: isolatedPolicy.assertControllerRuntime(baseEnv), authorization,
    authorizationSha256: hash(authRaw), depositSha256: hash(depositRaw), now: NOW };
  assert.doesNotThrow(() => evidenceModule.validateLiveNetlifyAuthorityBoundary(result.evidence, consumerOptions));
  assert.doesNotThrow(() => evidenceModule.validateSignedLiveNetlifyAuthorityBoundary(result.evidence, consumerOptions));
  for (const mutate of [
    e => { delete e.brokerAttestation.signedBrokerEnvelope; },
    e => { e.brokerAttestation.signedBrokerEnvelope += ' '; },
    e => { e.brokerAttestation.signedBrokerEnvelope = 'x'.repeat(262145); },
    e => { e.brokerAttestation.requestSha256 = '0'.repeat(64); },
    e => { e.brokerAttestation.authorizationEvidenceSha256 = '0'.repeat(64); },
    e => { e.brokerAttestation.rollbackAttestationDepositEvidenceSha256 = '0'.repeat(64); },
    e => { e.brokerAttestation.requestStartedAt = '2030-01-01T00:09:59.999Z'; },
    e => { e.brokerAttestation.normalizedStatementSha256 = '0'.repeat(64); },
    e => { e.brokerAttestation.signedBrokerStatementSha256 = '0'.repeat(64); },
    e => { const raw = JSON.parse(e.brokerAttestation.signedBrokerEnvelope);
      raw.statement.result.measurements.principal.subject = 'wrong-principal';
      e.brokerAttestation.signedBrokerEnvelope = JSON.stringify(raw); },
    e => { e.deploymentBoundary.manualUiPublishingDenied = false; }
  ]) {
    const altered = structuredClone(result.evidence); mutate(altered);
    assert.throws(() => evidenceModule.validateLiveNetlifyAuthorityBoundary(altered, consumerOptions), /CNYOS_/);
  }
  for (const patch of [{ authorizationSha256: '0'.repeat(64) }, { depositSha256: '0'.repeat(64) },
    { now: new Date('2030-01-01T00:15:00.000Z') },
    { runtime: { ...consumerOptions.runtime, workflowPath: policy.controller.rollbackWorkflowPath } }]) {
    assert.throws(() => evidenceModule.validateLiveNetlifyAuthorityBoundary(result.evidence, { ...consumerOptions, ...patch }), /CNYOS_/);
  }
  const reject = async (options, pattern = /CNYOS_/) => {
    const attempt = await run(options);
    await assert.rejects(attempt.promise, pattern);
    await assert.rejects(fs.stat(attempt.output), { code: 'ENOENT' });
    return attempt;
  };
  const inactive = await reject({ originalModule: true });
  assert.deepEqual(inactive.counts(), { oidcCalls: 0, networkCalls: 0 });
  for (const options of [
    { envPatch: { CNYOS_DISPATCH_NONCE: Buffer.alloc(32, 2).toString('base64url') } },
    { envPatch: { CNYOS_TARGET_CONTROLLER_RUN_ID: '700002' } },
    { envPatch: { CNYOS_CONTROLLER_WORKFLOW_PATH: policy.controller.rollbackWorkflowPath,
      GITHUB_WORKFLOW_REF: `${policy.controller.repository}/${policy.controller.rollbackWorkflowPath}@${policy.controller.protectedRef}` } },
    { changeAuthorization: a => { a.source.repository = 'other/source'; } },
    { changeAuthorization: a => { a.controllerRunId = '700002'; } },
    { changeDeposit: d => { d.schemaVersion = 2; } },
    { changeDeposit: d => { d.controllerWorkflowPath = policy.controller.rollbackWorkflowPath; } },
    { changeDeposit: d => { d.source.repository = 'other/source'; } },
    { changeDeposit: d => { d.source.tree = '0'.repeat(40); } },
    { changeDeposit: d => { d.source.extra = 'not-bound'; } },
    { changeDeposit: d => { d.target.netlifySiteId = policy.productionDenylist.netlifySiteId; } },
    { changeDeposit: d => { d.target.supabaseProjectRef = 'wrong-project'; } },
    { changeDeposit: d => { d.target.targetSha256 = '0'.repeat(64); } },
    { changeDeposit: d => { d.target.previousDeployId = '0'.repeat(24); } },
    { changeDeposit: d => { d.artifact.artifactSha256 = '0'.repeat(64); } }
  ]) {
    const attempt = await reject(options);
    assert.deepEqual(attempt.counts(), { oidcCalls: 0, networkCalls: 0 });
  }
  for (const name of common.OIDC_FORBIDDEN_ENVIRONMENT_NAMES) {
    const attempt = await reject({ envPatch: { [name]: '' } }, /CREDENTIAL_REJECTED/);
    assert.equal(attempt.counts().oidcCalls, 0);
  }
  const wrongEndpoint = await reject({ envPatch: { CNYOS_NETLIFY_AUTHORITY_BROKER_URL: 'https://other.test/v1/observe' } }, /URL_INVALID/);
  assert.equal(wrongEndpoint.counts().oidcCalls, 0);
  await reject({ envPatch: { CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: '0'.repeat(64) } });
  for (const mutate of [
    r => { r.target.controllerRunId = '700002'; },
    r => { r.source.commit = '0'.repeat(40); },
    r => { r.artifactSha256 = '0'.repeat(64); },
    r => { r.authorizationEvidenceSha256 = '0'.repeat(64); },
    r => { r.rollbackAttestationDepositEvidenceSha256 = '0'.repeat(64); },
    r => { r.observedAt = '2030-01-01T00:09:59.999Z'; },
    r => { r.expiresAt = NOW.toISOString(); },
    r => { r.retainedProof.immutable = false; },
    r => { r.retainedProof.retentionUntil = EXPIRES; },
    r => { r.retainedProof.reference = 'https://other.test/evidence/proof'; },
    r => { r.measurements.principal.teamRoles = ['Owner']; },
    r => { r.measurements.principal.accessibleSiteIds.push(policy.productionDenylist.netlifySiteId); },
    r => { r.measurements.permissions[0].decision = 'allow'; },
    r => { r.measurements.permissions[1] = structuredClone(r.measurements.permissions[0]); },
    r => { r.measurements.projects[0].gitPublishingEnabled = true; },
    r => { r.measurements.projects[0].buildHookCount = 1; },
    r => { r.measurements.projects[0].manualPublishingAllowed = true; },
    r => { r.measurements.publisherInventory.complete = false; },
    r => { r.measurements.enforcement.rules.pop(); },
    r => { r.measurements.enforcement.rules[1] = structuredClone(r.measurements.enforcement.rules[0]); }
  ]) await reject({ changeResult: mutate });
  await reject({ changeEnvelope: e => { e.statement.requestSha256 = '0'.repeat(64); } });
  await reject({ changeEnvelope: e => { e.brokerSignature.signatureBase64 = Buffer.alloc(64).toString('base64'); } });
  await reject({ changeEnvelope: e => { delete e.brokerSignature; } });
  await reject({ changeEnvelope: e => { e.extra = TOKEN; } }, /TOKEN_REFLECTION/);
  await reject({ changeResponse: response => { Object.defineProperty(response, 'url', { value: 'https://other.test' }); return response; } });
  const existing = await run({ envPatch: { CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH: positive.output } });
  await assert.rejects(existing.promise, /OUTPUT_EXISTS/);
  assert.equal(existing.counts().oidcCalls, 0);
  assert.deepEqual(JSON.parse(await fs.readFile(positive.output, 'utf8')), result.evidence);
  process.stdout.write('CNYOS activation contract live-netlify-authority-boundary: passed\n');
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
