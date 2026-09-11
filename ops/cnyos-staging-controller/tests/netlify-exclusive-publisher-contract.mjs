import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

assert.notEqual(process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE, 'true');
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error('OFFLINE_CONTRACT_NETWORK_FORBIDDEN'); };
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-publisher-contract-')));
const copy = path.join(scratch, 'controller');
const clone = value => structuredClone(value);
try {
  await fs.mkdir(copy);
  await fs.cp(path.join(root, 'scripts'), path.join(copy, 'scripts'), { recursive: true });
  const pair = crypto.generateKeyPairSync('ed25519');
  const policy = JSON.parse(await fs.readFile(path.join(root, 'controller-policy.json'), 'utf8'));
  policy.externalReconciliationBroker = { ...policy.externalReconciliationBroker,
    origin: 'https://publisher.test', operationPath: '/v1/reconcile', policyId: 'fixture-publisher-policy-0001',
    policySha256: '1'.repeat(64), signingKeyId: 'fixture-publisher-key-0001',
    signingPublicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    signingKeySpkiSha256: crypto.createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'),
    oidcAudience: 'https://publisher.test/oidc' };
  await fs.writeFile(path.join(copy, 'controller-policy.json'), `${JSON.stringify(policy, null, 2)}\n`, { flag: 'wx' });
  const importCopy = name => import(pathToFileURL(path.join(copy, 'scripts', name)).href);
  const p = await importCopy('verify-netlify-exclusive-publisher.mjs');
  const release = await importCopy('release-netlify-exclusive-publisher.mjs');
  const broker = await importCopy('reconcile-netlify-release-state.mjs');
  const { POLICY, sha256 } = await importCopy('policy.mjs');
  const finalizer = await importCopy('finalize-evidence.mjs');
  const trust = broker.brokerTrustRoot('reconciliation');
  const env = {
    GITHUB_REPOSITORY: POLICY.controller.repository, CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: '8123456', GITHUB_RUN_ATTEMPT: '1', GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: POLICY.controller.protectedRef, CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: 'a'.repeat(40), CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
    GITHUB_WORKFLOW_REF: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
    GITHUB_ACTOR: 'fixture-owner', GITHUB_TRIGGERING_ACTOR: 'fixture-owner'
  };
  const runtime = p.publisherRuntime(env);
  const observedAt = new Date('2032-01-01T00:05:00.000Z');
  const acquiredAt = '2032-01-01T00:04:30.000Z';
  const target = p.publisherTarget(runtime, Buffer.alloc(32, 23).toString('base64url'));
  const evidence = {
    schemaVersion: 1, source: { repository: POLICY.sourceRepository, commit: 'b'.repeat(40), tree: 'c'.repeat(40) },
    artifact: { artifactSha256: '2'.repeat(64) }, draftDeployId: 'd'.repeat(24), previousPublishedDeployId: 'e'.repeat(24),
    inputEvidenceSha256: Object.fromEntries(['preflight', 'rollbackReadiness', 'draftGate', 'draftVerification', 'draftMetadata',
      'controlBehavior', 'privateDraft', 'authorization', 'githubPrecredential', 'githubPrepromotion'].map(key => [key, sha256(key)])),
    minimumLeaseMinutes: 45, expectedLeaseActive: false, expectedRunBarrierActive: false,
    atomicLeaseAndBarrierRequired: true, productionAuthorization: false
  };
  const leaseId = 'fixture-lease-generation-0001';
  const acquired = {
    schemaVersion: 1, status: 'acquired', target: { ...target, barrierGeneration: leaseId },
    requestEvidenceSha256: sha256(JSON.stringify(evidence)), lockLeaseId: leaseId,
    acquiredAt, expiresAt: '2032-01-01T01:00:00.000Z',
    transition: { atomicCompareAndSwap: true, leaseActiveBefore: false, runBarrierActiveBefore: false,
      leaseActiveAfter: true, runBarrierActiveAfter: true, automaticBarrierExpiryPermitted: false,
      newMutationBlockedWhileRunBarrierActive: true, renewalSupported: true, releaseRequired: true },
    publisherExclusion: { netlifyGitPublishingDisabled: true, buildHooksDisabled: true, manualUiPublishingDenied: true,
      alternatePublishersDenied: true, inventoryComplete: true, evidenceSha256: '3'.repeat(64) }
  };
  const signature = statement => {
    const bytes = Buffer.from(JSON.stringify(statement));
    const signed = crypto.sign(null, bytes, pair.privateKey);
    return { algorithm: 'Ed25519', keyId: trust.signingKeyId, statementSha256: sha256(bytes),
      signatureBase64: signed.toString('base64'), signatureSha256: sha256(signed) };
  };
  function signedEnvelope(request, result) {
    const statement = { schemaVersion: 1, operationDomain: trust.operationDomain, operation: request.operation,
      policyId: trust.policyId, policySha256: trust.policySha256, requestSha256: sha256(JSON.stringify(request)),
      issuedAt: '2032-01-01T00:04:00.000Z', expiresAt: '2032-01-01T00:10:00.000Z', result };
    return { schemaVersion: 1, evidenceType: 'cnyos_staging_reconciliation_broker_envelope',
      statement, brokerSignature: signature(statement) };
  }
  const oidc = 'fixture_oidc_canary_never_serialized';
  function response(raw, url, { status = 200, redirected = false, headers = {} } = {}) {
    const value = new Response(raw, { status, headers: { 'content-type': 'application/json', ...headers } });
    Object.defineProperties(value, { url: { value: String(url) }, redirected: { value: redirected } });
    return value;
  }
  let calls = 0;
  const acquireRequest = p.publisherRequest(p.PUBLISHER_OPERATIONS.acquire, trust, p.publisherResumer(runtime), target, evidence);
  const options = { env: {}, trust, configuredUrl: `${trust.origin}${trust.operationPath}`,
    operation: p.PUBLISHER_OPERATIONS.acquire, resumer: p.publisherResumer(runtime), target, evidence,
    now: () => observedAt, oidcTokenProvider: async () => oidc };
  const goodFetch = async (url, init) => {
    calls++;
    assert.equal(String(url), 'https://publisher.test/v1/reconcile');
    assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    assert.equal(init.headers.Authorization, `Bearer ${oidc}`);
    assert.equal(init.body.includes(oidc), false);
    assert.deepEqual(JSON.parse(init.body), acquireRequest);
    return response(JSON.stringify(signedEnvelope(acquireRequest, acquired)), url);
  };
  const acquiredResponse = await broker.callSignedBrokerOperation({ ...options, fetchImpl: goodFetch });
  const lease = p.publisherLeaseFromResponse(acquiredResponse, acquireRequest, runtime);
  assert.equal(calls, 1);
  assert.equal(lease.lockLeaseId, leaseId);
  assert.equal(lease.runReconciliationBarrierGeneration, leaseId);
  assert.equal(lease.productionAuthorization, false);
  assert.equal(JSON.stringify(lease).includes(oidc), false);
  assert.deepEqual(p.validateRetainedPublisherLease(lease, runtime, new Date('2032-01-01T00:25:00.000Z')), lease,
    'historical acquisition signature remains verifiable after its response window, while the lease is active');
  for (const mutate of [
    value => { value.transition.atomicCompareAndSwap = false; },
    value => { value.transition.leaseActiveBefore = true; },
    value => { value.transition.runBarrierActiveBefore = true; },
    value => { value.transition.automaticBarrierExpiryPermitted = true; },
    value => { value.transition.runBarrierActiveAfter = false; },
    value => { value.transition.newMutationBlockedWhileRunBarrierActive = false; },
    value => { value.publisherExclusion.manualUiPublishingDenied = false; },
    value => { value.publisherExclusion.alternatePublishersDenied = false; },
    value => { value.publisherExclusion.inventoryComplete = false; },
    value => { value.target.netlifySiteId = POLICY.productionDenylist.netlifySiteId; },
    value => { value.target.controllerRunId = '991'; },
    value => { value.target.barrierGeneration = 'wrong-generation-0001'; },
    value => { value.requestEvidenceSha256 = '0'.repeat(64); },
    value => { value.expiresAt = '2032-01-01T00:20:00.000Z'; },
    value => { value.acquiredAt = '2032-01-01T00:06:00.000Z'; },
    value => { value.extra = true; }
  ]) {
    const invalid = clone(acquired); mutate(invalid);
    assert.throws(() => p.validatePublisherAcquisitionResult(invalid, { target, evidence, observedAt, trust }), /CNYOS_/);
  }
  for (const mutate of [
    value => { value.lockLeaseId = 'altered-lease-generation'; },
    value => { value.brokerRequest.evidence.draftDeployId = 'f'.repeat(24); },
    value => { value.brokerEnvelope.statement.result.transition.leaseActiveAfter = false; },
    value => { value.brokerEnvelope.brokerSignature.signatureBase64 = Buffer.alloc(64).toString('base64'); },
    value => { value.brokerEnvelope.statement.operation = p.PUBLISHER_OPERATIONS.release; },
    value => { value.extra = true; }
  ]) {
    const invalid = clone(lease); mutate(invalid);
    assert.throws(() => p.validateRetainedPublisherLease(invalid, runtime, observedAt), /CNYOS_/);
  }
  assert.throws(() => p.validateRetainedPublisherLease(lease, runtime, new Date('2032-01-01T01:00:00.000Z')), /CNYOS_/);
  for (const name of broker.OIDC_FORBIDDEN_ENVIRONMENT_NAMES) {
    assert.throws(() => p.publisherOidcEnvironment({ [name]: '' }), /CREDENTIAL_CORESIDENCY/);
    await assert.rejects(p.verifyNetlifyExclusivePublisher({ env: { ...env, [name]: '' } }), /CREDENTIAL_CORESIDENCY/);
    await assert.rejects(release.releaseNetlifyExclusivePublisher({ env: { ...env, [name]: '' } }), /CREDENTIAL_CORESIDENCY/);
  }
  const signed = JSON.stringify(signedEnvelope(acquireRequest, acquired));
  for (const fetchImpl of [
    async url => response(signed, url, { redirected: true }),
    async url => response(signed, 'https://other.test/v1/reconcile'),
    async url => response(signed, url, { status: 403 }),
    async url => response(signed, url, { headers: { 'content-type': 'text/html' } }),
    async url => response('x'.repeat(trust.maximumResponseBytes + 1), url),
    async url => response(`${signed}\n`, url),
    async url => response(signed, url, { headers: { 'x-canary': oidc } }),
    async url => response(JSON.stringify({ canary: oidc }), url),
    async () => { throw new Error(oidc); }
  ]) {
    await assert.rejects(broker.callSignedBrokerOperation({ ...options, fetchImpl }), error =>
      /^CNYOS_[A-Z0-9_]+$/.test(error.message) && !error.message.includes(oidc));
  }
  let forbiddenCalls = 0;
  await assert.rejects(broker.callSignedBrokerOperation({ ...options, configuredUrl: 'https://other.test/v1/reconcile',
    fetchImpl: async () => { forbiddenCalls++; } }), /CNYOS_/);
  assert.equal(forbiddenCalls, 0);
  const releaseEvidence = {
    schemaVersion: 1, netlifyDeployId: evidence.draftDeployId, source: evidence.source, artifact: evidence.artifact,
    originalExclusivePublisherEvidenceSha256: sha256(JSON.stringify(lease)), publishAttemptEvidenceSha256: '4'.repeat(64),
    promotionEvidenceSha256: '5'.repeat(64), finalCurrentEvidenceSha256: '6'.repeat(64), uatEvidenceSha256: '7'.repeat(64),
    finalCurrentVerifiedAt: '2032-01-01T00:04:20.000Z', uatCompletedAt: '2032-01-01T00:04:10.000Z',
    expectedLeaseActive: true, expectedRunBarrierActive: true, retainRunBarrier: true,
    expectedCurrentPublishedDeployId: evidence.draftDeployId, atomicReleaseReceiptRequired: true
  };
  const releaseTarget = { ...target, barrierGeneration: leaseId };
  const releaseRequest = p.publisherRequest(p.PUBLISHER_OPERATIONS.release, trust, p.publisherResumer(runtime), releaseTarget, releaseEvidence);
  const released = { schemaVersion: 1, status: 'released', target: releaseTarget,
    requestEvidenceSha256: sha256(JSON.stringify(releaseEvidence)), releasedAt: acquiredAt,
    currentPublishedDeployIdBeforeRelease: evidence.draftDeployId,
    currentPublishedDeployIdAfterRelease: evidence.draftDeployId,
    transition: { atomicCompareAndSwap: true, leaseActiveBefore: true, runBarrierActiveBefore: true,
      leaseActiveAfter: false, runBarrierActiveAfter: true, immutableReleaseReceiptStored: true,
      automaticBarrierExpiryPermitted: false, draftIntentsTerminalBeforeBarrierClearRequired: true } };
  const releaseResponse = await broker.callSignedBrokerOperation({ ...options, operation: p.PUBLISHER_OPERATIONS.release,
    target: releaseTarget, evidence: releaseEvidence, fetchImpl: async (url, init) => {
      assert.deepEqual(JSON.parse(init.body), releaseRequest);
      return response(JSON.stringify(signedEnvelope(releaseRequest, released)), url);
    } });
  const receipt = release.publisherReleaseReceiptFromResponse(releaseResponse, { runtime, target: releaseTarget, evidence: releaseEvidence });
  finalizer.validateExclusivePublisherReleaseEvidence(receipt, { runtime, commit: evidence.source.commit,
    tree: evidence.source.tree, deployId: evidence.draftDeployId, exclusivePublisher: lease,
    exclusivePublisherSha256: releaseEvidence.originalExclusivePublisherEvidenceSha256, observedAt,
    uatCompletedAt: new Date(releaseEvidence.uatCompletedAt), finalCurrentVerifiedAt: new Date(releaseEvidence.finalCurrentVerifiedAt) });
  assert.equal(receipt.runReconciliationBarrierActiveAfterRelease, true);
  for (const mutate of [
    value => { value.transition.atomicCompareAndSwap = false; },
    value => { value.transition.runBarrierActiveAfter = false; },
    value => { value.transition.immutableReleaseReceiptStored = false; },
    value => { value.transition.leaseActiveAfter = true; },
    value => { value.transition.draftIntentsTerminalBeforeBarrierClearRequired = false; },
    value => { value.currentPublishedDeployIdAfterRelease = evidence.previousPublishedDeployId; },
    value => { value.target.barrierGeneration = 'different-generation'; },
    value => { value.requestEvidenceSha256 = '0'.repeat(64); },
    value => { value.releasedAt = releaseEvidence.uatCompletedAt; },
    value => { value.releasedAt = releaseEvidence.finalCurrentVerifiedAt; },
    value => { value.releasedAt = '2032-01-01T00:06:00.000Z'; },
    value => { value.productionAuthorization = true; }
  ]) {
    const invalid = clone(released); mutate(invalid);
    assert.throws(() => release.validatePublisherReleaseResult(invalid,
      { target: releaseTarget, evidence: releaseEvidence, trust, observedAt }), /CNYOS_/);
  }
  const filename = path.join(scratch, 'input.json');
  await fs.writeFile(filename, '{}', { flag: 'wx' });
  await assert.rejects(p.publisherOutputAvailable(filename), /OUTPUT_EXISTS/);
  const output = path.join(scratch, 'lease.json');
  await p.publisherOutputAvailable(output, [{ filename, bytes: Buffer.from('{}') }]);
  const inputs = [{ filename, bytes: Buffer.from('{}') }];
  await p.publisherInputsUnchanged(inputs);
  await fs.writeFile(filename, '{"changed":true}');
  await assert.rejects(p.publisherInputsUnchanged(inputs), /INPUT_CHANGED/);
  await fs.symlink(filename, path.join(scratch, 'linked.json'));
  await assert.rejects(p.publisherEvidence({ CNYOS_CONTROLLER_TEST_EVIDENCE_PATH: path.join(scratch, 'linked.json'),
    CNYOS_EXPECTED_TEST_EVIDENCE_SHA256: sha256('{"changed":true}') }, 'TEST'), /CNYOS_/);
  const actual = await import(pathToFileURL(path.join(root, 'scripts', 'verify-netlify-exclusive-publisher.mjs')).href);
  await assert.rejects(actual.verifyNetlifyExclusivePublisher({ env, fetchImpl: async () => { forbiddenCalls++; } }), /CNYOS_/);
  assert.equal(forbiddenCalls, 0, 'unreviewed real policy fails before I/O authority use');
  process.stdout.write('CNYOS activation contract netlify-exclusive-publisher: passed\n');
} finally {
  globalThis.fetch = originalFetch;
  await fs.rm(scratch, { recursive: true, force: true });
}
