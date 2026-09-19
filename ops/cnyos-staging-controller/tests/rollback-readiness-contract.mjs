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
const scratch = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-readiness-contract-')));
const copy = path.join(scratch, 'controller');
const clone = value => structuredClone(value);
try {
  await fs.mkdir(copy);
  await fs.cp(path.join(root, 'scripts'), path.join(copy, 'scripts'), { recursive: true });
  const policy = JSON.parse(await fs.readFile(path.join(root, 'controller-policy.json'), 'utf8'));
  const pairs = Object.fromEntries(['rollback', 'membership', 'reconciliation'].map(kind => [kind, crypto.generateKeyPairSync('ed25519')]));
  const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  for (const [kind, field] of [['membership', 'rollbackPrincipalMembershipBroker'], ['reconciliation', 'externalReconciliationBroker']]) {
    const pair = pairs[kind];
    policy[field] = { ...policy[field], origin: `https://${kind}.test`, operationPath: '/v1/operation',
      policyId: `fixture-${kind}-policy-0001`, policySha256: digest(kind), signingKeyId: `fixture-${kind}-key-0001`,
      signingPublicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
      signingKeySpkiSha256: digest(pair.publicKey.export({ type: 'spki', format: 'der' })),
      oidcAudience: `https://${kind}.test/oidc` };
  }
  const pair = pairs.rollback;
  policy.rollbackAttestationBroker = { ...policy.rollbackAttestationBroker,
    origin: 'https://rollback.test', policyId: 'fixture-rollback-policy-0001', policySha256: digest('rollback'),
    receiptSigningKeyId: 'fixture-rollback-key-0001',
    receiptSigningPublicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    receiptSigningSpkiSha256: digest(pair.publicKey.export({ type: 'spki', format: 'der' })),
    oidcAudience: 'https://rollback.test/oidc' };
  await fs.writeFile(path.join(copy, 'controller-policy.json'), `${JSON.stringify(policy, null, 2)}\n`, { flag: 'wx' });
  const importCopy = name => import(pathToFileURL(path.join(copy, 'scripts', name)).href);
  const readiness = await importCopy('rollback-readiness.mjs');
  const publisher = await importCopy('verify-netlify-exclusive-publisher.mjs');
  const broker = await importCopy('reconcile-netlify-release-state.mjs');
  const { POLICY, POLICY_SHA256, sha256 } = await importCopy('policy.mjs');
  const netlify = await importCopy('netlify-evidence.mjs');
  const observedAt = new Date('2032-01-01T00:05:00.000Z');
  const now = () => new Date(observedAt);
  const nonce = Buffer.alloc(32, 29).toString('base64url');
  const source = { repository: POLICY.sourceRepository, commit: 'a'.repeat(40), tree: 'b'.repeat(40), functionSourceTree: 'c'.repeat(40) };
  const artifact = Object.fromEntries(['producerManifestSha256', 'artifactSha256', 'candidateBuildArtifactDigest',
    'staticReproducibilityEvidenceSha256', 'staticArtifactSha256', 'candidateDependencyLockSha256',
    'stagingConfigSha256', 'productionDenylistConfigSha256', 'functionBundleManifestSha256',
    'functionBundleDependencyLockSha256', 'functionSourcesSha256', 'githubArtifactDigest'].map(key => [key, sha256(key)]));
  artifact.fileCount = 3; artifact.producerRunId = '74423';
  const previous = '1'.repeat(24);
  const baseEnv = {
    GITHUB_REPOSITORY: POLICY.controller.repository, CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ID: '8123457', GITHUB_RUN_ATTEMPT: '1', GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: POLICY.controller.protectedRef, CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    GITHUB_SHA: 'd'.repeat(40), CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
    GITHUB_WORKFLOW_REF: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
    GITHUB_ACTOR: 'fixture-owner', GITHUB_TRIGGERING_ACTOR: 'fixture-owner',
    CNYOS_CANDIDATE_SHA: source.commit, CNYOS_DISPATCH_NONCE: nonce
  };
  const runtime = publisher.publisherRuntime(baseEnv);
  const target = publisher.publisherTarget(runtime, nonce);
  const rollbackTrust = broker.brokerTrustRoot('rollback');
  const membershipTrust = broker.brokerTrustRoot('membership');
  const sign = (statement, kind) => {
    const trust = broker.brokerTrustRoot(kind);
    const signed = crypto.sign(null, Buffer.from(JSON.stringify(statement)), pairs[kind].privateKey);
    return { algorithm: 'Ed25519', keyId: trust.signingKeyId, statementSha256: sha256(JSON.stringify(statement)),
      signatureBase64: signed.toString('base64'), signatureSha256: sha256(signed) };
  };
  const authorizationMaterial = Object.fromEntries(['authorizationPacketSha256', 'authorizationBundleSha256',
    'approverRegistrySha256', 'independentSecurityReviewerSignatureSha256',
    'managedPlatformRiskOwnerSignatureSha256', 'knownGoodEvidenceSha256'].map(key => [key, sha256(key)]));
  authorizationMaterial.independentSecurityReviewerKeyId = 'fixture-reviewer-key-0001';
  authorizationMaterial.managedPlatformRiskOwnerKeyId = 'fixture-risk-key-0001';
  const receipt = {
    schemaVersion: 1, evidenceType: 'cnyos_staging_rollback_attestation_deposit_receipt', status: 'sealed',
    scope: 'cnyos_staging_only', productionAuthorization: false, realPatientDataAuthorized: false,
    depositId: 'fixture-rollback-deposit-0001', depositSequence: 1, depositRequestSha256: sha256('deposit-request'),
    broker: { origin: rollbackTrust.origin, policyId: rollbackTrust.policyId, policySha256: rollbackTrust.policySha256,
      receiptSigningKeyId: rollbackTrust.signingKeyId, receiptSigningSpkiSha256: rollbackTrust.signingKeySpkiSha256 },
    controller: { repository: runtime.repository, ref: runtime.ref, commit: runtime.commit,
      workflowPath: runtime.workflowPath, workflowRef: runtime.workflowRef, runId: runtime.runId,
      runAttempt: 1, dispatchNonce: nonce, policySha256: POLICY_SHA256 },
    source, artifact, target: { netlifySiteId: POLICY.target.netlifySiteId, netlifyOrigin: POLICY.target.netlifyOrigin,
      supabaseProjectRef: POLICY.target.supabaseProjectRef, databaseSystemIdentifier: POLICY.target.databaseSystemIdentifier,
      targetSha256: sha256(JSON.stringify(POLICY.target)), previousDeployId: previous }, authorizationMaterial,
    depositSemantics: { appendOnly: true, immutable: true, oneDepositPerRunNonce: true, conflictingOverwriteRejected: true,
      identicalReplayReturnsOriginalReceipt: true, rawPayloadArtifactExposure: false },
    recoveryMaterial: Object.fromEntries(['canonicalAuthorizationJsonStored', 'independentSecurityReviewerSignatureStored',
      'managedPlatformRiskOwnerSignatureStored', 'knownGoodEvidenceBytesStored', 'authorizationVerificationBundleBytesStored',
      'approverRegistryBytesStored', 'encryptedAtRest', 'hashVerifiedBeforeSeal', 'retrievableForRecovery'].map(key => [key, true])),
    retrievalBoundary: { oidcAudience: rollbackTrust.oidcAudience, requiredControllerRepository: runtime.repository,
      requiredControllerRef: runtime.ref, requiredControllerWorkflowPath: runtime.workflowPath, requiredControllerRunId: runtime.runId,
      requiredControllerRunAttempt: 1, requiredDispatchNonce: nonce,
      externalReconciliationPolicyId: POLICY.externalReconciliationBroker.policyId,
      externalReconciliationPolicySha256: POLICY.externalReconciliationBroker.policySha256,
      failedRunCodeCannotDelete: true, watchdogRevisionCannotDelete: true, exactRunAndNonceRequired: true,
      oidcControllerIdentityRequired: true },
    depositedAt: '2032-01-01T00:00:00.000Z', retentionUntil: '2033-01-02T00:00:00.000Z'
  };
  const depositEnvelope = { schemaVersion: 1, evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
    receipt, brokerSignature: sign(receipt, 'rollback') };
  const depositRaw = JSON.stringify(depositEnvelope);
  const depositPath = path.join(scratch, 'deposit.json');
  await fs.writeFile(depositPath, depositRaw, { flag: 'wx', mode: 0o600 });
  baseEnv.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH = depositPath;
  baseEnv.CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256 = sha256(depositRaw);
  async function evidenceFile(env, suffix, value, filename = `${suffix.toLowerCase()}.json`) {
    const bytes = `${JSON.stringify(value, null, 2)}\n`;
    const file = path.join(scratch, filename);
    await fs.writeFile(file, bytes, { mode: 0o600 });
    env[`CNYOS_CONTROLLER_${suffix}_EVIDENCE_PATH`] = file;
    env[`CNYOS_EXPECTED_${suffix}_EVIDENCE_SHA256`] = sha256(bytes);
    return { file, bytes, sha256: sha256(bytes) };
  }
  const validation = {
    schemaVersion: 1, evidenceType: 'cnyos_staging_rollback_attestation_deposit_validation', status: 'passed',
    scope: 'cnyos_staging_only', productionAuthorization: false, realPatientDataAuthorized: false,
    secretValuesSerialized: false, verifiedAt: '2032-01-01T00:01:00.000Z',
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerWorkflowPath: runtime.workflowPath, controllerRunId: runtime.runId, controllerRunAttempt: 1,
    dispatchNonce: nonce, policySha256: POLICY_SHA256, source, artifact, target: receipt.target,
    previousDeployId: previous, ...Object.fromEntries(Object.entries(authorizationMaterial).filter(([key]) => key.endsWith('Sha256'))),
    depositId: receipt.depositId, depositRequestSha256: receipt.depositRequestSha256,
    depositReceiptSha256: sha256(depositRaw), depositedAt: receipt.depositedAt, retentionUntil: receipt.retentionUntil,
    brokerOrigin: rollbackTrust.origin, brokerPolicyId: rollbackTrust.policyId, brokerPolicySha256: rollbackTrust.policySha256,
    brokerReceiptSigningKeyId: rollbackTrust.signingKeyId, brokerReceiptSigningSpkiSha256: rollbackTrust.signingKeySpkiSha256,
    brokerStatementSha256: depositEnvelope.brokerSignature.statementSha256,
    brokerSignatureSha256: depositEnvelope.brokerSignature.signatureSha256,
    immutableAppendOnlyDepositVerified: true, exactRunNonceRetrievalBoundaryVerified: true,
    completeRecoveryMaterialStoredVerified: true, rawPayloadArtifactExposure: false
  };
  const validationFile = await evidenceFile(baseEnv, 'ROLLBACK_ATTESTATION_DEPOSIT', validation);
  const boundary = { subject: 'fixture-rollback-principal', membershipRole: 'Publisher', teamOwner: false,
    teamAdministrator: false, siteAccessScope: 'single_site', accountConfigurationCapabilityAbsent: true,
    teamAdministrationCapabilityAbsent: true, deployCapabilityVerified: true, restoreCapabilityVerified: true,
    verifiedAt: '2032-01-01T00:00:00.000Z', expiresAt: '2032-01-01T00:25:00.000Z', membershipEvidenceSha256: sha256('membership-prior') };
  const preflight = {
    schemaVersion: 1, evidenceType: 'cnyos_staging_controller_preflight', authorization: false,
    scope: 'cnyos_staging_only', productionAuthorization: false,
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit, controllerRunId: runtime.runId,
    dispatchNonce: nonce, source, artifact, target: POLICY.target, previousPublishedDeploy: { id: previous },
    preReleaseReconciliationEvidenceSha256: sha256('reconciliation'), liveGitHubPrecredentialBoundaryEvidenceSha256: sha256('github'),
    runtimeProofEnvelopeSha256: sha256('runtime-proof-envelope'),
    authorizationExpiresAt: boundary.expiresAt, principalProofExpiresAt: boundary.expiresAt,
    liveNetlifyAuthorityBoundaryExpiresAt: boundary.expiresAt, deploymentControlBoundaryExpiresAt: boundary.expiresAt,
    rollbackAttestationDepositEvidenceSha256: validationFile.sha256,
    rollbackAttestationDepositReceiptSha256: sha256(depositRaw), rollbackAttestationDepositId: receipt.depositId,
    rollbackAttestationRetentionUntil: receipt.retentionUntil, knownGoodRollbackEvidenceSha256: authorizationMaterial.knownGoodEvidenceSha256,
    netlifyPrincipalBoundary: { subject: 'fixture-publisher-principal' }, rollbackNetlifyPrincipalSubject: boundary.subject,
    rollbackNetlifyPrincipalBoundary: boundary, targetSiteAndPublisherExclusion: {
      productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId, productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin }
  };
  const preflightFile = await evidenceFile(baseEnv, 'PREFLIGHT', preflight);
  const context = await readiness.loadReadinessInputs(baseEnv, runtime, observedAt);
  assert.equal(context.deposit.sha256, sha256(depositRaw));
  let brokerCalls = 0;
  const oidc = 'fixture_oidc_canary_not_in_any_receipt';
  const rollbackToken = 'fixture_rollback_canary_only_in_netlify_headers';
  function response(value, url, { raw = false, status = 200, headers = {}, redirected = false } = {}) {
    const result = new Response(raw ? value : JSON.stringify(value), { status,
      headers: { 'content-type': 'application/json', ...headers } });
    Object.defineProperties(result, { url: { value: String(url) }, redirected: { value: redirected } });
    return result;
  }
  function resultFor(request) {
    const e = request.evidence;
    if (request.operation === readiness.ROLLBACK_READINESS_OPERATIONS.availability) return {
      schemaVersion: 1, status: 'available', target: request.target, requestEvidenceSha256: sha256(JSON.stringify(e)),
      depositId: e.depositId, depositReceiptSha256: e.depositReceiptSha256, authorizationMaterial: e.authorizationMaterial,
      previousPublishedDeployId: e.previousPublishedDeployId, verifiedAt: '2032-01-01T00:04:10.000Z',
      expiresAt: '2032-01-01T00:10:00.000Z', recoveryMaterialAvailable: true, hashesReverified: true,
      exactRunNonceRetrievalEnforced: true, rawPayloadDisclosed: false, recoveryEvidenceSha256: sha256('recovery-retrieval-proof')
    };
    assert.equal(request.operation, readiness.ROLLBACK_READINESS_OPERATIONS.membership);
    return { schemaVersion: 1, status: 'verified', target: request.target, requestEvidenceSha256: sha256(JSON.stringify(e)),
      principalSubject: e.recoveryPrincipalSubject, publisherPrincipalSubject: e.publisherPrincipalSubject,
      membershipRole: 'Publisher', membershipEvidenceSha256: e.priorMembershipEvidenceSha256,
      currentMembershipEvidenceSha256: sha256('current-membership'), verifiedAt: '2032-01-01T00:04:30.000Z',
      expiresAt: '2032-01-01T00:10:00.000Z', teamOwner: false, teamAdministrator: false,
      siteAccessScope: 'single_site', accountConfigurationCapabilityAbsent: true, teamAdministrationCapabilityAbsent: true,
      deployCapabilityVerified: true, restoreCapabilityVerified: true, inventoryComplete: true,
      accessibleSiteIds: [POLICY.target.netlifySiteId], productionAccess: false };
  }
  function envelopeFor(request, result) {
    const kind = request.operation === readiness.ROLLBACK_READINESS_OPERATIONS.availability ? 'rollback' : 'membership';
    const trust = broker.brokerTrustRoot(kind);
    const statement = { schemaVersion: 1, operationDomain: trust.operationDomain, operation: request.operation,
      policyId: trust.policyId, policySha256: trust.policySha256, requestSha256: sha256(JSON.stringify(request)),
      issuedAt: '2032-01-01T00:04:00.000Z', expiresAt: '2032-01-01T00:10:00.000Z', result };
    return { schemaVersion: 1, evidenceType: 'cnyos_staging_reconciliation_broker_envelope', statement, brokerSignature: sign(statement, kind) };
  }
  const brokerFetch = async (url, init) => {
    brokerCalls++;
    const request = JSON.parse(init.body);
    assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    assert.equal(init.headers.Authorization, `Bearer ${oidc}`);
    assert.equal(init.body.includes(oidc), false); assert.equal(init.body.includes(rollbackToken), false);
    assert.equal(request.controllerPolicySha256, POLICY_SHA256); assert.deepEqual(request.target, target);
    const expected = request.operation === readiness.ROLLBACK_READINESS_OPERATIONS.availability ?
      'https://rollback.test/' : 'https://membership.test/v1/operation';
    assert.equal(String(url), expected);
    return response(envelopeFor(request, resultFor(request)), url);
  };
  const prepareEnv = { ...baseEnv, CNYOS_ROLLBACK_ATTESTATION_BROKER_URL: 'https://rollback.test/',
    CNYOS_NETLIFY_PRINCIPAL_MEMBERSHIP_BROKER_URL: 'https://membership.test/v1/operation',
    CNYOS_CONTROLLER_ROLLBACK_READINESS_BROKER_EVIDENCE_PATH: path.join(scratch, 'prepared.json') };
  const prepared = await readiness.prepareRollbackReadinessBrokerEvidence({ env: prepareEnv, now,
    fetchImpl: brokerFetch, oidcTokenProvider: async () => oidc });
  assert.equal(brokerCalls, 2);
  assert.equal(prepared.evidence.secretValuesSerialized, false);
  const preparedRaw = await fs.readFile(prepared.evidencePath, 'utf8');
  for (const secret of [oidc, rollbackToken, 'authorizationJsonBase64', 'authorizationBundleBase64']) assert.equal(preparedRaw.includes(secret), false);
  const tokenEnv = { ...baseEnv, CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: rollbackToken,
    CNYOS_CONTROLLER_ROLLBACK_READINESS_BROKER_EVIDENCE_PATH: prepared.evidencePath,
    CNYOS_EXPECTED_ROLLBACK_READINESS_BROKER_EVIDENCE_SHA256: sha256(preparedRaw),
    CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH: path.join(scratch, 'readiness.json') };
  let tokenCalls = 0;
  const tokenFetch = async (url, init) => {
    tokenCalls++;
    assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    assert.equal(init.headers.Authorization, `Bearer ${rollbackToken}`); assert.equal(init.body, undefined);
    assert.ok(String(url).startsWith('https://api.netlify.com/api/v1/'));
    if (String(url).endsWith('/user')) return response({ id: boundary.subject }, url);
    assert.equal(String(url), 'https://api.netlify.com/api/v1/sites?per_page=100&page=1');
    return response([{ id: POLICY.target.netlifySiteId, name: POLICY.target.netlifySiteName,
      ssl_url: POLICY.target.netlifyOrigin, published_deploy: { id: previous } }], url);
  };
  const verified = await readiness.verifyRollbackReadinessToken({ env: tokenEnv, fetchImpl: tokenFetch, now });
  assert.equal(tokenCalls, 3); assert.equal(verified.evidence.restoreCapabilityVerified, true);
  netlify.validateRollbackReadinessEvidence(verified.evidence, { runtime, preflight,
    preflightSha256: preflightFile.sha256, observedAt });
  assert.equal(verified.evidence.expiresAt, '2032-01-01T00:10:00.000Z');
  assert.equal((await fs.readFile(verified.evidencePath, 'utf8')).includes(rollbackToken), false);
  const beforeCollision = brokerCalls;
  await assert.rejects(readiness.prepareRollbackReadinessBrokerEvidence({ env: prepareEnv, now,
    fetchImpl: brokerFetch, oidcTokenProvider: async () => oidc }), /OUTPUT_EXISTS/);
  assert.equal(brokerCalls, beforeCollision, 'existing output cannot cause a new broker operation');
  await assert.rejects(readiness.verifyRollbackReadinessToken({ env: tokenEnv, fetchImpl: tokenFetch, now }), /OUTPUT_EXISTS/);
  assert.equal(tokenCalls, 3);
  for (const name of broker.OIDC_FORBIDDEN_ENVIRONMENT_NAMES) {
    await assert.rejects(readiness.prepareRollbackReadinessBrokerEvidence({ env: { ...prepareEnv, [name]: '' }, now,
      fetchImpl: brokerFetch }), /CREDENTIAL_CORESIDENCY/);
  }
  for (const name of broker.EXECUTION_FORBIDDEN_ENVIRONMENT_NAMES) {
    await assert.rejects(readiness.verifyRollbackReadinessToken({ env: { ...tokenEnv, [name]: '' }, now,
      fetchImpl: tokenFetch }), /CREDENTIAL_CORESIDENCY/);
  }
  assert.equal(brokerCalls, 2); assert.equal(tokenCalls, 3);
  let counter = 0;
  for (const mutate of [
    value => { value.availabilityEnvelope.statement.result.recoveryMaterialAvailable = false; },
    value => { value.membershipEnvelope.statement.result.restoreCapabilityVerified = false; },
    value => { value.membershipEnvelope.brokerSignature.signatureBase64 = Buffer.alloc(64).toString('base64'); },
    value => { value.inputEvidence.depositReceiptSha256 = '0'.repeat(64); },
    value => { value.target.controllerRunId = '999'; },
    value => { value.target.dispatchNonce = Buffer.alloc(32, 30).toString('base64url'); },
    value => { value.availabilityEnvelope.statement.operation = readiness.ROLLBACK_READINESS_OPERATIONS.membership; },
    value => { value.membershipEnvelope.statement.expiresAt = '2032-01-01T00:04:59.000Z'; },
    value => { value.membershipEnvelope.statement.result.accessibleSiteIds.push(POLICY.productionDenylist.netlifySiteId); },
    value => { value.preparedAt = '2032-01-01T00:03:59.000Z'; }
  ]) {
    const bad = clone(prepared.evidence); mutate(bad);
    const attemptEnv = { ...tokenEnv, CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH: path.join(scratch, `bad-output-${counter}.json`) };
    await evidenceFile(attemptEnv, 'ROLLBACK_READINESS_BROKER', bad, `bad-broker-${counter++}.json`);
    await assert.rejects(readiness.verifyRollbackReadinessToken({ env: attemptEnv, now, fetchImpl: tokenFetch }), /CNYOS_/);
    await assert.rejects(fs.stat(attemptEnv.CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH), { code: 'ENOENT' });
  }
  assert.equal(tokenCalls, 3, 'tampered retained authority stops before any provider token request');
  const availabilityEvidence = context.evidence;
  const validAvailability = resultFor({ operation: readiness.ROLLBACK_READINESS_OPERATIONS.availability, target, evidence: availabilityEvidence });
  for (const mutate of [
    value => { value.hashesReverified = false; }, value => { value.rawPayloadDisclosed = true; },
    value => { value.exactRunNonceRetrievalEnforced = false; }, value => { value.depositId = 'other-deposit-0001'; },
    value => { value.authorizationMaterial.authorizationPacketSha256 = '0'.repeat(64); },
    value => { value.previousPublishedDeployId = '2'.repeat(24); },
    value => { value.recoveryEvidenceSha256 = 'invalid'; }, value => { value.extra = true; }
  ]) {
    const bad = clone(validAvailability); mutate(bad);
    assert.throws(() => readiness.validateAvailabilityResult(bad,
      { target, evidence: availabilityEvidence, observedAt, trust: rollbackTrust }), /CNYOS_/);
  }
  const membershipEvidence = readiness.readinessMembershipEvidence(context, prepared.evidence.availabilityEnvelope);
  const validMembership = resultFor({ operation: readiness.ROLLBACK_READINESS_OPERATIONS.membership, target, evidence: membershipEvidence });
  for (const mutate of [
    value => { value.principalSubject = value.publisherPrincipalSubject; }, value => { value.membershipRole = 'Owner'; },
    value => { value.teamOwner = true; }, value => { value.teamAdministrator = true; },
    value => { value.siteAccessScope = 'all_sites'; }, value => { value.accountConfigurationCapabilityAbsent = false; },
    value => { value.teamAdministrationCapabilityAbsent = false; }, value => { value.restoreCapabilityVerified = false; },
    value => { value.inventoryComplete = false; }, value => { value.productionAccess = true; },
    value => { value.membershipEvidenceSha256 = '0'.repeat(64); }, value => { value.currentMembershipEvidenceSha256 = 'invalid'; },
    value => { value.verifiedAt = '2032-01-01T00:04:00.000Z'; }, value => { value.expiresAt = '2032-01-01T00:20:00.000Z'; },
    value => { value.target.barrierGeneration = 'unexpected-generation'; }, value => { value.extra = true; }
  ]) {
    const bad = clone(validMembership); mutate(bad);
    assert.throws(() => readiness.validateMembershipResult(bad,
      { target, evidence: membershipEvidence, observedAt, trust: membershipTrust }), /CNYOS_/);
  }
  for (const badResponse of [
    async url => response({ id: boundary.subject }, url, { redirected: true }),
    async url => response({ id: boundary.subject }, 'https://other.test/user'),
    async url => response({ id: boundary.subject }, url, { status: 403 }),
    async url => response({ id: boundary.subject }, url, { headers: { 'content-type': 'text/html' } }),
    async url => response({ id: boundary.subject }, url, { headers: { 'set-cookie': 'fixture=1' } }),
    async url => response({ id: rollbackToken }, url),
    async url => response('x'.repeat(1024 * 1024 + 1), url, { raw: true }),
    async url => response({ id: 'different-principal' }, url),
    async () => { throw new Error(rollbackToken); }
  ]) {
    await assert.rejects(readiness.observeRollbackToken({ fetchImpl: badResponse, token: rollbackToken,
      expectedSubject: boundary.subject, previousDeployId: previous }), error =>
      /^CNYOS_[A-Z0-9_]+$/.test(error.message) && !error.message.includes(rollbackToken));
  }
  for (const [sites, headers] of [
    [[], {}], [[{ id: POLICY.productionDenylist.netlifySiteId }], {}],
    [[{ id: POLICY.target.netlifySiteId, name: POLICY.target.netlifySiteName, ssl_url: POLICY.target.netlifyOrigin,
      published_deploy: { id: previous } }], { link: '<https://api.netlify.com/api/v1/sites?page=2>; rel="next"' }],
    [[{ id: POLICY.target.netlifySiteId, name: POLICY.target.netlifySiteName, ssl_url: POLICY.target.netlifyOrigin,
      published_deploy: { id: '2'.repeat(24) } }], {}]
  ]) {
    await assert.rejects(readiness.observeRollbackToken({ token: rollbackToken, expectedSubject: boundary.subject,
      previousDeployId: previous, fetchImpl: async url => String(url).endsWith('/user') ?
        response({ id: boundary.subject }, url) : response(sites, url, { headers }) }), /CNYOS_/);
  }
  const freshPrepareEnv = { ...prepareEnv, CNYOS_CONTROLLER_ROLLBACK_READINESS_BROKER_EVIDENCE_PATH: path.join(scratch, 'failure-prepare.json') };
  await assert.rejects(readiness.prepareRollbackReadinessBrokerEvidence({ env: freshPrepareEnv, now,
    oidcTokenProvider: async () => oidc, fetchImpl: async url => response({}, url, { redirected: true }) }), /CNYOS_/);
  await assert.rejects(fs.stat(freshPrepareEnv.CNYOS_CONTROLLER_ROLLBACK_READINESS_BROKER_EVIDENCE_PATH), { code: 'ENOENT' });
  const mutationEnv = { ...tokenEnv, CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH: path.join(scratch, 'mutation-output.json') };
  let mutated = false;
  await assert.rejects(readiness.verifyRollbackReadinessToken({ env: mutationEnv, now, fetchImpl: async (url, init) => {
    if (!mutated) { mutated = true; await fs.writeFile(preflightFile.file, `${preflightFile.bytes} `); }
    return tokenFetch(url, init);
  } }), /INPUT_CHANGED/);
  await assert.rejects(fs.stat(mutationEnv.CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH), { code: 'ENOENT' });
  await fs.writeFile(preflightFile.file, preflightFile.bytes);
  await assert.rejects(readiness.verifyRollbackReadinessToken({ env: { ...mutationEnv,
    CNYOS_EXPECTED_ROLLBACK_READINESS_BROKER_EVIDENCE_SHA256: '0'.repeat(64) }, now, fetchImpl: tokenFetch }), /DIGEST/);
  await assert.rejects(readiness.verifyRollbackReadinessToken({ env: mutationEnv,
    now: () => new Date('2032-01-01T00:10:00.000Z'), fetchImpl: tokenFetch }), /CNYOS_/);
  const actual = await import(pathToFileURL(path.join(root, 'scripts', 'rollback-readiness.mjs')).href);
  let authorityCalls = 0;
  await assert.rejects(actual.prepareRollbackReadinessBrokerEvidence({ env: prepareEnv, now,
    fetchImpl: async () => { authorityCalls++; } }), /CNYOS_/);
  assert.equal(authorityCalls, 0, 'real placeholder policies never activate fixture authority');
  process.stdout.write('CNYOS activation contract rollback-readiness: passed\n');
} finally {
  globalThis.fetch = originalFetch;
  await fs.rm(scratch, { recursive: true, force: true });
}
