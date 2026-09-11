import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

assert.notEqual(
  process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE,
  'true',
  'rollback attestation deposit contract must remain offline'
);

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporaryRoot = await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-rollback-attestation-deposit-contract-')
);
const isolatedRoot = path.join(temporaryRoot, 'controller');
const scriptsRoot = path.join(isolatedRoot, 'scripts');
await fs.mkdir(scriptsRoot, { recursive: true });
await Promise.all([
  fs.copyFile(path.join(packageRoot, 'scripts', 'policy.mjs'), path.join(scriptsRoot, 'policy.mjs')),
  fs.copyFile(
    path.join(packageRoot, 'scripts', 'deposit-rollback-attestation.mjs'),
    path.join(scriptsRoot, 'deposit-rollback-attestation.mjs')
  ),
  fs.copyFile(
    path.join(packageRoot, 'scripts', 'verify-rollback-attestation-deposit.mjs'),
    path.join(scriptsRoot, 'verify-rollback-attestation-deposit.mjs')
  )
]);

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const clone = value => structuredClone(value);
const canonical = value => JSON.stringify(value);
const FIXED_NOW = new Date('2030-01-01T00:10:00.000Z');
const DEPOSITED_AT = '2030-01-01T00:10:00.000Z';
const RETENTION_UNTIL = '2031-01-01T00:10:00.000Z';
const CONTROLLER_COMMIT = 'a'.repeat(40);
const SOURCE_COMMIT = 'b'.repeat(40);
const SOURCE_TREE = 'c'.repeat(40);
const FUNCTION_TREE = 'd'.repeat(40);
const PREVIOUS_DEPLOY_ID = '0123456789abcdef01234567';
const RUN_ID = '7001001';
const NONCE = Buffer.alloc(32, 0x41).toString('base64url');
const OIDC_TOKEN = 'offline_oidc_token_canary_never_serialize_000001';

function deterministicEd25519(label) {
  const seed = crypto.createHash('sha256').update(`cnyos-deposit-test:${label}`).digest();
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: 'der',
    type: 'pkcs8'
  });
  return Object.freeze({ privateKey, publicKey: crypto.createPublicKey(privateKey) });
}

function publicRecord(id, role, githubLogin, ownerName, pair) {
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  return Object.freeze({
    id,
    role,
    githubLogin,
    ownerName,
    publicKeyPem,
    spkiSha256: sha256(pair.publicKey.export({ type: 'spki', format: 'der' }))
  });
}

const rollbackBroker = deterministicEd25519('rollback-broker');
const reconciliationBroker = deterministicEd25519('reconciliation-broker');
const reviewer = deterministicEd25519('reviewer');
const riskOwner = deterministicEd25519('risk-owner');
const wrongSigner = deterministicEd25519('wrong');
const reviewerRecord = publicRecord(
  'fixture-independent-reviewer-v1',
  'independent_security_reviewer',
  'SecurityReviewer',
  'Fixture Security Reviewer',
  reviewer
);
const riskRecord = publicRecord(
  'fixture-managed-risk-owner-v1',
  'managed_platform_risk_owner',
  'RiskOwner',
  'Fixture Managed Risk Owner',
  riskOwner
);

const sourcePolicy = JSON.parse(await fs.readFile(
  path.join(packageRoot, 'controller-policy.json'),
  'utf8'
));
sourcePolicy.rollbackAttestationBroker = {
  ...sourcePolicy.rollbackAttestationBroker,
  origin: 'https://rollback-attestation.test',
  policyId: 'rollback-attestation-policy-v1',
  policySha256: '1'.repeat(64),
  receiptSigningKeyId: 'rollback-attestation-key-v1',
  receiptSigningPublicKeyPem: rollbackBroker.publicKey.export({
    type: 'spki', format: 'pem'
  }),
  receiptSigningSpkiSha256: sha256(rollbackBroker.publicKey.export({
    type: 'spki', format: 'der'
  })),
  oidcAudience: 'https://rollback-attestation.test/oidc/controller',
  maximumReceiptAgeMinutes: 10,
  minimumRetentionDays: 365
};
sourcePolicy.externalReconciliationBroker = {
  ...sourcePolicy.externalReconciliationBroker,
  origin: 'https://reconciliation.test',
  operationPath: '/v1/reconcile',
  operationDomain: 'cnyos_staging_publish_reconciliation',
  policyId: 'reconciliation-policy-v1',
  policySha256: '2'.repeat(64),
  signingKeyId: 'reconciliation-key-v1',
  signingPublicKeyPem: reconciliationBroker.publicKey.export({
    type: 'spki', format: 'pem'
  }),
  signingKeySpkiSha256: sha256(reconciliationBroker.publicKey.export({
    type: 'spki', format: 'der'
  })),
  oidcAudience: 'https://reconciliation.test/oidc/controller'
};
const policyRaw = `${JSON.stringify(sourcePolicy, null, 2)}\n`;
await fs.writeFile(path.join(isolatedRoot, 'controller-policy.json'), policyRaw, {
  flag: 'wx', mode: 0o600
});
const POLICY_SHA256 = sha256(policyRaw);

const depositModule = await import(
  `${pathToFileURL(path.join(scriptsRoot, 'deposit-rollback-attestation.mjs')).href}?contract=1`
);
const verifierModule = await import(
  `${pathToFileURL(path.join(scriptsRoot, 'verify-rollback-attestation-deposit.mjs')).href}?contract=1`
);

const runtimeController = Object.freeze({
  repository: sourcePolicy.controller.repository,
  ref: sourcePolicy.controller.protectedRef,
  commit: CONTROLLER_COMMIT,
  workflowPath: sourcePolicy.controller.releaseWorkflowPath,
  workflowRef:
    `${sourcePolicy.controller.repository}/${sourcePolicy.controller.releaseWorkflowPath}@${sourcePolicy.controller.protectedRef}`,
  runId: RUN_ID,
  runAttempt: 1,
  dispatchNonce: NONCE
});
const source = Object.freeze({
  repository: sourcePolicy.sourceRepository,
  commit: SOURCE_COMMIT,
  tree: SOURCE_TREE,
  functionSourceTree: FUNCTION_TREE
});
const artifact = Object.freeze({
  producerManifestSha256: '3'.repeat(64),
  artifactSha256: '4'.repeat(64),
  fileCount: 9,
  candidateBuildArtifactDigest: '5'.repeat(64),
  staticReproducibilityEvidenceSha256: '6'.repeat(64),
  staticArtifactSha256: '7'.repeat(64),
  candidateDependencyLockSha256: '8'.repeat(64),
  stagingConfigSha256: '9'.repeat(64),
  productionDenylistConfigSha256: 'a'.repeat(64),
  functionBundleManifestSha256: 'b'.repeat(64),
  functionBundleDependencyLockSha256: 'c'.repeat(64),
  functionSourcesSha256: 'd'.repeat(64),
  producerRunId: RUN_ID,
  githubArtifactDigest: 'e'.repeat(64)
});
const knownGood = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_bootstrap_known_good',
  status: 'passed',
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  recordedAt: '2029-12-31T23:00:00.000Z',
  controllerRepository: sourcePolicy.controller.repository,
  policySha256: POLICY_SHA256,
  source: { repository: sourcePolicy.sourceRepository, commit: 'f'.repeat(40) },
  target: clone(sourcePolicy.target),
  netlifyDeployId: PREVIOUS_DEPLOY_ID,
  evidence: { sha256: 'f'.repeat(64), reference: 'fixture://known-good' }
});
const knownGoodBytes = Buffer.from(`${JSON.stringify(knownGood, null, 2)}\n`);
const registry = Object.freeze({
  schemaVersion: 1,
  environment: sourcePolicy.target.environment,
  keys: [reviewerRecord, riskRecord]
});
const registryBytes = Buffer.from(`${JSON.stringify(registry, null, 2)}\n`);

function externalAuthorizationBoundary() {
  return {
    policyId: sourcePolicy.externalReconciliationBroker.policyId,
    policySha256: sourcePolicy.externalReconciliationBroker.policySha256,
    targetControllerRepository: runtimeController.repository,
    targetControllerRef: runtimeController.ref,
    targetControllerWorkflowPath: runtimeController.workflowPath,
    targetControllerRunId: runtimeController.runId,
    targetControllerRunAttempt: 1,
    targetControllerCommit: runtimeController.commit,
    targetDispatchNonce: NONCE,
    targetNetlifySiteId: sourcePolicy.target.netlifySiteId
  };
}

function authorizationPacket() {
  return {
    schemaVersion: 3,
    evidenceType: 'cnyos_staging_controller_authorization',
    controller: clone(runtimeController),
    source: clone(source),
    artifact: clone(artifact),
    target: clone(sourcePolicy.target),
    exactHeadCi: {},
    runtimeCapabilityBoundary: {},
    deploymentControlBoundary: {
      externalRollbackReconciliationBroker: externalAuthorizationBoundary()
    },
    principalProof: {},
    independentSecurityReview: {
      reviewerGitHubLogin: reviewerRecord.githubLogin,
      reviewerName: reviewerRecord.ownerName
    },
    managedPlatformRiskAcceptance: {
      ownerGitHubLogin: riskRecord.githubLogin,
      ownerName: riskRecord.ownerName
    },
    rollbackRehearsal: {},
    migrationPromotion: {},
    strictPostRemediation: {},
    rollback: {
      restoreOnAnyPostPublishFailure: true,
      externalWatchdogRequired: true,
      restoreOnlyControllerOwnedDeploy: true,
      previousDeployId: PREVIOUS_DEPLOY_ID,
      knownGoodEvidence: {
        sha256: sha256(knownGoodBytes),
        reference: 'fixture://known-good'
      }
    },
    signatureKeyIds: {
      independentSecurityReviewer: reviewerRecord.id,
      managedPlatformRiskOwner: riskRecord.id
    },
    authorization: {
      decision: 'authorize_exact_cnyos_staging_controller_run',
      authorizedByGitHubLogin: riskRecord.githubLogin,
      authorizedByName: riskRecord.ownerName,
      authorizedByRole: 'Managed platform risk owner',
      authorizedAt: '2030-01-01T00:00:00.000Z',
      expiresAt: '2030-01-01T00:30:00.000Z',
      evidence: { sha256: '0'.repeat(64), reference: 'fixture://authorization' }
    },
    productionAuthorization: false,
    realPatientDataAuthorized: false
  };
}

function archived(record) {
  return {
    id: record.id,
    role: record.role,
    githubLogin: record.githubLogin,
    ownerName: record.ownerName,
    publicKeyPem: record.publicKeyPem,
    spkiSha256: record.spkiSha256
  };
}

function authorizationFixture(packet = authorizationPacket()) {
  const raw = canonical(packet);
  const authorizationBytes = Buffer.from(raw);
  const reviewerSignature = crypto.sign(null, authorizationBytes, reviewer.privateKey);
  const riskSignature = crypto.sign(null, authorizationBytes, riskOwner.privateKey);
  const validationEvidence = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_authorization_validation',
    status: 'authorized',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    verifiedAt: '2030-01-01T00:05:00.000Z',
    controllerRepository: runtimeController.repository,
    controllerRef: runtimeController.ref,
    controllerCommit: runtimeController.commit,
    controllerWorkflowPath: runtimeController.workflowPath,
    controllerRunId: runtimeController.runId,
    controllerRunAttempt: 1,
    githubActor: riskRecord.githubLogin,
    dispatchNonce: packet.controller.dispatchNonce,
    policySha256: POLICY_SHA256,
    source: clone(packet.source),
    artifact: clone(packet.artifact),
    target: clone(packet.target),
    previousDeployId: packet.rollback.previousDeployId,
    knownGoodRollbackEvidenceSha256: sha256(knownGoodBytes),
    independentReviewerGitHubLogin: reviewerRecord.githubLogin,
    namedRiskOwnerGitHubLogin: riskRecord.githubLogin,
    functionRemoteByteAttestationUnavailableAccepted: true,
    authorizationExpiresAt: '2030-01-01T00:30:00.000Z',
    principalProofVerifiedAt: '2030-01-01T00:00:00.000Z',
    principalProofExpiresAt: '2030-01-01T00:30:00.000Z',
    deploymentControlBoundaryObservedAt: '2030-01-01T00:00:00.000Z',
    deploymentControlBoundaryExpiresAt: '2030-01-01T00:30:00.000Z',
    netlifyPrincipalSubject: 'fixture-publisher',
    rollbackNetlifyPrincipalSubject: 'fixture-rollback',
    netlifyPrincipalBoundary: {},
    rollbackNetlifyPrincipalBoundary: {},
    targetSiteAndPublisherExclusion: {},
    exclusivePublisherEnforced: true,
    privateDraftAccessEnforced: true,
    failedDraftCleanupEnforced: true,
    githubReleaseBoundary: {},
    authorizationPacketSha256: sha256(authorizationBytes),
    approverRegistrySha256: sha256(registryBytes),
    signatureKeyIds: clone(packet.signatureKeyIds),
    signatureSha256: {
      independentSecurityReviewer: sha256(reviewerSignature),
      managedPlatformRiskOwner: sha256(riskSignature)
    }
  };
  const bundle = {
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_authorization_verification_bundle',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    secretValuesSerialized: false,
    authorizationPacketSha256: sha256(authorizationBytes),
    authorizationDecision: {
      decision: 'authorize_exact_cnyos_staging_controller_run',
      authorizedByGitHubLogin: riskRecord.githubLogin,
      authorizedAt: '2030-01-01T00:00:00.000Z',
      expiresAt: '2030-01-01T00:30:00.000Z',
      controllerRunId: runtimeController.runId,
      dispatchNonce: packet.controller.dispatchNonce,
      candidateCommit: packet.source.commit,
      candidateTree: packet.source.tree,
      artifactSha256: packet.artifact.artifactSha256
    },
    approverRegistrySha256: sha256(registryBytes),
    approverPublicKeys: [archived(reviewerRecord), archived(riskRecord)],
    signatureKeyIds: clone(packet.signatureKeyIds),
    signatureSha256: clone(validationEvidence.signatureSha256),
    knownGoodEvidence: {
      evidenceType: knownGood.evidenceType,
      sourceRepository: knownGood.source.repository,
      sourceCommit: knownGood.source.commit,
      netlifySiteId: knownGood.target.netlifySiteId,
      netlifyOrigin: knownGood.target.netlifyOrigin,
      netlifyDeployId: knownGood.netlifyDeployId
    },
    knownGoodEvidenceSha256: sha256(knownGoodBytes),
    validationEvidence
  };
  return Object.freeze({
    packet,
    raw,
    authorizationBytes,
    reviewerSignature,
    riskSignature,
    bundle,
    bundleBytes: Buffer.from(`${JSON.stringify(bundle, null, 2)}\n`)
  });
}

const fixture = authorizationFixture();
const registryPath = path.join(isolatedRoot, 'approver-registry.json');
const knownGoodPath = path.join(isolatedRoot, 'known-good.json');
const bundlePath = path.join(isolatedRoot, 'authorization-bundle.json');
await Promise.all([
  fs.writeFile(registryPath, registryBytes, { flag: 'wx', mode: 0o600 }),
  fs.writeFile(knownGoodPath, knownGoodBytes, { flag: 'wx', mode: 0o600 }),
  fs.writeFile(bundlePath, fixture.bundleBytes, { flag: 'wx', mode: 0o600 })
]);

const baseEnv = Object.freeze({
  GITHUB_REPOSITORY: runtimeController.repository,
  CNYOS_CONTROLLER_EXPECTED_REPOSITORY: runtimeController.repository,
  GITHUB_RUN_ID: runtimeController.runId,
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_REF_PROTECTED: 'true',
  GITHUB_REF: runtimeController.ref,
  CNYOS_CONTROLLER_PROTECTED_REF: runtimeController.ref,
  GITHUB_SHA: runtimeController.commit,
  CNYOS_CONTROLLER_WORKFLOW_PATH: runtimeController.workflowPath,
  GITHUB_WORKFLOW_REF: runtimeController.workflowRef,
  GITHUB_ACTOR: riskRecord.githubLogin,
  GITHUB_TRIGGERING_ACTOR: riskRecord.githubLogin,
  CNYOS_DISPATCH_NONCE: NONCE,
  CNYOS_CONTROLLER_AUTHORIZATION_JSON: fixture.raw,
  CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64: fixture.reviewerSignature.toString('base64'),
  CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64: fixture.riskSignature.toString('base64'),
  CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH: registryPath,
  CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_PATH: knownGoodPath,
  CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: bundlePath,
  CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: sha256(fixture.bundleBytes),
  CNYOS_ROLLBACK_ATTESTATION_BROKER_URL: sourcePolicy.rollbackAttestationBroker.origin
});

function signatureFor(receipt, privateKey = rollbackBroker.privateKey,
  keyId = sourcePolicy.rollbackAttestationBroker.receiptSigningKeyId) {
  const statement = canonical(receipt);
  const signature = crypto.sign(null, Buffer.from(statement), privateKey);
  return {
    algorithm: 'Ed25519',
    keyId,
    statementSha256: sha256(statement),
    signatureBase64: signature.toString('base64'),
    signatureSha256: sha256(signature)
  };
}

function receiptEnvelope(request, {
  mutateReceipt,
  mutateEnvelope,
  signingKey = rollbackBroker.privateKey,
  signingKeyId = sourcePolicy.rollbackAttestationBroker.receiptSigningKeyId
} = {}) {
  const receipt = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_receipt',
    status: 'sealed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    depositId: 'fixture-deposit-7001001-0001',
    depositSequence: 1,
    depositRequestSha256: sha256(canonical(request)),
    broker: {
      origin: sourcePolicy.rollbackAttestationBroker.origin,
      policyId: sourcePolicy.rollbackAttestationBroker.policyId,
      policySha256: sourcePolicy.rollbackAttestationBroker.policySha256,
      receiptSigningKeyId: sourcePolicy.rollbackAttestationBroker.receiptSigningKeyId,
      receiptSigningSpkiSha256:
        sourcePolicy.rollbackAttestationBroker.receiptSigningSpkiSha256
    },
    controller: clone(request.controller),
    source: clone(request.source),
    artifact: clone(request.artifact),
    target: clone(request.target),
    authorizationMaterial: clone(request.authorizationMaterial),
    depositSemantics: {
      appendOnly: true,
      immutable: true,
      oneDepositPerRunNonce: true,
      conflictingOverwriteRejected: true,
      identicalReplayReturnsOriginalReceipt: true,
      rawPayloadArtifactExposure: false
    },
    recoveryMaterial: {
      canonicalAuthorizationJsonStored: true,
      independentSecurityReviewerSignatureStored: true,
      managedPlatformRiskOwnerSignatureStored: true,
      knownGoodEvidenceBytesStored: true,
      authorizationVerificationBundleBytesStored: true,
      approverRegistryBytesStored: true,
      encryptedAtRest: true,
      hashVerifiedBeforeSeal: true,
      retrievableForRecovery: true
    },
    retrievalBoundary: clone(request.requiredRetrievalBoundary),
    depositedAt: DEPOSITED_AT,
    retentionUntil: RETENTION_UNTIL
  };
  mutateReceipt?.(receipt);
  const envelope = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
    receipt,
    brokerSignature: signatureFor(receipt, signingKey, signingKeyId)
  };
  mutateEnvelope?.(envelope);
  return envelope;
}

function responseFromBytes(bytes, {
  status = 201,
  url = `${sourcePolicy.rollbackAttestationBroker.origin}/`,
  redirected = false,
  contentType = 'application/json',
  contentLength = String(bytes.byteLength),
  headerEntries = [],
  chunkSize = bytes.byteLength
} = {}) {
  const entries = [
    ['content-type', contentType],
    ['content-length', contentLength],
    ...headerEntries
  ];
  let offset = 0;
  return {
    status,
    url,
    redirected,
    headers: {
      get(name) {
        return entries.find(([key]) => key.toLowerCase() === String(name).toLowerCase())?.[1] || null;
      },
      entries() { return entries[Symbol.iterator](); }
    },
    body: {
      getReader() {
        return {
          async read() {
            if (offset >= bytes.byteLength) return { done: true };
            const end = Math.min(bytes.byteLength, offset + Math.max(1, chunkSize));
            const value = new Uint8Array(bytes.subarray(offset, end));
            offset = end;
            return { done: false, value };
          },
          async cancel() { offset = bytes.byteLength; }
        };
      }
    }
  };
}

function brokerFetch(options = {}) {
  return async (endpoint, init) => {
    await options.onRequest?.(endpoint, init);
    if (options.conflict) {
      return responseFromBytes(Buffer.from('{}'), { status: 409 });
    }
    if (options.bodyBytes) return responseFromBytes(options.bodyBytes, options.response || {});
    const request = JSON.parse(init.body);
    const envelope = receiptEnvelope(request, options);
    let bytes = Buffer.from(canonical(envelope));
    if (options.reflectTokenInBody) bytes = Buffer.from(OIDC_TOKEN);
    return responseFromBytes(bytes, {
      ...(options.response || {}),
      ...(options.reflectTokenInHeader
        ? { headerEntries: [['x-reflected-token', OIDC_TOKEN]] }
        : {})
    });
  };
}

let caseNumber = 0;
function caseEnv(label, patch = {}) {
  caseNumber += 1;
  return {
    ...baseEnv,
    CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH: path.join(
      temporaryRoot,
      `${String(caseNumber).padStart(3, '0')}-${label.replaceAll(/[^a-z0-9-]/gi, '-')}.json`
    ),
    ...patch
  };
}

function oidcProvider(recorder = null, value = OIDC_TOKEN) {
  return async input => {
    recorder?.(input);
    return value;
  };
}

async function missing(filename) {
  try {
    await fs.lstat(filename);
    return false;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
}

async function expectNoOutput(label, action, expected) {
  const env = caseEnv(label);
  await assert.rejects(() => action(env), expected, label);
  assert.equal(await missing(env.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH), true,
    `${label}: failure must publish no receipt`);
}

try {
  let capturedRequest = null;
  let capturedEndpoint = null;
  let capturedInit = null;
  let capturedAudience = null;
  const validEnv = caseEnv('valid');
  const valid = await depositModule.depositRollbackAttestation({
    env: validEnv,
    fetchImpl: brokerFetch({
      onRequest(endpoint, init) {
        capturedEndpoint = endpoint;
        capturedInit = init;
        capturedRequest = init.body;
      }
    }),
    oidcTokenProvider: oidcProvider(input => { capturedAudience = input.audience; }),
    now: () => new Date(FIXED_NOW)
  });
  assert.equal(capturedEndpoint.href, `${sourcePolicy.rollbackAttestationBroker.origin}/`);
  assert.equal(capturedAudience, sourcePolicy.rollbackAttestationBroker.oidcAudience);
  assert.equal(capturedInit.method, 'POST');
  assert.equal(capturedInit.redirect, 'error');
  assert.equal(capturedInit.credentials, 'omit');
  assert.equal(capturedInit.referrerPolicy, 'no-referrer');
  assert.equal(capturedInit.cache, 'no-store');
  assert.deepEqual(Object.keys(capturedInit.headers).sort(),
    ['Accept', 'Authorization', 'Content-Type'].sort());
  assert.equal(capturedInit.headers.Authorization, `Bearer ${OIDC_TOKEN}`);
  assert.equal(capturedRequest.includes(OIDC_TOKEN), false);
  assert.equal(capturedRequest, canonical(JSON.parse(capturedRequest)));
  const request = JSON.parse(capturedRequest);
  assert.equal(request.operation, 'deposit_recovery_material');
  assert.equal(request.productionAuthorization, false);
  assert.equal(request.target.netlifySiteId, sourcePolicy.target.netlifySiteId);
  assert.equal(request.target.previousDeployId, PREVIOUS_DEPLOY_ID);
  assert.equal(request.controller.runId, RUN_ID);
  assert.equal(request.controller.dispatchNonce, NONCE);
  assert.equal(request.externalReconciliationPolicy.policySha256,
    sourcePolicy.externalReconciliationBroker.policySha256);
  const expectedMaterial = {
    authorizationJson: fixture.authorizationBytes,
    independentSecurityReviewerSignature: fixture.reviewerSignature,
    managedPlatformRiskOwnerSignature: fixture.riskSignature,
    knownGoodEvidence: knownGoodBytes,
    authorizationBundle: fixture.bundleBytes,
    approverRegistry: registryBytes
  };
  for (const [name, expectedBytes] of Object.entries(expectedMaterial)) {
    const descriptor = request.recoveryMaterial[name];
    assert.deepEqual(Object.keys(descriptor).sort(),
      ['base64', 'byteLength', 'encoding', 'sha256'].sort());
    assert.equal(descriptor.encoding, 'base64');
    assert.equal(descriptor.byteLength, expectedBytes.byteLength);
    assert.equal(descriptor.sha256, sha256(expectedBytes));
    assert.equal(descriptor.base64, expectedBytes.toString('base64'));
    assert.deepEqual(Buffer.from(descriptor.base64, 'base64'), expectedBytes);
  }
  assert.equal(valid.depositRequestSha256, sha256(capturedRequest));
  const exactReceiptBytes = await fs.readFile(valid.receiptPath);
  assert.equal(valid.receiptSha256, sha256(exactReceiptBytes));
  assert.equal(exactReceiptBytes.toString('utf8'), canonical(JSON.parse(exactReceiptBytes)));
  const serializedResult = canonical(valid);
  for (const secret of [
    fixture.raw,
    fixture.reviewerSignature.toString('base64'),
    fixture.riskSignature.toString('base64'),
    OIDC_TOKEN,
    registryBytes.toString('utf8'),
    knownGoodBytes.toString('utf8')
  ]) assert.equal(serializedResult.includes(secret), false, 'result must remain sanitized');

  const verificationEnv = {
    ...baseEnv,
    CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH: valid.receiptPath,
    CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256: sha256(exactReceiptBytes),
    CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH:
      path.join(temporaryRoot, 'verified-deposit.json')
  };
  const verified = await verifierModule.verifyRollbackAttestationDeposit({
    env: verificationEnv,
    now: () => new Date(FIXED_NOW)
  });
  assert.equal(verified.evidence.status, 'passed');
  assert.equal(verified.evidence.depositRequestSha256, sha256(capturedRequest));
  assert.equal(verified.evidence.completeRecoveryMaterialStoredVerified, true);

  const laterDepositTime = new Date(FIXED_NOW.getTime() + 1);
  const laterRetentionTime = new Date(laterDepositTime.getTime() + 365 * 86_400_000);
  let laterClockReads = 0;
  const laterDeposit = await depositModule.depositRollbackAttestation({
    env: caseEnv('honest-later-broker-time'),
    fetchImpl: brokerFetch({
      mutateReceipt(receipt) {
        receipt.depositedAt = laterDepositTime.toISOString();
        receipt.retentionUntil = laterRetentionTime.toISOString();
      }
    }),
    oidcTokenProvider: oidcProvider(),
    now: () => new Date(laterClockReads++ === 0 ? FIXED_NOW : laterDepositTime)
  });
  assert.equal(laterClockReads, 2, 'deposit must bracket the broker request with clock reads');
  assert.equal(laterDeposit.depositedAt, laterDepositTime.toISOString(),
    'an honest broker timestamp after request start must be accepted');

  const authorizationExpiry = new Date('2030-01-01T00:30:00.000Z');
  const expiryRetention = new Date(
    authorizationExpiry.getTime() + 365 * 86_400_000
  );
  let expiryClockReads = 0;
  await expectNoOutput('authorization-expired-before-deposit', env =>
    depositModule.depositRollbackAttestation({
      env,
      fetchImpl: brokerFetch({
        mutateReceipt(receipt) {
          receipt.depositedAt = authorizationExpiry.toISOString();
          receipt.retentionUntil = expiryRetention.toISOString();
        }
      }),
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(expiryClockReads++ === 0 ? FIXED_NOW : authorizationExpiry)
    }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/);
  assert.equal(expiryClockReads, 2,
    'authorization-expiry rejection must use the broker-response clock fence');

  const timelyDepositTime = new Date(authorizationExpiry.getTime() - 1);
  const delayedResponseTime = new Date(authorizationExpiry.getTime() + 1);
  let delayedClockReads = 0;
  const timelyDeposit = await depositModule.depositRollbackAttestation({
    env: caseEnv('timely-deposit-delayed-response'),
    fetchImpl: brokerFetch({
      mutateReceipt(receipt) {
        receipt.depositedAt = timelyDepositTime.toISOString();
        receipt.retentionUntil = expiryRetention.toISOString();
      }
    }),
    oidcTokenProvider: oidcProvider(),
    now: () => new Date(delayedClockReads++ === 0 ? timelyDepositTime : delayedResponseTime)
  });
  assert.equal(timelyDeposit.depositedAt, timelyDepositTime.toISOString(),
    'response delay past expiry must not invalidate a timely signed deposit');
  const timelyReceiptBytes = await fs.readFile(timelyDeposit.receiptPath);
  const timelyVerification = await verifierModule.verifyRollbackAttestationDeposit({
    env: {
      ...verificationEnv,
      CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH: timelyDeposit.receiptPath,
      CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256: sha256(timelyReceiptBytes),
      CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH:
        path.join(temporaryRoot, 'timely-deposit-delayed-verification.json')
    },
    now: () => new Date(delayedResponseTime)
  });
  assert.equal(timelyVerification.evidence.status, 'passed');

  await expectNoOutput('deposit-before-authorization-verification', env =>
    depositModule.depositRollbackAttestation({
      env,
      fetchImpl: brokerFetch({
        mutateReceipt(receipt) {
          receipt.depositedAt = '2030-01-01T00:04:59.999Z';
        }
      }),
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/);

  let retryRequest = null;
  const retryEnv = caseEnv('identical-retry');
  const retry = await depositModule.depositRollbackAttestation({
    env: retryEnv,
    fetchImpl: brokerFetch({
      response: { status: 200 },
      onRequest(_endpoint, init) { retryRequest = init.body; }
    }),
    oidcTokenProvider: oidcProvider(),
    now: () => new Date(FIXED_NOW)
  });
  assert.equal(retryRequest, capturedRequest, 'an identical retry must have identical request bytes');
  assert.deepEqual(await fs.readFile(retry.receiptPath), exactReceiptBytes,
    'an identical retry must preserve the original receipt bytes');

  const oidcRequestToken = 'offline_actions_oidc_request_token_never_forward_0001';
  const defaultOidcEnv = caseEnv('default-oidc', {
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.actions.test/token',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: oidcRequestToken
  });
  let defaultOidcBrokerCalls = 0;
  await depositModule.depositRollbackAttestation({
    env: defaultOidcEnv,
    fetchImpl: async (url, init) => {
      if (init.method === 'GET') {
        assert.equal(url.origin, 'https://oidc.actions.test');
        assert.equal(url.searchParams.get('audience'),
          sourcePolicy.rollbackAttestationBroker.oidcAudience);
        assert.equal(init.redirect, 'error');
        assert.equal(init.credentials, 'omit');
        assert.equal(init.referrerPolicy, 'no-referrer');
        assert.equal(init.headers.Authorization, `Bearer ${oidcRequestToken}`);
        const bytes = Buffer.from(canonical({ value: OIDC_TOKEN }));
        return responseFromBytes(bytes, { status: 200, url: url.href });
      }
      defaultOidcBrokerCalls += 1;
      assert.equal(init.headers.Authorization, `Bearer ${OIDC_TOKEN}`);
      assert.equal(init.body.includes(oidcRequestToken), false);
      return brokerFetch()(url, init);
    },
    now: () => new Date(FIXED_NOW)
  });
  assert.equal(defaultOidcBrokerCalls, 1);

  for (const invalidUrl of [
    `${sourcePolicy.rollbackAttestationBroker.origin}/`,
    'http://rollback-attestation.test',
    'https://user@rollback-attestation.test',
    'https://rollback-attestation.test:443',
    'https://rollback-attestation.test/v1/deposit',
    'https://rollback-attestation.test?deposit=1',
    'https://rollback-attestation.test#deposit'
  ]) {
    let oidcCalls = 0;
    await expectNoOutput(`endpoint-${sha256(invalidUrl).slice(0, 8)}`, env =>
      depositModule.depositRollbackAttestation({
        env: { ...env, CNYOS_ROLLBACK_ATTESTATION_BROKER_URL: invalidUrl },
        fetchImpl: brokerFetch(),
        oidcTokenProvider: oidcProvider(() => { oidcCalls += 1; }),
        now: () => new Date(FIXED_NOW)
      }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_URL_INVALID/);
    assert.equal(oidcCalls, 0, 'invalid endpoint must fail before OIDC');
  }

  await expectNoOutput('noncanonical-authorization', env =>
    depositModule.depositRollbackAttestation({
      env: { ...env, CNYOS_CONTROLLER_AUTHORIZATION_JSON: JSON.stringify(fixture.packet, null, 2) },
      fetchImpl: brokerFetch(), oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_JSON_INVALID_NONCANONICAL/);

  await expectNoOutput('noncanonical-signature-base64', env =>
    depositModule.depositRollbackAttestation({
      env: {
        ...env,
        CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64:
          `${fixture.reviewerSignature.toString('base64')}\n`
      },
      fetchImpl: brokerFetch(), oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_SECURITY_SIGNATURE_INVALID/);

  await expectNoOutput('wrong-authorization-signature', env =>
    depositModule.depositRollbackAttestation({
      env: {
        ...env,
        CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64:
          crypto.sign(null, fixture.authorizationBytes, wrongSigner.privateKey).toString('base64')
      },
      fetchImpl: brokerFetch(), oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_MATERIAL_INVALID/);

  await expectNoOutput('bundle-transport-digest', env =>
    depositModule.depositRollbackAttestation({
      env: { ...env, CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: '0'.repeat(64) },
      fetchImpl: brokerFetch(), oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_DIGEST_MISMATCH/);

  const partialBundlePath = path.join(temporaryRoot, 'partial-bundle.json');
  const partialBundleBytes = Buffer.from(canonical({ schemaVersion: 2 }));
  await fs.writeFile(partialBundlePath, partialBundleBytes);
  let partialOidcCalls = 0;
  await expectNoOutput('partial-bundle', env =>
    depositModule.depositRollbackAttestation({
      env: {
        ...env,
        CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: partialBundlePath,
        CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: sha256(partialBundleBytes)
      },
      fetchImpl: brokerFetch(),
      oidcTokenProvider: oidcProvider(() => { partialOidcCalls += 1; }),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_MATERIAL_INVALID/);
  assert.equal(partialOidcCalls, 0, 'partial inputs must fail before OIDC');

  for (const [label, mutatePacket] of [
    ['cross-run-authorization', packet => { packet.controller.runId = '7001002'; }],
    ['cross-nonce-authorization', packet => {
      packet.controller.dispatchNonce = Buffer.alloc(32, 0x43).toString('base64url');
    }],
    ['production-site-authorization', packet => {
      packet.target.netlifySiteId = sourcePolicy.productionDenylist.netlifySiteId;
      packet.target.netlifyOrigin = sourcePolicy.productionDenylist.netlifyOrigin;
    }]
  ]) {
    const changedPacket = authorizationPacket();
    mutatePacket(changedPacket);
    const changed = authorizationFixture(changedPacket);
    const changedBundlePath = path.join(temporaryRoot, `${label}-bundle.json`);
    await fs.writeFile(changedBundlePath, changed.bundleBytes);
    let oidcCalls = 0;
    await expectNoOutput(label, env => depositModule.depositRollbackAttestation({
      env: {
        ...env,
        CNYOS_CONTROLLER_AUTHORIZATION_JSON: changed.raw,
        CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64:
          changed.reviewerSignature.toString('base64'),
        CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64: changed.riskSignature.toString('base64'),
        CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: changedBundlePath,
        CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: sha256(changed.bundleBytes)
      },
      fetchImpl: brokerFetch(),
      oidcTokenProvider: oidcProvider(() => { oidcCalls += 1; }),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_MATERIAL_INVALID/);
    assert.equal(oidcCalls, 0, `${label} must fail before OIDC`);
  }

  const symlinkBundlePath = path.join(temporaryRoot, 'symlink-bundle.json');
  await fs.symlink(bundlePath, symlinkBundlePath);
  await expectNoOutput('symlink-bundle', env =>
    depositModule.depositRollbackAttestation({
      env: { ...env, CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: symlinkBundlePath },
      fetchImpl: brokerFetch(), oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_AUTHORIZATION_BUNDLE_INVALID/);

  await expectNoOutput('ambient-production-credential', env =>
    depositModule.depositRollbackAttestation({
      env: { ...env, NETLIFY_AUTH_TOKEN: 'must-not-be-available' },
      fetchImpl: brokerFetch(), oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_CREDENTIAL_ISOLATION_INVALID/);

  const brokerSignedFailures = [
    ['wrong-nonce', receipt => { receipt.controller.dispatchNonce =
      Buffer.alloc(32, 0x42).toString('base64url'); },
    /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['wrong-run', receipt => { receipt.controller.runId = '7001002'; },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['wrong-site', receipt => { receipt.target.netlifySiteId =
      sourcePolicy.productionDenylist.netlifySiteId; },
    /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['wrong-source', receipt => { receipt.source.commit = '0'.repeat(40); },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['wrong-request-hash', receipt => { receipt.depositRequestSha256 = '0'.repeat(64); },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['short-retention', receipt => { receipt.retentionUntil =
      '2030-12-31T00:09:59.000Z'; },
    /CNYOS_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT/],
    ['stale-receipt', receipt => { receipt.depositedAt =
      '2029-12-31T23:59:59.000Z'; },
    /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_STALE/],
    ['missing-bundle-storage', receipt => {
      receipt.recoveryMaterial.authorizationVerificationBundleBytesStored = false;
    }, /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['missing-registry-storage', receipt => {
      receipt.recoveryMaterial.approverRegistryBytesStored = false;
    }, /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/],
    ['extra-receipt-field', receipt => { receipt.unreviewed = true; },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID/]
  ];
  for (const [label, mutateReceipt, pattern] of brokerSignedFailures) {
    await expectNoOutput(label, env => depositModule.depositRollbackAttestation({
      env,
      fetchImpl: brokerFetch({ mutateReceipt }),
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), pattern);
  }

  await expectNoOutput('wrong-broker-key', env =>
    depositModule.depositRollbackAttestation({
      env,
      fetchImpl: brokerFetch({ signingKey: wrongSigner.privateKey }),
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_SIGNATURE_INVALID/);

  await expectNoOutput('noncanonical-response', env =>
    depositModule.depositRollbackAttestation({
      env,
      fetchImpl: async (_endpoint, init) => {
        const envelope = receiptEnvelope(JSON.parse(init.body));
        const bytes = Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`);
        return responseFromBytes(bytes);
      },
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_RECEIPT_INVALID_NONCANONICAL/);

  const responseFailures = [
    ['redirect', { response: { redirected: true } },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID/],
    ['wrong-final-url', { response: { url: 'https://other.test/' } },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID/],
    ['wrong-content-type', { response: { contentType: 'text/html' } },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID/],
    ['reflected-header', { reflectTokenInHeader: true },
      /CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_REFLECTION_INVALID/],
    ['reflected-body', { reflectTokenInBody: true },
      /CNYOS_ROLLBACK_ATTESTATION_OIDC_TOKEN_REFLECTION_INVALID/],
    ['conflict', { conflict: true },
      /CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID/]
  ];
  for (const [label, fetchOptions, pattern] of responseFailures) {
    await expectNoOutput(label, env => depositModule.depositRollbackAttestation({
      env,
      fetchImpl: brokerFetch(fetchOptions),
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), pattern);
  }

  await expectNoOutput('content-length-lie', env =>
    depositModule.depositRollbackAttestation({
      env,
      fetchImpl: async (_endpoint, init) => {
        const bytes = Buffer.from(canonical(receiptEnvelope(JSON.parse(init.body))));
        return responseFromBytes(bytes, { contentLength: String(bytes.byteLength - 1) });
      },
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID/);

  const bombBytes = Buffer.alloc(512 * 1024 + 1, 0x41);
  await expectNoOutput('response-bomb', env =>
    depositModule.depositRollbackAttestation({
      env,
      fetchImpl: brokerFetch({
        bodyBytes: bombBytes,
        response: { contentLength: '', chunkSize: 16 * 1024 }
      }),
      oidcTokenProvider: oidcProvider(),
      now: () => new Date(FIXED_NOW)
    }), /CNYOS_ROLLBACK_ATTESTATION_BROKER_RESPONSE_INVALID/);

  const raceEnv = caseEnv('output-race');
  const raceSentinel = Buffer.from('rival-output-must-survive');
  await assert.rejects(() => depositModule.depositRollbackAttestation({
    env: raceEnv,
    fetchImpl: brokerFetch({
      async onRequest() {
        await fs.writeFile(
          raceEnv.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH,
          raceSentinel,
          { flag: 'wx', mode: 0o600 }
        );
      }
    }),
    oidcTokenProvider: oidcProvider(),
    now: () => new Date(FIXED_NOW)
  }), /CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_EXISTS/);
  assert.deepEqual(
    await fs.readFile(raceEnv.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH),
    raceSentinel,
    'an output race must never overwrite or delete the rival file'
  );

  const existingEnv = caseEnv('existing-output');
  await fs.writeFile(
    existingEnv.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH,
    raceSentinel
  );
  let existingOidcCalls = 0;
  await assert.rejects(() => depositModule.depositRollbackAttestation({
    env: existingEnv,
    fetchImpl: brokerFetch(),
    oidcTokenProvider: oidcProvider(() => { existingOidcCalls += 1; }),
    now: () => new Date(FIXED_NOW)
  }), /CNYOS_ROLLBACK_ATTESTATION_RECEIPT_OUTPUT_EXISTS/);
  assert.equal(existingOidcCalls, 0, 'pre-existing output must fail before OIDC or network');
  assert.deepEqual(
    await fs.readFile(existingEnv.CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH),
    raceSentinel
  );

  process.stdout.write('CNYOS activation contract rollback-attestation-deposit: passed\n');
} finally {
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}
