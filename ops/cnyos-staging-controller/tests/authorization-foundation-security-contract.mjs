import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXED_NOW = new Date('2030-01-01T00:30:00.000Z');
const CREATED_AT = new Date('2030-01-01T00:10:00.000Z');
const NONCE = Buffer.alloc(32, 0x5a).toString('base64url');
const CONTROLLER_COMMIT = 'a'.repeat(40);
const GITHUB_ARTIFACT_DIGEST = 'b'.repeat(64);
const CANDIDATE_BUILD_DIGEST = 'c'.repeat(64);
const FUNCTION_LOCK_DIGEST = 'd'.repeat(64);
const PREVIOUS_DEPLOY_ID = '0123456789abcdef01234567';
const REVIEWER_KEY_ID = 'fixture-independent-reviewer-v1';
const RISK_KEY_ID = 'fixture-managed-risk-owner-v1';
const REVIEWER_LOGIN = 'security-reviewer';
const RISK_LOGIN = 'risk-owner';
const REVIEWER_NAME = 'Fixture Security Reviewer';
const RISK_NAME = 'Fixture Risk Owner';
const REVIEW_AREAS = Object.freeze([
  'trigger_function_and_browser_rpc_acl_revocation',
  'verification_sql_enforced_read_only_transaction',
  'atomic_failure_and_rollback_behavior'
]);
const FUNCTION_NAMES = Object.freeze([
  'account-access',
  'database-backup',
  'database-backup-background',
  'database-backup-recovery',
  'evidence-search',
  'line-oa-webhook',
  'owner-drive',
  'owner-subscription',
  'patient-identity',
  'platform-console',
  'restore-source'
]);
const REQUIRED_SCHEDULES = Object.freeze({
  'database-backup': '0 20 * * *',
  'database-backup-recovery': '*/15 0-2,20-23 * * *'
});

const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const gitBlobDigest = value => {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return crypto.createHash('sha1').update(Buffer.concat([
    Buffer.from(`blob ${bytes.byteLength}\0`, 'ascii'),
    bytes
  ])).digest('hex');
};
const clone = value => structuredClone(value);
const canonical = value => JSON.stringify(value);
const pointer = label => ({ sha256: digest(`fixture:${label}`), reference: `fixture://${label}` });

function git(cwd, args, encoding = 'utf8') {
  return execFileSync('git', args, {
    cwd,
    encoding,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH,
      LANG: 'C',
      LC_ALL: 'C',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_DATE: '2030-01-01T00:00:00Z',
      GIT_COMMITTER_DATE: '2030-01-01T00:00:00Z'
    }
  });
}

async function writeJson(filename, value) {
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function deterministicEd25519(label) {
  const seed = crypto.createHash('sha256').update(`cnyos-test-only:${label}`).digest();
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: 'der',
    type: 'pkcs8'
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

function publicRecord({ id, role, login, ownerName, publicKey }) {
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    id,
    role,
    githubLogin: login,
    ownerName,
    publicKeyPem,
    spkiSha256: digest(publicKey.export({ type: 'spki', format: 'der' }))
  };
}

async function copyControllerScripts(root) {
  const controllerRoot = path.join(root, 'controller');
  const scriptsRoot = path.join(controllerRoot, 'scripts');
  await fs.mkdir(scriptsRoot, { recursive: true });
  for (const filename of [
    'policy.mjs',
    'create-producer-bundle.mjs',
    'verify-producer-bundle.mjs',
    'verify-authorization.mjs',
    'verify-rollback-attestation-deposit.mjs'
  ]) {
    await fs.copyFile(path.join(packageRoot, 'scripts', filename), path.join(scriptsRoot, filename));
  }

  const policy = JSON.parse(await fs.readFile(
    path.join(packageRoot, 'controller-policy.json'),
    'utf8'
  ));
  policy.staticArtifactReproducibility.hermeticBuilderImageDigest = `sha256:${'1'.repeat(64)}`;
  policy.staticArtifactReproducibility.stagingConfigSha256 = '2'.repeat(64);
  policy.staticArtifactReproducibility.productionDenylistConfigSha256 = '3'.repeat(64);
  policy.publishing.netlifyCliVersion = '19.0.0';
  policy.privateDraftAccessBoundary.origin = 'https://draft-boundary.invalid';
  policy.privateDraftAccessBoundary.policyId = 'fixture-private-draft-policy-v1';
  policy.privateDraftAccessBoundary.policySha256 = '4'.repeat(64);
  policy.externalReconciliationBroker.policyId = 'fixture-rollback-reconciliation-v1';
  policy.externalReconciliationBroker.policySha256 = '5'.repeat(64);
  policy.netlifyAuthorityBoundary.policyId = 'fixture-netlify-authority-v1';
  policy.netlifyAuthorityBoundary.policySha256 = '6'.repeat(64);
  const rollbackBroker = deterministicEd25519('rollback-attestation-broker');
  policy.rollbackAttestationBroker.origin = 'https://rollback-attestation.invalid';
  policy.rollbackAttestationBroker.policyId = 'fixture-rollback-attestation-v1';
  policy.rollbackAttestationBroker.policySha256 = '7'.repeat(64);
  policy.rollbackAttestationBroker.receiptSigningKeyId = 'fixture-receipt-key-v1';
  policy.rollbackAttestationBroker.receiptSigningPublicKeyPem = rollbackBroker.publicKey.export({
    type: 'spki',
    format: 'pem'
  });
  policy.rollbackAttestationBroker.receiptSigningSpkiSha256 = digest(
    rollbackBroker.publicKey.export({ type: 'spki', format: 'der' })
  );
  policy.rollbackAttestationBroker.oidcAudience =
    'https://rollback-attestation.invalid/v1/controller';
  const policyRaw = `${JSON.stringify(policy, null, 2)}\n`;
  await fs.writeFile(path.join(controllerRoot, 'controller-policy.json'), policyRaw, 'utf8');

  const nonce = 'authorization-foundation-security';
  const createModule = await import(`${pathToFileURL(path.join(
    scriptsRoot,
    'create-producer-bundle.mjs'
  )).href}?fixture=${nonce}`);
  const verifyModule = await import(`${pathToFileURL(path.join(
    scriptsRoot,
    'verify-producer-bundle.mjs'
  )).href}?fixture=${nonce}`);
  const authorizationModule = await import(`${pathToFileURL(path.join(
    scriptsRoot,
    'verify-authorization.mjs'
  )).href}?fixture=${nonce}`);
  const policyModule = await import(`${pathToFileURL(path.join(
    scriptsRoot,
    'policy.mjs'
  )).href}?fixture=${nonce}`);
  const rollbackAttestationModule = await import(`${pathToFileURL(path.join(
    scriptsRoot,
    'verify-rollback-attestation-deposit.mjs'
  )).href}?fixture=${nonce}`);
  return {
    controllerRoot,
    policy,
    policySha256: digest(policyRaw),
    rollbackBroker,
    ...createModule,
    ...verifyModule,
    ...authorizationModule,
    ...policyModule,
    ...rollbackAttestationModule
  };
}

async function initializeCandidate(root) {
  const candidate = path.join(root, 'candidate');
  const functions = path.join(candidate, 'netlify', 'functions');
  await fs.mkdir(functions, { recursive: true });
  await fs.writeFile(path.join(candidate, 'package-lock.json'), '{"lockfileVersion":3}\n');
  await fs.writeFile(
    path.join(functions, 'fixture-handler.mjs'),
    'export default async () => new Response("fixture");\n',
    'utf8'
  );
  git(candidate, ['init', '--quiet', '--initial-branch=main']);
  git(candidate, ['config', 'user.name', 'CNYOS Fixture']);
  git(candidate, ['config', 'user.email', 'fixture@invalid.example']);
  git(candidate, ['add', '--', 'package-lock.json', 'netlify/functions/fixture-handler.mjs']);
  git(candidate, ['commit', '--quiet', '-m', 'fixture'], undefined);
  return {
    candidate,
    commit: String(git(candidate, ['rev-parse', 'HEAD'])).trim(),
    tree: String(git(candidate, ['rev-parse', 'HEAD^{tree}'])).trim(),
    functionTree: String(git(candidate, ['rev-parse', 'HEAD:netlify/functions'])).trim()
  };
}

async function regularFiles(directory) {
  const entries = [];
  async function visit(current, relative = '') {
    const children = await fs.readdir(current, { withFileTypes: true });
    for (const child of children) {
      const childRelative = relative ? `${relative}/${child.name}` : child.name;
      const absolute = path.join(current, child.name);
      if (child.isDirectory()) await visit(absolute, childRelative);
      else {
        const bytes = await fs.readFile(absolute);
        entries.push({ path: childRelative, size: bytes.byteLength, sha256: digest(bytes) });
      }
    }
  }
  await visit(directory);
  return entries.sort((left, right) => left.path.localeCompare(right.path));
}

async function prepareProducerInputs(root, controller, candidate) {
  const dist = path.join(root, 'reproduced-static');
  const bundles = path.join(root, 'prebundled-functions');
  await fs.mkdir(dist, { recursive: true });
  await fs.mkdir(bundles, { recursive: true });

  const brand = { clinicName: 'Chananya Staging', theme: 'clinical' };
  const tenantConfig = {
    schemaVersion: 1,
    deploymentId: controller.policy.target.deploymentId,
    tenant: {
      expectedClinicId: controller.policy.target.clinicId,
      expectedClinicCode: controller.policy.target.clinicCode
    },
    database: {
      provider: 'supabase',
      url: controller.policy.target.supabaseOrigin,
      publishableKey: `sb_publishable_${'A'.repeat(24)}`
    },
    auth: { redirectOrigin: controller.policy.target.authRedirectOrigin, provider: 'google' },
    identity: { qrIssuer: controller.policy.target.qrIssuer },
    brand,
    safety: { previewLocked: false }
  };
  const brandConfig = {
    schemaVersion: 1,
    deploymentId: controller.policy.target.deploymentId,
    tenant: { expectedClinicCode: controller.policy.target.clinicCode },
    identity: { qrIssuer: controller.policy.target.qrIssuer },
    brand,
    safety: { previewLocked: false }
  };
  const deployManifest = {
    schemaVersion: 1,
    deploymentId: controller.policy.target.deploymentId,
    source: { verified: true, commit: candidate.commit, tree: candidate.tree },
    tenant: {
      expectedClinicId: controller.policy.target.clinicId,
      expectedClinicCode: controller.policy.target.clinicCode
    },
    identity: { qrIssuer: controller.policy.target.qrIssuer },
    build: {
      context: 'production',
      deploymentClass: 'dedicated-staging',
      timestamp: CREATED_AT.toISOString()
    },
    safety: {
      previewLocked: false,
      databaseLocked: false,
      stagingDatabaseExplicitlyAcknowledged: true
    }
  };
  const files = new Map([
    ['_headers', '/*\n  X-CNYOS-Fixture: true\n'],
    ['_redirects', '/health /index.html 200\n'],
    ['brand-config.js', `// Generated fixture\nwindow.CLINICAL_OS_CONFIG = Object.freeze(${canonical(brandConfig)});\n`],
    ['deploy-manifest.json', `${canonical(deployManifest)}\n`],
    ['index.html', '<!doctype html><title>CNYOS fixture</title>\n'],
    ['tenant-config.js', `// Generated fixture\nwindow.CLINICAL_OS_CONFIG = Object.freeze(${canonical(tenantConfig)});\n`]
  ]);
  for (const [name, contents] of files) await fs.writeFile(path.join(dist, name), contents);
  const runtimeEntries = (await regularFiles(dist)).map(entry => ({ ...entry }));
  const runtimeManifest = {
    schemaVersion: 2,
    integrityAlgorithm: 'sha256',
    fileCount: runtimeEntries.length,
    files: runtimeEntries.map(entry => entry.path),
    integrity: runtimeEntries
  };
  await fs.writeFile(
    path.join(dist, 'runtime-publish-manifest.json'),
    `${canonical(runtimeManifest)}\n`
  );

  const bundleFileEntries = [];
  for (const name of FUNCTION_NAMES) {
    const bytes = Buffer.from(`PK-fixture-${name}\n`, 'utf8');
    await fs.writeFile(path.join(bundles, `${name}.zip`), bytes);
    bundleFileEntries.push({ path: `${name}.zip`, size: bytes.byteLength, sha256: digest(bytes) });
  }
  bundleFileEntries.sort((left, right) => left.path.localeCompare(right.path));

  const sourcePath = path.join(candidate.candidate, 'netlify', 'functions', 'fixture-handler.mjs');
  const sourceBytes = await fs.readFile(sourcePath);
  const sourceFiles = [{
    path: 'fixture-handler.mjs',
    size: sourceBytes.byteLength,
    sha256: digest(sourceBytes),
    gitObject: String(git(candidate.candidate, [
      'rev-parse',
      'HEAD:netlify/functions/fixture-handler.mjs'
    ])).trim()
  }];
  const baseEnv = {
    GITHUB_REPOSITORY: controller.policy.controller.repository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: controller.policy.controller.repository,
    GITHUB_RUN_ID: '1001',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: controller.policy.controller.protectedRef,
    CNYOS_CONTROLLER_PROTECTED_REF: controller.policy.controller.protectedRef,
    GITHUB_SHA: CONTROLLER_COMMIT,
    CNYOS_CONTROLLER_WORKFLOW_PATH: controller.policy.controller.releaseWorkflowPath,
    GITHUB_WORKFLOW_REF: `${controller.policy.controller.repository}/${controller.policy.controller.releaseWorkflowPath}@${controller.policy.controller.protectedRef}`,
    GITHUB_ACTOR: 'Risk-Owner',
    GITHUB_TRIGGERING_ACTOR: 'risk-owner',
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    CNYOS_DISPATCH_NONCE: NONCE,
    CNYOS_CANDIDATE_SHA: candidate.commit,
    CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST: CANDIDATE_BUILD_DIGEST,
    CNYOS_CANDIDATE_DIRECTORY: candidate.candidate,
    CNYOS_REPRODUCED_STATIC_DIRECTORY: dist,
    CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY: bundles,
    CNYOS_EXPECTED_FUNCTION_DEPENDENCY_LOCK_SHA256: FUNCTION_LOCK_DIGEST
  };
  const functionManifest = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_prebundled_functions',
    authorization: false,
    credentialsAvailable: false,
    controllerRepository: baseEnv.GITHUB_REPOSITORY,
    controllerRef: baseEnv.GITHUB_REF,
    controllerCommit: baseEnv.GITHUB_SHA,
    controllerRunId: baseEnv.GITHUB_RUN_ID,
    sourceRepository: controller.policy.sourceRepository,
    candidateCommit: candidate.commit,
    candidateTree: candidate.tree,
    functionSourceTree: candidate.functionTree,
    policySha256: controller.policySha256,
    netlifyCliVersion: controller.policy.publishing.netlifyCliVersion,
    importClosureComplete: true,
    externalImportsResolvedFromLock: true,
    dependencyLockSha256: FUNCTION_LOCK_DIGEST,
    sourceFilesSha256: digest(canonical(sourceFiles)),
    functionNames: [...FUNCTION_NAMES],
    schedules: { ...REQUIRED_SCHEDULES },
    files: bundleFileEntries
  };
  const functionManifestPath = path.join(root, 'function-bundle-manifest.json');
  await writeJson(functionManifestPath, functionManifest);

  const staticFiles = await regularFiles(dist);
  const dependencyLock = Buffer.from(String(git(
    candidate.candidate,
    ['show', 'HEAD:package-lock.json'],
    undefined
  )));
  const staticEvidence = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_static_reproducibility',
    status: 'passed',
    authorization: false,
    credentialsAvailable: false,
    controllerRepository: baseEnv.GITHUB_REPOSITORY,
    controllerRef: baseEnv.GITHUB_REF,
    controllerCommit: baseEnv.GITHUB_SHA,
    controllerRunId: baseEnv.GITHUB_RUN_ID,
    controllerRunAttempt: 1,
    policySha256: controller.policySha256,
    sourceRepository: controller.policy.sourceRepository,
    candidateCommit: candidate.commit,
    candidateTree: candidate.tree,
    untrustedReferenceArtifactDigest: CANDIDATE_BUILD_DIGEST,
    candidateDependencyLockSha256: digest(dependencyLock),
    configInputs: {
      stagingConfigSha256: controller.policy.staticArtifactReproducibility.stagingConfigSha256,
      productionDenylistConfigSha256:
        controller.policy.staticArtifactReproducibility.productionDenylistConfigSha256
    },
    buildEnvironment: {
      containerImageDigest:
        controller.policy.staticArtifactReproducibility.hermeticBuilderImageDigest,
      nodeVersion: '24.20.0',
      networkDisabled: true,
      lifecycleScriptsDisabled: true,
      sourceMountedReadOnly: true,
      isolatedOutput: true
    },
    byteForByteMatchWithUntrustedReference: true,
    staticArtifactSha256: digest(canonical(staticFiles)),
    fileCount: staticFiles.length,
    files: staticFiles,
    verifiedAt: '2030-01-01T00:09:00.000Z'
  };
  const staticEvidencePath = path.join(root, 'static-reproducibility-evidence.json');
  await writeJson(staticEvidencePath, staticEvidence);
  const staticEvidenceBytes = await fs.readFile(staticEvidencePath);

  return {
    ...candidate,
    dist,
    bundles,
    baseEnv: {
      ...baseEnv,
      CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH: functionManifestPath,
      CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH: staticEvidencePath,
      CNYOS_EXPECTED_STATIC_REPRODUCIBILITY_EVIDENCE_SHA256: digest(staticEvidenceBytes)
    }
  };
}

async function copyBundle(source, destination) {
  await fs.cp(source, destination, { recursive: true, errorOnExist: true, force: false });
}

function principal(policy, { rollback = false } = {}) {
  return {
    status: 'passed',
    tokenClass: 'dedicated_staging_only',
    subject: rollback ? 'netlify:fixture-rollback-principal' : 'netlify:fixture-publish-principal',
    inventoryComplete: true,
    accessibleSiteCount: 1,
    allowedSiteIds: [policy.target.netlifySiteId],
    productionAccess: false,
    membershipRole: 'Publisher',
    teamOwner: false,
    teamAdministrator: false,
    siteAccessScope: 'single_site',
    accountConfigurationCapabilityAbsent: true,
    teamAdministrationCapabilityAbsent: true,
    deployCapabilityVerified: true,
    membershipEvidence: pointer(rollback ? 'rollback-membership' : 'publisher-membership'),
    evidence: pointer(rollback ? 'rollback-principal' : 'publisher-principal'),
    verifiedAt: '2030-01-01T00:20:00.000Z',
    expiresAt: '2030-01-01T00:50:00.000Z',
    ...(rollback ? { restoreCapabilityVerified: true } : {})
  };
}

function authorizationPacket(controller, bundle, knownGoodSha256) {
  const manifest = bundle.manifest;
  const common = {
    status: 'passed',
    sourceCommit: manifest.candidateCommit,
    sourceTree: manifest.candidateTree,
    artifactSha256: manifest.artifactSha256
  };
  const aclDigest = digest('fixture-acl-catalog');
  const baseline = controller.policy.databaseEvidence.inventoryBaseline;
  return {
    schemaVersion: 3,
    evidenceType: 'cnyos_staging_controller_authorization',
    controller: {
      repository: controller.policy.controller.repository,
      ref: controller.policy.controller.protectedRef,
      commit: CONTROLLER_COMMIT,
      workflowPath: controller.policy.controller.releaseWorkflowPath,
      workflowRef: `${controller.policy.controller.repository}/${controller.policy.controller.releaseWorkflowPath}@${controller.policy.controller.protectedRef}`,
      runId: '1001',
      runAttempt: 1,
      dispatchNonce: NONCE
    },
    source: {
      repository: controller.policy.sourceRepository,
      commit: manifest.candidateCommit,
      tree: manifest.candidateTree,
      functionSourceTree: manifest.functionSourceTree
    },
    artifact: {
      producerManifestSha256: bundle.manifestSha256,
      artifactSha256: manifest.artifactSha256,
      fileCount: manifest.fileCount,
      candidateBuildArtifactDigest: manifest.candidateBuildArtifactDigest,
      staticReproducibilityEvidenceSha256: manifest.staticReproducibilityEvidenceSha256,
      staticArtifactSha256: manifest.staticArtifactSha256,
      candidateDependencyLockSha256: manifest.candidateDependencyLockSha256,
      stagingConfigSha256: manifest.stagingConfigSha256,
      productionDenylistConfigSha256: manifest.productionDenylistConfigSha256,
      functionBundleManifestSha256: manifest.functionBundleManifestSha256,
      functionBundleDependencyLockSha256: manifest.functionBundleDependencyLockSha256,
      functionSourcesSha256: manifest.functionSourcesSha256,
      producerRunId: '1001',
      githubArtifactDigest: GITHUB_ARTIFACT_DIGEST
    },
    target: clone(controller.policy.target),
    exactHeadCi: {
      ...common,
      conclusion: 'success',
      unresolvedBlockers: 0,
      completedAt: '2030-01-01T00:19:00.000Z',
      evidence: pointer('exact-head-ci')
    },
    runtimeCapabilityBoundary: {
      ...common,
      projectRef: controller.policy.target.supabaseProjectRef,
      netlifySiteId: controller.policy.target.netlifySiteId,
      platformControlEnabled: false,
      ownerDriveEnabled: false,
      restoreSourceApiEnabled: false,
      pubmedEnabled: false,
      directJsonRestoreTestEnabled: false,
      ownerControlEnabled: false,
      ownerControlScope: 'disabled',
      githubProductionDispatchReachable: false,
      driveOrBlobProductionReachable: false,
      lineProductionReachable: false,
      secretProjectBindingVerified: true,
      syntheticOnly: true,
      realPatientDataAuthorized: false,
      functionEnvironmentAllowlistComplete: true,
      functionSecretInventoryClosedWorld: true,
      browserProcessEnvironmentSanitized: true,
      candidateFunctionEgressPolicyEnforced: true,
      productionCredentialAbsenceVerified: true,
      stagingOnlyCredentialScopeVerified: true,
      serviceRoleNotInheritedByBrowserProcess: true,
      candidateFunctionsReceiveOnlyReviewedStagingSecrets: true,
      evidence: pointer('runtime-capability')
    },
    deploymentControlBoundary: {
      ...common,
      netlifySiteId: controller.policy.target.netlifySiteId,
      productionNetlifySiteId: controller.policy.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: controller.policy.productionDenylist.netlifyOrigin,
      exclusivePublisherEnforced: true,
      netlifyGitPublishingDisabled: true,
      buildHooksDisabled: true,
      manualUiPublishingDenied: true,
      targetSiteClassifiedStagingOnly: true,
      realPatientDataAbsent: true,
      legacyPublisherInventoryComplete: true,
      candidateRepositoryProductionWorkflowTargetDenied: true,
      candidateRepositoryPreviewWorkflowTargetDenied: true,
      allAlternatePublisherCredentialsTargetDenied: true,
      currentCnyosProductionMappingConflictResolved: true,
      compareAndSwapOrEquivalentLockEnforced: true,
      privateDraftAccessEnforced: true,
      failedDraftCleanupEnforced: true,
      rollbackEnvironmentNoninteractive: true,
      rollbackPrincipal: principal(controller.policy, { rollback: true }),
      externalRollbackReconciliationBroker: {
        policyId: controller.policy.externalReconciliationBroker.policyId,
        policySha256: controller.policy.externalReconciliationBroker.policySha256,
        executionAuthority: 'external_rollback_reconciliation_broker',
        immutablePolicy: true,
        independentOfTargetRunCode: true,
        independentOfWatchdogRevision: true,
        targetControllerRepository: controller.policy.controller.repository,
        targetControllerRef: controller.policy.controller.protectedRef,
        targetControllerRunId: '1001',
        targetControllerRunAttempt: 1,
        targetControllerCommit: CONTROLLER_COMMIT,
        targetControllerWorkflowPath: controller.policy.controller.releaseWorkflowPath,
        targetDispatchNonce: NONCE,
        targetNetlifySiteId: controller.policy.target.netlifySiteId,
        targetRunCannotSuppressReconciliation: true,
        watchdogRevisionCannotSuppressReconciliation: true,
        enforcesRollback: true,
        enforcesDraftCleanup: true,
        enforcesLeaseRelease: true,
        enforcesRunReconciliationBarrier: true,
        atomicLeaseReleaseRetainsRunReconciliationBarrier: true,
        blocksNewMutationWhileRunReconciliationBarrierActive: true,
        successfulReleaseCommitRequiresFinalEvidenceHashes: true,
        draftIntentTerminalBeforeBarrierClearRequired: true,
        automaticRunReconciliationBarrierExpiryPermitted: false,
        exactTerminalCommitRetryIdempotent: true,
        terminalSuccessAndRecoveryClaimMutuallyExclusive: true,
        terminalSuccessNeverRollbackEligible: true,
        recoveryClaimConflictsWithDelayedTerminalCommit: true,
        recoveryTerminalRecordImmutableAndRetrievable: true,
        recoveryTerminalRecordBindsExecutionReceipt: true,
        exactRecoveryFinalizationRetryIdempotent: true,
        terminalRecoveryNeverRollbackEligible: true,
        recoveryClaimAndPlanCorePersistedAtomically: true,
        recoveryClaimPlanCoreImmutableAndRetrievable: true,
        exactRecoveryClaimRetryIdempotent: true,
        authorizedWatchdogRecoveryClaimResumptionEnforced: true,
        recoveryAuthorizationRefreshPreservesClaimAndPlanCore: true,
        conflictingRecoveryClaimBindingsOrGenerationRejected: true,
        automaticRecoveryClaimExpiryPermitted: false,
        incompleteRecoveryRecordPreservesRecoveryClaimAndPlan: true,
        recoveryClaimAuthorizedResumerRepository: controller.policy.controller.repository,
        recoveryClaimAuthorizedResumerProtectedRef: controller.policy.controller.protectedRef,
        recoveryClaimAuthorizedResumerWorkflowPaths: [
          controller.policy.controller.releaseWorkflowPath,
          controller.policy.controller.rollbackWorkflowPath
        ],
        evidence: pointer('external-reconciliation-broker')
      },
      observedAt: '2030-01-01T00:20:00.000Z',
      expiresAt: '2030-01-01T00:50:00.000Z',
      evidence: pointer('deployment-control')
    },
    principalProof: principal(controller.policy),
    independentSecurityReview: {
      ...common,
      verdict: 'approved',
      reviewerGitHubLogin: REVIEWER_LOGIN,
      reviewerName: REVIEWER_NAME,
      reviewerRole: 'Independent security reviewer',
      areas: REVIEW_AREAS.map(id => ({
        id,
        verdict: 'passed',
        disposition: 'Reviewed and accepted for this exact fixture.'
      })),
      evidence: pointer('security-review'),
      reviewedAt: '2030-01-01T00:22:00.000Z'
    },
    managedPlatformRiskAcceptance: {
      status: 'accepted',
      scope: 'cnyos_staging_only',
      ownerGitHubLogin: RISK_LOGIN,
      ownerName: RISK_NAME,
      ownerRole: 'Managed platform risk owner',
      projectRef: controller.policy.target.supabaseProjectRef,
      databaseSystemIdentifier: controller.policy.target.databaseSystemIdentifier,
      managedDefaultAclScope: 'supabase_admin function defaults for public only',
      managedSupabaseAdminDefaultAclAccepted: true,
      functionRemoteByteAttestationUnavailableAccepted: true,
      currentPublicOwnership: {
        routines: 0,
        relations: 0,
        types: 0,
        evidence: pointer('current-public-ownership')
      },
      runtimeSetRole: {
        runtimeAndUntrustedCannotSetRoleToReviewedCreators: true,
        reviewedCreators: ['supabase_admin'],
        evidence: pointer('runtime-set-role')
      },
      rationale: 'Fixture accepts the precisely scoped managed platform limitation.',
      driftCheckOwner: 'Fixture operator',
      providerEscalationReference: 'fixture://provider-escalation',
      driftPolicy: {
        blockOnOwnershipDrift: true,
        blockOnCreatorDrift: true,
        blockOnRoleAttributeDrift: true,
        blockOnRoleMembershipDrift: true,
        blockOnDefaultAclDrift: true,
        evidence: pointer('drift-policy')
      },
      productionAuthorization: false,
      evidence: pointer('risk-acceptance'),
      acceptedAt: '2030-01-01T00:20:00.000Z',
      nextReviewAt: '2030-02-01T00:00:00.000Z',
      expiresAt: '2030-03-01T00:00:00.000Z'
    },
    rollbackRehearsal: {
      ...common,
      postgresqlMajorVersion: 17,
      connectionMode: 'direct',
      projectRef: controller.policy.target.supabaseProjectRef,
      databaseSystemIdentifier: controller.policy.target.databaseSystemIdentifier,
      maintenanceWindowStatus: 'completed',
      maintenanceWindowReference: 'fixture://maintenance-window',
      quiescenceVerified: true,
      quiescenceEvidence: pointer('quiescence'),
      normalRollback: {
        status: 'passed',
        atomicRollbackVerified: true,
        receipt: 'ACL_CATALOG_ROLLBACK_VERIFIED',
        noExecutableCommitDerivative: true,
        advisoryLockReleased: true,
        preAclCatalogSha256: aclDigest,
        postAclCatalogSha256: aclDigest,
        evidence: pointer('normal-rollback')
      },
      injectedFailure: {
        status: 'passed',
        exitWasNonzero: true,
        exactFailureObserved: true,
        failureInjectionPoint: 'fixture_after_acl_revocation',
        observedErrorSha256: digest('fixture injected failure'),
        postStateEqual: true,
        noExecutableCommitDerivative: true,
        advisoryLockReleased: true,
        preAclCatalogSha256: aclDigest,
        postAclCatalogSha256: aclDigest,
        evidence: pointer('injected-failure')
      },
      ambiguityRecoveryStatus: 'not_required_no_ambiguous_outcome',
      freshPostObserver: {
        status: 'passed',
        schemaVersion: baseline.observerSchemaVersion,
        baselineSchemaVersion: baseline.schemaVersion,
        baselineId: baseline.baselineId,
        baselineSha256: baseline.sha256,
        observedAt: '2030-01-01T00:21:00.000Z',
        afterNormalRollback: true,
        afterInjectedFailure: true,
        projectRef: controller.policy.target.supabaseProjectRef,
        databaseSystemIdentifier: controller.policy.target.databaseSystemIdentifier,
        ...clone(baseline.counts),
        expectedAclDigest: digest('fixture-observed-acl'),
        observedAclDigest: digest('fixture-observed-acl'),
        aclCatalogSha256: aclDigest,
        evidence: pointer('fresh-post-observer')
      },
      completedAt: '2030-01-01T00:20:00.000Z',
      evidence: pointer('rollback-rehearsal')
    },
    migrationPromotion: {
      ...common,
      promotionPullRequest:
        'https://github.com/apisarit/chananya-clinical-wellness-os/pull/99',
      promotionHeadRef: 'agent/ordered-migration-promotion',
      promotionHeadCommit: manifest.candidateCommit,
      promotionBaseRef: 'main',
      promotionBaseCommit: '8'.repeat(40),
      promotionRequiredState: 'open_ready_for_independent_review',
      pr36HeadRef: 'agent/p0-security-trigger-acl',
      pr36HeadCommit: '7'.repeat(40),
      pr36BaseRef: 'main',
      pr36BaseCommit: '8'.repeat(40),
      pr36RequiredState: 'open_draft_unapproved',
      pr36RemainsDraftAndUnapproved: true,
      orderedMigrationChainAppliedToChananyaStaging: true,
      chananyaLedger: { status: 'reconciled', evidence: pointer('chananya-ledger') },
      jitarsaLedger: {
        status: 'independently_reconciled',
        evidence: pointer('jitarsa-ledger')
      },
      preDeploymentAuthenticatedRegression: {
        status: 'passed',
        evidence: pointer('predeploy-regression')
      },
      evidence: pointer('migration-promotion')
    },
    strictPostRemediation: {
      ...common,
      projectRef: controller.policy.target.supabaseProjectRef,
      databaseSystemIdentifier: controller.policy.target.databaseSystemIdentifier,
      verificationSql: {
        status: 'passed',
        readOnlyEnforced: true,
        evidence: pointer('verification-sql')
      },
      triggerAndBrowserRpcAcl: { status: 'passed', evidence: pointer('acl-review') },
      postRemediationAuthenticatedRegression: {
        status: 'passed',
        evidence: pointer('post-remediation-regression')
      },
      unresolvedBlockers: 0,
      verifiedAt: '2030-01-01T00:22:00.000Z',
      evidence: pointer('strict-post-remediation')
    },
    rollback: {
      restoreOnAnyPostPublishFailure: true,
      externalWatchdogRequired: true,
      restoreOnlyControllerOwnedDeploy: true,
      previousDeployId: PREVIOUS_DEPLOY_ID,
      knownGoodEvidence: {
        sha256: knownGoodSha256,
        reference: 'fixture://known-good-evidence'
      }
    },
    signatureKeyIds: {
      independentSecurityReviewer: REVIEWER_KEY_ID,
      managedPlatformRiskOwner: RISK_KEY_ID
    },
    authorization: {
      decision: 'authorize_exact_cnyos_staging_controller_run',
      authorizedByGitHubLogin: 'RISK-OWNER',
      authorizedByName: RISK_NAME,
      authorizedByRole: 'Managed platform risk owner',
      authorizedAt: '2030-01-01T00:20:00.000Z',
      expiresAt: '2030-01-01T00:50:00.000Z',
      evidence: pointer('authorization-decision')
    },
    productionAuthorization: false,
    realPatientDataAuthorized: false
  };
}

function rollbackAttestationEnvelope(controller, archive, receiptPatch = {}) {
  const validation = archive.validationEvidence;
  const receipt = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_receipt',
    status: 'sealed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    depositId: 'fixture-deposit:1001:one',
    depositSequence: 1,
    depositRequestSha256: digest('fixture-deposit-request'),
    broker: {
      origin: controller.policy.rollbackAttestationBroker.origin,
      policyId: controller.policy.rollbackAttestationBroker.policyId,
      policySha256: controller.policy.rollbackAttestationBroker.policySha256,
      receiptSigningKeyId: controller.policy.rollbackAttestationBroker.receiptSigningKeyId,
      receiptSigningSpkiSha256:
        controller.policy.rollbackAttestationBroker.receiptSigningSpkiSha256
    },
    controller: {
      repository: controller.policy.controller.repository,
      ref: controller.policy.controller.protectedRef,
      commit: CONTROLLER_COMMIT,
      workflowPath: controller.policy.controller.releaseWorkflowPath,
      workflowRef: `${controller.policy.controller.repository}/${controller.policy.controller.releaseWorkflowPath}@${controller.policy.controller.protectedRef}`,
      runId: '1001',
      runAttempt: 1,
      dispatchNonce: NONCE,
      policySha256: controller.policySha256
    },
    source: clone(validation.source),
    artifact: clone(validation.artifact),
    target: {
      netlifySiteId: controller.policy.target.netlifySiteId,
      netlifyOrigin: controller.policy.target.netlifyOrigin,
      supabaseProjectRef: controller.policy.target.supabaseProjectRef,
      databaseSystemIdentifier: controller.policy.target.databaseSystemIdentifier,
      targetSha256: digest(canonical(controller.policy.target)),
      previousDeployId: validation.previousDeployId
    },
    authorizationMaterial: {
      authorizationPacketSha256: archive.authorizationPacketSha256,
      authorizationBundleSha256: digest(Buffer.from(JSON.stringify(archive, null, 2) + '\n')),
      approverRegistrySha256: archive.approverRegistrySha256,
      independentSecurityReviewerKeyId: archive.signatureKeyIds.independentSecurityReviewer,
      independentSecurityReviewerSignatureSha256:
        archive.signatureSha256.independentSecurityReviewer,
      managedPlatformRiskOwnerKeyId: archive.signatureKeyIds.managedPlatformRiskOwner,
      managedPlatformRiskOwnerSignatureSha256:
        archive.signatureSha256.managedPlatformRiskOwner,
      knownGoodEvidenceSha256: archive.knownGoodEvidenceSha256
    },
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
    retrievalBoundary: {
      oidcAudience: controller.policy.rollbackAttestationBroker.oidcAudience,
      requiredControllerRepository: controller.policy.controller.repository,
      requiredControllerRef: controller.policy.controller.protectedRef,
      requiredControllerWorkflowPath: controller.policy.controller.releaseWorkflowPath,
      requiredControllerRunId: '1001',
      requiredControllerRunAttempt: 1,
      requiredDispatchNonce: NONCE,
      externalReconciliationPolicyId: controller.policy.externalReconciliationBroker.policyId,
      externalReconciliationPolicySha256:
        controller.policy.externalReconciliationBroker.policySha256,
      failedRunCodeCannotDelete: true,
      watchdogRevisionCannotDelete: true,
      exactRunAndNonceRequired: true,
      oidcControllerIdentityRequired: true
    },
    depositedAt: FIXED_NOW.toISOString(),
    retentionUntil: '2031-01-01T00:30:00.000Z',
    ...receiptPatch
  };
  const statement = canonical(receipt);
  const signature = crypto.sign(null, Buffer.from(statement), controller.rollbackBroker.privateKey);
  return {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_rollback_attestation_deposit_envelope',
    receipt,
    brokerSignature: {
      algorithm: 'Ed25519',
      keyId: controller.policy.rollbackAttestationBroker.receiptSigningKeyId,
      statementSha256: digest(statement),
      signatureBase64: signature.toString('base64'),
      signatureSha256: digest(signature)
    }
  };
}

async function expectFailure(action, pattern, label) {
  await assert.rejects(action, pattern, label);
}

async function expectPathAbsent(filename, label) {
  await assert.rejects(
    fs.access(filename),
    error => error?.code === 'ENOENT',
    label
  );
}

async function main() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-auth-foundation-'));
  try {
    const controller = await copyControllerScripts(root);
    const objectA = '1'.repeat(40);
    const objectB = '2'.repeat(40);
    const treeRecord = (mode, object, filename) =>
      Buffer.from(`${mode} blob ${object}\t${filename}\0`, 'utf8');
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(
        Buffer.from(`100644 blob ${objectA}\tnetlify/functions/truncated.mjs`, 'utf8'),
        { rootPath: 'netlify/functions' }
      ),
      /CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID/,
      'truncated ls-tree output must fail closed'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(
        treeRecord('120000', objectA, 'netlify/functions/linked.mjs'),
        { rootPath: 'netlify/functions' }
      ),
      /CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID/,
      'Git symlink entries must not enter the producer source inventory'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(
        Buffer.from(`160000 commit ${objectA}\tnetlify/functions/submodule\0`, 'utf8'),
        { rootPath: 'netlify/functions' }
      ),
      /CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID/,
      'non-blob Git entries must not enter the producer source inventory'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(Buffer.concat([
        treeRecord('100644', objectA, 'netlify/functions/duplicate.mjs'),
        treeRecord('100755', objectB, 'netlify/functions/duplicate.mjs')
      ]), { rootPath: 'netlify/functions' }),
      /CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID/,
      'duplicate Git paths must fail closed'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(Buffer.concat([
        treeRecord('100644', objectA, 'netlify/functions/Case.mjs'),
        treeRecord('100644', objectB, 'netlify/functions/case.mjs')
      ]), { rootPath: 'netlify/functions' }),
      /CNYOS_PRODUCER_FUNCTION_PATH_COLLISION/,
      'portable case collisions must fail closed'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(Buffer.concat([
        treeRecord('100644', objectA, 'netlify/functions/path'),
        treeRecord('100644', objectB, 'netlify/functions/path/child.mjs')
      ]), { rootPath: 'netlify/functions' }),
      /CNYOS_PRODUCER_FUNCTION_FILE_DIRECTORY_CONFLICT/,
      'file-directory conflicts must fail closed'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(Buffer.concat([
        treeRecord('100644', objectA, 'netlify/functions/one.mjs'),
        treeRecord('100644', objectB, 'netlify/functions/two.mjs')
      ]), { rootPath: 'netlify/functions', maximumFiles: 1 }),
      /CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID/,
      'source file-count limits must fail closed'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobInventory(
        treeRecord('100644', objectA, 'netlify/functions/../escaped.mjs'),
        { rootPath: 'netlify/functions' }
      ),
      /CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID/,
      'non-normalized Git paths must fail closed'
    );
    assert.throws(
      () => controller.assertImmutableGitBlobLimits(
        [{ object: objectA }, { object: objectB }],
        new Map([[objectA, 8], [objectB, 8]]),
        { maximumAggregateBytes: 15 }
      ),
      /CNYOS_PRODUCER_GIT_SOURCE_AGGREGATE_TOO_LARGE/,
      'aggregate source-byte limits must account for every path'
    );

    const batchBytes = Buffer.from('immutable blob fixture\n', 'utf8');
    const batchObject = gitBlobDigest(batchBytes);
    const batchMetadata = Buffer.from(
      `${batchObject} blob ${batchBytes.byteLength}\n`,
      'ascii'
    );
    const batchSizes = controller.parseImmutableGitBlobBatchCheck(
      batchMetadata,
      [batchObject]
    );
    const batchPayload = Buffer.concat([
      batchMetadata,
      batchBytes,
      Buffer.from('\n', 'ascii')
    ]);
    assert.deepEqual(
      controller.parseImmutableGitBlobBatch(batchPayload, [batchObject], batchSizes).get(batchObject),
      batchBytes,
      'batch-read Git bytes must retain their exact object contents'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobBatchCheck(batchMetadata, [batchObject], {
        maximumFileBytes: batchBytes.byteLength - 1
      }),
      /CNYOS_PRODUCER_GIT_BLOB_METADATA_INVALID/,
      'oversized Git blobs must fail before their contents are read'
    );
    assert.throws(
      () => controller.parseImmutableGitBlobBatch(
        batchPayload.subarray(0, batchPayload.length - 1),
        [batchObject],
        batchSizes
      ),
      /CNYOS_PRODUCER_GIT_BLOB_CONTENT_INVALID/,
      'truncated cat-file batch output must fail closed'
    );
    const forgedObject = '3'.repeat(40);
    const forgedMetadata = new Map([[forgedObject, batchBytes.byteLength]]);
    assert.throws(
      () => controller.parseImmutableGitBlobBatch(Buffer.concat([
        Buffer.from(`${forgedObject} blob ${batchBytes.byteLength}\n`, 'ascii'),
        batchBytes,
        Buffer.from('\n', 'ascii')
      ]), [forgedObject], forgedMetadata),
      /CNYOS_PRODUCER_GIT_OBJECT_HASH_MISMATCH/,
      'Git blob bytes must hash to the exact ls-tree object ID'
    );

    const candidate = await initializeCandidate(root);
    const fixture = await prepareProducerInputs(root, controller, candidate);
    const bundleDirectory = path.join(root, 'producer-bundle');
    const producerEnv = {
      ...fixture.baseEnv,
      CNYOS_PRODUCER_BUNDLE_DIRECTORY: bundleDirectory
    };

    const created = await controller.createProducerBundle({
      env: producerEnv,
      now: () => new Date(CREATED_AT)
    });
    assert.equal(created.manifest.authorization, false);
    assert.equal(created.manifest.credentialsAvailable, false);
    assert.equal(created.manifest.candidateCommit, candidate.commit);

    const manifestBytes = await fs.readFile(created.manifestPath);
    const verifierEnv = {
      ...producerEnv,
      CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: digest(manifestBytes)
    };
    const verified = await controller.verifyProducerBundle({ env: verifierEnv });
    assert.equal(verified.manifest.artifactSha256, created.manifest.artifactSha256);

    const uppercaseCandidateBundle = path.join(root, 'uppercase-candidate-bundle');
    await expectFailure(
      () => controller.createProducerBundle({
        env: {
          ...producerEnv,
          CNYOS_CANDIDATE_SHA: candidate.commit.toUpperCase(),
          CNYOS_PRODUCER_BUNDLE_DIRECTORY: uppercaseCandidateBundle
        }
      }),
      /CNYOS_PRODUCER_CANDIDATE_SHA_INVALID/,
      'candidate source identity must be the exact lowercase SHA'
    );
    await expectPathAbsent(
      uppercaseCandidateBundle,
      'invalid candidate identity must not leave producer output'
    );

    const trackedFunctionPath = path.join(
      candidate.candidate,
      'netlify',
      'functions',
      'fixture-handler.mjs'
    );
    const committedFunctionBytes = Buffer.from(String(git(candidate.candidate, [
      'show',
      `${candidate.commit}:netlify/functions/fixture-handler.mjs`
    ])), 'utf8');
    await fs.writeFile(trackedFunctionPath, 'export default () => "dirty worktree overlay";\n');
    await fs.writeFile(
      path.join(candidate.candidate, 'netlify', 'functions', 'untracked-overlay.mjs'),
      'throw new Error("must never be read");\n'
    );
    await fs.symlink(
      path.join(root, 'outside-candidate-source'),
      path.join(candidate.candidate, 'netlify', 'functions', 'untracked-symlink.mjs')
    );
    const dirtyOverlayBundle = path.join(root, 'dirty-overlay-bundle');
    const dirtyOverlayCreated = await controller.createProducerBundle({
      env: { ...producerEnv, CNYOS_PRODUCER_BUNDLE_DIRECTORY: dirtyOverlayBundle },
      now: () => new Date(CREATED_AT)
    });
    assert.equal(dirtyOverlayCreated.manifest.artifactSha256, created.manifest.artifactSha256);
    assert.deepEqual(dirtyOverlayCreated.manifest.functionSources, created.manifest.functionSources);
    await fs.writeFile(trackedFunctionPath, committedFunctionBytes);
    await fs.unlink(path.join(
      candidate.candidate,
      'netlify',
      'functions',
      'untracked-overlay.mjs'
    ));
    await fs.unlink(path.join(
      candidate.candidate,
      'netlify',
      'functions',
      'untracked-symlink.mjs'
    ));

    const replacementBytesPath = path.join(root, 'replacement-object.txt');
    await fs.writeFile(replacementBytesPath, 'replacement ref must be ignored\n');
    const replacementObject = String(git(candidate.candidate, [
      'hash-object',
      '-w',
      replacementBytesPath
    ])).trim();
    const originalFunctionObject = created.manifest.functionSources[0].gitObject;
    git(candidate.candidate, ['replace', originalFunctionObject, replacementObject]);
    const isolatedGitEnvironmentNames = [
      'GIT_ALTERNATE_OBJECT_DIRECTORIES',
      'GIT_CONFIG_COUNT',
      'GIT_CONFIG_KEY_0',
      'GIT_CONFIG_VALUE_0',
      'GIT_DIR',
      'GIT_OBJECT_DIRECTORY',
      'GIT_REPLACE_REF_BASE',
      'GIT_WORK_TREE'
    ];
    const priorGitEnvironment = new Map(isolatedGitEnvironmentNames.map(name => [
      name,
      Object.hasOwn(process.env, name) ? process.env[name] : undefined
    ]));
    process.env.GIT_ALTERNATE_OBJECT_DIRECTORIES = path.join(root, 'untrusted-alternates');
    process.env.GIT_CONFIG_COUNT = '1';
    process.env.GIT_CONFIG_KEY_0 = 'core.hooksPath';
    process.env.GIT_CONFIG_VALUE_0 = path.join(root, 'untrusted-hooks');
    process.env.GIT_DIR = path.join(root, 'untrusted-git-dir');
    process.env.GIT_OBJECT_DIRECTORY = path.join(root, 'untrusted-object-directory');
    process.env.GIT_REPLACE_REF_BASE = 'refs/untrusted-replacements/';
    process.env.GIT_WORK_TREE = path.join(root, 'untrusted-worktree');
    const replacementBundle = path.join(root, 'replacement-ref-bundle');
    let replacementCreated;
    try {
      replacementCreated = await controller.createProducerBundle({
        env: { ...producerEnv, CNYOS_PRODUCER_BUNDLE_DIRECTORY: replacementBundle },
        now: () => new Date(CREATED_AT)
      });
    } finally {
      for (const [name, value] of priorGitEnvironment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      git(candidate.candidate, ['replace', '-d', originalFunctionObject]);
    }
    assert.equal(replacementCreated.manifest.artifactSha256, created.manifest.artifactSha256);
    assert.deepEqual(replacementCreated.manifest.functionSources, created.manifest.functionSources);

    const movedCommit = String(git(candidate.candidate, [
      'commit-tree',
      candidate.tree,
      '-p',
      candidate.commit,
      '-m',
      'interleaved head move'
    ])).trim();
    const movedHeadBundle = path.join(root, 'moved-head-bundle');
    try {
      await expectFailure(
        () => controller.createProducerBundle({
          env: { ...producerEnv, CNYOS_PRODUCER_BUNDLE_DIRECTORY: movedHeadBundle },
          now: () => new Date(CREATED_AT),
          beforeFinalHeadFence: async () => {
            git(candidate.candidate, ['update-ref', 'HEAD', movedCommit, candidate.commit]);
          }
        }),
        /CNYOS_PRODUCER_CANDIDATE_CHECKOUT_MOVED/,
        'an interleaved HEAD move must fail the final checkout fence'
      );
    } finally {
      git(candidate.candidate, ['update-ref', 'HEAD', candidate.commit, movedCommit]);
    }
    await expectPathAbsent(
      movedHeadBundle,
      'an interleaved HEAD move must not publish mixed or partial producer output'
    );

    const insideCandidateEnv = {
      ...producerEnv,
      CNYOS_PRODUCER_BUNDLE_DIRECTORY: path.join(candidate.candidate, 'forbidden-bundle')
    };
    await expectFailure(
      () => controller.createProducerBundle({ env: insideCandidateEnv }),
      /CNYOS_PRODUCER_BUNDLE_INSIDE_CANDIDATE/,
      'producer output must not enter the candidate checkout'
    );

    const symlinkTarget = path.join(root, 'symlink-target.txt');
    const distSymlink = path.join(fixture.dist, 'linked-secret.txt');
    await fs.writeFile(symlinkTarget, 'not public\n');
    await fs.symlink(symlinkTarget, distSymlink);
    await expectFailure(
      () => controller.createProducerBundle({
        env: { ...producerEnv, CNYOS_PRODUCER_BUNDLE_DIRECTORY: path.join(root, 'symlink-bundle') }
      }),
      /ARTIFACT_SYMLINK_REJECTED/,
      'producer must reject a symlinked reproduced-static input'
    );
    await fs.unlink(distSymlink);

    const byteTamperBundle = path.join(root, 'byte-tamper-bundle');
    await copyBundle(bundleDirectory, byteTamperBundle);
    await fs.appendFile(path.join(byteTamperBundle, 'payload', 'dist', 'index.html'), 'tamper');
    await expectFailure(
      () => controller.verifyProducerBundle({
        env: { ...verifierEnv, CNYOS_PRODUCER_BUNDLE_DIRECTORY: byteTamperBundle }
      }),
      /CNYOS_PRODUCER_BUNDLE_DIGEST_MISMATCH/,
      'post-production byte mutation (including a TOCTOU mutation) must fail'
    );

    const symlinkBundle = path.join(root, 'payload-symlink-bundle');
    await copyBundle(bundleDirectory, symlinkBundle);
    const linkedIndex = path.join(symlinkBundle, 'payload', 'dist', 'index.html');
    await fs.unlink(linkedIndex);
    await fs.symlink(symlinkTarget, linkedIndex);
    await expectFailure(
      () => controller.verifyProducerBundle({
        env: { ...verifierEnv, CNYOS_PRODUCER_BUNDLE_DIRECTORY: symlinkBundle }
      }),
      /ARTIFACT_SYMLINK_REJECTED/,
      'verifier must reject a payload symlink'
    );

    await expectFailure(
      () => controller.verifyProducerBundle({
        env: { ...verifierEnv, CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: '0'.repeat(64) }
      }),
      /CNYOS_PRODUCER_MANIFEST_DIGEST_MISMATCH/,
      'transport manifest digest must bind the producer manifest'
    );

    const pathTamperBundle = path.join(root, 'path-tamper-bundle');
    await copyBundle(bundleDirectory, pathTamperBundle);
    const pathManifestPath = path.join(pathTamperBundle, 'producer-manifest.json');
    const pathManifest = JSON.parse(await fs.readFile(pathManifestPath, 'utf8'));
    pathManifest.files[0].path = 'payload/dist/../escape';
    await writeJson(pathManifestPath, pathManifest);
    const pathManifestBytes = await fs.readFile(pathManifestPath);
    await expectFailure(
      () => controller.verifyProducerBundle({
        env: {
          ...verifierEnv,
          CNYOS_PRODUCER_BUNDLE_DIRECTORY: pathTamperBundle,
          CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: digest(pathManifestBytes)
        }
      }),
      /CNYOS_PRODUCER_MANIFEST_PATH_INVALID/,
      'manifest path traversal must fail even when its transport digest is recomputed'
    );

    await expectFailure(
      () => controller.verifyProducerBundle({
        env: { ...verifierEnv, CNYOS_CANDIDATE_SHA: 'f'.repeat(40) }
      }),
      /CNYOS_PRODUCER_CANDIDATE_COMMIT_MISMATCH/,
      'candidate source binding must reject a different expected commit'
    );

    const sourceTamperBundle = path.join(root, 'source-tamper-bundle');
    await copyBundle(bundleDirectory, sourceTamperBundle);
    const sourceManifestPath = path.join(sourceTamperBundle, 'producer-manifest.json');
    const sourceManifest = JSON.parse(await fs.readFile(sourceManifestPath, 'utf8'));
    sourceManifest.candidateTree = 'e'.repeat(40);
    await writeJson(sourceManifestPath, sourceManifest);
    const sourceManifestBytes = await fs.readFile(sourceManifestPath);
    await expectFailure(
      () => controller.verifyProducerBundle({
        env: {
          ...verifierEnv,
          CNYOS_PRODUCER_BUNDLE_DIRECTORY: sourceTamperBundle,
          CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: digest(sourceManifestBytes)
        }
      }),
      /CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID|CNYOS_PRODUCER_ARTIFACT_DIGEST_MISMATCH/,
      'source-tree tamper must invalidate cross-evidence or aggregate artifact identity'
    );

    const reviewer = deterministicEd25519('reviewer');
    const riskOwner = deterministicEd25519('risk-owner');
    const thirdParty = deterministicEd25519('wrong-signer');
    const registry = {
      schemaVersion: 1,
      environment: controller.policy.target.environment,
      keys: [
        publicRecord({
          id: REVIEWER_KEY_ID,
          role: 'independent_security_reviewer',
          login: 'SECURITY-REVIEWER',
          ownerName: REVIEWER_NAME,
          publicKey: reviewer.publicKey
        }),
        publicRecord({
          id: RISK_KEY_ID,
          role: 'managed_platform_risk_owner',
          login: 'RISK-OWNER',
          ownerName: RISK_NAME,
          publicKey: riskOwner.publicKey
        })
      ]
    };
    const registryPath = path.join(root, 'approver-registry.json');
    await writeJson(registryPath, registry);

    const knownGood = {
      schemaVersion: 1,
      evidenceType: 'cnyos_staging_controller_bootstrap_known_good',
      status: 'passed',
      scope: 'cnyos_staging_only',
      productionAuthorization: false,
      realPatientDataAuthorized: false,
      recordedAt: '2030-01-01T00:00:00.000Z',
      controllerRepository: controller.policy.controller.repository,
      policySha256: controller.policySha256,
      source: { repository: controller.policy.sourceRepository, commit: '9'.repeat(40) },
      target: clone(controller.policy.target),
      netlifyDeployId: PREVIOUS_DEPLOY_ID,
      evidence: pointer('known-good-bootstrap')
    };
    const knownGoodPath = path.join(root, 'known-good.json');
    await writeJson(knownGoodPath, knownGood);
    const knownGoodRaw = await fs.readFile(knownGoodPath, 'utf8');
    const packet = authorizationPacket(controller, verified, digest(knownGoodRaw));
    let authCase = 0;
    const makeAuthorizationEnv = async ({
      value = packet,
      raw = canonical(value),
      registryValue = registry,
      reviewerSigner = reviewer.privateKey,
      riskSigner = riskOwner.privateKey,
      knownGoodPathOverride = knownGoodPath,
      envPatch = {}
    } = {}) => {
      authCase += 1;
      const caseRoot = path.join(root, `authorization-case-${authCase}`);
      await fs.mkdir(caseRoot, { recursive: true });
      const caseRegistryPath = path.join(caseRoot, 'registry.json');
      await writeJson(caseRegistryPath, registryValue);
      return {
        ...verifierEnv,
        CNYOS_EXPECTED_GITHUB_ARTIFACT_DIGEST: GITHUB_ARTIFACT_DIGEST,
        CNYOS_CONTROLLER_AUTHORIZATION_JSON: raw,
        CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64:
          crypto.sign(null, Buffer.from(raw), reviewerSigner).toString('base64'),
        CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64:
          crypto.sign(null, Buffer.from(raw), riskSigner).toString('base64'),
        CNYOS_CONTROLLER_APPROVER_KEY_REGISTRY_PATH: caseRegistryPath,
        CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_PATH: knownGoodPathOverride,
        CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: path.join(caseRoot, 'evidence.json'),
        CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: path.join(caseRoot, 'archive.json'),
        ...envPatch
      };
    };

    const validRaw = canonical(packet);
    const validEnv = await makeAuthorizationEnv({ raw: validRaw });
    const authorized = await controller.verifyControllerAuthorization({
      env: validEnv,
      now: () => new Date(FIXED_NOW)
    });
    assert.equal(authorized.evidence.status, 'authorized');

    const reviewOnlyPacket = clone(packet);
    reviewOnlyPacket.migrationPromotion.pr36RequiredState = 'open_draft_review_only';
    delete reviewOnlyPacket.migrationPromotion.pr36RemainsDraftAndUnapproved;
    reviewOnlyPacket.migrationPromotion.pr36RemainsDraftAndUnmerged = true;
    reviewOnlyPacket.migrationPromotion.pr36ReviewDoesNotAuthorizeExecution = true;
    const reviewOnlyRaw = canonical(reviewOnlyPacket);
    const reviewOnly = await controller.verifyControllerAuthorization({
      env: await makeAuthorizationEnv({ value: reviewOnlyPacket, raw: reviewOnlyRaw }),
      now: () => new Date(FIXED_NOW)
    });
    assert.equal(reviewOnly.evidence.status, 'authorized',
      'signed review-only migration promotion must be accepted');

    for (const [label, envPatch] of [
      ['legacy-security-signature', {
        CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64:
          validEnv.CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64
      }],
      ['legacy-risk-signature', {
        CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64:
          validEnv.CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64
      }]
    ]) {
      await expectFailure(
        async () => controller.verifyControllerAuthorization({
          env: await makeAuthorizationEnv({
            value: reviewOnlyPacket,
            raw: reviewOnlyRaw,
            envPatch
          }),
          now: () => new Date(FIXED_NOW)
        }),
        /CNYOS_CONTROLLER_SIGNATURE_INVALID|CNYOS_CONTROLLER_AUTHORIZATION_INVALID/,
        `review-only packet must reject a ${label} from the legacy packet`
      );
    }

    for (const [label, mutate] of [
      ['missing-required-state', value => { delete value.migrationPromotion.pr36RequiredState; }],
      ['null-required-state', value => { value.migrationPromotion.pr36RequiredState = null; }],
      ['unknown-required-state', value => { value.migrationPromotion.pr36RequiredState = 'open_draft_unknown'; }],
      ['missing-unmerged', value => { delete value.migrationPromotion.pr36RemainsDraftAndUnmerged; }],
      ['null-unmerged', value => { value.migrationPromotion.pr36RemainsDraftAndUnmerged = null; }],
      ['false-unmerged', value => { value.migrationPromotion.pr36RemainsDraftAndUnmerged = false; }],
      ['wrongtype-unmerged', value => { value.migrationPromotion.pr36RemainsDraftAndUnmerged = 'true'; }],
      ['missing-no-execution', value => { delete value.migrationPromotion.pr36ReviewDoesNotAuthorizeExecution; }],
      ['null-no-execution', value => { value.migrationPromotion.pr36ReviewDoesNotAuthorizeExecution = null; }],
      ['false-no-execution', value => { value.migrationPromotion.pr36ReviewDoesNotAuthorizeExecution = false; }],
      ['wrongtype-no-execution', value => { value.migrationPromotion.pr36ReviewDoesNotAuthorizeExecution = 1; }]
    ]) {
      const invalid = clone(reviewOnlyPacket);
      mutate(invalid);
      await expectFailure(
        async () => controller.verifyControllerAuthorization({
          env: await makeAuthorizationEnv({ value: invalid, raw: canonical(invalid) }),
          now: () => new Date(FIXED_NOW)
        }),
        /CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID/,
        `review-only attestation boolean ${label} must fail`
      );
    }

    const mixedReviewOnlyPacket = clone(reviewOnlyPacket);
    mixedReviewOnlyPacket.migrationPromotion.pr36RemainsDraftAndUnapproved = true;
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: mixedReviewOnlyPacket, raw: canonical(mixedReviewOnlyPacket) }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID/,
      'review-only packets must reject mixed legacy fields'
    );

    const mixedLegacyPacket = clone(packet);
    mixedLegacyPacket.migrationPromotion.pr36RemainsDraftAndUnmerged = true;
    mixedLegacyPacket.migrationPromotion.pr36ReviewDoesNotAuthorizeExecution = true;
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: mixedLegacyPacket }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_MIGRATION_PROMOTION_INVALID/,
      'legacy packets must reject mixed review-only fields'
    );

    const stalePolicyKnownGood = clone(knownGood);
    stalePolicyKnownGood.policySha256 = 'f'.repeat(64);
    const stalePolicyKnownGoodPath = path.join(root, 'stale-policy-known-good.json');
    await writeJson(stalePolicyKnownGoodPath, stalePolicyKnownGood);
    const stalePolicyKnownGoodRaw = await fs.readFile(stalePolicyKnownGoodPath, 'utf8');
    const stalePolicyReviewOnlyPacket = clone(reviewOnlyPacket);
    stalePolicyReviewOnlyPacket.rollback.knownGoodEvidence.sha256 =
      digest(stalePolicyKnownGoodRaw);
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({
          value: stalePolicyReviewOnlyPacket,
          raw: canonical(stalePolicyReviewOnlyPacket),
          knownGoodPathOverride: stalePolicyKnownGoodPath
        }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID|CNYOS_CONTROLLER_AUTHORIZATION_INVALID/,
      'freshly signed review-only packet must reject known-good evidence with an incorrect policySha256'
    );

    const validPr36Policy = clone(controller.policy.githubReleaseBoundary);
    controller.assertPr36PolicyConfiguration(validPr36Policy);
    for (const [label, value] of [
      ['missing', (() => { const item = clone(validPr36Policy); delete item.allowedPr36States; return item; })()],
      ['null', { ...validPr36Policy, allowedPr36States: null }],
      ['false', { ...validPr36Policy, allowedPr36States: false }],
      ['unknown', { ...validPr36Policy, allowedPr36States: ['open_draft_unknown'] }],
      ['duplicate', { ...validPr36Policy, allowedPr36States: [...controller.PR36_ALLOWED_REQUIRED_STATES, controller.PR36_ALLOWED_REQUIRED_STATES[0]] }],
      ['reordered', { ...validPr36Policy, allowedPr36States: [...controller.PR36_ALLOWED_REQUIRED_STATES].reverse() }]
    ]) {
      assert.throws(
        () => controller.assertPr36PolicyConfiguration(value),
        /CNYOS_CONTROLLER_GITHUB_RELEASE_POLICY_INVALID/,
        `PR36 policy configuration ${label} must fail closed`
      );
    }

    const unsignedModeSwitch = await makeAuthorizationEnv({ raw: reviewOnlyRaw });
    unsignedModeSwitch.CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64 =
      validEnv.CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64;
    unsignedModeSwitch.CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64 =
      validEnv.CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64;
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: unsignedModeSwitch,
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_SIGNATURE_INVALID|CNYOS_CONTROLLER_AUTHORIZATION_INVALID/,
      'both signatures must bind the selected review-only mode'
    );
    assert.equal(authorized.evidence.productionAuthorization, false);
    assert.equal(authorized.evidence.targetSiteAndPublisherExclusion.productionNetlifySiteId,
      controller.policy.productionDenylist.netlifySiteId);
    assert.equal(authorized.evidence.targetSiteAndPublisherExclusion.productionNetlifyOrigin,
      controller.policy.productionDenylist.netlifyOrigin);

    const wrongProductionSite = clone(packet);
    wrongProductionSite.deploymentControlBoundary.productionNetlifySiteId =
      '00000000-0000-4000-8000-000000000002';
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: wrongProductionSite }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
      'a re-signed packet naming a different Production Site ID must fail'
    );

    const wrongProductionOrigin = clone(packet);
    wrongProductionOrigin.deploymentControlBoundary.productionNetlifyOrigin =
      'https://wrong-production.netlify.app';
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: wrongProductionOrigin }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
      'a re-signed packet naming a different Production origin must fail'
    );

    const recoveryClaimTrueFields = [
      'recoveryClaimAndPlanCorePersistedAtomically',
      'recoveryClaimPlanCoreImmutableAndRetrievable',
      'exactRecoveryClaimRetryIdempotent',
      'authorizedWatchdogRecoveryClaimResumptionEnforced',
      'recoveryAuthorizationRefreshPreservesClaimAndPlanCore',
      'conflictingRecoveryClaimBindingsOrGenerationRejected',
      'incompleteRecoveryRecordPreservesRecoveryClaimAndPlan'
    ];
    for (const field of recoveryClaimTrueFields) {
      for (const mutation of ['delete', 'flip']) {
        const invalidClaimPolicy = clone(packet);
        const broker = invalidClaimPolicy.deploymentControlBoundary
          .externalRollbackReconciliationBroker;
        if (mutation === 'delete') delete broker[field];
        else broker[field] = false;
        await expectFailure(
          async () => controller.verifyControllerAuthorization({
            env: await makeAuthorizationEnv({ value: invalidClaimPolicy }),
            now: () => new Date(FIXED_NOW)
          }),
          /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
          `recovery-claim broker field ${field} must be present and true (${mutation})`
        );
      }
    }
    for (const mutation of ['delete', 'flip']) {
      const invalidClaimExpiry = clone(packet);
      const broker = invalidClaimExpiry.deploymentControlBoundary
        .externalRollbackReconciliationBroker;
      if (mutation === 'delete') delete broker.automaticRecoveryClaimExpiryPermitted;
      else broker.automaticRecoveryClaimExpiryPermitted = true;
      await expectFailure(
        async () => controller.verifyControllerAuthorization({
          env: await makeAuthorizationEnv({ value: invalidClaimExpiry }),
          now: () => new Date(FIXED_NOW)
        }),
        /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
        `automatic recovery-claim expiry must be explicitly forbidden (${mutation})`
      );
    }
    for (const [field, invalidValue] of [
      ['targetControllerRef', 'refs/heads/not-main'],
      ['targetControllerRunAttempt', 2],
      ['targetNetlifySiteId', '00000000-0000-4000-8000-000000000003']
    ]) {
      for (const mutation of ['delete', 'alter']) {
        const invalidClaimBinding = clone(packet);
        const broker = invalidClaimBinding.deploymentControlBoundary
          .externalRollbackReconciliationBroker;
        if (mutation === 'delete') delete broker[field];
        else broker[field] = invalidValue;
        await expectFailure(
          async () => controller.verifyControllerAuthorization({
            env: await makeAuthorizationEnv({ value: invalidClaimBinding }),
            now: () => new Date(FIXED_NOW)
          }),
          /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
          `recovery-claim target binding ${field} must be exact (${mutation})`
        );
      }
    }
    for (const field of [
      'recoveryClaimAuthorizedResumerRepository',
      'recoveryClaimAuthorizedResumerProtectedRef',
      'recoveryClaimAuthorizedResumerWorkflowPaths'
    ]) {
      const missingResumer = clone(packet);
      delete missingResumer.deploymentControlBoundary
        .externalRollbackReconciliationBroker[field];
      await expectFailure(
        async () => controller.verifyControllerAuthorization({
          env: await makeAuthorizationEnv({ value: missingResumer }),
          now: () => new Date(FIXED_NOW)
        }),
        /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
        `recovery-claim resumer binding ${field} must be present`
      );
    }
    const wrongResumerRepository = clone(packet);
    wrongResumerRepository.deploymentControlBoundary.externalRollbackReconciliationBroker
      .recoveryClaimAuthorizedResumerRepository = 'apisarit/wrong-controller';
    const wrongResumerRef = clone(packet);
    wrongResumerRef.deploymentControlBoundary.externalRollbackReconciliationBroker
      .recoveryClaimAuthorizedResumerProtectedRef = 'refs/heads/not-main';
    const wrongResumerPaths = clone(packet);
    wrongResumerPaths.deploymentControlBoundary.externalRollbackReconciliationBroker
      .recoveryClaimAuthorizedResumerWorkflowPaths = [
        controller.policy.controller.rollbackWorkflowPath,
        controller.policy.controller.releaseWorkflowPath
      ];
    for (const [value, label] of [
      [wrongResumerRepository, 'repository'],
      [wrongResumerRef, 'protected ref'],
      [wrongResumerPaths, 'ordered workflow paths']
    ]) {
      await expectFailure(
        async () => controller.verifyControllerAuthorization({
          env: await makeAuthorizationEnv({ value }),
          now: () => new Date(FIXED_NOW)
        }),
        /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_INVALID/,
        `wrong recovery-claim authorized resumer ${label} must fail`
      );
    }

    const archiveRaw = await fs.readFile(authorized.verificationBundlePath, 'utf8');
    const archive = JSON.parse(archiveRaw);
    const reviewerSignature = validEnv.CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64;
    const riskSignature = validEnv.CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64;
    const reviewerPrivatePem = reviewer.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const riskPrivatePem = riskOwner.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const reviewerPrivateDer = reviewer.privateKey.export({ type: 'pkcs8', format: 'der' });
    const riskPrivateDer = riskOwner.privateKey.export({ type: 'pkcs8', format: 'der' });
    assert.equal(archive.secretValuesSerialized, false);
    assert.equal(Object.hasOwn(archive, 'authorizationJson'), false);
    assert.equal(Object.hasOwn(archive, 'knownGoodEvidenceJson'), false);
    assert.equal(Object.hasOwn(archive, 'signaturesBase64'), false);
    for (const forbidden of [
      validRaw,
      knownGoodRaw,
      canonical(knownGood),
      reviewerSignature,
      riskSignature,
      reviewerPrivatePem,
      riskPrivatePem,
      reviewerPrivateDer.toString('base64'),
      riskPrivateDer.toString('base64'),
      reviewerPrivateDer.toString('hex'),
      riskPrivateDer.toString('hex'),
      '-----BEGIN PRIVATE KEY-----'
    ]) {
      assert.equal(archiveRaw.includes(forbidden), false, 'archive must contain no raw/private material');
    }
    assert.deepEqual(Object.keys(archive.knownGoodEvidence).sort(), [
      'evidenceType',
      'netlifyDeployId',
      'netlifyOrigin',
      'netlifySiteId',
      'sourceCommit',
      'sourceRepository'
    ]);

    let depositCase = 0;
    const verifyDeposit = async (envelope, verificationTime = FIXED_NOW) => {
      depositCase += 1;
      const caseRoot = path.join(root, `deposit-case-${depositCase}`);
      await fs.mkdir(caseRoot, { recursive: true });
      const receiptPath = path.join(caseRoot, 'receipt.json');
      const receiptRaw = canonical(envelope);
      await fs.writeFile(receiptPath, receiptRaw, 'utf8');
      return controller.verifyRollbackAttestationDeposit({
        env: {
          ...validEnv,
          CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH: authorized.verificationBundlePath,
          CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256:
            digest(await fs.readFile(authorized.verificationBundlePath)),
          CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH: receiptPath,
          CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256: digest(receiptRaw),
          CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH:
            path.join(caseRoot, 'validation.json')
        },
        now: () => new Date(verificationTime)
      });
    };
    const validDepositEnvelope = rollbackAttestationEnvelope(controller, archive);
    const verifiedDeposit = await verifyDeposit(validDepositEnvelope);
    assert.equal(verifiedDeposit.evidence.status, 'passed');
    assert.equal(verifiedDeposit.evidence.secretValuesSerialized, false);
    assert.equal(verifiedDeposit.evidence.rawPayloadArtifactExposure, false);
    assert.equal(verifiedDeposit.evidence.completeRecoveryMaterialStoredVerified, true);
    const laterVerification = await verifyDeposit(
      validDepositEnvelope,
      new Date(FIXED_NOW.getTime() + 1)
    );
    assert.equal(laterVerification.evidence.status, 'passed',
      'later verification must not restart the full retention period');
    await expectFailure(
      () => verifyDeposit(rollbackAttestationEnvelope(controller, archive, {
        depositedAt: '2030-01-01T00:50:00.000Z',
        retentionUntil: '2031-01-01T00:50:00.000Z'
      }), new Date('2030-01-01T00:50:00.000Z')),
      /CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_STALE/,
      'a broker-signed deposit at authorization expiry must fail'
    );

    for (const field of [
      'authorizationVerificationBundleBytesStored',
      'approverRegistryBytesStored'
    ]) {
      const incompleteRecoveryReceipt = clone(validDepositEnvelope);
      incompleteRecoveryReceipt.receipt.recoveryMaterial[field] = false;
      const incompleteStatement = canonical(incompleteRecoveryReceipt.receipt);
      const incompleteSignature = crypto.sign(
        null,
        Buffer.from(incompleteStatement),
        controller.rollbackBroker.privateKey
      );
      incompleteRecoveryReceipt.brokerSignature.statementSha256 = digest(incompleteStatement);
      incompleteRecoveryReceipt.brokerSignature.signatureBase64 =
        incompleteSignature.toString('base64');
      incompleteRecoveryReceipt.brokerSignature.signatureSha256 = digest(incompleteSignature);
      await expectFailure(
        () => verifyDeposit(incompleteRecoveryReceipt),
        /CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID/,
        `signed receipt must attest stored ${field}`
      );
    }

    const tamperedDeposit = clone(validDepositEnvelope);
    tamperedDeposit.receipt.depositId = 'fixture-deposit:1001:tampered';
    await expectFailure(
      () => verifyDeposit(tamperedDeposit),
      /CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SIGNATURE_INVALID/,
      'broker receipt byte tampering must invalidate its signature'
    );
    await expectFailure(
      () => verifyDeposit(rollbackAttestationEnvelope(controller, archive, {
        retentionUntil: '2030-12-31T00:29:59.000Z'
      })),
      /CNYOS_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT/,
      'broker retention shorter than the protected minimum must fail'
    );
    const wrongNonceDeposit = rollbackAttestationEnvelope(controller, archive);
    wrongNonceDeposit.receipt.controller.dispatchNonce =
      Buffer.alloc(32, 0x31).toString('base64url');
    const wrongNonceStatement = canonical(wrongNonceDeposit.receipt);
    const wrongNonceSignature = crypto.sign(
      null,
      Buffer.from(wrongNonceStatement),
      controller.rollbackBroker.privateKey
    );
    wrongNonceDeposit.brokerSignature.statementSha256 = digest(wrongNonceStatement);
    wrongNonceDeposit.brokerSignature.signatureBase64 = wrongNonceSignature.toString('base64');
    wrongNonceDeposit.brokerSignature.signatureSha256 = digest(wrongNonceSignature);
    await expectFailure(
      () => verifyDeposit(wrongNonceDeposit),
      /CNYOS_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_INVALID/,
      'even a broker-signed receipt for another nonce must fail'
    );

    await expectFailure(
      () => controller.verifyControllerAuthorization({
        env: validEnv,
        now: () => new Date(FIXED_NOW)
      }),
      /EEXIST/,
      'a replay cannot overwrite the exclusive authorization outputs'
    );

    const noncanonicalRaw = JSON.stringify(packet, null, 2);
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ raw: noncanonicalRaw }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_AUTHORIZATION_JSON_NONCANONICAL/,
      'pretty-printed authorization must be rejected as noncanonical'
    );

    const noncanonicalRegistry = clone(registry);
    noncanonicalRegistry.keys[0].publicKeyPem = noncanonicalRegistry.keys[0].publicKeyPem.trimEnd();
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ registryValue: noncanonicalRegistry }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID/,
      'noncanonical public-key PEM must be rejected'
    );

    const privatePemRegistry = clone(registry);
    privatePemRegistry.keys[0].publicKeyPem = reviewerPrivatePem;
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ registryValue: privatePemRegistry }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID/,
      'private-key PEM must never be accepted as a registry public key'
    );

    const unusedPrivatePemRegistry = clone(registry);
    unusedPrivatePemRegistry.keys.push({
      ...publicRecord({
        id: 'fixture-unused-reviewer-v1',
        role: 'independent_security_reviewer',
        login: 'unused-reviewer',
        ownerName: 'Unused Fixture Reviewer',
        publicKey: thirdParty.publicKey
      }),
      publicKeyPem: thirdParty.privateKey.export({ type: 'pkcs8', format: 'pem' })
    });
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ registryValue: unusedPrivatePemRegistry }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_APPROVER_REGISTRY_INVALID/,
      'an unused registry record containing private-key PEM must fail closed'
    );

    const unusedDuplicateRegistry = clone(registry);
    unusedDuplicateRegistry.keys.push({
      ...unusedDuplicateRegistry.keys[0],
      id: 'fixture-unused-duplicate-v1',
      githubLogin: 'unused-duplicate',
      ownerName: 'Unused Duplicate Reviewer'
    });
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ registryValue: unusedDuplicateRegistry }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_APPROVER_REGISTRY_DUPLICATE_FINGERPRINT/,
      'duplicate SPKI fingerprints must fail even on an unused registry record'
    );

    const unknownNested = clone(packet);
    unknownNested.principalProof.evidence.unexpected = true;
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: unknownNested }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_PRINCIPAL_PROOF_INVALID/,
      'unknown nested authorization fields must fail closed'
    );

    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ riskSigner: thirdParty.privateKey }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_SIGNATURE_INVALID/,
      'a signature from an unpinned key must fail'
    );

    const dependentRegistry = clone(registry);
    dependentRegistry.keys[1] = {
      ...dependentRegistry.keys[1],
      publicKeyPem: dependentRegistry.keys[0].publicKeyPem,
      spkiSha256: dependentRegistry.keys[0].spkiSha256
    };
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({
          registryValue: dependentRegistry,
          riskSigner: reviewer.privateKey
        }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_APPROVER_REGISTRY_DUPLICATE_FINGERPRINT/,
      'review and risk signatures must use independent public keys'
    );

    const stalePrincipal = clone(packet);
    stalePrincipal.principalProof.verifiedAt = '2029-12-31T23:59:59.000Z';
    stalePrincipal.principalProof.expiresAt = '2030-01-01T00:30:01.000Z';
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: stalePrincipal }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_PRINCIPAL_PROOF_EXPIRED/,
      'publisher principal evidence older than 30 minutes must fail'
    );

    const staleDeployment = clone(packet);
    staleDeployment.deploymentControlBoundary.observedAt = '2029-12-31T23:59:59.000Z';
    staleDeployment.deploymentControlBoundary.expiresAt = '2030-01-01T00:30:01.000Z';
    staleDeployment.deploymentControlBoundary.rollbackPrincipal.expiresAt =
      '2030-01-01T00:30:01.000Z';
    staleDeployment.authorization.expiresAt = '2030-01-01T00:30:01.000Z';
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: staleDeployment }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_DEPLOYMENT_CONTROL_BOUNDARY_EXPIRED/,
      'deployment control evidence older than 30 minutes must fail'
    );

    const longAuthorization = clone(packet);
    longAuthorization.authorization.authorizedAt = '2030-01-01T00:19:00.000Z';
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: longAuthorization }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_AUTHORIZATION_EXPIRED/,
      'authorization lifetime longer than 30 minutes must fail'
    );

    const wrongRun = clone(packet);
    wrongRun.controller.runId = '1002';
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: wrongRun }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_RUN_BINDING_MISMATCH/,
      'authorization from another run must not be replayable'
    );

    const wrongNonce = clone(packet);
    wrongNonce.controller.dispatchNonce = Buffer.alloc(32, 0x6b).toString('base64url');
    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({ value: wrongNonce }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_CONTROLLER_RUN_BINDING_MISMATCH/,
      'authorization from another dispatch nonce must not be replayable'
    );

    await expectFailure(
      async () => controller.verifyControllerAuthorization({
        env: await makeAuthorizationEnv({
          envPatch: { CNYOS_DISPATCH_NONCE: Buffer.alloc(32, 0x7c).toString('base64url') }
        }),
        now: () => new Date(FIXED_NOW)
      }),
      /CNYOS_PRODUCER_NONCE_MISMATCH/,
      'a bundle from another dispatch nonce must not be replayable'
    );

    process.stdout.write('CNYOS activation contract authorization-foundation-security: passed\n');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

await main();
