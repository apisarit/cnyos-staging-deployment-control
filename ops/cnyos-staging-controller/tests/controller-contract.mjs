import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  EXPECTED_FUNCTION_NAMES,
  FUNCTIONS_REQUIRING_NO_SCHEDULE_OR_CUSTOM_ROUTE,
  POLICY,
  POLICY_SHA256,
  REQUIRED_SCHEDULES,
  aggregateDigest,
  assertControllerRuntime,
  assertDeploymentBoundary,
  canonicalIsoTimestamp,
  exactSha256,
  minimumFutureTimestamp,
  portableRelativePath,
  readFileBounded,
  readRegularFileStable,
  recentCanonicalTimestamp,
  safeOrigin,
  sha1,
  sha256,
  walkRegularFiles
} from '../scripts/policy.mjs';
import {
  assertPreReleaseReconciliationEvidence,
  assertRollbackAttestationRetention,
  assertDraftMetadataPromotionChain,
  assertPreflightDeploymentBoundary,
  assertFunctionMetadata,
  captureNetlifyPreflight,
  parseDeployReceipt,
  promoteExactDraft,
  recordDraftGate,
  recordNetlifyDeployReceipt,
  rollbackPublishedDeployment,
  strictDraftAccessToken,
  validateFunctionEnvironmentGitHubBoundary,
  verifyDraftStaticFiles
} from '../scripts/netlify-evidence.mjs';
import {
  FUNCTION_ENVIRONMENT_PREREQUISITE_ENVIRONMENT_NAMES,
  NETLIFY_CLI_CHILD_ENVIRONMENT_NAMES,
  functionEnvironmentPrerequisiteEnvironment,
  netlifyCliChildEnvironment,
  validateProtectedNetlifyCliProvenance,
  validateFunctionEnvironment
} from '../scripts/validate-function-environment.mjs';
import {
  assertDistinctOpaquePrincipalSubjects,
  sameGitHubLogin
} from '../scripts/verify-authorization.mjs';
import {
  ACTIVATION_PAIRS,
  ACTIVATION_TESTS,
  CLOSED_WORLD_SCRIPT_INVENTORY,
  CLOSED_WORLD_TEST_INVENTORY,
  REQUIRED_ACTIVATION_PREREQUISITES,
  assertClosedWorldEntries
} from '../scripts/run-activation-contracts.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = relative => fs.readFile(path.join(root, relative), 'utf8');

const [release, watchdog, authorization, producer, netlify, finalizer, rollbackAttestation,
  functionEnvironmentValidator, readme, lockRaw, packageRaw, activationRunner] =
  await Promise.all([
    read('workflow/cnyos-staging-controller.template.yml'),
    read('workflow/cnyos-staging-rollback-watchdog.template.yml'),
    read('scripts/verify-authorization.mjs'),
    read('scripts/create-producer-bundle.mjs'),
    read('scripts/netlify-evidence.mjs'),
    read('scripts/finalize-evidence.mjs'),
    read('scripts/verify-rollback-attestation-deposit.mjs'),
    read('scripts/validate-function-environment.mjs'),
    read('README.md'),
    read('package-lock.json'),
    read('package.json'),
    read('scripts/run-activation-contracts.mjs')
  ]);

assert.equal(POLICY.controller.repository, 'apisarit/cnyos-staging-deployment-control');
assert.equal(POLICY.controller.protectedRef, 'refs/heads/main');
assert.equal(POLICY.controller.releaseWorkflowPath, '.github/workflows/cnyos-staging-release.yml');
assert.equal(POLICY.controller.rollbackWorkflowPath,
  '.github/workflows/cnyos-staging-rollback-watchdog.yml');
assert.equal(POLICY.target.netlifySiteId, '7da5e39e-580d-44f1-8623-605313e2fb2b');
assert.deepEqual(POLICY.boundedTreatmentUatTarget, {
  deploymentId: 'chananya-clinical-staging',
  origin: 'https://cnyos-clinical-staging.netlify.app',
  netlifySiteId: '887e058b-6e13-461f-b3c7-ae096b7046fe',
  netlifySiteName: 'cnyos-clinical-staging',
  supabaseProjectRef: POLICY.target.supabaseProjectRef,
  supabaseOrigin: POLICY.target.supabaseOrigin,
  clinicId: POLICY.target.clinicId,
  clinicCode: POLICY.target.clinicCode
});
assert.notEqual(POLICY.boundedTreatmentUatTarget.netlifySiteId,
  POLICY.target.netlifySiteId);
assert.notEqual(POLICY.boundedTreatmentUatTarget.origin, POLICY.target.netlifyOrigin);
assert.equal(POLICY.productionDenylist.netlifySiteId,
  'f1a31624-f90b-4d72-be3d-e91b7e2b2f38');
assert.deepEqual(assertDeploymentBoundary(POLICY), {
  stagingSiteId: '7da5e39e-580d-44f1-8623-605313e2fb2b',
  stagingOrigin: 'https://cnyos.netlify.app',
  productionSiteId: 'f1a31624-f90b-4d72-be3d-e91b7e2b2f38',
  productionOrigin: 'https://chananya.netlify.app'
});
for (const mutate of [
  value => { value.target.netlifySiteId = value.productionDenylist.netlifySiteId; },
  value => { value.target.netlifyOrigin = value.productionDenylist.netlifyOrigin; },
  value => { delete value.productionDenylist.netlifySiteId; },
  value => { value.productionDenylist.netlifySiteId =
    value.productionDenylist.netlifySiteId.toUpperCase(); }
]) {
  const value = structuredClone(POLICY);
  mutate(value);
  assert.throws(() => assertDeploymentBoundary(value),
    /CNYOS_CONTROLLER_DEPLOYMENT_BOUNDARY_INVALID/);
}
const preflightBoundaryFixture = {
  target: structuredClone(POLICY.target),
  targetSiteAndPublisherExclusion: {
    productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
    productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin
  }
};
assert.equal(assertPreflightDeploymentBoundary(preflightBoundaryFixture),
  preflightBoundaryFixture.targetSiteAndPublisherExclusion);
for (const mutate of [
  value => { value.target.netlifyOrigin = POLICY.productionDenylist.netlifyOrigin; },
  value => { value.target.netlifySiteId = POLICY.productionDenylist.netlifySiteId; },
  value => { value.targetSiteAndPublisherExclusion.productionNetlifySiteId =
    POLICY.target.netlifySiteId; },
  value => { value.targetSiteAndPublisherExclusion.productionNetlifyOrigin =
    POLICY.target.netlifyOrigin; }
]) {
  const value = structuredClone(preflightBoundaryFixture);
  mutate(value);
  assert.throws(() => assertPreflightDeploymentBoundary(value),
    /CNYOS_CONTROLLER_PREFLIGHT_DEPLOYMENT_BOUNDARY_INVALID/);
}
assert.equal(POLICY.target.supabaseProjectRef, 'hsmnjwxurlmsizndjlun');
assert.equal(POLICY.productionAuthorization, false);
assert.equal(POLICY.realPatientDataAuthorized, false);
assert.equal(Object.isFrozen(POLICY), true);
assert.equal(Object.isFrozen(POLICY.target), true);
assert.equal(Object.isFrozen(POLICY.externalReconciliationBroker), true);
assert.equal(Object.isFrozen(POLICY.draftLifecycleBroker), true);
assert.equal(Object.isFrozen(POLICY.rollbackPrincipalMembershipBroker), true);
assert.equal(Object.isFrozen(POLICY.rollbackAttestationBroker), true);
assert.equal(POLICY.rollbackAttestationBroker.maximumReceiptAgeMinutes, 10);
assert.equal(POLICY.rollbackAttestationBroker.minimumRetentionDays, 365);
{
  const depositedAt = new Date('2030-01-01T00:00:00.000Z');
  const verifiedAt = new Date(depositedAt.getTime() + 1);
  const observedAt = new Date(depositedAt.getTime() + 2);
  const retentionUntil = new Date(
    depositedAt.getTime() + POLICY.rollbackAttestationBroker.minimumRetentionDays * 86_400_000
  );
  const accepted = assertRollbackAttestationRetention({
    depositedAt: depositedAt.toISOString(),
    verifiedAt: verifiedAt.toISOString(),
    retentionUntil: retentionUntil.toISOString()
  }, observedAt);
  assert.equal(accepted.retentionUntil.toISOString(), retentionUntil.toISOString());
  assert.throws(() => assertRollbackAttestationRetention({
    depositedAt: depositedAt.toISOString(),
    verifiedAt: verifiedAt.toISOString(),
    retentionUntil: new Date(retentionUntil.getTime() - 1).toISOString()
  }, observedAt), /CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT/);
  assert.throws(() => assertRollbackAttestationRetention({
    depositedAt: depositedAt.toISOString(),
    verifiedAt: new Date(retentionUntil.getTime() - 1).toISOString(),
    retentionUntil: retentionUntil.toISOString()
  }, retentionUntil), /CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_RETENTION_INSUFFICIENT/);
}
assert.equal(POLICY.databaseEvidence.maximumAgeMinutes, 30);
const inventoryBaseline = POLICY.databaseEvidence.inventoryBaseline;
assert.equal(inventoryBaseline.schemaVersion, 1);
assert.equal(inventoryBaseline.observerSchemaVersion, 2);
assert.equal(inventoryBaseline.supabaseProjectRef, POLICY.target.supabaseProjectRef);
assert.equal(inventoryBaseline.databaseSystemIdentifier, POLICY.target.databaseSystemIdentifier);
assert.equal(inventoryBaseline.sha256, sha256(JSON.stringify({
  schemaVersion: inventoryBaseline.schemaVersion,
  baselineId: inventoryBaseline.baselineId,
  observerSchemaVersion: inventoryBaseline.observerSchemaVersion,
  supabaseProjectRef: inventoryBaseline.supabaseProjectRef,
  databaseSystemIdentifier: inventoryBaseline.databaseSystemIdentifier,
  counts: inventoryBaseline.counts
})));
if (/^__/.test(POLICY.externalReconciliationBroker.policySha256)) {
  assert.throws(
    () => exactSha256(POLICY.externalReconciliationBroker.policySha256,
      'CNYOS_CONTROLLER_RECONCILIATION_BROKER_POLICY_INVALID'),
    /CNYOS_CONTROLLER_RECONCILIATION_BROKER_POLICY_INVALID/
  );
} else {
  assert.equal(exactSha256(POLICY.externalReconciliationBroker.policySha256,
    'CNYOS_CONTROLLER_RECONCILIATION_BROKER_POLICY_INVALID'),
  POLICY.externalReconciliationBroker.policySha256);
}

const trustPlaceholder = value => /^__[A-Z0-9_]+__$/.test(String(value || ''));
function assertPinnedBrokerTrustBoundary(name, value, operationDomain) {
  const exactKeys = [
    'maximumEvidenceAgeMinutes', 'maximumResponseBytes', 'oidcAudience',
    'operationDomain', 'operationPath', 'origin', 'policyId', 'policySha256',
    'signingKeyId', 'signingKeySpkiSha256', 'signingPublicKeyPem'
  ];
  assert.deepEqual(Object.keys(value).sort(), exactKeys, `${name} closed schema`);
  assert.equal(Object.isFrozen(value), true, `${name} frozen`);
  assert.equal(value.operationDomain, operationDomain, `${name} operation domain`);
  assert.equal(value.maximumEvidenceAgeMinutes, 10, `${name} maximum evidence age`);
  assert.equal(value.maximumResponseBytes, 65536, `${name} maximum response bytes`);

  const pinnedFields = [
    'origin', 'operationPath', 'policyId', 'policySha256', 'signingKeyId',
    'signingPublicKeyPem', 'signingKeySpkiSha256', 'oidcAudience'
  ];
  const placeholderStates = pinnedFields.map(field => trustPlaceholder(value[field]));
  assert.ok(placeholderStates.every(state => state === placeholderStates[0]),
    `${name} must be wholly bootstrap or wholly activated`);
  if (placeholderStates[0]) return;

  assert.equal(safeOrigin(value.origin, `${name}:origin`), value.origin, `${name} exact origin`);
  assert.match(value.operationPath, /^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]+$/,
    `${name} operation path`);
  assert.doesNotMatch(value.operationPath, /(?:^|\/)\.{1,2}(?:\/|$)|\/\//,
    `${name} canonical operation path`);
  const operationUrl = new URL(value.operationPath, value.origin);
  assert.equal(operationUrl.origin, value.origin, `${name} path origin`);
  assert.equal(operationUrl.pathname, value.operationPath, `${name} exact operation path`);
  assert.equal(operationUrl.search, '', `${name} operation query`);
  assert.equal(operationUrl.hash, '', `${name} operation fragment`);
  assert.match(value.policyId, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/,
    `${name} policy id`);
  assert.equal(exactSha256(value.policySha256, `${name}:policySha256`), value.policySha256);
  assert.match(value.signingKeyId, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/,
    `${name} signing key id`);
  let publicKey;
  assert.doesNotThrow(() => { publicKey = createPublicKey(value.signingPublicKeyPem); },
    `${name} public key parse`);
  assert.equal(publicKey.type, 'public', `${name} public key type`);
  assert.equal(publicKey.asymmetricKeyType, 'ed25519', `${name} Ed25519 key`);
  assert.equal(publicKey.export({ type: 'spki', format: 'pem' }), value.signingPublicKeyPem,
    `${name} canonical public PEM`);
  assert.equal(
    sha256(publicKey.export({ type: 'spki', format: 'der' })),
    exactSha256(value.signingKeySpkiSha256, `${name}:signingKeySpkiSha256`),
    `${name} SPKI digest`
  );
  const oidcAudience = new URL(value.oidcAudience);
  assert.equal(oidcAudience.protocol, 'https:', `${name} HTTPS OIDC audience`);
  assert.equal(oidcAudience.username, '', `${name} OIDC audience username`);
  assert.equal(oidcAudience.password, '', `${name} OIDC audience password`);
  assert.equal(oidcAudience.hash, '', `${name} OIDC audience fragment`);
  assert.equal(oidcAudience.href, value.oidcAudience, `${name} canonical OIDC audience`);
}

assertPinnedBrokerTrustBoundary(
  'external publish/reconciliation broker',
  POLICY.externalReconciliationBroker,
  'cnyos_staging_publish_reconciliation'
);
assertPinnedBrokerTrustBoundary(
  'draft lifecycle broker',
  POLICY.draftLifecycleBroker,
  'cnyos_staging_draft_lifecycle'
);
assertPinnedBrokerTrustBoundary(
  'rollback principal membership broker',
  POLICY.rollbackPrincipalMembershipBroker,
  'cnyos_staging_rollback_principal_membership'
);
for (const [name, value] of Object.entries({
  BACKUP_ENABLED: 'false',
  CNYOS_PLATFORM_CONTROL_ENABLED: 'false',
  CNYOS_OWNER_DRIVE_ENABLED: 'false',
  RESTORE_SOURCE_API_ENABLED: 'false',
  GOOGLE_DRIVE_SERVICE_ACCOUNT_ALLOW_RESTORE_TEST_DIRECT_JSON: 'false',
  CNYOS_EVIDENCE_PUBMED_ENABLED: 'false',
  CNYOS_OWNER_CONTROL_ENABLED: 'false'
})) assert.equal(POLICY.functionEnvironment[name], value, name);
const PROTECTED_REQUIRED_SCHEDULES = Object.freeze({
  'database-backup': '0 20 * * *',
  'database-backup-recovery': '*/15 0-2,20-23 * * *'
});
assert.deepEqual(REQUIRED_SCHEDULES, PROTECTED_REQUIRED_SCHEDULES);
assert.deepEqual(FUNCTIONS_REQUIRING_NO_SCHEDULE_OR_CUSTOM_ROUTE,
  ['database-backup-background']);

const validFunctionMetadata = {
  available_functions: EXPECTED_FUNCTION_NAMES.map(name => ({ n: name })),
  function_schedules: Object.entries(REQUIRED_SCHEDULES).map(([name, cron]) => ({ name, cron })),
  functions_config: {}
};
assert.deepEqual(assertFunctionMetadata(validFunctionMetadata),
  Object.entries(REQUIRED_SCHEDULES).map(([name, cron]) => ({ name, cron })));
assert.throws(() => assertFunctionMetadata({
  ...validFunctionMetadata,
  available_functions: validFunctionMetadata.available_functions.map(item => item.n ===
    'database-backup-background' ? { ...item, ro: true } : item)
}), /CNYOS_CONTROLLER_BACKGROUND_FUNCTION_ROUTE_OR_SCHEDULE_PRESENT/);
assert.throws(() => assertFunctionMetadata({
  ...validFunctionMetadata,
  functions_config: {
    'database-backup-background': { routes: [{ pattern: '/unsafe-background-route' }] }
  }
}), /CNYOS_CONTROLLER_BACKGROUND_FUNCTION_ROUTE_OR_SCHEDULE_PRESENT/);
assert.throws(() => assertFunctionMetadata({
  ...validFunctionMetadata,
  function_schedules: [
    ...validFunctionMetadata.function_schedules,
    { name: 'database-backup-background', cron: '* * * * *' }
  ]
}), /CNYOS_CONTROLLER_FUNCTION_SCHEDULE_MISMATCH/);

const lock = JSON.parse(lockRaw);
const packageManifest = JSON.parse(packageRaw);
assert.equal(packageManifest.scripts.test,
  'node tests/controller-contract.mjs && node tests/evidence-publication-contract.mjs && ' +
  'node tests/uat-evidence-schema-contract.mjs && ' +
  'node tests/live-github-release-boundary-contract.mjs && ' +
  'node tests/authorization-foundation-security-contract.mjs && ' +
  'node tests/rollback-principal-boundary-contract.mjs && ' +
  'node tests/rollback-authorization-chain-contract.mjs && ' +
  'node tests/controller-static-reproducibility-contract.mjs && ' +
  'node tests/controller-function-bundle-contract.mjs && ' +
  'node tests/function-recipe-input-contract.mjs && ' +
  'node tests/function-comparison-handoff-contract.mjs && ' +
  'node tests/controller-authenticated-uat-contract.mjs && ' +
  'node tests/controller-uat-evidence-publication-contract.mjs && ' +
  'node tests/controller-uat-access-observations-contract.mjs && ' +
  'node tests/controller-uat-browser-read-policy-contract.mjs && ' +
  'node tests/controller-uat-browser-transport-contract.mjs && ' +
  'node tests/controller-uat-browser-matrix-contract.mjs && ' +
  'node tests/rollback-attestation-deposit-contract.mjs && ' +
  'node tests/release-state-reconciliation-contract.mjs && ' +
  'node tests/netlify-control-file-behavior-contract.mjs && ' +
  'node tests/private-draft-access-boundary-contract.mjs && ' +
  'node tests/scheduled-function-route-denial-contract.mjs && ' +
  'node tests/live-netlify-authority-boundary-contract.mjs && ' +
  'node tests/backup-disable-runtime-boundary-contract.mjs && ' +
  'node tests/runtime-capability-boundary-contract.mjs && ' +
  'node tests/draft-mutation-recovery-contract.mjs && ' +
  'node tests/private-draft-lifecycle-contract.mjs && ' +
  'node tests/netlify-exclusive-publisher-contract.mjs && ' +
  'node tests/rollback-readiness-contract.mjs && ' +
  'node tests/external-broker-trust-boundaries-contract.mjs && ' +
  'node tests/bounded-treatment-uat-contract.mjs && ' +
  'node tests/provision-bounded-treatment-fixture-contract.mjs && ' +
  'node tests/protected-bounded-treatment-workflow-contract.mjs && ' +
  'node tests/local-controller-runtime-contract.mjs && ' +
  'node tests/local-bounded-treatment-workflow-contract.mjs && ' +
  'node tests/exact-staging-release-contract.mjs');
const defaultTestFiles = packageManifest.scripts.test.split(' && ').map(command => {
  assert.match(command, /^node tests\/[a-z0-9-]+-contract\.mjs$/,
    'default contracts must run explicitly without shell fallbacks');
  return command.slice('node tests/'.length);
});
assert.equal(new Set(defaultTestFiles).size, defaultTestFiles.length,
  'default offline contracts must not repeat a test');
const presentTestFiles = (await fs.readdir(path.join(root, 'tests'), { withFileTypes: true }))
  .filter(entry => entry.name.endsWith('-contract.mjs'))
  .map(entry => {
    assert.ok(entry.isFile() && !entry.isSymbolicLink(),
      'default offline contracts must be regular non-symlink files');
    return entry.name;
  }).sort();
assert.deepEqual([...defaultTestFiles].sort(), presentTestFiles,
  'npm test must cover every currently implemented offline contract');
assert.equal(packageManifest.scripts['test:activation'],
  'node scripts/run-activation-contracts.mjs');
assert.equal(packageManifest.scripts['uat:treatment:protected'],
  'node scripts/run-protected-bounded-treatment-uat.mjs');
assert.equal(packageManifest.scripts['test:treatment:local-controller'],
  'node tests/local-controller-runtime-contract.mjs && ' +
  'node tests/local-bounded-treatment-workflow-contract.mjs');
assert.equal(packageManifest.scripts['uat:treatment:local'], undefined,
  'local live UAT must start through the preload-sanitizing shell launcher, not npm');
assert.doesNotMatch(packageManifest.scripts.test, /test:activation|run-activation-contracts/);
assert.equal(lock.lockfileVersion, 3);
assert.equal(lock.packages[''].dependencies['@netlify/blobs'], '10.7.13');
assert.equal(lock.packages[''].dependencies.qrcode, '1.5.4');
assert.deepEqual(lock.packages[''].devDependencies, { playwright: '1.55.1' });
assert.equal(lock.packages['node_modules/playwright']?.version, '1.55.1');
assert.equal(lock.packages['node_modules/playwright-core']?.version, '1.55.1');
if (POLICY.publishing.netlifyCliVersion === '__AUDITED_NETLIFY_CLI_VERSION__') {
  assert.equal(lock.packages['node_modules/netlify-cli'], undefined);
} else {
  assert.match(POLICY.publishing.netlifyCliVersion, /^\d+\.\d+\.\d+$/);
  assert.equal(lock.packages['node_modules/netlify-cli']?.version,
    POLICY.publishing.netlifyCliVersion);
}

const protectedActivationPairs = [
  ['controller-function-bundle', ['scripts/controller-function-bundle.mjs'],
    'tests/controller-function-bundle-contract.mjs'],
  ['controller-authenticated-uat', ['scripts/controller-authenticated-uat.mjs'],
    'tests/controller-authenticated-uat-contract.mjs'],
  ['runtime-capability-boundary', ['scripts/verify-runtime-capability-boundary.mjs'],
    'tests/runtime-capability-boundary-contract.mjs'],
  ['live-netlify-authority-boundary',
    ['scripts/verify-live-netlify-authority-boundary.mjs'],
    'tests/live-netlify-authority-boundary-contract.mjs'],
  ['live-github-release-boundary',
    ['scripts/verify-live-github-release-boundary.mjs'],
    'tests/live-github-release-boundary-contract.mjs'],
  ['authorization-foundation-security', [],
    'tests/authorization-foundation-security-contract.mjs'],
  ['external-broker-trust-boundaries', [
    'scripts/verify-netlify-exclusive-publisher.mjs',
    'scripts/release-netlify-exclusive-publisher.mjs',
    'scripts/reconcile-netlify-release-state.mjs',
    'scripts/verify-private-draft-lifecycle.mjs',
    'scripts/create-netlify-draft-with-durable-intent.mjs',
    'scripts/cleanup-netlify-draft.mjs',
    'scripts/rollback-readiness.mjs'
  ], 'tests/external-broker-trust-boundaries-contract.mjs'],
  ['rollback-attestation-deposit', ['scripts/deposit-rollback-attestation.mjs'],
    'tests/rollback-attestation-deposit-contract.mjs'],
  ['netlify-control-file-behavior', ['scripts/verify-netlify-control-file-behavior.mjs'],
    'tests/netlify-control-file-behavior-contract.mjs'],
  ['netlify-exclusive-publisher', [
    'scripts/verify-netlify-exclusive-publisher.mjs',
    'scripts/release-netlify-exclusive-publisher.mjs'
  ], 'tests/netlify-exclusive-publisher-contract.mjs'],
  ['private-draft-lifecycle', ['scripts/verify-private-draft-lifecycle.mjs'],
    'tests/private-draft-lifecycle-contract.mjs'],
  ['draft-mutation-recovery', [
    'scripts/create-netlify-draft-with-durable-intent.mjs',
    'scripts/cleanup-netlify-draft.mjs'
  ], 'tests/draft-mutation-recovery-contract.mjs'],
  ['release-state-reconciliation', ['scripts/reconcile-netlify-release-state.mjs'],
    'tests/release-state-reconciliation-contract.mjs'],
  ['backup-disable-runtime-boundary', ['scripts/verify-backup-disable-runtime-boundary.mjs'],
    'tests/backup-disable-runtime-boundary-contract.mjs'],
  ['rollback-authorization-chain', ['scripts/verify-rollback-authorization-chain.mjs'],
    'tests/rollback-authorization-chain-contract.mjs'],
  ['rollback-principal-boundary', ['scripts/netlify-evidence.mjs'],
    'tests/rollback-principal-boundary-contract.mjs'],
  ['controller-static-reproducibility', ['scripts/controller-static-reproducibility.mjs'],
    'tests/controller-static-reproducibility-contract.mjs'],
  ['private-draft-access-boundary', ['scripts/private-draft-access-boundary.mjs'],
    'tests/private-draft-access-boundary-contract.mjs'],
  ['scheduled-function-route-denial', ['scripts/scheduled-function-route-denial.mjs'],
    'tests/scheduled-function-route-denial-contract.mjs'],
  ['rollback-readiness', ['scripts/rollback-readiness.mjs'],
    'tests/rollback-readiness-contract.mjs']
].map(([id, scripts, test]) => ({ id, scripts, test }));
assert.deepEqual(ACTIVATION_PAIRS, protectedActivationPairs);
for (const { id, test } of protectedActivationPairs) {
  const contract = ACTIVATION_TESTS.find(item => item.id === id);
  assert.equal(contract?.path, test);
  assert.equal(contract?.marker, `CNYOS activation contract ${id}: passed`);
}
const protectedFoundationScripts = [
  'bounded-treatment-uat.mjs',
  'local-controller-runtime.mjs',
  'provision-bounded-treatment-fixture.mjs',
  'run-local-bounded-treatment-uat.mjs',
  'run-local-bounded-treatment-uat.sh',
  'run-protected-bounded-treatment-uat.mjs',
  'materialize-function-recipe-input.mjs',
  'create-function-comparison-handoff.mjs',
  'controller-uat-access-observations.mjs',
  'controller-uat-browser-read-policy.mjs',
  'controller-uat-browser-transport.mjs',
  'controller-uat-browser-matrix.mjs',
  'controller-uat-evidence-publication.mjs',
  'controller-uat-subscription-evidence.mjs',
  'exact-staging-release.mjs',
  'materialize-exact-staging-config.mjs',
  'prepare-exact-staging-release.mjs',
  'run-exact-staging-clinical-uat.mjs',
  'create-producer-bundle.mjs',
  'finalize-evidence.mjs',
  'netlify-evidence.mjs',
  'policy.mjs',
  'run-activation-contracts.mjs',
  'validate-function-environment.mjs',
  'verify-authorization.mjs',
  'verify-producer-bundle.mjs',
  'verify-rollback-attestation-deposit.mjs'
];
assert.deepEqual(CLOSED_WORLD_SCRIPT_INVENTORY, [...new Set([
  ...protectedFoundationScripts,
  ...protectedActivationPairs.flatMap(pair => pair.scripts.map(item => path.posix.basename(item)))
])].sort());
assert.deepEqual(CLOSED_WORLD_TEST_INVENTORY, [
  'exact-staging-release-contract.mjs',
  'bounded-treatment-uat-contract.mjs',
  'local-bounded-treatment-workflow-contract.mjs',
  'local-controller-runtime-contract.mjs',
  'provision-bounded-treatment-fixture-contract.mjs',
  'protected-bounded-treatment-workflow-contract.mjs',
  'function-recipe-input-contract.mjs',
  'function-comparison-handoff-contract.mjs',
  'controller-uat-access-observations-contract.mjs',
  'controller-uat-browser-read-policy-contract.mjs',
  'controller-uat-browser-transport-contract.mjs',
  'controller-uat-browser-matrix-contract.mjs',
  'controller-uat-evidence-publication-contract.mjs',
  'evidence-publication-contract.mjs',
  'controller-contract.mjs',
  'uat-evidence-schema-contract.mjs',
  ...protectedActivationPairs.map(pair => path.posix.basename(pair.test))
].sort());
assert.equal(new Set(REQUIRED_ACTIVATION_PREREQUISITES).size,
  REQUIRED_ACTIVATION_PREREQUISITES.length);
assert.equal(new Set(CLOSED_WORLD_SCRIPT_INVENTORY).size,
  CLOSED_WORLD_SCRIPT_INVENTORY.length);
assert.equal(new Set(CLOSED_WORLD_TEST_INVENTORY).size,
  CLOSED_WORLD_TEST_INVENTORY.length);
const actualScriptEntries = await fs.readdir(path.join(root, 'scripts'), { withFileTypes: true });
assert.deepEqual(
  assertClosedWorldEntries(actualScriptEntries, CLOSED_WORLD_SCRIPT_INVENTORY, 'scripts'),
  CLOSED_WORLD_SCRIPT_INVENTORY
);
const actualTestEntries = await fs.readdir(path.join(root, 'tests'), { withFileTypes: true });
assert.deepEqual(
  assertClosedWorldEntries(actualTestEntries, CLOSED_WORLD_TEST_INVENTORY, 'tests'),
  CLOSED_WORLD_TEST_INVENTORY
);
assert.match(activationRunner, /await fs\.lstat\(absolutePath\)/);
assert.match(activationRunner,
  /!status\.isFile\(\) \|\| status\.isSymbolicLink\(\) \|\| status\.size < 1/);
assert.match(activationRunner, /assertClosedWorld\('scripts', CLOSED_WORLD_SCRIPT_INVENTORY\)/);
assert.match(activationRunner, /assertClosedWorld\('tests', CLOSED_WORLD_TEST_INVENTORY\)/);
const dirent = (name, kind = 'file') => ({
  name,
  isFile: () => kind === 'file',
  isSymbolicLink: () => kind === 'symlink'
});
assert.deepEqual(assertClosedWorldEntries([dirent('known.mjs')], ['known.mjs'], 'scripts'),
  ['known.mjs']);
for (const entries of [
  [dirent('known.mjs'), dirent('unlisted-helper.js')],
  [dirent('known.mjs'), dirent('unlisted-contract.cjs')],
  [dirent('known.mjs'), dirent('Known.mjs')],
  [dirent('known.mjs'), dirent('known.mjs\u0301')]
]) {
  assert.throws(() => assertClosedWorldEntries(entries, ['known.mjs'], 'scripts'),
    /CNYOS_CONTROLLER_ACTIVATION_SCRIPTS_INVENTORY_MISMATCH/);
}
for (const kind of ['symlink', 'directory']) {
  assert.throws(() => assertClosedWorldEntries([dirent('known.mjs', kind)], ['known.mjs'],
    'scripts'), /CNYOS_CONTROLLER_ACTIVATION_SCRIPTS_ENTRY_NOT_REGULAR/);
}
assert.match(activationRunner, /env: credentialFreeEnvironment\(\)/);
assert.match(activationRunner, /stdio: \['ignore', 'pipe', 'pipe'\]/);
assert.doesNotMatch(activationRunner, /\.\.\.process\.env|process\.env\[/);
assert.match(activationRunner, /result\.stdout !== `\$\{contract\.marker\}\\n`/);
assert.match(activationRunner, /result\.stderr !== ''/);

const workflowActivationFiles = REQUIRED_ACTIVATION_PREREQUISITES.filter(
  relative => relative !== 'scripts/netlify-evidence.mjs'
);
for (const relative of workflowActivationFiles) {
  assert.match(release, new RegExp(`test -f ops/cnyos-staging-controller/${relative.replaceAll('.', '\\.')}`));
  assert.match(watchdog,
    new RegExp(`test -f ops/cnyos-staging-controller/${relative.replaceAll('.', '\\.')}`));
}
assert.match(release,
  /test -f ops\/cnyos-staging-controller\/tests\/uat-evidence-schema-contract\.mjs/);
assert.match(watchdog,
  /test -f ops\/cnyos-staging-controller\/tests\/uat-evidence-schema-contract\.mjs/);
assert.match(release, /for protected_file in/);
assert.match(release, /test ! -L "\$protected_file"/);
assert.match(watchdog, /for protected_file in/);
assert.match(watchdog, /test ! -L "\$protected_file"/);
assert.match(watchdog, /actions\/setup-node@__PINNED_SETUP_NODE_COMMIT_SHA__/);
assert.match(watchdog, /node-version: 24\.20\.0/);
assert.match(watchdog,
  /cache-dependency-path: ops\/cnyos-staging-controller\/package-lock\.json/);
function assertOrdered(source, terms, label) {
  let previous = -1;
  for (const term of terms) {
    const current = source.indexOf(term, previous + 1);
    assert.ok(current > previous, `${label}: ${term}`);
    previous = current;
  }
}
function functionBlock(source, start, end) {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first + start.length);
  assert.ok(first >= 0 && last > first, `${start} source block`);
  return source.slice(first, last);
}
const netlifyTokenLiteral = 'CNYOS_STAGING_NETLIFY_AUTH_TOKEN';
const netlifyTokenAccess = `env.${netlifyTokenLiteral}`;
const countTokenLiterals = source => source.split(netlifyTokenLiteral).length - 1;
const countTokenAccesses = source => source.split(netlifyTokenAccess).length - 1;
const netlifyTokenFunctionBoundaries = [
  ['captureNetlifyPreflight', 'export async function recordDraftGate'],
  ['recordDraftGate', 'export async function recordPromotionAttempt'],
  ['recordNetlifyDeployReceipt', 'export function assertFunctionMetadata'],
  ['verifyDraftMetadata', 'export async function verifyDraftDeployment'],
  ['promoteExactDraft', 'export async function verifyPromotedDeployment'],
  ['verifyPromotedDeployment', 'export async function rollbackPublishedDeployment'],
  ['rollbackPublishedDeployment', 'async function main()']
];
for (const [name, end] of netlifyTokenFunctionBoundaries) {
  const block = functionBlock(netlify, `export async function ${name}`, end);
  assert.equal(countTokenAccesses(block), 1,
    `${name} must contain exactly one behaviorally covered token access`);
  assert.equal(countTokenLiterals(block), 1,
    `${name} must contain exactly one behaviorally covered token literal`);
  assert.match(block,
    /const token = required\(env\.CNYOS_STAGING_NETLIFY_AUTH_TOKEN/,
    `${name} token access must remain fail-closed`);
}
assert.equal(countTokenAccesses(netlify), netlifyTokenFunctionBoundaries.length,
  'Netlify token access outside the seven behaviorally covered functions is forbidden');
assert.equal(countTokenLiterals(netlify), netlifyTokenFunctionBoundaries.length + 1,
  'only the seven token consumers and the draft-verifier absence guard may name the token');
const draftVerificationTokenBoundary = functionBlock(
  netlify,
  'export async function verifyDraftDeployment',
  'export async function promoteExactDraft'
);
assert.equal(countTokenAccesses(draftVerificationTokenBoundary), 0,
  'draft byte verification must not access the Netlify publisher token');
assert.equal(countTokenLiterals(draftVerificationTokenBoundary), 1,
  'draft byte verification may name the publisher token only in its absence guard');
assert.match(draftVerificationTokenBoundary,
  /Object\.hasOwn\(env, 'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'\)/);
const functionEnvironmentTokenBlock = functionBlock(
  functionEnvironmentValidator,
  'export async function validateFunctionEnvironment',
  'const isMain ='
);
assert.equal(countTokenAccesses(functionEnvironmentTokenBlock), 1,
  'validateFunctionEnvironment must contain exactly one behaviorally covered token access');
assert.equal(countTokenLiterals(functionEnvironmentTokenBlock), 1,
  'validateFunctionEnvironment must contain exactly one behaviorally covered token literal');
assert.equal(countTokenAccesses(functionEnvironmentValidator), 1,
  'function-environment token access outside the behaviorally covered function is forbidden');
assert.equal(countTokenLiterals(functionEnvironmentValidator), 1,
  'function-environment token literal outside the behaviorally covered function is forbidden');
assert.match(functionEnvironmentTokenBlock,
  /const token = strictOpaqueToken\(env\.CNYOS_STAGING_NETLIFY_AUTH_TOKEN\)/);
assertOrdered(functionBlock(
  functionEnvironmentValidator,
  'export async function validateFunctionEnvironment',
  'const isMain ='
), [
  'await credentialBoundaryVerifier',
  'const cliProvenance = await cliProvenanceVerifier',
  'const cliStateDirectory = await createNetlifyCliStateDirectory',
  'try {',
  'credentialAccessAt = now()',
  'recentCanonicalTimestamp(',
  'const token = strictOpaqueToken(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
], 'function environment token gate');
assert.match(functionEnvironmentTokenBlock,
  /const cliStateDirectory = await createNetlifyCliStateDirectory\(env, runtime\);[\s\S]*?try \{[\s\S]*?recentCanonicalTimestamp\([\s\S]*?const token = strictOpaqueToken\(env\.CNYOS_STAGING_NETLIFY_AUTH_TOKEN\)/);
assertOrdered(functionBlock(
  functionEnvironmentValidator,
  'export async function validateProtectedNetlifyCliProvenance',
  'async function createNetlifyCliStateDirectory'
), [
  'await assertCanonicalDirectory(root, code)',
  'await assertCanonicalDirectory(nodeModulesRoot, code)',
  'await assertCanonicalDirectory(packageBinRoot, code)',
  'realInstalledPackageRoot = await assertCanonicalDirectory(installedPackageRoot, code)',
  'await assertCanonicalDirectoryChain(',
  'fs.realpath(expectedTarget)',
  'targetRealPath !== expectedTarget',
  '!targetRealPath.startsWith(`${realInstalledPackageRoot}${path.sep}`)'
], 'Netlify CLI canonical package containment');
assertOrdered(functionBlock(
  netlify,
  'export async function captureNetlifyPreflight',
  'export async function recordDraftGate'
), [
  'assertAuthorization(authorization.value, runtime, env, observedAt)',
  'CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH',
  'CNYOS_EXPECTED_RECONCILIATION_EVIDENCE_SHA256',
  'assertPreReleaseReconciliationEvidence(preReleaseReconciliation.value, runtime, observedAt)',
  'const token = required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
], 'pre-release reconciliation gate before publisher-token access');
assertOrdered(functionBlock(
  functionEnvironmentValidator,
  'async function createNetlifyCliStateDirectory',
  'function readNetlifyValue'
), [
  'fs.lstat(runnerTemp)',
  'fs.realpath(runnerTemp)'
], 'runner-temp final-component symlink gate');
assert.doesNotMatch(functionEnvironmentValidator, /\.\.\.process\.env/);
assert.match(functionEnvironmentValidator, /env: childEnvironment/);
assert.match(functionEnvironmentValidator, /cwd: cliStateDirectory/);
assert.doesNotMatch(functionEnvironmentValidator, /\bsandbox\b/i);
for (const [name, end] of [
  ['recordNetlifyDeployReceipt', 'export function assertFunctionMetadata'],
  ['verifyPromotedDeployment', 'export async function rollbackPublishedDeployment']
]) {
  assertOrdered(functionBlock(netlify, `export async function ${name}`, end), [
    'assertFreshPreflight',
    'const token = required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
  ], `${name} token gate`);
}
assertOrdered(functionBlock(
  netlify,
  'export async function verifyDraftMetadata',
  'export async function verifyDraftDeployment'
), [
  'await loadDraftVerificationContext',
  "Object.hasOwn(env, 'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN')",
  'const token = required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
], 'draft metadata token gate');
assert.match(functionBlock(
  netlify,
  'async function loadPreflightAndAttempt',
  'export async function recordNetlifyDeployReceipt'
), /assertPreflightDeploymentBoundary\(preflight\.value\)/);
assertOrdered(functionBlock(
  netlify,
  'export async function rollbackPublishedDeployment',
  'const command = process.argv[2]'
), [
  'await loadPreflightAndAttempt',
  'const token = required(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
], 'rollback token gate');
assertOrdered(release, [
  'npm test',
  'npm run test:activation'
], 'workflow activation test order');
assertOrdered(watchdog, [
  'Bootstrap stop — intentionally fail closed',
  'Check out protected watchdog',
  'Require the complete controller activation boundary',
  "! rg -n '__[A-Z_]+__|BLOCKED_UNTIL'",
  'Set up the protected watchdog test runtime',
  'npm ci --ignore-scripts',
  'npm test',
  'npm run test:activation',
  'Retrieve, authenticate, and sanitize exact-run recovery inputs',
  'Retain only the sanitized signed plan and validated authorization chain',
  'Execute only the hash-bound rollback plan with the rollback principal',
  'Conditionally restore and clean up only plan-authorized Netlify objects',
  'Finalize broker state without any Netlify credential',
  'Finalize only verified success or record incomplete recovery'
], 'watchdog activation, preparation, isolated execution, and finalization order');
assertOrdered(release, [
  'node ops/cnyos-staging-controller/scripts/verify-live-netlify-authority-boundary.mjs',
  'echo "evidence_sha256=$(sha256sum "$CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH"',
  'CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256: ${{ needs.prepare_function_environment_authorization.outputs.live_netlify_authority_sha256 }}',
  'node ops/cnyos-staging-controller/scripts/netlify-evidence.mjs preflight'
], 'fresh live Netlify authority boundary order');
assert.ok(release.includes(
  'CNYOS_NETLIFY_AUTHORITY_BROKER_URL: ${{ vars.CNYOS_NETLIFY_AUTHORITY_BROKER_URL }}'
));
for (const required of [
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: ${{ secrets.CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN }}',
  'CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL: ${{ vars.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL }}',
  'CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH: ${{ github.workspace }}/controller/release-chain/evidence/draft-access-boundary.json',
  'CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256: ${{ steps.draft_access.outputs.evidence_sha256 }}'
]) assert.ok(release.includes(required), required);
assertOrdered(release, [
  '\n  verify_draft_metadata:',
  'Verify exact draft metadata without access-boundary credential',
  'node ops/cnyos-staging-controller/scripts/netlify-evidence.mjs verify-draft-metadata',
  'Retain only the publisher-derived draft metadata',
  '\n  verify_draft_content:',
  'Verify private draft access boundary without publisher credential',
  'node ops/cnyos-staging-controller/scripts/private-draft-access-boundary.mjs',
  'Verify exact draft while current remains unchanged',
  'node ops/cnyos-staging-controller/scripts/netlify-evidence.mjs verify-draft',
  'Verify Netlify control-file behavior without publisher credential',
  'node ops/cnyos-staging-controller/scripts/verify-netlify-control-file-behavior.mjs',
  'Retain only access-boundary-derived draft evidence',
  '\n  verify_draft:',
  'Verify private draft lifecycle without access-boundary credential',
  'node ops/cnyos-staging-controller/scripts/verify-private-draft-lifecycle.mjs',
  'Bind exact hashes from every credential-isolated draft runner',
  'Retain the complete cross-runner draft verification chain'
], 'private draft boundary order');
assertOrdered(release, [
  'node ops/cnyos-staging-controller/scripts/netlify-evidence.mjs verify-promoted',
  'Retain only the publisher-derived promotion evidence',
  '\n  validate_promoted_routes:',
  'Deny public scheduled Function routes without publisher credentials',
  'node ops/cnyos-staging-controller/scripts/scheduled-function-route-denial.mjs',
  '\n  run_promoted_uat:',
  'node ops/cnyos-staging-controller/scripts/controller-authenticated-uat.mjs',
  '\n  verify_promoted_final_current:',
  'node ops/cnyos-staging-controller/scripts/netlify-evidence.mjs verify-final-current'
], 'scheduled route denial order');
assertOrdered(release, [
  'node ops/cnyos-staging-controller/scripts/netlify-evidence.mjs verify-final-current',
  'node ops/cnyos-staging-controller/scripts/release-netlify-exclusive-publisher.mjs',
  'echo "publisher_release_sha256=',
  'node ops/cnyos-staging-controller/scripts/finalize-evidence.mjs',
  'name: cnyos-final-${{ github.run_id }}',
  '\n  commit_successful_release:',
  'reconcile-netlify-release-state.mjs commit-successful-release',
  'name: cnyos-successful-release-terminal-${{ github.run_id }}'
], 'publisher release order');

function workflowStepSlice(name) {
  const marker = `      - name: ${name}`;
  const start = release.indexOf(marker);
  assert.notEqual(start, -1, `workflow step missing: ${name}`);
  const next = release.indexOf('\n      - name:', start + marker.length);
  return release.slice(start, next === -1 ? release.length : next);
}

function secretReferences(step) {
  const references = [...step.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g)]
    .map(match => match[1])
    .sort();
  assert.equal((step.match(/\bsecrets\b/g) || []).length, references.length,
    'noncanonical or hidden secret expression');
  return references;
}

function uniqueSecretReferences(source) {
  return [...new Set(secretReferences(source))].sort();
}

const promoteStep = workflowStepSlice('Promote only the receipt-bound draft');
const promotionAttemptStep = workflowStepSlice(
  'Acquire lease and persist exact promotion attempt without deployment or database credentials'
);
const authorizationStep = workflowStepSlice(
  'Validate exact-run signatures without deployment, database, rollback, or OIDC credentials'
);
const precredentialGitHubStep = workflowStepSlice(
  'Query PR 36 and the separate promotion PR with read-only identity'
);
const prepromotionGitHubStep = workflowStepSlice(
  'Requery PR 36 and the separate promotion PR with read-only identity'
);
const depositStep = workflowStepSlice(
  'Deposit exact recovery inputs with the immutable attestation broker'
);
const attestationStep = workflowStepSlice(
  'Verify the broker-signed sanitized attestation receipt'
);
const liveAuthorityStep = workflowStepSlice(
  'Obtain a signed live publisher-boundary attestation without deployment credentials'
);
const credentialReleasePrerequisiteStep = workflowStepSlice(
  'Seal publisher credential-release prerequisites without publisher credential'
);
const functionEnvironmentStep = workflowStepSlice(
  'Validate exact staging Function environment with released publisher credential'
);
const runtimeBoundariesStep = workflowStepSlice(
  'Verify backup-disable and runtime-capability boundaries without privileged credentials'
);
const runtimePrerequisiteStep = workflowStepSlice(
  'Re-hash runtime-boundary prerequisites without privileged credentials'
);
const preflightStep = workflowStepSlice(
  'Capture signed rollback target with released publisher credential'
);
const preflightChainRehashStep = workflowStepSlice(
  'Re-hash the complete preflight chain without publisher credential'
);
const draftGateStep = workflowStepSlice(
  'Recheck authorization, principal, and unchanged current deploy'
);
const prepareFunctionEnvironmentStart = release.indexOf(
  '\n  prepare_function_environment_authorization:'
);
const authorizeFunctionEnvironmentStart = release.indexOf('\n  authorize_function_environment:');
const runtimeBoundariesJobStart = release.indexOf(
  '\n  verify_runtime_boundaries:',
  authorizeFunctionEnvironmentStart
);
const runtimeProofJobStart = release.indexOf('\n  acquire_runtime_boundary_proof:',
  authorizeFunctionEnvironmentStart);
const authorizePreflightStart = release.indexOf(
  '\n  authorize_preflight:',
  runtimeBoundariesJobStart
);
const prepareRollbackReadinessStart = release.indexOf(
  '\n  prepare_rollback_readiness:',
  authorizePreflightStart
);
const rollbackReadinessStart = release.indexOf(
  '\n  rollback_readiness:',
  prepareRollbackReadinessStart
);
assert.ok(prepareFunctionEnvironmentStart >= 0 &&
  authorizeFunctionEnvironmentStart > prepareFunctionEnvironmentStart &&
  runtimeBoundariesJobStart > authorizeFunctionEnvironmentStart &&
  authorizePreflightStart > runtimeBoundariesJobStart &&
  prepareRollbackReadinessStart > authorizePreflightStart &&
  rollbackReadinessStart > prepareRollbackReadinessStart,
'split preflight job topology');
const authorizeReleaseStart = release.indexOf('\n  authorize_release:');
const precredentialGitHubJobStart = release.indexOf(
  '\n  verify_github_release_boundary_precredential:'
);
const prepromotionGitHubJobStart = release.indexOf(
  '\n  verify_github_release_boundary_prepromotion:'
);
const acquirePublisherJobStart = release.indexOf('\n  acquire_exclusive_publisher:');
const promoteJobStart = release.indexOf('\n  promote_and_validate:');
assert.ok(authorizeReleaseStart >= 0 &&
  prepareFunctionEnvironmentStart > authorizeReleaseStart &&
  precredentialGitHubJobStart > prepareFunctionEnvironmentStart &&
  authorizeFunctionEnvironmentStart > precredentialGitHubJobStart &&
  prepromotionGitHubJobStart > rollbackReadinessStart &&
  acquirePublisherJobStart > prepromotionGitHubJobStart &&
  promoteJobStart > acquirePublisherJobStart,
'isolated live GitHub release-boundary topology');
const precredentialGitHubJob = release.slice(
  precredentialGitHubJobStart,
  authorizeFunctionEnvironmentStart
);
const prepareFunctionEnvironmentJob = release.slice(
  prepareFunctionEnvironmentStart,
  precredentialGitHubJobStart
);
const prepromotionGitHubJob = release.slice(
  prepromotionGitHubJobStart,
  acquirePublisherJobStart
);
for (const job of [precredentialGitHubJob, prepromotionGitHubJob]) {
  assert.match(job, /permissions:\n\s+contents: read\n\s+pull-requests: read/);
  assert.doesNotMatch(job, /^\s+environment:/m);
  assert.doesNotMatch(job, /^\s+id-token:\s*write\s*$/m);
}
for (const step of [precredentialGitHubStep, prepromotionGitHubStep]) {
  assert.deepEqual(secretReferences(step), []);
  assert.match(step,
    /CNYOS_GITHUB_ACTIONS_READ_TOKEN: \$\{\{ github\.token \}\}/);
  assert.match(step, /verify-live-github-release-boundary\.mjs query/);
  assert.doesNotMatch(step,
    /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN):\s*.+$/m);
}
const authorizeFunctionEnvironmentJob = release.slice(
  authorizeFunctionEnvironmentStart,
  runtimeProofJobStart
);
const runtimeProofJob = release.slice(runtimeProofJobStart, runtimeBoundariesJobStart);
assert.ok(runtimeProofJobStart > authorizeFunctionEnvironmentStart &&
  runtimeProofJobStart < runtimeBoundariesJobStart, 'OIDC acquisition has its own runner');
assert.match(runtimeProofJob, /id-token: write/);
assert.deepEqual(secretReferences(runtimeProofJob), []);
assert.match(runtimeProofJob, /needs: \[produce, authorize_function_environment\]/);
assert.match(runtimeProofJob, /verify-runtime-capability-boundary\.mjs acquire/);
assert.match(runtimeProofJob, /CNYOS_RUNTIME_EVIDENCE_BROKER_URL: \$\{\{ vars\.CNYOS_RUNTIME_EVIDENCE_BROKER_URL \}\}/);
assert.match(runtimeBoundariesStep, /CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256: \$\{\{ needs\.acquire_runtime_boundary_proof\.outputs\.runtime_proof_sha256 \}\}/);
const runtimeBoundariesJob = release.slice(runtimeBoundariesJobStart, authorizePreflightStart);
const authorizePreflightJob = release.slice(
  authorizePreflightStart,
  prepareRollbackReadinessStart
);
const firstCredentialStepStart = release.indexOf(
  '      - name: Validate exact staging Function environment with released publisher credential',
  authorizeFunctionEnvironmentStart
);
assert.ok(firstCredentialStepStart > authorizeFunctionEnvironmentStart &&
  firstCredentialStepStart < runtimeBoundariesJobStart,
'authorization and Function-environment workflow topology');
const authorizePreflightBeforeCredentialRelease = release.slice(
  authorizeFunctionEnvironmentStart,
  firstCredentialStepStart
);
assert.match(authorizeFunctionEnvironmentJob,
  /\n    environment: cnyos-staging-publish\n/);
assert.doesNotMatch(authorizeFunctionEnvironmentJob, /^\s+id-token:\s*write\s*$/m);
assert.match(authorizeFunctionEnvironmentJob, /\n    timeout-minutes: 5\n/);
assert.match(authorizeFunctionEnvironmentJob,
  /needs: \[authorize_release, prepare_function_environment_authorization, verify_github_release_boundary_precredential\]/);
assert.match(prepareFunctionEnvironmentJob,
  /\n    environment: cnyos-staging-publish\n/);
assert.match(prepareFunctionEnvironmentJob, /\n      id-token: write\n/);
assert.doesNotMatch(prepareFunctionEnvironmentJob,
  /\$\{\{\s*secrets\.CNYOS_STAGING_NETLIFY_AUTH_TOKEN\s*\}\}/);
assert.match(precredentialGitHubJob,
  /needs: \[produce, authorize_release, prepare_function_environment_authorization\]/);
assert.match(authorizePreflightJob, /\n    permissions:\n      contents: read\n/);
assert.doesNotMatch(authorizePreflightJob, /^\s+id-token:\s*write\s*$/m);
assert.doesNotMatch(authorizePreflightBeforeCredentialRelease,
  /\$\{\{\s*secrets\.CNYOS_STAGING_NETLIFY_AUTH_TOKEN\s*\}\}/,
  'publisher secret reference before credential-release step');
assert.doesNotMatch(authorizePreflightBeforeCredentialRelease,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN):\s*.+$/m,
  'publisher token environment mapping before credential-release step');
const preflightUploadStep = workflowStepSlice(
  'Durably retain authorization and preflight before mutation'
);
const draftUploadStep = workflowStepSlice('Retain draft evidence');
const draftVerificationUploadStep = workflowStepSlice(
  'Retain the complete cross-runner draft verification chain'
);
const draftAccessStep = workflowStepSlice(
  'Verify private draft access boundary without publisher credential'
);
const draftMetadataStep = workflowStepSlice(
  'Verify exact draft metadata without access-boundary credential'
);
const verifyDraftStep = workflowStepSlice('Verify exact draft while current remains unchanged');
const controlBehaviorStep = workflowStepSlice(
  'Verify Netlify control-file behavior without publisher credential'
);
const privateDraftStep = workflowStepSlice(
  'Verify private draft lifecycle without access-boundary credential'
);
const bindDraftEvidenceStep = workflowStepSlice(
  'Bind exact hashes from every credential-isolated draft runner'
);
const verifyPromotedStep = workflowStepSlice('Verify promoted bytes');
const scheduledRouteDenialStep = workflowStepSlice(
  'Deny public scheduled Function routes without publisher credentials'
);
const uatStep = workflowStepSlice(
  'Run synthetic authenticated UAT without publisher credentials'
);
const finalCurrentStep = workflowStepSlice('Recheck exact current deploy after UAT');
const bindPromotionEvidenceStep = workflowStepSlice(
  'Bind exact hashes from every credential-isolated promotion runner'
);
const releasePublisherStep = workflowStepSlice(
  'Atomically release the publisher lease while retaining the run barrier'
);
const completeReleaseEvidenceStep = workflowStepSlice(
  'Require the complete direct-producer evidence set as regular files'
);
const finalizeStep = workflowStepSlice(
  'Close the cross-linked evidence set in a credential-free process'
);
const terminalCommitStep = workflowStepSlice(
  'Commit the exact successful release as the terminal broker operation'
);
const terminalReceiptUploadStep = workflowStepSlice(
  'Retain the signed successful-release terminal record'
);
function workflowJobSlice(source, name) {
  const marker = `\n  ${name}:`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `workflow job missing: ${name}`);
  const tailStart = start + marker.length;
  const nextMatch = source.slice(tailStart).match(/\n  [A-Za-z0-9_]+:\n/);
  const end = nextMatch ? tailStart + nextMatch.index : source.length;
  return source.slice(start, end);
}
function namedWorkflowStepSlice(source, name) {
  const marker = `      - name: ${name}`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `workflow step missing: ${name}`);
  const next = source.indexOf('\n      - name:', start + marker.length);
  return source.slice(start, next === -1 ? source.length : next);
}
const watchdogActivationJob = workflowJobSlice(watchdog, 'validate_watchdog_activation');
const watchdogPrepareJob = workflowJobSlice(watchdog, 'prepare_recovery');
const watchdogExecuteJob = workflowJobSlice(watchdog, 'execute_recovery');
const watchdogFinalizeJob = workflowJobSlice(watchdog, 'finalize_recovery');
const watchdogPrepareStep = namedWorkflowStepSlice(
  watchdog,
  'Retrieve, authenticate, and sanitize exact-run recovery inputs'
);
const watchdogExecuteStep = namedWorkflowStepSlice(
  watchdog,
  'Conditionally restore and clean up only plan-authorized Netlify objects'
);
const watchdogFinalizeStep = namedWorkflowStepSlice(
  watchdog,
  'Finalize only verified success or record incomplete recovery'
);
assertOrdered(watchdog, [
  '\n  validate_watchdog_activation:',
  '\n  prepare_recovery:',
  '\n  execute_recovery:',
  '\n  finalize_recovery:'
], 'watchdog activation and recovery credential-isolation topology');
assert.match(watchdogActivationJob,
  /permissions:\n\s+contents: read/);
assert.doesNotMatch(watchdogActivationJob, /^\s+id-token:\s*write\s*$/m);
assert.deepEqual(secretReferences(watchdogActivationJob), []);
assert.match(watchdogActivationJob,
  /test -z "\$\{ACTIONS_ID_TOKEN_REQUEST_URL\+set\}"/);
assert.match(watchdogActivationJob, /npm test\n\s+npm run test:activation/);
assert.match(watchdogPrepareJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: write/);
assert.match(watchdogPrepareJob, /needs: validate_watchdog_activation/);
assert.match(watchdogPrepareJob,
  /CNYOS_CONTROLLER_RECOVERY_PLAN_PATH:[\s\S]*CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH:/);
assert.deepEqual(secretReferences(watchdogPrepareJob), []);
assert.match(watchdogPrepareStep, /test -n "\$\{ACTIONS_ID_TOKEN_REQUEST_URL:-\}"/);
assert.match(watchdogPrepareStep, /prepare-watchdog-recovery/);
assert.match(watchdogPrepareStep,
  /CNYOS_ROLLBACK_ATTESTATION_BROKER_URL: \$\{\{ vars\.CNYOS_ROLLBACK_ATTESTATION_BROKER_URL \}\}/);
assert.match(watchdogPrepareStep,
  /CNYOS_NETLIFY_PUBLISH_BROKER_URL: \$\{\{ vars\.CNYOS_NETLIFY_PUBLISH_BROKER_URL \}\}/);
assert.match(watchdogPrepareStep,
  /CNYOS_DRAFT_LIFECYCLE_BROKER_URL: \$\{\{ vars\.CNYOS_DRAFT_LIFECYCLE_BROKER_URL \}\}/);
assert.match(watchdogPrepareJob,
  /recovery_disposition: \$\{\{ steps\.prepare\.outputs\.recovery_disposition \}\}/);
assert.match(watchdogPrepareJob,
  /terminal_receipt_sha256: \$\{\{ steps\.prepare\.outputs\.terminal_receipt_sha256 \}\}/);
assert.match(watchdogPrepareJob,
  /recovery_terminal_receipt_sha256: \$\{\{ steps\.prepare\.outputs\.recovery_terminal_receipt_sha256 \}\}/);
assert.match(watchdogPrepareStep,
  /case "\$recovery_disposition" in[\s\S]*recovery_required\)[\s\S]*terminal_success_rehydrated\)[\s\S]*terminal_recovery_rehydrated\)/);
assert.match(watchdogPrepareStep,
  /CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH:/);
assert.doesNotMatch(watchdogPrepareStep,
  /CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN:\s*\$\{\{\s*secrets\./);

assert.match(watchdogExecuteJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: none/);
assert.match(watchdogExecuteJob,
  /if: \$\{\{ always\(\) && needs\.prepare_recovery\.result == 'success' && needs\.prepare_recovery\.outputs\.recovery_disposition == 'recovery_required' \}\}/);
assert.deepEqual(secretReferences(watchdogExecuteJob), [
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN'
]);
assert.match(watchdogExecuteStep,
  /CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: \$\{\{ secrets\.CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN \}\}/);
assert.match(watchdogExecuteStep, /execute-watchdog-recovery-plan/);
assert.match(watchdogExecuteStep,
  /sha256sum "\$CNYOS_CONTROLLER_RECOVERY_PLAN_PATH"[\s\S]*"\$CNYOS_EXPECTED_RECOVERY_PLAN_SHA256"/);
assert.match(watchdogExecuteStep,
  /sha256sum "\$CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH"[\s\S]*"\$CNYOS_EXPECTED_ROLLBACK_CHAIN_EVIDENCE_SHA256"/);
assert.doesNotMatch(watchdogExecuteJob,
  /CNYOS_(?:ROLLBACK_ATTESTATION|NETLIFY_PUBLISH|DRAFT_LIFECYCLE|NETLIFY_AUTHORITY|NETLIFY_PRINCIPAL_MEMBERSHIP)_BROKER_URL:\s*\$\{\{/);
assert.doesNotMatch(watchdogExecuteJob,
  /CNYOS_STAGING_NETLIFY_AUTH_TOKEN:\s*\$\{\{\s*secrets\.|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY:\s*\$\{\{\s*secrets\./);

assert.match(watchdogFinalizeJob,
  /if: \$\{\{ always\(\) && github\.event\.workflow_run\.conclusion != 'success' && needs\.validate_watchdog_activation\.result == 'success' \}\}/);
assert.match(watchdogFinalizeJob,
  /needs: \[validate_watchdog_activation, prepare_recovery, execute_recovery\]/);
assert.doesNotMatch(watchdogFinalizeJob,
  /if: \$\{\{ always\(\) && needs\.prepare_recovery\.result == 'success' \}\}/);
assert.match(watchdogFinalizeJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: write/);
assert.deepEqual(secretReferences(watchdogFinalizeJob), []);
assert.match(watchdogFinalizeStep, /test -n "\$\{ACTIONS_ID_TOKEN_REQUEST_URL:-\}"/);
assert.match(watchdogFinalizeStep,
  /CNYOS_RECOVERY_PREPARATION_JOB_RESULT: \$\{\{ needs\.prepare_recovery\.result \}\}/);
assert.match(watchdogFinalizeStep,
  /if test "\$CNYOS_RECOVERY_PREPARATION_JOB_RESULT" = "success" &&/);
assert.match(watchdogFinalizeStep, /finalize-watchdog-recovery-success/);
assert.match(watchdogFinalizeStep, /finalize-rehydrated-successful-release/);
assert.match(watchdogFinalizeStep, /finalize-rehydrated-recovery/);
assert.match(watchdogFinalizeStep, /record-incomplete-watchdog-recovery/);
assertOrdered(watchdogFinalizeStep, [
  'recovery_inputs_verified=false',
  'execution_receipt_verified=false',
  'sha256sum "$CNYOS_CONTROLLER_RECOVERY_EXECUTION_RECEIPT_PATH"',
  'terminal_success_verified=false',
  'CNYOS_RECOVERY_DISPOSITION" = "terminal_success_rehydrated',
  'if test "$recovery_inputs_verified" = "true" &&',
  'CNYOS_RECOVERY_DISPOSITION" = "recovery_required',
  'finalize-watchdog-recovery-success',
  'elif test "$terminal_success_verified" = "true"',
  'finalize-rehydrated-successful-release',
  'elif test "$terminal_recovery_verified" = "true"',
  'finalize-rehydrated-recovery',
  'else',
  'record-incomplete-watchdog-recovery'
], 'watchdog separates rollback-required and terminal-success dispositions');
assert.doesNotMatch(watchdogFinalizeJob,
  /CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN:\s*\$\{\{\s*secrets\.|CNYOS_STAGING_NETLIFY_AUTH_TOKEN:\s*\$\{\{\s*secrets\./);
assert.deepEqual(secretReferences(watchdog), ['CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN']);

assert.deepEqual(secretReferences(liveAuthorityStep), []);
assert.match(liveAuthorityStep,
  /CNYOS_NETLIFY_AUTHORITY_BROKER_URL: \$\{\{ vars\.CNYOS_NETLIFY_AUTHORITY_BROKER_URL \}\}/);
assert.doesNotMatch(liveAuthorityStep,
  /CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN/);

assert.deepEqual(secretReferences(credentialReleasePrerequisiteStep), []);
assert.doesNotMatch(credentialReleasePrerequisiteStep,
  /CNYOS_STAGING_NETLIFY_AUTH_TOKEN:\s*\$\{\{\s*secrets\.|NETLIFY_AUTH_TOKEN:\s*\$\{\{/);
for (const name of [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN'
]) {
  assert.match(credentialReleasePrerequisiteStep,
    new RegExp(`test -z "\\$\\{${name}\\+set\\}"`), `${name} prerequisite absence`);
}
for (const [pathName, digestName] of [
  ['CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH',
    'CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH',
    'CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256'],
  ['CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH',
    'CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256'],
  ['CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH',
    'CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH',
    'CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256']
]) {
  assert.match(credentialReleasePrerequisiteStep,
    new RegExp(`sha256sum "\\$${pathName}"[\\s\\S]*"\\$${digestName}"`),
    `${pathName} credential-release binding`);
}
assert.match(credentialReleasePrerequisiteStep, /echo "sealed=true" >> "\$GITHUB_OUTPUT"/);
assert.match(credentialReleasePrerequisiteStep,
  /verify-live-github-release-boundary\.mjs validate-evidence(?:\s|$)/);
assert.doesNotMatch(credentialReleasePrerequisiteStep,
  /validate-historical-precredential-evidence/);
assert.match(preflightChainRehashStep,
  /verify-live-github-release-boundary\.mjs validate-historical-precredential-evidence/);

assert.deepEqual(secretReferences(functionEnvironmentStep), [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.match(functionEnvironmentStep,
  /if: \$\{\{ steps\.credential_release\.outputs\.sealed == 'true' \}\}/);
assert.match(functionEnvironmentStep, /validate-function-environment\.mjs/);
assert.match(functionEnvironmentStep,
  /echo "evidence_sha256=\$\(sha256sum "\$CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH"/);
assert.match(functionEnvironmentStep, /echo "validated=true" >> "\$GITHUB_OUTPUT"/);
assert.doesNotMatch(functionEnvironmentStep,
  /verify-backup-disable-runtime-boundary|verify-runtime-capability-boundary|netlify-evidence\.mjs preflight|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN/);

assert.deepEqual(secretReferences(runtimeBoundariesJob), []);
assert.match(runtimeBoundariesJob, /\n    permissions:\n      contents: read\n/);
assert.doesNotMatch(runtimeBoundariesJob, /^\s+environment:/m);
assert.doesNotMatch(runtimeBoundariesJob, /^\s+id-token:\s*write\s*$/m);
assert.match(runtimeBoundariesJob,
  /needs: \[produce, authorize_function_environment, acquire_runtime_boundary_proof\]/);
assert.match(runtimeBoundariesJob,
  /name: cnyos-function-environment-\$\{\{ github\.run_id \}\}/);
assert.match(runtimeBoundariesJob,
  /name: cnyos-runtime-boundaries-\$\{\{ github\.run_id \}\}/);
for (const step of [runtimePrerequisiteStep, runtimeBoundariesStep]) {
  assert.deepEqual(secretReferences(step), []);
  assert.match(step,
    /CNYOS_PRODUCER_BUNDLE_DIRECTORY: \$\{\{ github\.workspace \}\}\/controller\/release-input/);
  assert.match(step,
    /CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: \$\{\{ needs\.produce\.outputs\.manifest_sha256 \}\}/);
  for (const name of [
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_URL',
    'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
    'NETLIFY_AUTH_TOKEN',
    'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
    'CNYOS_STAGING_TEST_PASSWORD',
    'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
    'CNYOS_GITHUB_ACTIONS_READ_TOKEN'
  ]) {
    assert.match(step,
      new RegExp(`test -z "\\$\\{${name}\\+set\\}"`), `${name} runtime-boundary absence`);
  }
}
assert.deepEqual(secretReferences(runtimeBoundariesStep), []);
assert.match(runtimeBoundariesStep,
  /CNYOS_EXPECTED_FUNCTION_ENV_EVIDENCE_SHA256: \$\{\{ needs\.authorize_function_environment\.outputs\.function_environment_sha256 \}\}/);
assertOrdered(runtimeBoundariesStep, [
  'verify-backup-disable-runtime-boundary.mjs',
  'BACKUP_DISABLE_SHA=',
  'verify-runtime-capability-boundary.mjs',
  'RUNTIME_CAPABILITY_SHA=',
  'echo "runtime_capability_sha256='
], 'privileged-credential-free runtime boundary order');
assert.doesNotMatch(runtimeBoundariesStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN):\s*.+$/m);
assert.doesNotMatch(runtimeBoundariesStep,
  /netlify-evidence\.mjs preflight|validate-function-environment\.mjs/);

assert.deepEqual(secretReferences(authorizationStep), [
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64'
]);
assert.doesNotMatch(authorizationStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN):\s*.+$/m);
assert.deepEqual(secretReferences(depositStep), [
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64'
]);
assert.match(depositStep,
  /CNYOS_ROLLBACK_ATTESTATION_BROKER_URL: \$\{\{ vars\.CNYOS_ROLLBACK_ATTESTATION_BROKER_URL \}\}/);
assert.match(depositStep, /deposit-rollback-attestation\.mjs/);
assert.doesNotMatch(depositStep,
  /CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN/);
assert.deepEqual(secretReferences(attestationStep), []);
assert.match(attestationStep, /verify-rollback-attestation-deposit\.mjs/);
assert.doesNotMatch(attestationStep,
  /CNYOS_CONTROLLER_AUTHORIZATION_JSON|CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64|CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64|CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD/);
assert.doesNotMatch(depositStep,
  /echo[^\r\n]*(?:CNYOS_CONTROLLER_AUTHORIZATION_JSON|CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64|CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64)/);
for (const safeArtifact of [
  'authorization.json',
  'authorization-verification-bundle.json',
  'github-release-precredential.json',
  'rollback-attestation-deposit-receipt.json',
  'rollback-attestation-deposit-validation.json',
  'preflight.json'
]) assert.match(preflightUploadStep,
  new RegExp(`release-chain/(?:evidence/)?${safeArtifact.replaceAll('.', '\\.')}`));
assert.doesNotMatch(preflightUploadStep,
  /path:\s*\$\{\{ runner\.temp \}\}\/release-chain\/(?:\s|$)/m);
assert.doesNotMatch(preflightUploadStep,
  /authorization-raw|known-good|approver-registry|security-signature|risk-owner-signature|private-key/i);
assertOrdered(release, [
  'Validate exact-run signatures without deployment, database, rollback, or OIDC credentials',
  'Deposit exact recovery inputs with the immutable attestation broker',
  'Verify the broker-signed sanitized attestation receipt',
  'Obtain a signed live publisher-boundary attestation without deployment credentials',
  'Retain prepared authorization and publisher-boundary prerequisites',
  'Query PR 36 and the separate promotion PR with read-only identity',
  'Seal publisher credential-release prerequisites without publisher credential',
  'Validate exact staging Function environment with released publisher credential',
  'Retain authorization and Function-environment prerequisites',
  'Verify backup-disable and runtime-capability boundaries without privileged credentials',
  'Retain runtime-boundary evidence without privileged credentials',
  'Capture signed rollback target with released publisher credential',
  'Durably retain authorization and preflight before mutation',
  'Deploy only the durable intent with publisher credentials and no OIDC'
], 'rollback attestation deposit before mutation');
assertOrdered(release, [
  'Query PR 36 and the separate promotion PR with read-only identity',
  'Seal publisher credential-release prerequisites without publisher credential',
  'Validate exact staging Function environment with released publisher credential'
], 'precredential GitHub query before first Netlify credential');
assertOrdered(release, [
  'Requery PR 36 and the separate promotion PR with read-only identity',
  'Acquire lease and persist exact promotion attempt without deployment or database credentials',
  'Promote only the receipt-bound draft'
], 'fresh GitHub requery immediately before promotion chain');
assert.match(credentialReleasePrerequisiteStep,
  /verify-live-github-release-boundary\.mjs validate-evidence/);
assert.deepEqual(secretReferences(preflightStep), ['CNYOS_STAGING_NETLIFY_AUTH_TOKEN']);
for (const step of [preflightChainRehashStep, preflightStep]) {
  assert.match(step,
    /CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH: .*pre-release-reconciliation\.json/);
  assert.match(step,
    /CNYOS_EXPECTED_RECONCILIATION_EVIDENCE_SHA256: \$\{\{ needs\.authorize_function_environment\.outputs\.pre_release_reconciliation_sha256 \}\}/);
}
assert.match(preflightChainRehashStep,
  /sha256sum "\$CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH"[\s\S]*"\$CNYOS_EXPECTED_RECONCILIATION_EVIDENCE_SHA256"/);
assert.match(draftGateStep,
  /sha256sum "\$CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH"[\s\S]*"\$CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256"/);
assert.match(draftGateStep,
  /sha256sum "\$CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH"[\s\S]*"\$CNYOS_EXPECTED_ROLLBACK_READINESS_EVIDENCE_SHA256"/);
assert.match(preflightStep,
  /CNYOS_EXPECTED_FUNCTION_ENV_EVIDENCE_SHA256: \$\{\{ needs\.authorize_function_environment\.outputs\.function_environment_sha256 \}\}/);
assert.match(preflightStep,
  /CNYOS_EXPECTED_BACKUP_DISABLE_EVIDENCE_SHA256: \$\{\{ needs\.verify_runtime_boundaries\.outputs\.backup_disable_sha256 \}\}/);
assert.match(preflightStep,
  /CNYOS_EXPECTED_RUNTIME_CAPABILITY_EVIDENCE_SHA256: \$\{\{ needs\.verify_runtime_boundaries\.outputs\.runtime_capability_sha256 \}\}/);
assert.match(preflightStep, /netlify-evidence\.mjs preflight/);
assert.doesNotMatch(preflightStep,
  /validate-function-environment|verify-backup-disable-runtime-boundary|verify-runtime-capability-boundary|CNYOS_NETLIFY_CLI_PATH/);
assert.doesNotMatch(preflightStep,
  /CNYOS_CONTROLLER_AUTHORIZATION_JSON|CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64|CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN/);

assert.deepEqual(secretReferences(promotionAttemptStep), [],
  'promotion-attempt secret boundary');
assert.doesNotMatch(promotionAttemptStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD):/m);
for (const name of [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD'
]) {
  assert.match(promotionAttemptStep,
    new RegExp(`test -z "\\$\\{${name}\\+set\\}"`));
}
for (const step of [promotionAttemptStep, promoteStep]) {
  assert.match(step, /CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_PATH:/);
  assert.match(step, /CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH:/);
  assert.match(step, /CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256:/);
  assert.match(step,
    /CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_PATH: .*draft-metadata\.json/);
  assert.match(step,
    /CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256: \$\{\{ needs\.verify_draft\.outputs\.draft_metadata_sha256 \}\}/);
}
for (const [name, step] of [
  ['promote', promoteStep],
  ['verify-promoted', verifyPromotedStep],
  ['final-current', finalCurrentStep]
]) {
  assert.deepEqual(secretReferences(step), ['CNYOS_STAGING_NETLIFY_AUTH_TOKEN'],
    `${name} secret boundary`);
  assert.match(step,
    /^\s+CNYOS_STAGING_NETLIFY_AUTH_TOKEN: \$\{\{ secrets\.CNYOS_STAGING_NETLIFY_AUTH_TOKEN \}\}$/m);
  assert.doesNotMatch(step, /^\s+NETLIFY_AUTH_TOKEN:/m);
  assert.doesNotMatch(step,
    /^\s+(?:CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD):/m);
  assert.match(step, /test -z "\$\{ACTIONS_ID_TOKEN_REQUEST_TOKEN\+set\}"/);
  assert.match(step, /test -z "\$\{ACTIONS_ID_TOKEN_REQUEST_URL\+set\}"/);
}
assert.deepEqual(secretReferences(draftAccessStep), [
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN'
]);
assert.doesNotMatch(draftAccessStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN):/m);
assert.deepEqual(secretReferences(draftMetadataStep), [
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.doesNotMatch(draftMetadataStep,
  /^\s+CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN:/m);
assert.match(draftMetadataStep,
  /test -z "\$\{CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN\+set\}"/);
assert.deepEqual(secretReferences(verifyDraftStep), [
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN'
]);
assert.doesNotMatch(verifyDraftStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN):/m);
assert.match(verifyDraftStep,
  /CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256: \$\{\{ needs\.verify_draft_metadata\.outputs\.evidence_sha256 \}\}/);
assert.match(verifyDraftStep,
  /test -z "\$\{CNYOS_STAGING_NETLIFY_AUTH_TOKEN\+set\}"/);
assert.deepEqual(secretReferences(controlBehaviorStep), [
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN'
]);
assert.doesNotMatch(controlBehaviorStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN):/m);
assert.deepEqual(secretReferences(privateDraftStep), [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.doesNotMatch(privateDraftStep,
  /^\s+CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN:/m);
for (const filename of [
  'draft-access-boundary.json',
  'draft-metadata.json',
  'draft-verification.json',
  'control-behavior.json',
  'private-draft.json'
]) {
  assert.match(bindDraftEvidenceStep,
    new RegExp(`test -f "\\$evidence_path"[\\s\\S]*test ! -L "\\$evidence_path"`));
  assert.match(bindDraftEvidenceStep, new RegExp(filename.replaceAll('.', '\\.')));
}
assert.match(bindDraftEvidenceStep,
  /echo "\$expected_digest" \| grep -Eq '\^\[0-9a-f\]\{64\}\$'/);
assert.match(bindDraftEvidenceStep,
  /for evidence_name in \\\n\s+draft-access-boundary\.json \\\n\s+draft-metadata\.json \\\n\s+draft-verification\.json \\\n\s+control-behavior\.json \\\n\s+private-draft\.json\n\s+do\n[\s\S]*test -f "\$evidence_path"\n\s+test ! -L "\$evidence_path"\n\s+done/);
for (const [filename, digestName] of [
  ['draft-access-boundary.json', 'CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256'],
  ['draft-metadata.json', 'CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256'],
  ['draft-verification.json', 'CNYOS_EXPECTED_DRAFT_VERIFICATION_EVIDENCE_SHA256'],
  ['control-behavior.json', 'CNYOS_EXPECTED_CONTROL_BEHAVIOR_EVIDENCE_SHA256']
]) {
  assert.ok(bindDraftEvidenceStep.includes(
    `test "$(sha256sum "$CNYOS_CONTROLLER_EVIDENCE_DIRECTORY/${filename}" | cut -d ' ' -f 1)" = "$${digestName}"`
  ), `draft artifact hash binding: ${filename}`);
}
assert.deepEqual(secretReferences(scheduledRouteDenialStep), []);
assert.doesNotMatch(scheduledRouteDenialStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD):/m);
for (const step of [promotionAttemptStep, promoteStep]) {
  assert.match(step,
    /CNYOS_EXPECTED_ROLLBACK_READINESS_EVIDENCE_SHA256: \$\{\{ needs\.rollback_readiness\.outputs\.evidence_sha256 \}\}/);
  assert.match(step,
    /CNYOS_EXPECTED_DRAFT_GATE_EVIDENCE_SHA256: \$\{\{ needs\.draft_deploy\.outputs\.draft_gate_sha256 \}\}/);
}
assert.deepEqual(secretReferences(uatStep), [
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD'
]);
assert.match(uatStep,
  /^\s+CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: \$\{\{ secrets\.CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY \}\}$/m);
assert.match(uatStep,
  /^\s+CNYOS_STAGING_TEST_PASSWORD: \$\{\{ secrets\.CNYOS_STAGING_TEST_PASSWORD \}\}$/m);
assert.doesNotMatch(uatStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN):/m);
assert.match(uatStep, /test -z "\$\{ACTIONS_ID_TOKEN_REQUEST_TOKEN\+set\}"/);
assert.match(uatStep, /test -z "\$\{ACTIONS_ID_TOKEN_REQUEST_URL\+set\}"/);
assert.match(uatStep,
  /CNYOS_EXPECTED_SCHEDULED_ROUTE_DENIAL_EVIDENCE_SHA256: \$\{\{ needs\.validate_promoted_routes\.outputs\.evidence_sha256 \}\}/);
for (const filename of [
  'promotion.json',
  'post-promotion.json',
  'scheduled-route-denial.json',
  'uat.json',
  'final-current.json'
]) {
  assert.match(bindPromotionEvidenceStep,
    new RegExp(`test -f "\\$evidence_path"[\\s\\S]*test ! -L "\\$evidence_path"`));
  assert.match(bindPromotionEvidenceStep, new RegExp(filename.replaceAll('.', '\\.')));
}
assert.match(bindPromotionEvidenceStep,
  /echo "\$expected_digest" \| grep -Eq '\^\[0-9a-f\]\{64\}\$'/);
assert.match(bindPromotionEvidenceStep,
  /for evidence_name in \\\n\s+promotion\.json \\\n\s+post-promotion\.json \\\n\s+scheduled-route-denial\.json \\\n\s+uat\.json \\\n\s+final-current\.json\n\s+do\n[\s\S]*test -f "\$evidence_path"\n\s+test ! -L "\$evidence_path"\n\s+done/);
for (const [filename, digestName] of [
  ['promotion.json', 'CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256'],
  ['post-promotion.json', 'CNYOS_EXPECTED_POST_PROMOTION_EVIDENCE_SHA256'],
  ['scheduled-route-denial.json',
    'CNYOS_EXPECTED_SCHEDULED_ROUTE_DENIAL_EVIDENCE_SHA256'],
  ['uat.json', 'CNYOS_EXPECTED_UAT_EVIDENCE_SHA256']
]) {
  assert.ok(bindPromotionEvidenceStep.includes(
    `test "$(sha256sum "$CNYOS_CONTROLLER_EVIDENCE_DIRECTORY/${filename}" | cut -d ' ' -f 1)" = "$${digestName}"`
  ), `promotion artifact hash binding: ${filename}`);
}

assert.deepEqual(secretReferences(releasePublisherStep), []);
assert.ok(releasePublisherStep.includes('CNYOS_EXPECTED_UAT_EVIDENCE_SHA256: ${{ needs.run_promoted_uat.outputs.uat_sha256 }}'));
assert.match(releasePublisherStep, /sha256sum "\$CNYOS_CONTROLLER_UAT_EVIDENCE_PATH"/);
assert.ok(preflightStep.includes('CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256: ${{ needs.verify_runtime_boundaries.outputs.runtime_proof_sha256 }}'));
assert.ok(finalizeStep.includes('CNYOS_EXPECTED_RUNTIME_PROOF_ENVELOPE_SHA256: ${{ needs.authorize_preflight.outputs.runtime_proof_sha256 }}'));
assert.match(preflightUploadStep, /runtime-proof-envelope\.json/);
assert.match(releasePublisherStep,
  /CNYOS_NETLIFY_PUBLISH_BROKER_URL: \$\{\{ vars\.CNYOS_NETLIFY_PUBLISH_BROKER_URL \}\}/);
assert.doesNotMatch(releasePublisherStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD):/m);
const acquirePublisherJob = workflowJobSlice(release, 'acquire_exclusive_publisher');
const verifyDraftMetadataJob = workflowJobSlice(release, 'verify_draft_metadata');
const verifyDraftContentJob = workflowJobSlice(release, 'verify_draft_content');
const verifyDraftLifecycleJob = workflowJobSlice(release, 'verify_draft');
const promoteJob = workflowJobSlice(release, 'promote_and_validate');
const validatePromotedRoutesJob = workflowJobSlice(release, 'validate_promoted_routes');
const runPromotedUatJob = workflowJobSlice(release, 'run_promoted_uat');
const verifyPromotedFinalCurrentJob = workflowJobSlice(
  release,
  'verify_promoted_final_current'
);
const releaseAndFinalizeJob = workflowJobSlice(release, 'release_and_finalize');
const commitSuccessfulReleaseJob = workflowJobSlice(release, 'commit_successful_release');
const draftMetadataUpload = namedWorkflowStepSlice(
  verifyDraftMetadataJob,
  'Retain only the publisher-derived draft metadata'
);
const draftContentUpload = namedWorkflowStepSlice(
  verifyDraftContentJob,
  'Retain only access-boundary-derived draft evidence'
);
const promotionUpload = namedWorkflowStepSlice(
  promoteJob,
  'Retain only the publisher-derived promotion evidence'
);
const routeDenialUpload = namedWorkflowStepSlice(
  validatePromotedRoutesJob,
  'Retain only credential-free route-denial evidence'
);
const promotedUatUpload = namedWorkflowStepSlice(
  runPromotedUatJob,
  'Retain only database-authenticated UAT evidence'
);
assert.match(draftMetadataUpload,
  /name: cnyos-draft-metadata-\$\{\{ github\.run_id \}\}\n\s+path: controller\/release-chain\/evidence\/draft-metadata\.json\n\s+if-no-files-found: error/);
assert.match(draftContentUpload,
  /name: cnyos-draft-content-\$\{\{ github\.run_id \}\}\n\s+path: \|\n\s+controller\/release-chain\/evidence\/draft-access-boundary\.json\n\s+controller\/release-chain\/evidence\/draft-verification\.json\n\s+controller\/release-chain\/evidence\/control-behavior\.json\n\s+if-no-files-found: error/);
assert.match(promotionUpload,
  /name: cnyos-promotion-\$\{\{ github\.run_id \}\}\n\s+path: \|\n\s+controller\/release-chain\/evidence\/promotion\.json\n\s+controller\/release-chain\/evidence\/post-promotion\.json\n\s+if-no-files-found: error/);
assert.match(routeDenialUpload,
  /name: cnyos-scheduled-route-denial-\$\{\{ github\.run_id \}\}\n\s+path: controller\/release-chain\/evidence\/scheduled-route-denial\.json\n\s+if-no-files-found: error/);
assert.match(promotedUatUpload,
  /name: cnyos-promoted-uat-\$\{\{ github\.run_id \}\}\n\s+path: controller\/release-chain\/evidence\/uat\.json\n\s+if-no-files-found: error/);

function assertArtifactDownload(job, artifact, destination) {
  const escapedArtifact = artifact.replaceAll(/[-/]/g, '\\$&');
  const escapedDestination = destination.replaceAll(/[-/]/g, '\\$&');
  assert.match(job, new RegExp(
    `uses: actions/download-artifact@__PINNED_DOWNLOAD_ARTIFACT_COMMIT_SHA__[\\s\\S]{0,120}` +
    `name: ${escapedArtifact}-\\$\\{\\{ github\\.run_id \\}\\}\\n\\s+path: ${escapedDestination}`
  ));
}
assertArtifactDownload(verifyDraftContentJob, 'cnyos-draft-metadata',
  'controller/release-chain/evidence');
assertArtifactDownload(verifyDraftLifecycleJob, 'cnyos-draft-content',
  'controller/release-chain/evidence');
assertArtifactDownload(verifyDraftLifecycleJob, 'cnyos-draft-metadata',
  'controller/release-chain/evidence');
assertArtifactDownload(validatePromotedRoutesJob, 'cnyos-promotion',
  'controller/release-chain/evidence');
assertArtifactDownload(runPromotedUatJob, 'cnyos-promotion',
  'controller/release-chain/evidence');
assertArtifactDownload(runPromotedUatJob, 'cnyos-scheduled-route-denial',
  'controller/release-chain/evidence');
assertArtifactDownload(verifyPromotedFinalCurrentJob, 'cnyos-promotion',
  'controller/release-chain/evidence');
assertArtifactDownload(verifyPromotedFinalCurrentJob, 'cnyos-scheduled-route-denial',
  'controller/release-chain/evidence');
assertArtifactDownload(verifyPromotedFinalCurrentJob, 'cnyos-promoted-uat',
  'controller/release-chain/evidence');
assert.match(acquirePublisherJob,
  /permissions:\n\s+contents: read\n\s+id-token: write/);
assert.deepEqual(secretReferences(acquirePublisherJob), []);
assert.match(verifyDraftMetadataJob,
  /needs: \[produce, authorize_preflight, draft_deploy\]/);
assert.deepEqual(uniqueSecretReferences(verifyDraftMetadataJob), [
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.match(verifyDraftContentJob,
  /needs: \[produce, authorize_preflight, draft_deploy, verify_draft_metadata\]/);
assert.deepEqual(uniqueSecretReferences(verifyDraftContentJob), [
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN'
]);
assert.match(verifyDraftLifecycleJob,
  /needs: \[produce, authorize_preflight, rollback_readiness, draft_gate, draft_deploy, verify_draft_metadata, verify_draft_content\]/);
for (const binding of [
  'CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256: ${{ needs.draft_deploy.outputs.draft_intent_sha256 }}',
  'CNYOS_EXPECTED_DRAFT_GATE_EVIDENCE_SHA256: ${{ needs.draft_gate.outputs.draft_gate_sha256 }}',
  'CNYOS_EXPECTED_ROLLBACK_READINESS_EVIDENCE_SHA256: ${{ needs.rollback_readiness.outputs.evidence_sha256 }}',
  'CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256: ${{ needs.verify_draft_metadata.outputs.evidence_sha256 }}'
]) assert.ok(privateDraftStep.includes(binding), binding);
assert.deepEqual(uniqueSecretReferences(verifyDraftLifecycleJob), [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.match(verifyDraftLifecycleJob,
  /draft_verification_sha256: \$\{\{ needs\.verify_draft_content\.outputs\.draft_verification_sha256 \}\}/);
assert.match(verifyDraftLifecycleJob,
  /draft_access_boundary_sha256: \$\{\{ needs\.verify_draft_content\.outputs\.draft_access_boundary_sha256 \}\}/);
assert.match(verifyDraftLifecycleJob,
  /draft_metadata_sha256: \$\{\{ needs\.verify_draft_metadata\.outputs\.evidence_sha256 \}\}/);
assert.match(verifyDraftLifecycleJob,
  /control_behavior_sha256: \$\{\{ needs\.verify_draft_content\.outputs\.control_behavior_sha256 \}\}/);
assert.match(verifyDraftLifecycleJob,
  /name: cnyos-draft-metadata-\$\{\{ github\.run_id \}\}/);
assert.doesNotMatch(verifyDraftContentJob,
  /Retain only access-boundary-derived draft evidence[\s\S]*path: \|[\s\S]{0,300}draft-metadata\.json/);
for (const job of [verifyDraftMetadataJob, verifyDraftContentJob, verifyDraftLifecycleJob]) {
  assert.match(job, /permissions:\n\s+contents: read\n\s+id-token: none/);
  assert.doesNotMatch(job, /^\s+id-token:\s*write\s*$/m);
}
assert.match(promoteJob, /permissions:\n\s+contents: read\n\s+id-token: none/);
assert.doesNotMatch(promoteJob, /^\s+id-token:\s*write\s*$/m);
assert.match(promoteJob,
  /needs: \[produce, authorize_preflight, rollback_readiness, draft_deploy, verify_draft, verify_github_release_boundary_prepromotion, acquire_exclusive_publisher\]/);
assert.deepEqual(uniqueSecretReferences(promoteJob), [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.match(validatePromotedRoutesJob,
  /needs: \[produce, authorize_preflight, promote_and_validate\]/);
assert.deepEqual(uniqueSecretReferences(validatePromotedRoutesJob), []);
assert.doesNotMatch(validatePromotedRoutesJob, /\n    environment:/);
assert.match(validatePromotedRoutesJob,
  /permissions:\n\s+contents: read\n\s+id-token: none/);
assert.match(runPromotedUatJob,
  /needs: \[produce, promote_and_validate, validate_promoted_routes\]/);
assert.deepEqual(uniqueSecretReferences(runPromotedUatJob), [
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD'
]);
assert.match(verifyPromotedFinalCurrentJob,
  /needs: \[produce, authorize_preflight, promote_and_validate, validate_promoted_routes, run_promoted_uat\]/);
assert.deepEqual(uniqueSecretReferences(verifyPromotedFinalCurrentJob), [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
]);
assert.match(verifyPromotedFinalCurrentJob,
  /scheduled_route_denial_sha256: \$\{\{ needs\.validate_promoted_routes\.outputs\.evidence_sha256 \}\}/);
assert.match(verifyPromotedFinalCurrentJob,
  /uat_sha256: \$\{\{ needs\.run_promoted_uat\.outputs\.uat_sha256 \}\}/);
for (const job of [promoteJob, runPromotedUatJob, verifyPromotedFinalCurrentJob]) {
  assert.match(job, /permissions:\n\s+contents: read\n\s+id-token: none/);
  assert.doesNotMatch(job, /^\s+id-token:\s*write\s*$/m);
}
for (const job of [
  verifyDraftMetadataJob,
  verifyDraftContentJob,
  verifyDraftLifecycleJob,
  promoteJob,
  validatePromotedRoutesJob,
  runPromotedUatJob,
  verifyPromotedFinalCurrentJob
]) {
  const authorities = new Set(uniqueSecretReferences(job).map(name => {
    if (name === 'CNYOS_STAGING_NETLIFY_AUTH_TOKEN') return 'publisher';
    if (name === 'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN') return 'draft_access';
    if (name === 'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY' ||
      name === 'CNYOS_STAGING_TEST_PASSWORD') return 'database_uat';
    if (name === 'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY') return 'comparison_key';
    return name;
  }).filter(name => name !== 'comparison_key'));
  assert.ok(authorities.size <= 1, 'a runner must receive at most one bearer-authority class');
}
assert.match(releaseAndFinalizeJob,
  /permissions:\n\s+contents: read\n\s+id-token: write/);
assert.deepEqual(secretReferences(releaseAndFinalizeJob), []);
for (const artifact of [
  'cnyos-draft',
  'cnyos-preflight',
  'cnyos-rollback-readiness',
  'cnyos-draft-verification',
  'cnyos-github-prepromotion',
  'cnyos-attempt',
  'cnyos-promotion-validation'
]) {
  assert.match(releaseAndFinalizeJob,
    new RegExp(`name: ${artifact}-\\$\\{\\{ github\\.run_id \\}\\}`));
}
const expectedDownloadedReleaseEvidence = [...new Set(
  [...`${releasePublisherStep}\n${finalizeStep}`
    .matchAll(/\$\{\{ github\.workspace \}\}\/controller\/release-chain\/evidence\/([a-z0-9-]+\.json)/g)]
    .map(match => match[1])
)].filter(filename => ![
  'publisher-release.json',
  'final.json'
].includes(filename)).sort();
assert.deepEqual(expectedDownloadedReleaseEvidence, [
  'authorization-verification-bundle.json',
  'authorization.json',
  'backup-disable-runtime-boundary.json',
  'control-behavior.json',
  'draft-access-boundary.json',
  'draft-gate.json',
  'draft-intent.json',
  'draft-metadata.json',
  'draft-receipt.json',
  'draft-verification.json',
  'exclusive-publisher.json',
  'final-current.json',
  'function-environment.json',
  'github-release-precredential.json',
  'github-release-prepromotion.json',
  'live-netlify-authority-boundary.json',
  'post-promotion.json',
  'pre-release-reconciliation.json',
  'preflight.json',
  'private-draft.json',
  'promotion-attempt.json',
  'promotion.json',
  'rollback-attestation-deposit-receipt.json',
  'rollback-attestation-deposit-validation.json',
  'rollback-readiness.json',
  'runtime-capability.json',
  'runtime-proof-envelope.json',
  'scheduled-route-denial.json',
  'uat.json'
]);
for (const filename of expectedDownloadedReleaseEvidence) {
  assert.match(completeReleaseEvidenceStep,
    new RegExp(filename.replaceAll('.', '\\.')));
}
assertOrdered(completeReleaseEvidenceStep, [
  'test -d "$CNYOS_CONTROLLER_EVIDENCE_DIRECTORY"',
  'test ! -L "$CNYOS_CONTROLLER_EVIDENCE_DIRECTORY"',
  'test -f "$evidence_path"',
  'test ! -L "$evidence_path"'
], 'release evidence is complete and regular before any OIDC broker operation');
assertOrdered(releaseAndFinalizeJob, [
  'Download exact draft-chain evidence from its direct producer',
  'Download exact preflight evidence from its direct producer',
  'Download exact rollback-readiness evidence from its direct producer',
  'Download exact draft-verification evidence from its direct producer',
  'Download exact prepromotion GitHub evidence from its direct producer',
  'Download exact publisher-attempt evidence from its direct producer',
  'Download exact promotion and validation evidence',
  'Require the complete direct-producer evidence set as regular files',
  'Atomically release the publisher lease while retaining the run barrier'
], 'fresh finalization runner receives every direct-producer artifact before OIDC');
assert.match(commitSuccessfulReleaseJob,
  /if: \$\{\{ !cancelled\(\) && needs\.produce\.result == 'success' && needs\.authorize_release\.result == 'success' && needs\.release_and_finalize\.result == 'success' \}\}/);
assert.match(commitSuccessfulReleaseJob,
  /needs: \[produce, authorize_release, release_and_finalize\]/);
assert.match(commitSuccessfulReleaseJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: write/);
assert.deepEqual(secretReferences(commitSuccessfulReleaseJob), []);
assert.deepEqual(secretReferences(terminalCommitStep), []);
assert.match(terminalCommitStep,
  /CNYOS_RELEASE_FINALIZE_JOB_RESULT: \$\{\{ needs\.release_and_finalize\.result \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_PRODUCER_JOB_RESULT: \$\{\{ needs\.produce\.result \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_AUTHORIZATION_JOB_RESULT: \$\{\{ needs\.authorize_release\.result \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME: \$\{\{ steps\.download_final\.outcome \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_PRODUCER_ARTIFACT_DOWNLOAD_OUTCOME: \$\{\{ steps\.download_producer\.outcome \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_AUTHORIZATION_ARTIFACT_DOWNLOAD_OUTCOME: \$\{\{ steps\.download_authorization\.outcome \}\}/);
assert.match(commitSuccessfulReleaseJob,
  /name: Download the independently produced exact-byte bundle[\s\S]*name: cnyos-producer-\$\{\{ github\.run_id \}\}[\s\S]*path: controller\/terminal-input\/producer/);
assert.match(commitSuccessfulReleaseJob,
  /name: Download the independently verified signed authorization evidence[\s\S]*name: cnyos-authorization-\$\{\{ github\.run_id \}\}[\s\S]*path: controller\/terminal-input\/authorization/);
for (const binding of [
  'CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: ${{ needs.produce.outputs.manifest_sha256 }}',
  'CNYOS_EXPECTED_PRODUCER_ARTIFACT_SHA256: ${{ needs.produce.outputs.artifact_sha256 }}',
  'CNYOS_EXPECTED_PRODUCER_FILE_COUNT: ${{ needs.produce.outputs.file_count }}',
  'CNYOS_EXPECTED_PRODUCER_CANDIDATE_TREE: ${{ needs.produce.outputs.candidate_tree }}',
  'CNYOS_EXPECTED_PRODUCER_FUNCTION_SOURCE_TREE: ${{ needs.produce.outputs.function_source_tree }}',
  'CNYOS_EXPECTED_GITHUB_ARTIFACT_DIGEST: ${{ needs.produce.outputs.github_artifact_digest }}',
  'CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: ${{ needs.authorize_release.outputs.authorization_sha256 }}',
  'CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256: ${{ needs.authorize_release.outputs.authorization_bundle_sha256 }}'
]) assert.ok(terminalCommitStep.includes(binding), binding);
assert.match(terminalCommitStep,
  /CNYOS_NETLIFY_PUBLISH_BROKER_URL: \$\{\{ vars\.CNYOS_NETLIFY_PUBLISH_BROKER_URL \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_EXPECTED_FINAL_EVIDENCE_SHA256: \$\{\{ needs\.release_and_finalize\.outputs\.final_sha256 \}\}/);
assert.match(terminalCommitStep,
  /CNYOS_EXPECTED_PUBLISHER_RELEASE_EVIDENCE_SHA256: \$\{\{ needs\.release_and_finalize\.outputs\.publisher_release_sha256 \}\}/);
assertOrdered(terminalCommitStep, [
  'test "$CNYOS_RELEASE_FINALIZE_JOB_RESULT" = "success"',
  'test "$CNYOS_PRODUCER_JOB_RESULT" = "success"',
  'test "$CNYOS_AUTHORIZATION_JOB_RESULT" = "success"',
  'test "$CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME" = "success"',
  'test "$CNYOS_PRODUCER_ARTIFACT_DOWNLOAD_OUTCOME" = "success"',
  'test "$CNYOS_AUTHORIZATION_ARTIFACT_DOWNLOAD_OUTCOME" = "success"',
  'test -f "$CNYOS_CONTROLLER_FINAL_EVIDENCE_PATH"',
  'test ! -L "$CNYOS_CONTROLLER_FINAL_EVIDENCE_PATH"',
  'sha256sum "$CNYOS_CONTROLLER_FINAL_EVIDENCE_PATH"',
  'sha256sum "$CNYOS_CONTROLLER_PUBLISHER_RELEASE_EVIDENCE_PATH"',
  'commit-successful-release',
  'test -f "$CNYOS_CONTROLLER_SUCCESSFUL_RELEASE_TERMINAL_EVIDENCE_PATH"',
  'terminal_receipt_sha256='
], 'terminal broker commit consumes exact retained evidence and emits a signed receipt');
assert.match(terminalReceiptUploadStep,
  /name: cnyos-successful-release-terminal-\$\{\{ github\.run_id \}\}[\s\S]*retention-days: 365/);
assert.match(promoteJob,
  /name: Download exact rollback-readiness evidence[\s\S]{0,240}name: cnyos-rollback-readiness-\$\{\{ github\.run_id \}\}[\s\S]{0,160}path: controller\/release-chain\/evidence/);
assert.match(promoteJob,
  /name: Download exact preflight evidence[\s\S]{0,240}name: cnyos-preflight-\$\{\{ github\.run_id \}\}[\s\S]{0,160}path: controller\/release-chain\/evidence/);
for (const filename of [
  'pre-release-reconciliation.json',
  'authorization.json',
  'authorization-verification-bundle.json',
  'github-release-precredential.json',
  'rollback-attestation-deposit-receipt.json',
  'rollback-attestation-deposit-validation.json',
  'live-netlify-authority-boundary.json',
  'function-environment.json',
  'backup-disable-runtime-boundary.json',
  'runtime-capability.json',
  'preflight.json'
]) assert.match(preflightUploadStep,
  new RegExp(`release-chain/(?:evidence/)?${filename.replaceAll('.', '\\.')}`));
assert.match(draftUploadStep, /path: controller\/release-chain\/evidence\//);
for (const filename of [
  'draft-access-boundary.json',
  'draft-metadata.json',
  'draft-verification.json',
  'control-behavior.json',
  'private-draft.json'
]) assert.match(draftVerificationUploadStep, new RegExp(`evidence/${filename.replaceAll('.', '\\.')}`));

assert.deepEqual(secretReferences(finalizeStep), []);
assert.doesNotMatch(finalizeStep,
  /^\s+(?:CNYOS_STAGING_NETLIFY_AUTH_TOKEN|NETLIFY_AUTH_TOKEN|CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY|CNYOS_STAGING_TEST_PASSWORD|CNYOS_NETLIFY_PUBLISH_BROKER_URL):/m);
assert.match(finalizeStep,
  /CNYOS_EXPECTED_SCHEDULED_ROUTE_DENIAL_EVIDENCE_SHA256: \$\{\{ needs\.validate_promoted_routes\.outputs\.evidence_sha256 \}\}/);
assert.match(finalizeStep,
  /CNYOS_EXPECTED_UAT_EVIDENCE_SHA256: \$\{\{ needs\.run_promoted_uat\.outputs\.uat_sha256 \}\}/);
assert.match(finalizeStep,
  /CNYOS_EXPECTED_PUBLISHER_RELEASE_EVIDENCE_SHA256: \$\{\{ steps\.release_publisher\.outputs\.publisher_release_sha256 \}\}/);
assert.match(finalizeStep, /CNYOS_CONTROLLER_GITHUB_PRECREDENTIAL_EVIDENCE_PATH:/);
assert.match(finalizeStep, /CNYOS_CONTROLLER_GITHUB_PREPROMOTION_EVIDENCE_PATH:/);
assert.match(release, /CNYOS_CONTROLLER_BOOTSTRAP_STATE: BLOCKED_UNTIL_/);
assert.match(release, /test "\$CNYOS_CONTROLLER_BOOTSTRAP_STATE" = "REVIEWED_AND_ACTIVATED"/);
assert.match(readme, /Activation status: blocked by design/);
assert.match(readme, /external-broker-trust-boundaries/);
assert.match(readme, /live-github-release-boundary/);
assert.match(readme,
  /retained record\s+is audit evidence only; it is not sufficient mutation authority/s);
assert.match(readme,
  /fresh live GitHub read and the exact Netlify promotion as one\s+fail-closed operation under a single-use admission/s);
assert.match(readme,
  /present cross-job five-minute design is therefore an activation blocker/);
assert.match(readme, /no credential forwarding or serialization/);
assert.match(readme, /release-state-reconciliation/);
assert.match(readme, /both commit\/recovery CAS interleavings/);
assert.match(readme,
  /`terminal_success_rehydrated` and\s+`terminal_recovery_rehydrated` never schedule or execute a rollback-token job/s);
assert.match(readme, /recovery_required.*delayed successful-release commit\s+conflict/s);
assert.match(release, /actions\/checkout@__PINNED_CHECKOUT_COMMIT_SHA__/);
assert.match(release, /actions\/upload-artifact@__PINNED_UPLOAD_ARTIFACT_COMMIT_SHA__/);
assert.match(release, /__AUDITED_NETLIFY_CLI_VERSION__/);
assert.doesNotMatch(release, /\bnetlify\b[^\n]*\bdeploy\b[^\n]*--prod(?:\s|$)/);
assert.match(release, /name: Create the intent-bound unpromoted staging draft without OIDC/);
assert.match(release,
  /Record durable draft intent with OIDC and no deployment credentials[\s\S]*Deploy only the durable intent with publisher credentials and no OIDC/);
assert.match(release, /netlify-evidence\.mjs verify-draft/);
assert.match(release, /netlify-evidence\.mjs verify-draft-metadata/);
assert.match(release, /verify-netlify-control-file-behavior\.mjs/);
assert.match(release, /verify-runtime-capability-boundary\.mjs/);
assert.match(release, /verify-private-draft-lifecycle\.mjs/);
assert.match(release, /verify-netlify-exclusive-publisher\.mjs/);
assert.match(release, /netlify-evidence\.mjs promote/);
assert.match(release, /netlify-evidence\.mjs verify-promoted/);
assert.match(release, /controller-authenticated-uat\.mjs/);
assert.match(release, /netlify-evidence\.mjs verify-final-current/);
assert.match(release, /finalize-evidence\.mjs/);
assert.match(release, /release-netlify-exclusive-publisher\.mjs/);
assert.match(release, /cleanup-netlify-draft\.mjs/);

const buildSlice = release.slice(release.indexOf('\n  build_candidate:'),
  release.indexOf('\n  produce:'));
const producerSlice = release.slice(release.indexOf('\n  produce:'),
  release.indexOf('\n  authorize_release:'));
for (const slice of [buildSlice, producerSlice]) {
  assert.doesNotMatch(slice, /^\s+environment:/m);
  assert.doesNotMatch(slice, /\$\{\{\s*secrets\./);
}
assert.match(producerSlice, /controller-function-bundle\.mjs/);
assert.match(producerSlice,
  /file_count: \$\{\{ steps\.manifest\.outputs\.file_count \}\}/);
assert.match(producerSlice, /CNYOS_EXPECTED_FUNCTION_DEPENDENCY_LOCK_SHA256/);
assert.match(producerSlice,
  /CNYOS_REPRODUCED_STATIC_DIRECTORY: \$\{\{ runner\.temp \}\}\/cnyos-reproduced-static/);
assert.match(producer, /CNYOS_PRODUCER_REPRODUCED_STATIC_DIRECTORY_NOT_ISOLATED/);
assert.doesNotMatch(producerSlice,
  /CNYOS_REPRODUCED_STATIC_DIRECTORY:\s*\$\{\{ github\.workspace \}\}\/candidate\/dist/);
const reproduceStaticStep = workflowStepSlice(
  'Independently reproduce and compare the static artifact'
);
const createBundleStep = workflowStepSlice('Create controller-owned exact-byte bundle');
assert.match(createBundleStep,
  /echo "file_count=\$\(node -e '[^']*m\.fileCount[^']*' "\$MANIFEST"\)" >> "\$GITHUB_OUTPUT"/);
for (const step of [reproduceStaticStep, createBundleStep]) {
  assert.match(step,
    /CNYOS_REPRODUCED_STATIC_DIRECTORY: \$\{\{ runner\.temp \}\}\/cnyos-reproduced-static/);
  assert.doesNotMatch(step,
    /CNYOS_REPRODUCED_STATIC_DIRECTORY:\s*\$\{\{ github\.workspace \}\}|candidate\/dist/);
}
assert.match(reproduceStaticStep,
  /CNYOS_UNTRUSTED_STATIC_DIRECTORY: \$\{\{ runner\.temp \}\}\/cnyos-untrusted-static/);
assert.match(producer, /manifest\.dependencyLockSha256 !== expectedDependencyLockSha256/);
assert.match(producer, /CNYOS_PRODUCER_PRODUCTION_TARGET_MARKER_PRESENT/);
assert.match(producer, /POLICY\.productionDenylist\.netlifySiteId/);
assert.match(producer, /payload\/netlify\/functions\/\$\{file\.relativePath\}/);

for (const phrase of [
  'postgresqlMajorVersion !== 17',
  "receipt !== 'ACL_CATALOG_ROLLBACK_VERIFIED'",
  'runtimeAndUntrustedCannotSetRoleToReviewedCreators !== true',
  'blockOnDefaultAclDrift !== true',
  'compareAndSwapOrEquivalentLockEnforced !== true',
  'functionBundleManifestSha256 !== manifest.functionBundleManifestSha256',
  "maintenanceWindowStatus !== 'completed'",
  'rehearsal.quiescenceVerified !== true',
  'baselineSha256 !== inventoryBaseline.sha256',
  "ownerControlScope !== 'disabled'",
  "executionAuthority !== 'external_rollback_reconciliation_broker'",
  'reconciliationBroker.targetControllerRef !== packet.controller?.ref',
  'reconciliationBroker.targetControllerRunAttempt !== packet.controller?.runAttempt',
  'reconciliationBroker.targetNetlifySiteId !== POLICY.target.netlifySiteId',
  'targetRunCannotSuppressReconciliation !== true',
  'watchdogRevisionCannotSuppressReconciliation !== true',
  'reconciliationBroker.enforcesDraftCleanup !== true',
  'reconciliationBroker.enforcesLeaseRelease !== true',
  'reconciliationBroker.enforcesRunReconciliationBarrier !== true',
  'reconciliationBroker.atomicLeaseReleaseRetainsRunReconciliationBarrier !== true',
  'reconciliationBroker.blocksNewMutationWhileRunReconciliationBarrierActive !== true',
  'reconciliationBroker.successfulReleaseCommitRequiresFinalEvidenceHashes !== true',
  'reconciliationBroker.draftIntentTerminalBeforeBarrierClearRequired !== true',
  'reconciliationBroker.automaticRunReconciliationBarrierExpiryPermitted !== false',
  'reconciliationBroker.exactTerminalCommitRetryIdempotent !== true',
  'reconciliationBroker.terminalSuccessAndRecoveryClaimMutuallyExclusive !== true',
  'reconciliationBroker.terminalSuccessNeverRollbackEligible !== true',
  'reconciliationBroker.recoveryClaimConflictsWithDelayedTerminalCommit !== true',
  'reconciliationBroker.recoveryTerminalRecordImmutableAndRetrievable !== true',
  'reconciliationBroker.recoveryTerminalRecordBindsExecutionReceipt !== true',
  'reconciliationBroker.exactRecoveryFinalizationRetryIdempotent !== true',
  'reconciliationBroker.terminalRecoveryNeverRollbackEligible !== true',
  'reconciliationBroker.recoveryClaimAndPlanCorePersistedAtomically !== true',
  'reconciliationBroker.recoveryClaimPlanCoreImmutableAndRetrievable !== true',
  'reconciliationBroker.exactRecoveryClaimRetryIdempotent !== true',
  'reconciliationBroker.authorizedWatchdogRecoveryClaimResumptionEnforced !== true',
  'reconciliationBroker.recoveryAuthorizationRefreshPreservesClaimAndPlanCore !== true',
  'reconciliationBroker.conflictingRecoveryClaimBindingsOrGenerationRejected !== true',
  'reconciliationBroker.automaticRecoveryClaimExpiryPermitted !== false',
  'reconciliationBroker.incompleteRecoveryRecordPreservesRecoveryClaimAndPlan !== true',
  'reconciliationBroker.recoveryClaimAuthorizedResumerRepository !==',
  'reconciliationBroker.recoveryClaimAuthorizedResumerProtectedRef !==',
  'reconciliationBroker.recoveryClaimAuthorizedResumerWorkflowPaths',
  "value.membershipRole !== 'Publisher'",
  'record.publicKeyPem !== canonicalPublicKeyPem',
  'principalWindow.expiresAt > expiresAt',
  'secretValuesSerialized: false',
  'authorizationPacketSha256: sha256(raw)'
]) assert.ok(authorization.includes(phrase), phrase);
assert.doesNotMatch(authorization, /authorizationJson: raw/);
assert.doesNotMatch(authorization, /knownGoodEvidenceJson:/);
assert.doesNotMatch(authorization, /signaturesBase64:/);

for (const phrase of [
  'raw !== JSON.stringify(value)',
  "receipt.evidenceType !== 'cnyos_staging_rollback_attestation_deposit_receipt'",
  'receipt.depositSemantics.conflictingOverwriteRejected !== true',
  'receipt.depositSemantics.identicalReplayReturnsOriginalReceipt !== true',
  'receipt.depositSemantics.rawPayloadArtifactExposure !== false',
  'receipt.retrievalBoundary.requiredControllerRunAttempt !== 1',
  'receipt.retrievalBoundary.requiredDispatchNonce !== expectedController.dispatchNonce',
  'receipt.retrievalBoundary.oidcControllerIdentityRequired !== true',
  'receipt.authorizationMaterial.knownGoodEvidenceSha256',
  'authorizationBundleSha256: authorizationBundle.sha256',
  'receipt.recoveryMaterial.authorizationVerificationBundleBytesStored !== true',
  'receipt.recoveryMaterial.approverRegistryBytesStored !== true',
  'completeRecoveryMaterialStoredVerified: true',
  'retentionUntil <= observedAt',
  'retentionUntil.getTime() - depositedAt.getTime() < trust.minimumRetentionMs',
  '!crypto.verify(null, Buffer.from(statement), trust.publicKey, signature)',
  'secretValuesSerialized: false',
  'rawPayloadArtifactExposure: false'
]) assert.ok(rollbackAttestation.includes(phrase), phrase);
assert.doesNotMatch(rollbackAttestation,
  /authorizationJson\s*:|knownGoodEvidenceJson\s*:|signaturesBase64\s*:|privateKey/);
assert.match(netlify, /rollbackAttestationDepositEvidenceSha256/);
assert.match(netlify, /rollbackAttestationDepositReceiptSha256/);
assert.match(preflightStep,
  /CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256: \$\{\{ needs\.authorize_function_environment\.outputs\.rollback_attestation_evidence_sha256 \}\}/);
for (const [filename, output] of [
  ['authorization-verification-bundle.json',
    'needs.authorize_preflight.outputs.authorization_bundle_sha256'],
  ['rollback-attestation-deposit-receipt.json',
    'needs.authorize_preflight.outputs.rollback_attestation_receipt_sha256'],
  ['rollback-attestation-deposit-validation.json',
    'needs.authorize_preflight.outputs.rollback_attestation_evidence_sha256']
]) {
  assertOrdered(workflowJobSlice(release, 'prepare_failed_release_reconciliation'),
    [filename, output],
    `${filename} failed-recovery binding`);
}

assert.match(netlify, /expectedDraft: true/);
assert.match(netlify, /expectedDraft: false/);
assert.match(netlify, /!receiptOwnership \|\| !markerOwnership/);
assert.match(netlify, /authorizationSignaturesVerified !== true/);
assert.match(netlify, /CNYOS_CONTROLLER_RUNTIME_CAPABILITY_EVIDENCE_INVALID/);
assert.match(netlify, /CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_BOUNDARY_INVALID/);
assert.match(authorization,
  /deploymentBoundary\.productionNetlifySiteId !==\s*POLICY\.productionDenylist\.netlifySiteId/);
assert.match(authorization,
  /deploymentBoundary\.productionNetlifyOrigin !==\s*POLICY\.productionDenylist\.netlifyOrigin/);
assert.match(authorization,
  /productionNetlifySiteId:\s*validated\.protocol\.deploymentBoundary\.productionNetlifySiteId/);
assert.match(authorization,
  /productionNetlifyOrigin:\s*validated\.protocol\.deploymentBoundary\.productionNetlifyOrigin/);
assert.match(netlify,
  /boundary\.productionNetlifySiteId !== POLICY\.productionDenylist\.netlifySiteId/);
assert.match(netlify,
  /boundary\.productionNetlifyOrigin !== POLICY\.productionDenylist\.netlifyOrigin/);
assert.match(netlify,
  /exclusion\?\.productionNetlifySiteId !== POLICY\.productionDenylist\.netlifySiteId/);
assert.match(netlify,
  /exclusion\?\.productionNetlifyOrigin !== POLICY\.productionDenylist\.netlifyOrigin/);
assert.match(netlify, /publisherInventoryLiveVerified !== true/);
assert.match(netlify, /liveNetlifyAuthorityBoundaryEvidenceSha256/);
assert.match(netlify, /CNYOS_CONTROLLER_BACKUP_DISABLE_EVIDENCE_PATH_REQUIRED/);
assert.match(netlify, /await loadAndValidateRuntimeProofEnvelope\(/);
assert.match(netlify, /validateBackupDisableRuntimeEvidenceReceipt\(/);
assert.match(netlify, /validateRuntimeCapabilityEvidenceReceipt\(/);
assert.match(finalizer, /await loadAndValidateRuntimeProofEnvelope\(/);
assert.match(finalizer, /runtimeProofEnvelope: runtimeProofEnvelope\.sha256/);
assert.match(netlify, /anonymousDraftAccessDenied !== true/);
assert.match(netlify, /Authorization: `Bearer \$\{accessToken\}`/);
assert.match(netlify, /await exactSiteInventory\(fetchImpl, token, preflight\.value\.rollbackNetlifyPrincipalSubject\)/);
assert.match(netlify, /verify-final-current/);
const rollbackFreshnessBlock = netlify.match(
  /function rollbackReadinessMaximumAgeMilliseconds\(\) \{([\s\S]*?)\n\}/
)?.[1];
assert.ok(rollbackFreshnessBlock, 'rollback-readiness freshness policy helper');
assert.match(rollbackFreshnessBlock,
  /POLICY\.rollbackPrincipalMembershipBroker\?\.maximumEvidenceAgeMinutes/);
assert.doesNotMatch(rollbackFreshnessBlock, /databaseEvidence/);
assert.match(netlify,
  /expiresAt\.getTime\(\) - verifiedAt\.getTime\(\) > maximumAge/);
assert.match(netlify, /expiresAt > authorizationExpiresAt/);
assert.match(netlify,
  /rollbackReadinessEvidenceSha256: recoveryChain\.rollbackReadiness\.sha256/);
assert.match(netlify, /draftGateEvidenceSha256: recoveryChain\.draftGate\.sha256/);
const promoteFunction = netlify.slice(
  netlify.indexOf('export async function promoteExactDraft'),
  netlify.indexOf('export async function verifyPromotedDeployment')
);
const draftMetadataPromotionChainChecks = [
  ...promoteFunction.matchAll(/assertDraftMetadataPromotionChain\(/g)
];
assert.equal(draftMetadataPromotionChainChecks.length, 2,
  'promotion must validate draft metadata once at entry and again at the mutation clock');
assert.equal(
  [...promoteFunction.matchAll(/validateControlBehavior\(/g)].length,
  2,
  'promotion must validate exact control behavior once at entry and again at the mutation clock'
);
assert.match(finalizer, /validateNetlifyControlBehaviorEvidence\(controlBehavior\.value,/,
  'finalization must independently validate the exact control-behavior schema');
const promotionMutationClockIndex = promoteFunction.indexOf('const mutationAt = now()');
const promotionRestoreRequestIndex = promoteFunction.indexOf(
  'const promotion = await netlifyRequest('
);
const immediateGitHubRevalidationIndex = promoteFunction.indexOf(
  'const immediateLiveGitHubBoundary = await validateStoredLiveGitHubReleaseBoundary('
);
assert.ok(
  draftMetadataPromotionChainChecks[0].index < promotionMutationClockIndex &&
  promotionMutationClockIndex < draftMetadataPromotionChainChecks[1].index &&
  draftMetadataPromotionChainChecks[1].index < promotionRestoreRequestIndex,
  'mutation-clock draft metadata freshness validation must precede the restore POST'
);
assert.match(
  promoteFunction.slice(
    draftMetadataPromotionChainChecks[1].index,
    promotionRestoreRequestIndex
  ),
  /assertDraftMetadataPromotionChain\([\s\S]*?runtime,\s*mutationAt,\s*'CNYOS_CONTROLLER_PROMOTION_CHAIN_INVALID'/,
  'the second draft metadata validation must use the mutation clock'
);
assert.ok(
  immediateGitHubRevalidationIndex >= 0 &&
  immediateGitHubRevalidationIndex < promotionMutationClockIndex,
  'all asynchronous GitHub evidence revalidation must finish before the mutation clock'
);
const immediateMutationBoundary = promoteFunction.slice(
  promotionMutationClockIndex,
  promotionRestoreRequestIndex
);
assert.doesNotMatch(immediateMutationBoundary, /\bawait\b/,
  'no asynchronous work may make fresh evidence stale after the mutation clock');
assert.match(immediateMutationBoundary,
  /recentCanonicalTimestamp\(\s*immediateLiveGitHubBoundary\.evidence\.checkedAt,\s*mutationAt,/,
  'the immediate GitHub boundary must still be fresh at the mutation clock');
assert.match(immediateMutationBoundary, /leaseExpiresAt <= mutationAt/,
  'the publisher lease must still be active at the mutation clock');
assertOrdered(promoteFunction, [
  'loadAndValidatePromotionRecoveryChain(',
  'const immediateLiveGitHubBoundary = await validateStoredLiveGitHubReleaseBoundary(',
  'const mutationAt = now()',
  'assertFreshPreflight(preflight.value, runtime, mutationAt)',
  'assertDraftMetadataPromotionChain(',
  'validateRollbackReadinessEvidence(recoveryChain.rollbackReadiness.value',
  'validatePromotionDraftGate(recoveryChain.draftGate.value',
  '/restore`'
], 'fresh rollback-readiness and draft-gate chain immediately before promotion');
assert.match(finalizer, /finalCurrentVerification/);
assert.match(finalizer, /CNYOS_FINAL_AUTHORIZATION_OR_PUBLISHER_LEASE_EXPIRED/);
for (const barrierInvariant of [
  'runReconciliationBarrierActiveAfterRelease',
  'runReconciliationBarrierGeneration',
  'automaticRunReconciliationBarrierExpiryPermitted',
  'draftIntentTerminalBeforeRunReconciliationBarrierClearRequired'
]) assert.match(finalizer, new RegExp(barrierInvariant), barrierInvariant);
assert.match(finalizer, /value\.runReconciliationBarrierActiveAfterRelease !== true/);
assert.match(finalizer,
  /value\.runReconciliationBarrierGeneration !== exclusivePublisher\.lockLeaseId/);
assert.match(finalizer,
  /value\.automaticRunReconciliationBarrierExpiryPermitted !== false/);
assert.match(finalizer,
  /value\.draftIntentTerminalBeforeRunReconciliationBarrierClearRequired !== true/);
assert.match(netlify, /publisherLock\.value\.runReconciliationBarrierActive !== true/);
assert.match(netlify,
  /publisherLock\.value\.runReconciliationBarrierGeneration !==\s*publisherLock\.value\.lockLeaseId/);
assert.match(netlify,
  /publisherLock\.value\.newMutationBlockedWhileRunReconciliationBarrierActive !== true/);
assert.match(netlify,
  /publisherLock\.value\.automaticRunReconciliationBarrierExpiryPermitted !== false/);
for (const required of [
  'preReleaseReconciliation',
  'authorizationVerificationBundle',
  'rollbackAttestationDepositReceipt',
  'rollbackAttestationDepositValidation',
  'liveNetlifyAuthorityBoundary',
  'functionEnvironment',
  'runtimeProofEnvelope',
  'backupDisableRuntimeBoundary',
  'runtimeCapabilityBoundary',
  'rollbackReadiness',
  'draftGate',
  'durableDraftIntent',
  'privateDraftAccessBoundary',
  'draftMetadata',
  'promotionAttempt'
]) assert.match(finalizer, new RegExp(`${required}: [A-Za-z]+\\.sha256`), required);
const expectedRetainedEvidenceKeys = [
  'producerManifest', 'preReleaseReconciliation', 'authorization',
  'authorizationVerificationBundle', 'liveGitHubPrecredentialBoundary',
  'liveGitHubPrepromotionBoundary', 'rollbackAttestationDepositReceipt',
  'rollbackAttestationDepositValidation', 'liveNetlifyAuthorityBoundary',
  'functionEnvironment', 'runtimeProofEnvelope', 'backupDisableRuntimeBoundary', 'runtimeCapabilityBoundary',
  'preflight', 'rollbackReadiness', 'draftGate', 'durableDraftIntent', 'draftReceipt',
  'draftMetadata', 'draftVerification', 'controlBehavior', 'privateDraftAccessBoundary',
  'privateDraftLifecycle', 'exclusivePublisherLease', 'promotionAttempt',
  'exactPromotion', 'postPromotionVerification', 'scheduledFunctionRouteDenial',
  'authenticatedUat', 'finalCurrentVerification', 'exclusivePublisherRelease'
];
const finalizerRetainedBlock = finalizer.match(
  /const retained = Object\.freeze\(\{([\s\S]*?)\n\s*\}\);/
)?.[1];
assert.ok(finalizerRetainedBlock, 'finalizer retained-evidence object');
assert.deepEqual(
  [...finalizerRetainedBlock.matchAll(/^\s+([A-Za-z][A-Za-z0-9]+):/gm)].map(match => match[1]),
  expectedRetainedEvidenceKeys,
  'finalizer retained-evidence keys'
);
const authorizationRetainedBlock = authorization.match(
  /assertExactKeys\(value\.retainedEvidenceSha256, \[([\s\S]*?)\n\s*\],\s*'CNYOS_CONTROLLER_KNOWN_GOOD_EVIDENCE_INVALID'\);/
)?.[1];
assert.ok(authorizationRetainedBlock, 'known-good retained-evidence allowlist');
assert.deepEqual(
  [...authorizationRetainedBlock.matchAll(/'([A-Za-z][A-Za-z0-9]+)'/g)].map(match => match[1]),
  expectedRetainedEvidenceKeys,
  'final evidence must remain reusable as the next known-good rollback record'
);
for (const [pathName, digestName] of [
  ['CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH',
    'CNYOS_EXPECTED_RECONCILIATION_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_AUTHORIZATION_BUNDLE_PATH',
    'CNYOS_EXPECTED_AUTHORIZATION_BUNDLE_SHA256'],
  ['CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_PATH',
    'CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_RECEIPT_SHA256'],
  ['CNYOS_CONTROLLER_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_PATH',
    'CNYOS_EXPECTED_ROLLBACK_ATTESTATION_DEPOSIT_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH',
    'CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH',
    'CNYOS_EXPECTED_FUNCTION_ENV_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_BACKUP_DISABLE_EVIDENCE_PATH',
    'CNYOS_EXPECTED_BACKUP_DISABLE_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_RUNTIME_CAPABILITY_EVIDENCE_PATH',
    'CNYOS_EXPECTED_RUNTIME_CAPABILITY_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_ROLLBACK_READINESS_EVIDENCE_PATH',
    'CNYOS_EXPECTED_ROLLBACK_READINESS_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_DRAFT_GATE_EVIDENCE_PATH',
    'CNYOS_EXPECTED_DRAFT_GATE_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH',
    'CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH',
    'CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_PATH',
    'CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256'],
  ['CNYOS_CONTROLLER_PUBLISH_ATTEMPT_EVIDENCE_PATH',
    'CNYOS_EXPECTED_PUBLISH_ATTEMPT_EVIDENCE_SHA256']
]) {
  assert.match(finalizer, new RegExp(`'${pathName}'[\\s\\S]{0,120}'${digestName}'`));
  assert.match(finalizeStep, new RegExp(`${pathName}:[\\s\\S]{0,240}${digestName}:`));
}
assert.match(finalizer,
  /draftVerification\.value\.privateDraftAccessBoundaryEvidenceSha256 !==\s*privateDraftAccessBoundary\.sha256/);
assert.match(finalizer,
  /draftVerification\.value\.draftMetadataEvidenceSha256 !== draftMetadata\.sha256/);
assert.match(finalizer,
  /preflight\.value\.preReleaseReconciliationEvidenceSha256 !==\s*preReleaseReconciliation\.sha256/);
assert.match(finalizer,
  /preflight\.value\.functionEnvironmentEvidenceSha256 !== functionEnvironment\.sha256/);
assert.match(finalizer,
  /functionEnvironment\.value\.liveGitHubPrecredentialBoundaryEvidenceSha256 !==\s*liveGitHubPrecredentialBoundary\.sha256/);
assert.match(finalizer,
  /functionEnvironmentVerifiedAt < precredentialGitHubCheckedAt/);
assert.match(finalizer,
  /functionEnvironmentVerifiedAt\.getTime\(\) - precredentialGitHubCheckedAt\.getTime\(\) >/);
assert.match(finalizer,
  /functionEnvironmentVerifiedAt > preflightCapturedAt/);
assert.match(netlify,
  /promotedAt: mutationAt\.toISOString\(\)/);
assert.match(finalizer,
  /prepromotionGitHubCheckedAt > promotionAttemptedAt/);
assert.match(finalizer,
  /promotionAttemptedAt > promotionMutationAt/);
assert.match(finalizer,
  /promotionMutationAt < prepromotionGitHubCheckedAt/);
assert.match(finalizer,
  /promotionMutationAt\.getTime\(\) - prepromotionGitHubCheckedAt\.getTime\(\) >/);
assert.match(finalizer,
  /promotionMutationAt > postPromotionVerifiedAt/);
assert.match(finalizer,
  /preflight\.value\.backupDisableEvidenceSha256 !== backupDisableRuntimeBoundary\.sha256/);
assert.match(finalizer,
  /preflight\.value\.runtimeCapabilityEvidenceSha256 !== runtimeCapabilityBoundary\.sha256/);
assert.match(finalizer,
  /promotionAttempt\.value\.rollbackReadinessEvidenceSha256 !== rollbackReadiness\.sha256/);
assert.match(finalizer,
  /promotionAttempt\.value\.draftGateEvidenceSha256 !== draftGate\.sha256/);
assert.match(finalizeStep,
  /CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256: \$\{\{ needs\.verify_draft\.outputs\.draft_access_boundary_sha256 \}\}/);
assert.match(finalizeStep,
  /CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256: \$\{\{ needs\.verify_draft\.outputs\.draft_metadata_sha256 \}\}/);
assert.match(release,
  /function_environment_sha256: \$\{\{ steps\.function_environment\.outputs\.evidence_sha256 \}\}/);
assert.match(release,
  /backup_disable_sha256: \$\{\{ steps\.runtime_boundaries\.outputs\.backup_disable_sha256 \}\}/);
assert.match(release,
  /runtime_capability_sha256: \$\{\{ steps\.runtime_boundaries\.outputs\.runtime_capability_sha256 \}\}/);
assert.match(functionEnvironmentStep,
  /echo "evidence_sha256=\$\(sha256sum "\$CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH"/);
assert.match(runtimeBoundariesStep,
  /echo "backup_disable_sha256=\$BACKUP_DISABLE_SHA" >> "\$GITHUB_OUTPUT"/);
assert.match(runtimeBoundariesStep,
  /echo "runtime_capability_sha256=\$RUNTIME_CAPABILITY_SHA" >> "\$GITHUB_OUTPUT"/);
assert.match(promoteJob,
  /name: Download exact draft verification[\s\S]{0,360}name: cnyos-draft-verification-\$\{\{ github\.run_id \}\}[\s\S]{0,240}path: controller\/release-chain\/evidence/);
for (const output of [
  'pre_release_reconciliation_sha256: ${{ steps.reconciliation.outputs.evidence_sha256 }}',
  'live_netlify_authority_sha256: ${{ steps.live_authority.outputs.evidence_sha256 }}',
  'draft_intent_sha256: ${{ steps.intent.outputs.draft_intent_sha256 }}'
]) assert.ok(release.includes(output), output);
assert.match(finalizer,
  /rollbackAttestationValidation\.value\.depositReceiptSha256 !==\s*rollbackAttestationReceipt\.sha256/);
assert.match(finalizer,
  /draftGate\.value\.rollbackReadinessEvidenceSha256 !== rollbackReadiness\.sha256/);
assert.match(finalizer,
  /promotion\.value\.promotionAttemptEvidenceSha256 !== promotionAttempt\.sha256/);

assert.match(release, /environment: cnyos-staging-rollback/);
assert.match(release, /CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN/);
const failedRecoveryPreparationJob = workflowJobSlice(
  release,
  'prepare_failed_release_reconciliation'
);
const failedRecoveryExecutionJob = workflowJobSlice(release, 'reconcile_failed_release');
const failedRecoveryFinalizationJob = workflowJobSlice(
  release,
  'finalize_failed_release_reconciliation'
);
assertOrdered(release, [
  '\n  prepare_failed_release_reconciliation:',
  '\n  reconcile_failed_release:',
  '\n  finalize_failed_release_reconciliation:'
], 'failed release recovery credential-isolation topology');
for (const failedResult of [
  'needs.draft_deploy.result',
  'needs.acquire_exclusive_publisher.result',
  'needs.promote_and_validate.result',
  'needs.validate_promoted_routes.result',
  'needs.run_promoted_uat.result',
  'needs.verify_promoted_final_current.result',
  'needs.release_and_finalize.result',
  'needs.commit_successful_release.result'
]) {
  assert.match(failedRecoveryPreparationJob,
    new RegExp(`${failedResult.replaceAll('.', '\\.')} != 'success'`));
  assert.match(failedRecoveryFinalizationJob,
    new RegExp(`${failedResult.replaceAll('.', '\\.')} != 'success'`));
}
assert.match(failedRecoveryPreparationJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: write/);
assert.match(failedRecoveryPreparationJob, /if: \$\{\{ always\(\)/);
assert.deepEqual(secretReferences(failedRecoveryPreparationJob), []);
assert.match(failedRecoveryPreparationJob,
  /needs: \[authorize_preflight, prepare_draft_intent, draft_deploy, acquire_exclusive_publisher, promote_and_validate, validate_promoted_routes, run_promoted_uat, verify_promoted_final_current, release_and_finalize, commit_successful_release\]/);
assert.match(failedRecoveryPreparationJob,
  /id: download_draft_intent\n\s+if: \$\{\{ needs\.prepare_draft_intent\.result == 'success' \}\}[\s\S]*name: cnyos-draft-intent-\$\{\{ github\.run_id \}\}/);
assert.doesNotMatch(failedRecoveryPreparationJob,
  /if: \$\{\{[^\n]*outputs\.draft_intent_sha256 != ''/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_DRAFT_INTENT_JOB_RESULT: \$\{\{ needs\.prepare_draft_intent\.result \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_DRAFT_INTENT_ARTIFACT_DOWNLOAD_OUTCOME: \$\{\{ steps\.download_draft_intent\.outcome \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256: \$\{\{ needs\.prepare_draft_intent\.outputs\.draft_intent_sha256 \}\}/);
assert.match(failedRecoveryPreparationJob,
  /id: download_final\n\s+if: \$\{\{ needs\.release_and_finalize\.result == 'success' \}\}[\s\S]*name: cnyos-final-\$\{\{ github\.run_id \}\}/);
assert.doesNotMatch(failedRecoveryPreparationJob,
  /if: \$\{\{[^\n]*outputs\.final_sha256 != ''/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_FINAL_ARTIFACT_DOWNLOAD_OUTCOME: \$\{\{ steps\.download_final\.outcome \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_SUCCESSFUL_RELEASE_COMMIT_JOB_RESULT: \$\{\{ needs\.commit_successful_release\.result \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_EXPECTED_FINAL_EVIDENCE_SHA256: \$\{\{ needs\.release_and_finalize\.outputs\.final_sha256 \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_EXPECTED_PUBLISHER_RELEASE_EVIDENCE_SHA256: \$\{\{ needs\.release_and_finalize\.outputs\.publisher_release_sha256 \}\}/);
for (const [stepId, producer, artifact] of [
  ['download_draft', 'draft_deploy', 'cnyos-draft'],
  ['download_promotion', 'promote_and_validate', 'cnyos-promotion']
]) {
  assert.match(failedRecoveryPreparationJob, new RegExp(
    `id: ${stepId}\\n\\s+if: \\$\\{\\{ needs\\.${producer}\\.result == 'success' \\}\\}` +
    `[\\s\\S]*name: ${artifact}-\\$\\{\\{ github\\.run_id \\}\\}`
  ));
}
assert.match(failedRecoveryPreparationJob,
  /if: \$\{\{ needs\.acquire_exclusive_publisher\.result == 'success' \}\}[\s\S]*name: cnyos-attempt-\$\{\{ github\.run_id \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_PROMOTION_JOB_RESULT: \$\{\{ needs\.promote_and_validate\.result \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_ROUTE_VALIDATION_JOB_RESULT: \$\{\{ needs\.validate_promoted_routes\.result \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_UAT_JOB_RESULT: \$\{\{ needs\.run_promoted_uat\.result \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_FINAL_CURRENT_JOB_RESULT: \$\{\{ needs\.verify_promoted_final_current\.result \}\}/);
assert.match(failedRecoveryPreparationJob,
  /CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256: \$\{\{ needs\.promote_and_validate\.outputs\.promotion_sha256 \}\}/);
assert.doesNotMatch(failedRecoveryPreparationJob,
  /if: \$\{\{[^\n]*outputs\.attempt_sha256 != ''/);
assert.match(failedRecoveryPreparationJob, /prepare-failed-release-reconciliation/);
assert.match(failedRecoveryPreparationJob,
  /recovery_disposition: \$\{\{ steps\.prepare\.outputs\.recovery_disposition \}\}/);
assert.match(failedRecoveryPreparationJob,
  /terminal_receipt_sha256: \$\{\{ steps\.prepare\.outputs\.terminal_receipt_sha256 \}\}/);
assert.match(failedRecoveryPreparationJob,
  /recovery_terminal_receipt_sha256: \$\{\{ steps\.prepare\.outputs\.recovery_terminal_receipt_sha256 \}\}/);
assert.match(failedRecoveryPreparationJob,
  /case "\$recovery_disposition" in[\s\S]*recovery_required\)[\s\S]*terminal_success_rehydrated\)[\s\S]*terminal_recovery_rehydrated\)/);
assert.match(failedRecoveryPreparationJob,
  /name: cnyos-reconciliation-preparation-\$\{\{ github\.run_id \}\}/);
for (const filename of ['reconciliation-plan.json', 'rollback-authorization-chain.json']) {
  assert.match(failedRecoveryPreparationJob, new RegExp(filename.replaceAll('.', '\\.')));
}
assert.match(failedRecoveryPreparationJob, /test -n "\$\{ACTIONS_ID_TOKEN_REQUEST_URL:-\}"/);
assert.doesNotMatch(failedRecoveryPreparationJob,
  /CNYOS_STAGING_NETLIFY_(?:AUTH|ROLLBACK)_TOKEN:\s*\$\{\{\s*secrets\./);

assert.match(failedRecoveryExecutionJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: none/);
assert.match(failedRecoveryExecutionJob,
  /if: \$\{\{ always\(\) && needs\.prepare_failed_release_reconciliation\.result == 'success' && needs\.prepare_failed_release_reconciliation\.outputs\.recovery_disposition == 'recovery_required' \}\}/);
assert.deepEqual(secretReferences(failedRecoveryExecutionJob), [
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN'
]);
assert.match(failedRecoveryExecutionJob,
  /CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: \$\{\{ secrets\.CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN \}\}/);
assert.doesNotMatch(failedRecoveryExecutionJob,
  /CNYOS_(?:ROLLBACK_ATTESTATION|NETLIFY_PUBLISH|DRAFT_LIFECYCLE|NETLIFY_AUTHORITY|NETLIFY_PRINCIPAL_MEMBERSHIP)_BROKER_URL:\s*\$\{\{/);
assert.match(failedRecoveryExecutionJob, /ACTIONS_ID_TOKEN_REQUEST_URL \\/);
assert.match(failedRecoveryExecutionJob, /ACTIONS_ID_TOKEN_REQUEST_TOKEN \\/);
assert.match(failedRecoveryExecutionJob,
  /execute-failed-release-reconciliation-plan/);
assert.match(failedRecoveryExecutionJob,
  /CNYOS_REQUIRED_RECOVERY_DISPOSITION: recovery_required/);
assertOrdered(failedRecoveryExecutionJob, [
  'sha256sum "$CNYOS_CONTROLLER_RECONCILIATION_PLAN_PATH"',
  'sha256sum "$CNYOS_CONTROLLER_ROLLBACK_CHAIN_EVIDENCE_PATH"',
  'execute-failed-release-reconciliation-plan',
  'execution_receipt_sha256='
], 'recovery mutation consumes hash-bound plan and emits its receipt');

assert.match(failedRecoveryFinalizationJob,
  /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: write/);
assert.match(failedRecoveryFinalizationJob, /if: \$\{\{ always\(\)/);
assert.match(failedRecoveryFinalizationJob,
  /needs: \[authorize_preflight, draft_deploy, acquire_exclusive_publisher, promote_and_validate, validate_promoted_routes, run_promoted_uat, verify_promoted_final_current, release_and_finalize, commit_successful_release, prepare_failed_release_reconciliation, reconcile_failed_release\]/);
assert.deepEqual(secretReferences(failedRecoveryFinalizationJob), []);
assert.match(failedRecoveryFinalizationJob,
  /needs\.reconcile_failed_release\.result == 'success' && needs\.reconcile_failed_release\.outputs\.execution_receipt_sha256 != ''/);
assert.match(failedRecoveryFinalizationJob,
  /continue-on-error: true[\s\S]*name: cnyos-reconciliation-netlify-\$\{\{ github\.run_id \}\}/);
assert.match(failedRecoveryFinalizationJob,
  /test -n "\$\{ACTIONS_ID_TOKEN_REQUEST_URL:-\}"/);
assertOrdered(failedRecoveryFinalizationJob, [
  'preparation_verified=false',
  'execution_verified=false',
  'sha256sum "$CNYOS_CONTROLLER_RECONCILIATION_EXECUTION_RECEIPT_PATH"',
  'terminal_success_verified=false',
  'CNYOS_RECOVERY_DISPOSITION" = "terminal_success_rehydrated',
  'if test "$preparation_verified" = "true" &&',
  'CNYOS_RECOVERY_DISPOSITION" = "recovery_required',
  'finalize-failed-release-reconciliation-success',
  'elif test "$terminal_success_verified" = "true"',
  'finalize-rehydrated-successful-release',
  'elif test "$terminal_recovery_verified" = "true"',
  'finalize-rehydrated-recovery',
  'else',
  'record-incomplete-failed-release-reconciliation'
], 'failed-release finalization separates recovery from rehydrated terminal success');
assert.match(failedRecoveryFinalizationJob,
  /name: cnyos-reconciliation-\$\{\{ github\.run_id \}\}/);
assert.doesNotMatch(failedRecoveryFinalizationJob,
  /CNYOS_STAGING_NETLIFY_(?:AUTH|ROLLBACK)_TOKEN:\s*\$\{\{\s*secrets\./);
assert.match(watchdog, /CNYOS_CONTROLLER_WORKFLOW_PATH: \.github\/workflows\/cnyos-staging-rollback-watchdog\.yml/);
assert.match(watchdog, /SOURCE_EVENT.*workflow_dispatch/s);
assert.match(watchdog, /git rev-parse HEAD/);
for (const mode of [
  'prepare-watchdog-recovery',
  'execute-watchdog-recovery-plan',
  'finalize-watchdog-recovery-success',
  'finalize-rehydrated-successful-release',
  'finalize-rehydrated-recovery',
  'record-incomplete-watchdog-recovery'
]) assert.match(watchdog, new RegExp(`reconcile-netlify-release-state\\.mjs ${mode}`));

const runtime = {
  GITHUB_REPOSITORY: POLICY.controller.repository,
  CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
  GITHUB_RUN_ID: '123456',
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_REF_PROTECTED: 'true',
  CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
  GITHUB_REF: POLICY.controller.protectedRef,
  GITHUB_SHA: 'a'.repeat(40),
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
  GITHUB_WORKFLOW_REF:
    `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
  GITHUB_ACTOR: 'apisarit',
  GITHUB_TRIGGERING_ACTOR: 'apisarit'
};
const parsedRuntime = assertControllerRuntime(runtime);
const promotionMetadataVerifiedAt = '2026-09-08T12:00:00.000Z';
const promotionMetadataSource = Object.freeze({
  repository: POLICY.sourceRepository,
  commit: 'b'.repeat(40),
  tree: 'c'.repeat(40),
  functionSourceTree: 'd'.repeat(40)
});
const promotionMetadataArtifact = Object.freeze({
  producerManifestSha256: '1'.repeat(64),
  artifactSha256: '2'.repeat(64)
});
const promotionMetadataSchedules = Object.freeze(
  Object.entries(REQUIRED_SCHEDULES).map(([name, cron]) => Object.freeze({ name, cron }))
);
const promotionMetadataFunctions = Object.freeze([...EXPECTED_FUNCTION_NAMES]);
const promotionMetadataFunctionProvenance = Object.freeze({
  netlifyCliVersion: POLICY.publishing.netlifyCliVersion,
  functionSourceTree: promotionMetadataSource.functionSourceTree,
  skipFunctionsCacheRequired: true
});
const promotionMetadataDraftDeployId = 'fedcba987654321001234567';
const promotionMetadataPreviousDeployId = '0123456789abcdef01234567';
const promotionMetadataExactDeployOrigin =
  `https://${promotionMetadataDraftDeployId}--${POLICY.target.netlifySiteName}.netlify.app`;
const promotionMetadataReceiptSha256 = '3'.repeat(64);
const promotionMetadataPreflight = Object.freeze({ value: Object.freeze({
  dispatchNonce: Buffer.alloc(32, 0x44).toString('base64url'),
  source: promotionMetadataSource,
  artifact: promotionMetadataArtifact,
  previousPublishedDeploy: Object.freeze({ id: promotionMetadataPreviousDeployId })
}) });
const promotionMetadataEvidence = Object.freeze({
  sha256: '4'.repeat(64),
  value: Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_draft_metadata_verification',
    status: 'passed',
    authorization: false,
    promotionAuthorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: promotionMetadataVerifiedAt,
    controllerRepository: parsedRuntime.repository,
    controllerRef: parsedRuntime.ref,
    controllerCommit: parsedRuntime.commit,
    controllerRunId: parsedRuntime.runId,
    dispatchNonce: promotionMetadataPreflight.value.dispatchNonce,
    source: promotionMetadataSource,
    artifact: promotionMetadataArtifact,
    target: POLICY.target,
    previousDeployId: promotionMetadataPreviousDeployId,
    currentPublishedDeployId: promotionMetadataPreviousDeployId,
    draftDeployId: promotionMetadataDraftDeployId,
    exactDraftDeployOrigin: promotionMetadataExactDeployOrigin,
    schedules: promotionMetadataSchedules,
    functionNames: promotionMetadataFunctions,
    functionProcessProvenance: promotionMetadataFunctionProvenance,
    functionByteAttestationAvailable: false,
    publisherCredentialIsolated: true,
    publisherCredentialOpaqueIdentityHmacSha256: '5'.repeat(64),
    credentialSeparationHmacKeyConfirmationSha256: '6'.repeat(64),
    credentialSeparationHmacKeySerialized: false,
    draftReceiptEvidenceSha256: promotionMetadataReceiptSha256
  })
});
const promotionMetadataVerification = Object.freeze({ value: Object.freeze({
  artifact: promotionMetadataArtifact,
  draftDeployId: promotionMetadataDraftDeployId,
  exactDraftDeployOrigin: promotionMetadataExactDeployOrigin,
  schedules: promotionMetadataSchedules,
  functionNames: promotionMetadataFunctions,
  functionProcessProvenance: promotionMetadataFunctionProvenance,
  draftReceiptEvidenceSha256: promotionMetadataReceiptSha256,
  draftMetadataEvidenceSha256: promotionMetadataEvidence.sha256,
  publisherAndDraftAccessCredentialCoResidencyPrevented: true,
  credentialSeparationHmacKeyConfirmed: true,
  credentialSeparationHmacKeySerialized: false
}) });
assert.doesNotThrow(() => assertDraftMetadataPromotionChain(
  promotionMetadataEvidence,
  promotionMetadataVerification,
  promotionMetadataPreflight,
  parsedRuntime,
  new Date('2026-09-08T12:10:00.000Z'),
  'CNYOS_TEST_DRAFT_METADATA_STALE'
), 'draft metadata remains valid at the exact ten-minute boundary');
assert.throws(() => assertDraftMetadataPromotionChain(
  promotionMetadataEvidence,
  promotionMetadataVerification,
  promotionMetadataPreflight,
  parsedRuntime,
  new Date('2026-09-08T12:10:00.001Z'),
  'CNYOS_TEST_DRAFT_METADATA_STALE'
), /CNYOS_TEST_DRAFT_METADATA_STALE/,
'an advancing mutation clock must reject metadata one millisecond past its freshness boundary');
assert.equal(assertControllerRuntime(runtime).workflowPath, POLICY.controller.releaseWorkflowPath);
assert.equal(assertControllerRuntime({
  ...runtime,
  GITHUB_ACTOR: 'ApiSarit',
  GITHUB_TRIGGERING_ACTOR: 'apisarit'
}).actor, 'ApiSarit');
assert.throws(() => assertControllerRuntime({ ...runtime, GITHUB_WORKFLOW_REF:
  `${POLICY.controller.repository}/.github/workflows/evil.yml@${POLICY.controller.protectedRef}` }),
/CNYOS_CONTROLLER_WORKFLOW_REF_INVALID/);
assert.equal(sameGitHubLogin('Jaoball', 'jaoball'), true);
assert.equal(sameGitHubLogin('Jaoball', 'jaoball '), false);
assert.equal(sameGitHubLogin('bad_login', 'bad_login'), false);
assert.equal(sameGitHubLogin(123, '123'), false);
assert.doesNotThrow(() => assertDistinctOpaquePrincipalSubjects('principal-A', 'principal-a'));
assert.throws(
  () => assertDistinctOpaquePrincipalSubjects('principal-A', 'principal-A'),
  /CNYOS_CONTROLLER_NETLIFY_PRINCIPALS_NOT_DISTINCT/
);
assert.throws(
  () => assertDistinctOpaquePrincipalSubjects(' principal-A', 'principal-A'),
  /CNYOS_CONTROLLER_NETLIFY_PRINCIPALS_NOT_DISTINCT/
);

const referenceTime = new Date('2026-09-08T12:00:00.000Z');
assert.equal(
  canonicalIsoTimestamp('2026-09-08T11:59:59.999Z').toISOString(),
  '2026-09-08T11:59:59.999Z'
);
for (const invalid of [
  undefined,
  'junk',
  '2026-02-30T00:00:00.000Z',
  '2026-09-08T12:00:00Z',
  '2026-09-08T12:00:00.000+00:00',
  ' 2026-09-08T12:00:00.000Z'
]) assert.throws(() => canonicalIsoTimestamp(invalid), /TIMESTAMP_INVALID/);
assert.equal(
  minimumFutureTimestamp(
    '2026-09-08T12:45:00.000Z',
    referenceTime,
    45 * 60 * 1000
  ).toISOString(),
  '2026-09-08T12:45:00.000Z'
);
for (const invalidLease of [
  '2026-09-08T11:59:59.999Z',
  '2026-09-08T12:44:59.999Z',
  'not-a-lease'
]) assert.throws(
  () => minimumFutureTimestamp(invalidLease, referenceTime, 45 * 60 * 1000),
  /TIMESTAMP_INVALID/
);
assert.equal(
  recentCanonicalTimestamp(
    '2026-09-08T11:30:00.000Z',
    referenceTime,
    30 * 60 * 1000
  ).toISOString(),
  '2026-09-08T11:30:00.000Z'
);
for (const staleOrFuture of [
  '2026-09-08T11:29:59.999Z',
  '2026-09-08T12:00:00.001Z',
  'invalid'
]) assert.throws(
  () => recentCanonicalTimestamp(staleOrFuture, referenceTime, 30 * 60 * 1000),
  /TIMESTAMP_INVALID/
);
assert.equal(portableRelativePath('assets/app.js'), 'assets/app.js');
assert.throws(() => portableRelativePath('assets/e\u0301.js'), /ARTIFACT_PATH_INVALID/);

assert.deepEqual(NETLIFY_CLI_CHILD_ENVIRONMENT_NAMES, [
  'CI',
  'HOME',
  'LANG',
  'LC_ALL',
  'NETLIFY_AUTH_TOKEN',
  'NETLIFY_CLI_TELEMETRY_DISABLED',
  'NETLIFY_SITE_ID',
  'NO_COLOR',
  'PATH',
  'TMPDIR',
  'TZ',
  'XDG_CACHE_HOME',
  'XDG_CONFIG_HOME'
]);
assert.deepEqual(FUNCTION_ENVIRONMENT_PREREQUISITE_ENVIRONMENT_NAMES, [
  'CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH',
  'CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256',
  'CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE'
]);
const directPrerequisiteEnvironment = functionEnvironmentPrerequisiteEnvironment({
  CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: '/offline/authorization.json',
  CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH: '/offline/github-boundary.json',
  CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH: '/offline/live-authority.json',
  CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: 'a'.repeat(64),
  CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256: 'c'.repeat(64),
  CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256: 'b'.repeat(64),
  CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE: 'before_netlify_credential',
  CNYOS_STAGING_NETLIFY_AUTH_TOKEN: 'must-not-be-projected',
  CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: 'must-not-be-projected'
});
assert.deepEqual(Object.keys(directPrerequisiteEnvironment).sort(),
  FUNCTION_ENVIRONMENT_PREREQUISITE_ENVIRONMENT_NAMES);
assert.equal(Object.isFrozen(directPrerequisiteEnvironment), true);
assert.equal('CNYOS_STAGING_NETLIFY_AUTH_TOKEN' in directPrerequisiteEnvironment, false);
assert.equal('CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY' in directPrerequisiteEnvironment, false);
const directChildEnvironment = netlifyCliChildEnvironment({
  token: 'offline-publisher-token',
  isolatedStateRoot: '/tmp/cnyos-netlify-child-contract',
  nodeExecutable: '/opt/cnyos-node/bin/node'
});
assert.deepEqual(Object.keys(directChildEnvironment).sort(),
  NETLIFY_CLI_CHILD_ENVIRONMENT_NAMES);
assert.equal(Object.isFrozen(directChildEnvironment), true);
assert.equal(directChildEnvironment.PATH,
  ['/opt/cnyos-node/bin', '/usr/local/bin', '/usr/bin', '/bin'].join(path.delimiter));
for (const invalidToken of [undefined, '', 'too-short', ' token-with-padding',
  'token-with-newline-012345\n']) {
  assert.throws(() => netlifyCliChildEnvironment({
    token: invalidToken,
    isolatedStateRoot: '/tmp/cnyos-netlify-child-contract'
  }), /CNYOS_CONTROLLER_NETLIFY_TOKEN_(?:REQUIRED|INVALID)/);
}

const functionBoundaryCheckedAt = '2026-09-08T11:59:00.000Z';
const functionBoundaryVerifiedAt = '2026-09-08T11:59:30.000Z';
const functionBoundaryObservedAt = new Date('2026-09-08T12:00:00.000Z');
const functionBoundarySha256 = 'f'.repeat(64);
const functionBoundaryFixture = Object.freeze({
  value: Object.freeze({
    verifiedAt: functionBoundaryVerifiedAt,
    liveGitHubPrecredentialBoundaryEvidenceSha256: functionBoundarySha256,
    runtimeProofEnvelopeSha256: 'c'.repeat(64)
  })
});
const storedGitHubBoundaryFixture = Object.freeze({
  evidence: Object.freeze({ checkedAt: functionBoundaryCheckedAt }),
  sha256: functionBoundarySha256
});
const validatedFunctionBoundary = validateFunctionEnvironmentGitHubBoundary(
  functionBoundaryFixture,
  storedGitHubBoundaryFixture,
  functionBoundaryObservedAt
);
assert.equal(validatedFunctionBoundary.functionEnvironmentVerifiedAt.toISOString(),
  functionBoundaryVerifiedAt);
assert.equal(validatedFunctionBoundary.liveGitHubPrecredentialBoundaryCheckedAt.toISOString(),
  functionBoundaryCheckedAt);
assert.throws(() => validateFunctionEnvironmentGitHubBoundary(
  functionBoundaryFixture,
  { value: { checkedAt: functionBoundaryCheckedAt }, sha256: functionBoundarySha256 },
  functionBoundaryObservedAt
), /CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_INVALID/,
'the stored GitHub verifier return shape must use evidence, not an undefined value member');
assert.throws(() => validateFunctionEnvironmentGitHubBoundary(
  functionBoundaryFixture,
  { evidence: { checkedAt: functionBoundaryCheckedAt }, sha256: 'e'.repeat(64) },
  functionBoundaryObservedAt
), /CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_INVALID/,
'function-environment evidence must bind the exact stored GitHub boundary digest');
assert.throws(() => validateFunctionEnvironmentGitHubBoundary(
  { value: { ...functionBoundaryFixture.value, verifiedAt: '2026-09-08T11:58:59.999Z' } },
  storedGitHubBoundaryFixture,
  functionBoundaryObservedAt
), /CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_INVALID/,
'function-environment verification cannot predate the GitHub release-boundary observation');
const historicalFunctionBoundary = validateFunctionEnvironmentGitHubBoundary(
  functionBoundaryFixture,
  storedGitHubBoundaryFixture,
  new Date('2026-09-08T12:10:00.000Z')
);
assert.equal(historicalFunctionBoundary.functionEnvironmentVerifiedAt.toISOString(),
  functionBoundaryVerifiedAt,
'preflight may preserve a hash-bound first-credential proof after its live freshness window');
assert.throws(() => validateFunctionEnvironmentGitHubBoundary(
  functionBoundaryFixture,
  {
    evidence: { checkedAt: '2026-09-08T12:00:00.001Z' },
    sha256: functionBoundarySha256
  },
  functionBoundaryObservedAt
), /CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_INVALID/,
'a future GitHub release-boundary observation must fail closed');
assert.throws(() => validateFunctionEnvironmentGitHubBoundary(
  functionBoundaryFixture,
  {
    evidence: { checkedAt: '2026-09-08T11:54:29.999Z' },
    sha256: functionBoundarySha256
  },
  functionBoundaryObservedAt
), /CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_INVALID/,
'first credential access more than five minutes after the GitHub observation must fail closed');

const functionEnvironmentBoundaryRoot = await fs.realpath(await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-function-environment-boundary-')
));
try {
  const fixtureCliVersion = '99.88.77';
  const fixtureCliBin = Object.freeze({ netlify: 'bin/run.js', ntl: 'bin/run.js' });
  const fixtureCliIntegrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
  const fixturePackageManifest = Object.freeze({
    name: 'cnyos-staging-protected-controller',
    version: '0.1.0',
    dependencies: Object.freeze({ 'netlify-cli': fixtureCliVersion })
  });
  const fixtureCliManifest = Object.freeze({
    name: 'netlify-cli',
    version: fixtureCliVersion,
    bin: fixtureCliBin
  });
  const fixturePackageLock = Object.freeze({
    name: 'cnyos-staging-protected-controller',
    version: '0.1.0',
    lockfileVersion: 3,
    requires: true,
    packages: Object.freeze({
      '': Object.freeze({
        name: 'cnyos-staging-protected-controller',
        version: '0.1.0',
        dependencies: Object.freeze({ 'netlify-cli': fixtureCliVersion })
      }),
      'node_modules/netlify-cli': Object.freeze({
        version: fixtureCliVersion,
        resolved:
          `https://registry.npmjs.org/netlify-cli/-/netlify-cli-${fixtureCliVersion}.tgz`,
        integrity: fixtureCliIntegrity,
        bin: fixtureCliBin
      })
    })
  });
  const fakeCli = path.join(
    functionEnvironmentBoundaryRoot,
    'node_modules',
    'netlify-cli',
    'bin',
    'run.js'
  );
  const fakeCliLink = path.join(
    functionEnvironmentBoundaryRoot,
    'node_modules',
    '.bin',
    'netlify'
  );
  await fs.mkdir(path.dirname(fakeCli), { recursive: true });
  await fs.mkdir(path.dirname(fakeCliLink), { recursive: true });
  await fs.writeFile(
    path.join(functionEnvironmentBoundaryRoot, 'package.json'),
    JSON.stringify(fixturePackageManifest),
    { flag: 'wx' }
  );
  await fs.writeFile(
    path.join(functionEnvironmentBoundaryRoot, 'package-lock.json'),
    JSON.stringify(fixturePackageLock),
    { flag: 'wx' }
  );
  await fs.writeFile(
    path.join(functionEnvironmentBoundaryRoot, 'node_modules', 'netlify-cli', 'package.json'),
    JSON.stringify(fixtureCliManifest),
    { flag: 'wx' }
  );
  await fs.writeFile(fakeCli, '#!/usr/bin/env node\n', { flag: 'wx', mode: 0o700 });
  await fs.symlink('../netlify-cli/bin/run.js', fakeCliLink);
  const verifiedFixtureCli = await validateProtectedNetlifyCliProvenance({
    cliPath: fakeCliLink,
    controllerPackageRoot: functionEnvironmentBoundaryRoot,
    expectedVersion: fixtureCliVersion
  });
  assert.deepEqual(verifiedFixtureCli, {
    cliRealPath: await fs.realpath(fakeCli),
    packageVersion: fixtureCliVersion,
    lockIntegrity: fixtureCliIntegrity
  });
  await assert.rejects(validateProtectedNetlifyCliProvenance({
    cliPath: fakeCli,
    controllerPackageRoot: functionEnvironmentBoundaryRoot,
    expectedVersion: fixtureCliVersion
  }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/,
    'direct node_modules/netlify-cli target must not replace the exact package bin link');
  await assert.rejects(validateProtectedNetlifyCliProvenance({
    cliPath: fakeCliLink,
    controllerPackageRoot: functionEnvironmentBoundaryRoot,
    expectedVersion: '__AUDITED_NETLIFY_CLI_VERSION__'
  }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/,
  'placeholder policy version must fail closed');
  for (const [label, mutate] of [
    ['root dependency range', ({ packageManifest }) => {
      packageManifest.dependencies['netlify-cli'] = `^${fixtureCliVersion}`;
    }],
    ['installed package identity', ({ cliManifest }) => {
      cliManifest.name = 'not-netlify-cli';
    }],
    ['installed bin mapping', ({ cliManifest }) => {
      cliManifest.bin.netlify = 'bin/other.js';
    }],
    ['lock integrity', ({ packageLock }) => {
      packageLock.packages['node_modules/netlify-cli'].integrity = 'sha512-invalid';
    }]
  ]) {
    const candidate = {
      packageManifest: structuredClone(fixturePackageManifest),
      packageLock: structuredClone(fixturePackageLock),
      cliManifest: structuredClone(fixtureCliManifest)
    };
    mutate(candidate);
    await Promise.all([
      fs.writeFile(
        path.join(functionEnvironmentBoundaryRoot, 'package.json'),
        JSON.stringify(candidate.packageManifest)
      ),
      fs.writeFile(
        path.join(functionEnvironmentBoundaryRoot, 'package-lock.json'),
        JSON.stringify(candidate.packageLock)
      ),
      fs.writeFile(
        path.join(functionEnvironmentBoundaryRoot, 'node_modules', 'netlify-cli', 'package.json'),
        JSON.stringify(candidate.cliManifest)
      )
    ]);
    await assert.rejects(validateProtectedNetlifyCliProvenance({
      cliPath: fakeCliLink,
      controllerPackageRoot: functionEnvironmentBoundaryRoot,
      expectedVersion: fixtureCliVersion
    }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/, label);
  }
  await Promise.all([
    fs.writeFile(
      path.join(functionEnvironmentBoundaryRoot, 'package.json'),
      JSON.stringify(fixturePackageManifest)
    ),
    fs.writeFile(
      path.join(functionEnvironmentBoundaryRoot, 'package-lock.json'),
      JSON.stringify(fixturePackageLock)
    ),
    fs.writeFile(
      path.join(functionEnvironmentBoundaryRoot, 'node_modules', 'netlify-cli', 'package.json'),
      JSON.stringify(fixtureCliManifest)
    )
  ]);
  const fixtureCliProvenanceVerifier = ({ cliPath }) =>
    validateProtectedNetlifyCliProvenance({
      cliPath,
      controllerPackageRoot: functionEnvironmentBoundaryRoot,
      expectedVersion: fixtureCliVersion
    });

  const publishToken = 'offline-publisher-token-never-sent-to-a-network';
  const functionPrecredentialBoundarySha256 = 'c'.repeat(64);
  const functionPrecredentialBoundaryCheckedAt = '2026-09-08T11:59:00.000Z';
  const validFunctionCredentialBoundary = Object.freeze({
    liveGitHubPrecredentialBoundary: Object.freeze({
      evidence: Object.freeze({ checkedAt: functionPrecredentialBoundaryCheckedAt }),
      sha256: functionPrecredentialBoundarySha256
    })
  });
  const forbiddenCanaries = Object.freeze({
    NETLIFY_AUTH_TOKEN: 'ambient-netlify-token-secret-canary',
    CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: 'service-role-secret-canary',
    CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN: 'rollback-token-secret-canary',
    CNYOS_STAGING_TEST_PASSWORD: 'database-password-secret-canary',
    CNYOS_CONTROLLER_AUTHORIZATION_JSON: 'authorization-secret-canary',
    CNYOS_GITHUB_ACTIONS_READ_TOKEN: 'github-read-token-secret-canary',
    DATABASE_URL: 'production-database-url-secret-canary',
    PGPASSWORD: 'postgres-password-secret-canary'
  });
  function trackedFunctionEnvironment(outputName, {
    cliPath = fakeCliLink,
    runnerTemp = functionEnvironmentBoundaryRoot
  } = {}) {
    const tracked = {
      ...runtime,
      RUNNER_TEMP: runnerTemp,
      CNYOS_NETLIFY_CLI_PATH: cliPath,
      CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: '/offline/authorization.json',
      CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH:
        '/offline/live-authority.json',
      CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: 'a'.repeat(64),
      CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256: 'b'.repeat(64),
      CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH:
        path.join(functionEnvironmentBoundaryRoot, outputName)
    };
    const reads = new Map();
    for (const [name, value] of Object.entries({
      CNYOS_STAGING_NETLIFY_AUTH_TOKEN: publishToken,
      ...forbiddenCanaries
    })) {
      reads.set(name, 0);
      Object.defineProperty(tracked, name, {
        enumerable: true,
        configurable: false,
        get() {
          reads.set(name, reads.get(name) + 1);
          return value;
        }
      });
    }
    return Object.freeze({
      env: tracked,
      reads: name => reads.get(name)
    });
  }

  const symlinkEscapePackageRoot = path.join(
    functionEnvironmentBoundaryRoot,
    'symlink-escape-controller'
  );
  const symlinkEscapeInstalledRoot = path.join(
    symlinkEscapePackageRoot,
    'node_modules',
    'netlify-cli'
  );
  const symlinkEscapeCliLink = path.join(
    symlinkEscapePackageRoot,
    'node_modules',
    '.bin',
    'netlify'
  );
  const outsidePackageBin = path.join(functionEnvironmentBoundaryRoot, 'outside-package-bin');
  const outsidePackageCli = path.join(outsidePackageBin, 'run.js');
  await Promise.all([
    fs.mkdir(symlinkEscapeInstalledRoot, { recursive: true }),
    fs.mkdir(path.dirname(symlinkEscapeCliLink), { recursive: true }),
    fs.mkdir(outsidePackageBin, { recursive: true })
  ]);
  await Promise.all([
    fs.writeFile(
      path.join(symlinkEscapePackageRoot, 'package.json'),
      JSON.stringify(fixturePackageManifest)
    ),
    fs.writeFile(
      path.join(symlinkEscapePackageRoot, 'package-lock.json'),
      JSON.stringify(fixturePackageLock)
    ),
    fs.writeFile(
      path.join(symlinkEscapeInstalledRoot, 'package.json'),
      JSON.stringify(fixtureCliManifest)
    ),
    fs.writeFile(outsidePackageCli, '#!/usr/bin/env node\n', { mode: 0o700 })
  ]);
  await fs.symlink(outsidePackageBin, path.join(symlinkEscapeInstalledRoot, 'bin'), 'dir');
  await fs.symlink('../netlify-cli/bin/run.js', symlinkEscapeCliLink);
  for (const [label, credentialBoundary] of [
    ['missing GitHub proof', Object.freeze({})],
    ['malformed GitHub proof digest', Object.freeze({
      liveGitHubPrecredentialBoundary: Object.freeze({
        evidence: Object.freeze({ checkedAt: functionPrecredentialBoundaryCheckedAt }),
        sha256: 'not-a-digest'
      })
    })],
    ['future GitHub proof', Object.freeze({
      liveGitHubPrecredentialBoundary: Object.freeze({
        evidence: Object.freeze({ checkedAt: '2026-09-08T12:00:00.001Z' }),
        sha256: functionPrecredentialBoundarySha256
      })
    })],
    ['stale GitHub proof', Object.freeze({
      liveGitHubPrecredentialBoundary: Object.freeze({
        evidence: Object.freeze({ checkedAt: '2026-09-08T11:54:59.999Z' }),
        sha256: functionPrecredentialBoundarySha256
      })
    })]
  ]) {
    const boundaryGuard = trackedFunctionEnvironment(
      `invalid-github-boundary-${label.replaceAll(' ', '-')}.json`
    );
    let boundaryCliCalls = 0;
    await assert.rejects(validateFunctionEnvironment({
      env: boundaryGuard.env,
      now: () => new Date('2026-09-08T12:00:00.000Z'),
      credentialBoundaryVerifier: async () => credentialBoundary,
      cliProvenanceVerifier: async () => {
        boundaryCliCalls += 1;
        throw new Error('CNYOS_TEST_CLI_PROVENANCE_MUST_NOT_RUN');
      },
      execFileImpl: () => {
        boundaryCliCalls += 1;
        throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
      }
    }), /CNYOS_CONTROLLER_FUNCTION_ENV_GITHUB_BOUNDARY_INVALID/, label);
    assert.equal(boundaryCliCalls, 0, `${label}: CLI work must not begin`);
    assert.equal(boundaryGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
      `${label}: publisher token must remain unread`);
  }
  const symlinkEscapeGuard = trackedFunctionEnvironment(
    'symlink-escape-must-not-exist.json',
    { cliPath: symlinkEscapeCliLink }
  );
  let symlinkEscapeCliCalls = 0;
  await assert.rejects(validateFunctionEnvironment({
    env: symlinkEscapeGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => validFunctionCredentialBoundary,
    cliProvenanceVerifier: ({ cliPath }) => validateProtectedNetlifyCliProvenance({
      cliPath,
      controllerPackageRoot: symlinkEscapePackageRoot,
      expectedVersion: fixtureCliVersion
    }),
    execFileImpl: () => {
      symlinkEscapeCliCalls += 1;
      throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
    }
  }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/);
  assert.equal(symlinkEscapeCliCalls, 0);
  assert.equal(symlinkEscapeGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
    'outside-package intermediate bin symlink must fail before publisher-token access');
  for (const name of Object.keys(forbiddenCanaries)) {
    assert.equal(symlinkEscapeGuard.reads(name), 0, `${name} must remain unread`);
  }

  const defaultProvenanceGuard = trackedFunctionEnvironment(
    'default-provenance-must-not-exist.json'
  );
  let defaultProvenanceCliCalls = 0;
  await assert.rejects(validateFunctionEnvironment({
    env: defaultProvenanceGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => validFunctionCredentialBoundary,
    execFileImpl: () => {
      defaultProvenanceCliCalls += 1;
      throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
    }
  }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/);
  assert.equal(defaultProvenanceCliCalls, 0);
  assert.equal(defaultProvenanceGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
    'placeholder policy and absent protected CLI lock entry must fail before token access');

  const unbrandedProvenanceGuard = trackedFunctionEnvironment(
    'unbranded-provenance-must-not-exist.json'
  );
  let unbrandedProvenanceCliCalls = 0;
  await assert.rejects(validateFunctionEnvironment({
    env: unbrandedProvenanceGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => validFunctionCredentialBoundary,
    cliProvenanceVerifier: async () => Object.freeze({ cliRealPath: fakeCli }),
    execFileImpl: () => {
      unbrandedProvenanceCliCalls += 1;
      throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
    }
  }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/);
  assert.equal(unbrandedProvenanceCliCalls, 0);
  assert.equal(unbrandedProvenanceGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
    'an arbitrary fake node_modules/netlify-cli file must fail before token access');

  const successfulGuard = trackedFunctionEnvironment('function-environment.json');
  const cliCalls = [];
  let prerequisiteCalls = 0;
  const result = await validateFunctionEnvironment({
    env: successfulGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async ({
      env: prerequisiteEnvironment,
      runtime: observedRuntime,
      observedAt
    }) => {
      prerequisiteCalls += 1;
      assert.notEqual(prerequisiteEnvironment, successfulGuard.env);
      assert.deepEqual(Object.keys(prerequisiteEnvironment).sort(),
        FUNCTION_ENVIRONMENT_PREREQUISITE_ENVIRONMENT_NAMES);
      assert.equal('CNYOS_STAGING_NETLIFY_AUTH_TOKEN' in prerequisiteEnvironment, false);
      for (const name of Object.keys(forbiddenCanaries)) {
        assert.equal(name in prerequisiteEnvironment, false);
      }
      assert.equal(observedRuntime.runId, runtime.GITHUB_RUN_ID);
      assert.equal(observedAt.toISOString(), '2026-09-08T12:00:00.000Z');
      assert.equal(successfulGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0);
      for (const name of Object.keys(forbiddenCanaries)) {
        assert.equal(successfulGuard.reads(name), 0);
      }
      return validFunctionCredentialBoundary;
    },
    cliProvenanceVerifier: fixtureCliProvenanceVerifier,
    execFileImpl: (filename, args, options) => {
      assert.equal(successfulGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 1);
      for (const name of Object.keys(forbiddenCanaries)) {
        assert.equal(successfulGuard.reads(name), 0);
      }
      cliCalls.push({ filename, args, options });
      return `${POLICY.functionEnvironment[args[1]]}\n`;
    }
  });
  assert.equal(prerequisiteCalls, 1);
  assert.equal(successfulGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 1);
  for (const name of Object.keys(forbiddenCanaries)) {
    assert.equal(successfulGuard.reads(name), 0, `${name} must never be read`);
  }
  const expectedFunctionVariables = Object.keys(POLICY.functionEnvironment).sort();
  assert.equal(cliCalls.length, expectedFunctionVariables.length);
  assert.deepEqual(cliCalls.map(call => call.args[1]), expectedFunctionVariables);
  const firstChildEnvironment = cliCalls[0].options.env;
  for (const [index, call] of cliCalls.entries()) {
    assert.equal(call.filename, await fs.realpath(fakeCli));
    assert.deepEqual(call.args, [
      'env:get',
      expectedFunctionVariables[index],
      `--site=${POLICY.target.netlifySiteId}`,
      '--context=production',
      '--scope=functions'
    ]);
    assert.deepEqual(Object.keys(call.options).sort(), [
      'cwd', 'encoding', 'env', 'maxBuffer', 'stdio', 'timeout', 'windowsHide'
    ]);
    assert.equal(call.options.encoding, 'utf8');
    assert.equal(call.options.maxBuffer, 1024 * 1024);
    assert.deepEqual(call.options.stdio, ['ignore', 'pipe', 'pipe']);
    assert.equal(call.options.timeout, 30_000);
    assert.equal(call.options.windowsHide, true);
    assert.equal(call.options.env, firstChildEnvironment);
    assert.deepEqual(Object.keys(call.options.env).sort(),
      NETLIFY_CLI_CHILD_ENVIRONMENT_NAMES);
    assert.equal(call.options.env.NETLIFY_AUTH_TOKEN, publishToken);
    assert.equal(call.options.env.NETLIFY_SITE_ID, POLICY.target.netlifySiteId);
    assert.equal(call.options.env.NETLIFY_CLI_TELEMETRY_DISABLED, '1');
    assert.equal(call.options.env.HOME, path.join(call.options.cwd, 'home'));
    assert.equal(call.options.env.TMPDIR, path.join(call.options.cwd, 'tmp'));
    assert.equal(call.options.env.XDG_CACHE_HOME, path.join(call.options.cwd, 'cache'));
    assert.equal(call.options.env.XDG_CONFIG_HOME, path.join(call.options.cwd, 'config'));
    const serializedChild = JSON.stringify(call.options.env);
    for (const canary of Object.values(forbiddenCanaries)) {
      assert.doesNotMatch(serializedChild, new RegExp(canary));
    }
  }
  await assert.rejects(fs.access(cliCalls[0].options.cwd), error => error?.code === 'ENOENT',
    'isolated Netlify CLI state directory must be removed');
  assert.deepEqual(result.evidence.validatedVariableNames, expectedFunctionVariables);
  assert.equal(result.evidence.schemaVersion, 2);
  assert.equal(result.evidence.liveGitHubPrecredentialBoundaryEvidenceSha256,
    functionPrecredentialBoundarySha256);
  assert.equal(result.evidence.valuesSerialized, false);
  const serializedEvidence = JSON.stringify(result.evidence);
  assert.doesNotMatch(serializedEvidence, new RegExp(publishToken));
  for (const canary of Object.values(forbiddenCanaries)) {
    assert.doesNotMatch(serializedEvidence, new RegExp(canary));
  }

  const invalidCliGuard = trackedFunctionEnvironment('invalid-cli-must-not-exist.json', {
    cliPath: path.join(
      functionEnvironmentBoundaryRoot,
      'missing',
      'node_modules',
      'netlify-cli',
      'bin',
      'run.js'
    )
  });
  let invalidCliCalls = 0;
  await assert.rejects(validateFunctionEnvironment({
    env: invalidCliGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => validFunctionCredentialBoundary,
    cliProvenanceVerifier: fixtureCliProvenanceVerifier,
    execFileImpl: () => {
      invalidCliCalls += 1;
      throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
    }
  }), /CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID/);
  assert.equal(invalidCliCalls, 0);
  assert.equal(invalidCliGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
    'publisher token must remain unread when CLI validation fails');
  for (const name of Object.keys(forbiddenCanaries)) {
    assert.equal(invalidCliGuard.reads(name), 0, `${name} must remain unread`);
  }

  const runnerTempTarget = path.join(functionEnvironmentBoundaryRoot, 'runner-temp-target');
  const runnerTempLink = path.join(functionEnvironmentBoundaryRoot, 'runner-temp-link');
  await fs.mkdir(runnerTempTarget);
  await fs.symlink(runnerTempTarget, runnerTempLink, 'dir');
  const symlinkRunnerGuard = trackedFunctionEnvironment(
    'symlink-runner-must-not-exist.json',
    { runnerTemp: runnerTempLink }
  );
  let symlinkRunnerCliCalls = 0;
  await assert.rejects(validateFunctionEnvironment({
    env: symlinkRunnerGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => validFunctionCredentialBoundary,
    cliProvenanceVerifier: fixtureCliProvenanceVerifier,
    execFileImpl: () => {
      symlinkRunnerCliCalls += 1;
      throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
    }
  }), /CNYOS_CONTROLLER_RUNNER_TEMP_INVALID/);
  assert.equal(symlinkRunnerCliCalls, 0);
  assert.equal(symlinkRunnerGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
    'publisher token must remain unread for a symlinked RUNNER_TEMP');
  assert.deepEqual(await fs.readdir(runnerTempTarget), []);
  for (const name of Object.keys(forbiddenCanaries)) {
    assert.equal(symlinkRunnerGuard.reads(name), 0, `${name} must remain unread`);
  }

  const midLoopGuard = trackedFunctionEnvironment('mid-loop-must-not-exist.json');
  let midLoopCalls = 0;
  let failedStateDirectory;
  await assert.rejects(validateFunctionEnvironment({
    env: midLoopGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => validFunctionCredentialBoundary,
    cliProvenanceVerifier: fixtureCliProvenanceVerifier,
    execFileImpl: (_filename, args, options) => {
      midLoopCalls += 1;
      failedStateDirectory = options.cwd;
      if (midLoopCalls === 2) throw new Error('CNYOS_TEST_MID_LOOP_CLI_FAILURE');
      return `${POLICY.functionEnvironment[args[1]]}\n`;
    }
  }), /CNYOS_CONTROLLER_FUNCTION_ENV_READ_FAILED/);
  assert.equal(midLoopCalls, 2);
  assert.equal(midLoopGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 1);
  assert.equal(typeof failedStateDirectory, 'string');
  await assert.rejects(fs.access(failedStateDirectory), error => error?.code === 'ENOENT',
    'mid-loop CLI failure must remove the isolated CLI state directory');
  await assert.rejects(
    fs.access(path.join(functionEnvironmentBoundaryRoot, 'mid-loop-must-not-exist.json')),
    error => error?.code === 'ENOENT'
  );
  for (const name of Object.keys(forbiddenCanaries)) {
    assert.equal(midLoopGuard.reads(name), 0, `${name} must remain unread`);
  }

  const rejectedGuard = trackedFunctionEnvironment('must-not-exist.json');
  let rejectedCliCalls = 0;
  await assert.rejects(validateFunctionEnvironment({
    env: rejectedGuard.env,
    now: () => new Date('2026-09-08T12:00:00.000Z'),
    credentialBoundaryVerifier: async () => {
      throw new Error('CNYOS_TEST_PREREQUISITE_REJECTED');
    },
    execFileImpl: () => {
      rejectedCliCalls += 1;
      throw new Error('CNYOS_TEST_CLI_MUST_NOT_RUN');
    }
  }), /CNYOS_TEST_PREREQUISITE_REJECTED/);
  assert.equal(rejectedCliCalls, 0);
  assert.equal(rejectedGuard.reads('CNYOS_STAGING_NETLIFY_AUTH_TOKEN'), 0,
    'publisher token must remain unread before prerequisite verification');
  for (const name of Object.keys(forbiddenCanaries)) {
    assert.equal(rejectedGuard.reads(name), 0, `${name} must remain unread`);
  }
  await assert.rejects(
    fs.access(path.join(functionEnvironmentBoundaryRoot, 'must-not-exist.json')),
    error => error?.code === 'ENOENT'
  );
} finally {
  await fs.rm(functionEnvironmentBoundaryRoot, { recursive: true, force: true });
}

const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-controller-contract-'));
try {
  await fs.writeFile(path.join(temporary, 'target.txt'), 'a');
  await fs.symlink('target.txt', path.join(temporary, 'alias.txt'));
  await assert.rejects(walkRegularFiles(temporary), /ARTIFACT_SYMLINK_REJECTED/);
  await assert.rejects(
    readFileBounded(path.join(temporary, 'alias.txt'), 16, 'BOUNDARY_FILE_INVALID'),
    /BOUNDARY_FILE_INVALID/
  );
  assert.equal(
    (await readRegularFileStable(
      path.join(temporary, 'target.txt'),
      16,
      'BOUNDARY_FILE_INVALID'
    )).toString('utf8'),
    'a'
  );
} finally {
  await fs.rm(temporary, { recursive: true, force: true });
}

const netlifyBoundaryTestRoot = await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-controller-netlify-boundary-')
);
try {
  const boundaryNow = new Date('2026-09-08T12:00:00.000Z');
  const boundaryExpiry = '2026-09-08T12:30:00.000Z';
  const boundaryNonce = Buffer.alloc(32, 0x42).toString('base64url');
  const boundaryToken = 'offline-netlify-token-that-must-never-be-used';
  const previousDeployId = '0123456789abcdef01234567';
  const candidateCommit = 'b'.repeat(40);
  const candidateTree = 'c'.repeat(40);
  const functionSourceTree = 'd'.repeat(40);

  const authorizationBoundaryFixture = () => ({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_authorization_validation',
    status: 'authorized',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    controllerRepository: runtime.GITHUB_REPOSITORY,
    controllerRef: runtime.GITHUB_REF,
    controllerCommit: runtime.GITHUB_SHA,
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerRunAttempt: 1,
    target: {
      netlifySiteId: POLICY.target.netlifySiteId,
      netlifyOrigin: POLICY.target.netlifyOrigin
    },
    targetSiteAndPublisherExclusion: {
      productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin
    },
    authorizationExpiresAt: boundaryExpiry,
    deploymentControlBoundaryExpiresAt: boundaryExpiry
  });
  const preReleaseReconciliationBoundaryFixture = () => ({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_pre_release_reconciliation',
    status: 'passed',
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    secretValuesSerialized: false,
    checkedAt: boundaryNow.toISOString(),
    controllerRepository: runtime.GITHUB_REPOSITORY,
    controllerRef: runtime.GITHUB_REF,
    controllerCommit: runtime.GITHUB_SHA,
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerRunAttempt: 1,
    policySha256: POLICY_SHA256,
    brokerPolicyId: POLICY.externalReconciliationBroker.policyId,
    brokerPolicySha256: POLICY.externalReconciliationBroker.policySha256,
    brokerInventoryComplete: true,
    allPriorRunsTerminal: true,
    activeRunReconciliationBarrierCount: 0,
    newMutationBlockedWhileAnyRunReconciliationBarrierActive: true,
    automaticRunReconciliationBarrierExpiryPermitted: false,
    target: structuredClone(POLICY.target)
  });
  if (/^[0-9a-f]{64}$/.test(POLICY.externalReconciliationBroker.policySha256)) {
    assert.equal(
      assertPreReleaseReconciliationEvidence(
        preReleaseReconciliationBoundaryFixture(),
        assertControllerRuntime(runtime),
        boundaryNow
      ).status,
      'passed'
    );
  } else {
    assert.throws(() => assertPreReleaseReconciliationEvidence(
      preReleaseReconciliationBoundaryFixture(),
      assertControllerRuntime(runtime),
      boundaryNow
    ), /CNYOS_CONTROLLER_PRE_RELEASE_RECONCILIATION_EVIDENCE_INVALID/,
    'placeholder broker policy must fail closed before credential access');
  }
  const activeBarrierReconciliation = preReleaseReconciliationBoundaryFixture();
  activeBarrierReconciliation.allPriorRunsTerminal = false;
  activeBarrierReconciliation.activeRunReconciliationBarrierCount = 1;
  assert.throws(() => assertPreReleaseReconciliationEvidence(
    activeBarrierReconciliation,
    assertControllerRuntime(runtime),
    boundaryNow
  ), /CNYOS_CONTROLLER_PRE_RELEASE_RECONCILIATION_EVIDENCE_INVALID/,
  'a prior run barrier must block pre-release reconciliation');
  const preflightBoundaryEvidenceFixture = () => ({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_preflight',
    productionAuthorization: false,
    controllerRepository: runtime.GITHUB_REPOSITORY,
    controllerRef: runtime.GITHUB_REF,
    controllerCommit: runtime.GITHUB_SHA,
    controllerRunId: runtime.GITHUB_RUN_ID,
    preReleaseReconciliationEvidenceSha256: 'f'.repeat(64),
    liveGitHubPrecredentialBoundaryEvidenceSha256: 'e'.repeat(64),
    runtimeProofEnvelopeSha256: 'c'.repeat(64),
    target: structuredClone(POLICY.target),
    targetSiteAndPublisherExclusion: {
      productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin
    },
    authorizationExpiresAt: boundaryExpiry,
    deploymentControlBoundaryExpiresAt: boundaryExpiry,
    principalProofExpiresAt: boundaryExpiry,
    liveNetlifyAuthorityBoundaryExpiresAt: boundaryExpiry,
    previousPublishedDeploy: { id: previousDeployId }
  });
  const boundaryMutations = [
    {
      label: 'staging Site ID collides with Production',
      apply: value => { value.target.netlifySiteId = POLICY.productionDenylist.netlifySiteId; }
    },
    {
      label: 'staging Site ID is replaced by another canonical ID',
      apply: value => {
        value.target.netlifySiteId = '00000000-0000-4000-8000-000000000099';
      }
    },
    {
      label: 'staging origin collides with Production',
      apply: value => { value.target.netlifyOrigin = POLICY.productionDenylist.netlifyOrigin; }
    },
    {
      label: 'staging origin is replaced by another canonical origin',
      apply: value => { value.target.netlifyOrigin = 'https://wrong-staging.netlify.app'; }
    },
    {
      label: 'Production Site ID is replaced by staging',
      apply: value => {
        value.targetSiteAndPublisherExclusion.productionNetlifySiteId =
          POLICY.target.netlifySiteId;
      }
    },
    {
      label: 'Production Site ID is replaced by another canonical ID',
      apply: value => {
        value.targetSiteAndPublisherExclusion.productionNetlifySiteId =
          '00000000-0000-4000-8000-000000000098';
      }
    },
    {
      label: 'Production origin is replaced by staging',
      apply: value => {
        value.targetSiteAndPublisherExclusion.productionNetlifyOrigin =
          POLICY.target.netlifyOrigin;
      }
    },
    {
      label: 'Production origin is replaced by another canonical origin',
      apply: value => {
        value.targetSiteAndPublisherExclusion.productionNetlifyOrigin =
          'https://wrong-production.netlify.app';
      }
    }
  ];

  async function writeBoundaryEvidence(filename, value) {
    const bytes = Buffer.from(JSON.stringify(value));
    const evidencePath = path.join(netlifyBoundaryTestRoot, filename);
    await fs.writeFile(evidencePath, bytes, { flag: 'wx', mode: 0o600 });
    return { evidencePath, evidenceSha256: sha256(bytes) };
  }

  function withUnreadNetlifyToken(baseEnv) {
    const env = { ...baseEnv };
    let tokenReads = 0;
    Object.defineProperty(env, 'CNYOS_STAGING_NETLIFY_AUTH_TOKEN', {
      configurable: false,
      enumerable: true,
      get() {
        tokenReads += 1;
        return boundaryToken;
      }
    });
    return Object.freeze({ env, tokenReads: () => tokenReads });
  }

  async function rejectsBeforeNetlifyFetch(label, baseEnv, invoke, expectedError) {
    const tokenGuard = withUnreadNetlifyToken(baseEnv);
    let fetchCalls = 0;
    const fetchImpl = async () => {
      fetchCalls += 1;
      throw new Error(`UNEXPECTED_NETLIFY_FETCH:${label}`);
    };
    await assert.rejects(invoke(tokenGuard.env, fetchImpl), expectedError, label);
    assert.equal(tokenGuard.tokenReads(), 0,
      `${label}: invalid boundary must precede Netlify credential access`);
    assert.equal(fetchCalls, 0, `${label}: invalid boundary must precede Netlify fetch`);
  }

  const fakeCliMarker = path.join(netlifyBoundaryTestRoot, 'fake-netlify-cli-called');
  const fakeCliPath = path.join(
    netlifyBoundaryTestRoot,
    'node_modules',
    'netlify-cli',
    'bin',
    'netlify'
  );
  await fs.mkdir(path.dirname(fakeCliPath), { recursive: true });
  await fs.writeFile(
    fakeCliPath,
    `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(fakeCliMarker)}, 'called');\n`,
    { flag: 'wx', mode: 0o700 }
  );

  for (const [index, mutation] of boundaryMutations.entries()) {
    const authorizationEvidence = authorizationBoundaryFixture();
    mutation.apply(authorizationEvidence);
    const authorizationFile = await writeBoundaryEvidence(
      `authorization-boundary-${index}.json`,
      authorizationEvidence
    );
    const authorizationEnv = {
      ...runtime,
      CNYOS_NETLIFY_CLI_PATH: fakeCliPath,
      CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: authorizationFile.evidencePath,
      CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: authorizationFile.evidenceSha256
    };
    await rejectsBeforeNetlifyFetch(
      `captureNetlifyPreflight: ${mutation.label}`,
      authorizationEnv,
      (env, fetchImpl) => captureNetlifyPreflight({
        env,
        fetchImpl,
        now: () => new Date(boundaryNow)
      }),
      /CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_INVALID/
    );
    const functionEnvironmentTokenGuard = withUnreadNetlifyToken(authorizationEnv);
    await assert.rejects(
      validateFunctionEnvironment({
        env: functionEnvironmentTokenGuard.env,
        now: () => new Date(boundaryNow)
      }),
      /CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_INVALID/,
      `validateFunctionEnvironment: ${mutation.label}`
    );
    assert.equal(functionEnvironmentTokenGuard.tokenReads(), 0,
      `validateFunctionEnvironment: ${mutation.label}: invalid boundary must precede credential access`);
    await assert.rejects(
      fs.access(fakeCliMarker),
      error => error?.code === 'ENOENT',
      `validateFunctionEnvironment: ${mutation.label}: invalid boundary must precede CLI execution`
    );
  }

  const validAuthorizationFile = await writeBoundaryEvidence(
    'authorization-valid-for-reconciliation-gate.json',
    authorizationBoundaryFixture()
  );
  const validReconciliationFile = await writeBoundaryEvidence(
    'pre-release-reconciliation-valid.json',
    preReleaseReconciliationBoundaryFixture()
  );
  const reconciliationGateEnv = {
    ...runtime,
    CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: validAuthorizationFile.evidencePath,
    CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: validAuthorizationFile.evidenceSha256,
    CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH: validReconciliationFile.evidencePath,
    CNYOS_EXPECTED_RECONCILIATION_EVIDENCE_SHA256: '0'.repeat(64)
  };
  await rejectsBeforeNetlifyFetch(
    'captureNetlifyPreflight: reconciliation digest mismatch',
    reconciliationGateEnv,
    (env, fetchImpl) => captureNetlifyPreflight({
      env,
      fetchImpl,
      now: () => new Date(boundaryNow)
    }),
    /CNYOS_CONTROLLER_PRE_RELEASE_RECONCILIATION_EVIDENCE_INVALID_DIGEST_MISMATCH/
  );
  const invalidReconciliation = preReleaseReconciliationBoundaryFixture();
  invalidReconciliation.target.netlifySiteId = POLICY.productionDenylist.netlifySiteId;
  const invalidReconciliationFile = await writeBoundaryEvidence(
    'pre-release-reconciliation-invalid-target.json',
    invalidReconciliation
  );
  await rejectsBeforeNetlifyFetch(
    'captureNetlifyPreflight: reconciliation semantic mismatch',
    {
      ...reconciliationGateEnv,
      CNYOS_CONTROLLER_RECONCILIATION_EVIDENCE_PATH:
        invalidReconciliationFile.evidencePath,
      CNYOS_EXPECTED_RECONCILIATION_EVIDENCE_SHA256:
        invalidReconciliationFile.evidenceSha256
    },
    (env, fetchImpl) => captureNetlifyPreflight({
      env,
      fetchImpl,
      now: () => new Date(boundaryNow)
    }),
    /CNYOS_CONTROLLER_PRE_RELEASE_RECONCILIATION_EVIDENCE_INVALID/
  );

  for (const [index, mutation] of boundaryMutations.entries()) {
    const preflightEvidence = preflightBoundaryEvidenceFixture();
    mutation.apply(preflightEvidence);
    const preflightFile = await writeBoundaryEvidence(
      `preflight-boundary-${index}.json`,
      preflightEvidence
    );
    const preflightEnv = {
      ...runtime,
      CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.evidencePath,
      CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.evidenceSha256,
      CNYOS_CONTROLLER_ROLLBACK_ACK: 'RESTORE_EXACT_CNYOS_STAGING_PREVIOUS_DEPLOY'
    };
    for (const [name, invoke] of [
      ['recordDraftGate', (env, fetchImpl) => recordDraftGate({
        env,
        fetchImpl,
        now: () => new Date(boundaryNow)
      })],
      ['recordNetlifyDeployReceipt', (env, fetchImpl) => recordNetlifyDeployReceipt({
        env,
        fetchImpl,
        now: () => new Date(boundaryNow)
      })],
      ['promoteExactDraft', (env, fetchImpl) => promoteExactDraft({
        env,
        fetchImpl,
        now: () => new Date(boundaryNow)
      })],
      ['rollbackPublishedDeployment', (env, fetchImpl) => rollbackPublishedDeployment({
        env,
        fetchImpl,
        now: () => new Date(boundaryNow)
      })]
    ]) {
      await rejectsBeforeNetlifyFetch(
        `${name}: ${mutation.label}`,
        preflightEnv,
        invoke,
        /CNYOS_CONTROLLER_PREFLIGHT_DEPLOYMENT_BOUNDARY_INVALID/
      );
    }
  }

  const isolatedPackageRoot = path.join(netlifyBoundaryTestRoot, 'activated-policy-package');
  const sourceScriptsRoot = path.join(root, 'scripts');
  const isolatedScriptsRoot = path.join(isolatedPackageRoot, 'scripts');
  await fs.mkdir(isolatedPackageRoot);
  await fs.cp(sourceScriptsRoot, isolatedScriptsRoot, { recursive: true });
  const [sourceScriptFiles, isolatedScriptFiles] = await Promise.all([
    walkRegularFiles(sourceScriptsRoot),
    walkRegularFiles(isolatedScriptsRoot)
  ]);
  assert.deepEqual(
    isolatedScriptFiles.map(file => file.relativePath),
    sourceScriptFiles.map(file => file.relativePath),
    'isolated verifier must copy the complete script inventory'
  );
  for (let index = 0; index < sourceScriptFiles.length; index += 1) {
    const [sourceBytes, isolatedBytes] = await Promise.all([
      fs.readFile(sourceScriptFiles[index].absolutePath),
      fs.readFile(isolatedScriptFiles[index].absolutePath)
    ]);
    assert.equal(sha256(isolatedBytes), sha256(sourceBytes),
      `${sourceScriptFiles[index].relativePath}: isolated script hash drift`);
    assert.deepEqual(isolatedBytes, sourceBytes,
      `${sourceScriptFiles[index].relativePath}: isolated script byte drift`);
  }

  function replaceExactlyOnce(source, from, to, label) {
    assert.equal(source.split(from).length - 1, 1, `${label}: substitution source count`);
    return source.replace(from, to);
  }
  const sourcePolicyRaw = await fs.readFile(path.join(root, 'controller-policy.json'), 'utf8');
  const sourceStagingConfigDigest =
    POLICY.staticArtifactReproducibility.stagingConfigSha256;
  const sourceProductionConfigDigest =
    POLICY.staticArtifactReproducibility.productionDenylistConfigSha256;
  const sourceBuilderImageDigest =
    POLICY.staticArtifactReproducibility.hermeticBuilderImageDigest;
  const sourceDraftBoundaryOrigin = POLICY.privateDraftAccessBoundary.origin;
  const sourceDraftBoundaryPolicyId = POLICY.privateDraftAccessBoundary.policyId;
  const sourceDraftBoundaryPolicySha256 = POLICY.privateDraftAccessBoundary.policySha256;
  const isolatedStagingConfigDigest = sha256('offline-staging-config-boundary-fixture');
  const isolatedProductionConfigDigest = sha256('offline-production-denylist-boundary-fixture');
  const isolatedBuilderImageDigest =
    `sha256:${sha256('offline-hermetic-builder-boundary-fixture')}`;
  const isolatedDraftBoundaryOrigin = 'https://cnyos-draft-reader.example.test';
  const isolatedDraftBoundaryPolicyId = 'cnyos-private-draft-access-v1';
  const isolatedDraftBoundaryPolicySha256 = sha256('offline-private-draft-boundary-policy');
  let isolatedPolicyRaw = replaceExactlyOnce(
    sourcePolicyRaw,
    JSON.stringify(sourceStagingConfigDigest),
    JSON.stringify(isolatedStagingConfigDigest),
    'staging configuration digest'
  );
  isolatedPolicyRaw = replaceExactlyOnce(
    isolatedPolicyRaw,
    JSON.stringify(sourceProductionConfigDigest),
    JSON.stringify(isolatedProductionConfigDigest),
    'Production denylist configuration digest'
  );
  isolatedPolicyRaw = replaceExactlyOnce(
    isolatedPolicyRaw,
    JSON.stringify(sourceBuilderImageDigest),
    JSON.stringify(isolatedBuilderImageDigest),
    'hermetic builder image digest'
  );
  isolatedPolicyRaw = replaceExactlyOnce(
    isolatedPolicyRaw,
    JSON.stringify(sourceDraftBoundaryOrigin),
    JSON.stringify(isolatedDraftBoundaryOrigin),
    'private draft boundary origin'
  );
  isolatedPolicyRaw = replaceExactlyOnce(
    isolatedPolicyRaw,
    JSON.stringify(sourceDraftBoundaryPolicyId),
    JSON.stringify(isolatedDraftBoundaryPolicyId),
    'private draft boundary policy ID'
  );
  isolatedPolicyRaw = replaceExactlyOnce(
    isolatedPolicyRaw,
    JSON.stringify(sourceDraftBoundaryPolicySha256),
    JSON.stringify(isolatedDraftBoundaryPolicySha256),
    'private draft boundary policy digest'
  );
  let restoredPolicyRaw = replaceExactlyOnce(
    isolatedPolicyRaw,
    JSON.stringify(isolatedStagingConfigDigest),
    JSON.stringify(sourceStagingConfigDigest),
    'restore staging configuration digest'
  );
  restoredPolicyRaw = replaceExactlyOnce(
    restoredPolicyRaw,
    JSON.stringify(isolatedProductionConfigDigest),
    JSON.stringify(sourceProductionConfigDigest),
    'restore Production denylist configuration digest'
  );
  restoredPolicyRaw = replaceExactlyOnce(
    restoredPolicyRaw,
    JSON.stringify(isolatedBuilderImageDigest),
    JSON.stringify(sourceBuilderImageDigest),
    'restore hermetic builder image digest'
  );
  restoredPolicyRaw = replaceExactlyOnce(
    restoredPolicyRaw,
    JSON.stringify(isolatedDraftBoundaryOrigin),
    JSON.stringify(sourceDraftBoundaryOrigin),
    'restore private draft boundary origin'
  );
  restoredPolicyRaw = replaceExactlyOnce(
    restoredPolicyRaw,
    JSON.stringify(isolatedDraftBoundaryPolicyId),
    JSON.stringify(sourceDraftBoundaryPolicyId),
    'restore private draft boundary policy ID'
  );
  restoredPolicyRaw = replaceExactlyOnce(
    restoredPolicyRaw,
    JSON.stringify(isolatedDraftBoundaryPolicySha256),
    JSON.stringify(sourceDraftBoundaryPolicySha256),
    'restore private draft boundary policy digest'
  );
  assert.equal(restoredPolicyRaw, sourcePolicyRaw,
    'isolated policy may differ only at the six explicit offline-fixture placeholders');
  const isolatedPolicyValue = JSON.parse(isolatedPolicyRaw);
  const expectedIsolatedPolicyValue = structuredClone(POLICY);
  expectedIsolatedPolicyValue.staticArtifactReproducibility.stagingConfigSha256 =
    isolatedStagingConfigDigest;
  expectedIsolatedPolicyValue.staticArtifactReproducibility.productionDenylistConfigSha256 =
    isolatedProductionConfigDigest;
  expectedIsolatedPolicyValue.staticArtifactReproducibility.hermeticBuilderImageDigest =
    isolatedBuilderImageDigest;
  expectedIsolatedPolicyValue.privateDraftAccessBoundary.origin =
    isolatedDraftBoundaryOrigin;
  expectedIsolatedPolicyValue.privateDraftAccessBoundary.policyId =
    isolatedDraftBoundaryPolicyId;
  expectedIsolatedPolicyValue.privateDraftAccessBoundary.policySha256 =
    isolatedDraftBoundaryPolicySha256;
  assert.deepEqual(isolatedPolicyValue, expectedIsolatedPolicyValue,
    'isolated policy object may differ only at the six explicit offline-fixture placeholders');
  await fs.writeFile(
    path.join(isolatedPackageRoot, 'controller-policy.json'),
    isolatedPolicyRaw,
    { flag: 'wx', mode: 0o600 }
  );
  const isolatedNetlify = await import(pathToFileURL(
    path.join(isolatedScriptsRoot, 'netlify-evidence.mjs')
  ).href);
  const isolatedPolicy = await import(pathToFileURL(
    path.join(isolatedScriptsRoot, 'policy.mjs')
  ).href);
  const isolatedProducerVerifier = await import(pathToFileURL(
    path.join(isolatedScriptsRoot, 'verify-producer-bundle.mjs')
  ).href);
  assert.notEqual(isolatedPolicy.POLICY_SHA256, POLICY_SHA256);
  assert.equal(isolatedPolicy.POLICY_SHA256, sha256(isolatedPolicyRaw));
  assert.deepEqual(isolatedPolicy.POLICY, expectedIsolatedPolicyValue);

  const bundleDirectory = path.join(netlifyBoundaryTestRoot, 'producer-bundle');
  const staticBytes = Buffer.from('offline boundary fixture', 'utf8');
  const payloads = [
    { path: 'payload/dist/index.html', bytes: staticBytes },
    ...EXPECTED_FUNCTION_NAMES.map(name => ({
      path: `payload/netlify/functions/${name}.zip`,
      bytes: Buffer.from(`offline function archive fixture:${name}`, 'utf8')
    }))
  ].sort((left, right) => left.path.localeCompare(right.path));
  for (const file of payloads) {
    const destination = path.join(bundleDirectory, file.path);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, file.bytes, { flag: 'wx', mode: 0o600 });
  }
  const manifestFiles = payloads.map(file => ({
    path: file.path,
    size: file.bytes.byteLength,
    sha256: sha256(file.bytes)
  }));
  const staticFiles = manifestFiles
    .filter(file => file.path.startsWith('payload/dist/'))
    .map(file => ({
      path: file.path.slice('payload/dist/'.length),
      size: file.size,
      sha256: file.sha256
    }));
  const candidateBuildArtifactDigest = '3'.repeat(64);
  const candidateDependencyLockSha256 = '4'.repeat(64);
  const staticArtifactSha256 = sha256(JSON.stringify(staticFiles));
  const staticReproducibility = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_static_reproducibility',
    status: 'passed',
    authorization: false,
    credentialsAvailable: false,
    controllerRepository: runtime.GITHUB_REPOSITORY,
    controllerRef: runtime.GITHUB_REF,
    controllerCommit: runtime.GITHUB_SHA,
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerRunAttempt: 1,
    policySha256: isolatedPolicy.POLICY_SHA256,
    sourceRepository: isolatedPolicy.POLICY.sourceRepository,
    candidateCommit,
    candidateTree,
    untrustedReferenceArtifactDigest: candidateBuildArtifactDigest,
    candidateDependencyLockSha256,
    configInputs: {
      stagingConfigSha256:
        isolatedPolicy.POLICY.staticArtifactReproducibility.stagingConfigSha256,
      productionDenylistConfigSha256:
        isolatedPolicy.POLICY.staticArtifactReproducibility.productionDenylistConfigSha256
    },
    buildEnvironment: {
      containerImageDigest:
        isolatedPolicy.POLICY.staticArtifactReproducibility.hermeticBuilderImageDigest,
      nodeVersion: '24.20.0',
      networkDisabled: true,
      lifecycleScriptsDisabled: true,
      sourceMountedReadOnly: true,
      isolatedOutput: true
    },
    staticArtifactSha256,
    byteForByteMatchWithUntrustedReference: true,
    fileCount: staticFiles.length,
    files: staticFiles,
    verifiedAt: '2026-09-08T11:59:00.000Z'
  };
  const staticReproducibilityBytes = Buffer.from(JSON.stringify(staticReproducibility));
  await fs.writeFile(
    path.join(bundleDirectory, 'static-reproducibility.json'),
    staticReproducibilityBytes,
    { flag: 'wx', mode: 0o600 }
  );
  const functionBundleManifestBytes = Buffer.from('{"schemaVersion":1}');
  await fs.writeFile(
    path.join(bundleDirectory, 'function-bundle-manifest.json'),
    functionBundleManifestBytes,
    { flag: 'wx', mode: 0o600 }
  );
  const functionSources = [{
    path: 'netlify/functions/offline-boundary-fixture.ts',
    size: 1,
    sha256: '5'.repeat(64),
    gitObject: 'e'.repeat(40)
  }];
  const producerManifest = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_unprivileged_producer_bundle',
    authorization: false,
    credentialsAvailable: false,
    controllerRepository: runtime.GITHUB_REPOSITORY,
    controllerRef: runtime.GITHUB_REF,
    controllerCommit: runtime.GITHUB_SHA,
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerRunAttempt: 1,
    dispatchNonce: boundaryNonce,
    sourceRepository: isolatedPolicy.POLICY.sourceRepository,
    candidateCommit,
    candidateTree,
    functionSourceTree,
    candidateBuildArtifactDigest,
    staticReproducibilityEvidenceSha256: sha256(staticReproducibilityBytes),
    staticArtifactSha256,
    candidateDependencyLockSha256,
    stagingConfigSha256:
      isolatedPolicy.POLICY.staticArtifactReproducibility.stagingConfigSha256,
    productionDenylistConfigSha256:
      isolatedPolicy.POLICY.staticArtifactReproducibility.productionDenylistConfigSha256,
    functionBundleManifestSha256: sha256(functionBundleManifestBytes),
    functionBundleDependencyLockSha256: '6'.repeat(64),
    functionSourcesSha256: sha256(JSON.stringify(functionSources)),
    functionSources,
    policySha256: isolatedPolicy.POLICY_SHA256,
    generatedAt: boundaryNow.toISOString(),
    fileCount: manifestFiles.length,
    files: manifestFiles
  };
  const producerIdentity = {
    schemaVersion: producerManifest.schemaVersion,
    evidenceType: producerManifest.evidenceType,
    authorization: producerManifest.authorization,
    credentialsAvailable: producerManifest.credentialsAvailable,
    controllerRepository: producerManifest.controllerRepository,
    controllerRef: producerManifest.controllerRef,
    controllerCommit: producerManifest.controllerCommit,
    controllerRunId: producerManifest.controllerRunId,
    controllerRunAttempt: producerManifest.controllerRunAttempt,
    dispatchNonce: producerManifest.dispatchNonce,
    sourceRepository: producerManifest.sourceRepository,
    candidateCommit: producerManifest.candidateCommit,
    candidateTree: producerManifest.candidateTree,
    functionSourceTree: producerManifest.functionSourceTree,
    candidateBuildArtifactDigest: producerManifest.candidateBuildArtifactDigest,
    staticReproducibilityEvidenceSha256:
      producerManifest.staticReproducibilityEvidenceSha256,
    staticArtifactSha256: producerManifest.staticArtifactSha256,
    candidateDependencyLockSha256: producerManifest.candidateDependencyLockSha256,
    stagingConfigSha256: producerManifest.stagingConfigSha256,
    productionDenylistConfigSha256: producerManifest.productionDenylistConfigSha256,
    functionBundleManifestSha256: producerManifest.functionBundleManifestSha256,
    functionBundleDependencyLockSha256: producerManifest.functionBundleDependencyLockSha256,
    functionSourcesSha256: producerManifest.functionSourcesSha256,
    policySha256: producerManifest.policySha256
  };
  producerManifest.artifactSha256 = aggregateDigest(producerIdentity, manifestFiles);
  const validatedStaticReceipt =
    isolatedProducerVerifier.validateStaticReproducibilityReceipt(
      staticReproducibility,
      producerManifest,
      staticFiles
    );
  assert.equal(validatedStaticReceipt.staticArtifactSha256, staticArtifactSha256);
  assert.deepEqual(validatedStaticReceipt.files, staticFiles);
  assert.equal(validatedStaticReceipt.verifiedAt.toISOString(), staticReproducibility.verifiedAt);
  assert.equal(Object.isFrozen(validatedStaticReceipt), true);
  const reorderedFileKeyReceipt = structuredClone(staticReproducibility);
  reorderedFileKeyReceipt.files = reorderedFileKeyReceipt.files.map(entry => ({
    sha256: entry.sha256,
    path: entry.path,
    size: entry.size
  }));
  assert.notEqual(JSON.stringify(reorderedFileKeyReceipt.files), JSON.stringify(staticFiles));
  assert.equal(
    isolatedProducerVerifier.validateStaticReproducibilityReceipt(
      reorderedFileKeyReceipt,
      producerManifest,
      staticFiles
    ).staticArtifactSha256,
    staticArtifactSha256,
    'static aggregate digest must not depend on receipt object-key insertion order'
  );

  const staticReceiptMutations = [
    {
      label: 'extra top-level field',
      apply: value => { value.unreviewed = true; }
    },
    {
      label: 'missing required field',
      apply: value => { delete value.schemaVersion; }
    },
    {
      label: 'authorization flag',
      apply: value => { value.authorization = true; }
    },
    {
      label: 'credentials flag',
      apply: value => { value.credentialsAvailable = true; }
    },
    {
      label: 'config-input topology',
      apply: value => { value.configInputs.unreviewed = '5'.repeat(64); }
    },
    {
      label: 'missing config input',
      apply: value => { delete value.configInputs.productionDenylistConfigSha256; }
    },
    {
      label: 'staging config identity',
      apply: value => { value.configInputs.stagingConfigSha256 = '9'.repeat(64); }
    },
    {
      label: 'Production denylist config identity',
      apply: value => { value.configInputs.productionDenylistConfigSha256 = '9'.repeat(64); }
    },
    {
      label: 'build-environment topology',
      apply: value => { value.buildEnvironment.unreviewed = true; }
    },
    {
      label: 'missing build-environment field',
      apply: value => { delete value.buildEnvironment.sourceMountedReadOnly; }
    },
    {
      label: 'builder image identity',
      apply: value => { value.buildEnvironment.containerImageDigest = `sha256:${'9'.repeat(64)}`; }
    },
    {
      label: 'builder Node version',
      apply: value => { value.buildEnvironment.nodeVersion = '24.20.1'; }
    },
    {
      label: 'network-disabled build isolation claim',
      apply: value => { value.buildEnvironment.networkDisabled = false; }
    },
    {
      label: 'lifecycle-scripts-disabled build isolation claim',
      apply: value => { value.buildEnvironment.lifecycleScriptsDisabled = false; }
    },
    {
      label: 'read-only source build isolation claim',
      apply: value => { value.buildEnvironment.sourceMountedReadOnly = false; }
    },
    {
      label: 'isolated-output build isolation claim',
      apply: value => { value.buildEnvironment.isolatedOutput = false; }
    },
    {
      label: 'byte-for-byte comparison claim',
      apply: value => { value.byteForByteMatchWithUntrustedReference = false; }
    },
    {
      label: 'controller identity',
      apply: value => { value.controllerRepository = 'attacker/controller'; }
    },
    {
      label: 'controller ref identity',
      apply: value => { value.controllerRef = 'refs/heads/unprotected'; }
    },
    {
      label: 'controller commit identity',
      apply: value => { value.controllerCommit = '9'.repeat(40); }
    },
    {
      label: 'controller run identity',
      apply: value => { value.controllerRunId = '654321'; }
    },
    {
      label: 'controller run attempt',
      apply: value => { value.controllerRunAttempt = 2; }
    },
    {
      label: 'source identity',
      apply: value => { value.sourceRepository = 'attacker/source'; }
    },
    {
      label: 'policy identity',
      apply: value => { value.policySha256 = '9'.repeat(64); }
    },
    {
      label: 'candidate commit identity',
      apply: value => { value.candidateCommit = '8'.repeat(40); }
    },
    {
      label: 'candidate tree identity',
      apply: value => { value.candidateTree = '7'.repeat(40); }
    },
    {
      label: 'untrusted reference artifact identity',
      apply: value => { value.untrustedReferenceArtifactDigest = '8'.repeat(64); }
    },
    {
      label: 'candidate dependency lock identity',
      apply: value => { value.candidateDependencyLockSha256 = '8'.repeat(64); }
    },
    {
      label: 'evidence type',
      apply: value => { value.evidenceType = 'unreviewed_static_reproducibility'; }
    },
    {
      label: 'evidence status',
      apply: value => { value.status = 'failed'; }
    },
    {
      label: 'noncanonical timestamp',
      apply: value => { value.verifiedAt = '2026-09-08T11:59:00Z'; }
    },
    {
      label: 'future timestamp',
      apply: value => { value.verifiedAt = '2026-09-08T12:00:00.001Z'; }
    },
    {
      label: 'stale timestamp',
      apply: value => { value.verifiedAt = '2026-09-08T11:29:59.999Z'; }
    },
    {
      label: 'extra file field',
      apply: value => { value.files[0].unreviewed = true; }
    },
    {
      label: 'file digest',
      apply: value => { value.files[0].sha256 = '9'.repeat(64); }
    },
    {
      label: 'file count',
      apply: value => { value.fileCount += 1; }
    },
    {
      label: 'static aggregate digest',
      apply: value => { value.staticArtifactSha256 = '9'.repeat(64); }
    }
  ];
  for (const mutation of staticReceiptMutations) {
    const receipt = structuredClone(staticReproducibility);
    mutation.apply(receipt);
    assert.throws(
      () => isolatedProducerVerifier.validateStaticReproducibilityReceipt(
        receipt,
        producerManifest,
        staticFiles
      ),
      /CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID/,
      mutation.label
    );
  }

  const producerManifestBytes = Buffer.from(JSON.stringify(producerManifest));
  await fs.writeFile(
    path.join(bundleDirectory, 'producer-manifest.json'),
    producerManifestBytes,
    { flag: 'wx', mode: 0o600 }
  );
  const producerBundleVerifierEnv = {
    ...runtime,
    CNYOS_DISPATCH_NONCE: boundaryNonce,
    CNYOS_CANDIDATE_SHA: candidateCommit,
    CNYOS_PRODUCER_BUNDLE_DIRECTORY: bundleDirectory,
    CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: sha256(producerManifestBytes)
  };
  const verifiedProducerBundle = await isolatedProducerVerifier.verifyProducerBundle({
    env: producerBundleVerifierEnv
  });
  assert.equal(verifiedProducerBundle.manifestSha256, sha256(producerManifestBytes));

  const helperOnlyTamperDirectory = path.join(
    netlifyBoundaryTestRoot,
    'producer-bundle-helper-only-receipt-tamper'
  );
  await fs.cp(bundleDirectory, helperOnlyTamperDirectory, {
    recursive: true,
    errorOnExist: true,
    force: false
  });
  const helperOnlyTamperedReceipt = structuredClone(staticReproducibility);
  helperOnlyTamperedReceipt.buildEnvironment.isolatedOutput = false;
  const helperOnlyTamperedReceiptBytes = Buffer.from(JSON.stringify(helperOnlyTamperedReceipt));
  await fs.writeFile(
    path.join(helperOnlyTamperDirectory, 'static-reproducibility.json'),
    helperOnlyTamperedReceiptBytes
  );
  const helperOnlyTamperedManifest = structuredClone(producerManifest);
  helperOnlyTamperedManifest.staticReproducibilityEvidenceSha256 =
    sha256(helperOnlyTamperedReceiptBytes);
  const helperOnlyTamperedIdentity = {
    ...producerIdentity,
    staticReproducibilityEvidenceSha256:
      helperOnlyTamperedManifest.staticReproducibilityEvidenceSha256
  };
  helperOnlyTamperedManifest.artifactSha256 = aggregateDigest(
    helperOnlyTamperedIdentity,
    helperOnlyTamperedManifest.files
  );
  const helperOnlyTamperedManifestBytes = Buffer.from(JSON.stringify(helperOnlyTamperedManifest));
  const helperOnlyTamperedManifestSha256 = sha256(helperOnlyTamperedManifestBytes);
  await fs.writeFile(
    path.join(helperOnlyTamperDirectory, 'producer-manifest.json'),
    helperOnlyTamperedManifestBytes
  );
  assert.equal(
    helperOnlyTamperedManifest.staticReproducibilityEvidenceSha256,
    sha256(helperOnlyTamperedReceiptBytes),
    'tampered receipt transport digest must be internally coherent'
  );
  assert.notEqual(
    helperOnlyTamperedManifest.staticReproducibilityEvidenceSha256,
    producerManifest.staticReproducibilityEvidenceSha256,
    'helper-only mutation must carry a newly computed receipt transport digest'
  );
  assert.equal(
    helperOnlyTamperedManifest.artifactSha256,
    aggregateDigest(helperOnlyTamperedIdentity, helperOnlyTamperedManifest.files),
    'tampered producer artifact identity must be internally coherent'
  );
  assert.notEqual(
    helperOnlyTamperedManifestSha256,
    sha256(producerManifestBytes),
    'helper-only mutation must carry a newly computed manifest transport digest'
  );
  await assert.rejects(
    isolatedProducerVerifier.verifyProducerBundle({
      env: {
        ...producerBundleVerifierEnv,
        CNYOS_PRODUCER_BUNDLE_DIRECTORY: helperOnlyTamperDirectory,
        CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256: helperOnlyTamperedManifestSha256
      }
    }),
    /CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID/,
    'full bundle verification must invoke the strict static-reproducibility validator'
  );

  const promotionEvidence = {
    evidenceType: 'cnyos_staging_controller_exact_deploy_promotion',
    status: 'passed',
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerCommit: runtime.GITHUB_SHA,
    source: { commit: candidateCommit },
    artifact: { artifactSha256: producerManifest.artifactSha256 }
  };
  const promotionFile = await writeBoundaryEvidence(
    'valid-promotion-prefix.json',
    promotionEvidence
  );
  const isolatedBundleEnv = {
    ...producerBundleVerifierEnv,
    CNYOS_CONTROLLER_PROMOTION_EVIDENCE_PATH: promotionFile.evidencePath,
    CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256: promotionFile.evidenceSha256
  };

  const validDraftPreflightFile = await writeBoundaryEvidence(
    'draft-verification-preflight.json',
    preflightBoundaryEvidenceFixture()
  );
  const draftDeployId = 'fedcba987654321001234567';
  const draftReceiptFile = await writeBoundaryEvidence(
    'draft-verification-receipt.json',
    {
      evidenceType: 'cnyos_staging_controller_draft_deploy_receipt',
      promotionAuthorization: false,
      controllerRunId: runtime.GITHUB_RUN_ID,
      source: { commit: candidateCommit },
      artifact: { artifactSha256: producerManifest.artifactSha256 },
      previousDeployId,
      draftDeployId,
      netlifyCliVersion: isolatedPolicy.POLICY.publishing.netlifyCliVersion,
      preflightEvidenceSha256: validDraftPreflightFile.evidenceSha256
    }
  );
  const draftMetadataPath = path.join(netlifyBoundaryTestRoot, 'draft-metadata.json');
  const publisherToken = 'offline-publisher-token-that-must-not-cross-the-boundary';
  const credentialSeparationHmacKey = Buffer.alloc(32, 0x68).toString('base64url');
  const draftMetadataEnv = {
    ...producerBundleVerifierEnv,
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: validDraftPreflightFile.evidencePath,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: validDraftPreflightFile.evidenceSha256,
    CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH: draftReceiptFile.evidencePath,
    CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256: draftReceiptFile.evidenceSha256,
    CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_PATH: draftMetadataPath,
    CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY: credentialSeparationHmacKey,
    CNYOS_STAGING_NETLIFY_AUTH_TOKEN: publisherToken
  };
  assert.equal(Object.hasOwn(
    draftMetadataEnv,
    'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN'
  ), false);
  const draftSiteFixture = {
    id: isolatedPolicy.POLICY.target.netlifySiteId,
    name: isolatedPolicy.POLICY.target.netlifySiteName,
    ssl_url: isolatedPolicy.POLICY.target.netlifyOrigin,
    published_deploy: { id: previousDeployId }
  };
  const draftDeployOrigin =
    `https://${draftDeployId}--${isolatedPolicy.POLICY.target.netlifySiteName}.netlify.app`;
  const draftDeployFixture = {
    id: draftDeployId,
    site_id: isolatedPolicy.POLICY.target.netlifySiteId,
    state: 'ready',
    context: 'production',
    deploy_ssl_url: draftDeployOrigin,
    title: isolatedPolicy.deploymentMarker(
      runtime.GITHUB_RUN_ID,
      boundaryNonce,
      candidateCommit
    ),
    draft: true,
    available_functions: isolatedPolicy.EXPECTED_FUNCTION_NAMES.map(name => ({ n: name })),
    function_schedules: Object.entries(isolatedPolicy.REQUIRED_SCHEDULES)
      .map(([name, cron]) => ({ name, cron })),
    functions_config: {}
  };
  const metadataRequests = [];
  const metadataResult = await isolatedNetlify.verifyDraftMetadata({
    env: draftMetadataEnv,
    fetchImpl: async (url, options) => {
      metadataRequests.push({ url, options });
      const pathname = new URL(url).pathname;
      const sitePath =
        `/api/v1/sites/${encodeURIComponent(isolatedPolicy.POLICY.target.netlifySiteId)}`;
      const deployPath = `/api/v1/deploys/${draftDeployId}`;
      const value = pathname === sitePath
        ? draftSiteFixture
        : pathname === deployPath
          ? draftDeployFixture
          : null;
      assert.notEqual(value, null, `unexpected metadata request: ${url}`);
      return new Response(JSON.stringify(value), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    },
    now: () => new Date(boundaryNow)
  });
  assert.deepEqual(
    metadataRequests.map(request => new URL(request.url).pathname),
    [
      `/api/v1/sites/${encodeURIComponent(isolatedPolicy.POLICY.target.netlifySiteId)}`,
      `/api/v1/deploys/${draftDeployId}`,
      `/api/v1/sites/${encodeURIComponent(isolatedPolicy.POLICY.target.netlifySiteId)}`
    ]
  );
  for (const request of metadataRequests) {
    assert.equal(request.options.headers.Authorization, `Bearer ${publisherToken}`);
    assert.equal(request.options.redirect, 'error');
  }
  assert.equal(metadataResult.evidence.publisherCredentialIsolated, true);
  assert.equal(metadataResult.evidence.draftDeployId, draftDeployId);
  assert.match(metadataResult.evidence.publisherCredentialOpaqueIdentityHmacSha256,
    /^[0-9a-f]{64}$/);
  assert.match(metadataResult.evidence.credentialSeparationHmacKeyConfirmationSha256,
    /^[0-9a-f]{64}$/);
  assert.equal(metadataResult.evidence.credentialSeparationHmacKeySerialized, false);
  assert.equal(JSON.stringify(metadataResult.evidence).includes(publisherToken), false);
  assert.equal(JSON.stringify(metadataResult.evidence).includes(credentialSeparationHmacKey), false);
  const draftMetadataBytes = await fs.readFile(draftMetadataPath);
  const draftMetadataSha256 = sha256(draftMetadataBytes);
  assert.equal(draftMetadataSha256,
    sha256(`${JSON.stringify(metadataResult.evidence, null, 2)}\n`));

  for (const [index, boundaryTokenPresence] of [
    undefined,
    '',
    `boundary-token.${'x'.repeat(32)}`
  ].entries()) {
    let fetchCalls = 0;
    await assert.rejects(
      isolatedNetlify.verifyDraftMetadata({
        env: {
          ...draftMetadataEnv,
          CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: boundaryTokenPresence,
          CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_PATH:
            path.join(netlifyBoundaryTestRoot, `rejected-draft-metadata-${index}.json`)
        },
        fetchImpl: async () => {
          fetchCalls += 1;
          throw new Error('CNYOS_TEST_METADATA_FETCH_MUST_NOT_RUN');
        },
        now: () => new Date(boundaryNow)
      }),
      /CNYOS_CONTROLLER_DRAFT_CREDENTIAL_CORESIDENCY_FORBIDDEN/,
      `draft metadata must reject boundary-token own-property presence: ${index}`
    );
    assert.equal(fetchCalls, 0,
      'draft metadata credential co-residency must be rejected before Netlify fetch');
  }

  const draftAccessBoundaryFile = await writeBoundaryEvidence(
    'draft-access-boundary.json',
    {
      schemaVersion: 1,
      evidenceType: 'cnyos_staging_controller_private_draft_access_boundary',
      status: 'passed',
      scope: 'cnyos_staging_only',
      productionAuthorization: false,
      verifiedAt: boundaryNow.toISOString(),
      controllerRepository: runtime.GITHUB_REPOSITORY,
      controllerRef: runtime.GITHUB_REF,
      controllerCommit: runtime.GITHUB_SHA,
      controllerRunId: runtime.GITHUB_RUN_ID,
      source: {
        repository: producerManifest.sourceRepository,
        commit: candidateCommit,
        tree: candidateTree
      },
      artifact: { artifactSha256: producerManifest.artifactSha256 },
      target: {
        netlifySiteId: isolatedPolicy.POLICY.target.netlifySiteId,
        netlifyOrigin: isolatedPolicy.POLICY.target.netlifyOrigin
      },
      preflightEvidenceSha256: validDraftPreflightFile.evidenceSha256,
      draftReceiptEvidenceSha256: draftReceiptFile.evidenceSha256,
      currentPublishedDeployId: previousDeployId,
      draftDeployId,
      exactDraftDeployOrigin: draftDeployOrigin,
      boundary: {
        origin: isolatedDraftBoundaryOrigin,
        policyId: isolatedDraftBoundaryPolicyId,
        policySha256: isolatedDraftBoundaryPolicySha256,
        endpointPath: '/v1/read-netlify-draft-file',
        requestMethod: 'POST',
        authorizationHeaderConsumedAtBoundary: true,
        authorizationHeaderForwardedUpstream: false,
        cookiesForwardedUpstream: false,
        redirectsFollowed: false,
        fixedTargetSiteId: true,
        fixedTargetDeployId: true,
        exactDeployOriginRequired: true,
        candidateRoutingCanChangeUpstreamTarget: false,
        readOperationReturnsOnlyHashBoundUpstreamBytes: true,
        probeOperationReturnsOnlySanitizedMetadata: true,
        secretSerializationPrevented: true
      },
      canary: {
        verifiedAt: boundaryNow.toISOString(),
        requestNonce: Buffer.alloc(32, 0x6e).toString('base64url'),
        candidateFunctionReached: true,
        boundaryCredentialObserved: false,
        authorizationHeaderObserved: false,
        cookiesObserved: false,
        responseReflectedCredential: false
      }
    }
  );
  const draftAccessToken = `offline-draft-access.${'x'.repeat(32)}`;
  const draftVerificationPath =
    path.join(netlifyBoundaryTestRoot, 'draft-verification.json');
  const draftVerificationEnv = {
    ...producerBundleVerifierEnv,
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: validDraftPreflightFile.evidencePath,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: validDraftPreflightFile.evidenceSha256,
    CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH: draftReceiptFile.evidencePath,
    CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256: draftReceiptFile.evidenceSha256,
    CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL: isolatedDraftBoundaryOrigin,
    CNYOS_CONTROLLER_DRAFT_ACCESS_BOUNDARY_EVIDENCE_PATH:
      draftAccessBoundaryFile.evidencePath,
    CNYOS_EXPECTED_DRAFT_ACCESS_BOUNDARY_EVIDENCE_SHA256:
      draftAccessBoundaryFile.evidenceSha256,
    CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_PATH: draftMetadataPath,
    CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256: draftMetadataSha256,
    CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY: credentialSeparationHmacKey,
    CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: draftAccessToken,
    CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH: draftVerificationPath
  };
  assert.equal(Object.hasOwn(
    draftVerificationEnv,
    'CNYOS_STAGING_NETLIFY_AUTH_TOKEN'
  ), false);
  assert.equal(Object.hasOwn(draftVerificationEnv, 'NETLIFY_AUTH_TOKEN'), false);
  const boundaryRequests = [];
  const draftVerificationResult = await isolatedNetlify.verifyDraftDeployment({
    env: draftVerificationEnv,
    fetchImpl: async (url, options) => {
      boundaryRequests.push({ url, options });
      return new Response(staticBytes, {
        status: 200,
        headers: {
          'content-type': 'application/octet-stream',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'x-cnyos-boundary-policy-id': isolatedDraftBoundaryPolicyId,
          'x-cnyos-boundary-policy-sha256': isolatedDraftBoundaryPolicySha256,
          'x-cnyos-upstream-authorization-forwarded': 'false',
          'x-cnyos-upstream-cookies-forwarded': 'false',
          'x-cnyos-upstream-redirect-followed': 'false'
        }
      });
    },
    now: () => new Date(boundaryNow)
  });
  assert.equal(boundaryRequests.length, 1);
  assert.equal(boundaryRequests[0].url,
    `${isolatedDraftBoundaryOrigin}/v1/read-netlify-draft-file`);
  assert.equal(boundaryRequests[0].options.headers.Authorization, `Bearer ${draftAccessToken}`);
  assert.equal(boundaryRequests[0].options.redirect, 'error');
  assert.equal(boundaryRequests[0].url.startsWith('https://api.netlify.com/'), false);
  assert.equal(draftVerificationResult.evidence.draftMetadataEvidenceSha256,
    draftMetadataSha256);
  assert.equal(
    draftVerificationResult.evidence.publisherAndDraftAccessCredentialCoResidencyPrevented,
    true
  );
  assert.equal(draftVerificationResult.evidence.credentialSeparationHmacKeyConfirmed, true);
  assert.equal(draftVerificationResult.evidence.credentialSeparationHmacKeySerialized, false);
  assert.equal(JSON.stringify(draftVerificationResult.evidence).includes(draftAccessToken), false);
  assert.equal(
    JSON.stringify(draftVerificationResult.evidence).includes(credentialSeparationHmacKey),
    false
  );

  const promotedVerificationEvidence = {
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_exact_deploy_promotion',
    status: 'passed',
    controllerRunId: runtime.GITHUB_RUN_ID,
    controllerCommit: runtime.GITHUB_SHA,
    source: { commit: candidateCommit },
    artifact: { artifactSha256: producerManifest.artifactSha256 },
    promotedDeployId: draftDeployId,
    preflightEvidenceSha256: validDraftPreflightFile.evidenceSha256
  };
  const promotedVerificationFile = await writeBoundaryEvidence(
    'promotion-for-completion-time.json',
    promotedVerificationEvidence
  );
  const publishedSiteFixture = {
    ...draftSiteFixture,
    published_deploy: { id: draftDeployId }
  };
  const publishedDeployFixture = {
    ...draftDeployFixture,
    draft: false,
    published_at: '2026-09-08T12:00:15.000Z'
  };
  const promotedFetch = async url => {
    const pathname = new URL(url).pathname;
    const sitePath =
      `/api/v1/sites/${encodeURIComponent(isolatedPolicy.POLICY.target.netlifySiteId)}`;
    if (pathname === sitePath) {
      return new Response(JSON.stringify(publishedSiteFixture), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    }
    if (pathname === `/api/v1/deploys/${draftDeployId}`) {
      return new Response(JSON.stringify(publishedDeployFixture), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    }
    if (pathname === `${sitePath}/files`) {
      return new Response(JSON.stringify([{
        path: '/index.html',
        size: staticBytes.byteLength,
        sha: sha1(staticBytes)
      }]), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    }
    if (pathname === `${sitePath}/files/index.html`) {
      return new Response(staticBytes, { status: 200 });
    }
    throw new Error(`CNYOS_TEST_UNEXPECTED_PROMOTED_REQUEST:${pathname}`);
  };
  const promotedVerificationEnv = {
    ...producerBundleVerifierEnv,
    CNYOS_STAGING_NETLIFY_AUTH_TOKEN: publisherToken,
    CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: validDraftPreflightFile.evidencePath,
    CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: validDraftPreflightFile.evidenceSha256,
    CNYOS_CONTROLLER_PROMOTION_EVIDENCE_PATH: promotedVerificationFile.evidencePath,
    CNYOS_EXPECTED_PROMOTION_EVIDENCE_SHA256: promotedVerificationFile.evidenceSha256,
    CNYOS_CONTROLLER_POST_PROMOTION_EVIDENCE_PATH:
      path.join(netlifyBoundaryTestRoot, 'post-promotion-completion-time.json')
  };
  let promotedClockReads = 0;
  const promotedCompletionTime = new Date('2026-09-08T12:01:00.000Z');
  const promotedResult = await isolatedNetlify.verifyPromotedDeployment({
    env: promotedVerificationEnv,
    fetchImpl: promotedFetch,
    now: () => promotedClockReads++ === 0 ? new Date(boundaryNow) : promotedCompletionTime
  });
  assert.equal(promotedClockReads, 2);
  assert.equal(promotedResult.evidence.verifiedAt, promotedCompletionTime.toISOString(),
    'verifiedAt must be captured after the final publisher-current check');

  const expiredOutput = path.join(
    netlifyBoundaryTestRoot,
    'rejected-post-promotion-expired-at-completion.json'
  );
  let expiredClockReads = 0;
  await assert.rejects(isolatedNetlify.verifyPromotedDeployment({
    env: {
      ...promotedVerificationEnv,
      CNYOS_CONTROLLER_POST_PROMOTION_EVIDENCE_PATH: expiredOutput
    },
    fetchImpl: promotedFetch,
    now: () => expiredClockReads++ === 0 ? new Date(boundaryNow) : new Date(boundaryExpiry)
  }), /CNYOS_CONTROLLER_PREFLIGHT_AUTHORIZATION_EXPIRED/,
  'authority expiring during remote verification must fail before evidence is written');
  await assert.rejects(fs.access(expiredOutput), error => error?.code === 'ENOENT');

  let credentialComparisonFetchCalls = 0;
  const rejectCredentialComparisonFetch = async () => {
    credentialComparisonFetchCalls += 1;
    throw new Error('CNYOS_TEST_CREDENTIAL_COMPARISON_FETCH_MUST_NOT_RUN');
  };
  await assert.rejects(
    isolatedNetlify.verifyDraftDeployment({
      env: {
        ...draftVerificationEnv,
        CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN: publisherToken,
        CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH:
          path.join(netlifyBoundaryTestRoot, 'rejected-identical-bearer.json')
      },
      fetchImpl: rejectCredentialComparisonFetch,
      now: () => new Date(boundaryNow)
    }),
    /CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_NOT_SEPARATE/
  );
  assert.equal(credentialComparisonFetchCalls, 0,
    'identical publisher and draft bearer must fail before boundary fetch');

  const mismatchedCredentialSeparationHmacKey =
    Buffer.alloc(32, 0x69).toString('base64url');
  await assert.rejects(
    isolatedNetlify.verifyDraftDeployment({
      env: {
        ...draftVerificationEnv,
        CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY: mismatchedCredentialSeparationHmacKey,
        CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH:
          path.join(netlifyBoundaryTestRoot, 'rejected-hmac-key-mismatch.json')
      },
      fetchImpl: rejectCredentialComparisonFetch,
      now: () => new Date(boundaryNow)
    }),
    /CNYOS_CONTROLLER_CREDENTIAL_SEPARATION_HMAC_KEY_MISMATCH/
  );
  assert.equal(credentialComparisonFetchCalls, 0,
    'different credential-separation HMAC key must fail before boundary fetch');

  for (const [publisherVariable, publisherValue] of [
    ['CNYOS_STAGING_NETLIFY_AUTH_TOKEN', publisherToken],
    ['NETLIFY_AUTH_TOKEN', undefined]
  ]) {
    let fetchCalls = 0;
    await assert.rejects(
      isolatedNetlify.verifyDraftDeployment({
        env: {
          ...draftVerificationEnv,
          [publisherVariable]: publisherValue,
          CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH:
            path.join(netlifyBoundaryTestRoot, `rejected-${publisherVariable}.json`)
        },
        fetchImpl: async () => {
          fetchCalls += 1;
          throw new Error('CNYOS_TEST_BOUNDARY_FETCH_MUST_NOT_RUN');
        },
        now: () => new Date(boundaryNow)
      }),
      /CNYOS_CONTROLLER_DRAFT_CREDENTIAL_CORESIDENCY_FORBIDDEN/,
      `${publisherVariable} presence must be rejected before boundary fetch`
    );
    assert.equal(fetchCalls, 0,
      `${publisherVariable} presence must be rejected before boundary fetch`);
  }

  let tamperedMetadataFetchCalls = 0;
  const noBoundaryFetch = async () => {
    tamperedMetadataFetchCalls += 1;
    throw new Error('CNYOS_TEST_TAMPERED_METADATA_FETCH_MUST_NOT_RUN');
  };
  const mismatchedDraftMetadataSha256 =
    `${draftMetadataSha256[0] === '0' ? '1' : '0'}${draftMetadataSha256.slice(1)}`;
  await assert.rejects(
    isolatedNetlify.verifyDraftDeployment({
      env: {
        ...draftVerificationEnv,
        CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256: mismatchedDraftMetadataSha256,
        CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH:
          path.join(netlifyBoundaryTestRoot, 'rejected-metadata-digest.json')
      },
      fetchImpl: noBoundaryFetch,
      now: () => new Date(boundaryNow)
    }),
    /CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_INVALID_DIGEST_MISMATCH/
  );
  assert.equal(tamperedMetadataFetchCalls, 0,
    'tampered metadata digest must fail before boundary fetch');

  const tamperedMetadataIdentity = structuredClone(metadataResult.evidence);
  tamperedMetadataIdentity.source.commit = '9'.repeat(40);
  const tamperedMetadataIdentityFile = await writeBoundaryEvidence(
    'draft-metadata-tampered-identity.json',
    tamperedMetadataIdentity
  );
  await assert.rejects(
    isolatedNetlify.verifyDraftDeployment({
      env: {
        ...draftVerificationEnv,
        CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_PATH:
          tamperedMetadataIdentityFile.evidencePath,
        CNYOS_EXPECTED_DRAFT_METADATA_EVIDENCE_SHA256:
          tamperedMetadataIdentityFile.evidenceSha256,
        CNYOS_CONTROLLER_DRAFT_VERIFICATION_EVIDENCE_PATH:
          path.join(netlifyBoundaryTestRoot, 'rejected-metadata-identity.json')
      },
      fetchImpl: noBoundaryFetch,
      now: () => new Date(boundaryNow)
    }),
    /CNYOS_CONTROLLER_DRAFT_METADATA_EVIDENCE_INVALID/
  );
  assert.equal(tamperedMetadataFetchCalls, 0,
    'tampered metadata identity must fail before boundary fetch');

  for (const [index, mutation] of boundaryMutations.entries()) {
    const preflightEvidence = preflightBoundaryEvidenceFixture();
    mutation.apply(preflightEvidence);
    const preflightFile = await writeBoundaryEvidence(
      `isolated-preflight-boundary-${index}.json`,
      preflightEvidence
    );
    const env = {
      ...isolatedBundleEnv,
      CNYOS_CONTROLLER_PREFLIGHT_EVIDENCE_PATH: preflightFile.evidencePath,
      CNYOS_EXPECTED_PREFLIGHT_EVIDENCE_SHA256: preflightFile.evidenceSha256
    };
    for (const [name, invoke] of [
      ['verifyDraftDeployment', (guardedEnv, fetchImpl) =>
        isolatedNetlify.verifyDraftDeployment({
        env: guardedEnv,
        fetchImpl,
        now: () => new Date(boundaryNow)
      })],
      ['verifyPromotedDeployment', (guardedEnv, fetchImpl) =>
        isolatedNetlify.verifyPromotedDeployment({
        env: guardedEnv,
        fetchImpl,
        now: () => new Date(boundaryNow)
      })],
      ['verifyPromotedDeployment(finalCheck)', (guardedEnv, fetchImpl) =>
        isolatedNetlify.verifyPromotedDeployment({
          env: guardedEnv,
          fetchImpl,
          now: () => new Date(boundaryNow),
          finalCheck: true
        })
      ]
    ]) {
      await rejectsBeforeNetlifyFetch(
        `${name}: ${mutation.label}`,
        env,
        invoke,
        /CNYOS_CONTROLLER_PREFLIGHT_DEPLOYMENT_BOUNDARY_INVALID/
      );
    }
  }
} finally {
  await fs.rm(netlifyBoundaryTestRoot, { recursive: true, force: true });
}

const deployId = '0123456789abcdef01234567';
assert.deepEqual(parseDeployReceipt({
  deploy_id: deployId,
  site_id: POLICY.target.netlifySiteId,
  site_name: POLICY.target.netlifySiteName,
  deploy_ssl_url: `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`
}), {
  deployId,
  exactDeployOrigin: `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`
});

const draftAccessToken = `draft-access-token.${'x'.repeat(32)}`;
assert.equal(strictDraftAccessToken(draftAccessToken), draftAccessToken);
for (const invalidToken of [undefined, '', 'short', `${'x'.repeat(31)}\n`, `token ${'x'.repeat(32)}`]) {
  assert.throws(() => strictDraftAccessToken(invalidToken),
    /CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_INVALID/);
}
const draftFileBytes = Buffer.from('authenticated immutable draft bytes', 'utf8');
const draftBundle = {
  manifest: {
    files: [{
      path: 'payload/dist/index.html',
      size: draftFileBytes.byteLength,
      sha256: sha256(draftFileBytes)
    }]
  }
};
const draftOrigin = `https://${deployId}--${POLICY.target.netlifySiteName}.netlify.app`;
const draftBoundaryOrigin = 'https://cnyos-draft-reader.example.test';
const draftBoundaryPolicyId = 'cnyos-private-draft-access-v1';
const draftBoundaryPolicySha256 = 'd'.repeat(64);
let observedDraftRequest = null;
let observedDraftRequestCount = 0;
const draftStaticEvidence = await verifyDraftStaticFiles(
  async (url, options) => {
    observedDraftRequestCount += 1;
    observedDraftRequest = { url, options };
    return new Response(draftFileBytes, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'x-cnyos-boundary-policy-id': draftBoundaryPolicyId,
        'x-cnyos-boundary-policy-sha256': draftBoundaryPolicySha256,
        'x-cnyos-upstream-authorization-forwarded': 'false',
        'x-cnyos-upstream-cookies-forwarded': 'false',
        'x-cnyos-upstream-redirect-followed': 'false'
      }
    });
  },
  draftBoundaryOrigin,
  draftOrigin,
  deployId,
  draftBundle,
  draftAccessToken,
  {
    controllerRunId: '123456',
    boundaryPolicyId: draftBoundaryPolicyId,
    boundaryPolicySha256: draftBoundaryPolicySha256
  }
);
assert.equal(observedDraftRequestCount, 1);
assert.equal(observedDraftRequest.url,
  `${draftBoundaryOrigin}/v1/read-netlify-draft-file`);
assert.equal(new URL(observedDraftRequest.url).origin, draftBoundaryOrigin);
assert.equal(observedDraftRequest.url.includes(draftOrigin), false);
assert.equal(observedDraftRequest.options.method, 'POST');
assert.equal(observedDraftRequest.options.redirect, 'error');
assert.equal(observedDraftRequest.options.credentials, 'omit');
assert.equal(observedDraftRequest.options.referrerPolicy, 'no-referrer');
assert.equal(observedDraftRequest.options.cache, 'no-store');
assert.equal(observedDraftRequest.options.headers.Authorization, `Bearer ${draftAccessToken}`);
assert.notEqual(observedDraftRequest.options.headers.Authorization, 'Bearer netlify-publish-token');
assert.equal(JSON.stringify(observedDraftRequest.options.headers).includes(draftOrigin), false);
const observedDraftRequestBody = JSON.parse(observedDraftRequest.options.body);
assert.equal(JSON.stringify(observedDraftRequestBody).includes(draftAccessToken), false);
assert.equal(observedDraftRequest.options.body.split(draftOrigin).length - 1, 1);
assert.deepEqual(observedDraftRequestBody, {
  schemaVersion: 1,
  operation: 'read_exact_netlify_draft_file',
  controllerRunId: '123456',
  netlifySiteId: POLICY.target.netlifySiteId,
  netlifyDeployId: deployId,
  exactDraftDeployOrigin: draftOrigin,
  path: '/index.html',
  expectedSize: draftFileBytes.byteLength,
  expectedSha256: sha256(draftFileBytes)
});
assert.equal(draftStaticEvidence.fileCount, 1);
assert.equal(JSON.stringify(draftStaticEvidence).includes(draftAccessToken), false);
await assert.rejects(
  verifyDraftStaticFiles(
    async () => new Response(draftFileBytes, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'x-cnyos-boundary-policy-id': draftBoundaryPolicyId,
        'x-cnyos-boundary-policy-sha256': draftBoundaryPolicySha256,
        'x-cnyos-upstream-authorization-forwarded': 'false',
        'x-cnyos-upstream-cookies-forwarded': 'false',
        'x-cnyos-upstream-redirect-followed': 'false',
        'x-debug-boundary-token': draftAccessToken
      }
    }),
    draftBoundaryOrigin,
    draftOrigin,
    deployId,
    draftBundle,
    draftAccessToken,
    {
      controllerRunId: '123456',
      boundaryPolicyId: draftBoundaryPolicyId,
      boundaryPolicySha256: draftBoundaryPolicySha256
    }
  ),
  /CNYOS_CONTROLLER_DRAFT_ACCESS_TOKEN_REFLECTED/,
  'raw draft-byte verification must reject bearer reflection in any response header'
);
let rejectedDraftOriginFetchCalls = 0;
await assert.rejects(
  verifyDraftStaticFiles(
    async () => {
      rejectedDraftOriginFetchCalls += 1;
      return new Response(draftFileBytes, { status: 200 });
    },
    draftBoundaryOrigin,
    'https://cnyos.netlify.app',
    deployId,
    draftBundle,
    draftAccessToken,
    {
      controllerRunId: '123456',
      boundaryPolicyId: draftBoundaryPolicyId,
      boundaryPolicySha256: draftBoundaryPolicySha256
    }
  ),
  /CNYOS_CONTROLLER_DRAFT_ORIGIN_INVALID/
);
assert.equal(rejectedDraftOriginFetchCalls, 0,
  'invalid Netlify draft origin must precede the boundary fetch');

process.stdout.write('CNYOS protected-controller offline contract: passed\n');
