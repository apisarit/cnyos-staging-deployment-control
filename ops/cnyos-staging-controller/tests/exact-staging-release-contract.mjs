import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  EXACT_STAGING_ENVIRONMENT,
  EXACT_STAGING_FUNCTION_ENVIRONMENT,
  EXACT_STAGING_LIMITS,
  EXACT_STAGING_PRODUCTION_DENYLIST,
  EXACT_STAGING_SECRET_NAMES,
  EXACT_STAGING_SYNTHETIC_HN_PATTERN,
  EXACT_STAGING_TARGET,
  EXACT_STAGING_WORKFLOW_PATH,
  ExactStagingReleaseError,
  assertScopedOpdWriteBody,
  assertSecretFreeEvidence,
  createScopedOpdWriteLedger,
  loadExactStagingConfig,
  parseNetlifyDeployReceipt,
  sha256,
  verifyExactStagingFunctionEnvironment,
  verifyExactStagingArtifact
} from '../scripts/exact-staging-release.mjs';
import {
  classifyExactStagingPublishReconciliation,
  createExactStagingPublishAttempt,
  createExactStagingPublishIntent,
  deriveExactStagingTerminalStatus,
  executeExactStagingPublishAttempt,
  finalizeExactStagingEvidence,
  reconcileExactStagingPublish
} from '../scripts/exact-staging-publish.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(packageRoot, '..', '..');
const workflow = await fs.readFile(path.join(repositoryRoot, EXACT_STAGING_WORKFLOW_PATH), 'utf8');
const publisherPackage = JSON.parse(await fs.readFile(path.join(repositoryRoot,
  'ops/cnyos-staging-publisher/package.json'), 'utf8'));
const publisherLock = JSON.parse(await fs.readFile(path.join(repositoryRoot,
  'ops/cnyos-staging-publisher/package-lock.json'), 'utf8'));
const runner = await fs.readFile(path.join(packageRoot,
  'scripts/run-exact-staging-clinical-uat.mjs'), 'utf8');
const publisher = await fs.readFile(path.join(packageRoot,
  'scripts/exact-staging-publish.mjs'), 'utf8');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-exact-staging-contract-'));
const artifact = path.join(root, 'artifact');
const dist = path.join(artifact, 'dist');
const functions = path.join(artifact, 'functions');
const work = path.join(root, 'work');
await fs.mkdir(dist, { recursive: true });
await fs.mkdir(functions, { recursive: true });

const controllerCommit = '9'.repeat(40);
const commit = 'a'.repeat(40);
const tree = 'b'.repeat(40);
const rollback = 'c'.repeat(24);
const runtimeNames = [
  'index.html', 'login.html', 'auth-callback.html', 'owner-control.html',
  'clinical-v3.html', 'pharmacy.html', 'app.js', 'app.css', 'auth-config.js',
  'tenant-config.js', 'brand-config.js', 'deploy-manifest.json'
].sort();
const deployManifest = {
  schemaVersion: 1,
  deploymentId: EXACT_STAGING_TARGET.deploymentId,
  tenant: {
    expectedClinicId: EXACT_STAGING_TARGET.clinicId,
    expectedClinicCode: EXACT_STAGING_TARGET.clinicCode
  },
  identity: { qrIssuer: EXACT_STAGING_TARGET.qrIssuer },
  source: { commit, tree, verified: true },
  build: {
    context: 'production', deploymentClass: 'dedicated-staging',
    timestamp: '2026-10-13T00:00:00.000Z'
  },
  safety: {
    previewLocked: false, databaseLocked: false,
    stagingDatabaseExplicitlyAcknowledged: true
  }
};
for (const name of runtimeNames) {
  const value = name === 'deploy-manifest.json'
    ? `${JSON.stringify(deployManifest)}\n` : `${name}:synthetic\n`;
  await fs.writeFile(path.join(dist, name), value);
}
const integrity = [];
for (const name of runtimeNames) {
  const bytes = await fs.readFile(path.join(dist, name));
  integrity.push({ path: name, size: bytes.length, sha256: sha256(bytes) });
}
await fs.writeFile(path.join(dist, 'runtime-publish-manifest.json'), `${JSON.stringify({
  schemaVersion: 2, generatedAt: '2026-10-13T00:00:00.000Z',
  fileCount: runtimeNames.length, files: runtimeNames,
  integrityAlgorithm: 'sha256', integrity
})}\n`);
const functionBytes = Buffer.from('export default async () => new Response("synthetic");\n');
await fs.writeFile(path.join(functions, 'handler.mjs'), functionBytes);
const functionEntries = [{
  path: 'handler.mjs', size: functionBytes.length, sha256: sha256(functionBytes), mode: '100644'
}];
const functionManifest = {
  schemaVersion: 1, artifactType: 'cnyos-staging-function-inputs',
  source: {
    gitObjectFormat: 'sha1', requestedRef: commit, resolvedRefObjectId: commit,
    sourcePath: 'netlify/functions', sourceTreeObjectId: 'd'.repeat(40)
  },
  fileCount: 1, totalBytes: functionBytes.length, files: functionEntries,
  manifestDigestAlgorithm: 'sha256',
  manifestDigestEncoding: 'utf8-json-stringify-files-array-v1',
  manifestSha256: sha256(Buffer.from(JSON.stringify(functionEntries))),
  treeDigestAlgorithm: 'sha256', treeDigestDomain: 'synthetic',
  treeDigestEncoding: 'synthetic', treeSha256: 'e'.repeat(64), overallSha256: 'e'.repeat(64)
};
await fs.writeFile(path.join(artifact, 'function-input-manifest.json'),
  `${JSON.stringify(functionManifest)}\n`);

const config = loadExactStagingConfig({
  CNYOS_EXPECTED_CONTROLLER_COMMIT: controllerCommit,
  CNYOS_EXPECTED_SOURCE_COMMIT: commit,
  CNYOS_EXPECTED_SOURCE_TREE: tree,
  CNYOS_EXPECTED_ROLLBACK_DEPLOY_ID: rollback,
  CNYOS_STAGING_RUN_REFERENCE: 'exact-staging-contract-20261013',
  CNYOS_STAGING_ARTIFACT_DIRECTORY: artifact,
  CNYOS_EXACT_STAGING_WORK_DIRECTORY: work
});
const verified = await verifyExactStagingArtifact(config);
assert.equal(verified.artifact.source.commit, commit);
assert.equal(verified.artifact.source.tree, tree);
assert.equal(verified.artifact.runtimeFileCount, runtimeNames.length);
assert.equal(verified.artifact.functionFileCount, 1);

const receipt = parseNetlifyDeployReceipt({
  deploy_id: 'f'.repeat(24),
  site_id: EXACT_STAGING_TARGET.netlifySiteId,
  deploy_url: `https://${'f'.repeat(24)}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`
}, config);
assert.equal(receipt.siteId, EXACT_STAGING_TARGET.netlifySiteId);
assert.equal(receipt.source.commit, commit);
assert.throws(() => parseNetlifyDeployReceipt({
  deploy_id: 'f'.repeat(24), site_id: EXACT_STAGING_PRODUCTION_DENYLIST.netlifySiteIds[0]
}, config), ExactStagingReleaseError);
assert.throws(() => assertSecretFreeEvidence({ leaked: 'prefix-SECRET-value' }, ['SECRET']),
  ExactStagingReleaseError);

const encounterId = '11111111-1111-4111-a111-111111111111';
const patientId = '22222222-2222-4222-a222-222222222222';
const practitionerUserId = '33333333-3333-4333-a333-333333333333';
const scopedBody = JSON.stringify({
  p_encounter_id: encounterId,
  p_history: { patient_id: patientId, actor_id: practitionerUserId, synthetic: true }
});
assert.deepEqual(assertScopedOpdWriteBody(scopedBody, 'application/json; charset=UTF-8', {
  encounterId, patientId, practitionerUserId
}), {
  encounterIdBound: true,
  patientIdentifiersBoundWhenPresent: true,
  actorIdentifiersBoundWhenPresent: true
});
for (const body of [
  JSON.stringify({ p_encounter_id: patientId, p_history: {} }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { patient_id: encounterId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { patient_uuid: encounterId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { 'patient-id': encounterId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { id_for_patient: encounterId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { updated_by: patientId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { actor_uuid: patientId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { patient: { id: encounterId } } }),
  JSON.stringify({ p_encounter_id: encounterId,
    p_history: { patient_identity: { uuid: encounterId } } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { actor: { id: patientId } } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: { opaque_reference: patientId } }),
  JSON.stringify({ p_encounter_id: encounterId, p_history: {}, patient_uuid: patientId }),
  JSON.stringify({ p_encounter_id: encounterId }),
  '{'
]) {
  assert.throws(() => assertScopedOpdWriteBody(body, 'application/json', {
    encounterId, patientId, practitionerUserId
  }), ExactStagingReleaseError);
}
assert.throws(() => assertScopedOpdWriteBody(scopedBody, 'text/plain', {
  encounterId, patientId, practitionerUserId
}), ExactStagingReleaseError);
assert.deepEqual(assertScopedOpdWriteBody(JSON.stringify({
  p_encounter_id: encounterId,
  p_history: {
    patient_uuid: patientId,
    actor: { id: practitionerUserId },
    source_patient_identifier: patientId
  }
}), 'application/json', { encounterId, patientId, practitionerUserId }), {
  encounterIdBound: true,
  patientIdentifiersBoundWhenPresent: true,
  actorIdentifiersBoundWhenPresent: true
});

const browserWriteLedger = createScopedOpdWriteLedger(2);
browserWriteLedger.reserve(1);
browserWriteLedger.reserve(2);
assert.throws(() => browserWriteLedger.reserve(3),
  /CNYOS_EXACT_STAGING_OPD_WRITE_BUDGET_EXCEEDED/);
assert.deepEqual(browserWriteLedger.evidence(3), {
  limit: 2,
  dispatched: 2,
  contextCount: 3,
  perContext: [
    { contextOrdinal: 1, writes: 1 },
    { contextOrdinal: 2, writes: 1 },
    { contextOrdinal: 3, writes: 0 }
  ],
  records: [
    { ordinal: 1, contextOrdinal: 1, rpc: 'save_ttm_opd_history', reservedBeforeFetch: true },
    { ordinal: 2, contextOrdinal: 2, rpc: 'save_ttm_opd_history', reservedBeforeFetch: true }
  ]
});

const functionEnvironment = verifyExactStagingFunctionEnvironment(config, 'n'.repeat(32), {
  cliPath: '/locked/netlify',
  env: {
    PATH: '/usr/bin', HOME: '/tmp/home',
    XDG_CONFIG_HOME: '/tmp/config', XDG_CACHE_HOME: '/tmp/cache'
  },
  execFileImpl: (executable, args, options) => {
    assert.equal(executable, '/locked/netlify');
    assert.equal(args[0], 'env:get');
    assert.equal(args[2], `--site=${EXACT_STAGING_TARGET.netlifySiteId}`);
    assert.equal(args[3], '--context=production');
    assert.equal(args[4], '--scope=functions');
    assert.equal(options.env.NETLIFY_AUTH_TOKEN, 'n'.repeat(32));
    return `${EXACT_STAGING_FUNCTION_ENVIRONMENT[args[1]]}\n`;
  }
});
assert.deepEqual(functionEnvironment.validatedVariableNames,
  Object.keys(EXACT_STAGING_FUNCTION_ENVIRONMENT).sort());
assert.equal(functionEnvironment.productionDenylistConfirmed, true);
assert.throws(() => verifyExactStagingFunctionEnvironment(config, 'n'.repeat(32), {
  cliPath: '/locked/netlify',
  env: {
    PATH: '/usr/bin', HOME: '/tmp/home',
    XDG_CONFIG_HOME: '/tmp/config', XDG_CACHE_HOME: '/tmp/cache'
  },
  execFileImpl: () => `${EXACT_STAGING_PRODUCTION_DENYLIST.origins[0]}\n`
}), ExactStagingReleaseError);

const tampered = path.join(dist, 'app.js');
await fs.appendFile(tampered, 'tamper');
await assert.rejects(() => verifyExactStagingArtifact(config), ExactStagingReleaseError);
await fs.writeFile(tampered, 'app.js:synthetic\n');

const unexpectedRootFile = path.join(artifact, 'unexpected-root-file.txt');
await fs.writeFile(unexpectedRootFile, 'must be rejected\n');
await assert.rejects(() => verifyExactStagingArtifact(config),
  /CNYOS_EXACT_STAGING_ARTIFACT_CLOSED_WORLD_INVALID/);
await fs.rm(unexpectedRootFile);

await fs.writeFile(config.functionManifestPath, `${JSON.stringify({
  ...functionManifest,
  source: { ...functionManifest.source, resolvedRefObjectId: '8'.repeat(40) }
})}\n`);
await assert.rejects(() => verifyExactStagingArtifact(config),
  /CNYOS_EXACT_STAGING_FUNCTION_MANIFEST_INVALID/);
await fs.writeFile(config.functionManifestPath, `${JSON.stringify(functionManifest)}\n`);

const savedFunctionManifest = path.join(artifact, 'function-input-manifest.saved.json');
await fs.rename(config.functionManifestPath, savedFunctionManifest);
await fs.symlink(savedFunctionManifest, config.functionManifestPath);
await assert.rejects(() => verifyExactStagingArtifact(config),
  /CNYOS_EXACT_STAGING_FUNCTION_MANIFEST_INVALID/);
await fs.rm(config.functionManifestPath);
await fs.rename(savedFunctionManifest, config.functionManifestPath);

assert.equal(EXACT_STAGING_ENVIRONMENT, 'cnyos-staging-publish');
assert.equal(EXACT_STAGING_LIMITS.authUsers, 7);
assert.equal(EXACT_STAGING_LIMITS.syntheticCases, 1);
assert.equal(EXACT_STAGING_LIMITS.browserOpdWrites, 2);
assert.equal(EXACT_STAGING_LIMITS.totalMutations, 51);
assert.equal(EXACT_STAGING_LIMITS.requestRetries, 0);
assert.deepEqual(EXACT_STAGING_SECRET_NAMES, [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD'
]);
assert.equal(EXACT_STAGING_SYNTHETIC_HN_PATTERN, '^CHANANYASTG-[0-9]{8}$');

assert.match(workflow, /^on:\n  workflow_dispatch:\n/m);
assert.doesNotMatch(workflow, /^\s+(?:push|pull_request|workflow_run|schedule):/m);
assert.match(workflow, /^permissions:\n  actions: read\n  contents: read$/m);
for (const input of [
  'controller_commit', 'app_commit', 'app_tree', 'rollback_deploy_id', 'run_reference'
]) {
  assert.match(workflow, new RegExp(`^      ${input}:$`, 'm'));
}
for (const forbiddenInput of ['site_id', 'origin', 'project_ref', 'clinic_id']) {
  assert.doesNotMatch(workflow, new RegExp(`^      ${forbiddenInput}:$`, 'm'));
}
const workflowJobSlice = name => {
  const marker = `  ${name}:\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `workflow job ${name} is missing`);
  const following = workflow.slice(start + marker.length);
  const next = following.match(/^  [A-Za-z0-9_-]+:\n/m);
  return workflow.slice(start, next ? start + marker.length + next.index : workflow.length);
};
const buildJob = workflowJobSlice('build_candidate_artifact');
const protectedJob = workflowJobSlice('exact-staging-deploy-uat');
const sourceReadSecretName = 'CNYOS_APP_SOURCE_READ_TOKEN';
const secretReferences = value => [...value.matchAll(
  /\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}/g
)].map(match => match[1]);
const privateCheckoutStep = buildJob.match(
  /      - name: Checkout exact private application commit\n[\s\S]*?(?=\n      - name:)/
)?.[0];

assert.match(buildJob, /^  build_candidate_artifact:\n    needs: admit-controller-runtime$/m);
assert.match(buildJob, /repository: apisarit\/chananya-clinical-wellness-os/);
assert.match(buildJob, /ref: \$\{\{ inputs\.app_commit \}\}/);
assert.match(buildJob, /rev-parse 'HEAD\^\{tree\}'[\s\S]*CNYOS_EXPECTED_SOURCE_TREE/);
assert.doesNotMatch(buildJob, /^    environment:/m);
assert.ok(privateCheckoutStep, 'private application checkout step is missing');
assert.match(privateCheckoutStep,
  /uses: actions\/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5\.0\.1/);
assert.match(privateCheckoutStep, /repository: apisarit\/chananya-clinical-wellness-os/);
assert.match(privateCheckoutStep, /ref: \$\{\{ inputs\.app_commit \}\}/);
assert.match(privateCheckoutStep, /path: candidate-source/);
assert.match(privateCheckoutStep, /fetch-depth: 1/);
assert.deepEqual(secretReferences(buildJob), [sourceReadSecretName]);
assert.deepEqual(secretReferences(privateCheckoutStep), [sourceReadSecretName]);
assert.match(privateCheckoutStep,
  /token: \$\{\{ secrets\.CNYOS_APP_SOURCE_READ_TOKEN \}\}/);
assert.match(privateCheckoutStep, /persist-credentials: false/);
assert.doesNotMatch(buildJob.replace(privateCheckoutStep, ''),
  /CNYOS_APP_SOURCE_READ_TOKEN|\$\{\{\s*secrets\./);
for (const protectedName of EXACT_STAGING_SECRET_NAMES) {
  assert.doesNotMatch(buildJob, new RegExp(protectedName));
}
assert.equal((buildJob.match(/\$\{\{ vars\.CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY \}\}/g) || [])
  .length, 1);
assert.match(buildJob, /artifact_id: \$\{\{ steps\.upload_candidate\.outputs\.artifact-id \}\}/);
assert.match(buildJob,
  /artifact_digest: \$\{\{ steps\.upload_candidate\.outputs\.artifact-digest \}\}/);
assert.match(buildJob,
  /uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\.6\.2/);
assert.match(buildJob, /id: upload_candidate/);
assert.match(buildJob, /if-no-files-found: error/);
assert.match(buildJob, /include-hidden-files: false/);
assert.match(buildJob, /overwrite: false/);
assert.match(buildJob, /retention-days: 1/);

assert.match(protectedJob,
  /^    needs:\n      - admit-controller-runtime\n      - build_candidate_artifact$/m);
assert.match(protectedJob, /environment:\n\s+name: cnyos-staging-publish/);
assert.doesNotMatch(protectedJob, /repository: apisarit\/chananya-clinical-wellness-os/);
assert.doesNotMatch(protectedJob, /candidate-source/);
assert.doesNotMatch(protectedJob, /CNYOS_APP_SOURCE_READ_TOKEN/);
assert.equal((workflow.match(/CNYOS_APP_SOURCE_READ_TOKEN/g) || []).length, 1);
assert.doesNotMatch(protectedJob,
  /npm run check|npm run build:staging-artifact|materialize-staging-functions\.mjs/);
assert.equal((protectedJob.match(/uses: actions\/checkout@/g) || []).length, 1);
assert.match(protectedJob, /ref: \$\{\{ inputs\.controller_commit \}\}/);
assert.match(protectedJob,
  /uses: actions\/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\.3\.0/);
assert.match(protectedJob,
  /artifact-ids: \$\{\{ needs\.build_candidate_artifact\.outputs\.artifact_id \}\}/);
assert.match(protectedJob, /merge-multiple: true/);
assert.match(protectedJob, /CNYOS_CANDIDATE_ARTIFACT_ID" =~ \^\[0-9\]\+\$/);
assert.match(protectedJob,
  /CNYOS_CANDIDATE_ARTIFACT_DIGEST" =~ \^\[0-9a-f\]\{64\}\$/);
assert.doesNotMatch(protectedJob, /name: cnyos-exact-staging-candidate-/);
assert.equal((protectedJob.match(/\$\{\{ vars\.CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY \}\}/g) || [])
  .length, 1);
const downloadIndex = protectedJob.indexOf('uses: actions/download-artifact@');
const transportDigestIndex = protectedJob.indexOf(
  '- name: Fail closed on the immutable artifact transport digest');
const downloadedVerificationIndex = protectedJob.indexOf(
  '- name: Verify downloaded closed-world artifact before any publish or UAT secret');
const firstProtectedSecretIndex = protectedJob.indexOf('${{ secrets.');
assert.ok(downloadIndex >= 0 && downloadIndex < transportDigestIndex,
  'the immutable artifact must be downloaded before transport digest verification');
assert.ok(transportDigestIndex < downloadedVerificationIndex,
  'the transport digest must pass before closed-world content verification');
assert.ok(downloadedVerificationIndex < firstProtectedSecretIndex,
  'downloaded artifact verification must complete before the first protected secret');
const protectedPrefix = protectedJob.slice(0, firstProtectedSecretIndex);
assert.doesNotMatch(protectedPrefix,
  /candidate-source|npm run build|materialize-staging-functions|chananya-clinical-wellness-os/);
assert.match(protectedPrefix, /verifyExactStagingArtifact\(loadExactStagingConfig\(\)\)/);
assert.match(protectedPrefix,
  /actions\/artifacts\/\$\{CNYOS_CANDIDATE_ARTIFACT_ID:\?\}\/zip/);
assert.match(protectedPrefix,
  /test "\$observed_digest" = "\$CNYOS_CANDIDATE_ARTIFACT_DIGEST"/);
assert.doesNotMatch(workflow, /GITHUB_REF_PROTECTED/);
assert.match(workflow, /GITHUB_ACTOR" = "apisarit"/);
assert.match(workflow, /GITHUB_ACTOR_ID" = "216305243"/);
assert.match(workflow, /GITHUB_TRIGGERING_ACTOR" = "\$GITHUB_ACTOR"/);
assert.match(workflow, /GITHUB_RUN_ATTEMPT.*1/);
assert.match(workflow, /CNYOS_EXPECTED_CONTROLLER_COMMIT" = "\$GITHUB_SHA"/);
assert.match(workflow, /GITHUB_WORKFLOW_SHA" = "\$GITHUB_SHA"/);
assert.match(workflow, /git rev-parse HEAD\)" = "\$GITHUB_SHA"/);
for (const [name, job] of [
  ['build_candidate_artifact', buildJob], ['exact-staging-deploy-uat', protectedJob]
]) {
  const jobHeader = job.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?^    steps:\\n`, 'm'))?.[0];
  assert.ok(jobHeader, `${name} header is missing`);
  assert.doesNotMatch(jobHeader, /\$\{\{\s*runner\.temp\s*\}\}/,
    'runner context is unavailable in job-level env');
}
assert.match(workflow,
  /printf 'XDG_CONFIG_HOME=%s\/cnyos-netlify-config\\n' \\\n\s+"\$\{RUNNER_TEMP:\?\}" >> "\$\{GITHUB_ENV:\?\}"/);
assert.match(workflow,
  /printf 'XDG_CACHE_HOME=%s\/cnyos-netlify-cache\\n' \\\n\s+"\$\{RUNNER_TEMP:\?\}" >> "\$\{GITHUB_ENV:\?\}"/);
assert.match(workflow,
  /mkdir -m 700 \\\n\s+"\$\{RUNNER_TEMP:\?\}\/cnyos-netlify-config" \\\n\s+"\$\{RUNNER_TEMP:\?\}\/cnyos-netlify-cache"/);
assert.doesNotMatch(workflow, /npx\s|npm exec|--yes/);
assert.match(workflow, /exact-staging-publish\.mjs attempt/);
assert.match(workflow, /if: \$\{\{ always\(\) && steps\.publish_attempt\.outcome != 'skipped' \}\}/);
assert.match(workflow, /exact-staging-publish\.mjs reconcile/);
assert.match(workflow,
  /if: \$\{\{ steps\.reconcile_publish\.outputs\.publish_reconciled == 'true' \}\}/);
assert.match(workflow, /if: \$\{\{ always\(\) \}\}[\s\S]*exact-staging-publish\.mjs finalize/);
assert.match(publisher, /'deploy', '--prod', '--no-build', '--json'/);
assert.match(publisher, /kind: 'cnyos_exact_staging_publish_intent'/);
assert.match(publisher, /kind: 'cnyos_exact_staging_publish_reconciliation'/);
assert.match(publisher, /kind: 'cnyos_exact_staging_terminal_evidence'/);
assert.doesNotMatch(publisher, /\/restore\b|deploys\/[^'"`]+\/restore/);
assert.equal(publisherPackage.dependencies['netlify-cli'], '23.1.2');
assert.equal(publisherLock.packages[''].dependencies['netlify-cli'], '23.1.2');
assert.equal(publisherLock.packages['node_modules/netlify-cli'].version, '23.1.2');
assert.match(publisherLock.packages['node_modules/netlify-cli'].integrity, /^sha512-/);
assert.match(publisher, /'--site', EXACT_STAGING_TARGET\.netlifySiteId/);
assert.doesNotMatch(workflow, /--site\s+\$\{\{/);
assert.match(workflow, /hsmnjwxurlmsizndjlun/);
assert.match(workflow, /qptxnrldzzinlcabudjv/);
assert.match(workflow, /7da5e39e-580d-44f1-8623-605313e2fb2b/);
assert.match(workflow, /run-exact-staging-clinical-uat\.mjs/);
assert.match(protectedJob, /retention-days: 7/);
assert.doesNotMatch(workflow, /id-token:\s*write/);

for (const role of [
  'reception', 'source_practitioner', 'attending', 'pharmacy_reviewer',
  'pharmacy_dispenser', 'billing', 'admin'
]) assert.match(runner, new RegExp(`key: '${role}'`));
for (const operation of [
  'book_clinic_appointment', 'check_in_clinic_appointment', 'save_ttm_opd_history',
  'create_clinical_consult_request', 'transition_clinical_consult_request',
  'get_clinical_consult_request', 'create_ipd_admission_request',
  'transition_ipd_admission', 'get_ipd_admission', 'append_ipd_clinical_entry',
  'create_atomic_prescription_handoff',
  'transition_atomic_prescription_dispensing', 'issue_atomic_dispensing_invoice',
  'record_atomic_invoice_payment'
]) assert.match(runner, new RegExp(operation));
for (const expectedContract of [
  'expectDeniedWithoutMutation', 'CONSULT_RECEIVER_MUST_DIFFER_FROM_SENDER',
  'RECEPTION_ROLE_REQUIRED', 'medication_reconciliation', 'discharge_summary',
  'prepare_discharge', 'confirm_discharge', 'readAdminAuditHistory',
  'AUDIT_METADATA_KEYS', 'CNYOS_EXACT_STAGING_ADMIN_AUDIT_PHI_LEAK',
  'CNYOS_EXACT_STAGING_ADMIN_AUDIT_ACTOR_OR_TRANSITION_INVALID',
  'CNYOS_EXACT_STAGING_MUTATION_COUNT_INVALID'
]) assert.match(runner, new RegExp(expectedContract));
assert.match(runner, /consultReadback = role => readRpc\(as\(role\), 'get_clinical_consult_request'/);
assert.match(runner, /ipdReadback = role => readRpc\(as\(role\), 'get_ipd_admission'/);
assert.match(runner, /budget\.records\.length !== config\.limits\.totalMutations/);
assert.match(runner, /realPhiUsed: false/);
assert.match(runner, /SYNTHETIC-E2E/);
assert.match(runner, /EXACT_STAGING_SYNTHETIC_HN_PATTERN/);
assert.match(runner, /hnGeneratedByServer: true/);
assert.match(runner, /patient\.payment_right !== 'SYNTHETIC-E2E'/);
assert.match(runner, /patient\.email != null/);
assert.match(runner, /patient\.created_by/);
assert.match(runner, /browserOpdWrites/);
assert.match(runner, /stoppedWithoutRetry: true/);
assert.match(runner, /route\.fetch\(\{ timeout: config\.limits\.requestTimeoutMs \}\)/);
assert.ok(runner.indexOf('assertScopedOpdWriteBody(') < runner.indexOf('route.fetch({ timeout:'),
  'the scoped request body must be validated before route.fetch');
assert.ok(runner.indexOf('writeLedger.reserve(') < runner.indexOf('route.fetch({ timeout:'),
  'the shared write ledger must reserve capacity before route.fetch');
assert.match(runner, /createScopedOpdWriteLedger\(config\.limits\.browserOpdWrites\)/);
assert.match(runner, /writeLedger\.evidence\(evidence\.contexts\)/);
assert.match(runner, /OPD_WRITE_TRANSPORT_UNCERTAIN/);
assert.match(runner, /writeFresh0600\(path\.join\(config\.uploadDirectory, 'deploy-receipt\.json'/);
assert.match(runner, /kind: 'cnyos_exact_staging_deploy_receipt_error'/);
assert.match(runner, /rawSha256: receiptBytes \? sha256\(receiptBytes\) : null/);
assert.match(runner, /deployReceiptCaptured: receipt !== null/);

const binding = {
  schemaVersion: 1, kind: 'cnyos_exact_staging_candidate_binding', stagingOnly: true,
  productionAuthorized: false, source: { commit, tree },
  controller: {
    repository: 'apisarit/cnyos-staging-deployment-control',
    commit: controllerCommit,
    workflowPath: '.github/workflows/cnyos-exact-staging-deploy-uat.yml'
  },
  target: {
    siteId: EXACT_STAGING_TARGET.netlifySiteId, origin: EXACT_STAGING_TARGET.origin,
    deploymentId: EXACT_STAGING_TARGET.deploymentId,
    supabaseProjectRef: EXACT_STAGING_TARGET.supabaseProjectRef,
    clinicId: EXACT_STAGING_TARGET.clinicId
  }, rollbackBaselineDeployId: rollback,
  artifact: verified.artifact,
  functionEnvironment,
  limits: config.limits,
  preparedAt: '2026-10-13T00:00:30.000Z'
};
const baseline = {
  schemaVersion: 1, kind: 'cnyos_exact_staging_rollback_baseline', stagingOnly: true,
  siteId: EXACT_STAGING_TARGET.netlifySiteId, origin: EXACT_STAGING_TARGET.origin,
  deployId: rollback,
  exactDeployOrigin:
    `https://${rollback}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`,
  observedAt: '2026-10-13T00:00:00.000Z'
};
const intent = createExactStagingPublishIntent(config, binding, baseline, {
  now: '2026-10-13T00:01:00.000Z', workflowRunId: '12345'
});
assert.equal(intent.controller.commit, controllerCommit);
assert.equal(intent.automaticRollbackAuthorized, false);
assert.throws(() => createExactStagingPublishIntent(config, {
  ...binding,
  controller: { ...binding.controller, commit: '8'.repeat(40) }
}, baseline), /CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID/);
for (const artifactKey of [
  'deployManifestSha256', 'runtimeManifestSha256',
  'functionManifestSha256', 'functionTreeSha256'
]) {
  assert.throws(() => createExactStagingPublishIntent(config, {
    ...binding, artifact: { ...binding.artifact, [artifactKey]: 'not-a-sha256' }
  }, baseline), /CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID/);
}
const attempt = createExactStagingPublishAttempt(intent, {
  status: null, signal: 'SIGTERM', error: { code: 'ETIMEDOUT' }
}, Buffer.alloc(0), Buffer.from('redacted'), {
  startedAt: '2026-10-13T00:02:00.000Z', completedAt: '2026-10-13T00:04:30.000Z',
  receiptCaptured: false, outputSecretBoundaryViolated: false
});
assert.equal(attempt.cliOutcome, 'TIMEOUT');
assert.equal(attempt.status, 'UNKNOWN_PENDING_RECONCILIATION');
assert.deepEqual(classifyExactStagingPublishReconciliation({
  baselineDeployId: rollback,
  observation: { currentDeployId: 'd'.repeat(24), candidateMatches: true }
}), { status: 'PASS', result: 'APPLIED_VERIFIED' });
assert.deepEqual(classifyExactStagingPublishReconciliation({
  baselineDeployId: rollback,
  observation: { currentDeployId: rollback, candidateMatches: false }
}), { status: 'UNCERTAIN', result: 'ATTEMPT_DEPLOY_ID_UNKNOWN' });
assert.deepEqual(classifyExactStagingPublishReconciliation({
  baselineDeployId: rollback, receiptDeployId: 'd'.repeat(24), attemptedDeployState: 'error',
  observation: { currentDeployId: rollback, candidateMatches: false }
}), { status: 'FAIL', result: 'ATTEMPT_TERMINAL_FAILURE' });
assert.deepEqual(classifyExactStagingPublishReconciliation({
  baselineDeployId: rollback, receiptDeployId: 'd'.repeat(24), attemptedDeployState: 'ready',
  observation: { currentDeployId: rollback, candidateMatches: false }
}), { status: 'FAIL', result: 'ATTEMPT_READY_NOT_CANONICAL' });
assert.equal(deriveExactStagingTerminalStatus('PASS', 'PASS', true), 'PASS');
assert.equal(deriveExactStagingTerminalStatus('PASS', 'FAIL', true), 'FAIL');
assert.equal(deriveExactStagingTerminalStatus('UNCERTAIN', 'FAIL', false), 'UNCERTAIN');

const publishWork = path.join(root, 'publish-work');
const publishConfig = loadExactStagingConfig({
  CNYOS_EXPECTED_CONTROLLER_COMMIT: controllerCommit,
  CNYOS_EXPECTED_SOURCE_COMMIT: commit,
  CNYOS_EXPECTED_SOURCE_TREE: tree,
  CNYOS_EXPECTED_ROLLBACK_DEPLOY_ID: rollback,
  CNYOS_STAGING_RUN_REFERENCE: 'exact-staging-publish-contract-20261013',
  CNYOS_STAGING_ARTIFACT_DIRECTORY: artifact,
  CNYOS_EXACT_STAGING_WORK_DIRECTORY: publishWork
});
await fs.mkdir(publishConfig.uploadDirectory, { recursive: true, mode: 0o700 });
await fs.mkdir(publishConfig.privateDirectory, { recursive: true, mode: 0o700 });
for (const [name, value] of [
  ['candidate-binding.json', binding], ['rollback-baseline.json', baseline]
]) {
  await fs.writeFile(path.join(publishConfig.uploadDirectory, name),
    `${JSON.stringify(value)}\n`, { mode: 0o600 });
}
const githubOutput = path.join(root, 'github-output');
const token = 'netlify-token-not-a-secret-fixture';
const attemptEvidence = await executeExactStagingPublishAttempt(publishConfig, token, {
  env: {
    GITHUB_WORKSPACE: root, GITHUB_RUN_ID: '12345', PATH: '/usr/bin', HOME: root,
    XDG_CONFIG_HOME: path.join(root, 'xdg-config'), XDG_CACHE_HOME: path.join(root, 'xdg-cache')
  },
  cliPath: '/locked/netlify', candidateDirectory: root,
  now: (() => {
    const values = ['2026-10-13T00:10:00.000Z', '2026-10-13T00:10:01.000Z',
      '2026-10-13T00:10:02.000Z'];
    return () => values.shift();
  })(),
  spawnSyncImpl: (executable, args, options) => {
    assert.equal(executable, '/locked/netlify');
    assert.equal(args[0], 'deploy');
    assert.equal(options.env.NETLIFY_AUTH_TOKEN, token);
    assert.equal(existsSync(path.join(publishConfig.uploadDirectory, 'publish-intent.json')), true,
      'intent must be durable before invoking the publisher');
    return { status: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from('redacted') };
  }
});
assert.equal(attemptEvidence.cliOutcome, 'EXIT_NONZERO');
const evidencePath = name => path.join(publishConfig.uploadDirectory, name);
const overwriteEvidence = async (name, value) => {
  await fs.writeFile(evidencePath(name), `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await fs.chmod(evidencePath(name), 0o600);
};
const readEvidence = async name => JSON.parse(await fs.readFile(evidencePath(name), 'utf8'));
const persistedIntent = await readEvidence('publish-intent.json');
const persistedAttempt = await readEvidence('publish-attempt.json');
const expectPreObservationRejection = async expected => {
  await assert.rejects(() => reconcileExactStagingPublish(publishConfig, token, {
    attempts: 1, delayMs: 0,
    fetchImpl: async () => { throw new Error('observation must not run'); }
  }), expected);
};

await overwriteEvidence('candidate-binding.json', {
  ...binding,
  artifact: { ...binding.artifact, runtimeManifestSha256: '0'.repeat(64) }
});
await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_CHAIN_INVALID/);
await overwriteEvidence('candidate-binding.json', binding);

for (const mutate of [
  value => ({ ...value, artifact: { ...value.artifact,
    source: { ...value.artifact.source, commit: '8'.repeat(40) } } }),
  value => ({ ...value, artifact: { ...value.artifact, runtimeFileCount: 0 } }),
  value => ({ ...value, functionEnvironment: { ...value.functionEnvironment,
    exactValuesSha256: '0'.repeat(64) } }),
  value => ({ ...value, limits: { ...value.limits, authUsers: 6 } })
]) {
  await overwriteEvidence('candidate-binding.json', mutate(structuredClone(binding)));
  await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID/);
  await overwriteEvidence('candidate-binding.json', binding);
}

await overwriteEvidence('rollback-baseline.json', {
  ...baseline, deployId: 'e'.repeat(24),
  exactDeployOrigin:
    `https://${'e'.repeat(24)}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app`
});
await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID/);
await overwriteEvidence('rollback-baseline.json', baseline);

await overwriteEvidence('rollback-baseline.json', {
  ...baseline, observedAt: 'not-an-iso-timestamp'
});
await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_BINDING_INVALID/);
await overwriteEvidence('rollback-baseline.json', baseline);

const tamperedIntent = {
  ...persistedIntent,
  artifact: { ...persistedIntent.artifact, runtimeManifestSha256: '0'.repeat(64) }
};
await overwriteEvidence('publish-intent.json', tamperedIntent);
await overwriteEvidence('publish-attempt.json', {
  ...persistedAttempt,
  intentSha256: sha256(Buffer.from(JSON.stringify(tamperedIntent)))
});
await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_CHAIN_INVALID/);
await overwriteEvidence('publish-intent.json', persistedIntent);
await overwriteEvidence('publish-attempt.json', persistedAttempt);

const expectCoordinatedIntentRejection = async mutate => {
  const changedIntent = mutate(structuredClone(persistedIntent));
  await overwriteEvidence('publish-intent.json', changedIntent);
  await overwriteEvidence('publish-attempt.json', {
    ...persistedAttempt,
    intentSha256: sha256(Buffer.from(JSON.stringify(changedIntent)))
  });
  await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_CHAIN_INVALID/);
  await overwriteEvidence('publish-intent.json', persistedIntent);
  await overwriteEvidence('publish-attempt.json', persistedAttempt);
};
for (const mutate of [
  value => ({ ...value, automaticRollbackAttempted: true }),
  value => ({ ...value, operation: { ...value.operation, cliTimeoutSeconds: 121 } }),
  value => ({ ...value, run: { ...value.run, workflowRunId: 'fabricated' } })
]) await expectCoordinatedIntentRejection(mutate);

for (const mutate of [
  value => ({ ...value, outputSecretBoundaryViolated: true }),
  value => ({ ...value, cliOutcome: 'EXIT_ZERO', exitCode: 1 }),
  value => ({ ...value, stdoutByteLength: 1, stdoutSha256: null }),
  value => ({ ...value, retryCount: 1 }),
  value => ({ ...value, completedAt: '2026-10-13T00:09:59.000Z' })
]) {
  await overwriteEvidence('publish-attempt.json', mutate(structuredClone(persistedAttempt)));
  await expectPreObservationRejection(/CNYOS_EXACT_STAGING_PUBLISH_CHAIN_INVALID/);
  await overwriteEvidence('publish-attempt.json', persistedAttempt);
}

const candidateDeployId = 'd'.repeat(24);
const runtimeManifestBytes = await fs.readFile(path.join(dist, 'runtime-publish-manifest.json'));
const response = value => new Response(typeof value === 'string' || Buffer.isBuffer(value)
  ? value : JSON.stringify(value), { status: 200 });
const reconciled = await reconcileExactStagingPublish(publishConfig, token, {
  env: { GITHUB_OUTPUT: githubOutput }, attempts: 1, delayMs: 0,
  now: () => '2026-10-13T00:11:00.000Z',
  fetchImpl: async urlValue => {
    const url = String(urlValue);
    if (url === `https://api.netlify.com/api/v1/sites/${EXACT_STAGING_TARGET.netlifySiteId}`) {
      return response({
        id: EXACT_STAGING_TARGET.netlifySiteId, name: EXACT_STAGING_TARGET.netlifySiteName,
        ssl_url: EXACT_STAGING_TARGET.origin, published_deploy: { id: candidateDeployId }
      });
    }
    if (url === `https://api.netlify.com/api/v1/deploys/${candidateDeployId}`) {
      return response({ id: candidateDeployId, site_id: EXACT_STAGING_TARGET.netlifySiteId,
        state: 'ready' });
    }
    if (url.endsWith('/deploy-manifest.json')) return response(deployManifest);
    if (url.endsWith('/runtime-publish-manifest.json')) return response(runtimeManifestBytes);
    throw new Error(`unexpected fetch ${url}`);
  }
});
assert.equal(reconciled.status, 'PASS');
assert.equal(reconciled.result, 'APPLIED_VERIFIED');
assert.equal(reconciled.cliOutcome, 'EXIT_NONZERO');
assert.equal(existsSync(path.join(publishConfig.privateDirectory,
  'netlify-deploy-receipt.json')), true);
assert.match(await fs.readFile(githubOutput, 'utf8'), /publish_reconciled=true/);
const normalizedReceipt = JSON.parse(await fs.readFile(path.join(publishConfig.privateDirectory,
  'netlify-deploy-receipt.json'), 'utf8'));
await overwriteEvidence('deploy-receipt.json', normalizedReceipt);
const roleKeys = [
  'reception', 'source_practitioner', 'attending', 'pharmacy_reviewer',
  'pharmacy_dispenser', 'billing', 'admin'
];
const roleTuples = {
  reception: ['reception', 'staff', 'reception'],
  source_practitioner: ['practitioner', 'staff', 'practitioner'],
  attending: ['doctor', 'staff', 'doctor'],
  pharmacy_reviewer: ['pharmacy', 'staff', 'pharmacy'],
  pharmacy_dispenser: ['pharmacy', 'staff', 'pharmacy'],
  billing: ['billing', 'staff', 'billing'],
  admin: ['viewer', 'admin', 'admin']
};
const accounts = Object.fromEntries(roleKeys.map((key, index) => [key, {
  userId: `${String(index + 1).repeat(8)}-${String(index + 1).repeat(4)}-4${String(index + 1).repeat(3)}-a${String(index + 1).repeat(3)}-${String(index + 1).repeat(12)}`,
  emailSha256: String(index + 1).repeat(64),
  profileRole: roleTuples[key][0], systemRole: roleTuples[key][1],
  clinicRole: roleTuples[key][2], syntheticMarkerVerified: true,
  authenticatedSessionVerified: true
}]));
const actorIds = Object.fromEntries(roleKeys.map(key => [key, accounts[key].userId]));
const syntheticPatient = {
  id: '88888888-8888-4888-a888-888888888888',
  hn: 'CHANANYASTG-00000001', syntheticRunSuffix: publishConfig.runId.slice(-8),
  hnGeneratedByServer: true, clinicId: EXACT_STAGING_TARGET.clinicId,
  paymentRight: 'SYNTHETIC-E2E', realIdentifiersAbsent: true
};
const fixtureEvidence = {
  schemaVersion: 1, kind: 'cnyos_exact_staging_synthetic_fixture', status: 'PASS',
  syntheticOnly: true, realPhiUsed: false, controller: binding.controller,
  source: { commit, tree }, deployId: candidateDeployId, runId: publishConfig.runId,
  accounts, distinctAccountCount: roleKeys.length, patient: syntheticPatient,
  limits: publishConfig.limits
};
const mutationRecords = [];
const addMutation = (name, authority, resource, status = 200) => {
  mutationRecords.push({
    ordinal: mutationRecords.length + 1, name, authority, resource,
    dispatched: true, status, uncertain: false
  });
};
for (const _role of roleKeys) {
  addMutation('create_auth_user', 'service_role', '/auth/v1/admin/users');
  addMutation('upsert_profile', 'service_role', '/rest/v1/profiles');
  addMutation('insert_clinic_membership', 'service_role',
    '/rest/v1/clinic_memberships', 201);
}
addMutation('upsert_product_master', 'pharmacy_reviewer',
  '/rest/v1/rpc/upsert_product_master');
addMutation('set_clinic_product_price', 'billing', '/rest/v1/rpc/set_clinic_product_price');
addMutation('insert_inventory_lot', 'service_role', '/rest/v1/inventory_lots', 201);
addMutation('upsert_patient_registration', 'reception',
  '/rest/v1/rpc/upsert_patient_registration');
addMutation('create_practitioner_schedule', 'reception',
  '/rest/v1/rpc/create_practitioner_schedule');
addMutation('book_clinic_appointment', 'reception', '/rest/v1/rpc/book_clinic_appointment');
addMutation('check_in_clinic_appointment', 'reception',
  '/rest/v1/rpc/check_in_clinic_appointment');
addMutation('set_clinic_appointment_status', 'source_practitioner',
  '/rest/v1/rpc/set_clinic_appointment_status');
addMutation('save_ttm_opd_history', 'source_practitioner',
  '/rest/v1/rpc/save_ttm_opd_history');
addMutation('save_ttm_opd_history', 'source_practitioner',
  '/rest/v1/rpc/save_ttm_opd_history');
addMutation('create_clinical_consult_request', 'source_practitioner',
  '/rest/v1/rpc/create_clinical_consult_request');
addMutation('transition_clinical_consult_request', 'source_practitioner',
  '/rest/v1/rpc/transition_clinical_consult_request', 400);
for (let index = 0; index < 3; index += 1) {
  addMutation('transition_clinical_consult_request', 'attending',
    '/rest/v1/rpc/transition_clinical_consult_request');
}
addMutation('create_ipd_admission_request', 'source_practitioner',
  '/rest/v1/rpc/create_ipd_admission_request');
addMutation('transition_ipd_admission', 'source_practitioner',
  '/rest/v1/rpc/transition_ipd_admission', 400);
addMutation('transition_ipd_admission', 'reception', '/rest/v1/rpc/transition_ipd_admission');
addMutation('transition_ipd_admission', 'attending', '/rest/v1/rpc/transition_ipd_admission');
for (let index = 0; index < 3; index += 1) {
  addMutation('append_ipd_clinical_entry', 'attending',
    '/rest/v1/rpc/append_ipd_clinical_entry');
}
addMutation('transition_ipd_admission', 'attending', '/rest/v1/rpc/transition_ipd_admission');
addMutation('transition_ipd_admission', 'reception', '/rest/v1/rpc/transition_ipd_admission');
addMutation('create_atomic_prescription_handoff', 'source_practitioner',
  '/rest/v1/rpc/create_atomic_prescription_handoff');
addMutation('transition_atomic_prescription_dispensing', 'pharmacy_reviewer',
  '/rest/v1/rpc/transition_atomic_prescription_dispensing');
addMutation('transition_atomic_prescription_dispensing', 'pharmacy_dispenser',
  '/rest/v1/rpc/transition_atomic_prescription_dispensing');
addMutation('transition_atomic_prescription_dispensing', 'pharmacy_dispenser',
  '/rest/v1/rpc/transition_atomic_prescription_dispensing');
addMutation('issue_atomic_dispensing_invoice', 'billing',
  '/rest/v1/rpc/issue_atomic_dispensing_invoice');
addMutation('record_atomic_invoice_payment', 'billing',
  '/rest/v1/rpc/record_atomic_invoice_payment');
assert.equal(mutationRecords.length, publishConfig.limits.totalMutations);
const ipdEntryIds = [101, 102, 103, 104, 105];
const ipdEventIds = [201, 202, 203, 204, 205, 206, 207, 208];
const uatEvidence = {
  schemaVersion: 1, kind: 'cnyos_exact_staging_role_separated_uat', status: 'PASS',
  stagingOnly: true, productionAuthorized: false, controller: binding.controller,
  source: { commit, tree }, deployment: normalizedReceipt,
  target: {
    origin: EXACT_STAGING_TARGET.origin, siteId: EXACT_STAGING_TARGET.netlifySiteId,
    supabaseProjectRef: EXACT_STAGING_TARGET.supabaseProjectRef,
    clinicId: EXACT_STAGING_TARGET.clinicId
  },
  journey: {
    syntheticOnly: true, realPhiUsed: false, runId: publishConfig.runId,
    actorIds, patient: syntheticPatient,
    opdBrowserProof: {
      contexts: 3, saveReloadAmend: true, writes: publishConfig.limits.browserOpdWrites,
      writeLedger: {
        limit: publishConfig.limits.browserOpdWrites,
        dispatched: publishConfig.limits.browserOpdWrites, contextCount: 3,
        perContext: [
          { contextOrdinal: 1, writes: 1 },
          { contextOrdinal: 2, writes: 1 },
          { contextOrdinal: 3, writes: 0 }
        ],
        records: [
          { ordinal: 1, contextOrdinal: 1, rpc: 'save_ttm_opd_history',
            reservedBeforeFetch: true },
          { ordinal: 2, contextOrdinal: 2, rpc: 'save_ttm_opd_history',
            reservedBeforeFetch: true }
        ]
      }
    },
    consult: {
      id: '99999999-9999-4999-a999-999999999999',
      status: 'completed',
      version: 4,
      senderActorId: actorIds.source_practitioner,
      receiverActorId: actorIds.attending,
      wrongRole: {
        status: 'DENIED', expectedError: 'CONSULT_RECEIVER_MUST_DIFFER_FROM_SENDER',
        noMutationReadbackVerified: true
      },
      participantDetailReadbackVerified: true,
      eventTimelineReadbackVerified: true,
      eventTypes: ['requested', 'acknowledged', 'accepted', 'completed'],
      eventDetails: [
        { eventType: 'requested', fromStatus: null, toStatus: 'requested',
          resultingVersion: 1, actorId: actorIds.source_practitioner },
        { eventType: 'acknowledged', fromStatus: 'requested', toStatus: 'acknowledged',
          resultingVersion: 2, actorId: actorIds.attending },
        { eventType: 'accepted', fromStatus: 'acknowledged', toStatus: 'accepted',
          resultingVersion: 3, actorId: actorIds.attending },
        { eventType: 'completed', fromStatus: 'accepted', toStatus: 'completed',
          resultingVersion: 4, actorId: actorIds.attending }
      ]
    },
    admission: {
      id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
      status: 'discharged',
      version: 8,
      sourceActorId: actorIds.source_practitioner,
      attendingActorId: actorIds.attending,
      placementAndDischargeActorId: actorIds.reception,
      wrongRole: {
        status: 'DENIED', expectedError: 'RECEPTION_ROLE_REQUIRED',
        noMutationReadbackVerified: true
      },
      timelineReadbackVerified: true,
      sourceAdmissionRequestOnlyVerified: true,
      receptionClinicalEntriesAndActorIdsRedacted: true,
      entryTypes: [
        'admission_request', 'admission_note', 'progress_note',
        'medication_reconciliation', 'discharge_summary'
      ],
      eventTypes: [
        'requested', 'bed_assigned', 'admitted', 'entry_appended', 'entry_appended',
        'entry_appended', 'discharge_ready', 'discharged'
      ],
      entryDetails: [
        { entryId: ipdEntryIds[0], entryType: 'admission_request',
          authorId: actorIds.source_practitioner, admissionVersion: 1 },
        { entryId: ipdEntryIds[1], entryType: 'admission_note',
          authorId: actorIds.attending, admissionVersion: 3 },
        { entryId: ipdEntryIds[2], entryType: 'progress_note',
          authorId: actorIds.attending, admissionVersion: 4 },
        { entryId: ipdEntryIds[3], entryType: 'medication_reconciliation',
          authorId: actorIds.attending, admissionVersion: 5 },
        { entryId: ipdEntryIds[4], entryType: 'discharge_summary',
          authorId: actorIds.attending, admissionVersion: 6 }
      ],
      eventDetails: [
        { eventId: ipdEventIds[0], eventType: 'requested', fromStatus: null,
          toStatus: 'requested', resultingVersion: 1,
          actorId: actorIds.source_practitioner, clinicalEntryId: ipdEntryIds[0] },
        { eventId: ipdEventIds[1], eventType: 'bed_assigned', fromStatus: 'requested',
          toStatus: 'bed_assigned', resultingVersion: 2,
          actorId: actorIds.reception, clinicalEntryId: null },
        { eventId: ipdEventIds[2], eventType: 'admitted', fromStatus: 'bed_assigned',
          toStatus: 'admitted', resultingVersion: 3,
          actorId: actorIds.attending, clinicalEntryId: ipdEntryIds[1] },
        { eventId: ipdEventIds[3], eventType: 'entry_appended', fromStatus: 'admitted',
          toStatus: 'admitted', resultingVersion: 4,
          actorId: actorIds.attending, clinicalEntryId: ipdEntryIds[2] },
        { eventId: ipdEventIds[4], eventType: 'entry_appended', fromStatus: 'admitted',
          toStatus: 'admitted', resultingVersion: 5,
          actorId: actorIds.attending, clinicalEntryId: ipdEntryIds[3] },
        { eventId: ipdEventIds[5], eventType: 'entry_appended', fromStatus: 'admitted',
          toStatus: 'admitted', resultingVersion: 6,
          actorId: actorIds.attending, clinicalEntryId: ipdEntryIds[4] },
        { eventId: ipdEventIds[6], eventType: 'discharge_ready', fromStatus: 'admitted',
          toStatus: 'discharge_ready', resultingVersion: 7,
          actorId: actorIds.attending, clinicalEntryId: null },
        { eventId: ipdEventIds[7], eventType: 'discharged', fromStatus: 'discharge_ready',
          toStatus: 'discharged', resultingVersion: 8,
          actorId: actorIds.reception, clinicalEntryId: null }
      ]
    },
    pharmacy: {
      separated: true, reviewerActorId: actorIds.pharmacy_reviewer,
      dispenserActorId: actorIds.pharmacy_dispenser
    },
    billing: { grandTotal: 800, invoiceStatus: 'paid', actorId: actorIds.billing },
    admin: {
      actorId: actorIds.admin, separatelyAuthenticated: true,
      auditHistoryReadbackVerified: true, auditPhiRedacted: true,
      auditClinicalPayloadRedacted: true,
      auditActorAndTransitionReadbackVerified: true,
      auditRowCount: 12,
      auditActionCounts: {
        create_clinical_consult_request: 1,
        transition_clinical_consult_request: 3,
        create_ipd_admission_request: 1,
        transition_ipd_admission: 4,
        append_ipd_clinical_entry: 3
      }
    }
  },
  mutationBudget: {
    limit: publishConfig.limits.totalMutations,
    dispatched: publishConfig.limits.totalMutations,
    writeRetries: 0,
    records: mutationRecords
  },
  startedAt: '2026-10-13T00:11:01.000Z',
  completedAt: '2026-10-13T00:11:30.000Z'
};
await overwriteEvidence('fixture-evidence.json', fixtureEvidence);
await overwriteEvidence('uat-evidence.json', uatEvidence);
const manifestedFiles = [
  'candidate-binding.json', 'rollback-baseline.json', 'publish-intent.json',
  'publish-attempt.json', 'publish-reconciliation.json', 'deploy-receipt.json',
  'fixture-evidence.json', 'uat-evidence.json'
];
const writeEvidenceManifest = async () => {
  const entries = [];
  for (const name of manifestedFiles) {
    const bytes = await fs.readFile(evidencePath(name));
    entries.push({ name, size: bytes.length, sha256: sha256(bytes) });
  }
  await overwriteEvidence('evidence-manifest.json', {
    schemaVersion: 1, kind: 'cnyos_exact_staging_evidence_manifest', status: 'PASS',
    stagingOnly: true, productionAuthorized: false, controller: binding.controller,
    source: { commit, tree }, deployId: candidateDeployId, rollbackDeployId: rollback,
    evidence: entries
  });
};
await writeEvidenceManifest();

const terminal = await finalizeExactStagingEvidence(publishConfig, {
  now: () => '2026-10-13T00:12:00.000Z'
});
assert.equal(terminal.status, 'PASS');
assert.equal(terminal.evidenceSetValid, true);
assert.equal(terminal.controller.commit, controllerCommit);
await fs.rm(evidencePath('terminal-evidence.json'));

const validEvidence = new Map();
for (const name of [...manifestedFiles, 'evidence-manifest.json']) {
  validEvidence.set(name, await readEvidence(name));
}
const expectFinalizationTamperRejected = async (name, mutate, expected, {
  rebuildManifest = true
} = {}) => {
  const original = validEvidence.get(name);
  await overwriteEvidence(name, mutate(structuredClone(original)));
  if (rebuildManifest && name !== 'evidence-manifest.json') await writeEvidenceManifest();
  await assert.rejects(() => finalizeExactStagingEvidence(publishConfig), expected);
  await overwriteEvidence(name, original);
  await writeEvidenceManifest();
};

for (const mutate of [
  value => ({ ...value, target: { ...value.target, origin: 'https://cnyos.cloud' } }),
  value => ({ ...value, result: 'FABRICATED_PASS' }),
  value => ({ ...value, status: 'FABRICATED' }),
  value => ({ ...value, normalizedDeployId: rollback }),
  value => ({ ...value, cliOutcome: 'EXIT_ZERO' }),
  value => ({ ...value, reconciledAt: 'not-an-iso-timestamp' })
]) {
  await expectFinalizationTamperRejected('publish-reconciliation.json', mutate,
    /CNYOS_EXACT_STAGING_RECONCILIATION_EVIDENCE_INVALID/);
}

for (const mutate of [
  value => ({ ...value, kind: 'fabricated_uat' }),
  value => ({ ...value, source: { ...value.source, commit: '8'.repeat(40) } }),
  value => ({ ...value, deployment: { ...value.deployment, deployId: 'e'.repeat(24),
    exactDeployOrigin:
      `https://${'e'.repeat(24)}--${EXACT_STAGING_TARGET.netlifySiteName}.netlify.app` } }),
  value => ({ ...value, target: { ...value.target, siteId: '0'.repeat(36) } }),
  value => ({ ...value, controller: { ...value.controller, commit: '8'.repeat(40) } }),
  value => ({ ...value, journey: { ...value.journey, runId: 'SYNTH-FABRICATED' } }),
  value => ({ ...value, journey: { ...value.journey, patient: {
    ...value.journey.patient, hn: 'SYNTHETIC-E2E-TEST'
  } } }),
  value => ({ ...value, journey: { ...value.journey, patient: {
    ...value.journey.patient, hn: 'CHANANYASTG-000000001'
  } } }),
  value => ({ ...value, journey: { ...value.journey, patient: {
    ...value.journey.patient, syntheticRunSuffix: 'BADRUNID'
  } } }),
  value => ({ ...value, journey: { ...value.journey, patient: {
    ...value.journey.patient, hnGeneratedByServer: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, patient: {
    ...value.journey.patient, clinicId: '00000000-0000-4000-8000-000000000000'
  } } }),
  value => ({ ...value, journey: { ...value.journey, patient: {
    ...value.journey.patient, paymentRight: 'CASH'
  } } }),
  value => ({ ...value, journey: { ...value.journey, actorIds: {
    ...value.journey.actorIds,
    pharmacy_dispenser: value.journey.actorIds.pharmacy_reviewer
  } } }),
  value => ({ ...value, journey: { ...value.journey, opdBrowserProof: {
    ...value.journey.opdBrowserProof, saveReloadAmend: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, consult: {
    ...value.journey.consult, senderActorId: value.journey.actorIds.attending
  } } }),
  value => ({ ...value, journey: { ...value.journey, consult: {
    ...value.journey.consult, id: 'not-a-uuid'
  } } }),
  value => ({ ...value, journey: { ...value.journey, consult: {
    ...value.journey.consult, version: 3
  } } }),
  value => ({ ...value, journey: { ...value.journey, consult: {
    ...value.journey.consult,
    wrongRole: { ...value.journey.consult.wrongRole, noMutationReadbackVerified: false }
  } } }),
  value => ({ ...value, journey: { ...value.journey, consult: {
    ...value.journey.consult,
    eventTypes: value.journey.consult.eventTypes.slice(0, -1)
  } } }),
  value => ({ ...value, journey: { ...value.journey, consult: {
    ...value.journey.consult,
    eventDetails: value.journey.consult.eventDetails.map((event, index) => index === 2
      ? { ...event, resultingVersion: 99 } : event)
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission, status: 'admitted'
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission, id: 'not-a-uuid'
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission, version: 7
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission,
    placementAndDischargeActorId: value.journey.actorIds.attending
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission,
    wrongRole: { ...value.journey.admission.wrongRole, expectedError: 'IPD_VERSION_STALE' }
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission,
    entryTypes: value.journey.admission.entryTypes.filter(type => type !== 'discharge_summary')
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission, receptionClinicalEntriesAndActorIdsRedacted: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission,
    entryDetails: value.journey.admission.entryDetails.map((entry, index) => index === 3
      ? { ...entry, authorId: value.journey.actorIds.source_practitioner } : entry)
  } } }),
  value => ({ ...value, journey: { ...value.journey, admission: {
    ...value.journey.admission,
    eventDetails: value.journey.admission.eventDetails.map((event, index) => index === 4
      ? { ...event, clinicalEntryId: value.journey.admission.entryDetails[4].entryId } : event)
  } } }),
  value => ({ ...value, journey: { ...value.journey, pharmacy: {
    ...value.journey.pharmacy, separated: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, billing: {
    ...value.journey.billing, invoiceStatus: 'open'
  } } }),
  value => ({ ...value, journey: { ...value.journey, admin: {
    ...value.journey.admin, separatelyAuthenticated: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, admin: {
    ...value.journey.admin, auditActorAndTransitionReadbackVerified: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, admin: {
    ...value.journey.admin, auditClinicalPayloadRedacted: false
  } } }),
  value => ({ ...value, journey: { ...value.journey, admin: {
    ...value.journey.admin,
    auditActionCounts: { ...value.journey.admin.auditActionCounts,
      transition_ipd_admission: 3 }
  } } }),
  value => ({ ...value, mutationBudget: {
    ...value.mutationBudget,
    dispatched: value.mutationBudget.dispatched - 1,
    records: value.mutationBudget.records.slice(0, -1)
  } }),
  value => ({ ...value, mutationBudget: {
    ...value.mutationBudget,
    records: value.mutationBudget.records.map((record, index) => index === 32
      ? { ...record, status: 200 } : record)
  } }),
  value => ({ ...value, mutationBudget: {
    ...value.mutationBudget,
    records: value.mutationBudget.records.map((record, index) => index === 37
      ? { ...record, uncertain: true } : record)
  } }),
  value => ({ ...value, mutationBudget: {
    ...value.mutationBudget,
    records: value.mutationBudget.records.map((record, index) => index === 45
      ? { ...record, authority: 'billing' } : record)
  } }),
  value => ({ ...value, mutationBudget: {
    ...value.mutationBudget,
    records: value.mutationBudget.records.map((record, index) => index === 50
      ? { ...record, resource: '/rest/v1/rpc/wrong' } : record)
  } }),
  value => ({ ...value, mutationBudget: {
    ...value.mutationBudget,
    records: value.mutationBudget.records.map((record, index) => index === 0
      ? { ...record, ordinal: 2 } : record)
  } })
]) {
  await expectFinalizationTamperRejected('uat-evidence.json', mutate,
    /CNYOS_EXACT_STAGING_(?:UAT_EVIDENCE|DEPLOY_RECEIPT)_INVALID/);
}

await expectFinalizationTamperRejected('fixture-evidence.json', value => ({
  ...value, patient: { ...value.patient, id: '77777777-7777-4777-a777-777777777777' }
}), /CNYOS_EXACT_STAGING_FIXTURE_EVIDENCE_INVALID/);
for (const mutatePatient of [
  patient => ({ ...patient, hn: 'CHANANYASTG-000000001' }),
  patient => ({ ...patient, syntheticRunSuffix: 'BADRUNID' }),
  patient => ({ ...patient, hnGeneratedByServer: false }),
  patient => ({ ...patient, clinicId: '00000000-0000-4000-8000-000000000000' }),
  patient => ({ ...patient, paymentRight: 'CASH' })
]) {
  await expectFinalizationTamperRejected('fixture-evidence.json', value => ({
    ...value, patient: mutatePatient(value.patient)
  }), /CNYOS_EXACT_STAGING_FIXTURE_EVIDENCE_INVALID/);
}
await expectFinalizationTamperRejected('fixture-evidence.json', value => ({
  ...value, accounts: { ...value.accounts, admin: {
    ...value.accounts.admin, clinicRole: 'viewer'
  } }
}), /CNYOS_EXACT_STAGING_FIXTURE_EVIDENCE_INVALID/);
await expectFinalizationTamperRejected('deploy-receipt.json', value => ({
  ...value, source: { ...value.source, tree: '8'.repeat(40) }
}), /CNYOS_EXACT_STAGING_DEPLOY_RECEIPT_INVALID/);
await expectFinalizationTamperRejected('publish-attempt.json', value => ({
  ...value, completedAt: '2099-01-01T00:00:00.000Z'
}), /CNYOS_EXACT_STAGING_EVIDENCE_MANIFEST_INVALID/, { rebuildManifest: false });
await expectFinalizationTamperRejected('evidence-manifest.json', value => ({
  ...value,
  evidence: value.evidence.map((entry, index) => index === 0
    ? { ...entry, sha256: '0'.repeat(64) } : entry)
}), /CNYOS_EXACT_STAGING_EVIDENCE_MANIFEST_INVALID/, { rebuildManifest: false });

const terminalAfterAdversarialChecks = await finalizeExactStagingEvidence(publishConfig, {
  now: () => '2026-10-13T00:13:00.000Z'
});
assert.equal(terminalAfterAdversarialChecks.status, 'PASS');
assert.equal(terminalAfterAdversarialChecks.evidenceSetValid, true);

process.stdout.write('Exact staging release contracts passed.\n');
