import assert from 'node:assert/strict';
import crypto from 'node:crypto';
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
  EXACT_STAGING_TARGET,
  EXACT_STAGING_WORKFLOW_PATH,
  ExactStagingReleaseError,
  assertSecretFreeEvidence,
  loadExactStagingConfig,
  parseNetlifyDeployReceipt,
  sha256,
  verifyExactStagingFunctionEnvironment,
  verifyExactStagingArtifact
} from '../scripts/exact-staging-release.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(packageRoot, '..', '..');
const workflow = await fs.readFile(path.join(repositoryRoot, EXACT_STAGING_WORKFLOW_PATH), 'utf8');
const publisherPackage = JSON.parse(await fs.readFile(path.join(repositoryRoot,
  'ops/cnyos-staging-publisher/package.json'), 'utf8'));
const publisherLock = JSON.parse(await fs.readFile(path.join(repositoryRoot,
  'ops/cnyos-staging-publisher/package-lock.json'), 'utf8'));
const runner = await fs.readFile(path.join(packageRoot,
  'scripts/run-exact-staging-clinical-uat.mjs'), 'utf8');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-exact-staging-contract-'));
const artifact = path.join(root, 'artifact');
const dist = path.join(artifact, 'dist');
const functions = path.join(artifact, 'functions');
const work = path.join(root, 'work');
await fs.mkdir(dist, { recursive: true });
await fs.mkdir(functions, { recursive: true });

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

assert.equal(EXACT_STAGING_ENVIRONMENT, 'cnyos-staging-publish');
assert.equal(EXACT_STAGING_LIMITS.authUsers, 7);
assert.equal(EXACT_STAGING_LIMITS.syntheticCases, 1);
assert.equal(EXACT_STAGING_LIMITS.browserOpdWrites, 2);
assert.equal(EXACT_STAGING_LIMITS.requestRetries, 0);
assert.deepEqual(EXACT_STAGING_SECRET_NAMES, [
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY',
  'CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD'
]);

assert.match(workflow, /^on:\n  workflow_dispatch:\n/m);
assert.doesNotMatch(workflow, /^\s+(?:push|pull_request|workflow_run|schedule):/m);
for (const input of ['app_commit', 'app_tree', 'rollback_deploy_id', 'run_reference']) {
  assert.match(workflow, new RegExp(`^      ${input}:$`, 'm'));
}
for (const forbiddenInput of ['site_id', 'origin', 'project_ref', 'clinic_id']) {
  assert.doesNotMatch(workflow, new RegExp(`^      ${forbiddenInput}:$`, 'm'));
}
assert.match(workflow, /repository: apisarit\/chananya-clinical-wellness-os/);
assert.match(workflow, /ref: \$\{\{ inputs\.app_commit \}\}/);
assert.match(workflow, /rev-parse 'HEAD\^\{tree\}'[\s\S]*CNYOS_EXPECTED_SOURCE_TREE/);
assert.match(workflow, /environment:\n\s+name: cnyos-staging-publish/);
assert.match(workflow, /GITHUB_REF_PROTECTED.*true/);
assert.match(workflow, /GITHUB_RUN_ATTEMPT.*1/);
assert.match(workflow, /XDG_CONFIG_HOME: \$\{\{ runner\.temp \}\}\/cnyos-netlify-config/);
assert.match(workflow, /XDG_CACHE_HOME: \$\{\{ runner\.temp \}\}\/cnyos-netlify-cache/);
assert.match(workflow, /mkdir -m 700 "\$XDG_CONFIG_HOME" "\$XDG_CACHE_HOME"/);
assert.doesNotMatch(workflow, /npx\s|npm exec|--yes/);
assert.match(workflow,
  /ops\/cnyos-staging-publisher\/node_modules\/\.bin\/netlify" deploy/);
assert.equal(publisherPackage.dependencies['netlify-cli'], '23.1.2');
assert.equal(publisherLock.packages[''].dependencies['netlify-cli'], '23.1.2');
assert.equal(publisherLock.packages['node_modules/netlify-cli'].version, '23.1.2');
assert.match(publisherLock.packages['node_modules/netlify-cli'].integrity, /^sha512-/);
assert.match(workflow, /--site 887e058b-6e13-461f-b3c7-ae096b7046fe/);
assert.doesNotMatch(workflow, /--site\s+\$\{\{/);
assert.match(workflow, /hsmnjwxurlmsizndjlun/);
assert.match(workflow, /qptxnrldzzinlcabudjv/);
assert.match(workflow, /7da5e39e-580d-44f1-8623-605313e2fb2b/);
assert.match(workflow, /run-exact-staging-clinical-uat\.mjs/);
assert.match(workflow, /retention-days: 7/);
assert.doesNotMatch(workflow, /id-token:\s*write/);

for (const role of [
  'reception', 'source_practitioner', 'attending', 'pharmacy_reviewer',
  'pharmacy_dispenser', 'billing', 'admin'
]) assert.match(runner, new RegExp(`key: '${role}'`));
for (const operation of [
  'book_clinic_appointment', 'check_in_clinic_appointment', 'save_ttm_opd_history',
  'create_clinical_consult_request', 'create_ipd_admission_request',
  'append_ipd_clinical_entry', 'create_atomic_prescription_handoff',
  'transition_atomic_prescription_dispensing', 'issue_atomic_dispensing_invoice',
  'record_atomic_invoice_payment'
]) assert.match(runner, new RegExp(operation));
assert.match(runner, /realPhiUsed: false/);
assert.match(runner, /SYNTHETIC-E2E/);
assert.match(runner, /browserOpdWrites/);
assert.match(runner, /stoppedWithoutRetry: true/);
assert.match(runner, /route\.fetch\(\{ timeout: config\.limits\.requestTimeoutMs \}\)/);
assert.match(runner, /OPD_WRITE_TRANSPORT_UNCERTAIN/);
assert.match(runner, /writeFresh0600\(path\.join\(config\.uploadDirectory, 'deploy-receipt\.json'/);
assert.match(runner, /kind: 'cnyos_exact_staging_deploy_receipt_error'/);
assert.match(runner, /rawSha256: receiptBytes \? sha256\(receiptBytes\) : null/);
assert.match(runner, /deployReceiptCaptured: receipt !== null/);

process.stdout.write('Exact staging release contracts passed.\n');
