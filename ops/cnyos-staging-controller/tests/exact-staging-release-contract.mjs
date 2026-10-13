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
  kind: 'cnyos_exact_staging_candidate_binding', stagingOnly: true,
  productionAuthorized: false, source: { commit, tree },
  target: {
    siteId: EXACT_STAGING_TARGET.netlifySiteId, origin: EXACT_STAGING_TARGET.origin,
    supabaseProjectRef: EXACT_STAGING_TARGET.supabaseProjectRef
  }, rollbackBaselineDeployId: rollback,
  artifact: verified.artifact
};
const baseline = {
  kind: 'cnyos_exact_staging_rollback_baseline',
  siteId: EXACT_STAGING_TARGET.netlifySiteId, deployId: rollback
};
const intent = createExactStagingPublishIntent(config, binding, baseline, {
  now: '2026-10-13T00:01:00.000Z', workflowRunId: '12345'
});
assert.equal(intent.automaticRollbackAuthorized, false);
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

process.stdout.write('Exact staging release contracts passed.\n');
