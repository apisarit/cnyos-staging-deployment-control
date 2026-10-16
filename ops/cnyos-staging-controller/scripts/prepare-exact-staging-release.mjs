import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import {
  captureRollbackBaseline,
  loadExactStagingConfig,
  verifyExactStagingFunctionEnvironment,
  verifyExactStagingArtifact,
  writeFresh0600
} from './exact-staging-release.mjs';

const config = loadExactStagingConfig();
const token = String(process.env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN || '').trim();
if (token.length < 20) throw new Error('CNYOS_EXACT_STAGING_NETLIFY_TOKEN_REQUIRED');
await fs.mkdir(config.workDirectory, { recursive: false, mode: 0o700 });
await fs.mkdir(config.privateDirectory, { mode: 0o700 });
await fs.mkdir(config.uploadDirectory, { mode: 0o700 });

const verified = await verifyExactStagingArtifact(config);
const functionEnvironment = verifyExactStagingFunctionEnvironment(config, token, {
  cliPath: path.resolve(process.cwd(), '..', 'cnyos-staging-publisher',
    'node_modules', '.bin', 'netlify')
});
const baseline = await captureRollbackBaseline(config, token);
const binding = {
  schemaVersion: 1,
  kind: 'cnyos_exact_staging_candidate_binding',
  stagingOnly: true,
  productionAuthorized: false,
  controller: {
    repository: 'apisarit/cnyos-staging-deployment-control',
    commit: config.controllerCommit,
    workflowPath: '.github/workflows/cnyos-exact-staging-deploy-uat.yml'
  },
  source: { commit: config.appCommit, tree: config.appTree },
  target: {
    siteId: config.target.netlifySiteId,
    origin: config.target.origin,
    deploymentId: config.target.deploymentId,
    supabaseProjectRef: config.target.supabaseProjectRef,
    clinicId: config.target.clinicId
  },
  artifact: verified.artifact,
  functionEnvironment,
  limits: config.limits,
  rollbackBaselineDeployId: baseline.deployId,
  preparedAt: new Date().toISOString()
};
const secrets = [token];
await writeFresh0600(path.join(config.uploadDirectory, 'candidate-binding.json'), binding, secrets);
await writeFresh0600(path.join(config.uploadDirectory, 'rollback-baseline.json'), baseline, secrets);
await writeFresh0600(path.join(config.privateDirectory, 'artifact-verification.json'), {
  ...binding,
  deployManifest: verified.deployManifest,
  runtimeManifest: verified.runtimeManifest,
  functionManifest: verified.functionManifest,
  databaseManifest: verified.databaseManifest,
  databaseReconciliationManifest: verified.reconciliationManifest
}, secrets);
