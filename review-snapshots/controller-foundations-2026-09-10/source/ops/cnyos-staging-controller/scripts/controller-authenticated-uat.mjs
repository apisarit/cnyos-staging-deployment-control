import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { POLICY, assertControllerRuntime } from './policy.mjs';

export const CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE =
  'CNYOS_CONTROLLER_AUTHENTICATED_UAT_HARNESS_NOT_ACTIVATED';

export const CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS = Object.freeze([
  'exact Chananya ledger + independent Jitarsa evidence binding',
  'pre-provisioned isolated cross-tenant fixtures without broad service-role DML',
  'crash-consistent durable recovery/watchdog for every mutation',
  'ephemeral identities with session revocation/partial-provision recovery',
  'pre-dispatch default-deny browser interception across pages/workers/websockets with exact ' +
    'routes and bounded downloads',
  'real non-mocked 11-role/schema/RPC/CDP contract',
  'Production→Quality segregation/rework evidence',
  'failure screenshots',
  'atomic no-replace evidence publication'
]);

export const CONTROLLER_AUTHENTICATED_UAT_LIVE_BLOCKER = Object.freeze({
  state: 'blocked',
  workflowJob: 'run_promoted_uat',
  workflowTemplate:
    'ops/cnyos-staging-controller/workflow/cnyos-staging-controller.template.yml',
  finalizerConsumer:
    'ops/cnyos-staging-controller/scripts/finalize-evidence.mjs#validateAuthenticatedUatEvidence',
  failureCode: CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE
});

export const CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'CNYOS_SUPABASE_DB_PASSWORD',
  'CNYOS_SUPABASE_DB_URL',
  'DATABASE_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'PGDATABASE',
  'PGHOST',
  'PGPASSFILE',
  'PGPASSWORD',
  'PGPORT',
  'PGSERVICE',
  'PGSERVICEFILE',
  'PGUSER',
  'POSTGRES_PASSWORD',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_DB_PASSWORD',
  'SUPABASE_DB_URL',
  'SUPABASE_SERVICE_ROLE_KEY'
]);

const SAFE_FAILURE_CODES = new Set([
  CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE,
  'CNYOS_CONTROLLER_AUTHENTICATED_UAT_OPTIONS_INVALID',
  'CNYOS_CONTROLLER_AUTHENTICATED_UAT_ENVIRONMENT_INVALID',
  'CNYOS_CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_CREDENTIAL_ENVIRONMENT',
  'CNYOS_CONTROLLER_REPOSITORY_REQUIRED',
  'CNYOS_CONTROLLER_EXPECTED_REPOSITORY_REQUIRED',
  'CNYOS_CONTROLLER_REPOSITORY_MISMATCH',
  'CNYOS_CONTROLLER_RUN_ID_INVALID',
  'CNYOS_CONTROLLER_RERUN_REJECTED',
  'CNYOS_CONTROLLER_REF_NOT_PROTECTED',
  'CNYOS_CONTROLLER_PROTECTED_REF_REQUIRED',
  'CNYOS_CONTROLLER_REF_MISMATCH',
  'CNYOS_CONTROLLER_COMMIT_INVALID',
  'CNYOS_CONTROLLER_WORKFLOW_PATH_REQUIRED',
  'CNYOS_CONTROLLER_WORKFLOW_PATH_INVALID',
  'CNYOS_CONTROLLER_WORKFLOW_REF_REQUIRED',
  'CNYOS_CONTROLLER_WORKFLOW_REF_INVALID',
  'CNYOS_CONTROLLER_ACTOR_REQUIRED',
  'CNYOS_CONTROLLER_TRIGGERING_ACTOR_REQUIRED',
  'CNYOS_CONTROLLER_ACTOR_MISMATCH'
]);

function fail(code) {
  throw new Error(code);
}

function assertNoForbiddenCredentialNames() {
  for (const name of CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Reflect.has(process.env, name)) {
      fail('CNYOS_CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_CREDENTIAL_ENVIRONMENT');
    }
  }
}

function assertControllerAuthenticatedUatRuntime() {
  if (typeof process.env !== 'object' || process.env === null) {
    fail('CNYOS_CONTROLLER_AUTHENTICATED_UAT_ENVIRONMENT_INVALID');
  }
  assertNoForbiddenCredentialNames();
  const runtime = assertControllerRuntime(process.env);
  if (runtime.workflowPath !== POLICY.controller.releaseWorkflowPath) {
    fail('CNYOS_CONTROLLER_WORKFLOW_PATH_INVALID');
  }
  return runtime;
}

export async function runControllerAuthenticatedUat(...callerArguments) {
  // Caller-supplied objects are never inspected. This inert boundary accepts no dependency,
  // environment, evidence, network, browser, filesystem, or output injection surface.
  if (callerArguments.length !== 0) fail('CNYOS_CONTROLLER_AUTHENTICATED_UAT_OPTIONS_INVALID');
  assertControllerAuthenticatedUatRuntime();

  // The workflow and finalizer intentionally remain blocked until every exported
  // activation control has an independently reviewed implementation and evidence contract.
  fail(CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE);
}

function safeFailureCode(error) {
  const candidate = typeof error?.message === 'string' ? error.message : '';
  return SAFE_FAILURE_CODES.has(candidate) ? candidate :
    'CNYOS_CONTROLLER_AUTHENTICATED_UAT_FAILED';
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runControllerAuthenticatedUat().catch(error => {
    process.stderr.write(`${safeFailureCode(error)}\n`);
    process.exitCode = 1;
  });
}
