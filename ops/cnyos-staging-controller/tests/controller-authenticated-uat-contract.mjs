import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import * as controllerAuthenticatedUat from '../scripts/controller-authenticated-uat.mjs';

const {
  CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES,
  CONTROLLER_AUTHENTICATED_UAT_LIVE_BLOCKER,
  CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS,
  CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE,
  runControllerAuthenticatedUat
} = controllerAuthenticatedUat;
import { POLICY } from '../scripts/policy.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptPath = path.join(packageRoot, 'scripts', 'controller-authenticated-uat.mjs');
const temporaryRoot = await fs.mkdtemp(
  path.join(await fs.realpath(os.tmpdir()), 'cnyos-controller-authenticated-uat-contract-')
);

const expectedRepository = POLICY.controller.repository;
const expectedRef = POLICY.controller.protectedRef;
const expectedWorkflow = POLICY.controller.releaseWorkflowPath;

function runtimeEnvironment() {
  return {
    GITHUB_REPOSITORY: expectedRepository,
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: expectedRepository,
    GITHUB_RUN_ID: '424242',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REF: expectedRef,
    CNYOS_CONTROLLER_PROTECTED_REF: expectedRef,
    GITHUB_SHA: 'a'.repeat(40),
    CNYOS_CONTROLLER_WORKFLOW_PATH: expectedWorkflow,
    GITHUB_WORKFLOW_REF: `${expectedRepository}/${expectedWorkflow}@${expectedRef}`,
    GITHUB_ACTOR: 'controller-reviewer',
    GITHUB_TRIGGERING_ACTOR: 'Controller-Reviewer'
  };
}

async function expectCallerRejected(...callerArguments) {
  await assert.rejects(
    runControllerAuthenticatedUat(...callerArguments),
    error => error?.message === 'CNYOS_CONTROLLER_AUTHENTICATED_UAT_OPTIONS_INVALID' &&
      error.message !== CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE
  );
}

async function absent(filename) {
  try {
    await fs.lstat(filename);
    return false;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
}

try {
  assert.deepEqual(Object.keys(controllerAuthenticatedUat).sort(), [
    'CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES',
    'CONTROLLER_AUTHENTICATED_UAT_LIVE_BLOCKER',
    'CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS',
    'CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE',
    'runControllerAuthenticatedUat'
  ]);
  assert.equal(CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE,
    'CNYOS_CONTROLLER_AUTHENTICATED_UAT_HARNESS_NOT_ACTIVATED');
  assert.equal(Object.isFrozen(CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS), true);
  assert.deepEqual(CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS, [
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
  assert.equal(new Set(CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS).size, 9);
  assert.throws(() => {
    CONTROLLER_AUTHENTICATED_UAT_MISSING_ACTIVATION_CONTROLS.push('unreviewed control');
  }, TypeError);
  assert.deepEqual(CONTROLLER_AUTHENTICATED_UAT_LIVE_BLOCKER, {
    state: 'blocked',
    workflowJob: 'run_promoted_uat',
    workflowTemplate:
      'ops/cnyos-staging-controller/workflow/cnyos-staging-controller.template.yml',
    finalizerConsumer:
      'ops/cnyos-staging-controller/scripts/finalize-evidence.mjs#validateAuthenticatedUatEvidence',
    failureCode: CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE
  });
  assert.equal(Object.isFrozen(CONTROLLER_AUTHENTICATED_UAT_LIVE_BLOCKER), true);

  assert.equal(Object.isFrozen(CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES), true);
  assert.deepEqual(CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES,
    [...CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES].sort());
  for (const name of [
    'CNYOS_STAGING_DATABASE_URL',
    'CNYOS_SUPABASE_ACCESS_TOKEN',
    'CNYOS_SUPABASE_DB_PASSWORD',
    'CNYOS_SUPABASE_DB_URL',
    'PGDATABASE',
    'PGHOST',
    'PGPASSWORD',
    'PGPORT',
    'PGUSER',
    'POSTGRES_PASSWORD',
    'SUPABASE_ACCESS_TOKEN',
    'SUPABASE_DB_PASSWORD',
    'SUPABASE_DB_URL',
    'SUPABASE_SERVICE_ROLE_KEY'
  ]) assert.ok(CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES.includes(name), name);
  assert.equal(CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES
    .includes('CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY'), false);
  assert.equal(CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_ENVIRONMENT_NAMES
    .includes('CNYOS_STAGING_TEST_PASSWORD'), false);

  const existingOutput = path.join(temporaryRoot, 'existing-uat.json');
  const absentOutput = path.join(temporaryRoot, 'absent-uat.json');
  await fs.writeFile(existingOutput, 'existing evidence must remain byte-exact\n', { mode: 0o600 });

  const injectedNames = [
    'env',
    'fetchImpl',
    'browserImpl',
    'cdpImpl',
    'writerImpl',
    'writeJsonExclusiveImpl',
    'readFileImpl',
    'fileInputs',
    'evidenceInputs',
    'outputPath'
  ];
  const injectedGetterReads = new Map(injectedNames.map(name => [name, 0]));
  const accessorOptions = {};
  for (const name of injectedNames) {
    Object.defineProperty(accessorOptions, name, {
      configurable: true,
      enumerable: true,
      get() {
        injectedGetterReads.set(name, injectedGetterReads.get(name) + 1);
        throw new Error(`caller getter must remain untouched: ${name}`);
      }
    });
  }
  await expectCallerRejected(accessorOptions);
  assert.deepEqual([...injectedGetterReads.values()], Array(injectedNames.length).fill(0));

  let inheritedGetterReads = 0;
  const inheritedRuntimePrototype = { ...runtimeEnvironment() };
  Object.defineProperty(inheritedRuntimePrototype, 'NETLIFY_AUTH_TOKEN', {
    configurable: true,
    enumerable: true,
    get() {
      inheritedGetterReads += 1;
      throw new Error('inherited credential must remain untouched');
    }
  });
  const inheritedRuntime = Object.create(inheritedRuntimePrototype);
  const inheritedOptionsPrototype = {};
  Object.defineProperty(inheritedOptionsPrototype, 'env', {
    configurable: true,
    enumerable: true,
    get() {
      inheritedGetterReads += 1;
      return inheritedRuntime;
    }
  });
  await expectCallerRejected(Object.create(inheritedOptionsPrototype));
  assert.equal(inheritedGetterReads, 0);

  const trapCounts = new Map();
  const proxyHandler = {};
  for (const trap of [
    'defineProperty',
    'deleteProperty',
    'get',
    'getOwnPropertyDescriptor',
    'getPrototypeOf',
    'has',
    'isExtensible',
    'ownKeys',
    'preventExtensions',
    'set',
    'setPrototypeOf'
  ]) {
    trapCounts.set(trap, 0);
    proxyHandler[trap] = () => {
      trapCounts.set(trap, trapCounts.get(trap) + 1);
      throw new Error(`caller Proxy trap must remain untouched: ${trap}`);
    };
  }
  const hiddenCredentialProxy = new Proxy({
    env: inheritedRuntime,
    NETLIFY_AUTH_TOKEN: 'hidden credential must never be inspected',
    CNYOS_CONTROLLER_UAT_EVIDENCE_PATH: absentOutput
  }, proxyHandler);
  await expectCallerRejected(hiddenCredentialProxy);
  assert.deepEqual([...trapCounts.values()], Array(trapCounts.size).fill(0));

  for (const argument of [undefined, null, false, 0, '', { env: runtimeEnvironment() }]) {
    await expectCallerRejected(argument);
  }
  await expectCallerRejected(hiddenCredentialProxy, accessorOptions);
  assert.deepEqual([...trapCounts.values()], Array(trapCounts.size).fill(0));
  assert.deepEqual([...injectedGetterReads.values()], Array(injectedNames.length).fill(0));

  assert.equal(await fs.readFile(existingOutput, 'utf8'),
    'existing evidence must remain byte-exact\n');
  assert.equal(await absent(absentOutput), true);

  const cliOutput = path.join(temporaryRoot, 'cli-existing-uat.json');
  await fs.writeFile(cliOutput, 'cli sentinel\n', { mode: 0o600 });
  const cliSecret = 'must-never-appear-service-secret';
  const cliPassword = 'must-never-appear-password';
  const cli = spawnSync(process.execPath, [scriptPath], {
    cwd: packageRoot,
    encoding: 'utf8',
    env: {
      ...runtimeEnvironment(),
      CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: cliSecret,
      CNYOS_STAGING_TEST_PASSWORD: cliPassword,
      CNYOS_CONTROLLER_UAT_EVIDENCE_PATH: cliOutput,
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin'
    },
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, '');
  assert.equal(cli.stderr, `${CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE}\n`);
  assert.doesNotMatch(cli.stderr, new RegExp(`${cliSecret}|${cliPassword}`));
  assert.equal(await fs.readFile(cliOutput, 'utf8'), 'cli sentinel\n');

  const invalidCli = spawnSync(process.execPath, [scriptPath], {
    cwd: packageRoot,
    encoding: 'utf8',
    env: {
      ...runtimeEnvironment(),
      GITHUB_TRIGGERING_ACTOR: 'other-reviewer',
      CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY: cliSecret,
      CNYOS_STAGING_TEST_PASSWORD: cliPassword,
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin'
    },
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  assert.equal(invalidCli.status, 1);
  assert.equal(invalidCli.stdout, '');
  assert.equal(invalidCli.stderr, 'CNYOS_CONTROLLER_ACTOR_MISMATCH\n');
  assert.doesNotMatch(invalidCli.stderr, new RegExp(`${cliSecret}|${cliPassword}`));

  const forbiddenCliSecret = 'forbidden-netlify-secret-must-never-appear';
  const forbiddenCli = spawnSync(process.execPath, [scriptPath], {
    cwd: packageRoot,
    encoding: 'utf8',
    env: {
      ...runtimeEnvironment(),
      NETLIFY_AUTH_TOKEN: forbiddenCliSecret,
      CNYOS_CONTROLLER_UAT_EVIDENCE_PATH: absentOutput,
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin'
    },
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  assert.equal(forbiddenCli.status, 1);
  assert.equal(forbiddenCli.stdout, '');
  assert.equal(forbiddenCli.stderr,
    'CNYOS_CONTROLLER_AUTHENTICATED_UAT_FORBIDDEN_CREDENTIAL_ENVIRONMENT\n');
  assert.doesNotMatch(forbiddenCli.stderr, new RegExp(forbiddenCliSecret));
  assert.equal(await absent(absentOutput), true);

  const scriptSource = await fs.readFile(scriptPath, 'utf8');
  assert.doesNotMatch(scriptSource, /node:(?:fs|child_process|http|https|net|tls)/);
  assert.match(scriptSource,
    /import \{ POLICY, assertControllerRuntime \} from '\.\/policy\.mjs';/);
  for (const removed of [
    '/rest/v1/',
    '/auth/v1/',
    'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
    'CNYOS_STAGING_TEST_PASSWORD',
    'CNYOS_CONTROLLER_UAT_EVIDENCE_PATH',
    'CNYOS_CONTROLLER_PROMOTION_EVIDENCE_PATH',
    'CNYOS_PRODUCER_BUNDLE_DIRECTORY',
    'controllerAuthenticatedUatRequest',
    'executeControllerOwnedAuthenticatedUat',
    'executeMobileChromiumRouteMatrix',
    'validateControllerAuthenticatedUatGateEvidence',
    'provisionSyntheticIdentities',
    'verifyAccessControl',
    'verifyMigrationHealth',
    'verifyJourney',
    'verifySyntheticJourneys',
    'verifySubscriptionRestoration',
    'buildAuditAndSegregation',
    'current_access_context',
    'department_can',
    'is_clinic_member',
    'admin_set_staff_membership_active',
    'set_clinic_subscription_state',
    'create_encounter_with_diagnosis',
    'create_prescription_handoff',
    'dispense_prescription_order',
    'record_invoice_payment',
    'chrome-remote-interface',
    'Network.enable',
    'Target.setAutoAttach',
    'Page.navigate',
    'writeJsonExclusive',
    'gateEvidence',
    'dispensingAtomicRollbackVerified',
    'subscriptionRestoration',
    "status: 'passed'",
    'fetchImpl',
    'browserImpl',
    'cdpImpl',
    'writerImpl',
    'readFileImpl',
    'environmentFromOptions',
    'ownDataValue'
  ]) assert.equal(scriptSource.includes(removed), false, removed);
  assert.match(scriptSource,
    /export async function runControllerAuthenticatedUat\(\.\.\.callerArguments\)/);
  assert.equal((scriptSource.match(/callerArguments/g) || []).length, 2,
    'entrypoint may only bind the rest array and inspect its length');
  assert.match(scriptSource,
    /callerArguments\.length !== 0[\s\S]*assertControllerAuthenticatedUatRuntime\(\);[\s\S]*fail\(CONTROLLER_AUTHENTICATED_UAT_NOT_ACTIVATED_CODE\)/);
  assert.match(scriptSource, /assertControllerRuntime\(process\.env\)/);
  assert.match(scriptSource, /workflow and finalizer intentionally remain blocked/i);
} finally {
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

process.stdout.write('CNYOS activation contract controller-authenticated-uat: passed\n');
