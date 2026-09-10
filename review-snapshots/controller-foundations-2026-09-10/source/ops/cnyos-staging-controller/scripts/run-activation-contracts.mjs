import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const FOUNDATION_SCRIPTS = Object.freeze([
  'scripts/materialize-function-recipe-input.mjs',
  'scripts/create-function-comparison-handoff.mjs',
  'scripts/controller-uat-access-observations.mjs',
  'scripts/controller-uat-browser-read-policy.mjs',
  'scripts/controller-uat-browser-transport.mjs',
  'scripts/controller-uat-evidence-publication.mjs',
  'scripts/create-producer-bundle.mjs',
  'scripts/finalize-evidence.mjs',
  'scripts/netlify-evidence.mjs',
  'scripts/policy.mjs',
  'scripts/run-activation-contracts.mjs',
  'scripts/validate-function-environment.mjs',
  'scripts/verify-authorization.mjs',
  'scripts/verify-producer-bundle.mjs',
  'scripts/verify-rollback-attestation-deposit.mjs'
]);

export const ACTIVATION_PAIRS = Object.freeze([
  Object.freeze({
    id: 'controller-function-bundle',
    scripts: Object.freeze(['scripts/controller-function-bundle.mjs']),
    test: 'tests/controller-function-bundle-contract.mjs'
  }),
  Object.freeze({
    id: 'controller-authenticated-uat',
    scripts: Object.freeze(['scripts/controller-authenticated-uat.mjs']),
    test: 'tests/controller-authenticated-uat-contract.mjs'
  }),
  Object.freeze({
    id: 'runtime-capability-boundary',
    scripts: Object.freeze(['scripts/verify-runtime-capability-boundary.mjs']),
    test: 'tests/runtime-capability-boundary-contract.mjs'
  }),
  Object.freeze({
    id: 'live-netlify-authority-boundary',
    scripts: Object.freeze(['scripts/verify-live-netlify-authority-boundary.mjs']),
    test: 'tests/live-netlify-authority-boundary-contract.mjs'
  }),
  Object.freeze({
    id: 'live-github-release-boundary',
    scripts: Object.freeze(['scripts/verify-live-github-release-boundary.mjs']),
    test: 'tests/live-github-release-boundary-contract.mjs'
  }),
  Object.freeze({
    id: 'authorization-foundation-security',
    scripts: Object.freeze([]),
    test: 'tests/authorization-foundation-security-contract.mjs'
  }),
  Object.freeze({
    id: 'external-broker-trust-boundaries',
    scripts: Object.freeze([
      'scripts/verify-netlify-exclusive-publisher.mjs',
      'scripts/release-netlify-exclusive-publisher.mjs',
      'scripts/reconcile-netlify-release-state.mjs',
      'scripts/verify-private-draft-lifecycle.mjs',
      'scripts/create-netlify-draft-with-durable-intent.mjs',
      'scripts/cleanup-netlify-draft.mjs',
      'scripts/rollback-readiness.mjs'
    ]),
    test: 'tests/external-broker-trust-boundaries-contract.mjs'
  }),
  Object.freeze({
    id: 'rollback-attestation-deposit',
    scripts: Object.freeze(['scripts/deposit-rollback-attestation.mjs']),
    test: 'tests/rollback-attestation-deposit-contract.mjs'
  }),
  Object.freeze({
    id: 'netlify-control-file-behavior',
    scripts: Object.freeze(['scripts/verify-netlify-control-file-behavior.mjs']),
    test: 'tests/netlify-control-file-behavior-contract.mjs'
  }),
  Object.freeze({
    id: 'netlify-exclusive-publisher',
    scripts: Object.freeze([
      'scripts/verify-netlify-exclusive-publisher.mjs',
      'scripts/release-netlify-exclusive-publisher.mjs'
    ]),
    test: 'tests/netlify-exclusive-publisher-contract.mjs'
  }),
  Object.freeze({
    id: 'private-draft-lifecycle',
    scripts: Object.freeze(['scripts/verify-private-draft-lifecycle.mjs']),
    test: 'tests/private-draft-lifecycle-contract.mjs'
  }),
  Object.freeze({
    id: 'draft-mutation-recovery',
    scripts: Object.freeze([
      'scripts/create-netlify-draft-with-durable-intent.mjs',
      'scripts/cleanup-netlify-draft.mjs'
    ]),
    test: 'tests/draft-mutation-recovery-contract.mjs'
  }),
  Object.freeze({
    id: 'release-state-reconciliation',
    scripts: Object.freeze(['scripts/reconcile-netlify-release-state.mjs']),
    test: 'tests/release-state-reconciliation-contract.mjs'
  }),
  Object.freeze({
    id: 'backup-disable-runtime-boundary',
    scripts: Object.freeze(['scripts/verify-backup-disable-runtime-boundary.mjs']),
    test: 'tests/backup-disable-runtime-boundary-contract.mjs'
  }),
  Object.freeze({
    id: 'rollback-authorization-chain',
    scripts: Object.freeze(['scripts/verify-rollback-authorization-chain.mjs']),
    test: 'tests/rollback-authorization-chain-contract.mjs'
  }),
  Object.freeze({
    id: 'rollback-principal-boundary',
    scripts: Object.freeze(['scripts/netlify-evidence.mjs']),
    test: 'tests/rollback-principal-boundary-contract.mjs'
  }),
  Object.freeze({
    id: 'controller-static-reproducibility',
    scripts: Object.freeze(['scripts/controller-static-reproducibility.mjs']),
    test: 'tests/controller-static-reproducibility-contract.mjs'
  }),
  Object.freeze({
    id: 'private-draft-access-boundary',
    scripts: Object.freeze(['scripts/private-draft-access-boundary.mjs']),
    test: 'tests/private-draft-access-boundary-contract.mjs'
  }),
  Object.freeze({
    id: 'scheduled-function-route-denial',
    scripts: Object.freeze(['scripts/scheduled-function-route-denial.mjs']),
    test: 'tests/scheduled-function-route-denial-contract.mjs'
  }),
  Object.freeze({
    id: 'rollback-readiness',
    scripts: Object.freeze(['scripts/rollback-readiness.mjs']),
    test: 'tests/rollback-readiness-contract.mjs'
  })
]);

const BASE_TESTS = Object.freeze([
  Object.freeze({
    id: 'uat-browser-read-policy',
    path: 'tests/controller-uat-browser-read-policy-contract.mjs',
    marker: 'CNYOS UAT browser read policy contract: passed'
  }),
  Object.freeze({
    id: 'uat-browser-transport',
    path: 'tests/controller-uat-browser-transport-contract.mjs',
    marker: 'CNYOS UAT browser transport contract: passed'
  }),
  Object.freeze({
    id: 'function-recipe-input',
    path: 'tests/function-recipe-input-contract.mjs',
    marker: 'CNYOS Function recipe input filesystem contract: passed'
  }),
  Object.freeze({
    id: 'function-comparison-handoff',
    path: 'tests/function-comparison-handoff-contract.mjs',
    marker: 'CNYOS Function comparison handoff filesystem contract: passed'
  }),
  Object.freeze({
    id: 'uat-access-observations',
    path: 'tests/controller-uat-access-observations-contract.mjs',
    marker: 'CNYOS UAT access observation comparison contract: passed'
  }),
  Object.freeze({
    id: 'uat-evidence-publication',
    path: 'tests/controller-uat-evidence-publication-contract.mjs',
    marker: 'CNYOS UAT evidence publication filesystem contract: passed'
  }),
  Object.freeze({
    id: 'controller-offline',
    path: 'tests/controller-contract.mjs',
    marker: 'CNYOS protected-controller offline contract: passed'
  }),
  Object.freeze({
    id: 'uat-evidence-schema',
    path: 'tests/uat-evidence-schema-contract.mjs',
    marker: 'CNYOS authenticated-UAT evidence schema contract: passed'
  })
]);

export const ACTIVATION_TESTS = Object.freeze(ACTIVATION_PAIRS.map(pair => Object.freeze({
  id: pair.id,
  path: pair.test,
  marker: `CNYOS activation contract ${pair.id}: passed`
})));

export const ALL_TEST_CONTRACTS = Object.freeze([...BASE_TESTS, ...ACTIVATION_TESTS]);

export const REQUIRED_ACTIVATION_PREREQUISITES = Object.freeze([...new Set(
  ACTIVATION_PAIRS.flatMap(pair => [...pair.scripts, pair.test])
)].sort());

export const CLOSED_WORLD_SCRIPT_INVENTORY = Object.freeze([...new Set([
  ...FOUNDATION_SCRIPTS,
  ...ACTIVATION_PAIRS.flatMap(pair => pair.scripts)
])].map(item => path.posix.basename(item)).sort());

export const CLOSED_WORLD_TEST_INVENTORY = Object.freeze(
  ALL_TEST_CONTRACTS.map(item => path.posix.basename(item.path)).sort()
);

function fail(code) {
  throw new Error(code);
}

async function assertRegularNonSymlink(relativePath) {
  const absolutePath = path.join(packageRoot, relativePath);
  let status;
  try {
    status = await fs.lstat(absolutePath);
  } catch {
    fail(`CNYOS_CONTROLLER_ACTIVATION_PREREQUISITE_MISSING:${relativePath}`);
  }
  if (!status.isFile() || status.isSymbolicLink() || status.size < 1) {
    fail(`CNYOS_CONTROLLER_ACTIVATION_PREREQUISITE_NOT_REGULAR:${relativePath}`);
  }
}

export function assertClosedWorldEntries(entries, expectedNames, directory) {
  const actualNames = entries.map(entry => entry.name).sort();
  if (actualNames.length !== expectedNames.length ||
    actualNames.some((name, index) => name !== expectedNames[index])) {
    fail(`CNYOS_CONTROLLER_ACTIVATION_${directory.toUpperCase()}_INVENTORY_MISMATCH`);
  }
  if (entries.some(entry => !entry.isFile() || entry.isSymbolicLink())) {
    fail(`CNYOS_CONTROLLER_ACTIVATION_${directory.toUpperCase()}_ENTRY_NOT_REGULAR`);
  }
  return actualNames;
}

async function assertClosedWorld(directory, expectedNames) {
  const absoluteDirectory = path.join(packageRoot, directory);
  let directoryStatus;
  try {
    directoryStatus = await fs.lstat(absoluteDirectory);
  } catch {
    fail(`CNYOS_CONTROLLER_ACTIVATION_DIRECTORY_INVALID:${directory}`);
  }
  if (!directoryStatus.isDirectory() || directoryStatus.isSymbolicLink()) {
    fail(`CNYOS_CONTROLLER_ACTIVATION_DIRECTORY_INVALID:${directory}`);
  }
  const entries = await fs.readdir(absoluteDirectory, { withFileTypes: true });
  const actualNames = assertClosedWorldEntries(entries, expectedNames, directory);
  for (const name of actualNames) await assertRegularNonSymlink(`${directory}/${name}`);
}

function credentialFreeEnvironment() {
  return Object.freeze({
    LANG: 'C',
    LC_ALL: 'C',
    NODE_ENV: 'test',
    TZ: 'UTC',
    CNYOS_CONTROLLER_ACTIVATION_CONTRACT: 'true',
    CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE: 'false'
  });
}

function runContract(contract) {
  const result = spawnSync(process.execPath, [path.join(packageRoot, contract.path)], {
    cwd: packageRoot,
    env: credentialFreeEnvironment(),
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    timeout: 120_000,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  if (result.error || result.signal || result.status !== 0 || result.stderr !== '' ||
    result.stdout !== `${contract.marker}\n`) {
    fail(`CNYOS_CONTROLLER_ACTIVATION_TEST_FAILED:${contract.path}`);
  }
}

export async function runActivationContracts() {
  await assertClosedWorld('scripts', CLOSED_WORLD_SCRIPT_INVENTORY);
  await assertClosedWorld('tests', CLOSED_WORLD_TEST_INVENTORY);
  for (const relativePath of REQUIRED_ACTIVATION_PREREQUISITES) {
    await assertRegularNonSymlink(relativePath);
  }
  for (const contract of ALL_TEST_CONTRACTS) runContract(contract);
  process.stdout.write('CNYOS protected-controller activation contracts: passed\n');
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runActivationContracts().catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_CONTROLLER_ACTIVATION_TESTS_FAILED')}\n`);
    process.exitCode = 1;
  });
}
