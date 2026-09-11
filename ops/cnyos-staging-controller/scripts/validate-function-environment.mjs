import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  POLICY,
  POLICY_SHA256,
  assertControllerRuntime,
  exactSha256,
  fail,
  isPlainObject,
  parseJsonObject,
  readFileBounded,
  recentCanonicalTimestamp,
  required,
  sha256,
  writeJsonExclusive
} from './policy.mjs';
import { validateStoredNetlifyCredentialBoundary } from './netlify-evidence.mjs';

const CONTROLLER_PACKAGE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);
const VERIFIED_NETLIFY_CLI_PROVENANCE = new WeakSet();
const EXACT_SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]{40,}={0,2}$/;

export const NETLIFY_CLI_CHILD_ENVIRONMENT_NAMES = Object.freeze([
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

export const FUNCTION_ENVIRONMENT_PREREQUISITE_ENVIRONMENT_NAMES = Object.freeze([
  'CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH',
  'CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH',
  'CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256',
  'CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256',
  'CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE',
  'CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256'
].sort());

export function functionEnvironmentPrerequisiteEnvironment(env) {
  const prerequisiteEnvironment = Object.freeze({
    CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH:
      env.CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH,
    CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH:
      env.CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH,
    CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH:
      env.CNYOS_CONTROLLER_LIVE_NETLIFY_AUTHORITY_EVIDENCE_PATH,
    CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256:
      env.CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256,
    CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256:
      env.CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256,
    CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE:
      env.CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE,
    CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256:
      env.CNYOS_EXPECTED_LIVE_NETLIFY_AUTHORITY_EVIDENCE_SHA256
  });
  if (JSON.stringify(Object.keys(prerequisiteEnvironment).sort()) !==
    JSON.stringify(FUNCTION_ENVIRONMENT_PREREQUISITE_ENVIRONMENT_NAMES)) {
    fail('CNYOS_CONTROLLER_FUNCTION_ENV_PREREQUISITE_ENVIRONMENT_INVALID');
  }
  return prerequisiteEnvironment;
}

function strictOpaqueToken(value) {
  const token = required(value, 'CNYOS_CONTROLLER_NETLIFY_TOKEN_REQUIRED', 4096);
  if (value !== token || token.length < 16 || /[\s\0]/.test(token)) {
    fail('CNYOS_CONTROLLER_NETLIFY_TOKEN_INVALID');
  }
  return token;
}

export function netlifyCliChildEnvironment({
  token,
  isolatedStateRoot,
  nodeExecutable = process.execPath
}) {
  const root = path.resolve(required(
    isolatedStateRoot,
    'CNYOS_CONTROLLER_NETLIFY_CLI_STATE_DIRECTORY_INVALID',
    4096
  ));
  const executable = path.resolve(required(
    nodeExecutable,
    'CNYOS_CONTROLLER_NODE_EXECUTABLE_INVALID',
    4096
  ));
  const child = Object.freeze({
    CI: 'true',
    HOME: path.join(root, 'home'),
    LANG: 'C',
    LC_ALL: 'C',
    NETLIFY_AUTH_TOKEN: strictOpaqueToken(token),
    NETLIFY_CLI_TELEMETRY_DISABLED: '1',
    NETLIFY_SITE_ID: POLICY.target.netlifySiteId,
    NO_COLOR: '1',
    PATH: [...new Set([
      path.dirname(executable),
      '/usr/local/bin',
      '/usr/bin',
      '/bin'
    ])].join(path.delimiter),
    TMPDIR: path.join(root, 'tmp'),
    TZ: 'UTC',
    XDG_CACHE_HOME: path.join(root, 'cache'),
    XDG_CONFIG_HOME: path.join(root, 'config')
  });
  if (JSON.stringify(Object.keys(child).sort()) !==
    JSON.stringify(NETLIFY_CLI_CHILD_ENVIRONMENT_NAMES)) {
    fail('CNYOS_CONTROLLER_NETLIFY_CLI_ENVIRONMENT_INVALID');
  }
  return child;
}

async function loadCliJson(filename) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID';
  const bytes = await readFileBounded(filename, 4 * 1024 * 1024, code);
  return parseJsonObject(bytes.toString('utf8'), code);
}

function equalExactStringMaps(left, right) {
  if (!isPlainObject(left) || !isPlainObject(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] &&
      typeof left[key] === 'string' && left[key] === right[key]);
}

async function assertCanonicalDirectory(directory, code) {
  const status = await fs.lstat(directory);
  if (!status.isDirectory() || status.isSymbolicLink()) fail(code);
  const realDirectory = await fs.realpath(directory);
  if (realDirectory !== directory) fail(code);
  return realDirectory;
}

async function assertCanonicalDirectoryChain(rootDirectory, targetDirectory, code) {
  const relative = path.relative(rootDirectory, targetDirectory);
  if (relative === '') return;
  if (path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) {
    fail(code);
  }
  let current = rootDirectory;
  for (const component of relative.split(path.sep)) {
    if (!component || component === '.' || component === '..') fail(code);
    current = path.join(current, component);
    await assertCanonicalDirectory(current, code);
  }
}

export async function validateProtectedNetlifyCliProvenance({
  cliPath,
  controllerPackageRoot = CONTROLLER_PACKAGE_ROOT,
  expectedVersion = POLICY.publishing?.netlifyCliVersion
} = {}) {
  const code = 'CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID';
  const rootValue = required(controllerPackageRoot, code, 4096);
  const root = path.resolve(rootValue);
  if (controllerPackageRoot !== rootValue || rootValue !== root) fail(code);
  const version = required(expectedVersion, code, 100);
  if (expectedVersion !== version || !EXACT_SEMVER.test(version)) fail(code);
  const expectedCliLink = path.join(root, 'node_modules', '.bin', 'netlify');
  const requestedCli = required(cliPath, 'CNYOS_CONTROLLER_NETLIFY_CLI_PATH_REQUIRED', 4096);
  if (cliPath !== requestedCli || requestedCli !== expectedCliLink) fail(code);

  const packageManifestPath = path.join(root, 'package.json');
  const packageLockPath = path.join(root, 'package-lock.json');
  const nodeModulesRoot = path.join(root, 'node_modules');
  const packageBinRoot = path.join(nodeModulesRoot, '.bin');
  const installedPackageRoot = path.join(root, 'node_modules', 'netlify-cli');
  const installedManifestPath = path.join(installedPackageRoot, 'package.json');
  let packageManifest;
  let packageLock;
  let installedManifest;
  let realInstalledPackageRoot;
  try {
    await assertCanonicalDirectory(root, code);
    await assertCanonicalDirectory(nodeModulesRoot, code);
    await assertCanonicalDirectory(packageBinRoot, code);
    realInstalledPackageRoot = await assertCanonicalDirectory(installedPackageRoot, code);
    if (!realInstalledPackageRoot.startsWith(`${nodeModulesRoot}${path.sep}`)) fail(code);
    [packageManifest, packageLock, installedManifest] = await Promise.all([
      loadCliJson(packageManifestPath),
      loadCliJson(packageLockPath),
      loadCliJson(installedManifestPath)
    ]);
  } catch (error) {
    if (error?.message === code) throw error;
    fail(code);
  }
  const rootLockEntry = packageLock.packages?.[''];
  const cliLockEntry = packageLock.packages?.['node_modules/netlify-cli'];
  const installedBin = installedManifest.bin;
  const lockedBin = cliLockEntry?.bin;
  if (packageManifest.name !== 'cnyos-staging-protected-controller' ||
    packageManifest.dependencies?.['netlify-cli'] !== version ||
    packageLock.lockfileVersion !== 3 || !isPlainObject(rootLockEntry) ||
    rootLockEntry.dependencies?.['netlify-cli'] !== version ||
    !isPlainObject(cliLockEntry) || cliLockEntry.version !== version ||
    cliLockEntry.resolved !==
      `https://registry.npmjs.org/netlify-cli/-/netlify-cli-${version}.tgz` ||
    typeof cliLockEntry.integrity !== 'string' ||
    !SHA512_INTEGRITY.test(cliLockEntry.integrity) ||
    installedManifest.name !== 'netlify-cli' || installedManifest.version !== version ||
    !equalExactStringMaps(installedBin, lockedBin)) {
    fail(code);
  }
  const binMapping = required(installedBin.netlify, code, 500);
  if (installedBin.netlify !== binMapping || path.posix.isAbsolute(binMapping) ||
    binMapping !== path.posix.normalize(binMapping) || binMapping.startsWith('../') ||
    binMapping.includes('\\')) {
    fail(code);
  }
  const expectedTarget = path.resolve(installedPackageRoot, ...binMapping.split('/'));
  if (!expectedTarget.startsWith(`${installedPackageRoot}${path.sep}`)) fail(code);

  let cliRealPath;
  try {
    await assertCanonicalDirectoryChain(
      installedPackageRoot,
      path.dirname(expectedTarget),
      code
    );
    const linkStatus = await fs.lstat(expectedCliLink);
    const targetStatus = await fs.lstat(expectedTarget);
    if (!linkStatus.isSymbolicLink() || !targetStatus.isFile() || targetStatus.isSymbolicLink()) {
      fail(code);
    }
    const [linkValue, linkRealPath, targetRealPath] = await Promise.all([
      fs.readlink(expectedCliLink),
      fs.realpath(expectedCliLink),
      fs.realpath(expectedTarget)
    ]);
    const expectedLinkValue = path.relative(packageBinRoot, expectedTarget);
    if (path.isAbsolute(linkValue) || linkValue !== path.normalize(linkValue) ||
      linkValue !== expectedLinkValue || targetRealPath !== expectedTarget ||
      !targetRealPath.startsWith(`${realInstalledPackageRoot}${path.sep}`) ||
      linkRealPath !== targetRealPath) fail(code);
    cliRealPath = targetRealPath;
  } catch (error) {
    if (error?.message === code) throw error;
    fail(code);
  }
  const provenance = Object.freeze({
    cliRealPath,
    packageVersion: version,
    lockIntegrity: cliLockEntry.integrity
  });
  VERIFIED_NETLIFY_CLI_PROVENANCE.add(provenance);
  return provenance;
}

async function createNetlifyCliStateDirectory(env, runtime) {
  const runnerTemp = path.resolve(required(
    env.RUNNER_TEMP,
    'CNYOS_CONTROLLER_RUNNER_TEMP_REQUIRED',
    4096
  ));
  let realRunnerTemp;
  try {
    const entryStatus = await fs.lstat(runnerTemp);
    if (!entryStatus.isDirectory() || entryStatus.isSymbolicLink()) {
      fail('CNYOS_CONTROLLER_RUNNER_TEMP_INVALID');
    }
    realRunnerTemp = await fs.realpath(runnerTemp);
    const status = await fs.lstat(realRunnerTemp);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      fail('CNYOS_CONTROLLER_RUNNER_TEMP_INVALID');
    }
  } catch (error) {
    if (error?.message === 'CNYOS_CONTROLLER_RUNNER_TEMP_INVALID') throw error;
    fail('CNYOS_CONTROLLER_RUNNER_TEMP_INVALID');
  }
  let stateDirectory;
  try {
    stateDirectory = await fs.mkdtemp(path.join(
      realRunnerTemp,
      `cnyos-netlify-cli-${runtime.runId}-`
    ));
    await Promise.all(['home', 'tmp', 'cache', 'config'].map(directory =>
      fs.mkdir(path.join(stateDirectory, directory), { mode: 0o700 })
    ));
    await fs.chmod(stateDirectory, 0o700);
  } catch {
    fail('CNYOS_CONTROLLER_NETLIFY_CLI_STATE_DIRECTORY_INVALID');
  }
  return stateDirectory;
}

function readNetlifyValue(cli, name, {
  childEnvironment,
  cwd,
  execFileImpl
}) {
  let stdout;
  try {
    stdout = execFileImpl(cli, [
      'env:get',
      name,
      `--site=${POLICY.target.netlifySiteId}`,
      '--context=production',
      '--scope=functions'
    ], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30_000,
      windowsHide: true,
      cwd,
      env: childEnvironment
    });
  } catch {
    fail('CNYOS_CONTROLLER_FUNCTION_ENV_READ_FAILED');
  }
  const value = String(stdout).replace(/\r?\n$/, '');
  if (!value || value.length > 2048 || /[\r\n\0]/.test(value)) {
    fail('CNYOS_CONTROLLER_FUNCTION_ENV_VALUE_INVALID');
  }
  return value;
}

export async function validateFunctionEnvironment({
  env = process.env,
  now = () => new Date(),
  credentialBoundaryVerifier = validateStoredNetlifyCredentialBoundary,
  cliProvenanceVerifier = validateProtectedNetlifyCliProvenance,
  execFileImpl = execFileSync
} = {}) {
  const runtime = assertControllerRuntime(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_TIME_INVALID');
  }
  if (typeof credentialBoundaryVerifier !== 'function' ||
    typeof cliProvenanceVerifier !== 'function' || typeof execFileImpl !== 'function') {
    fail('CNYOS_CONTROLLER_FUNCTION_ENV_DEPENDENCY_INVALID');
  }
  const credentialBoundary = await credentialBoundaryVerifier({
    env: functionEnvironmentPrerequisiteEnvironment(env),
    runtime,
    observedAt
  });
  const liveGitHubPrecredentialBoundary =
    credentialBoundary?.liveGitHubPrecredentialBoundary;
  const liveGitHubPrecredentialBoundaryEvidenceSha256 = exactSha256(
    liveGitHubPrecredentialBoundary?.sha256,
    'CNYOS_CONTROLLER_FUNCTION_ENV_GITHUB_BOUNDARY_INVALID'
  );
  const githubBoundaryMaximumAgeMs =
    POLICY.githubReleaseBoundary.maximumEvidenceAgeMinutes * 60 * 1000;
  const liveGitHubPrecredentialBoundaryCheckedAt = recentCanonicalTimestamp(
    liveGitHubPrecredentialBoundary?.evidence?.checkedAt,
    observedAt,
    githubBoundaryMaximumAgeMs,
    'CNYOS_CONTROLLER_FUNCTION_ENV_GITHUB_BOUNDARY_INVALID'
  );
  const cliProvenance = await cliProvenanceVerifier({
    cliPath: env.CNYOS_NETLIFY_CLI_PATH,
    controllerPackageRoot: CONTROLLER_PACKAGE_ROOT,
    expectedVersion: POLICY.publishing?.netlifyCliVersion
  });
  if (!VERIFIED_NETLIFY_CLI_PROVENANCE.has(cliProvenance)) {
    fail('CNYOS_CONTROLLER_NETLIFY_CLI_PROVENANCE_INVALID');
  }
  const expectedEntries = Object.entries(POLICY.functionEnvironment)
    .sort(([left], [right]) => left.localeCompare(right));
  const observed = [];
  const cliStateDirectory = await createNetlifyCliStateDirectory(env, runtime);
  let credentialAccessAt;
  try {
    credentialAccessAt = now();
    if (!(credentialAccessAt instanceof Date) || Number.isNaN(credentialAccessAt.getTime()) ||
      credentialAccessAt < observedAt) fail('CNYOS_CONTROLLER_TIME_INVALID');
    recentCanonicalTimestamp(
      liveGitHubPrecredentialBoundaryCheckedAt.toISOString(),
      credentialAccessAt,
      githubBoundaryMaximumAgeMs,
      'CNYOS_CONTROLLER_FUNCTION_ENV_GITHUB_BOUNDARY_INVALID'
    );
    const token = strictOpaqueToken(env.CNYOS_STAGING_NETLIFY_AUTH_TOKEN);
    const childEnvironment = netlifyCliChildEnvironment({
      token,
      isolatedStateRoot: cliStateDirectory
    });
    for (const [name, expected] of expectedEntries) {
      const value = readNetlifyValue(cliProvenance.cliRealPath, name, {
        childEnvironment,
        cwd: cliStateDirectory,
        execFileImpl
      });
      if (value !== expected) fail('CNYOS_CONTROLLER_FUNCTION_ENV_TARGET_MISMATCH');
      observed.push([name, value]);
    }
  } finally {
    try { await fs.rm(cliStateDirectory, { recursive: true, force: false }); }
    catch { fail('CNYOS_CONTROLLER_NETLIFY_CLI_STATE_CLEANUP_FAILED'); }
  }
  if (POLICY.functionEnvironment.SUPABASE_URL === POLICY.productionDenylist.supabaseOrigin ||
    POLICY.functionEnvironment.CNYOS_ACCOUNT_CLINIC_ID === POLICY.productionDenylist.clinicId ||
    POLICY.functionEnvironment.CNYOS_ACCOUNT_CLINIC_CODE === POLICY.productionDenylist.clinicCode) {
    fail('CNYOS_CONTROLLER_FUNCTION_ENV_PRODUCTION_TARGET_DENIED');
  }
  const evidence = Object.freeze({
    schemaVersion: 2,
    evidenceType: 'cnyos_staging_controller_function_environment_validation',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    verifiedAt: credentialAccessAt.toISOString(),
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerRunId: runtime.runId,
    target: POLICY.target,
    policySha256: POLICY_SHA256,
    liveGitHubPrecredentialBoundaryEvidenceSha256,
    validatedVariableNames: Object.freeze(expectedEntries.map(([name]) => name)),
    exactValuesSha256: sha256(JSON.stringify(observed)),
    productionDenylistConfirmed: true,
    protectedSecretPresenceVerified: false,
    valuesSerialized: false
  });
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_FUNCTION_ENV_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({ evidence, evidencePath });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  validateFunctionEnvironment().then(async result => {
    const bytes = await fs.readFile(result.evidencePath);
    process.stdout.write(`${JSON.stringify({
      evidencePath: result.evidencePath,
      evidenceSha256: sha256(bytes),
      validatedVariableCount: result.evidence.validatedVariableNames.length
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_CONTROLLER_FUNCTION_ENV_VALIDATION_FAILED')}\n`);
    process.exitCode = 1;
  });
}
