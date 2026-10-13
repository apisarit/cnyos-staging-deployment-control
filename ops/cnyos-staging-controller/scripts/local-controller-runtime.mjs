import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { POLICY, POLICY_SHA256 } from './policy.mjs';

export const LOCAL_CONTROLLER_KIND = 'local_exact_remote_pr_head';
export const LOCAL_CONTROLLER_ENTRYPOINT =
  'ops/cnyos-staging-controller/scripts/run-local-bounded-treatment-uat.mjs';
export const LOCAL_CONTROLLER_ACK =
  'I_AUTHORIZE_LOCAL_EXACT_REMOTE_PR_HEAD_SYNTHETIC_STAGING_ONLY';

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const BRANCH = /^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,198}[A-Za-z0-9._-])?$/;
const GITHUB_TOKEN = /^[^\s]{20,8192}$/;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const COMMAND_TIMEOUT_MS = 120_000;
const GIT_BIN = '/usr/bin/git';
const NODE_BIN = process.execPath;
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY_ROOT = path.resolve(PACKAGE_ROOT, '../..');
const REMOTE_HTTPS = `https://github.com/${POLICY.controller.repository}.git`;
const REMOTE_SSH = `git@github.com:${POLICY.controller.repository}.git`;
const GITHUB_API = 'https://api.github.com';
const GITHUB_ACTIONS_APP_ID = 15368;
const REQUIRED_CHECKS = Object.freeze([
  Object.freeze({ name: 'contracts', workflowPath: '.github/workflows/controller-contracts.yml' }),
  Object.freeze({ name: 'offline-contracts',
    workflowPath: '.github/workflows/controller-offline-ci.yml' })
]);
const verifiedLocalRuntimes = new WeakSet();

export class LocalControllerRuntimeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'LocalControllerRuntimeError';
    this.code = code;
  }
}

function fail(code) {
  throw new LocalControllerRuntimeError(code);
}

function required(value, code, maximum = 4096) {
  const normalized = String(value ?? '').trim();
  if (!normalized || normalized.length > maximum) fail(code);
  return normalized;
}

function exact(value, pattern, code) {
  const normalized = required(value, code).toLowerCase();
  if (!pattern.test(normalized)) fail(code);
  return normalized;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function safeChildEnvironment() {
  const allowed = [
    'HOME', 'LANG', 'LC_ALL', 'LOGNAME', 'PATH', 'SSH_AUTH_SOCK', 'TMPDIR', 'USER',
    'XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR'
  ];
  const env = Object.fromEntries(allowed
    .filter(name => typeof process.env[name] === 'string')
    .map(name => [name, process.env[name]]));
  env.GIT_TERMINAL_PROMPT = '0';
  env.GIT_CONFIG_NOSYSTEM = '1';
  env.GIT_OPTIONAL_LOCKS = '0';
  return env;
}

async function runExecutable(filename, args, { cwd = REPOSITORY_ROOT, timeout = COMMAND_TIMEOUT_MS } = {}) {
  try {
    const result = await promisify(execFile)(filename, args, {
      cwd,
      env: safeChildEnvironment(),
      encoding: 'utf8',
      timeout,
      maxBuffer: MAX_OUTPUT_BYTES,
      windowsHide: true
    });
    return String(result.stdout || '').trim();
  } catch {
    fail('CNYOS_LOCAL_CONTROLLER_COMMAND_FAILED');
  }
}

async function git(args, options) {
  return runExecutable(GIT_BIN, [
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.pager=cat',
    ...args
  ], options);
}

async function regularFileSha256(filename, code) {
  const resolved = path.resolve(filename);
  let handle;
  try {
    handle = await fs.open(resolved, 'r');
    const before = await handle.stat({ bigint: true });
    const linked = await fs.lstat(resolved, { bigint: true });
    if (!before.isFile() || !linked.isFile() || linked.isSymbolicLink() ||
      before.dev !== linked.dev || before.ino !== linked.ino || before.size < 2n ||
      before.size > BigInt(MAX_OUTPUT_BYTES)) fail(code);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
      bytes.length !== Number(before.size)) fail(code);
    return sha256(bytes);
  } catch (error) {
    if (error instanceof LocalControllerRuntimeError) throw error;
    fail(code);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function assertRepositorySnapshot(root, expectedCommit, expectedTree, branch) {
  const [topLevel, symbolicRef, head, tree, originMain, upstream, status, fetchUrl, pushUrl,
    fetchSpec] = await Promise.all([
    git(['rev-parse', '--show-toplevel'], { cwd: root }),
    git(['symbolic-ref', '--quiet', 'HEAD'], { cwd: root }),
    git(['rev-parse', '--verify', 'HEAD^{commit}'], { cwd: root }),
    git(['rev-parse', '--verify', 'HEAD^{tree}'], { cwd: root }),
    git(['rev-parse', '--verify', `refs/remotes/origin/${branch}^{commit}`], { cwd: root }),
    git(['rev-parse', '--symbolic-full-name', '@{upstream}'], { cwd: root }),
    git(['status', '--porcelain=v2', '--untracked-files=all'], { cwd: root }),
    git(['remote', 'get-url', '--all', 'origin'], { cwd: root }),
    git(['remote', 'get-url', '--push', '--all', 'origin'], { cwd: root }),
    git(['config', '--get-all', 'remote.origin.fetch'], { cwd: root })
  ]);
  const canonicalRoot = await fs.realpath(root).catch(() => fail('CNYOS_LOCAL_CONTROLLER_ROOT_INVALID'));
  const canonicalTopLevel = await fs.realpath(topLevel)
    .catch(() => fail('CNYOS_LOCAL_CONTROLLER_ROOT_INVALID'));
  const allowedRemote = value => value === REMOTE_HTTPS || value === REMOTE_SSH;
  if (canonicalRoot !== canonicalTopLevel || canonicalRoot !== REPOSITORY_ROOT ||
    symbolicRef !== `refs/heads/${branch}` || head !== expectedCommit || tree !== expectedTree ||
    originMain !== expectedCommit || upstream !== `refs/remotes/origin/${branch}` || status !== '' ||
    fetchUrl.split('\n').filter(Boolean).length !== 1 || !allowedRemote(fetchUrl) ||
    pushUrl.split('\n').filter(Boolean).length !== 1 || !allowedRemote(pushUrl) ||
    fetchSpec !== '+refs/heads/*:refs/remotes/origin/*') {
    fail('CNYOS_LOCAL_CONTROLLER_REPOSITORY_STATE_INVALID');
  }
}

async function readJsonResponse(response, code) {
  if (!response?.body?.getReader || response.status !== 200) fail(code);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_OUTPUT_BYTES) {
        await reader.cancel().catch(() => {});
        fail(code);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    fail(code);
  }
}

async function githubGet(pathname, token, code) {
  const url = new URL(pathname, GITHUB_API);
  if (url.origin !== GITHUB_API || !url.pathname.startsWith('/repos/') ||
    url.username || url.password || url.port || url.hash) fail(code);
  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      redirect: 'error',
      cache: 'no-store',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'cnyos-local-staging-controller/1.0'
      },
      signal: AbortSignal.timeout(20_000)
    });
  } catch {
    fail(code);
  }
  return readJsonResponse(response, code);
}

async function assertGitHubPrHead(prNumber, branch, expectedCommit, token) {
  const base = `/repos/${POLICY.controller.repository}`;
  const pr = await githubGet(`${base}/pulls/${prNumber}`, token,
    'CNYOS_LOCAL_CONTROLLER_GITHUB_PR_INVALID');
  if (pr?.number !== prNumber || pr.state !== 'open' || pr.draft !== true ||
    pr.merged !== false || pr.merged_at !== null || pr.head?.sha !== expectedCommit ||
    pr.head?.ref !== branch || pr.head?.repo?.full_name !== POLICY.controller.repository ||
    pr.base?.ref !== 'main' || pr.base?.repo?.full_name !== POLICY.controller.repository) {
    fail('CNYOS_LOCAL_CONTROLLER_GITHUB_PR_STATE_INVALID');
  }
  const checks = await githubGet(`${base}/commits/${expectedCommit}/check-runs?per_page=100`, token,
    'CNYOS_LOCAL_CONTROLLER_GITHUB_CHECKS_INVALID');
  if (!Number.isSafeInteger(checks?.total_count) || checks.total_count < REQUIRED_CHECKS.length ||
    checks.total_count > 100 || !Array.isArray(checks.check_runs) ||
    checks.check_runs.length !== checks.total_count) {
    fail('CNYOS_LOCAL_CONTROLLER_GITHUB_CHECKS_INVALID');
  }
  for (const requiredCheck of REQUIRED_CHECKS) {
    const matching = checks.check_runs.filter(item => item?.name === requiredCheck.name)
      .sort((left, right) => Number(right?.id || 0) - Number(left?.id || 0));
    const latest = matching[0];
    if (!latest || latest.head_sha !== expectedCommit || latest.status !== 'completed' ||
      latest.conclusion !== 'success' || latest.app?.id !== GITHUB_ACTIONS_APP_ID ||
      latest.app?.slug !== 'github-actions') {
      fail('CNYOS_LOCAL_CONTROLLER_GITHUB_CHECK_REQUIRED');
    }
    let details;
    try { details = new URL(latest.details_url); }
    catch { fail('CNYOS_LOCAL_CONTROLLER_GITHUB_CHECK_REQUIRED'); }
    const detailsMatch = new RegExp(`^/${POLICY.controller.repository.replace('/', '\\/')}` +
      '/actions/runs/([0-9]+)/job/[0-9]+$').exec(details.pathname);
    if (details.origin !== 'https://github.com' || details.username || details.password ||
      details.port || details.search || details.hash || !detailsMatch) {
      fail('CNYOS_LOCAL_CONTROLLER_GITHUB_CHECK_REQUIRED');
    }
    const run = await githubGet(`${base}/actions/runs/${detailsMatch[1]}`, token,
      'CNYOS_LOCAL_CONTROLLER_GITHUB_CHECK_RUN_INVALID');
    if (run?.id !== Number(detailsMatch[1]) || run.event !== 'pull_request' ||
      run.status !== 'completed' || run.conclusion !== 'success' || run.run_attempt !== 1 ||
      run.head_sha !== expectedCommit || run.head_branch !== branch ||
      run.path !== requiredCheck.workflowPath ||
      run.repository?.full_name !== POLICY.controller.repository ||
      run.head_repository?.full_name !== POLICY.controller.repository ||
      !Array.isArray(run.pull_requests) ||
      !run.pull_requests.some(item => item?.number === prNumber)) {
      fail('CNYOS_LOCAL_CONTROLLER_GITHUB_CHECK_RUN_INVALID');
    }
  }
  return Object.freeze({ prNumber, requiredChecks: Object.freeze(REQUIRED_CHECKS.map(item =>
    Object.freeze({ ...item }))) });
}

async function verifyControllerSource(root) {
  await runExecutable(NODE_BIN, ['tooling/verify-source.mjs'], { cwd: root });
  await runExecutable(NODE_BIN, ['tooling/verify-source-contract.mjs'], { cwd: root });
  let packageValue;
  try {
    packageValue = JSON.parse(await fs.readFile(path.join(PACKAGE_ROOT, 'package.json'), 'utf8'));
  } catch {
    fail('CNYOS_LOCAL_CONTROLLER_PACKAGE_INVALID');
  }
  const testCommands = String(packageValue?.scripts?.test || '').split(' && ');
  if (testCommands.length < 4 || testCommands.some(command =>
    !/^node tests\/[A-Za-z0-9][A-Za-z0-9._-]*\.mjs$/.test(command)) ||
    new Set(testCommands).size !== testCommands.length) {
    fail('CNYOS_LOCAL_CONTROLLER_PACKAGE_TESTS_INVALID');
  }
  for (const command of testCommands) {
    await runExecutable(NODE_BIN, [command.slice('node '.length)], { cwd: PACKAGE_ROOT });
  }
  const sourceManifestSha256 = await regularFileSha256(
    path.join(root, 'provenance/source-manifest.json'),
    'CNYOS_LOCAL_CONTROLLER_SOURCE_MANIFEST_INVALID'
  );
  const packageLockSha256 = await regularFileSha256(
    path.join(PACKAGE_ROOT, 'package-lock.json'),
    'CNYOS_LOCAL_CONTROLLER_PACKAGE_LOCK_INVALID'
  );
  return Object.freeze({ sourceManifestSha256, packageLockSha256 });
}

export async function assertLocalExactRemotePrHeadControllerRuntime(env = process.env) {
  if (env.CNYOS_LOCAL_SANITIZED_LAUNCH !== '1') {
    fail('CNYOS_LOCAL_CONTROLLER_SANITIZED_LAUNCH_REQUIRED');
  }
  for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES',
    'DYLD_LIBRARY_PATH']) {
    if (String(env[name] || '').trim()) fail('CNYOS_LOCAL_CONTROLLER_PRELOAD_ENV_FORBIDDEN');
  }
  if (env.CNYOS_LOCAL_CONTROLLER_MODE !== 'LIVE' ||
    env.CNYOS_LOCAL_CONTROLLER_ACK !== LOCAL_CONTROLLER_ACK) {
    fail('CNYOS_LOCAL_CONTROLLER_EXPLICIT_ACK_REQUIRED');
  }
  const rootInput = required(env.CNYOS_LOCAL_CONTROLLER_REPOSITORY_ROOT,
    'CNYOS_LOCAL_CONTROLLER_ROOT_REQUIRED', 4096);
  if (!path.isAbsolute(rootInput)) fail('CNYOS_LOCAL_CONTROLLER_ROOT_INVALID');
  const expectedCommit = exact(env.CNYOS_EXPECTED_CONTROLLER_COMMIT, SHA40,
    'CNYOS_LOCAL_CONTROLLER_COMMIT_INVALID');
  const expectedTree = exact(env.CNYOS_EXPECTED_CONTROLLER_TREE, SHA40,
    'CNYOS_LOCAL_CONTROLLER_TREE_INVALID');
  const branch = required(env.CNYOS_EXPECTED_CONTROLLER_BRANCH,
    'CNYOS_LOCAL_CONTROLLER_BRANCH_INVALID', 200);
  if (!BRANCH.test(branch) || branch.includes('..') || branch.includes('//') ||
    branch.startsWith('main') || branch.endsWith('.lock')) {
    fail('CNYOS_LOCAL_CONTROLLER_BRANCH_INVALID');
  }
  const prNumber = Number(env.CNYOS_EXPECTED_CONTROLLER_PR_NUMBER);
  if (!Number.isSafeInteger(prNumber) || prNumber < 1) {
    fail('CNYOS_LOCAL_CONTROLLER_PR_NUMBER_INVALID');
  }
  const githubToken = required(env.CNYOS_LOCAL_CONTROLLER_GITHUB_READ_TOKEN,
    'CNYOS_LOCAL_CONTROLLER_GITHUB_TOKEN_REQUIRED', 8192);
  if (!GITHUB_TOKEN.test(githubToken)) fail('CNYOS_LOCAL_CONTROLLER_GITHUB_TOKEN_INVALID');
  const expectedPolicySha256 = exact(env.CNYOS_EXPECTED_CONTROLLER_POLICY_SHA256, SHA256,
    'CNYOS_LOCAL_CONTROLLER_POLICY_DIGEST_INVALID');
  if (expectedPolicySha256 !== POLICY_SHA256) {
    fail('CNYOS_LOCAL_CONTROLLER_POLICY_DIGEST_MISMATCH');
  }
  const runId = required(env.CNYOS_LOCAL_CONTROLLER_RUN_ID,
    'CNYOS_LOCAL_CONTROLLER_RUN_ID_INVALID', 96);
  if (!RUN_ID.test(runId)) fail('CNYOS_LOCAL_CONTROLLER_RUN_ID_INVALID');

  const root = await fs.realpath(rootInput).catch(() => fail('CNYOS_LOCAL_CONTROLLER_ROOT_INVALID'));
  await assertRepositorySnapshot(root, expectedCommit, expectedTree, branch);
  const github = await assertGitHubPrHead(prNumber, branch, expectedCommit, githubToken);
  const source = await verifyControllerSource(root);
  // Close the time-of-check window before any caller may construct an admission.
  await assertRepositorySnapshot(root, expectedCommit, expectedTree, branch);
  await assertGitHubPrHead(prNumber, branch, expectedCommit, githubToken);

  const operator = os.userInfo().username;
  if (!operator) fail('CNYOS_LOCAL_CONTROLLER_OPERATOR_INVALID');
  const runtime = Object.freeze({
    kind: LOCAL_CONTROLLER_KIND,
    repository: POLICY.controller.repository,
    runId,
    ref: `refs/heads/${branch}`,
    commit: expectedCommit,
    tree: expectedTree,
    workflowPath: LOCAL_CONTROLLER_ENTRYPOINT,
    workflowRef: `${POLICY.controller.repository}/${LOCAL_CONTROLLER_ENTRYPOINT}` +
      `@refs/heads/${branch}`,
    actor: null,
    operatorIdentitySha256: sha256(Buffer.from(operator)),
    policySha256: POLICY_SHA256,
    sourceManifestSha256: source.sourceManifestSha256,
    packageLockSha256: source.packageLockSha256,
    pullRequestNumber: github.prNumber,
    requiredChecks: github.requiredChecks,
    independentReviewerApproval: false,
    productionAuthorization: false
  });
  verifiedLocalRuntimes.add(runtime);
  return runtime;
}

export function assertVerifiedLocalControllerRuntime(runtime) {
  if (!runtime || !verifiedLocalRuntimes.has(runtime) ||
    runtime.kind !== LOCAL_CONTROLLER_KIND ||
    runtime.repository !== POLICY.controller.repository ||
    !runtime.ref?.startsWith('refs/heads/') || runtime.ref === POLICY.controller.protectedRef ||
    runtime.workflowPath !== LOCAL_CONTROLLER_ENTRYPOINT ||
    runtime.policySha256 !== POLICY_SHA256 || runtime.independentReviewerApproval !== false ||
    runtime.productionAuthorization !== false || !Number.isSafeInteger(runtime.pullRequestNumber) ||
    runtime.pullRequestNumber < 1 || !Array.isArray(runtime.requiredChecks) ||
    canonicalRequiredChecks(runtime.requiredChecks) !== canonicalRequiredChecks(REQUIRED_CHECKS)) {
    fail('CNYOS_LOCAL_CONTROLLER_RUNTIME_NOT_VERIFIED');
  }
  return runtime;
}

function canonicalRequiredChecks(value) {
  return JSON.stringify(value);
}
