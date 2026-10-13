import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  LOCAL_CONTROLLER_ACK,
  LOCAL_CONTROLLER_ENTRYPOINT,
  LOCAL_CONTROLLER_KIND,
  LocalControllerRuntimeError,
  assertLocalExactRemotePrHeadControllerRuntime,
  assertVerifiedLocalControllerRuntime
} from '../scripts/local-controller-runtime.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = await fs.readFile(path.join(packageRoot,
  'scripts/local-controller-runtime.mjs'), 'utf8');

assert.equal(LOCAL_CONTROLLER_KIND, 'local_exact_remote_pr_head');
assert.equal(LOCAL_CONTROLLER_ENTRYPOINT,
  'ops/cnyos-staging-controller/scripts/run-local-bounded-treatment-uat.mjs');
assert.equal(LOCAL_CONTROLLER_ACK,
  'I_AUTHORIZE_LOCAL_EXACT_REMOTE_PR_HEAD_SYNTHETIC_STAGING_ONLY');

assert.throws(() => assertVerifiedLocalControllerRuntime(Object.freeze({
  kind: LOCAL_CONTROLLER_KIND
})), error => error instanceof LocalControllerRuntimeError &&
  error.code === 'CNYOS_LOCAL_CONTROLLER_RUNTIME_NOT_VERIFIED');

await assert.rejects(() => assertLocalExactRemotePrHeadControllerRuntime({}), error =>
  error instanceof LocalControllerRuntimeError &&
  error.code === 'CNYOS_LOCAL_CONTROLLER_SANITIZED_LAUNCH_REQUIRED');

await assert.rejects(() => assertLocalExactRemotePrHeadControllerRuntime({
  CNYOS_LOCAL_SANITIZED_LAUNCH: '1'
}), error =>
  error instanceof LocalControllerRuntimeError &&
  error.code === 'CNYOS_LOCAL_CONTROLLER_EXPLICIT_ACK_REQUIRED');

await assert.rejects(() => assertLocalExactRemotePrHeadControllerRuntime({
  CNYOS_LOCAL_SANITIZED_LAUNCH: '1',
  CNYOS_LOCAL_CONTROLLER_MODE: 'LIVE',
  CNYOS_LOCAL_CONTROLLER_ACK: LOCAL_CONTROLLER_ACK
}), error => error instanceof LocalControllerRuntimeError &&
  error.code === 'CNYOS_LOCAL_CONTROLLER_ROOT_REQUIRED');

// The local boundary must remain distinct from and must not modify the protected
// GitHub runtime assertion. These source-level checks pin the critical live
// invariants that are intentionally not injectable in tests.
for (const fragment of [
  "const GIT_BIN = '/usr/bin/git';",
  "git(['symbolic-ref', '--quiet', 'HEAD']",
  "git(['status', '--porcelain=v2', '--untracked-files=all']",
  "git(['rev-parse', '--verify', `refs/remotes/origin/${branch}^{commit}`]",
  "await assertRepositorySnapshot(root, expectedCommit, expectedTree, branch);",
  'await assertGitHubPrHead(prNumber, branch, expectedCommit, githubToken);',
  "latest.app?.id !== GITHUB_ACTIONS_APP_ID",
  "run.path !== requiredCheck.workflowPath",
  "run.event !== 'pull_request'",
  "run.pull_requests.some(item => item?.number === prNumber)",
  "'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'",
  "env.CNYOS_LOCAL_SANITIZED_LAUNCH !== '1'",
  "await runExecutable(NODE_BIN, ['tooling/verify-source.mjs']",
  "await runExecutable(NODE_BIN, ['tooling/verify-source-contract.mjs']",
  "!/^node tests\\/[A-Za-z0-9][A-Za-z0-9._-]*\\.mjs$/.test(command)",
  "await runExecutable(NODE_BIN, [command.slice('node '.length)]",
  'independentReviewerApproval: false',
  'productionAuthorization: false',
  'verifiedLocalRuntimes.add(runtime)'
]) assert.ok(source.includes(fragment), `missing fail-closed fragment: ${fragment}`);

assert.equal((source.match(/assertGitHubPrHead\(prNumber, branch, expectedCommit, githubToken\)/g) ||
  []).length, 2, 'GitHub PR head and checks must be rechecked after source verification');
assert.ok(!source.includes('GITHUB_REF_PROTECTED'),
  'local evidence must not impersonate a GitHub protected ref');
assert.ok(!source.includes('child_process.exec('), 'shell command execution is forbidden');
assert.ok(!source.includes('shell: true'), 'shell execution is forbidden');

console.log('local exact remote PR-head controller runtime contract: ok');
