import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { sha256, POLICY } from '../scripts/policy.mjs';
import { runControllerStaticReproducibility } from '../scripts/controller-static-reproducibility.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'cnyos-static-contract-'));
const imageId = `sha256:${'a'.repeat(64)}`;
const containerId = 'b'.repeat(64);
const recipe = 'node scripts/generate-tenant-config.mjs && node scripts/build-u-synthesise.mjs && node scripts/build-netlify-publish.mjs';
const childEnv = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' };
function git(cwd, args, extra = {}) {
  return execFileSync('/usr/bin/git', ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', ...args],
    { cwd, env: { ...childEnv, ...extra }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}
async function absent(filename) {
  try { await fs.lstat(filename); return false; } catch (error) {
    if (error.code === 'ENOENT') return true;
    throw error;
  }
}
const runtime = {
  GITHUB_REPOSITORY: POLICY.controller.repository,
  CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
  GITHUB_REF: POLICY.controller.protectedRef,
  CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
  GITHUB_REF_PROTECTED: 'true', GITHUB_SHA: 'c'.repeat(40), GITHUB_RUN_ID: '9191',
  GITHUB_RUN_ATTEMPT: '1', GITHUB_ACTOR: 'controller-reviewer', GITHUB_TRIGGERING_ACTOR: 'controller-reviewer',
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
  GITHUB_WORKFLOW_REF: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`
};

try {
  let calls = 0;
  await assert.rejects(runControllerStaticReproducibility({ env: runtime,
    dockerFactory: () => { calls += 1; throw new Error('must not execute'); } }), /POLICY_NOT_REVIEWED/);
  assert.equal(calls, 0);
  const cli = spawnSync(process.execPath, [path.join(root, 'scripts/controller-static-reproducibility.mjs')],
    { env: { ...childEnv, ...runtime }, encoding: 'utf8' });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, '');
  assert.equal(cli.stderr, 'CNYOS_STATIC_REPRODUCIBILITY_POLICY_NOT_REVIEWED\n');

  // Only this temporary module tree has fixture pins. The repository policy and
  // public configurations are never rewritten; no container runs in this test.
  const controller = path.join(temporary, 'controller');
  await fs.mkdir(path.join(controller, 'scripts'), { recursive: true });
  await fs.mkdir(path.join(controller, 'config'));
  for (const filename of ['policy.mjs', 'controller-static-reproducibility.mjs',
    'controller-function-bundle.mjs', 'create-producer-bundle.mjs', 'verify-producer-bundle.mjs']) {
    await fs.copyFile(path.join(root, 'scripts', filename), path.join(controller, 'scripts', filename));
  }
  function config(target, staging) {
    return {
      schemaVersion: 1, deploymentId: staging ? target.deploymentId : 'chananya-production',
      database: { provider: 'supabase', url: target.supabaseOrigin, publishableKey: `sb_publishable_${'X'.repeat(32)}` },
      tenant: { expectedClinicId: target.clinicId, expectedClinicCode: target.clinicCode },
      identity: { qrIssuer: target.qrIssuer },
      auth: { redirectOrigin: staging ? target.authRedirectOrigin : target.netlifyOrigin, provider: 'google' }
    };
  }
  const stagingBytes = Buffer.from(JSON.stringify(config(POLICY.target, true)));
  const productionBytes = Buffer.from(JSON.stringify(config(POLICY.productionDenylist, false)));
  const stagingPath = path.join(controller, 'config/cnyos-public-staging.json');
  const productionPath = path.join(controller, 'config/cnyos-production-denylist.json');
  await fs.writeFile(stagingPath, stagingBytes);
  await fs.writeFile(productionPath, productionBytes);
  const policy = JSON.parse(await fs.readFile(path.join(root, 'controller-policy.json'), 'utf8'));
  policy.staticArtifactReproducibility.hermeticBuilderImageDigest = imageId;
  policy.staticArtifactReproducibility.stagingConfigSha256 = sha256(stagingBytes);
  policy.staticArtifactReproducibility.productionDenylistConfigSha256 = sha256(productionBytes);
  await fs.writeFile(path.join(controller, 'controller-policy.json'), JSON.stringify(policy));
  const module = await import(pathToFileURL(path.join(controller, 'scripts/controller-static-reproducibility.mjs')));
  const verifier = await import(pathToFileURL(path.join(controller, 'scripts/verify-producer-bundle.mjs')));
  const isolatedPolicy = await import(pathToFileURL(path.join(controller, 'scripts/policy.mjs')));

  const candidate = path.join(temporary, 'candidate');
  await fs.mkdir(path.join(candidate, '.github'), { recursive: true });
  await fs.mkdir(path.join(candidate, 'scripts'));
  await fs.writeFile(path.join(candidate, '.github/offline.txt'), 'tracked dot-directory\n');
  await fs.writeFile(path.join(candidate, '.gitignore'), 'ignored-overlay\n');
  await fs.writeFile(path.join(candidate, 'package.json'), JSON.stringify({ scripts: { 'build:staging-artifact': recipe } }));
  await fs.writeFile(path.join(candidate, 'package-lock.json'), '{"lockfileVersion":3}\n');
  await fs.writeFile(path.join(candidate, 'index.html'), '<main>synthetic static contract</main>\n');
  for (const name of ['generate-tenant-config', 'build-u-synthesise', 'build-netlify-publish']) {
    await fs.writeFile(path.join(candidate, 'scripts', `${name}.mjs`), 'throw new Error("CANDIDATE_MUST_NOT_EXECUTE_ON_HOST");\n');
  }
  git(candidate, ['init', '--quiet']);
  git(candidate, ['add', '.']);
  git(candidate, ['-c', 'user.name=Offline Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'synthetic immutable build fixture'],
    { GIT_AUTHOR_DATE: '2026-09-09T12:00:00+07:00', GIT_COMMITTER_DATE: '2026-09-09T12:00:00+07:00' });
  const candidateCommit = git(candidate, ['rev-parse', 'HEAD']);
  const candidateTree = git(candidate, ['rev-parse', 'HEAD^{tree}']);
  // Ambient checkout data and Git configuration must not enter the source mount.
  await fs.writeFile(path.join(candidate, 'ignored-overlay'), 'not an input\n');
  await fs.writeFile(path.join(candidate, 'index.html'), 'uncommitted working-tree overlay\n');
  await fs.appendFile(path.join(candidate, '.git/config'), '\n[fixture]\nprivateMarker = never-mount-original-config\n');
  const source = module.readStaticImmutableSource(candidate, candidateCommit);
  assert.equal(source.tree, candidateTree);
  assert.equal(source.timestamp, '2026-09-09T05:00:00.000Z');
  assert.equal(source.blobs.some(item => item.path === '.github/offline.txt'), true);
  assert.equal(source.blobs.some(item => item.path === 'ignored-overlay'), false);
  assert.equal(source.blobs.find(item => item.path === 'index.html').bytes.toString(), '<main>synthetic static contract</main>\n');

  let fixtureIndex = 0;
  async function fixture() {
    const base = path.join(temporary, `run-${++fixtureIndex}`);
    const reference = path.join(base, 'reference');
    await fs.mkdir(reference, { recursive: true });
    const content = Buffer.from('<main>synthetic independently compared bytes</main>\n');
    await fs.writeFile(path.join(reference, 'index.html'), content);
    return { base, content, env: { ...runtime, CNYOS_CANDIDATE_DIRECTORY: candidate,
      CNYOS_CANDIDATE_SHA: candidateCommit, CNYOS_UNTRUSTED_STATIC_DIRECTORY: reference,
      CNYOS_REPRODUCED_STATIC_DIRECTORY: path.join(base, 'reproduced'),
      CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH: path.join(base, 'receipt.json'),
      CNYOS_PUBLIC_STAGING_CONFIG_PATH: stagingPath, CNYOS_PRODUCTION_DENYLIST_CONFIG_PATH: productionPath,
      CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST: 'd'.repeat(64) } };
  }
  function inspection(plan, exited) {
    const args = module.staticDockerCreateArguments(plan);
    return { Id: containerId, Image: imageId, Name: `/${plan.name}`,
      HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, PublishAllPorts: false,
        PidMode: '', IpcMode: 'none', CgroupnsMode: 'private', PidsLimit: 64, Memory: 536870912,
        MemorySwap: 536870912, NanoCpus: 1_000_000_000, RestartPolicy: { Name: 'no' }, CapDrop: ['ALL'],
        CapAdd: null, SecurityOpt: ['no-new-privileges=true'], PortBindings: {}, Devices: [], DeviceRequests: [],
        VolumesFrom: null, LogConfig: { Type: 'none' },
        Tmpfs: { '/work': 'rw,nosuid,nodev,noexec,size=536870912,nr_inodes=16384,mode=1777' } },
      Config: { User: `${plan.uid}:${plan.gid}`, Entrypoint: ['/usr/bin/env'], Cmd: args.slice(args.indexOf(imageId) + 1),
        Healthcheck: { Test: ['NONE'] } },
      Mounts: [[plan.source, '/input/source'], [plan.gitRoot, '/input/git'], [plan.configRoot, '/config'], [plan.launcher, '/controller/launch.mjs']]
        .map(([Source, Destination]) => ({ Type: 'bind', Source, Destination, RW: false, Propagation: 'rprivate' })),
      NetworkSettings: { Networks: { none: {} } },
      State: { Status: exited ? 'exited' : 'created', Running: false, ExitCode: 0, OOMKilled: false, Error: '' } };
  }
  function dockerFixture(run, options = {}) {
    const calls = [];
    let savedPlan;
    let inspections = 0;
    return { calls, get plan() { return savedPlan; }, factory: async plan => {
      savedPlan = plan;
      assert.equal(git(candidate, ['--git-dir', plan.gitRoot, 'rev-parse', 'HEAD']), candidateCommit);
      assert.equal(git(candidate, ['--git-dir', plan.gitRoot, 'rev-parse', 'HEAD^{tree}']), candidateTree);
      assert.equal(git(candidate, ['--git-dir', plan.gitRoot, 'show', 'HEAD:index.html']), '<main>synthetic static contract</main>');
      assert.equal(await absent(path.join(plan.source, '.git')), true);
      assert.equal(await absent(path.join(plan.source, 'ignored-overlay')), true);
      assert.doesNotMatch(await fs.readFile(path.join(plan.gitRoot, 'config'), 'utf8'), /privateMarker|never-mount/);
      const launcher = await fs.readFile(plan.launcher, 'utf8');
      assert.match(launcher, /distRoot\.isDirectory\(\).*distRoot\.isSymbolicLink\(\)/);
      assert.match(launcher, /before\.nlink!==1/);
      assert.match(launcher, /O_NOFOLLOW/);
      return async args => {
        calls.push(args);
        if (args[0] === 'image') return JSON.stringify([{ Id: options.wrongImage ? `sha256:${'0'.repeat(64)}` : imageId,
          Os: 'linux', Architecture: 'amd64', Config: { Volumes: options.imageVolume ? { '/unexpected': {} } : null } }]);
        if (args[1] === 'create') {
          assert.equal(args.includes('--pull=never'), true);
          assert.equal(args.includes('--network=none'), true);
          assert.equal(args.filter(item => item.startsWith('type=bind')).every(item => item.includes(',readonly,')), true);
          assert.equal(args.some(item => item.includes('docker.sock') || item.includes(candidate)), false);
          if (options.createError) throw new Error('SYNTHETIC_CREATE_COLLISION');
          if (options.unknownId) return 'uncertain-create-response';
          return `${containerId}\n`;
        }
        if (args[1] === 'inspect') {
          const result = inspection(plan, inspections++ > 0);
          if (options.inspectMutation) options.inspectMutation(result, inspections);
          return JSON.stringify([result]);
        }
        if (args[1] === 'start') {
          if (options.startError) throw new Error('SYNTHETIC_START_FAILURE');
          if (options.duringStart) await options.duringStart(plan);
          const bytes = options.mismatch ? Buffer.from('mismatch') : run.content;
          return options.wire ?? JSON.stringify({ schemaVersion: 1, nodeVersion: '24.20.0',
            files: [{ path: 'index.html', size: bytes.length, base64: bytes.toString('base64') }] });
        }
        if (args[1] === 'rm') {
          assert.deepEqual(args, ['container', 'rm', '--force', containerId]);
          if (options.cleanupError) throw new Error('SYNTHETIC_CLEANUP_FAILURE');
          return containerId;
        }
        throw new Error('UNEXPECTED_OFFLINE_DOCKER_COMMAND');
      };
    } };
  }
  const successful = await fixture();
  const docker = dockerFixture(successful);
  const receipt = await module.runControllerStaticReproducibility({ env: successful.env, dockerFactory: docker.factory });
  assert.equal(receipt.authorization, false);
  assert.equal(receipt.credentialsAvailable, false);
  assert.deepEqual(await fs.readFile(path.join(successful.env.CNYOS_REPRODUCED_STATIC_DIRECTORY, 'index.html')), successful.content);
  assert.deepEqual(JSON.parse(await fs.readFile(successful.env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH)), receipt);
  assert.equal((await fs.stat(successful.env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH)).nlink, 1);
  assert.equal(await absent(docker.plan.scratch), true);
  assert.equal(docker.calls.filter(item => item[1] === 'rm').length, 1);
  verifier.validateStaticReproducibilityReceipt(receipt, { ...receipt,
    candidateBuildArtifactDigest: receipt.untrustedReferenceArtifactDigest,
    stagingConfigSha256: receipt.configInputs.stagingConfigSha256,
    productionDenylistConfigSha256: receipt.configInputs.productionDenylistConfigSha256,
    generatedAt: new Date(Date.parse(receipt.verifiedAt) + 1).toISOString() }, receipt.files);
  assert.equal(receipt.policySha256, isolatedPolicy.POLICY_SHA256);

  for (const [label, options, error, removeCount] of [
    ['image mismatch', { wrongImage: true }, /IMAGE_IDENTITY_INVALID/, 0],
    ['image volume', { imageVolume: true }, /IMAGE_IDENTITY_INVALID/, 0],
    ['create collision', { createError: true }, /SYNTHETIC_CREATE_COLLISION/, 0],
    ['unknown create ID', { unknownId: true }, /CONTAINER_ID_INVALID/, 0],
    ['inspected image mismatch', { inspectMutation: i => { i.Image = `sha256:${'0'.repeat(64)}`; } }, /CONTAINER_ISOLATION_INVALID/, 0],
    ['network control', { inspectMutation: i => { i.HostConfig.NetworkMode = 'bridge'; } }, /CONTAINER_ISOLATION_INVALID/, 0],
    ['mount control', { inspectMutation: i => { i.Mounts[0].RW = true; } }, /CONTAINER_MOUNTS_INVALID/, 0],
    ['start failure', { startError: true }, /SYNTHETIC_START_FAILURE/, 1],
    ['cleanup failure', { cleanupError: true }, /SYNTHETIC_CLEANUP_FAILURE/, 1],
    ['failed exit', { inspectMutation: (i, count) => { if (count === 2) i.State.ExitCode = 31; } }, /CONTAINER_EXECUTION_FAILED/, 1],
    ['byte mismatch', { mismatch: true }, /BYTE_COMPARISON_FAILED/, 1],
    ['invalid protocol', { wire: 'not JSON' }, /BUILD_OUTPUT_INVALID/, 1]
  ]) {
    const run = await fixture(); const mock = dockerFixture(run, options);
    await assert.rejects(module.runControllerStaticReproducibility({ env: run.env, dockerFactory: mock.factory }), error, label);
    assert.equal(mock.calls.filter(item => item[1] === 'rm').length, removeCount, label);
    if (removeCount === 0) assert.equal(mock.calls.some(item => item[1] === 'start'), false, label);
    assert.equal(await absent(run.env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH), true, label);
    assert.equal(await absent(run.env.CNYOS_REPRODUCED_STATIC_DIRECTORY), true, label);
    assert.equal(await absent(mock.plan.scratch), true, label);
  }
  for (const key of [...module.STATIC_REPRODUCIBILITY_FORBIDDEN_ENVIRONMENT_NAMES, 'DOCKER_HOST', 'DOCKER_CONFIG', 'NODE_OPTIONS']) {
    let invoked = 0;
    await assert.rejects(module.runControllerStaticReproducibility({ env: { ...successful.env, [key]: 'inert-fixture' },
      dockerFactory: () => { invoked += 1; } }), /AMBIENT_AUTHORITY_REJECTED/);
    assert.equal(invoked, 0);
  }
  const malformed = [
    { path: '../outside', size: 0, base64: '' }, { path: '.git/config', size: 0, base64: '' },
    { path: 'x', size: 2, base64: 'YQ==' }, { path: 'x', size: 1, base64: 'YQ' },
    { path: 'x', size: 0, base64: '', extra: true }
  ];
  for (const item of malformed) assert.throws(() => module.parseStaticBuildOutput(JSON.stringify({
    schemaVersion: 1, nodeVersion: '24.20.0', files: [item] })), /CNYOS_/);
  for (const files of [[{ path: 'a', size: 0, base64: '' }, { path: 'A', size: 0, base64: '' }],
    [{ path: 'a', size: 0, base64: '' }, { path: 'a/b', size: 0, base64: '' }]]) {
    assert.throws(() => module.parseStaticBuildOutput(JSON.stringify({ schemaVersion: 1, nodeVersion: '24.20.0', files })), /BUILD_OUTPUT_INVALID/);
  }
  const changedReference = await fixture();
  const referenceMock = dockerFixture(changedReference, { duringStart: () => fs.writeFile(
    path.join(changedReference.env.CNYOS_UNTRUSTED_STATIC_DIRECTORY, 'index.html'), 'changed') });
  await assert.rejects(module.runControllerStaticReproducibility({ env: changedReference.env, dockerFactory: referenceMock.factory }), /BYTE_COMPARISON_FAILED/);
  assert.equal(await absent(changedReference.env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH), true);
  const symlink = await fixture();
  await fs.symlink('index.html', path.join(symlink.env.CNYOS_UNTRUSTED_STATIC_DIRECTORY, 'linked.html'));
  await assert.rejects(module.runControllerStaticReproducibility({ env: symlink.env,
    dockerFactory: () => { throw new Error('must not execute'); } }), /ARTIFACT_LINK_REJECTED/);
  const hardlink = await fixture();
  await fs.link(path.join(hardlink.env.CNYOS_UNTRUSTED_STATIC_DIRECTORY, 'index.html'), path.join(hardlink.base, 'extra-link'));
  await assert.rejects(module.runControllerStaticReproducibility({ env: hardlink.env,
    dockerFactory: () => { throw new Error('must not execute'); } }), /ARTIFACT_LINK_REJECTED/);
  let overwritten = 0;
  await assert.rejects(module.runControllerStaticReproducibility({ env: successful.env,
    dockerFactory: () => { overwritten += 1; } }), /OUTPUT_ALREADY_EXISTS/);
  assert.equal(overwritten, 0);
  assert.deepEqual(JSON.parse(await fs.readFile(successful.env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH)), receipt);
  const badConfig = await fixture();
  await assert.rejects(module.runControllerStaticReproducibility({ env: { ...badConfig.env,
    CNYOS_PUBLIC_STAGING_CONFIG_PATH: path.join(candidate, 'package.json') },
    dockerFactory: () => { throw new Error('must not execute'); } }), /CONFIG_NOT_CONTROLLER_OWNED/);
  await fs.writeFile(stagingPath, Buffer.concat([stagingBytes, Buffer.from(' ')]));
  await assert.rejects(module.runControllerStaticReproducibility({ env: badConfig.env,
    dockerFactory: () => { throw new Error('must not execute'); } }), /CONFIG_DIGEST_MISMATCH/);
  await fs.writeFile(stagingPath, stagingBytes);
  const headChange = await fixture();
  const headMock = dockerFixture(headChange, { duringStart: () => {
    git(candidate, ['-c', 'user.name=Offline Fixture', '-c', 'user.email=fixture@example.invalid',
      'commit', '--quiet', '--allow-empty', '-m', 'changed fixture head']);
  } });
  await assert.rejects(module.runControllerStaticReproducibility({ env: headChange.env, dockerFactory: headMock.factory }), /HEAD_CHANGED/);
  assert.equal(await absent(headChange.env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH), true);
  process.stdout.write('CNYOS activation contract controller-static-reproducibility: passed\n');
} finally { await fs.rm(temporary, { recursive: true, force: true }); }
