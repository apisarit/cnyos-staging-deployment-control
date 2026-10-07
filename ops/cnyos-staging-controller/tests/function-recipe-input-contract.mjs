import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { materializeFunctionRecipeInput, selectFunctionRecipeInput, parseFunctionRecipeInputArguments } from '../scripts/materialize-function-recipe-input.mjs';
import { createFunctionComparisonHandoff } from '../scripts/create-function-comparison-handoff.mjs';
import { readFunctionBundleCandidateSnapshot } from '../scripts/controller-function-bundle.mjs';
import { EXPECTED_FUNCTION_NAMES, sha256 } from '../scripts/policy.mjs';

const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'cnyos-recipe-input-'));
const candidateDirectory = path.join(root, 'candidate');
const script = fileURLToPath(new URL('../scripts/materialize-function-recipe-input.mjs', import.meta.url));
const write = async (filename, bytes) => {
  await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  await fs.writeFile(filename, bytes, { mode: 0o600 });
};
const git = args => execFileSync('/usr/bin/git', args, { cwd: candidateDirectory, encoding: 'utf8',
  env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const commit = () => { git(['add', '--all']); git(['-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'fixture']); return git(['rev-parse', 'HEAD']); };
const absent = filename => assert.rejects(fs.lstat(filename), error => error.code === 'ENOENT');
const encode = object => Buffer.from(`${JSON.stringify(object, null, 2)}\n`);
try {
  await fs.mkdir(candidateDirectory, { mode: 0o700 });
  git(['init', '--quiet']);
  const sourceBytes = new Map(EXPECTED_FUNCTION_NAMES.map(name => [`netlify/functions/${name}.mts`, Buffer.from(`// inert ${name}\n`)]));
  sourceBytes.set('netlify/functions/_shared/example.mjs', Buffer.from('// shared source\n'));
  sourceBytes.set('platform-config.js', Buffer.from('throw new Error("must never execute source");\n'));
  for (const [name, bytes] of sourceBytes) await write(path.join(candidateDirectory, name), bytes);
  await write(path.join(candidateDirectory, 'package.json'), '{"scripts":{"prepare":"must-not-run"}}\n');
  await write(path.join(candidateDirectory, '.gitignore'), '.env\nignored.mjs\n');
  const candidateCommit = commit();
  const snapshot = await readFunctionBundleCandidateSnapshot(candidateDirectory, candidateCommit);
  const selected = selectFunctionRecipeInput(snapshot);
  assert.equal(selected.files.length, EXPECTED_FUNCTION_NAMES.length + 2);
  assert.deepEqual(selected.files.map(file => file.path), [...sourceBytes.keys()].sort());
  assert.throws(() => selectFunctionRecipeInput({ ...snapshot, blobs: [...snapshot.blobs, snapshot.blobs.find(file => file.path === 'platform-config.js')] }), /SOURCE_LAYOUT/);
  assert.throws(() => selectFunctionRecipeInput({ ...snapshot, blobs: snapshot.blobs.map(file => file.path === 'platform-config.js' ? { ...file, bytes: Buffer.alloc(16 * 1024 * 1024 + 1) } : file) }), /SOURCE_SIZE/);
  const large = Buffer.alloc(16 * 1024 * 1024);
  assert.throws(() => selectFunctionRecipeInput({ ...snapshot, blobs: snapshot.blobs.map(file => file.path.startsWith('netlify/functions/') ? { ...file, bytes: large } : file) }), /SOURCE_SIZE/);
  const excess = Array.from({ length: 129 }, (_, index) => ({ ...snapshot.blobs[0], path: `netlify/functions/_shared/example-${String(index).replace(/\d/g, digit => String.fromCharCode(97 + Number(digit)))}.mjs` }));
  assert.throws(() => selectFunctionRecipeInput({ ...snapshot, blobs: [...snapshot.blobs, ...excess] }), /SOURCE_LAYOUT/);
  // Untracked/ignored files and tracked working-tree overlays cannot be exported.
  await write(path.join(candidateDirectory, '.env'), 'FIXTURE_NOT_A_REAL_SECRET=private\n');
  await write(path.join(candidateDirectory, 'ignored.mjs'), 'untracked input\n');
  await fs.unlink(path.join(candidateDirectory, 'platform-config.js'));
  await fs.symlink(path.join(candidateDirectory, 'ignored.mjs'), path.join(candidateDirectory, 'platform-config.js'));
  let serial = 0;
  const options = { candidateDirectory, candidateCommit };
  const prepare = changes => materializeFunctionRecipeInput({ ...options, outputDirectory: path.join(root, `output-${++serial}`), ...changes }, { env: {} });
  const outputDirectory = path.join(root, 'prepared');
  const prepared = await prepare({ outputDirectory });
  const manifestBytes = await fs.readFile(prepared.inputManifestPath);
  assert.deepEqual(manifestBytes, selected.manifestBytes);
  assert.equal(prepared.inputManifestSha256, sha256(manifestBytes));
  assert.deepEqual(Object.keys(prepared.manifest).sort(), ['declaredGitCommit', 'files', 'schema']);
  for (const [name, bytes] of sourceBytes) {
    const filename = path.join(prepared.sourceDirectory, name);
    assert.deepEqual(await fs.readFile(filename), bytes);
    const stat = await fs.stat(filename);
    assert.equal(stat.nlink, 1); assert.equal(stat.mode & 0o777, 0o600);
  }
  for (const name of ['.git', '.env', 'package.json', 'ignored.mjs']) await absent(path.join(prepared.sourceDirectory, name));
  assert.equal((await fs.stat(outputDirectory)).mode & 0o777, 0o700);
  await assert.rejects(prepare({ outputDirectory }), /CNYOS_FUNCTION_INPUT_IO_FAILURE/);
  assert.deepEqual(await fs.readFile(prepared.inputManifestPath), manifestBytes);
  await assert.rejects(prepare({ outputDirectory: path.join(candidateDirectory, 'bad') }), /OUTPUT_PATH/);
  const outputLink = path.join(root, 'output-link');
  await fs.symlink(outputDirectory, outputLink);
  await assert.rejects(prepare({ outputDirectory: outputLink }), /IO_FAILURE/);
  const parentLink = path.join(root, 'parent-link');
  await fs.symlink(root, parentLink);
  await assert.rejects(prepare({ outputDirectory: path.join(parentLink, 'bad') }), /DIRECTORY/);
  const credentialOutput = path.join(root, 'credentials');
  await assert.rejects(materializeFunctionRecipeInput({ ...options, outputDirectory: credentialOutput }, { env: { GH_TOKEN: 'fixture-only' } }), /CREDENTIAL/);
  await absent(credentialOutput);

  // Exercise the real preparation -> existing comparison/archive consumer path.
  const buildDirs = [path.join(root, 'first'), path.join(root, 'second')];
  const outputFiles = [];
  for (const name of EXPECTED_FUNCTION_NAMES) {
    for (const relative of ['___netlify-entry-point.mjs', '___netlify-bootstrap.mjs', `netlify/functions/${name}.mjs`]) {
      const namePath = `${name}/${relative}`; const bytes = Buffer.from(`// inert output ${namePath}\n`);
      for (const directory of buildDirs) await write(path.join(directory, 'functions', namePath), bytes);
      outputFiles.push({ path: namePath, size: bytes.length, sha256: sha256(bytes) });
    }
  }
  outputFiles.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const recipePath = path.join(root, 'recipe.mjs'); const dependencyLockPath = path.join(root, 'lock.json');
  const recipe = Buffer.from('throw new Error("no recipe execution");\n'); const lock = Buffer.from('{}\n');
  await write(recipePath, recipe); await write(dependencyLockPath, lock);
  const observation = { schema: 'cnyos-candidate-function-build-observation/v1', execution: 'injected-test-double',
    declaredGitCommit: candidateCommit, inputManifestSha256: prepared.inputManifestSha256, sourceFiles: prepared.manifest.files,
    toolchainLockSha256: sha256(lock), outputFiles };
  for (const directory of buildDirs) await write(path.join(directory, 'candidate-build.json'), encode(observation));
  const handoff = await createFunctionComparisonHandoff({ ...options, firstBuildDirectory: buildDirs[0], secondBuildDirectory: buildDirs[1],
    inputManifestPath: prepared.inputManifestPath, recipePath, dependencyLockPath, expectedInputManifestSha256: prepared.inputManifestSha256,
    expectedRecipeSha256: sha256(recipe), expectedDependencyLockSha256: sha256(lock), outputDirectory: path.join(root, 'handoff') });
  assert.equal(handoff.files.length, EXPECTED_FUNCTION_NAMES.length); assert.equal(handoff.authorization, false); assert.equal(handoff.producerEligible, false);

  const cliOutput = path.join(root, 'cli');
  const args = ['--candidate-directory', candidateDirectory, '--candidate-commit', candidateCommit, '--output-directory', cliOutput];
  assert.deepEqual(parseFunctionRecipeInputArguments(args), { ...options, outputDirectory: cliOutput });
  assert.throws(() => parseFunctionRecipeInputArguments([...args, '--activate']), /ARGUMENTS/);
  const child = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent' } });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.stderr, '');
  assert.equal(child.stdout, JSON.stringify({ kind: 'immutable-function-recipe-input', fileCount: EXPECTED_FUNCTION_NAMES.length + 2,
    inputManifestSha256: prepared.inputManifestSha256 }) + '\n');
  assert.equal(child.stdout.includes(root), false);
  const deniedCliOutput = path.join(root, 'cli-denied');
  const denied = spawnSync(process.execPath, [script, ...args.slice(0, 5), deniedCliOutput], {
    encoding: 'utf8', env: { PATH: '/usr/bin:/bin', GH_TOKEN: 'fixture-private-sentinel' }
  });
  assert.equal(denied.status, 1); assert.equal(denied.stdout, '');
  assert.match(denied.stderr, /^CNYOS_FUNCTION_BUNDLE_[A-Z_]+\n$/);
  assert.equal(denied.stderr.includes('sentinel'), false);
  await absent(deniedCliOutput);

  const originalOpen = fs.open;
  for (const failure of ['source-write', 'parent-sync', 'manifest-sync', 'final-directory-sync']) {
    const partial = path.join(root, failure); let rootSyncs = 0;
    fs.open = async (filename, ...args) => {
      if (failure === 'source-write' && filename.endsWith('/source/platform-config.js') && filename.startsWith(partial)) throw new Error(`private sentinel ${root}`);
      const handle = await originalOpen(filename, ...args);
      if ((failure === 'parent-sync' && filename === root) ||
        (failure === 'manifest-sync' && filename === path.join(partial, 'input-manifest.json') && args[0] === 'wx') ||
        (failure === 'final-directory-sync' && filename === partial && ++rootSyncs === 2)) handle.sync = async () => { throw new Error(`private sentinel ${root}`); };
      return handle;
    };
    try { await assert.rejects(prepare({ outputDirectory: partial }), error => { assert.equal(error.message, 'CNYOS_FUNCTION_INPUT_IO_FAILURE'); return true; }); }
    finally { fs.open = originalOpen; }
    await absent(path.join(partial, 'input-manifest.json'));
  }
  // Source-layout failures are actual committed Git inputs, not runtime execution.
  await fs.unlink(path.join(candidateDirectory, 'platform-config.js'));
  await write(path.join(candidateDirectory, 'platform-config.js'), sourceBytes.get('platform-config.js'));
  await write(path.join(candidateDirectory, 'netlify/functions/_shared/unsupported.json'), '{}\n');
  await assert.rejects(prepare({ candidateCommit: commit() }), /SOURCE_LAYOUT/);
  await fs.unlink(path.join(candidateDirectory, 'netlify/functions/_shared/unsupported.json'));
  await fs.symlink('platform-config.js', path.join(candidateDirectory, 'tracked-link'));
  await assert.rejects(prepare({ candidateCommit: commit() }), /NON_REGULAR_GIT_ENTRY/);
  await fs.unlink(path.join(candidateDirectory, 'tracked-link'));
  await fs.unlink(path.join(candidateDirectory, 'platform-config.js'));
  await assert.rejects(prepare({ candidateCommit: commit() }), /SOURCE_LAYOUT/);
  assert.deepEqual(await fs.readFile(prepared.inputManifestPath), manifestBytes);
  console.log('CNYOS Function recipe input filesystem contract: passed');
} finally {
  // Only this test's uniquely allocated fixture tree is removed.
  await fs.rm(root, { recursive: true, force: true });
}
