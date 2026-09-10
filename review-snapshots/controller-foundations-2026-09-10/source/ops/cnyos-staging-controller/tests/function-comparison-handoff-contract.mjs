import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createFunctionComparisonHandoff } from '../scripts/create-function-comparison-handoff.mjs';
import { EXPECTED_FUNCTION_NAMES, sha256 } from '../scripts/policy.mjs';
import { readFunctionBundleZipEntries } from '../scripts/controller-function-bundle.mjs';

const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'cnyos-function-handoff-'));
const write = async (filename, bytes) => {
  await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  await fs.writeFile(filename, bytes, { mode: 0o600 });
};
const encode = object => Buffer.from(`${JSON.stringify(object)}\n`);
const git = (cwd, args) => execFileSync('/usr/bin/git', args, { cwd, encoding: 'utf8',
  env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Offline Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
    GIT_COMMITTER_NAME: 'Offline Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const absent = async filename => {
  await assert.rejects(fs.lstat(filename), error => error.code === 'ENOENT');
};

try {
  const candidateDirectory = path.join(root, 'candidate');
  await fs.mkdir(candidateDirectory, { mode: 0o700 });
  git(candidateDirectory, ['init', '--quiet']);
  const sourceFiles = [];
  for (const name of EXPECTED_FUNCTION_NAMES) {
    const relative = `netlify/functions/${name}.mts`;
    const bytes = Buffer.from(`// inert source fixture: ${name}\n`);
    await write(path.join(candidateDirectory, relative), bytes);
    sourceFiles.push({ path: relative, sha256: sha256(bytes) });
  }
  const platform = Buffer.from('// immutable platform fixture\n');
  await write(path.join(candidateDirectory, 'platform-config.js'), platform);
  sourceFiles.push({ path: 'platform-config.js', sha256: sha256(platform) });
  sourceFiles.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  git(candidateDirectory, ['add', '.']);
  git(candidateDirectory, ['-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'inert source fixture']);
  const candidateCommit = git(candidateDirectory, ['rev-parse', 'HEAD']);
  const inputManifestPath = path.join(root, 'input.json');
  const recipePath = path.join(root, 'recipe.mjs');
  const dependencyLockPath = path.join(root, 'lock.json');
  const input = { schema: 'cnyos-function-source-input/v1', declaredGitCommit: candidateCommit, files: sourceFiles };
  const inputBytes = encode(input);
  // These fixture bytes must never be imported. Hashing them proves no execution.
  const recipeBytes = Buffer.from('throw new Error("fixture must not execute");\n');
  const lockBytes = Buffer.from('{"lockfileVersion":3,"packages":{}}\n');
  await write(inputManifestPath, inputBytes);
  await write(recipePath, recipeBytes);
  await write(dependencyLockPath, lockBytes);
  const firstBuildDirectory = path.join(root, 'first');
  const secondBuildDirectory = path.join(root, 'second');
  const outputFiles = [];
  const outputContents = new Map();
  for (const name of EXPECTED_FUNCTION_NAMES) {
    for (const relative of ['___netlify-entry-point.mjs', '___netlify-bootstrap.mjs', `netlify/functions/${name}.mjs`]) {
      const outputPath = `${name}/${relative}`;
      const bytes = Buffer.from(`// inert output fixture: ${outputPath}\n`);
      outputContents.set(outputPath, bytes);
      outputFiles.push({ path: outputPath, size: bytes.length, sha256: sha256(bytes) });
      for (const build of [firstBuildDirectory, secondBuildDirectory]) await write(path.join(build, 'functions', outputPath), bytes);
    }
  }
  outputFiles.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const observation = { schema: 'cnyos-candidate-function-build-observation/v1', execution: 'injected-test-double',
    declaredGitCommit: candidateCommit, inputManifestSha256: sha256(inputBytes),
    toolchainLockSha256: sha256(lockBytes), sourceFiles, outputFiles };
  const observationBytes = encode(observation);
  for (const build of [firstBuildDirectory, secondBuildDirectory]) await write(path.join(build, 'candidate-build.json'), observationBytes);
  const options = { candidateDirectory, candidateCommit, firstBuildDirectory, secondBuildDirectory,
    inputManifestPath, recipePath, dependencyLockPath, expectedInputManifestSha256: sha256(inputBytes),
    expectedRecipeSha256: sha256(recipeBytes), expectedDependencyLockSha256: sha256(lockBytes) };
  let serial = 0;
  const attempt = (changes = {}) => createFunctionComparisonHandoff({ ...options, outputDirectory: path.join(root, `output-${++serial}`), ...changes });
  const outputDirectory = path.join(root, 'complete');
  const result = await attempt({ outputDirectory });
  assert.equal(result.schema, 'cnyos-function-comparison-handoff/v1');
  assert.equal(result.authorization, false);
  assert.equal(result.producerEligible, false);
  for (const forbidden of ['evidenceType', 'importClosureComplete', 'externalImportsResolvedFromLock', 'netlifyCliVersion', 'controllerRunId']) assert.equal(Object.hasOwn(result, forbidden), false);
  assert.deepEqual(result.observations.map(item => item.declaredExecution), ['injected-test-double', 'injected-test-double']);
  assert.equal(result.files.length, 11);
  assert.equal((await fs.stat(outputDirectory)).mode & 0o777, 0o700);
  for (const archive of result.files) {
    const filename = path.join(outputDirectory, archive.path);
    const bytes = await fs.readFile(filename);
    assert.equal(sha256(bytes), archive.sha256);
    assert.equal(bytes.length, archive.size);
    assert.equal((await fs.stat(filename)).mode & 0o777, 0o600);
    for (const file of readFunctionBundleZipEntries(bytes)) assert.deepEqual(file.bytes, outputContents.get(`${archive.path.slice(0, -4)}/${file.path}`));
  }
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(outputDirectory, 'comparison-handoff.json'), 'utf8')), result);
  const retainedManifest = await fs.readFile(path.join(outputDirectory, 'comparison-handoff.json'));
  await assert.rejects(attempt({ outputDirectory }), /^Error: CNYOS_FUNCTION_HANDOFF_IO_FAILURE$/);
  assert.deepEqual(await fs.readFile(path.join(outputDirectory, 'comparison-handoff.json')), retainedManifest);
  await assert.rejects(attempt({ secondBuildDirectory: firstBuildDirectory }), /INPUT_OVERLAP/);
  await assert.rejects(attempt({ outputDirectory: path.join(candidateDirectory, 'output') }), /OUTPUT_PATH/);
  for (const key of ['expectedInputManifestSha256', 'expectedRecipeSha256', 'expectedDependencyLockSha256']) await assert.rejects(attempt({ [key]: '0'.repeat(64) }), /INPUT_DIGEST/);

  // An internally self-consistent input claim cannot substitute different source.
  const wrongInput = encode({ ...input, files: sourceFiles.map(file => file.path === 'platform-config.js' ? { ...file, sha256: '0'.repeat(64) } : file) });
  await write(inputManifestPath, wrongInput);
  await assert.rejects(attempt({ expectedInputManifestSha256: sha256(wrongInput) }), /IMMUTABLE_SOURCE_BINDING/);
  await write(inputManifestPath, inputBytes);
  // Ambient checkout changes are not read as source inputs.
  await write(path.join(candidateDirectory, 'platform-config.js'), 'ambient changed bytes');
  await attempt();

  const observationPath = path.join(secondBuildDirectory, 'candidate-build.json');
  for (const change of [{ declaredGitCommit: '0'.repeat(40) }, { toolchainLockSha256: '0'.repeat(64) },
    { inputManifestSha256: '0'.repeat(64) }, { sourceFiles: [] }, { execution: 'approved' }]) {
    await write(observationPath, encode({ ...observation, ...change }));
    await assert.rejects(attempt(), /OBSERVATION_BINDING/);
  }
  await write(observationPath, encode({ ...observation, outputFiles: outputFiles.slice(1) }));
  await assert.rejects(attempt(), /OBSERVATION_OUTPUT/);
  await write(observationPath, observationBytes);
  const firstOutputPath = outputFiles[0].path;
  const changedOutput = path.join(secondBuildDirectory, 'functions', firstOutputPath);
  await write(changedOutput, 'different bytes');
  await assert.rejects(attempt(), /BUILD_BYTES_DIFFER/);
  await write(changedOutput, outputContents.get(firstOutputPath));
  await fs.unlink(changedOutput);
  await fs.symlink(path.join(firstBuildDirectory, 'functions', firstOutputPath), changedOutput);
  await assert.rejects(attempt(), /BUILD_OUTPUT_INVALID/);
  await fs.unlink(changedOutput);
  await write(changedOutput, outputContents.get(firstOutputPath));

  // Controlled IO failures exercise fencing and durability without concurrency,
  // candidate execution, network, or destructive changes outside this fixture.
  const originalOpen = fs.open;
  for (const failure of ['archive-write', 'parent-directory-sync', 'final-directory-sync']) {
    const partial = path.join(root, failure);
    let directorySyncs = 0;
    fs.open = async (filename, ...args) => {
      if (failure === 'archive-write' && filename === path.join(partial, result.files[1].path)) throw new Error(`private fixture sentinel: ${root}/secret-name`);
      const handle = await originalOpen(filename, ...args);
      if (filename === root && failure === 'parent-directory-sync') handle.sync = async () => { throw new Error(`private fixture sentinel: ${root}/secret-name`); };
      if (filename === partial && failure === 'final-directory-sync' && ++directorySyncs === 2) handle.sync = async () => { throw new Error('fixture sync failure'); };
      return handle;
    };
    try { await assert.rejects(attempt({ outputDirectory: partial }), error => {
      assert.equal(error.message, 'CNYOS_FUNCTION_HANDOFF_IO_FAILURE');
      assert.equal(error.message.includes(root), false);
      assert.equal(error.message.includes('sentinel'), false);
      return true;
    }); }
    finally { fs.open = originalOpen; }
    await absent(path.join(partial, 'comparison-handoff.json'));
  }
  const originalMkdir = fs.mkdir;
  const fenced = path.join(root, 'fenced');
  fs.mkdir = async (filename, ...args) => {
    const value = await originalMkdir(filename, ...args);
    if (filename === fenced) await fs.writeFile(observationPath, encode({ ...observation, execution: 'local-zisi' }));
    return value;
  };
  try { await assert.rejects(attempt({ outputDirectory: fenced }), /INPUT_CHANGED/); }
  finally { fs.mkdir = originalMkdir; }
  await absent(path.join(fenced, 'comparison-handoff.json'));
  assert.deepEqual(await fs.readFile(recipePath), recipeBytes);
  assert.deepEqual(await fs.readFile(dependencyLockPath), lockBytes);
  assert.equal(git(candidateDirectory, ['rev-parse', 'HEAD']), candidateCommit);
  console.log('CNYOS Function comparison handoff filesystem contract: passed');
} finally {
  // This test alone owns the mkdtemp directory and all descendants.
  await fs.rm(root, { recursive: true, force: true });
}
