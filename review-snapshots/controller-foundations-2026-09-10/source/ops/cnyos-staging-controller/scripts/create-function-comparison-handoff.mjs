// A local, comparison-only handoff. No compiler, candidate module, provider,
// approval or protected producer is executed. Call only after both builders stop.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { sha256 } from './policy.mjs';
import { selectFunctionRecipeInput } from './materialize-function-recipe-input.mjs';
import {
  readFunctionBundleCandidateSnapshot, compareFunctionBundleDirectories,
  readFunctionBundleZipEntries
} from './controller-function-bundle.mjs';

const fail = code => { throw new Error(`CNYOS_FUNCTION_HANDOFF_${code}`); };
const same = (a, b) => ['dev', 'ino', 'size', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
const inside = (parent, child) => child === parent || child.startsWith(`${parent}${path.sep}`);
const order = (a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path));

async function directory(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value ||
    await fs.realpath(value) !== value || !(await fs.lstat(value)).isDirectory()) fail('DIRECTORY');
  return value;
}

async function readStable(filename, limit = 4 * 1024 * 1024) {
  if (!path.isAbsolute(filename) || path.resolve(filename) !== filename || await fs.realpath(filename) !== filename) fail('FILE_PATH');
  const before = await fs.lstat(filename, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(limit) || (before.mode & 0o7022n)) fail('FILE_TYPE_MODE_SIZE');
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !same(before, opened)) fail('FILE_CHANGED');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    if (used !== Number(before.size) || !same(before, await handle.stat({ bigint: true })) ||
      !same(before, await fs.lstat(filename, { bigint: true }))) fail('FILE_CHANGED');
    return bytes.subarray(0, used);
  } finally { await handle.close(); }
}

function json(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('JSON'); }
}

function sourceFiles(snapshot) {
  try { return selectFunctionRecipeInput(snapshot).files; }
  catch { fail('SOURCE_LAYOUT'); }
}

async function writeExclusive(filename, bytes) {
  const handle = await fs.open(filename, 'wx', 0o600);
  const identity = await handle.stat({ bigint: true });
  try { await handle.writeFile(bytes); await handle.sync(); return identity; }
  catch (error) {
    const current = await fs.lstat(filename, { bigint: true });
    if (current.dev === identity.dev && current.ino === identity.ino) await fs.unlink(filename);
    throw error;
  }
  finally { await handle.close(); }
}

/** Caller-supplied hashes are byte constraints, NOT trusted approvals or proof
 * that this recipe/lock actually executed. Observations remain untrusted claims.
 * On partial publication failure, leave owned partial ZIPs for inspection, never
 * delete a broad directory or replace existing output. No complete manifest is
 * written until all archives have been persisted, read back, and inputs fenced.
 */
export async function createFunctionComparisonHandoff(options) {
  try { return await createHandoff(options); }
  catch (error) {
    // Only closed-format controller enum errors leave this library. Native FS,
    // Git and decoder messages may contain private paths or command arguments.
    if (/^CNYOS_FUNCTION_(?:HANDOFF|BUNDLE)_[A-Z_]{1,96}$/.test(error?.message)) throw new Error(error.message);
    fail('IO_FAILURE');
  }
}

async function createHandoff({
  candidateDirectory, candidateCommit, firstBuildDirectory, secondBuildDirectory,
  inputManifestPath, recipePath, dependencyLockPath, expectedInputManifestSha256,
  expectedRecipeSha256, expectedDependencyLockSha256, outputDirectory
}) {
  const roots = await Promise.all([candidateDirectory, firstBuildDirectory, secondBuildDirectory].map(directory));
  if (roots.some((root, index) => roots.some((other, otherIndex) => index !== otherIndex && inside(root, other)))) fail('INPUT_OVERLAP');
  if (typeof outputDirectory !== 'string' || !path.isAbsolute(outputDirectory) || path.resolve(outputDirectory) !== outputDirectory ||
    roots.some(root => inside(root, outputDirectory) || inside(outputDirectory, root))) fail('OUTPUT_PATH');
  const parentDirectory = await directory(path.dirname(outputDirectory));
  const parentIdentity = await fs.lstat(parentDirectory, { bigint: true });
  const inputs = [inputManifestPath, recipePath, dependencyLockPath,
    path.join(firstBuildDirectory, 'candidate-build.json'), path.join(secondBuildDirectory, 'candidate-build.json')];
  if (inputs.some(filename => typeof filename !== 'string' || inside(outputDirectory, filename))) fail('OUTPUT_PATH');
  const originals = await Promise.all(inputs.map(filename => readStable(filename)));
  const expected = [expectedInputManifestSha256, expectedRecipeSha256, expectedDependencyLockSha256];
  if (expected.some((digest, index) => !/^[a-f0-9]{64}$/.test(digest) || sha256(originals[index]) !== digest)) fail('INPUT_DIGEST');
  const snapshot = await readFunctionBundleCandidateSnapshot(candidateDirectory, candidateCommit);
  const files = sourceFiles(snapshot);
  const input = json(originals[0]);
  if (!isDeepStrictEqual(input, { schema: 'cnyos-function-source-input/v1', declaredGitCommit: candidateCommit, files })) fail('IMMUTABLE_SOURCE_BINDING');
  const observations = originals.slice(3).map(json);
  for (const observation of observations) {
    if (!observation || observation.schema !== 'cnyos-candidate-function-build-observation/v1' ||
      !['local-zisi', 'injected-test-double'].includes(observation.execution) ||
      observation.declaredGitCommit !== candidateCommit || observation.inputManifestSha256 !== expectedInputManifestSha256 ||
      observation.toolchainLockSha256 !== expectedDependencyLockSha256 || !isDeepStrictEqual(observation.sourceFiles, files)) fail('OBSERVATION_BINDING');
  }
  const archives = await compareFunctionBundleDirectories(
    path.join(firstBuildDirectory, 'functions'), path.join(secondBuildDirectory, 'functions'));
  const actualFiles = archives.flatMap(archive => readFunctionBundleZipEntries(archive.bytes).map(file => ({
    path: `${archive.path.slice(0, -4)}/${file.path}`, size: file.bytes.length, sha256: sha256(file.bytes)
  }))).sort(order);
  if (observations.some(observation => !isDeepStrictEqual(observation.outputFiles, actualFiles))) fail('OBSERVATION_OUTPUT');

  async function fenceInputs() {
    for (let index = 0; index < inputs.length; index++) {
      if (!(await readStable(inputs[index])).equals(originals[index])) fail('INPUT_CHANGED');
    }
    const current = await readFunctionBundleCandidateSnapshot(candidateDirectory, candidateCommit);
    if (current.candidateTree !== snapshot.candidateTree || !isDeepStrictEqual(sourceFiles(current), files)) fail('SOURCE_CHANGED');
  }
  await fenceInputs();
  // mkdir is exclusive: an existing directory, file or symlink is never reused.
  await fs.mkdir(outputDirectory, { mode: 0o700 });
  const outputIdentity = await fs.lstat(outputDirectory, { bigint: true });
  async function outputStillOwned() {
    const current = await fs.lstat(outputDirectory, { bigint: true });
    if (!current.isDirectory() || current.dev !== outputIdentity.dev || current.ino !== outputIdentity.ino ||
      current.mode !== outputIdentity.mode || await fs.realpath(outputDirectory) !== outputDirectory) fail('OUTPUT_CHANGED');
  }
  for (const archive of archives) {
    await outputStillOwned();
    await writeExclusive(path.join(outputDirectory, archive.path), archive.bytes);
  }
  for (const archive of archives) {
    if (!(await readStable(path.join(outputDirectory, archive.path), 32 * 1024 * 1024)).equals(archive.bytes)) fail('OUTPUT_CHANGED');
  }
  if (!isDeepStrictEqual((await fs.readdir(outputDirectory)).sort(), archives.map(file => file.path).sort())) fail('OUTPUT_CHANGED');
  await fenceInputs();
  await outputStillOwned();
  const directoryHandle = await fs.open(outputDirectory, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  // Persist the fresh output directory's name in its parent before publishing
  // completion; syncing the child alone does not persist that parent entry.
  if (await fs.realpath(parentDirectory) !== parentDirectory) fail('OUTPUT_CHANGED');
  const parentHandle = await fs.open(parentDirectory, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await parentHandle.stat({ bigint: true });
    if (!current.isDirectory() || current.dev !== parentIdentity.dev || current.ino !== parentIdentity.ino) fail('OUTPUT_CHANGED');
    await parentHandle.sync();
  } finally { await parentHandle.close(); }
  const manifest = {
    schema: 'cnyos-function-comparison-handoff/v1', authorization: false, producerEligible: false,
    candidateCommit, candidateTree: snapshot.candidateTree, functionSourceTree: snapshot.functionSourceTree,
    sourceFiles: files, inputManifestSha256: expectedInputManifestSha256,
    comparedRecipeSha256: expectedRecipeSha256, comparedDependencyLockSha256: expectedDependencyLockSha256,
    observations: originals.slice(3).map((bytes, index) => ({ sha256: sha256(bytes), declaredExecution: observations[index].execution })),
    files: archives.map(({ path, size, sha256 }) => ({ path, size, sha256 })),
    limitations: ['Only the supplied output byte snapshots were compared',
      'Recipe and lock hashes identify supplied bytes, not attested execution',
      'No independent build, isolation, import closure, approval or release eligibility is established']
  };
  const manifestPath = path.join(outputDirectory, 'comparison-handoff.json');
  await outputStillOwned();
  const manifestIdentity = await writeExclusive(manifestPath, Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`));
  try {
    await outputStillOwned();
    const finalDirectoryHandle = await fs.open(outputDirectory, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await finalDirectoryHandle.sync(); } finally { await finalDirectoryHandle.close(); }
  } catch (error) {
    // Remove only our exact completion file on an ambiguous durability failure.
    const current = await fs.lstat(manifestPath, { bigint: true });
    if (current.dev === manifestIdentity.dev && current.ino === manifestIdentity.ino) await fs.unlink(manifestPath);
    throw error;
  }
  return manifest;
}
