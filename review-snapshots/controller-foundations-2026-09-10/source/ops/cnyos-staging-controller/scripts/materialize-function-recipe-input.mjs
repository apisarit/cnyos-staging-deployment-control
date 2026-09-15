// Immutable local source preparation only. Never imports candidate code, runs a
// compiler, contacts a provider, or enables a protected controller entrypoint.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, EXPECTED_FUNCTION_NAMES } from './policy.mjs';
import { readFunctionBundleCandidateSnapshot, assertFunctionBundleCredentialFree } from './controller-function-bundle.mjs';

const fail = code => { throw new Error(`CNYOS_FUNCTION_INPUT_${code}`); };
const inside = (parent, child) => child === parent || child.startsWith(`${parent}${path.sep}`);
const order = (a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path));
const sameObject = (a, b) => a.dev === b.dev && a.ino === b.ino && a.mode === b.mode;
const sameFile = (a, b) => sameObject(a, b) && ['nlink', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);

// Only call with the controller's verified immutable Git snapshot. The selector
// enforces the recipe's exact format and bounds; it does not authenticate callers.
export function selectFunctionRecipeInput(snapshot) {
  if (!snapshot || !/^[a-f0-9]{40}$/.test(snapshot.candidateCommit) || !Array.isArray(snapshot.blobs)) fail('SNAPSHOT');
  const blobs = snapshot.blobs.filter(file => file.path?.startsWith('netlify/functions/') || file.path === 'platform-config.js');
  const names = new Set();
  let total = 0;
  for (const file of blobs) {
    if (!(file.path === 'platform-config.js' || EXPECTED_FUNCTION_NAMES.some(name => file.path === `netlify/functions/${name}.mts`) ||
      /^netlify\/functions\/_shared\/[a-z][a-z0-9-]*\.mjs$/.test(file.path)) || names.has(file.path)) fail('SOURCE_LAYOUT');
    names.add(file.path);
    if (!['100644', '100755'].includes(file.mode) || !Buffer.isBuffer(file.bytes)) fail('SOURCE_TYPE');
    total += file.bytes.length;
    if (file.bytes.length > 16 * 1024 * 1024 || total > 64 * 1024 * 1024) fail('SOURCE_SIZE');
  }
  if (blobs.length < 12 || blobs.length > 128 || !names.has('platform-config.js') ||
    EXPECTED_FUNCTION_NAMES.some(name => !names.has(`netlify/functions/${name}.mts`))) fail('SOURCE_LAYOUT');
  blobs.sort(order);
  const files = blobs.map(file => ({ path: file.path, sha256: sha256(file.bytes) }));
  const manifest = { schema: 'cnyos-function-source-input/v1', declaredGitCommit: snapshot.candidateCommit, files };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  if (manifestBytes.length > 128 * 1024) fail('MANIFEST_SIZE');
  return { blobs, files, manifest, manifestBytes, totalBytes: total };
}

async function directory(filename) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || path.resolve(filename) !== filename ||
    await fs.realpath(filename) !== filename) fail('DIRECTORY');
  const identity = await fs.lstat(filename, { bigint: true });
  if (!identity.isDirectory()) fail('DIRECTORY');
  return identity;
}

export function parseFunctionRecipeInputArguments(args) {
  if (args.length !== 6 || args[0] !== '--candidate-directory' || args[2] !== '--candidate-commit' || args[4] !== '--output-directory' ||
    !/^[a-f0-9]{40}$/.test(args[3]) || [args[1], args[5]].some(value => !path.isAbsolute(value) || path.resolve(value) !== value)) fail('ARGUMENTS');
  return { candidateDirectory: args[1], candidateCommit: args[3], outputDirectory: args[5] };
}

export async function materializeFunctionRecipeInput(options, { env = process.env } = {}) {
  try { return await materialize(options, env); }
  catch (error) {
    if (/^CNYOS_FUNCTION_(?:INPUT|BUNDLE)_[A-Z_]{1,96}$/.test(error?.message)) throw new Error(error.message);
    fail('IO_FAILURE');
  }
}

async function materialize({ candidateDirectory, candidateCommit, outputDirectory }, env) {
  assertFunctionBundleCredentialFree(env);
  await directory(candidateDirectory);
  if (typeof outputDirectory !== 'string' || !path.isAbsolute(outputDirectory) || path.resolve(outputDirectory) !== outputDirectory ||
    inside(candidateDirectory, outputDirectory) || inside(outputDirectory, candidateDirectory)) fail('OUTPUT_PATH');
  const parent = path.dirname(outputDirectory);
  const parentIdentity = await directory(parent);
  const snapshot = await readFunctionBundleCandidateSnapshot(candidateDirectory, candidateCommit);
  const selected = selectFunctionRecipeInput(snapshot);
  const directories = new Map();
  const written = new Map();
  const manifestPath = path.join(outputDirectory, 'input-manifest.json');

  async function assertDirectory(filename, expected) {
    if (!sameObject(await directory(filename), expected)) fail('OUTPUT_CHANGED');
  }
  async function makeDirectory(filename) {
    await fs.mkdir(filename, { mode: 0o700 }); // exclusive, never reuse a directory
    directories.set(filename, await directory(filename));
  }
  async function writeFile(filename, bytes) {
    await assertDirectory(path.dirname(filename), directories.get(path.dirname(filename)));
    const handle = await fs.open(filename, 'wx', 0o600);
    try {
      written.set(filename, await handle.stat({ bigint: true }));
      await handle.writeFile(bytes);
      await handle.sync();
    } finally { await handle.close(); }
  }
  async function verifyFile(filename, bytes) {
    if (await fs.realpath(filename) !== filename) fail('OUTPUT_CHANGED');
    const before = await fs.lstat(filename, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || !sameObject(before, written.get(filename)) || before.size !== BigInt(bytes.length)) fail('OUTPUT_CHANGED');
    const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      if (!sameFile(before, await handle.stat({ bigint: true }))) fail('OUTPUT_CHANGED');
      const actual = Buffer.alloc(bytes.length + 1);
      let offset = 0;
      while (offset < actual.length) {
        const { bytesRead } = await handle.read(actual, offset, actual.length - offset, null);
        if (!bytesRead) break;
        offset += bytesRead;
      }
      if (offset !== bytes.length || !actual.subarray(0, offset).equals(bytes) || !sameFile(before, await handle.stat({ bigint: true })) ||
        !sameFile(before, await fs.lstat(filename, { bigint: true }))) fail('OUTPUT_CHANGED');
    } finally { await handle.close(); }
  }
  async function syncDirectory(filename, identity) {
    await assertDirectory(filename, identity);
    const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      if (!sameObject(await handle.stat({ bigint: true }), identity)) fail('OUTPUT_CHANGED');
      await handle.sync();
    } finally { await handle.close(); }
  }
  await makeDirectory(outputDirectory);
  try {
    const source = path.join(outputDirectory, 'source');
    await makeDirectory(source);
    for (const blob of selected.blobs) {
      const segments = blob.path.split('/');
      let ancestor = source;
      for (const segment of segments.slice(0, -1)) {
        await assertDirectory(ancestor, directories.get(ancestor));
        ancestor = path.join(ancestor, segment);
        if (!directories.has(ancestor)) await makeDirectory(ancestor);
      }
      await writeFile(path.join(source, blob.path), blob.bytes);
    }
    for (const blob of selected.blobs) await verifyFile(path.join(source, blob.path), blob.bytes);
    // Assert exact contents, including directories; do not silently export extras.
    for (const [filename, identity] of directories) {
      await assertDirectory(filename, identity);
      const expected = [...directories.keys(), ...written.keys()].filter(item => item !== filename && path.dirname(item) === filename).map(item => path.basename(item)).sort();
      if (JSON.stringify((await fs.readdir(filename)).sort()) !== JSON.stringify(expected)) fail('OUTPUT_CHANGED');
    }
    const current = await readFunctionBundleCandidateSnapshot(candidateDirectory, candidateCommit);
    if (current.candidateTree !== snapshot.candidateTree || !selectFunctionRecipeInput(current).manifestBytes.equals(selected.manifestBytes)) fail('SOURCE_CHANGED');
    for (const [filename, identity] of [...directories].reverse()) await syncDirectory(filename, identity);
    await syncDirectory(parent, parentIdentity);
    await writeFile(manifestPath, selected.manifestBytes);
    await verifyFile(manifestPath, selected.manifestBytes);
    await syncDirectory(outputDirectory, directories.get(outputDirectory));
    return { manifest: selected.manifest, inputManifestSha256: sha256(selected.manifestBytes), candidateTree: snapshot.candidateTree,
      sourceDirectory: source, inputManifestPath: manifestPath };
  } catch (error) {
    // Keep partial source files for diagnosis. Remove only this invocation's exact
    // manifest inode: neither broad cleanup nor another caller's existing data.
    const identity = written.get(manifestPath);
    if (identity) {
      const current = await fs.lstat(manifestPath, { bigint: true });
      if (sameObject(current, identity)) await fs.unlink(manifestPath);
    }
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await materializeFunctionRecipeInput(parseFunctionRecipeInputArguments(process.argv.slice(2)));
    process.stdout.write(JSON.stringify({ kind: 'immutable-function-recipe-input', fileCount: result.manifest.files.length,
      inputManifestSha256: result.inputManifestSha256 }) + '\n');
  } catch (error) {
    const code = /^CNYOS_FUNCTION_(?:INPUT|BUNDLE)_[A-Z_]{1,96}$/.test(error?.message) ? error.message : 'CNYOS_FUNCTION_INPUT_IO_FAILURE';
    process.stderr.write(code + '\n'); process.exitCode = 1;
  }
}
