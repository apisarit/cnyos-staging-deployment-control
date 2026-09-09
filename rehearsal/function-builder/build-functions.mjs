// Candidate recipe, NOT a controller producer or an isolation/approval mechanism.
// Run only inside a credential-free, network-disabled, resource-bounded Linux
// worker with read-only input/toolchain mounts. Never execute application output.
// API source: netlify/build@d30dc9ad0c79ea23f01354f2487187d3398f5de2.
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve, isAbsolute, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const FUNCTIONS = Object.freeze([
  'account-access', 'database-backup', 'database-backup-background',
  'database-backup-recovery', 'evidence-search', 'line-oa-webhook', 'owner-drive',
  'owner-subscription', 'patient-identity', 'platform-console', 'restore-source',
]);
const PINS = Object.freeze({ '@netlify/blobs': '10.7.13', '@netlify/zip-it-and-ship-it': '15.5.1', qrcode: '1.5.4' });
const LOCK_SHA256 = 'f9d030d772c2c1518a1bdc4ceb5124ed8c3d23753d041b964cf1ee783410c286';
const HERE = dirname(fileURLToPath(import.meta.url));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code) => { throw new Error(`CNYOS_CANDIDATE_${code}`); };
const inside = (parent, child) => child === parent || child.startsWith(`${parent}${sep}`);
const sorted = (values) => [...values].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
const same = (a, b) => ['dev', 'ino', 'size', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'].every((key) => a[key] === b[key]);

async function directory(path) {
  if (!isAbsolute(path) || resolve(path) !== path || await fs.realpath(path) !== path || !(await fs.lstat(path)).isDirectory()) fail('DIRECTORY');
  return path;
}

async function readRegular(path, maximum = 16 * 1024 * 1024, stage = 'input-or-metadata') {
  if (await fs.realpath(path) !== path) throw new Error(JSON.stringify({ code: 'CNYOS_CANDIDATE_FILE_PATH', stage }));
  const before = await fs.lstat(path, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum) || (before.mode & 0o7022n)) fail('FILE_TYPE_MODE_OR_SIZE');
  const handle = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!same(before, await handle.stat({ bigint: true }))) fail('FILE_CHANGED');
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== Number(before.size) || !same(before, await handle.stat({ bigint: true })) || !same(before, await fs.lstat(path, { bigint: true }))) fail('FILE_CHANGED');
    return buffer.subarray(0, offset);
  } finally { await handle.close(); }
}

export async function materializeDependencies(source, destination) {
  // NFT traces filesystem links and ZISI preserves their original targets.
  // Copy the pinned, read-only installed tree instead of linking across roots.
  // This is byte materialization, not package installation or import execution.
  await directory(source);
  if (!isAbsolute(destination) || resolve(destination) !== destination || inside(source, destination) || inside(destination, source)) fail('DEPENDENCY_DESTINATION');
  await directory(dirname(destination));
  let entries = 0;
  let total = 0;
  async function visit(from, to) {
    await directory(from);
    await fs.mkdir(to, { mode: 0o700 });
    const reader = await fs.opendir(from);
    for await (const item of reader) {
      if (++entries > 50000 || !/^[A-Za-z0-9_.@+-]+$/.test(item.name) || item.name === '.' || item.name === '..') fail('DEPENDENCY_ENTRY');
      const input = join(from, item.name);
      // Omit only npm's verified Unix command-shim directories at dependency
      // boundaries. An application package's ordinary data/.bin is not omitted.
      if (basename(from) === 'node_modules' && item.name === '.bin') {
        await directory(input);
        const shims = await fs.opendir(input);
        for await (const shim of shims) {
          if (++entries > 50000 || !/^[A-Za-z0-9_.+-]+$/.test(shim.name)) fail('DEPENDENCY_SHIM');
          const shimPath = join(input, shim.name);
          const status = await fs.lstat(shimPath);
          const target = await fs.realpath(shimPath);
          if (!status.isSymbolicLink() || !inside(source, target) || !(await fs.lstat(target)).isFile()) fail('DEPENDENCY_SHIM');
        }
        continue;
      }
      const status = await fs.lstat(input, { bigint: true });
      if (status.isDirectory()) await visit(input, join(to, item.name));
      else {
        const bytes = await readRegular(input, 32 * 1024 * 1024, 'dependency-materialization');
        total += bytes.length;
        if (total > 384 * 1024 * 1024) fail('DEPENDENCY_SIZE');
        await fs.writeFile(join(to, item.name), bytes, { flag: 'wx', mode: (status.mode & 0o111n) ? 0o700 : 0o600 });
      }
    }
  }
  await visit(source, destination);
}

export function parseInputManifest(bytes) {
  if (bytes.length > 128 * 1024) fail('INPUT_MANIFEST_SIZE');
  const input = JSON.parse(bytes.toString('utf8'));
  if (Object.keys(input).sort().join(',') !== 'declaredGitCommit,files,schema' || input.schema !== 'cnyos-function-source-input/v1' || !/^[a-f0-9]{40}$/.test(input.declaredGitCommit) || !Array.isArray(input.files) || input.files.length < 12 || input.files.length > 128) fail('INPUT_MANIFEST');
  const paths = input.files.map((file) => {
    if (Object.keys(file).sort().join(',') !== 'path,sha256' || typeof file.path !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) fail('INPUT_FILE');
    if (!(file.path === 'platform-config.js' || FUNCTIONS.some((name) => file.path === `netlify/functions/${name}.mts`) || /^netlify\/functions\/_shared\/[a-z][a-z0-9-]*\.mjs$/.test(file.path))) fail('INPUT_PATH');
    return file.path;
  });
  if (new Set(paths).size !== paths.length || JSON.stringify(paths) !== JSON.stringify(sorted(paths)) || !paths.includes('platform-config.js') || FUNCTIONS.some((name) => !paths.includes(`netlify/functions/${name}.mts`))) fail('INPUT_SET');
  return input;
}

export function compilerOptions(source, output) {
  return {
    archiveFormat: 'none', basePath: source, repositoryRoot: source,
    configFileDirectories: [], parallelLimit: 1,
    manifest: join(output, 'zisi-observations.json'),
    // ZISI 15.5.1 forces NFT for API v2. Its NFT transformer still uses
    // esbuild for local-import bundling/transpilation, then traces packages.
    // NFT derives the archive root from traced AND included file directories.
    // Include only our generated root metadata to fix that root at source,
    // including for functions whose local imports were entirely bundled.
    config: { '*': { nodeBundler: 'nft', nodeVersion: '24.x', nodeModuleFormat: 'esm', nodeSourcemap: false, externalNodeModules: [], ignoredNodeModules: [], includedFiles: ['package.json'], includedFilesBasePath: source } },
  };
}

export function assertCompilerResult(result, workspace, destination) {
  const checks = {
    path: result.path === join(destination, result.name),
    mainFile: result.mainFile === join(workspace, 'netlify/functions', `${result.name}.mts`),
    runtime: result.runtime === 'js',
    bundler: result.bundler === 'nft',
    runtimeVersion: result.runtimeVersion === 'nodejs24.x',
    runtimeAPIVersion: result.runtimeAPIVersion === 2,
    entryFilename: result.entryFilename === '___netlify-entry-point.mjs',
    bundlerErrors: !(result.bundlerErrors?.length ?? 0),
    bundlerWarnings: !(result.bundlerWarnings?.length ?? 0),
    nativeNodeModules: Object.keys(result.nativeNodeModules ?? {}).length === 0,
  };
  const fields = Object.keys(checks).filter((name) => !checks[name]);
  if (fields.length) {
    // Closed names only; never emit returned paths, source, warning text or
    // other compiler-controlled values. One bounded JSON line at the CLI.
    throw new Error(JSON.stringify({
      code: 'CNYOS_CANDIDATE_COMPILER_RESULT',
      function: FUNCTIONS.includes(result.name) ? result.name : 'unknown',
      fields,
    }));
  }
}

export function assertExecutionEnvironment() {
  // Necessary local checks, NOT proof of network/mount/resource isolation.
  if (process.platform !== 'linux' || process.version !== 'v24.20.0' || typeof process.getuid !== 'function' || process.getuid() === 0) fail('EXECUTION_PLATFORM');
  const allowed = new Set(['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ']);
  if (Object.keys(process.env).some((name) => !allowed.has(name))) fail('AMBIENT_ENVIRONMENT');
}

async function installedCompiler(toolchain) {
  assertExecutionEnvironment();
  await directory(join(toolchain, 'node_modules'));
  for (const [name, version] of Object.entries(PINS)) {
    const pkg = JSON.parse(await readRegular(join(toolchain, 'node_modules', name, 'package.json')));
    if (pkg.name !== name || pkg.version !== version) fail('INSTALLED_PACKAGE');
  }
  // A fixed local entrypoint; no npm, PATH lookup, plugin or app-code import.
  return (await import(pathToFileURL(join(toolchain, 'node_modules/@netlify/zip-it-and-ship-it/dist/main.js')).href)).zipFunctions;
}

async function inventory(root) {
  const files = [];
  let total = 0;
  let entries = 0;
  async function visit(path, prefix) {
    await directory(path);
    const dir = await fs.opendir(path);
    for await (const item of dir) {
      if (++entries > 16384 || !/^[A-Za-z0-9_@][A-Za-z0-9_.@+-]*$/.test(item.name) || /\.(?:pem|key|node)$/i.test(item.name)) fail('OUTPUT_ENTRY');
      const absolute = join(path, item.name);
      const name = prefix ? `${prefix}/${item.name}` : item.name;
      if (item.isDirectory()) await visit(absolute, name);
      else {
        const bytes = await readRegular(absolute, 16 * 1024 * 1024, 'function-output-inventory');
        total += bytes.length;
        if (total > 256 * 1024 * 1024) fail('OUTPUT_SIZE');
        files.push({ path: name, size: bytes.length, sha256: hash(bytes) });
      }
    }
  }
  await visit(root, '');
  return files.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
}

export async function buildFunctions({ source, inputManifest, output, toolchain = HERE }, { compiler } = {}) {
  await directory(source);
  await directory(toolchain);
  if (!isAbsolute(output) || resolve(output) !== output) fail('OUTPUT_PATH');
  await directory(dirname(output));
  if ([source, toolchain].some((path) => inside(path, output) || inside(output, path))) fail('OUTPUT_OVERLAP');
  const manifestBytes = await readRegular(inputManifest, 128 * 1024);
  const manifest = parseInputManifest(manifestBytes);
  const lockBytes = await readRegular(join(toolchain, 'package-lock.json'), 1024 * 1024);
  if (hash(lockBytes) !== LOCK_SHA256) fail('LOCK_DIGEST');
  const pkg = JSON.parse(await readRegular(join(toolchain, 'package.json')));
  if (JSON.stringify(pkg.dependencies) !== JSON.stringify(PINS) || pkg.engines?.node !== '24.20.0' || pkg.packageManager !== 'npm@11.19.0') fail('PACKAGE_PINS');
  if (compiler !== undefined && typeof compiler !== 'function') fail('COMPILER_TYPE');
  const isTestDouble = compiler !== undefined;
  if (!isTestDouble) assertExecutionEnvironment();
  // Exclusive allocation: never let ZISI's rm(existing functionFolder) see a
  // caller-owned existing output. Failed runs leave diagnostics, no success file.
  await fs.mkdir(output, { mode: 0o700 });
  const workspace = join(output, 'source-workspace');
  await fs.mkdir(workspace, { mode: 0o700 });
  const destination = join(output, 'functions');
  let observation;
  try {
    let total = 0;
    for (const file of manifest.files) {
      const bytes = await readRegular(join(source, file.path));
      total += bytes.length;
      if (total > 64 * 1024 * 1024 || hash(bytes) !== file.sha256) fail('SOURCE_DIGEST');
      const target = join(workspace, file.path);
      await fs.mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await fs.writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
    }
    // Deliberately generated, not copied from candidate configuration. The
    // only rewritten bytes are these additional, identified build configs.
    const generated = {
      'package.json': `${JSON.stringify({ private: true, type: 'module', dependencies: { '@netlify/blobs': PINS['@netlify/blobs'], qrcode: PINS.qrcode } })}\n`,
      'tsconfig.json': `${JSON.stringify({ compilerOptions: { target: 'ES2024', module: 'NodeNext', moduleResolution: 'NodeNext' } })}\n`,
    };
    for (const [path, bytes] of Object.entries(generated)) await fs.writeFile(join(workspace, path), bytes, { flag: 'wx', mode: 0o600 });
    await materializeDependencies(join(toolchain, 'node_modules'), join(workspace, 'node_modules'));
    const zipFunctions = compiler ?? await installedCompiler(toolchain);
    const results = await zipFunctions(join(workspace, 'netlify/functions'), destination, compilerOptions(workspace, output));
    if (!Array.isArray(results) || results.length !== FUNCTIONS.length || JSON.stringify(sorted(results.map((entry) => entry.name))) !== JSON.stringify(FUNCTIONS)) fail('FUNCTION_SET');
    for (const result of results) {
      assertCompilerResult(result, workspace, destination);
    }
    if (JSON.stringify(sorted(await fs.readdir(destination))) !== JSON.stringify(FUNCTIONS)) fail('OUTPUT_SET');
    const outputFiles = await inventory(destination);
    for (const name of FUNCTIONS) {
      for (const [component, path] of [['entry', '___netlify-entry-point.mjs'], ['bootstrap', '___netlify-bootstrap.mjs'], ['application', `netlify/functions/${name}.mjs`]]) {
        if (!outputFiles.some((file) => file.path === `${name}/${path}`)) {
          throw new Error(JSON.stringify({ code: 'CNYOS_CANDIDATE_OUTPUT_HANDLER', function: name, component,
            rootApplicationPresent: outputFiles.some((file) => file.path === `${name}/${name}.mjs`) }));
        }
      }
      const packageFile = outputFiles.find((file) => file.path === `${name}/package.json`);
      if (!packageFile || packageFile.sha256 !== hash(generated['package.json'])) {
        throw new Error(JSON.stringify({ code: 'CNYOS_CANDIDATE_OUTPUT_GENERATED_CONFIG', function: name, component: 'package.json' }));
      }
    }
    // Recheck copied inputs after compilation. This is byte association, not
    // proof that declaredGitCommit was independently fetched/authenticated.
    for (const file of manifest.files) if (hash(await readRegular(join(workspace, file.path), 16 * 1024 * 1024, 'copied-source-recheck')) !== file.sha256) fail('COPIED_SOURCE_CHANGED');
    if (hash(await readRegular(join(toolchain, 'package-lock.json'), 1024 * 1024)) !== LOCK_SHA256) fail('LOCK_CHANGED');
    observation = {
      schema: 'cnyos-candidate-function-build-observation/v1',
      execution: isTestDouble ? 'injected-test-double' : 'local-zisi',
      declaredGitCommit: manifest.declaredGitCommit,
      inputManifestSha256: hash(manifestBytes), sourceFiles: manifest.files,
      toolchainLockSha256: LOCK_SHA256, packagePins: PINS,
      generatedConfigs: Object.entries(generated).map(([path, bytes]) => ({ path, sha256: hash(bytes) })),
      requestedTarget: 'nodejs24.x', runningNode: process.version,
      functions: results.map(({ name, runtime, bundler, runtimeVersion, runtimeAPIVersion, entryFilename }) => ({ name, runtime, bundler, runtimeVersion, runtimeAPIVersion, entryFilename })).sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name))),
      outputFiles,
      limitations: ['No provider deployment or native invocation performed', 'No independent-build, import-closure, source-authority or isolation attestation', 'Not accepted as a controller producer manifest or security approval'],
    };
  } finally {
    // Only our private generated workspace; never source/toolchain/output roots.
    await fs.rm(workspace, { recursive: true, force: true });
  }
  // Publish observations only after successful cleanup, never on a failed run.
  await fs.writeFile(join(output, 'candidate-build.json'), `${JSON.stringify(observation, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return observation;
}

export function parseArguments(args) {
  if (args.length !== 6 || args[0] !== '--source' || args[2] !== '--input-manifest' || args[4] !== '--output' || [args[1], args[3], args[5]].some((value) => !isAbsolute(value) || resolve(value) !== value)) fail('ARGUMENTS');
  return { source: args[1], inputManifest: args[3], output: args[5] };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await buildFunctions(parseArguments(process.argv.slice(2)));
    process.stdout.write(`Candidate compilation observations: ${result.functions.length} functions; not release evidence.\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
