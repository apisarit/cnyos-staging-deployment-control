import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  EXPECTED_FUNCTION_NAMES,
  POLICY
} from '../scripts/policy.mjs';
import * as bundle from '../scripts/controller-function-bundle.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptPath = path.join(packageRoot, 'scripts', 'controller-function-bundle.mjs');
const CONTROLLER_COMMIT = 'a'.repeat(40);
const UTF8_FLAG = 0x0800;
const ZIP_VERSION = 20;
const ZIP_UNIX_VERSION = 0x0314;
const MAX_ENTRY_BYTES = 16 * 1024 * 1024;

function git(cwd, args, encoding = 'utf8') {
  return execFileSync('git', args, {
    cwd,
    encoding,
    env: {
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_OPTIONAL_LOCKS: '0',
      HOME: '/nonexistent',
      LANG: 'C',
      LC_ALL: 'C',
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin'
    },
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
}

async function absent(filename) {
  try {
    await fs.lstat(filename);
    return false;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
}

const CRC_TABLE = Object.freeze(Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value >>> 1) ^ (0xedb88320 & -(value & 1));
  }
  return value >>> 0;
}));

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function asBytes(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value || '', 'utf8');
}

function makeZip(records, {
  prefix = Buffer.alloc(0),
  gap = Buffer.alloc(0),
  archiveComment = Buffer.alloc(0)
} = {}) {
  const localParts = [prefix];
  const centralParts = [];
  const metadata = [];
  let offset = prefix.length;
  for (const record of records) {
    const content = asBytes(record.content);
    const method = record.method ?? 0;
    const compressed = record.compressed
      ? asBytes(record.compressed)
      : method === 8 ? zlib.deflateRawSync(content) : Buffer.from(content);
    const localName = Buffer.from(record.localName ?? record.path, 'utf8');
    const centralName = Buffer.from(record.path, 'utf8');
    const localExtra = asBytes(record.localExtra);
    const centralExtra = asBytes(record.centralExtra);
    const entryComment = asBytes(record.entryComment);
    const checksum = record.crc ?? crc32(content);
    const compressedSize = record.compressedSize ?? compressed.length;
    const uncompressedSize = record.uncompressedSize ?? content.length;
    const flags = record.flags ?? UTF8_FLAG;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(record.localVersion ?? ZIP_VERSION, 4);
    local.writeUInt16LE(record.localFlags ?? flags, 6);
    local.writeUInt16LE(record.localMethod ?? method, 8);
    local.writeUInt16LE(record.time ?? 0x4a21, 10);
    local.writeUInt16LE(record.date ?? 0x5821, 12);
    local.writeUInt32LE(record.localCrc ?? checksum, 14);
    local.writeUInt32LE(record.localCompressedSize ?? compressedSize, 18);
    local.writeUInt32LE(record.localUncompressedSize ?? uncompressedSize, 22);
    local.writeUInt16LE(localName.length, 26);
    local.writeUInt16LE(localExtra.length, 28);
    metadata.push({
      centralExtra,
      centralName,
      checksum,
      compressedSize,
      entryComment,
      flags,
      localOffset: record.localOffset ?? offset,
      method,
      mode: record.mode ?? 0o100644,
      uncompressedSize,
      versionMadeBy: record.versionMadeBy ?? ZIP_UNIX_VERSION,
      versionNeeded: record.versionNeeded ?? ZIP_VERSION
    });
    localParts.push(local, localName, localExtra, compressed, gap);
    offset += local.length + localName.length + localExtra.length + compressed.length + gap.length;
  }
  const centralOffset = offset;
  let centralSize = 0;
  for (const record of metadata) {
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(record.versionMadeBy, 4);
    central.writeUInt16LE(record.versionNeeded, 6);
    central.writeUInt16LE(record.flags, 8);
    central.writeUInt16LE(record.method, 10);
    central.writeUInt16LE(0x4a21, 12);
    central.writeUInt16LE(0x5821, 14);
    central.writeUInt32LE(record.checksum, 16);
    central.writeUInt32LE(record.compressedSize, 20);
    central.writeUInt32LE(record.uncompressedSize, 24);
    central.writeUInt16LE(record.centralName.length, 28);
    central.writeUInt16LE(record.centralExtra.length, 30);
    central.writeUInt16LE(record.entryComment.length, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE((record.mode << 16) >>> 0, 38);
    central.writeUInt32LE(record.localOffset, 42);
    centralParts.push(
      central,
      record.centralName,
      record.centralExtra,
      record.entryComment
    );
    centralSize += central.length + record.centralName.length +
      record.centralExtra.length + record.entryComment.length;
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(records.length, 8);
  eocd.writeUInt16LE(records.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  eocd.writeUInt16LE(archiveComment.length, 20);
  return Buffer.concat([...localParts, ...centralParts, eocd, archiveComment]);
}

function centralRecords(bytes) {
  const eocd = bytes.length - 22;
  const count = bytes.readUInt16LE(eocd + 10);
  let cursor = bytes.readUInt32LE(eocd + 16);
  const records = [];
  for (let index = 0; index < count; index += 1) {
    assert.equal(bytes.readUInt32LE(cursor), 0x02014b50);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    records.push({ central: cursor, local: bytes.readUInt32LE(cursor + 42) });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return records;
}

function expectArchiveFailure(bytes, pattern = /CNYOS_FUNCTION_BUNDLE_ARCHIVE_/) {
  assert.throws(() => bundle.readFunctionBundleZipEntries(bytes), pattern);
}

async function initializeCandidate(root) {
  const candidate = path.join(root, 'candidate');
  const functions = path.join(candidate, 'netlify', 'functions');
  await fs.mkdir(path.join(functions, '_shared'), { recursive: true });
  for (const name of EXPECTED_FUNCTION_NAMES) {
    const hostileSemantics = name === 'account-access'
      ? [
        "const indirect = module['require'];",
        "eval('indirect(\\\"node:net\\\")');",
        "process.getBuiltinModule?.('node:child_process');",
        "import('unlocked-' + 'package');"
      ].join('\n')
      : '';
    const misleadingSchedule = name === 'database-backup'
      ? "// schedule: '0 20 * * *'\nexport const config = { ['schedule']: 'wrong' };\n"
      : name === 'database-backup-background'
        ? "export const config = { ['schedule']: '* * * * *' };\n"
        : '';
    await fs.writeFile(
      path.join(functions, `${name}.mts`),
      `${hostileSemantics}\n${misleadingSchedule}export default async () => new Response('${name}:first');\n`
    );
  }
  await fs.writeFile(
    path.join(functions, '_shared', 'executable.mjs'),
    'export const executable = true;\n',
    { mode: 0o755 }
  );
  await fs.writeFile(path.join(candidate, 'netlify.toml'), [
    '[functions]',
    '  directory = "netlify/functions"',
    '[[plugins]]',
    '  package = "/tmp/untrusted-candidate-plugin"',
    ''
  ].join('\n'));
  await fs.writeFile(path.join(candidate, 'package-lock.json'), '{"lockfileVersion":3}\n');
  git(candidate, ['init', '--quiet', '--initial-branch=main']);
  git(candidate, ['config', 'user.name', 'CNYOS Fixture']);
  git(candidate, ['config', 'user.email', 'fixture@invalid.example']);
  git(candidate, ['add', '--', '.']);
  git(candidate, ['update-index', '--chmod=+x',
    'netlify/functions/_shared/executable.mjs']);
  git(candidate, ['commit', '--quiet', '-m', 'first']);
  const first = String(git(candidate, ['rev-parse', 'HEAD'])).trim();

  await fs.writeFile(
    path.join(functions, 'account-access.mts'),
    "export default async () => new Response('account-access:second');\n"
  );
  git(candidate, ['add', '--', 'netlify/functions/account-access.mts']);
  git(candidate, ['commit', '--quiet', '-m', 'second']);
  const second = String(git(candidate, ['rev-parse', 'HEAD'])).trim();
  git(candidate, ['replace', first, second]);
  return { candidate, first, second };
}

function runtimeEnvironment(root, candidate) {
  return {
    CNYOS_CANDIDATE_DIRECTORY: candidate.candidate,
    CNYOS_CANDIDATE_SHA: candidate.second,
    CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE: 'false',
    CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
    CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
    CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
    CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH: path.join(root, 'published', 'manifest.json'),
    CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY: path.join(root, 'published', 'functions'),
    GITHUB_ACTOR: 'Risk-Owner',
    GITHUB_REF: POLICY.controller.protectedRef,
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_REPOSITORY: POLICY.controller.repository,
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_RUN_ID: '1001',
    GITHUB_SHA: CONTROLLER_COMMIT,
    GITHUB_TRIGGERING_ACTOR: 'risk-owner',
    GITHUB_WORKFLOW_REF:
      `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}` +
      `@${POLICY.controller.protectedRef}`
  };
}

const temporaryBase = await fs.realpath(os.tmpdir());
const root = await fs.mkdtemp(path.join(temporaryBase, 'cnyos-controller-function-bundle-'));
try {
  const candidate = await initializeCandidate(root);

  // Git objects, never mutable HEAD expressions or worktree bytes, select source identity.
  const firstSnapshot = await bundle.readFunctionBundleImmutableCommit(
    candidate.candidate,
    candidate.first
  );
  assert.equal(firstSnapshot.candidateCommit, candidate.first);
  assert.equal(firstSnapshot.candidateTree, String(git(candidate.candidate, [
    '--no-replace-objects', 'rev-parse', `${candidate.first}^{tree}`
  ])).trim());
  assert.deepEqual(
    firstSnapshot.sourceFiles.filter(entry => !entry.path.includes('/')).map(entry =>
      entry.path.slice(0, -4)
    ).sort(),
    [...EXPECTED_FUNCTION_NAMES].sort()
  );
  assert.equal(firstSnapshot.blobs.find(entry =>
    entry.path === 'netlify/functions/_shared/executable.mjs'
  ).mode, '100755');
  const firstAccount = firstSnapshot.blobs.find(entry =>
    entry.path === 'netlify/functions/account-access.mts'
  );
  assert.match(firstAccount.bytes.toString('utf8'), /account-access:first/);
  assert.doesNotMatch(firstAccount.bytes.toString('utf8'), /account-access:second/);
  await assert.rejects(
    bundle.readFunctionBundleCandidateSnapshot(candidate.candidate, candidate.first),
    /CNYOS_FUNCTION_BUNDLE_CANDIDATE_CHECKOUT_MISMATCH/
  );

  const secondSnapshot = await bundle.readFunctionBundleCandidateSnapshot(
    candidate.candidate,
    candidate.second
  );
  const secondAccount = secondSnapshot.blobs.find(entry =>
    entry.path === 'netlify/functions/account-access.mts'
  );
  assert.match(secondAccount.bytes.toString('utf8'), /account-access:second/);
  // A real Git-object read succeeds with no caller PATH and ignores ambient Git
  // overrides. No candidate command, filter, hook, or network transport is run.
  const isolatedGitRead = spawnSync(process.execPath, ['--input-type=module', '-e',
    `const bundle = await import(${JSON.stringify(pathToFileURL(scriptPath).href)});` +
    `const snapshot = await bundle.readFunctionBundleCandidateSnapshot(${JSON.stringify(candidate.candidate)}, ${JSON.stringify(candidate.second)});` +
    'process.stdout.write(snapshot.candidateCommit);'
  ], { env: { PATH: '/nonexistent', LANG: 'C', LC_ALL: 'C',
    GIT_DIR: '/nonexistent', GIT_WORK_TREE: '/nonexistent', GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'extensions.objectFormat', GIT_CONFIG_VALUE_0: 'sha256' },
    encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(isolatedGitRead.status, 0, isolatedGitRead.stderr);
  assert.equal(isolatedGitRead.stdout, candidate.second);
  assert.equal(isolatedGitRead.stderr, '');
  await fs.writeFile(
    path.join(candidate.candidate, 'netlify', 'functions', 'account-access.mts'),
    "throw new Error('ambient worktree attack');\n"
  );
  await fs.writeFile(path.join(candidate.candidate, 'ambient-untracked'), 'attack\n');
  const committedAgain = await bundle.readFunctionBundleCandidateSnapshot(
    candidate.candidate,
    candidate.second
  );
  assert.match(committedAgain.blobs.find(entry =>
    entry.path === 'netlify/functions/account-access.mts'
  ).bytes.toString('utf8'), /account-access:second/);

  const roguePath = path.join(candidate.candidate, 'netlify', 'functions', 'rogue.mts');
  await fs.writeFile(roguePath, 'export default async () => new Response("rogue");\n');
  git(candidate.candidate, ['add', '--', 'netlify/functions/rogue.mts']);
  git(candidate.candidate, ['commit', '--quiet', '-m', 'rogue function']);
  const rogueCommit = String(git(candidate.candidate, ['rev-parse', 'HEAD'])).trim();
  await assert.rejects(
    bundle.readFunctionBundleImmutableCommit(candidate.candidate, rogueCommit),
    /CNYOS_FUNCTION_BUNDLE_FUNCTION_NAME_MISMATCH/
  );
  await fs.unlink(roguePath);
  git(candidate.candidate, ['add', '--all', '--', 'netlify/functions/rogue.mts']);
  git(candidate.candidate, ['commit', '--quiet', '-m', 'remove rogue function']);

  // Unsafe and cross-platform ambiguous source paths are rejected before materialization.
  for (const sourcePath of [
    'C:/drive.mjs',
    'folder/file.mjs:stream',
    'folder/trailing.',
    'folder/trailing ',
    'CON',
    'aux.txt',
    'folder/LPT1.json',
    '.git/config',
    'unicod\u00e9.mjs'
  ]) {
    assert.throws(
      () => bundle.assertSafeFunctionSourcePath(sourcePath),
      /CNYOS_FUNCTION_BUNDLE_SOURCE_PATH_INVALID/
    );
  }
  assert.throws(
    () => bundle.parseFunctionBundleGitInventory(Buffer.from(
      `100644 blob ${'1'.repeat(40)}\tFolder/File.mjs\0` +
      `100644 blob ${'2'.repeat(40)}\tfolder/file.mjs\0`
    )),
    /CNYOS_FUNCTION_BUNDLE_SOURCE_PATH_COLLISION/
  );
  assert.throws(
    () => bundle.parseFunctionBundleGitInventory(Buffer.from(
      `120000 blob ${'1'.repeat(40)}\tlink\0`
    )),
    /CNYOS_FUNCTION_BUNDLE_NON_REGULAR_GIT_ENTRY/
  );
  assert.throws(
    () => bundle.parseFunctionBundleGitInventory(Buffer.from(
      `100644 blob ${'1'.repeat(40)}\tfile.mjs`
    )),
    /CNYOS_FUNCTION_BUNDLE_GIT_TREE_INVALID/
  );

  const symlinkPath = path.join(candidate.candidate, 'unsafe-link');
  await fs.symlink('package-lock.json', symlinkPath);
  git(candidate.candidate, ['add', '--', 'unsafe-link']);
  git(candidate.candidate, ['commit', '--quiet', '-m', 'symlink']);
  const symlinkCommit = String(git(candidate.candidate, ['rev-parse', 'HEAD'])).trim();
  await assert.rejects(
    bundle.readFunctionBundleImmutableCommit(candidate.candidate, symlinkCommit),
    /CNYOS_FUNCTION_BUNDLE_NON_REGULAR_GIT_ENTRY/
  );

  // Valid archives canonicalize byte-for-byte despite input order, compression, time and mode.
  const handler = Buffer.from('export default async () => new Response("ok");\n');
  const shared = Buffer.from('export const shared = true;\n');
  const rawA = makeZip([
    { path: 'lib/shared.js', content: shared, method: 8, mode: 0o100755 },
    { path: 'account-access.mjs', content: handler, method: 8, mode: 0o100755 }
  ]);
  const rawB = makeZip([
    { path: 'account-access.mjs', content: handler },
    { path: 'lib/shared.js', content: shared }
  ]);
  const canonicalA = bundle.canonicalizeFunctionBundleArchive(rawA, 'account-access');
  const canonicalB = bundle.canonicalizeFunctionBundleArchive(rawB, 'account-access');
  assert.equal(canonicalA.equals(canonicalB), true);
  assert.deepEqual(
    bundle.readFunctionBundleZipEntries(canonicalA).map(entry => entry.path),
    ['account-access.mjs', 'lib/shared.js']
  );
  assert.equal(canonicalA.readUInt16LE(8), 0);
  assert.equal(canonicalA.readUInt16LE(10), 0);
  assert.equal(canonicalA.readUInt16LE(12), 0x0021);
  const canonicalCentral = centralRecords(canonicalA)[0].central;
  assert.equal(canonicalA.readUInt32LE(canonicalCentral + 38) >>> 16, 0o100644);

  assert.throws(
    () => bundle.canonicalizeFunctionBundleArchive(rawA, 'not-allowed'),
    /CNYOS_FUNCTION_BUNDLE_FUNCTION_NAME_MISMATCH/
  );
  assert.throws(
    () => bundle.canonicalizeFunctionBundleArchive(
      makeZip([{ path: 'other.mjs', content: handler }]),
      'account-access'
    ),
    /CNYOS_FUNCTION_BUNDLE_ARCHIVE_HANDLER_MISSING/
  );

  // Real ZISI v2 ESM layout, byte assembly only: no generated code is executed.
  const v2Entries = [
    { path: '___netlify-entry-point.mjs', content: '// inert entry fixture' },
    { path: '___netlify-bootstrap.mjs', content: '// inert bootstrap fixture' },
    { path: 'netlify/functions/account-access.mjs', content: handler }
  ];
  const v2Canonical = bundle.canonicalizeFunctionBundleArchive(makeZip(v2Entries), 'account-access');
  assert.deepEqual(bundle.readFunctionBundleZipEntries(v2Canonical).map(entry => entry.path),
    v2Entries.map(entry => entry.path).sort());
  for (let missing = 0; missing < v2Entries.length; missing++) {
    assert.throws(() => bundle.canonicalizeFunctionBundleArchive(makeZip([
      ...v2Entries.filter((entry, index) => index !== missing),
      { path: 'account-access.mjs', content: handler }
    ]), 'account-access'), /ARCHIVE_HANDLER_MISSING/);
  }
  assert.throws(() => bundle.canonicalizeFunctionBundleArchive(makeZip(v2Entries), 'owner-drive'), /ARCHIVE_HANDLER_MISSING/);

  // ZIP metadata is closed: no descriptors, encryption, ZIP64, extras, comments or aliases.
  expectArchiveFailure(Buffer.alloc(22));
  expectArchiveFailure(Buffer.from('not a zip'));
  for (const flags of [UTF8_FLAG | 0x0001, UTF8_FLAG | 0x0008, UTF8_FLAG | 0x0040]) {
    expectArchiveFailure(makeZip([{ path: 'account-access.mjs', content: handler, flags }]));
  }
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs', content: handler, centralExtra: Buffer.from([1, 2])
  }]));
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs', content: handler, localExtra: Buffer.from([1, 2])
  }]));
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs', content: handler, entryComment: Buffer.from('comment')
  }]));
  expectArchiveFailure(makeZip(
    [{ path: 'account-access.mjs', content: handler }],
    { archiveComment: Buffer.from('comment') }
  ));
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs', content: handler, mode: 0o120777
  }]));
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs', content: handler, method: 9
  }]));
  const zip64 = Buffer.from(rawB);
  zip64.writeUInt32LE(0xffffffff, centralRecords(zip64)[0].central + 20);
  expectArchiveFailure(zip64);

  const localCrcMismatch = Buffer.from(rawB);
  localCrcMismatch.writeUInt32LE(0, centralRecords(localCrcMismatch)[0].local + 14);
  expectArchiveFailure(localCrcMismatch);
  const localSizeMismatch = Buffer.from(rawB);
  localSizeMismatch.writeUInt32LE(0, centralRecords(localSizeMismatch)[0].local + 18);
  expectArchiveFailure(localSizeMismatch);
  const localTimeMismatch = Buffer.from(rawB);
  localTimeMismatch.writeUInt16LE(0, centralRecords(localTimeMismatch)[0].local + 10);
  expectArchiveFailure(localTimeMismatch);
  const duplicateOffset = Buffer.from(rawB);
  const duplicateRecords = centralRecords(duplicateOffset);
  duplicateOffset.writeUInt32LE(duplicateRecords[0].local, duplicateRecords[1].central + 42);
  expectArchiveFailure(duplicateOffset);
  expectArchiveFailure(makeZip(
    [{ path: 'account-access.mjs', content: handler }],
    { prefix: Buffer.from('hidden-prefix') }
  ));
  expectArchiveFailure(makeZip(
    [{ path: 'account-access.mjs', content: handler }],
    { gap: Buffer.from('hidden-gap') }
  ));
  const compressedHandler = zlib.deflateRawSync(handler);
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs',
    content: handler,
    method: 8,
    compressed: Buffer.concat([compressedHandler, Buffer.from('trailing')])
  }]));

  // Windows device, drive, ADS, trailing-dot/space, case and prefix collisions are denied.
  for (const archivePath of [
    'C:/handler.mjs',
    'handler.mjs:stream',
    'trailing.',
    'trailing ',
    'CON',
    'aux.txt',
    'dir/COM1.js',
    'unicod\u00e9.mjs',
    '.env',
    'keys/private.pem',
    'dir/'
  ]) {
    expectArchiveFailure(makeZip([{ path: archivePath, content: handler }]));
  }
  expectArchiveFailure(makeZip([
    { path: 'File.js', content: handler },
    { path: 'file.js', content: handler }
  ]), /CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_COLLISION/);
  expectArchiveFailure(makeZip([
    { path: 'lib', content: handler },
    { path: 'lib/shared.js', content: shared }
  ]), /CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_COLLISION/);
  expectArchiveFailure(makeZip([
    { path: 'same.js', content: handler },
    { path: 'same.js', content: shared }
  ]), /CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_COLLISION/);

  // Declared expansion is preflighted globally before any inflate and per entry.
  expectArchiveFailure(makeZip([{
    path: 'account-access.mjs',
    content: Buffer.alloc(0),
    method: 8,
    uncompressedSize: MAX_ENTRY_BYTES + 1
  }]), /CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE/);
  expectArchiveFailure(makeZip(Array.from({ length: 5 }, (_, index) => ({
    path: index === 0 ? 'account-access.mjs' : `lib/${index}.js`,
    content: Buffer.alloc(0),
    method: 8,
    uncompressedSize: MAX_ENTRY_BYTES
  }))), /CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE/);

  // Canonical STORE size is bounded before Buffer.concat allocates the result.
  const largeA = Buffer.alloc(MAX_ENTRY_BYTES, 0x20);
  const largeB = Buffer.alloc(MAX_ENTRY_BYTES, 0x21);
  assert.throws(() => bundle.canonicalizeFunctionBundleArchive(makeZip([
    { path: 'account-access.mjs', content: largeA, method: 8 },
    { path: 'lib/large.js', content: largeB, method: 8 }
  ]), 'account-access'), /CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE/);

  // Real filesystem assembly produces canonical archives without executing files.
  // The two directories are synthetic outputs, not independently attested builds.
  const firstBuild = path.join(root, 'unpacked-first');
  const secondBuild = path.join(root, 'unpacked-second');
  async function unpackedBuild(directory, reverse) {
    await fs.mkdir(directory, { mode: 0o700 });
    for (const name of reverse ? [...EXPECTED_FUNCTION_NAMES].reverse() : EXPECTED_FUNCTION_NAMES) {
      const folder = path.join(directory, name);
      await fs.mkdir(path.join(folder, 'lib'), { recursive: true, mode: 0o700 });
      const handler = Buffer.from(`export default async () => new Response('${name}');\n`);
      const shared = Buffer.from('export const data = "offline assembly";\n');
      const writes = [[`${name}.mjs`, handler], ['lib/shared.mjs', shared], ['lib/empty.json', Buffer.alloc(0)]];
      for (const [relative, bytes] of reverse ? writes.reverse() : writes) {
        await fs.writeFile(path.join(folder, relative), bytes, { flag: 'wx', mode: reverse ? 0o755 : 0o600 });
      }
    }
  }
  await unpackedBuild(firstBuild, false);
  await unpackedBuild(secondBuild, true);
  const assembled = await bundle.collectFunctionBundleDirectory(firstBuild);
  assert.deepEqual(assembled.map(file => file.path), EXPECTED_FUNCTION_NAMES.map(name => `${name}.zip`).sort());
  for (const file of assembled) {
    const name = file.path.slice(0, -4);
    const expected = bundle.canonicalizeFunctionBundleArchive(makeZip([
      { path: `${name}.mjs`, content: `export default async () => new Response('${name}');\n` },
      { path: 'lib/shared.mjs', content: 'export const data = "offline assembly";\n' },
      { path: 'lib/empty.json', content: '' }
    ]), name);
    assert.deepEqual(file.bytes, expected);
    assert.equal(file.size, expected.length);
    assert.equal(Object.isFrozen(file), true);
  }
  const equal = await bundle.compareFunctionBundleDirectories(firstBuild, secondBuild);
  assert.deepEqual(equal, assembled, 'creation order and executable bits are normalized canonically');
  assert.equal(Object.isFrozen(equal), true);
  assert.equal(Object.hasOwn(equal, 'authorization'), false);
  assert.equal(Object.hasOwn(equal, 'evidenceType'), false);
  await assert.rejects(bundle.compareFunctionBundleDirectories(firstBuild, firstBuild), /DIRECTORIES_NOT_ISOLATED/);
  await assert.rejects(bundle.compareFunctionBundleDirectories(firstBuild, path.join(firstBuild, EXPECTED_FUNCTION_NAMES[0])),
    /DIRECTORIES_NOT_ISOLATED/);

  const altered = path.join(secondBuild, 'account-access', 'lib', 'shared.mjs');
  await fs.writeFile(altered, 'export const data = "different output";\n');
  await assert.rejects(bundle.compareFunctionBundleDirectories(firstBuild, secondBuild), /BUILD_BYTES_DIFFER/);
  await fs.writeFile(altered, 'export const data = "offline assembly";\n');

  async function rejectTemporaryEntry(relative, prepare, pattern) {
    const filename = path.join(firstBuild, relative);
    await prepare(filename);
    try { await assert.rejects(bundle.collectFunctionBundleDirectory(firstBuild), pattern); }
    finally { await fs.rm(filename, { recursive: true, force: true }); }
  }
  await rejectTemporaryEntry('extra-function', file => fs.mkdir(file), /FUNCTION_NAME_MISMATCH/);
  await rejectTemporaryEntry('account-access/.env', file => fs.writeFile(file, 'synthetic-only'), /ARCHIVE_FORBIDDEN_PATH/);
  await rejectTemporaryEntry('account-access/lib/certificate.pem', file => fs.writeFile(file, 'synthetic-only'), /ARCHIVE_FORBIDDEN_PATH/);
  await rejectTemporaryEntry('account-access/lib/linked.mjs', file => fs.symlink(altered, file), /BUILD_OUTPUT_INVALID/);
  await rejectTemporaryEntry('account-access/lib/hardlinked.mjs', file => fs.link(altered, file), /BUILD_OUTPUT_INVALID/);
  await rejectTemporaryEntry('account-access/lib/large.bin', async file => {
    const handle = await fs.open(file, 'wx', 0o600);
    try { await handle.truncate(MAX_ENTRY_BYTES + 1); } finally { await handle.close(); }
  }, /BUILD_OUTPUT_TOO_LARGE/);

  const assembledHandler = path.join(firstBuild, 'account-access', 'account-access.mjs');
  await fs.chmod(assembledHandler, 0o666);
  await assert.rejects(bundle.collectFunctionBundleDirectory(firstBuild), /BUILD_OUTPUT_INVALID/);
  await fs.chmod(assembledHandler, 0o600);
  await fs.rename(assembledHandler, `${assembledHandler}.renamed`);
  await assert.rejects(bundle.collectFunctionBundleDirectory(firstBuild), /ARCHIVE_HANDLER_MISSING/);
  await fs.rename(`${assembledHandler}.renamed`, assembledHandler);
  const absentFunction = path.join(firstBuild, 'account-access');
  const movedFunction = path.join(root, 'account-access-held');
  await fs.rename(absentFunction, movedFunction);
  await assert.rejects(bundle.collectFunctionBundleDirectory(firstBuild), /FUNCTION_NAME_MISMATCH/);
  await fs.rename(movedFunction, absentFunction);
  assert.deepEqual(await bundle.compareFunctionBundleDirectories(firstBuild, secondBuild), assembled);
  assert.deepEqual((await fs.readdir(firstBuild)).sort(), [...EXPECTED_FUNCTION_NAMES].sort(),
    'assembly creates no archive, manifest, or receipt in the supplied directories');

  const v2Build = path.join(root, 'unpacked-v2');
  await fs.mkdir(v2Build, { mode: 0o700 });
  for (const name of EXPECTED_FUNCTION_NAMES) {
    const folder = path.join(v2Build, name);
    await fs.mkdir(path.join(folder, 'netlify/functions'), { recursive: true, mode: 0o700 });
    for (const file of ['___netlify-entry-point.mjs', '___netlify-bootstrap.mjs', `netlify/functions/${name}.mjs`]) {
      await fs.writeFile(path.join(folder, file), '// inert v2 layout fixture', { mode: 0o600 });
    }
  }
  const v2Archives = await bundle.collectFunctionBundleDirectory(v2Build);
  assert.equal(v2Archives.length, EXPECTED_FUNCTION_NAMES.length);
  for (const archive of v2Archives) assert.deepEqual(bundle.canonicalizeFunctionBundleArchive(archive.bytes, archive.path.slice(0, -4)), archive.bytes);
  const v2Bootstrap = path.join(v2Build, 'account-access/___netlify-bootstrap.mjs');
  await fs.rename(v2Bootstrap, `${v2Bootstrap}.held`);
  await assert.rejects(bundle.collectFunctionBundleDirectory(v2Build), /ARCHIVE_HANDLER_MISSING/);
  await fs.rename(`${v2Bootstrap}.held`, v2Bootstrap);

  // There is deliberately no local CLI/toolchain success path or unsupported semantic claim.
  const scriptSource = await fs.readFile(scriptPath, 'utf8');
  assert.match(scriptSource, /execFileSync\('\/usr\/bin\/git'/);
  for (const setting of ['GIT_NO_LAZY_FETCH', 'GIT_TERMINAL_PROMPT', 'GIT_NO_REPLACE_OBJECTS', 'GIT_ALLOW_PROTOCOL',
    'GIT_ATTR_NOSYSTEM', 'protocol.allow=never', 'core.fsmonitor=false', 'core.hooksPath=/dev/null']) {
    assert.equal(scriptSource.includes(setting), true, `${setting} protects the immutable reader`);
  }
  assert.match(scriptSource, /fsConstants\.O_RDONLY \| fsConstants\.O_NOFOLLOW \| fsConstants\.O_NONBLOCK/,
    'opening a replaced non-regular output cannot block before the regular-file check');
  for (const unsupported of [
    'FUNCTION_BUNDLE_CHILD_ENVIRONMENT_NAMES',
    'NETWORK_DENY_PRELOAD',
    'externalImportsResolvedFromLock',
    'extractFunctionBundleModuleReferences',
    'functions:build',
    'importClosureComplete',
    'netlifyCliVersion',
    'networkDisabled',
    'packageNameFromSpecifier',
    'publishOutputs',
    'assertScheduledSourceContracts',
    'validateFunctionBundleToolchain'
  ]) {
    assert.equal(scriptSource.includes(unsupported), false, `${unsupported} must remain absent`);
  }

  const fakeController = path.join(root, 'fake-controller');
  const fakeBin = path.join(fakeController, 'node_modules', '.bin', 'netlify');
  const executionSentinel = path.join(root, 'fake-tool-executed');
  await fs.mkdir(path.dirname(fakeBin), { recursive: true });
  await fs.writeFile(fakeBin, [
    '#!/bin/sh',
    `touch ${JSON.stringify(executionSentinel)}`,
    'node -e "require(\'node:net\').Socket(); require(\'node:http2\')"',
    'curl https://invalid.example',
    ''
  ].join('\n'), { mode: 0o755 });
  await fs.writeFile(path.join(fakeController, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      'node_modules/netlify-cli': {
        version: '1.2.3',
        integrity: 'sha512-arbitrary-metadata-does-not-authenticate-installed-bytes'
      }
    }
  }));

  const env = runtimeEnvironment(root, candidate);
  let injectedSpawnCalled = false;
  await assert.rejects(
    bundle.createControllerFunctionBundle({
      env,
      spawnImpl: () => {
        injectedSpawnCalled = true;
        throw new Error('must not run');
      }
    }),
    error => error?.message === bundle.FUNCTION_BUNDLE_NOT_ACTIVATED_CODE
  );
  assert.equal(injectedSpawnCalled, false);
  assert.equal(await absent(executionSentinel), true);
  assert.equal(await absent(env.CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY), true);
  assert.equal(await absent(env.CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH), true);

  // Existing or symlinked destinations are not touched on the fail-closed path.
  await fs.mkdir(env.CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY, { recursive: true });
  await fs.writeFile(path.join(env.CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY, 'keep'), 'keep\n');
  await fs.mkdir(path.dirname(env.CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH), { recursive: true });
  await fs.writeFile(env.CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH, 'keep manifest\n');
  await assert.rejects(
    bundle.createControllerFunctionBundle({ env }),
    error => error?.message === bundle.FUNCTION_BUNDLE_NOT_ACTIVATED_CODE
  );
  assert.equal(await fs.readFile(
    path.join(env.CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY, 'keep'),
    'utf8'
  ), 'keep\n');
  assert.equal(await fs.readFile(env.CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH, 'utf8'),
    'keep manifest\n');

  const credentialEnv = { ...env, NETLIFY_AUTH_TOKEN: '' };
  await assert.rejects(
    bundle.createControllerFunctionBundle({ env: credentialEnv }),
    /CNYOS_FUNCTION_BUNDLE_CREDENTIAL_ENVIRONMENT_REJECTED/
  );

  const cliEnv = runtimeEnvironment(path.join(root, 'cli'), candidate);
  const cli = spawnSync(process.execPath, [scriptPath], {
    cwd: packageRoot,
    encoding: 'utf8',
    env: { ...cliEnv, PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin' },
    maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, '');
  assert.equal(cli.stderr, `${bundle.FUNCTION_BUNDLE_NOT_ACTIVATED_CODE}\n`);
  assert.equal(await absent(cliEnv.CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY), true);
  assert.equal(await absent(cliEnv.CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH), true);
} finally {
  await fs.rm(root, { recursive: true, force: true });
}

process.stdout.write('CNYOS activation contract controller-function-bundle: passed\n');
