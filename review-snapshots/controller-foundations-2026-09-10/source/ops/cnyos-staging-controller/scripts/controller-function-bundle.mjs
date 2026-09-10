import { execFileSync } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import {
  EXPECTED_FUNCTION_NAMES,
  MAX_FILE_BYTES,
  assertControllerRuntime,
  fail,
  required,
  sha1,
  sha256
} from './policy.mjs';

const SHA40 = /^[0-9a-f]{40}$/;
const MAX_TREE_FILES = 4096;
const MAX_TREE_BYTES = 256 * 1024 * 1024;
const MAX_GIT_METADATA_BYTES = 4 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES = MAX_TREE_BYTES + MAX_GIT_METADATA_BYTES;
const MAX_PATH_BYTES = 4096;
const MAX_PATH_COMPONENTS = 64;
const MAX_ZIP_ENTRIES = 16_384;
const MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES = 16 * 1024 * 1024;
const MAX_ZIP_UNCOMPRESSED_BYTES = 64 * 1024 * 1024;
const FIXED_DOS_TIME = 0;
const FIXED_DOS_DATE = 0x0021;
const ZIP_UTF8_FLAG = 0x0800;
const ZIP_STORE_METHOD = 0;
const ZIP_DEFLATE_METHOD = 8;
const ZIP_VERSION = 20;
const ZIP_UNIX_VERSION = 0x0314;
const WINDOWS_RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/i;
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export const FUNCTION_BUNDLE_NOT_ACTIVATED_CODE =
  'CNYOS_FUNCTION_BUNDLE_HERMETIC_RUNNER_NOT_ACTIVATED';

export const FUNCTION_BUNDLE_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'NETLIFY_SITE_ID',
  'PGPASSWORD',
  'SUPABASE_DB_PASSWORD',
  'SUPABASE_SERVICE_ROLE_KEY'
].sort());

function decodeUtf8(value, code) {
  try {
    return textDecoder.decode(value);
  } catch {
    fail(code);
  }
}

function bytewiseCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function exactAbsolutePath(value, code) {
  const normalized = required(value, code, MAX_PATH_BYTES);
  if (value !== normalized || !path.isAbsolute(normalized) || path.resolve(normalized) !== normalized ||
    normalized === path.parse(normalized).root) fail(code);
  return normalized;
}

async function assertCanonicalDirectory(directory, code) {
  const exact = exactAbsolutePath(directory, code);
  let status;
  let real;
  try {
    status = await fs.lstat(exact);
    real = await fs.realpath(exact);
  } catch {
    fail(code);
  }
  if (!status.isDirectory() || status.isSymbolicLink() || real !== exact) fail(code);
  return exact;
}

function assertPortableRelativePath(value, code) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value, 'utf8') > MAX_PATH_BYTES ||
    value.startsWith('/') || value.includes('\\') || /[\u0000-\u001f\u007f]/u.test(value) ||
    value.normalize('NFC') !== value || path.posix.normalize(value) !== value ||
    !/^[\x20-\x7e]+$/.test(value)) {
    fail(code);
  }
  const components = value.split('/');
  if (components.length > MAX_PATH_COMPONENTS || components.some(component =>
    !component || component === '.' || component === '..' || component.includes(':') ||
    component.startsWith(' ') || component.endsWith(' ') || component.endsWith('.') ||
    WINDOWS_RESERVED_COMPONENT.test(component))) {
    fail(code);
  }
  return value;
}

export function assertSafeFunctionSourcePath(value) {
  const sourcePath = assertPortableRelativePath(
    value,
    'CNYOS_FUNCTION_BUNDLE_SOURCE_PATH_INVALID'
  );
  if (sourcePath.split('/').some(component => component.toLowerCase() === '.git')) {
    fail('CNYOS_FUNCTION_BUNDLE_SOURCE_PATH_INVALID');
  }
  return sourcePath;
}

export function assertFunctionBundleCredentialFree(env) {
  if (!env || typeof env !== 'object') fail('CNYOS_FUNCTION_BUNDLE_ENVIRONMENT_INVALID');
  for (const name of FUNCTION_BUNDLE_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) fail('CNYOS_FUNCTION_BUNDLE_CREDENTIAL_ENVIRONMENT_REJECTED');
  }
  if (Object.hasOwn(env, 'CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE') &&
    env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE !== 'false') {
    fail('CNYOS_FUNCTION_BUNDLE_CREDENTIAL_ENVIRONMENT_REJECTED');
  }
}

function gitEnvironment() {
  return {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_ALLOW_PROTOCOL: '',
    GIT_PROTOCOL_FROM_USER: '0',
    GIT_ATTR_NOSYSTEM: '1',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin'
  };
}

function runGit(candidateDirectory, args, {
  encoding = 'buffer',
  input,
  maxBuffer = MAX_GIT_OUTPUT_BYTES
} = {}) {
  try {
    return execFileSync('/usr/bin/git', [
      '--no-replace-objects', '--literal-pathspecs',
      '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
      '-c', 'protocol.allow=never', ...args
    ], {
      cwd: candidateDirectory,
      encoding,
      env: gitEnvironment(),
      input,
      maxBuffer,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30_000,
      windowsHide: true
    });
  } catch {
    fail('CNYOS_FUNCTION_BUNDLE_GIT_COMMAND_FAILED');
  }
}

function exactCandidateCommit(value) {
  const normalized = required(
    value,
    'CNYOS_FUNCTION_BUNDLE_CANDIDATE_SHA_REQUIRED',
    40
  ).toLowerCase();
  if (value !== normalized || !SHA40.test(normalized)) {
    fail('CNYOS_FUNCTION_BUNDLE_CANDIDATE_SHA_INVALID');
  }
  return normalized;
}

export function parseFunctionBundleGitInventory(raw) {
  if (!Buffer.isBuffer(raw) || (raw.length && raw[raw.length - 1] !== 0)) {
    fail('CNYOS_FUNCTION_BUNDLE_GIT_TREE_INVALID');
  }
  const records = [];
  const exactPaths = new Set();
  const portablePaths = new Set();
  let start = 0;
  for (let index = 0; index < raw.length; index += 1) {
    if (raw[index] !== 0) continue;
    if (index === start) fail('CNYOS_FUNCTION_BUNDLE_GIT_TREE_INVALID');
    const record = raw.subarray(start, index);
    start = index + 1;
    const tab = record.indexOf(0x09);
    if (tab <= 0 || tab === record.length - 1) fail('CNYOS_FUNCTION_BUNDLE_GIT_TREE_INVALID');
    const header = decodeUtf8(
      record.subarray(0, tab),
      'CNYOS_FUNCTION_BUNDLE_GIT_TREE_INVALID'
    );
    const sourcePath = assertSafeFunctionSourcePath(decodeUtf8(
      record.subarray(tab + 1),
      'CNYOS_FUNCTION_BUNDLE_SOURCE_PATH_INVALID'
    ));
    const match = /^(100644|100755) blob ([0-9a-f]{40})$/.exec(header);
    if (!match) fail('CNYOS_FUNCTION_BUNDLE_NON_REGULAR_GIT_ENTRY');
    const portable = sourcePath.toLowerCase();
    if (exactPaths.has(sourcePath) || portablePaths.has(portable)) {
      fail('CNYOS_FUNCTION_BUNDLE_SOURCE_PATH_COLLISION');
    }
    exactPaths.add(sourcePath);
    portablePaths.add(portable);
    records.push(Object.freeze({ path: sourcePath, mode: match[1], gitObject: match[2] }));
  }
  if (!records.length || records.length > MAX_TREE_FILES) {
    fail('CNYOS_FUNCTION_BUNDLE_GIT_TREE_INVALID');
  }
  records.sort((left, right) => bytewiseCompare(left.path, right.path));
  return Object.freeze(records);
}

function gitBlobObject(bytes) {
  return sha1(Buffer.concat([Buffer.from(`blob ${bytes.byteLength}\0`, 'utf8'), bytes]));
}

function parseBatchCheck(raw, objectIds) {
  const lines = decodeUtf8(raw, 'CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID').split('\n');
  if (lines.at(-1) !== '') fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
  lines.pop();
  if (lines.length !== objectIds.length) fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
  const sizes = new Map();
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^([0-9a-f]{40}) blob (0|[1-9]\d*)$/.exec(lines[index]);
    const size = Number(match?.[2]);
    if (!match || match[1] !== objectIds[index] || !Number.isSafeInteger(size) ||
      size < 0 || size > MAX_FILE_BYTES) {
      fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
    }
    sizes.set(match[1], size);
  }
  return sizes;
}

function parseBatchBlobs(raw, objectIds, sizes) {
  const blobs = new Map();
  let cursor = 0;
  for (const objectId of objectIds) {
    const newline = raw.indexOf(0x0a, cursor);
    if (newline < cursor || newline - cursor > 128) {
      fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
    }
    const header = decodeUtf8(
      raw.subarray(cursor, newline),
      'CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID'
    );
    const size = sizes.get(objectId);
    if (header !== `${objectId} blob ${size}`) {
      fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
    }
    const start = newline + 1;
    const end = start + size;
    if (end >= raw.length || raw[end] !== 0x0a) {
      fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
    }
    const bytes = Buffer.from(raw.subarray(start, end));
    if (gitBlobObject(bytes) !== objectId) fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
    blobs.set(objectId, bytes);
    cursor = end + 1;
  }
  if (cursor !== raw.length) fail('CNYOS_FUNCTION_BUNDLE_GIT_BLOB_INVALID');
  return blobs;
}

function readImmutableGitBlobs(candidateDirectory, inventory) {
  const objectIds = [...new Set(inventory.map(entry => entry.gitObject))].sort();
  const batchInput = Buffer.from(`${objectIds.join('\n')}\n`, 'ascii');
  const check = runGit(candidateDirectory, [
    'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'
  ], {
    input: batchInput,
    maxBuffer: MAX_GIT_METADATA_BYTES
  });
  const sizes = parseBatchCheck(check, objectIds);
  let materializedBytes = 0;
  for (const entry of inventory) {
    materializedBytes += sizes.get(entry.gitObject);
    if (!Number.isSafeInteger(materializedBytes) || materializedBytes > MAX_TREE_BYTES) {
      fail('CNYOS_FUNCTION_BUNDLE_SOURCE_TREE_TOO_LARGE');
    }
  }
  const uniqueBytes = objectIds.reduce((total, objectId) => total + sizes.get(objectId), 0);
  const batch = runGit(candidateDirectory, ['cat-file', '--batch'], {
    input: batchInput,
    maxBuffer: uniqueBytes + MAX_GIT_METADATA_BYTES
  });
  return parseBatchBlobs(batch, objectIds, sizes);
}

function assertClosedWorldFunctionNames(functionBlobs) {
  const names = [];
  for (const entry of functionBlobs) {
    if (entry.path.includes('/')) continue;
    const match = /^([A-Za-z0-9_-]+)\.mts$/.exec(entry.path);
    if (!match) fail('CNYOS_FUNCTION_BUNDLE_ENTRYPOINT_INVALID');
    names.push(match[1]);
  }
  names.sort();
  const expected = [...EXPECTED_FUNCTION_NAMES].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    fail('CNYOS_FUNCTION_BUNDLE_FUNCTION_NAME_MISMATCH');
  }
}

export async function readFunctionBundleImmutableCommit(candidateDirectory, candidateCommit) {
  const directory = await assertCanonicalDirectory(
    candidateDirectory,
    'CNYOS_FUNCTION_BUNDLE_CANDIDATE_DIRECTORY_INVALID'
  );
  const commit = exactCandidateCommit(candidateCommit);
  const objectFormat = String(runGit(directory, ['rev-parse', '--show-object-format'], {
    encoding: 'utf8',
    maxBuffer: MAX_GIT_METADATA_BYTES
  })).trim();
  if (objectFormat !== 'sha1') fail('CNYOS_FUNCTION_BUNDLE_GIT_OBJECT_FORMAT_INVALID');
  const resolvedCommit = String(runGit(
    directory,
    ['rev-parse', '--verify', `${commit}^{commit}`],
    { encoding: 'utf8', maxBuffer: MAX_GIT_METADATA_BYTES }
  )).trim().toLowerCase();
  const candidateTree = String(runGit(
    directory,
    ['rev-parse', '--verify', `${commit}^{tree}`],
    { encoding: 'utf8', maxBuffer: MAX_GIT_METADATA_BYTES }
  )).trim().toLowerCase();
  const functionSourceTree = String(runGit(
    directory,
    ['rev-parse', '--verify', `${commit}:netlify/functions`],
    { encoding: 'utf8', maxBuffer: MAX_GIT_METADATA_BYTES }
  )).trim().toLowerCase();
  if (resolvedCommit !== commit || !SHA40.test(candidateTree) || !SHA40.test(functionSourceTree)) {
    fail('CNYOS_FUNCTION_BUNDLE_CANDIDATE_COMMIT_INVALID');
  }

  const inventory = parseFunctionBundleGitInventory(runGit(directory, [
    'ls-tree', '-r', '-z', '--full-tree', commit
  ]));
  const immutableBlobs = readImmutableGitBlobs(directory, inventory);
  const blobs = inventory.map(entry => Object.freeze({
    ...entry,
    bytes: Buffer.from(immutableBlobs.get(entry.gitObject))
  }));
  const prefix = 'netlify/functions/';
  const functionBlobs = blobs.filter(entry => entry.path.startsWith(prefix)).map(entry =>
    Object.freeze({ ...entry, path: entry.path.slice(prefix.length) })
  );
  if (!functionBlobs.length || functionBlobs.some(entry => !entry.path)) {
    fail('CNYOS_FUNCTION_BUNDLE_FUNCTION_SOURCE_EMPTY');
  }
  assertClosedWorldFunctionNames(functionBlobs);
  const sourceFiles = functionBlobs.map(entry => Object.freeze({
    path: entry.path,
    size: entry.bytes.byteLength,
    sha256: sha256(entry.bytes),
    gitObject: entry.gitObject
  })).sort((left, right) => bytewiseCompare(left.path, right.path));
  return Object.freeze({
    candidateCommit: commit,
    candidateTree,
    functionSourceTree,
    blobs: Object.freeze(blobs),
    sourceFiles: Object.freeze(sourceFiles),
    sourceFilesSha256: sha256(JSON.stringify(sourceFiles))
  });
}

function readHeadCommit(candidateDirectory) {
  const head = String(runGit(
    candidateDirectory,
    ['rev-parse', '--verify', 'HEAD^{commit}'],
    { encoding: 'utf8', maxBuffer: MAX_GIT_METADATA_BYTES }
  )).trim().toLowerCase();
  if (!SHA40.test(head)) fail('CNYOS_FUNCTION_BUNDLE_CANDIDATE_CHECKOUT_MISMATCH');
  return head;
}

export async function readFunctionBundleCandidateSnapshot(candidateDirectory, candidateCommit) {
  const directory = await assertCanonicalDirectory(
    candidateDirectory,
    'CNYOS_FUNCTION_BUNDLE_CANDIDATE_DIRECTORY_INVALID'
  );
  const commit = exactCandidateCommit(candidateCommit);
  if (readHeadCommit(directory) !== commit) {
    fail('CNYOS_FUNCTION_BUNDLE_CANDIDATE_CHECKOUT_MISMATCH');
  }
  const snapshot = await readFunctionBundleImmutableCommit(directory, commit);
  if (readHeadCommit(directory) !== commit) {
    fail('CNYOS_FUNCTION_BUNDLE_CANDIDATE_CHECKOUT_MISMATCH');
  }
  return snapshot;
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

function safeZipPath(value) {
  const archivePath = assertPortableRelativePath(
    value,
    'CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_INVALID'
  );
  const components = archivePath.split('/');
  if (components.some(component => component.toLowerCase() === '.git' ||
    /^\.env(?:\.|$)/i.test(component)) || /\.(?:key|pem)$/i.test(components.at(-1))) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_FORBIDDEN_PATH');
  }
  return archivePath;
}

function findEndOfCentralDirectory(bytes) {
  const minimum = Math.max(0, bytes.length - 65_557);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
}

function registerArchivePath(name, files, directories) {
  const portable = name.toLowerCase();
  if (files.has(portable) || directories.has(portable)) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_COLLISION');
  }
  const components = portable.split('/');
  let prefix = '';
  for (let index = 0; index < components.length - 1; index += 1) {
    prefix = prefix ? `${prefix}/${components[index]}` : components[index];
    if (files.has(prefix)) fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_COLLISION');
    directories.add(prefix);
  }
  files.add(portable);
}

function inflateZipEntry(method, compressed, expectedSize, remainingBudget) {
  if (expectedSize > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES || expectedSize > remainingBudget) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE');
  }
  if (method === ZIP_STORE_METHOD) {
    if (compressed.byteLength !== expectedSize) fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    return Buffer.from(compressed);
  }
  if (method !== ZIP_DEFLATE_METHOD) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_COMPRESSION_INVALID');
  }
  let result;
  try {
    result = zlib.inflateRawSync(compressed, {
      info: true,
      maxOutputLength: Math.min(expectedSize, remainingBudget) + 1
    });
  } catch {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
  }
  if (!result || !Buffer.isBuffer(result.buffer) ||
    !Number.isSafeInteger(result.engine?.bytesWritten) ||
    result.engine.bytesWritten !== compressed.byteLength) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
  }
  return Buffer.from(result.buffer);
}

export function readFunctionBundleZipEntries(archiveBytes) {
  const bytes = Buffer.isBuffer(archiveBytes) ? archiveBytes : Buffer.from(archiveBytes || '');
  if (bytes.length < 22 || bytes.length > MAX_FILE_BYTES) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
  }
  const eocd = findEndOfCentralDirectory(bytes);
  const disk = bytes.readUInt16LE(eocd + 4);
  const centralDisk = bytes.readUInt16LE(eocd + 6);
  const diskEntries = bytes.readUInt16LE(eocd + 8);
  const totalEntries = bytes.readUInt16LE(eocd + 10);
  const centralSize = bytes.readUInt32LE(eocd + 12);
  const centralOffset = bytes.readUInt32LE(eocd + 16);
  const commentLength = bytes.readUInt16LE(eocd + 20);
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries || !totalEntries ||
    totalEntries > MAX_ZIP_ENTRIES || commentLength !== 0 || eocd + 22 !== bytes.length ||
    centralSize < totalEntries * 46 || centralOffset === 0 || centralOffset > eocd ||
    centralSize !== eocd - centralOffset ||
    (eocd >= 20 && bytes.readUInt32LE(eocd - 20) === 0x07064b50)) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
  }

  const metadata = [];
  const portableFiles = new Set();
  const portableDirectories = new Set();
  let cursor = centralOffset;
  let declaredUncompressed = 0;
  for (let index = 0; index < totalEntries; index += 1) {
    if (cursor + 46 > eocd || bytes.readUInt32LE(cursor) !== 0x02014b50) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    }
    const versionMadeBy = bytes.readUInt16LE(cursor + 4);
    const versionNeeded = bytes.readUInt16LE(cursor + 6);
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const modifiedTime = bytes.readUInt16LE(cursor + 12);
    const modifiedDate = bytes.readUInt16LE(cursor + 14);
    const expectedCrc = bytes.readUInt32LE(cursor + 16);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const uncompressedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const entryCommentLength = bytes.readUInt16LE(cursor + 32);
    const startDisk = bytes.readUInt16LE(cursor + 34);
    const internalAttributes = bytes.readUInt16LE(cursor + 36);
    const externalAttributes = bytes.readUInt32LE(cursor + 38);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const centralEnd = cursor + 46 + nameLength + extraLength + entryCommentLength;
    const unixMode = externalAttributes >>> 16;
    if (versionMadeBy !== ZIP_UNIX_VERSION || versionNeeded !== ZIP_VERSION ||
      flags !== ZIP_UTF8_FLAG || ![ZIP_STORE_METHOD, ZIP_DEFLATE_METHOD].includes(method) ||
      !nameLength || extraLength !== 0 || entryCommentLength !== 0 || startDisk !== 0 ||
      internalAttributes !== 0 || (externalAttributes & 0xffff) !== 0 ||
      ![0o100644, 0o100755].includes(unixMode) || centralEnd > eocd ||
      compressedSize === 0xffffffff || uncompressedSize === 0xffffffff ||
      compressedSize > MAX_FILE_BYTES ||
      uncompressedSize > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES ||
      (method === ZIP_STORE_METHOD && compressedSize !== uncompressedSize)) {
      fail(uncompressedSize > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES
        ? 'CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE'
        : 'CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    }
    declaredUncompressed += uncompressedSize;
    if (!Number.isSafeInteger(declaredUncompressed) ||
      declaredUncompressed > MAX_ZIP_UNCOMPRESSED_BYTES) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE');
    }
    const nameBytes = Buffer.from(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    const name = safeZipPath(decodeUtf8(
      nameBytes,
      'CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_INVALID'
    ));
    registerArchivePath(name, portableFiles, portableDirectories);
    metadata.push(Object.freeze({
      compressedSize,
      expectedCrc,
      flags,
      localOffset,
      method,
      modifiedDate,
      modifiedTime,
      name,
      nameBytes,
      uncompressedSize,
      versionNeeded
    }));
    cursor = centralEnd;
  }
  if (cursor !== eocd) fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');

  const entries = [];
  const localRanges = [];
  let inflatedBytes = 0;
  for (const entry of metadata) {
    const { localOffset } = entry;
    if (localOffset + 30 > centralOffset || bytes.readUInt32LE(localOffset) !== 0x04034b50) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    }
    const localVersion = bytes.readUInt16LE(localOffset + 4);
    const localFlags = bytes.readUInt16LE(localOffset + 6);
    const localMethod = bytes.readUInt16LE(localOffset + 8);
    const localTime = bytes.readUInt16LE(localOffset + 10);
    const localDate = bytes.readUInt16LE(localOffset + 12);
    const localCrc = bytes.readUInt32LE(localOffset + 14);
    const localCompressedSize = bytes.readUInt32LE(localOffset + 18);
    const localUncompressedSize = bytes.readUInt32LE(localOffset + 22);
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const localNameStart = localOffset + 30;
    const dataStart = localNameStart + localNameLength;
    if (localVersion !== entry.versionNeeded || localFlags !== entry.flags ||
      localMethod !== entry.method || localTime !== entry.modifiedTime ||
      localDate !== entry.modifiedDate || localCrc !== entry.expectedCrc ||
      localCompressedSize !== entry.compressedSize ||
      localUncompressedSize !== entry.uncompressedSize || localExtraLength !== 0 ||
      localNameLength !== entry.nameBytes.byteLength || dataStart > centralOffset ||
      !bytes.subarray(localNameStart, dataStart).equals(entry.nameBytes) ||
      entry.compressedSize > centralOffset - dataStart) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    }
    const dataEnd = dataStart + entry.compressedSize;
    const content = inflateZipEntry(
      entry.method,
      bytes.subarray(dataStart, dataEnd),
      entry.uncompressedSize,
      MAX_ZIP_UNCOMPRESSED_BYTES - inflatedBytes
    );
    if (content.byteLength !== entry.uncompressedSize || crc32(content) !== entry.expectedCrc) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    }
    inflatedBytes += content.byteLength;
    entries.push(Object.freeze({ path: entry.name, bytes: content }));
    localRanges.push([localOffset, dataEnd]);
  }
  localRanges.sort((left, right) => left[0] - right[0]);
  if (localRanges[0][0] !== 0 || localRanges.at(-1)[1] !== centralOffset) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
  }
  for (let index = 1; index < localRanges.length; index += 1) {
    if (localRanges[index][0] !== localRanges[index - 1][1]) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
    }
  }
  return Object.freeze(entries.sort((left, right) => bytewiseCompare(left.path, right.path)));
}

function deterministicZip(entries) {
  if (!Array.isArray(entries) || !entries.length || entries.length > MAX_ZIP_ENTRIES) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_INVALID');
  }
  const ordered = [...entries].sort((left, right) => bytewiseCompare(left.path, right.path));
  const localParts = [];
  const centralParts = [];
  let localSize = 0;
  let centralSize = 0;
  let uncompressedSize = 0;
  for (const entry of ordered) {
    const name = safeZipPath(entry.path);
    const nameBytes = Buffer.from(name, 'utf8');
    const content = Buffer.isBuffer(entry.bytes) ? entry.bytes : Buffer.from(entry.bytes || '');
    if (nameBytes.length > 0xffff || content.length > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE');
    }
    uncompressedSize += content.length;
    const projectedLocalSize = localSize + 30 + nameBytes.length + content.length;
    const projectedCentralSize = centralSize + 46 + nameBytes.length;
    if (!Number.isSafeInteger(uncompressedSize) || uncompressedSize > MAX_ZIP_UNCOMPRESSED_BYTES ||
      projectedLocalSize + projectedCentralSize + 22 > MAX_FILE_BYTES) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE');
    }
    const checksum = crc32(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(ZIP_VERSION, 4);
    local.writeUInt16LE(ZIP_UTF8_FLAG, 6);
    local.writeUInt16LE(ZIP_STORE_METHOD, 8);
    local.writeUInt16LE(FIXED_DOS_TIME, 10);
    local.writeUInt16LE(FIXED_DOS_DATE, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, nameBytes, content);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(ZIP_UNIX_VERSION, 4);
    central.writeUInt16LE(ZIP_VERSION, 6);
    central.writeUInt16LE(ZIP_UTF8_FLAG, 8);
    central.writeUInt16LE(ZIP_STORE_METHOD, 10);
    central.writeUInt16LE(FIXED_DOS_TIME, 12);
    central.writeUInt16LE(FIXED_DOS_DATE, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    central.writeUInt32LE(localSize, 42);
    centralParts.push(central, nameBytes);
    localSize = projectedLocalSize;
    centralSize = projectedCentralSize;
  }
  const totalSize = localSize + centralSize + 22;
  if (totalSize > MAX_FILE_BYTES) fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_TOO_LARGE');
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(ordered.length, 8);
  eocd.writeUInt16LE(ordered.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(localSize, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, ...centralParts, eocd], totalSize);
}

function assertFunctionArchiveLayout(entries, functionName) {
  const paths = new Set(entries.map(entry => entry.path));
  // ZISI 15.5.1's Node API v2 ESM layout with explicit repository basePath.
  // This is a structural check only, not authentication of bootstrap/app code.
  // Partial v2 output must not fall back to acceptance of a legacy named file.
  if (paths.has('___netlify-entry-point.mjs') || paths.has('___netlify-bootstrap.mjs')) {
    if (!['___netlify-entry-point.mjs', '___netlify-bootstrap.mjs',
      `netlify/functions/${functionName}.mjs`].every(name => paths.has(name))) {
      fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_HANDLER_MISSING');
    }
    return;
  }
  if (!['.cjs', '.js', '.mjs'].some(extension => paths.has(`${functionName}${extension}`))) {
    fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_HANDLER_MISSING');
  }
}

export function canonicalizeFunctionBundleArchive(archiveBytes, functionName) {
  if (!EXPECTED_FUNCTION_NAMES.includes(functionName)) {
    fail('CNYOS_FUNCTION_BUNDLE_FUNCTION_NAME_MISMATCH');
  }
  const entries = readFunctionBundleZipEntries(archiveBytes);
  assertFunctionArchiveLayout(entries, functionName);
  return deterministicZip(entries);
}

function sameFilesystemIdentity(before, after) {
  return before.dev === after.dev && before.ino === after.ino &&
    before.mode === after.mode && before.nlink === after.nlink &&
    before.size === after.size && before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs;
}

async function readBuildOutputFile(filename, before, remainingBytes) {
  const code = 'CNYOS_FUNCTION_BUNDLE_BUILD_OUTPUT_CHANGED';
  const limit = Math.min(MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES, remainingBytes);
  if (before.size > BigInt(limit)) fail('CNYOS_FUNCTION_BUNDLE_BUILD_OUTPUT_TOO_LARGE');
  let handle;
  try {
    handle = await fs.open(filename,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameFilesystemIdentity(before, opened)) fail(code);
    // Bound allocation and each read even if a producer has unexpectedly resumed.
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await handle.read(bytes, used, bytes.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const named = await fs.lstat(filename, { bigint: true });
    if (used !== Number(before.size) || !sameFilesystemIdentity(before, after) ||
      !sameFilesystemIdentity(before, named)) fail(code);
    return bytes.subarray(0, used);
  } catch (error) {
    if (error?.message === code) throw error;
    fail(code);
  } finally {
    if (handle) await handle.close();
  }
}

// Consume a stopped, unprivileged builder's unpacked output: one directory per
// expected Function, with a named legacy handler or the complete v2 ESM layout.
// This performs real file reads and archive assembly without loading those files
// as modules, running a compiler, writing deploy output, or issuing evidence.
// The caller still has to establish the builder/toolchain and source provenance.
export async function collectFunctionBundleDirectory(buildDirectory) {
  const code = 'CNYOS_FUNCTION_BUNDLE_BUILD_OUTPUT_INVALID';
  const root = await assertCanonicalDirectory(buildDirectory, code);
  const identities = new Map();
  const portableNames = new Set();
  const expected = new Set(EXPECTED_FUNCTION_NAMES);
  const archives = [];
  let entryCount = 0;
  let rawBytes = 0;
  let archiveBytes = 0;

  async function inspect(filename, relative) {
    if (++entryCount > MAX_ZIP_ENTRIES) fail('CNYOS_FUNCTION_BUNDLE_BUILD_OUTPUT_TOO_LARGE');
    if (relative) {
      safeZipPath(relative);
      const portable = relative.toLowerCase();
      if (portableNames.has(portable)) fail('CNYOS_FUNCTION_BUNDLE_ARCHIVE_PATH_COLLISION');
      portableNames.add(portable);
    }
    const status = await fs.lstat(filename, { bigint: true });
    if (status.isSymbolicLink() || (!status.isDirectory() && !status.isFile()) ||
      (status.mode & 0o7022n) !== 0n || (status.isFile() && status.nlink !== 1n)) fail(code);
    if (status.isFile() && ![0o100600n, 0o100644n, 0o100700n, 0o100755n].includes(status.mode)) fail(code);
    if (status.isDirectory() && await fs.realpath(filename) !== filename) fail(code);
    identities.set(filename, status);
    return status;
  }

  async function visit(directory, functionName, prefix, entries, budget) {
    const reader = await fs.opendir(directory);
    for await (const entry of reader) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const fullRelative = `${functionName}/${relative}`;
      safeZipPath(fullRelative);
      const filename = path.join(directory, entry.name);
      const status = await inspect(filename, fullRelative);
      if (status.isDirectory()) {
        await visit(filename, functionName, relative, entries, budget);
      } else {
        const bytes = await readBuildOutputFile(filename, status,
          Math.min(MAX_ZIP_UNCOMPRESSED_BYTES - budget.bytes, MAX_TREE_BYTES - rawBytes));
        budget.bytes += bytes.length;
        rawBytes += bytes.length;
        entries.push({ path: relative, bytes });
      }
    }
  }

  await inspect(root, '');
  const reader = await fs.opendir(root);
  for await (const entry of reader) {
    if (!expected.delete(entry.name)) fail('CNYOS_FUNCTION_BUNDLE_FUNCTION_NAME_MISMATCH');
    const directory = path.join(root, entry.name);
    const status = await inspect(directory, entry.name);
    if (!status.isDirectory()) fail(code);
    const entries = [];
    await visit(directory, entry.name, '', entries, { bytes: 0 });
    assertFunctionArchiveLayout(entries, entry.name);
    const bytes = deterministicZip(entries);
    archiveBytes += bytes.length;
    if (archiveBytes > MAX_TREE_BYTES) fail('CNYOS_FUNCTION_BUNDLE_BUILD_OUTPUT_TOO_LARGE');
    archives.push(Object.freeze({ path: `${entry.name}.zip`, size: bytes.length, sha256: sha256(bytes), bytes }));
  }
  if (expected.size) fail('CNYOS_FUNCTION_BUNDLE_FUNCTION_NAME_MISMATCH');
  // Catch replaced files/directories and additions/removals anywhere in the tree
  // before returning the in-memory byte snapshot. Atime changes do not affect it.
  for (const [filename, before] of identities) {
    if (!sameFilesystemIdentity(before, await fs.lstat(filename, { bigint: true }))) {
      fail('CNYOS_FUNCTION_BUNDLE_BUILD_OUTPUT_CHANGED');
    }
  }
  archives.sort((left, right) => bytewiseCompare(left.path, right.path));
  return Object.freeze(archives);
}

// Equality is about these two byte snapshots only. It does not establish that
// their builders were independent, isolated, approved, or source-reproducible.
export async function compareFunctionBundleDirectories(firstDirectory, secondDirectory) {
  const code = 'CNYOS_FUNCTION_BUNDLE_BUILD_DIRECTORIES_NOT_ISOLATED';
  const first = await assertCanonicalDirectory(firstDirectory, code);
  const second = await assertCanonicalDirectory(secondDirectory, code);
  if (first === second || first.startsWith(`${second}${path.sep}`) ||
    second.startsWith(`${first}${path.sep}`)) fail(code);
  const left = await collectFunctionBundleDirectory(first);
  const right = await collectFunctionBundleDirectory(second);
  if (left.length !== right.length || left.some((file, index) =>
    file.path !== right[index].path || !file.bytes.equals(right[index].bytes))) {
    fail('CNYOS_FUNCTION_BUNDLE_BUILD_BYTES_DIFFER');
  }
  return left;
}

export async function createControllerFunctionBundle({ env = process.env } = {}) {
  assertFunctionBundleCredentialFree(env);
  assertControllerRuntime(env);

  // Activation requires a separately protected, digest-pinned hermetic builder whose
  // network namespace, minimal generated config, complete toolchain filesystem and
  // post-build identity are independently verified. This repository contains no such
  // reviewed runner contract, so this entry point must not execute a local tool or
  // publish Function evidence.
  fail(FUNCTION_BUNDLE_NOT_ACTIVATED_CODE);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  createControllerFunctionBundle().catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_FUNCTION_BUNDLE_FAILED')}\n`);
    process.exitCode = 1;
  });
}
