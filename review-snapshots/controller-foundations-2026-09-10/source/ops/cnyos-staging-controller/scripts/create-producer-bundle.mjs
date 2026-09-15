import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY,
  POLICY_SHA256,
  EXPECTED_FUNCTION_NAMES,
  MAX_FILE_BYTES,
  REQUIRED_SCHEDULES,
  aggregateDigest,
  assertControllerRuntime,
  canonicalIsoTimestamp,
  decodeNonce,
  exactSha40,
  exactSha256,
  fail,
  isPlainObject,
  portableRelativePath,
  readFileBounded,
  readRegularFileStable,
  required,
  sha1,
  sha256,
  walkRegularFiles,
  writeJsonExclusive
} from './policy.mjs';

const requiredDistFiles = Object.freeze([
  '_headers',
  '_redirects',
  'brand-config.js',
  'deploy-manifest.json',
  'index.html',
  'runtime-publish-manifest.json',
  'tenant-config.js'
]);

const MAX_GIT_TREE_BYTES = 4 * 1024 * 1024;
const MAX_GIT_SOURCE_FILES = 4096;
const MAX_GIT_SOURCE_BYTES = 128 * 1024 * 1024;
const MAX_GIT_PATH_BYTES = 4096;
const MAX_GIT_PROTOCOL_LINE_BYTES = 256;
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });

function runGit(candidateDirectory, args, encoding = 'utf8', options = {}) {
  const isolated = { ...process.env };
  for (const name of Object.keys(isolated)) {
    if (name.startsWith('GIT_')) delete isolated[name];
  }
  isolated.GIT_CONFIG_NOSYSTEM = '1';
  isolated.GIT_CONFIG_GLOBAL = '/dev/null';
  isolated.GIT_NO_REPLACE_OBJECTS = '1';
  isolated.GIT_OPTIONAL_LOCKS = '0';
  isolated.LC_ALL = 'C';
  return execFileSync('git', ['--no-replace-objects', '--literal-pathspecs', ...args], {
    cwd: candidateDirectory,
    encoding,
    env: isolated,
    input: options.input,
    maxBuffer: options.maxBuffer || 64 * 1024 * 1024,
    stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe']
  });
}

function gitOutput(candidateDirectory, args, encoding, code, options = {}) {
  try {
    return runGit(candidateDirectory, args, encoding, options);
  } catch {
    fail(code);
  }
}

function exactGitObjectId(raw, code) {
  const value = String(raw).trim();
  if (!/^[0-9a-f]{40}$/.test(value)) fail(code);
  return value;
}

function checkoutHead(candidateDirectory) {
  return exactGitObjectId(gitOutput(
    candidateDirectory,
    ['rev-parse', '--verify', 'HEAD^{commit}'],
    'utf8',
    'CNYOS_PRODUCER_CANDIDATE_CHECKOUT_MISMATCH'
  ), 'CNYOS_PRODUCER_CANDIDATE_CHECKOUT_MISMATCH');
}

function decodeGitPath(bytes, code) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_GIT_PATH_BYTES) fail(code);
  let value;
  try { value = fatalUtf8.decode(bytes); }
  catch { fail(code); }
  return portableRelativePath(value, code);
}

export function parseImmutableGitBlobInventory(raw, {
  rootPath = '',
  maximumFiles = MAX_GIT_SOURCE_FILES,
  maximumTreeBytes = MAX_GIT_TREE_BYTES,
  code = 'CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID'
} = {}) {
  if (!Buffer.isBuffer(raw) || !Number.isSafeInteger(maximumFiles) || maximumFiles < 1 ||
    !Number.isSafeInteger(maximumTreeBytes) || maximumTreeBytes < 1 ||
    raw.length > maximumTreeBytes || (raw.length > 0 && raw[raw.length - 1] !== 0)) fail(code);
  const normalizedRoot = rootPath ? portableRelativePath(rootPath, code) : '';
  const prefix = normalizedRoot ? `${normalizedRoot}/` : '';
  const result = [];
  const exactPaths = new Set();
  const portablePaths = new Set();
  let offset = 0;
  while (offset < raw.length) {
    const end = raw.indexOf(0, offset);
    if (end < 0 || end === offset || result.length >= maximumFiles) fail(code);
    const record = raw.subarray(offset, end);
    offset = end + 1;
    const separator = record.indexOf(9);
    if (separator < 1) fail(code);
    const header = record.subarray(0, separator).toString('ascii');
    const match = /^(100644|100755) blob ([0-9a-f]{40})$/.exec(header);
    if (!match) fail(code);
    const fullPath = decodeGitPath(record.subarray(separator + 1), code);
    if (prefix && !fullPath.startsWith(prefix)) fail(code);
    const relativePath = prefix ? fullPath.slice(prefix.length) : fullPath;
    portableRelativePath(relativePath, code);
    const portableKey = relativePath.toLowerCase();
    if (exactPaths.has(relativePath)) fail(code);
    if (portablePaths.has(portableKey)) fail('CNYOS_PRODUCER_FUNCTION_PATH_COLLISION');
    exactPaths.add(relativePath);
    portablePaths.add(portableKey);
    result.push(Object.freeze({
      relativePath,
      mode: match[1],
      object: match[2]
    }));
  }
  for (const entry of result) {
    const parts = entry.relativePath.toLowerCase().split('/');
    for (let index = 1; index < parts.length; index += 1) {
      if (portablePaths.has(parts.slice(0, index).join('/'))) {
        fail('CNYOS_PRODUCER_FUNCTION_FILE_DIRECTORY_CONFLICT');
      }
    }
  }
  return Object.freeze(result.sort((left, right) =>
    left.relativePath.localeCompare(right.relativePath)));
}

export function parseImmutableGitBlobBatchCheck(raw, expectedObjects, {
  maximumFileBytes = MAX_FILE_BYTES,
  code = 'CNYOS_PRODUCER_GIT_BLOB_METADATA_INVALID'
} = {}) {
  if (!Buffer.isBuffer(raw) || !Array.isArray(expectedObjects) ||
    !Number.isSafeInteger(maximumFileBytes) || maximumFileBytes < 0 ||
    (raw.length > 0 && raw[raw.length - 1] !== 10)) fail(code);
  const lines = raw.length ? raw.subarray(0, raw.length - 1).toString('ascii').split('\n') : [];
  if (lines.length !== expectedObjects.length) fail(code);
  const result = new Map();
  for (let index = 0; index < lines.length; index += 1) {
    if (Buffer.byteLength(lines[index], 'ascii') > MAX_GIT_PROTOCOL_LINE_BYTES) fail(code);
    const match = /^([0-9a-f]{40}) blob ([0-9]+)$/.exec(lines[index]);
    const expected = expectedObjects[index];
    if (!match || match[1] !== expected || result.has(expected)) fail(code);
    const size = Number(match[2]);
    if (!Number.isSafeInteger(size) || size < 0 || size > maximumFileBytes) fail(code);
    result.set(expected, size);
  }
  return result;
}

export function parseImmutableGitBlobBatch(raw, expectedObjects, objectSizes, {
  code = 'CNYOS_PRODUCER_GIT_BLOB_CONTENT_INVALID'
} = {}) {
  if (!Buffer.isBuffer(raw) || !Array.isArray(expectedObjects) || !(objectSizes instanceof Map)) {
    fail(code);
  }
  const result = new Map();
  let offset = 0;
  for (const expected of expectedObjects) {
    const headerEnd = raw.indexOf(10, offset);
    if (headerEnd < offset || headerEnd - offset > MAX_GIT_PROTOCOL_LINE_BYTES) fail(code);
    const header = raw.subarray(offset, headerEnd).toString('ascii');
    const match = /^([0-9a-f]{40}) blob ([0-9]+)$/.exec(header);
    const expectedSize = objectSizes.get(expected);
    if (!match || match[1] !== expected || Number(match[2]) !== expectedSize) fail(code);
    const contentStart = headerEnd + 1;
    const contentEnd = contentStart + expectedSize;
    if (!Number.isSafeInteger(contentEnd) || contentEnd >= raw.length || raw[contentEnd] !== 10) {
      fail(code);
    }
    const bytes = Buffer.from(raw.subarray(contentStart, contentEnd));
    if (sha1(Buffer.concat([
      Buffer.from(`blob ${bytes.byteLength}\0`, 'ascii'),
      bytes
    ])) !== expected) fail('CNYOS_PRODUCER_GIT_OBJECT_HASH_MISMATCH');
    result.set(expected, bytes);
    offset = contentEnd + 1;
  }
  if (offset !== raw.length) fail(code);
  return result;
}

export function assertImmutableGitBlobLimits(inventory, objectSizes, {
  maximumFiles = MAX_GIT_SOURCE_FILES + 1,
  maximumAggregateBytes = MAX_GIT_SOURCE_BYTES,
  code = 'CNYOS_PRODUCER_GIT_BLOB_INVENTORY_INVALID'
} = {}) {
  if (!Array.isArray(inventory) || !(objectSizes instanceof Map) ||
    !Number.isSafeInteger(maximumFiles) || maximumFiles < 1 ||
    !Number.isSafeInteger(maximumAggregateBytes) || maximumAggregateBytes < 0 ||
    !inventory.length || inventory.length > maximumFiles) fail(code);
  let aggregateSize = 0;
  for (const entry of inventory) {
    const size = objectSizes.get(entry?.object);
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_BYTES) fail(code);
    aggregateSize += size;
    if (!Number.isSafeInteger(aggregateSize) || aggregateSize > maximumAggregateBytes) {
      fail('CNYOS_PRODUCER_GIT_SOURCE_AGGREGATE_TOO_LARGE');
    }
  }
  return aggregateSize;
}

function readImmutableGitBlobs(candidateDirectory, inventory) {
  if (!Array.isArray(inventory)) fail('CNYOS_PRODUCER_GIT_BLOB_INVENTORY_INVALID');
  const objects = [...new Set(inventory.map(entry => entry.object))];
  const input = Buffer.from(`${objects.join('\n')}\n`, 'ascii');
  const metadataRaw = gitOutput(
    candidateDirectory,
    ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
    'buffer',
    'CNYOS_PRODUCER_GIT_BLOB_METADATA_INVALID',
    { input, maxBuffer: Math.max(1024, objects.length * MAX_GIT_PROTOCOL_LINE_BYTES) }
  );
  const sizes = parseImmutableGitBlobBatchCheck(metadataRaw, objects);
  assertImmutableGitBlobLimits(inventory, sizes);
  const uniqueAggregateSize = objects.reduce((total, object) => total + sizes.get(object), 0);
  const batchRaw = gitOutput(
    candidateDirectory,
    ['cat-file', '--batch'],
    'buffer',
    'CNYOS_PRODUCER_GIT_BLOB_CONTENT_INVALID',
    {
      input,
      maxBuffer: uniqueAggregateSize + (objects.length * MAX_GIT_PROTOCOL_LINE_BYTES) + 1
    }
  );
  return parseImmutableGitBlobBatch(batchRaw, objects, sizes);
}

function loadImmutableCandidateSource(candidateDirectory, candidateCommit) {
  const commitType = String(gitOutput(
    candidateDirectory,
    ['cat-file', '-t', candidateCommit],
    'utf8',
    'CNYOS_PRODUCER_CANDIDATE_OBJECT_INVALID'
  )).trim();
  if (commitType !== 'commit') fail('CNYOS_PRODUCER_CANDIDATE_OBJECT_INVALID');
  const candidateTree = exactGitObjectId(gitOutput(
    candidateDirectory,
    ['rev-parse', '--verify', `${candidateCommit}^{tree}`],
    'utf8',
    'CNYOS_PRODUCER_CANDIDATE_TREE_INVALID'
  ), 'CNYOS_PRODUCER_CANDIDATE_TREE_INVALID');
  const functionSourceTree = exactGitObjectId(gitOutput(
    candidateDirectory,
    ['rev-parse', '--verify', `${candidateCommit}:netlify/functions`],
    'utf8',
    'CNYOS_PRODUCER_FUNCTION_TREE_INVALID'
  ), 'CNYOS_PRODUCER_FUNCTION_TREE_INVALID');
  const functionType = String(gitOutput(
    candidateDirectory,
    ['cat-file', '-t', `${candidateCommit}:netlify/functions`],
    'utf8',
    'CNYOS_PRODUCER_FUNCTION_TREE_INVALID'
  )).trim();
  if (functionType !== 'tree') fail('CNYOS_PRODUCER_FUNCTION_TREE_INVALID');

  const functionInventory = parseImmutableGitBlobInventory(gitOutput(
    candidateDirectory,
    ['ls-tree', '-r', '-z', '--full-tree', candidateCommit, '--', 'netlify/functions'],
    'buffer',
    'CNYOS_PRODUCER_FUNCTION_GIT_INVENTORY_INVALID',
    { maxBuffer: MAX_GIT_TREE_BYTES }
  ), { rootPath: 'netlify/functions' });
  if (!functionInventory.length) fail('CNYOS_PRODUCER_FUNCTION_TREE_EMPTY');
  const lockInventory = parseImmutableGitBlobInventory(gitOutput(
    candidateDirectory,
    ['ls-tree', '-z', '--full-tree', candidateCommit, '--', 'package-lock.json'],
    'buffer',
    'CNYOS_PRODUCER_DEPENDENCY_LOCK_GIT_ENTRY_INVALID',
    { maxBuffer: 8192 }
  ), {
    maximumFiles: 1,
    maximumTreeBytes: 8192,
    code: 'CNYOS_PRODUCER_DEPENDENCY_LOCK_GIT_ENTRY_INVALID'
  });
  if (lockInventory.length !== 1 || lockInventory[0].relativePath !== 'package-lock.json') {
    fail('CNYOS_PRODUCER_DEPENDENCY_LOCK_GIT_ENTRY_INVALID');
  }
  const allInventory = [...functionInventory, lockInventory[0]];
  const blobs = readImmutableGitBlobs(candidateDirectory, allInventory);
  return Object.freeze({
    candidateTree,
    functionSourceTree,
    functionInventory,
    functionBlobs: blobs,
    candidateDependencyLockBytes: blobs.get(lockInventory[0].object)
  });
}

async function fileEntry(file, { gitObject = null } = {}) {
  const bytes = await readRegularFileStable(
    file.absolutePath,
    MAX_FILE_BYTES,
    'CNYOS_PRODUCER_ARTIFACT_FILE_CHANGED'
  );
  return Object.freeze({
    path: file.manifestPath,
    size: bytes.byteLength,
    sha256: sha256(bytes),
    ...(gitObject ? { gitObject } : {}),
    bytes,
    sourcePath: file.absolutePath
  });
}

function assertStagingDeployManifest(bytes, candidateCommit, candidateTree) {
  let manifest;
  try { manifest = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_PRODUCER_DEPLOY_MANIFEST_INVALID'); }
  if (!isPlainObject(manifest) || manifest.schemaVersion !== 1 ||
    manifest.deploymentId !== POLICY.target.deploymentId ||
    manifest.source?.verified !== true ||
    manifest.source?.commit !== candidateCommit ||
    manifest.source?.tree !== candidateTree ||
    manifest.tenant?.expectedClinicId !== POLICY.target.clinicId ||
    manifest.tenant?.expectedClinicCode !== POLICY.target.clinicCode ||
    manifest.identity?.qrIssuer !== POLICY.target.qrIssuer ||
    manifest.build?.context !== 'production' ||
    manifest.build?.deploymentClass !== 'dedicated-staging' ||
    !Number.isFinite(Date.parse(manifest.build?.timestamp || '')) ||
    manifest.safety?.previewLocked !== false ||
    manifest.safety?.databaseLocked !== false ||
    manifest.safety?.stagingDatabaseExplicitlyAcknowledged !== true) {
    fail('CNYOS_PRODUCER_DEPLOY_MANIFEST_INVALID');
  }
  return manifest;
}

function assertRuntimeManifest(bytes, distEntries) {
  let manifest;
  try { manifest = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_PRODUCER_RUNTIME_MANIFEST_INVALID'); }
  if (!isPlainObject(manifest) || manifest.schemaVersion !== 2 ||
    manifest.integrityAlgorithm !== 'sha256' || !Array.isArray(manifest.files) ||
    !Array.isArray(manifest.integrity) || manifest.fileCount !== manifest.files.length ||
    manifest.files.length !== manifest.integrity.length) {
    fail('CNYOS_PRODUCER_RUNTIME_MANIFEST_INVALID');
  }
  const expectedEntries = distEntries
    .filter(item => item.path.startsWith('payload/dist/') &&
      item.path !== 'payload/dist/runtime-publish-manifest.json')
    .map(item => Object.freeze({
      path: item.path.slice('payload/dist/'.length),
      size: item.size,
      sha256: item.sha256
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const expected = expectedEntries.map(item => item.path);
  if (!manifest.files.every(item => typeof item === 'string') ||
    !isDeepStrictEqual(manifest.files, expected)) {
    fail('CNYOS_PRODUCER_RUNTIME_FILESET_MISMATCH');
  }
  for (const [index, entry] of manifest.integrity.entries()) {
    const expectedEntry = expectedEntries[index];
    if (!isPlainObject(entry) || Object.keys(entry).sort().join(',') !== 'path,sha256,size' ||
      entry.path !== expectedEntry.path || entry.size !== expectedEntry.size ||
      entry.sha256 !== expectedEntry.sha256) {
      fail('CNYOS_PRODUCER_RUNTIME_INTEGRITY_MISMATCH');
    }
  }
}

function parseGeneratedConfig(bytes, label) {
  const text = bytes.toString('utf8');
  const match = text.match(/^\/\/ Generated[^\r\n]*\r?\nwindow\.CLINICAL_OS_CONFIG = Object\.freeze\((\{[\s\S]*\})\);\s*$/);
  if (!match) fail(`CNYOS_PRODUCER_${label}_CONFIG_INVALID`);
  let value;
  try { value = JSON.parse(match[1]); }
  catch { fail(`CNYOS_PRODUCER_${label}_CONFIG_INVALID`); }
  if (!isPlainObject(value)) fail(`CNYOS_PRODUCER_${label}_CONFIG_INVALID`);
  return value;
}

function assertBrowserTarget(tenantBytes, brandBytes, deployManifest) {
  const tenant = parseGeneratedConfig(tenantBytes, 'TENANT');
  const brand = parseGeneratedConfig(brandBytes, 'BRAND');
  const key = String(tenant.database?.publishableKey || '');
  if (tenant.schemaVersion !== 1 || tenant.deploymentId !== POLICY.target.deploymentId ||
    tenant.tenant?.expectedClinicId !== POLICY.target.clinicId ||
    tenant.tenant?.expectedClinicCode !== POLICY.target.clinicCode ||
    tenant.database?.provider !== 'supabase' || tenant.database?.url !== POLICY.target.supabaseOrigin ||
    !/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(key) ||
    /(?:replace|placeholder|example|change[-_]?me|test(?:_|-)?only)/i.test(key) ||
    tenant.auth?.redirectOrigin !== POLICY.target.authRedirectOrigin ||
    tenant.auth?.provider !== 'google' || tenant.identity?.qrIssuer !== POLICY.target.qrIssuer ||
    tenant.safety?.previewLocked !== false) {
    fail('CNYOS_PRODUCER_TENANT_TARGET_MISMATCH');
  }
  const denied = POLICY.productionDenylist;
  if (tenant.database.url === denied.supabaseOrigin ||
    tenant.tenant.expectedClinicId === denied.clinicId ||
    tenant.tenant.expectedClinicCode === denied.clinicCode ||
    tenant.identity.qrIssuer === denied.qrIssuer || tenant.auth.redirectOrigin === denied.netlifyOrigin) {
    fail('CNYOS_PRODUCER_PRODUCTION_TARGET_DENIED');
  }
  if (brand.schemaVersion !== 1 || brand.deploymentId !== tenant.deploymentId ||
    !isDeepStrictEqual(brand.brand, tenant.brand) ||
    brand.tenant?.expectedClinicCode !== tenant.tenant.expectedClinicCode ||
    brand.identity?.qrIssuer !== tenant.identity.qrIssuer || brand.safety?.previewLocked !== false ||
    !isDeepStrictEqual(deployManifest.tenant, tenant.tenant) ||
    deployManifest.identity?.qrIssuer !== tenant.identity.qrIssuer) {
    fail('CNYOS_PRODUCER_BRAND_MANIFEST_TARGET_MISMATCH');
  }
}

async function loadStaticReproducibilityEvidence({
  env,
  runtime,
  candidateDirectory,
  candidateCommit,
  candidateTree,
  candidateDependencyLockBytes,
  candidateBuildArtifactDigest,
  distFiles,
  observedAt
}) {
  const filename = path.resolve(required(
    env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_PATH_REQUIRED',
    4096
  ));
  if (filename === candidateDirectory || filename.startsWith(`${candidateDirectory}${path.sep}`)) {
    fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_UNTRUSTED');
  }
  const bytes = await readFileBounded(
    filename,
    4 * 1024 * 1024,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID'
  );
  const digest = sha256(bytes);
  if (digest !== exactSha256(
    env.CNYOS_EXPECTED_STATIC_REPRODUCIBILITY_EVIDENCE_SHA256,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_DIGEST_REQUIRED'
  )) {
    fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_DIGEST_MISMATCH');
  }
  let evidence;
  try { evidence = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID'); }
  const policy = POLICY.staticArtifactReproducibility;
  const builderImageDigest = String(policy?.hermeticBuilderImageDigest || '');
  const stagingConfigSha256 = exactSha256(
    policy?.stagingConfigSha256,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_INVALID'
  );
  const productionDenylistConfigSha256 = exactSha256(
    policy?.productionDenylistConfigSha256,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_INVALID'
  );
  if (!/^sha256:[0-9a-f]{64}$/.test(builderImageDigest) ||
    policy?.contractRequired !== true || policy?.networkDisabledDuringBuild !== true) {
    fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_INVALID');
  }
  const staticFiles = distFiles
    .map(file => ({ path: file.relativePath, size: file.status.size }))
    .sort((left, right) => left.path.localeCompare(right.path));
  for (const entry of staticFiles) {
    const file = distFiles.find(candidate => candidate.relativePath === entry.path);
    entry.sha256 = sha256(await readRegularFileStable(
      file.absolutePath,
      MAX_FILE_BYTES,
      'CNYOS_PRODUCER_STATIC_ARTIFACT_CHANGED_DURING_READ'
    ));
  }
  const staticArtifactSha256 = sha256(JSON.stringify(staticFiles));
  if (!Buffer.isBuffer(candidateDependencyLockBytes) ||
    candidateDependencyLockBytes.byteLength > MAX_FILE_BYTES) {
    fail('CNYOS_PRODUCER_DEPENDENCY_LOCK_GIT_ENTRY_INVALID');
  }
  const candidateDependencyLockSha256 = sha256(candidateDependencyLockBytes);
  const verifiedAt = canonicalIsoTimestamp(
    evidence?.verifiedAt,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID'
  );
  if (!isPlainObject(evidence) || evidence.schemaVersion !== 1 ||
    evidence.evidenceType !== 'cnyos_staging_controller_static_reproducibility' ||
    evidence.status !== 'passed' || evidence.authorization !== false ||
    evidence.credentialsAvailable !== false ||
    evidence.controllerRepository !== runtime.repository ||
    evidence.controllerRef !== runtime.ref || evidence.controllerCommit !== runtime.commit ||
    evidence.controllerRunId !== runtime.runId || evidence.controllerRunAttempt !== 1 ||
    evidence.policySha256 !== POLICY_SHA256 ||
    evidence.sourceRepository !== POLICY.sourceRepository ||
    evidence.candidateCommit !== candidateCommit || evidence.candidateTree !== candidateTree ||
    evidence.untrustedReferenceArtifactDigest !== candidateBuildArtifactDigest ||
    evidence.candidateDependencyLockSha256 !== candidateDependencyLockSha256 ||
    evidence.configInputs?.stagingConfigSha256 !== stagingConfigSha256 ||
    evidence.configInputs?.productionDenylistConfigSha256 !== productionDenylistConfigSha256 ||
    evidence.buildEnvironment?.containerImageDigest !== builderImageDigest ||
    evidence.buildEnvironment?.nodeVersion !== '24.20.0' ||
    evidence.buildEnvironment?.networkDisabled !== true ||
    evidence.buildEnvironment?.lifecycleScriptsDisabled !== true ||
    evidence.buildEnvironment?.sourceMountedReadOnly !== true ||
    evidence.buildEnvironment?.isolatedOutput !== true ||
    evidence.byteForByteMatchWithUntrustedReference !== true ||
    evidence.staticArtifactSha256 !== staticArtifactSha256 ||
    evidence.fileCount !== staticFiles.length ||
    !isDeepStrictEqual(evidence.files, staticFiles) ||
    verifiedAt > observedAt || observedAt.getTime() - verifiedAt.getTime() > 30 * 60 * 1000) {
    fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID');
  }
  return Object.freeze({
    bytes,
    sha256: digest,
    files: Object.freeze(staticFiles.map(entry => Object.freeze({ ...entry }))),
    staticArtifactSha256,
    candidateDependencyLockSha256,
    stagingConfigSha256,
    productionDenylistConfigSha256
  });
}

async function loadPrebundledFunctions({
  env,
  runtime,
  candidateCommit,
  candidateTree,
  functionSourceTree,
  sourceEntries
}) {
  const directory = path.resolve(required(
    env.CNYOS_PREBUNDLED_FUNCTIONS_DIRECTORY,
    'CNYOS_PRODUCER_PREBUNDLED_FUNCTIONS_DIRECTORY_REQUIRED',
    4096
  ));
  const manifestBytes = await readFileBounded(
    required(env.CNYOS_FUNCTION_BUNDLE_MANIFEST_PATH,
      'CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_REQUIRED', 4096),
    4 * 1024 * 1024,
    'CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_INVALID'
  );
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); }
  catch { fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_INVALID'); }
  const sourceFiles = sourceEntries.map(entry => Object.freeze({
    path: entry.path.slice('source/netlify/functions/'.length),
    size: entry.size,
    sha256: entry.sha256,
    gitObject: entry.gitObject
  }));
  const expectedSourceSha256 = sha256(JSON.stringify(sourceFiles));
  const expectedDependencyLockSha256 = exactSha256(
    env.CNYOS_EXPECTED_FUNCTION_DEPENDENCY_LOCK_SHA256,
    'CNYOS_PRODUCER_FUNCTION_DEPENDENCY_LOCK_DIGEST_REQUIRED'
  );
  if (!isPlainObject(manifest) || manifest.schemaVersion !== 1 ||
    manifest.evidenceType !== 'cnyos_staging_controller_prebundled_functions' ||
    manifest.authorization !== false || manifest.credentialsAvailable !== false ||
    manifest.controllerRepository !== runtime.repository || manifest.controllerRef !== runtime.ref ||
    manifest.controllerCommit !== runtime.commit || manifest.controllerRunId !== runtime.runId ||
    manifest.sourceRepository !== POLICY.sourceRepository ||
    manifest.candidateCommit !== candidateCommit || manifest.candidateTree !== candidateTree ||
    manifest.functionSourceTree !== functionSourceTree || manifest.policySha256 !== POLICY_SHA256 ||
    manifest.netlifyCliVersion !== POLICY.publishing.netlifyCliVersion ||
    manifest.importClosureComplete !== true || manifest.externalImportsResolvedFromLock !== true ||
    manifest.dependencyLockSha256 !== expectedDependencyLockSha256 ||
    manifest.sourceFilesSha256 !== expectedSourceSha256 ||
    !isDeepStrictEqual(manifest.functionNames, EXPECTED_FUNCTION_NAMES) ||
    !isDeepStrictEqual(manifest.schedules, REQUIRED_SCHEDULES) || !Array.isArray(manifest.files)) {
    fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_INVALID');
  }
  const files = await walkRegularFiles(directory);
  const expectedNames = EXPECTED_FUNCTION_NAMES.map(name => `${name}.zip`).sort();
  const actualNames = files.map(item => item.relativePath).sort();
  if (!isDeepStrictEqual(actualNames, expectedNames) || manifest.files.length !== expectedNames.length) {
    fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_FILESET_MISMATCH');
  }
  const declared = new Map();
  let previous = '';
  for (const entry of manifest.files) {
    if (!isPlainObject(entry) || Object.keys(entry).sort().join(',') !== 'path,sha256,size' ||
      typeof entry.path !== 'string' || entry.path <= previous ||
      !expectedNames.includes(entry.path) || !Number.isSafeInteger(entry.size) || entry.size < 1 ||
      !/^[0-9a-f]{64}$/.test(String(entry.sha256 || ''))) {
      fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_INVALID');
    }
    previous = entry.path;
    declared.set(entry.path, entry);
  }
  const deployEntries = [];
  for (const file of files.sort((left, right) => left.relativePath.localeCompare(right.relativePath))) {
    const bytes = await readRegularFileStable(
      file.absolutePath,
      MAX_FILE_BYTES,
      'CNYOS_PRODUCER_FUNCTION_BUNDLE_CHANGED_DURING_READ'
    );
    const expected = declared.get(file.relativePath);
    if (!expected || bytes.byteLength !== expected.size || sha256(bytes) !== expected.sha256) {
      fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_DIGEST_MISMATCH');
    }
    deployEntries.push(Object.freeze({
      path: `payload/netlify/functions/${file.relativePath}`,
      size: bytes.byteLength,
      sha256: expected.sha256,
      bytes,
      sourcePath: file.absolutePath
    }));
  }
  return Object.freeze({
    deployEntries,
    sourceFiles,
    sourceFilesSha256: expectedSourceSha256,
    manifestBytes,
    manifestSha256: sha256(manifestBytes),
    dependencyLockSha256: manifest.dependencyLockSha256
  });
}

async function copyEntry(bundleDirectory, entry) {
  const destination = path.resolve(bundleDirectory, entry.path);
  const root = `${path.resolve(bundleDirectory)}${path.sep}`;
  if (!destination.startsWith(root)) fail('CNYOS_PRODUCER_BUNDLE_PATH_ESCAPE');
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const handle = await fs.open(destination, 'wx', 0o600);
  try { await handle.writeFile(entry.bytes); }
  finally { await handle.close(); }
}

export async function createProducerBundle({
  env = process.env,
  now = () => new Date(),
  beforeFinalHeadFence = null
} = {}) {
  const runtime = assertControllerRuntime(env);
  const candidateDirectory = path.resolve(required(
    env.CNYOS_CANDIDATE_DIRECTORY,
    'CNYOS_PRODUCER_CANDIDATE_DIRECTORY_REQUIRED',
    4096
  ));
  const bundleDirectory = path.resolve(required(
    env.CNYOS_PRODUCER_BUNDLE_DIRECTORY,
    'CNYOS_PRODUCER_BUNDLE_DIRECTORY_REQUIRED',
    4096
  ));
  if (bundleDirectory === candidateDirectory || bundleDirectory.startsWith(`${candidateDirectory}${path.sep}`)) {
    fail('CNYOS_PRODUCER_BUNDLE_INSIDE_CANDIDATE');
  }
  const distDirectory = path.resolve(required(
    env.CNYOS_REPRODUCED_STATIC_DIRECTORY,
    'CNYOS_PRODUCER_REPRODUCED_STATIC_DIRECTORY_REQUIRED',
    4096
  ));
  if (distDirectory === candidateDirectory ||
    distDirectory.startsWith(`${candidateDirectory}${path.sep}`) ||
    distDirectory === bundleDirectory ||
    distDirectory.startsWith(`${bundleDirectory}${path.sep}`)) {
    fail('CNYOS_PRODUCER_REPRODUCED_STATIC_DIRECTORY_NOT_ISOLATED');
  }
  try {
    await fs.lstat(bundleDirectory);
    fail('CNYOS_PRODUCER_BUNDLE_ALREADY_EXISTS');
  } catch (error) {
    if (error?.message === 'CNYOS_PRODUCER_BUNDLE_ALREADY_EXISTS') throw error;
    if (error?.code !== 'ENOENT') throw error;
  }

  const rawCandidateCommit = String(env.CNYOS_CANDIDATE_SHA || '');
  const candidateCommit = exactSha40(rawCandidateCommit, 'CNYOS_PRODUCER_CANDIDATE_SHA_INVALID');
  if (rawCandidateCommit !== candidateCommit) fail('CNYOS_PRODUCER_CANDIDATE_SHA_INVALID');
  if (beforeFinalHeadFence !== null && typeof beforeFinalHeadFence !== 'function') {
    fail('CNYOS_PRODUCER_HEAD_FENCE_INVALID');
  }
  if (checkoutHead(candidateDirectory) !== candidateCommit) {
    fail('CNYOS_PRODUCER_CANDIDATE_CHECKOUT_MISMATCH');
  }
  const immutableSource = loadImmutableCandidateSource(candidateDirectory, candidateCommit);
  const { candidateTree, functionSourceTree } = immutableSource;
  const nonce = decodeNonce(env.CNYOS_DISPATCH_NONCE).value;
  const candidateBuildArtifactDigest = exactSha256(
    env.CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST,
    'CNYOS_PRODUCER_BUILD_ARTIFACT_DIGEST_REQUIRED'
  );
  const generatedAt = now();
  if (!(generatedAt instanceof Date) || Number.isNaN(generatedAt.getTime())) {
    fail('CNYOS_PRODUCER_TIME_INVALID');
  }

  const distFiles = await walkRegularFiles(distDirectory, 'payload/dist');
  if (!distFiles.length) fail('CNYOS_PRODUCER_DIST_EMPTY');
  const staticReproducibility = await loadStaticReproducibilityEvidence({
    env,
    runtime,
    candidateDirectory,
    candidateCommit,
    candidateTree,
    candidateDependencyLockBytes: immutableSource.candidateDependencyLockBytes,
    candidateBuildArtifactDigest,
    distFiles,
    observedAt: generatedAt
  });
  const distPaths = new Set(distFiles.map(item => item.relativePath));
  for (const requiredFile of requiredDistFiles) {
    if (!distPaths.has(requiredFile)) fail('CNYOS_PRODUCER_REQUIRED_DIST_FILE_MISSING');
  }
  for (const item of distPaths) {
    if (/(?:^|\/)(?:\.env(?:\.|$)|\.git(?:\/|$)|artifacts(?:\/|$))|\.(?:sql|pem|key)$/i.test(item) ||
      item.split('/').some(part => part.startsWith('.'))) {
      fail('CNYOS_PRODUCER_FORBIDDEN_PUBLIC_FILE');
    }
  }

  const entries = [];
  for (const file of distFiles) entries.push(await fileEntry(file));
  const packagedStaticFiles = entries
    .map(entry => ({
      path: entry.path.slice('payload/dist/'.length),
      size: entry.size,
      sha256: entry.sha256
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  if (!isDeepStrictEqual(packagedStaticFiles, staticReproducibility.files)) {
    fail('CNYOS_PRODUCER_STATIC_ARTIFACT_CHANGED_AFTER_REPRODUCTION');
  }
  const sourceEntries = immutableSource.functionInventory.map(tracked => {
    const bytes = immutableSource.functionBlobs.get(tracked.object);
    if (!Buffer.isBuffer(bytes)) fail('CNYOS_PRODUCER_GIT_BLOB_CONTENT_INVALID');
    return Object.freeze({
      path: `source/netlify/functions/${tracked.relativePath}`,
      size: bytes.byteLength,
      sha256: sha256(bytes),
      gitObject: tracked.object,
      bytes
    });
  });
  const functionBundle = await loadPrebundledFunctions({
    env,
    runtime,
    candidateCommit,
    candidateTree,
    functionSourceTree,
    sourceEntries
  });
  entries.push(...functionBundle.deployEntries);
  entries.sort((left, right) => left.path.localeCompare(right.path));

  const deployEntry = entries.find(item => item.path === 'payload/dist/deploy-manifest.json');
  const runtimeEntry = entries.find(item => item.path === 'payload/dist/runtime-publish-manifest.json');
  const tenantEntry = entries.find(item => item.path === 'payload/dist/tenant-config.js');
  const brandEntry = entries.find(item => item.path === 'payload/dist/brand-config.js');
  const deployManifest = assertStagingDeployManifest(deployEntry.bytes, candidateCommit, candidateTree);
  assertBrowserTarget(tenantEntry.bytes, brandEntry.bytes, deployManifest);
  assertRuntimeManifest(runtimeEntry.bytes, entries);
  const deniedMarkers = [
    POLICY.productionDenylist.netlifySiteId,
    POLICY.productionDenylist.netlifyOrigin,
    POLICY.productionDenylist.supabaseProjectRef,
    POLICY.productionDenylist.supabaseOrigin,
    POLICY.productionDenylist.clinicId
  ];
  for (const entry of entries.filter(item => item.path.startsWith('payload/dist/'))) {
    const text = entry.bytes.toString('utf8');
    if (deniedMarkers.some(marker => marker && text.includes(marker))) {
      fail('CNYOS_PRODUCER_PRODUCTION_TARGET_MARKER_PRESENT');
    }
  }

  const identity = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_unprivileged_producer_bundle',
    authorization: false,
    credentialsAvailable: false,
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerRunId: runtime.runId,
    controllerRunAttempt: 1,
    dispatchNonce: nonce,
    sourceRepository: POLICY.sourceRepository,
    candidateCommit,
    candidateTree,
    functionSourceTree,
    candidateBuildArtifactDigest,
    staticReproducibilityEvidenceSha256: staticReproducibility.sha256,
    staticArtifactSha256: staticReproducibility.staticArtifactSha256,
    candidateDependencyLockSha256: staticReproducibility.candidateDependencyLockSha256,
    stagingConfigSha256: staticReproducibility.stagingConfigSha256,
    productionDenylistConfigSha256: staticReproducibility.productionDenylistConfigSha256,
    functionBundleManifestSha256: functionBundle.manifestSha256,
    functionBundleDependencyLockSha256: functionBundle.dependencyLockSha256,
    functionSourcesSha256: functionBundle.sourceFilesSha256,
    policySha256: POLICY_SHA256
  });
  const publicEntries = entries.map(({ bytes, sourcePath, ...entry }) => Object.freeze(entry));
  const artifactSha256 = aggregateDigest(identity, publicEntries);
  const manifest = Object.freeze({
    ...identity,
    generatedAt: generatedAt.toISOString(),
    artifactSha256,
    fileCount: publicEntries.length,
    files: publicEntries,
    functionSources: functionBundle.sourceFiles
  });

  if (beforeFinalHeadFence) await beforeFinalHeadFence();
  if (checkoutHead(candidateDirectory) !== candidateCommit) {
    fail('CNYOS_PRODUCER_CANDIDATE_CHECKOUT_MOVED');
  }

  let createdOutput = false;
  try {
    await fs.mkdir(bundleDirectory, { recursive: false, mode: 0o700 });
    createdOutput = true;
    for (const entry of entries) await copyEntry(bundleDirectory, entry);
    const functionManifestHandle = await fs.open(
      path.join(bundleDirectory, 'function-bundle-manifest.json'),
      'wx',
      0o600
    );
    try { await functionManifestHandle.writeFile(functionBundle.manifestBytes); }
    finally { await functionManifestHandle.close(); }
    const staticEvidenceHandle = await fs.open(
      path.join(bundleDirectory, 'static-reproducibility.json'),
      'wx',
      0o600
    );
    try { await staticEvidenceHandle.writeFile(staticReproducibility.bytes); }
    finally { await staticEvidenceHandle.close(); }
    const manifestPath = await writeJsonExclusive(
      path.join(bundleDirectory, 'producer-manifest.json'),
      manifest
    );
    return Object.freeze({ bundleDirectory, manifestPath, manifest });
  } catch (error) {
    if (createdOutput) await fs.rm(bundleDirectory, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  createProducerBundle().then(result => {
    process.stdout.write(`${JSON.stringify({
      manifestPath: result.manifestPath,
      artifactSha256: result.manifest.artifactSha256,
      candidateTree: result.manifest.candidateTree,
      functionSourceTree: result.manifest.functionSourceTree
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_PRODUCER_BUNDLE_FAILED')}\n`);
    process.exitCode = 1;
  });
}
