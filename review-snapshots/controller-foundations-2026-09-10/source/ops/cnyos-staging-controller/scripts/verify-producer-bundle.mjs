import path from 'node:path';
import process from 'node:process';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  POLICY,
  POLICY_SHA256,
  EXPECTED_FUNCTION_NAMES,
  MAX_FILE_BYTES,
  aggregateDigest,
  assertExactKeys,
  assertControllerRuntime,
  canonicalIsoTimestamp,
  decodeNonce,
  exactSha256,
  fail,
  isPlainObject,
  normalizedRelativePath,
  portableRelativePath,
  readFileBounded,
  readRegularFileStable,
  required,
  sha256,
  walkRegularFiles
} from './policy.mjs';

const STATIC_REPRODUCIBILITY_EVIDENCE_KEYS = Object.freeze([
  'authorization',
  'buildEnvironment',
  'byteForByteMatchWithUntrustedReference',
  'candidateCommit',
  'candidateDependencyLockSha256',
  'candidateTree',
  'configInputs',
  'controllerCommit',
  'controllerRef',
  'controllerRepository',
  'controllerRunAttempt',
  'controllerRunId',
  'credentialsAvailable',
  'evidenceType',
  'fileCount',
  'files',
  'policySha256',
  'schemaVersion',
  'sourceRepository',
  'staticArtifactSha256',
  'status',
  'untrustedReferenceArtifactDigest',
  'verifiedAt'
]);

const STATIC_REPRODUCIBILITY_CONFIG_KEYS = Object.freeze([
  'productionDenylistConfigSha256',
  'stagingConfigSha256'
]);

const STATIC_REPRODUCIBILITY_BUILD_ENVIRONMENT_KEYS = Object.freeze([
  'containerImageDigest',
  'isolatedOutput',
  'lifecycleScriptsDisabled',
  'networkDisabled',
  'nodeVersion',
  'sourceMountedReadOnly'
]);

const STATIC_REPRODUCIBILITY_FILE_KEYS = Object.freeze(['path', 'sha256', 'size']);
const STATIC_REPRODUCIBILITY_MAXIMUM_AGE_MS = 30 * 60 * 1000;

export function validateStaticReproducibilityReceipt(evidence, manifest, staticFiles) {
  const evidenceCode = 'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID';
  const policyCode = 'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_INVALID';
  assertExactKeys(evidence, STATIC_REPRODUCIBILITY_EVIDENCE_KEYS, evidenceCode);
  assertExactKeys(evidence.configInputs, STATIC_REPRODUCIBILITY_CONFIG_KEYS, evidenceCode);
  assertExactKeys(
    evidence.buildEnvironment,
    STATIC_REPRODUCIBILITY_BUILD_ENVIRONMENT_KEYS,
    evidenceCode
  );
  if (!isPlainObject(manifest) || !Array.isArray(staticFiles) || !Array.isArray(evidence.files)) {
    fail(evidenceCode);
  }

  const reproducibilityPolicy = POLICY.staticArtifactReproducibility;
  const builderImageDigest = String(reproducibilityPolicy?.hermeticBuilderImageDigest || '');
  const stagingConfigSha256 = String(reproducibilityPolicy?.stagingConfigSha256 || '');
  const productionDenylistConfigSha256 =
    String(reproducibilityPolicy?.productionDenylistConfigSha256 || '');
  if (!isPlainObject(reproducibilityPolicy) || reproducibilityPolicy.contractRequired !== true ||
    reproducibilityPolicy.networkDisabledDuringBuild !== true ||
    !/^sha256:[0-9a-f]{64}$/.test(builderImageDigest) ||
    !/^[0-9a-f]{64}$/.test(stagingConfigSha256) ||
    !/^[0-9a-f]{64}$/.test(productionDenylistConfigSha256) ||
    !/^[0-9a-f]{64}$/.test(POLICY_SHA256)) {
    fail(policyCode);
  }

  let previousPath = '';
  for (const entry of evidence.files) {
    assertExactKeys(entry, STATIC_REPRODUCIBILITY_FILE_KEYS, evidenceCode);
    const entryPath = portableRelativePath(entry.path, evidenceCode);
    if (entryPath !== entry.path || (previousPath && entryPath.localeCompare(previousPath) <= 0) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > MAX_FILE_BYTES ||
      !/^[0-9a-f]{64}$/.test(String(entry.sha256 || ''))) {
      fail(evidenceCode);
    }
    previousPath = entryPath;
  }

  const verifiedAt = canonicalIsoTimestamp(evidence.verifiedAt, evidenceCode);
  const generatedAt = canonicalIsoTimestamp(manifest.generatedAt, evidenceCode);
  if (verifiedAt > generatedAt ||
    generatedAt.getTime() - verifiedAt.getTime() > STATIC_REPRODUCIBILITY_MAXIMUM_AGE_MS) {
    fail(evidenceCode);
  }

  if (staticFiles.some(entry => !isPlainObject(entry))) fail(evidenceCode);
  const canonicalStaticFiles = staticFiles.map(entry => Object.freeze({
    path: entry.path,
    size: entry.size,
    sha256: entry.sha256
  }));
  const expectedStaticArtifactSha256 = sha256(JSON.stringify(canonicalStaticFiles));
  if (evidence.schemaVersion !== 1 ||
    evidence.evidenceType !== 'cnyos_staging_controller_static_reproducibility' ||
    evidence.status !== 'passed' || evidence.authorization !== false ||
    evidence.credentialsAvailable !== false ||
    evidence.controllerRepository !== POLICY.controller?.repository ||
    evidence.controllerRepository !== manifest.controllerRepository ||
    evidence.controllerRef !== POLICY.controller?.protectedRef ||
    evidence.controllerRef !== manifest.controllerRef ||
    evidence.controllerCommit !== manifest.controllerCommit ||
    !/^[0-9a-f]{40}$/.test(String(evidence.controllerCommit || '')) ||
    evidence.controllerRunId !== manifest.controllerRunId ||
    !/^\d+$/.test(String(evidence.controllerRunId || '')) ||
    evidence.controllerRunAttempt !== 1 ||
    evidence.controllerRunAttempt !== manifest.controllerRunAttempt ||
    evidence.policySha256 !== POLICY_SHA256 || evidence.policySha256 !== manifest.policySha256 ||
    evidence.sourceRepository !== POLICY.sourceRepository ||
    evidence.sourceRepository !== manifest.sourceRepository ||
    evidence.candidateCommit !== manifest.candidateCommit ||
    !/^[0-9a-f]{40}$/.test(String(evidence.candidateCommit || '')) ||
    evidence.candidateTree !== manifest.candidateTree ||
    !/^[0-9a-f]{40}$/.test(String(evidence.candidateTree || '')) ||
    evidence.untrustedReferenceArtifactDigest !== manifest.candidateBuildArtifactDigest ||
    !/^[0-9a-f]{64}$/.test(String(evidence.untrustedReferenceArtifactDigest || '')) ||
    evidence.candidateDependencyLockSha256 !== manifest.candidateDependencyLockSha256 ||
    !/^[0-9a-f]{64}$/.test(String(evidence.candidateDependencyLockSha256 || '')) ||
    evidence.configInputs.stagingConfigSha256 !== stagingConfigSha256 ||
    evidence.configInputs.stagingConfigSha256 !== manifest.stagingConfigSha256 ||
    evidence.configInputs.productionDenylistConfigSha256 !== productionDenylistConfigSha256 ||
    evidence.configInputs.productionDenylistConfigSha256 !==
      manifest.productionDenylistConfigSha256 ||
    evidence.buildEnvironment.containerImageDigest !== builderImageDigest ||
    evidence.buildEnvironment.nodeVersion !== '24.20.0' ||
    evidence.buildEnvironment.networkDisabled !== true ||
    evidence.buildEnvironment.lifecycleScriptsDisabled !== true ||
    evidence.buildEnvironment.sourceMountedReadOnly !== true ||
    evidence.buildEnvironment.isolatedOutput !== true ||
    evidence.byteForByteMatchWithUntrustedReference !== true ||
    !Number.isSafeInteger(evidence.fileCount) || evidence.fileCount < 1 ||
    evidence.fileCount !== evidence.files.length ||
    !isDeepStrictEqual(evidence.files, canonicalStaticFiles) ||
    evidence.staticArtifactSha256 !== expectedStaticArtifactSha256 ||
    evidence.staticArtifactSha256 !== manifest.staticArtifactSha256) {
    fail(evidenceCode);
  }

  return Object.freeze({
    verifiedAt,
    staticArtifactSha256: expectedStaticArtifactSha256,
    files: Object.freeze(canonicalStaticFiles)
  });
}

function identityFromManifest(manifest) {
  return Object.freeze({
    schemaVersion: manifest.schemaVersion,
    evidenceType: manifest.evidenceType,
    authorization: manifest.authorization,
    credentialsAvailable: manifest.credentialsAvailable,
    controllerRepository: manifest.controllerRepository,
    controllerRef: manifest.controllerRef,
    controllerCommit: manifest.controllerCommit,
    controllerRunId: manifest.controllerRunId,
    controllerRunAttempt: manifest.controllerRunAttempt,
    dispatchNonce: manifest.dispatchNonce,
    sourceRepository: manifest.sourceRepository,
    candidateCommit: manifest.candidateCommit,
    candidateTree: manifest.candidateTree,
    functionSourceTree: manifest.functionSourceTree,
    candidateBuildArtifactDigest: manifest.candidateBuildArtifactDigest,
    staticReproducibilityEvidenceSha256: manifest.staticReproducibilityEvidenceSha256,
    staticArtifactSha256: manifest.staticArtifactSha256,
    candidateDependencyLockSha256: manifest.candidateDependencyLockSha256,
    stagingConfigSha256: manifest.stagingConfigSha256,
    productionDenylistConfigSha256: manifest.productionDenylistConfigSha256,
    functionBundleManifestSha256: manifest.functionBundleManifestSha256,
    functionBundleDependencyLockSha256: manifest.functionBundleDependencyLockSha256,
    functionSourcesSha256: manifest.functionSourcesSha256,
    policySha256: manifest.policySha256
  });
}

export async function verifyProducerBundle({ env = process.env } = {}) {
  const runtime = assertControllerRuntime(env);
  const bundleDirectory = path.resolve(required(
    env.CNYOS_PRODUCER_BUNDLE_DIRECTORY,
    'CNYOS_BUNDLE_DIRECTORY_REQUIRED',
    4096
  ));
  const manifestPath = path.join(bundleDirectory, 'producer-manifest.json');
  const manifestBytes = await readFileBounded(
    manifestPath,
    4 * 1024 * 1024,
    'CNYOS_PRODUCER_MANIFEST_INVALID'
  );
  const manifestSha256 = sha256(manifestBytes);
  if (env.CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256) {
    const expected = exactSha256(
      env.CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256,
      'CNYOS_EXPECTED_PRODUCER_MANIFEST_SHA256_INVALID'
    );
    if (manifestSha256 !== expected) fail('CNYOS_PRODUCER_MANIFEST_DIGEST_MISMATCH');
  }
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); }
  catch { fail('CNYOS_PRODUCER_MANIFEST_INVALID'); }
  if (!isPlainObject(manifest) || manifest.schemaVersion !== 1 ||
    manifest.evidenceType !== 'cnyos_staging_unprivileged_producer_bundle' ||
    manifest.authorization !== false || manifest.credentialsAvailable !== false ||
    manifest.controllerRepository !== runtime.repository ||
    manifest.controllerRef !== runtime.ref || manifest.controllerCommit !== runtime.commit ||
    manifest.controllerRunId !== runtime.runId ||
    manifest.controllerRunAttempt !== 1 || manifest.sourceRepository !== POLICY.sourceRepository ||
    manifest.policySha256 !== POLICY_SHA256 || !Array.isArray(manifest.files) ||
    !Array.isArray(manifest.functionSources) ||
    manifest.fileCount !== manifest.files.length || manifest.fileCount < 1) {
    fail('CNYOS_PRODUCER_MANIFEST_INVALID');
  }
  const nonce = decodeNonce(env.CNYOS_DISPATCH_NONCE).value;
  if (manifest.dispatchNonce !== nonce) fail('CNYOS_PRODUCER_NONCE_MISMATCH');
  if (env.CNYOS_CANDIDATE_SHA && manifest.candidateCommit !== String(env.CNYOS_CANDIDATE_SHA).toLowerCase()) {
    fail('CNYOS_PRODUCER_CANDIDATE_COMMIT_MISMATCH');
  }
  for (const field of ['candidateCommit', 'candidateTree', 'functionSourceTree']) {
    if (!/^[0-9a-f]{40}$/.test(String(manifest[field] || ''))) fail('CNYOS_PRODUCER_MANIFEST_INVALID');
  }
  if (!/^[0-9a-f]{64}$/.test(String(manifest.candidateBuildArtifactDigest || '')) ||
    (env.CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST &&
      manifest.candidateBuildArtifactDigest !== exactSha256(
        env.CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST,
        'CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST_INVALID'
      )) ||
    !['staticReproducibilityEvidenceSha256', 'staticArtifactSha256',
      'candidateDependencyLockSha256', 'stagingConfigSha256',
      'productionDenylistConfigSha256', 'functionBundleManifestSha256',
      'functionBundleDependencyLockSha256', 'functionSourcesSha256']
      .every(field => /^[0-9a-f]{64}$/.test(String(manifest[field] || ''))) ||
    !/^[0-9a-f]{64}$/.test(String(manifest.artifactSha256 || '')) ||
    typeof manifest.generatedAt !== 'string' || !Number.isFinite(Date.parse(manifest.generatedAt))) {
    fail('CNYOS_PRODUCER_MANIFEST_INVALID');
  }
  if (manifest.stagingConfigSha256 !== exactSha256(
    POLICY.staticArtifactReproducibility?.stagingConfigSha256,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_INVALID'
  ) || manifest.productionDenylistConfigSha256 !== exactSha256(
    POLICY.staticArtifactReproducibility?.productionDenylistConfigSha256,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_INVALID'
  )) {
    fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_POLICY_MISMATCH');
  }
  const staticEvidenceBytes = await readFileBounded(
    path.join(bundleDirectory, 'static-reproducibility.json'),
    4 * 1024 * 1024,
    'CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID'
  );
  if (sha256(staticEvidenceBytes) !== manifest.staticReproducibilityEvidenceSha256) {
    fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_DIGEST_MISMATCH');
  }
  let staticEvidence;
  try { staticEvidence = JSON.parse(staticEvidenceBytes.toString('utf8')); }
  catch { fail('CNYOS_PRODUCER_STATIC_REPRODUCIBILITY_EVIDENCE_INVALID'); }
  const functionBundleManifestBytes = await readFileBounded(
    path.join(bundleDirectory, 'function-bundle-manifest.json'),
    4 * 1024 * 1024,
    'CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_INVALID'
  );
  if (sha256(functionBundleManifestBytes) !== manifest.functionBundleManifestSha256) {
    fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_MANIFEST_DIGEST_MISMATCH');
  }

  const declared = new Map();
  let previous = '';
  for (const entry of manifest.files) {
    if (!isPlainObject(entry) || Object.keys(entry).some(key =>
      !['path', 'size', 'sha256', 'gitObject'].includes(key))) {
      fail('CNYOS_PRODUCER_MANIFEST_FILE_INVALID');
    }
    const manifestFilePath = normalizedRelativePath(entry.path, 'CNYOS_PRODUCER_MANIFEST_PATH_INVALID');
    if (!manifestFilePath.startsWith('payload/dist/') &&
      !manifestFilePath.startsWith('payload/netlify/functions/')) {
      fail('CNYOS_PRODUCER_MANIFEST_PATH_INVALID');
    }
    if (manifestFilePath <= previous || declared.has(manifestFilePath) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0 ||
      !/^[0-9a-f]{64}$/.test(String(entry.sha256 || ''))) {
      fail('CNYOS_PRODUCER_MANIFEST_FILE_INVALID');
    }
    if (manifestFilePath.startsWith('payload/netlify/functions/')) {
      if (entry.gitObject !== undefined || !/^payload\/netlify\/functions\/[A-Za-z0-9_-]+\.zip$/.test(
        manifestFilePath
      )) fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_FILE_INVALID');
    } else if (entry.gitObject !== undefined) {
      fail('CNYOS_PRODUCER_MANIFEST_FILE_INVALID');
    }
    previous = manifestFilePath;
    declared.set(manifestFilePath, entry);
  }
  const declaredStaticFiles = manifest.files
    .filter(entry => entry.path.startsWith('payload/dist/'))
    .map(entry => ({
      path: entry.path.slice('payload/dist/'.length),
      size: entry.size,
      sha256: entry.sha256
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  validateStaticReproducibilityReceipt(staticEvidence, manifest, declaredStaticFiles);

  const sourceNames = new Set();
  let previousSource = '';
  for (const entry of manifest.functionSources) {
    if (!isPlainObject(entry) || Object.keys(entry).sort().join(',') !== 'gitObject,path,sha256,size' ||
      typeof entry.path !== 'string' || entry.path <= previousSource || sourceNames.has(entry.path) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0 ||
      !/^[0-9a-f]{64}$/.test(String(entry.sha256 || '')) ||
      !/^[0-9a-f]{40}$/.test(String(entry.gitObject || ''))) {
      fail('CNYOS_PRODUCER_FUNCTION_SOURCE_MANIFEST_INVALID');
    }
    normalizedRelativePath(entry.path, 'CNYOS_PRODUCER_FUNCTION_SOURCE_PATH_INVALID');
    previousSource = entry.path;
    sourceNames.add(entry.path);
  }
  if (!manifest.functionSources.length || sha256(JSON.stringify(manifest.functionSources)) !==
    manifest.functionSourcesSha256) fail('CNYOS_PRODUCER_FUNCTION_SOURCE_MANIFEST_INVALID');
  const bundleNames = manifest.files.filter(entry =>
    entry.path.startsWith('payload/netlify/functions/'))
    .map(entry => path.posix.basename(entry.path, '.zip')).sort();
  if (bundleNames.length !== EXPECTED_FUNCTION_NAMES.length ||
    EXPECTED_FUNCTION_NAMES.some((name, index) => name !== bundleNames[index])) {
    fail('CNYOS_PRODUCER_FUNCTION_BUNDLE_FILESET_MISMATCH');
  }

  const payloadFiles = await walkRegularFiles(path.join(bundleDirectory, 'payload'), 'payload');
  if (payloadFiles.length !== declared.size) fail('CNYOS_PRODUCER_BUNDLE_FILESET_MISMATCH');
  for (const file of payloadFiles) {
    const expected = declared.get(file.manifestPath);
    if (!expected) fail('CNYOS_PRODUCER_BUNDLE_FILESET_MISMATCH');
    const bytes = await readRegularFileStable(
      file.absolutePath,
      MAX_FILE_BYTES,
      'CNYOS_PRODUCER_BUNDLE_FILE_CHANGED_DURING_READ'
    );
    if (bytes.byteLength !== expected.size || sha256(bytes) !== expected.sha256) {
      fail('CNYOS_PRODUCER_BUNDLE_DIGEST_MISMATCH');
    }
  }

  const identity = identityFromManifest(manifest);
  if (aggregateDigest(identity, manifest.files) !== manifest.artifactSha256) {
    fail('CNYOS_PRODUCER_ARTIFACT_DIGEST_MISMATCH');
  }
  return Object.freeze({ bundleDirectory, manifestPath, manifestBytes, manifestSha256, manifest });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  verifyProducerBundle().then(result => {
    process.stdout.write(`${JSON.stringify({
      manifestSha256: result.manifestSha256,
      artifactSha256: result.manifest.artifactSha256,
      candidateCommit: result.manifest.candidateCommit,
      candidateTree: result.manifest.candidateTree,
      functionSourceTree: result.manifest.functionSourceTree
    })}\n`);
  }).catch(error => {
    process.stderr.write(`${String(error?.message || 'CNYOS_PRODUCER_BUNDLE_VERIFICATION_FAILED')}\n`);
    process.exitCode = 1;
  });
}
