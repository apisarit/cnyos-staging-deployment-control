import crypto from 'node:crypto';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { AdapterError, extractTarGzip, sha256, validateReleaseRequest } from './common.mjs';

const COMMIT = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_FILE = 12 * 1024 * 1024;
const TRUSTED_RUNTIME_FILES = Object.freeze(['Dockerfile', 'nginx.conf', 'docker-compose.yml']);

function json(bytes, code) {
  try { return JSON.parse(bytes.toString('utf8')); } catch { throw new AdapterError(code); }
}

async function safelyOwned(file, { directory = false } = {}) {
  const stat = await fs.lstat(file).catch(() => null);
  return !!stat && !stat.isSymbolicLink() && (directory ? stat.isDirectory() : stat.isFile()) &&
    stat.uid === 0 && (stat.mode & 0o022) === 0;
}

async function atomicJson(file, value) {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  const handle = await fs.open(tmp, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(tmp, file);
  const directory = await fs.open(path.dirname(file), 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}

function health(port, route, expected, timeout = 10_000, headers = {}) {
  return new Promise((resolve, reject) => {
    const code = port === 18080 ? 'WEB_HEALTH_FAILED' : 'SUPABASE_HEALTH_FAILED';
    const req = http.get({ hostname: '127.0.0.1', port, path: route, timeout, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        response.statusCode === 200 && (expected === null || body === expected)
          ? resolve() : reject(new AdapterError(code));
      });
    });
    req.on('timeout', () => req.destroy(new AdapterError('HEALTH_TIMEOUT')));
    req.on('error', () => reject(new AdapterError(code)));
  });
}

async function authenticatedSupabaseHealth(file = process.env.CNYOS_SUPABASE_ANON_KEY_FILE || '/etc/cnyos-broker/supabase-anon-key') {
  if (!path.isAbsolute(file)) throw new AdapterError('SUPABASE_HEALTH_KEY_PATH_INVALID');
  const stat = await fs.lstat(file).catch(() => null);
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o077) !== 0 || stat.size < 20 || stat.size > 4096) {
    throw new AdapterError('SUPABASE_HEALTH_KEY_UNAVAILABLE');
  }
  const key = (await fs.readFile(file, 'utf8')).trim();
  if (!/^[A-Za-z0-9_.-]{20,4096}$/.test(key)) throw new AdapterError('SUPABASE_HEALTH_KEY_INVALID');
  return health(18000, '/auth/v1/health', null, 10_000, { apikey: key });
}

function run(file, args, cwd, { spawnImpl = spawn, timeoutMs = 10 * 60_000, env = process.env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(file, args, { cwd, env, shell: false, stdio: ['ignore', 'ignore', 'ignore'] });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new AdapterError('DOCKER_TIMEOUT')); }, timeoutMs);
    child.on('error', () => { clearTimeout(timer); reject(new AdapterError('DOCKER_UNAVAILABLE')); });
    child.on('close', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new AdapterError('DOCKER_FAILED')); });
  });
}

function validateManifest(files, request, commit) {
  const runtimeBytes = files.get('runtime-publish-manifest.json');
  const deployBytes = files.get('deploy-manifest.json');
  const runtime = json(runtimeBytes, 'RUNTIME_MANIFEST_INVALID');
  const deploy = json(deployBytes, 'DEPLOY_MANIFEST_INVALID');
  if (request.runtimeManifestSha256 !== sha256(runtimeBytes) || request.deployManifestSha256 !== sha256(deployBytes)) {
    throw new AdapterError('MANIFEST_DIGEST_MISMATCH');
  }
  if (runtime.schemaVersion !== 2 || runtime.integrityAlgorithm !== 'sha256' ||
      !Array.isArray(runtime.files) || !Array.isArray(runtime.integrity) ||
      runtime.files.length !== runtime.integrity.length || runtime.fileCount !== runtime.files.length) {
    throw new AdapterError('RUNTIME_MANIFEST_INVALID');
  }
  if (deploy.source?.commit !== commit || deploy.source?.tree !== request.source.tree || deploy.source?.verified !== true ||
      deploy.build?.context !== 'production' || deploy.build?.deploymentClass !== 'dedicated-staging' ||
      deploy.safety?.previewLocked !== false || deploy.safety?.databaseLocked !== false ||
      deploy.safety?.stagingDatabaseExplicitlyAcknowledged !== true) {
    throw new AdapterError('DEPLOY_MANIFEST_BINDING_INVALID');
  }
  if (!runtime.files.every(name => typeof name === 'string' && /^[A-Za-z0-9_][A-Za-z0-9._-]{0,199}$/.test(name))) {
    throw new AdapterError('RUNTIME_FILESET_INVALID');
  }
  const expected = new Set([...runtime.files, 'runtime-publish-manifest.json']);
  if (expected.size !== files.size || [...files.keys()].some(name => !expected.has(name))) throw new AdapterError('RUNTIME_FILESET_INVALID');
  const integrity = new Map();
  for (const [index, item] of runtime.integrity.entries()) {
    if (!item || item.path !== runtime.files[index] || !DIGEST.test(item.sha256) ||
        !Number.isSafeInteger(item.size) || item.size < 0 || item.size > MAX_FILE || integrity.has(item.path)) {
      throw new AdapterError('RUNTIME_INTEGRITY_INVALID');
    }
    integrity.set(item.path, item);
  }
  for (const name of runtime.files) {
    const data = files.get(name);
    if (!data || data.length > MAX_FILE || integrity.get(name)?.size !== data.length || integrity.get(name)?.sha256 !== sha256(data)) {
      throw new AdapterError('RUNTIME_INTEGRITY_MISMATCH');
    }
  }
  return { runtime, deploy };
}

async function readSpoolFiles(spoolDir, names) {
  const files = new Map();
  for (const name of names) {
    const target = path.join(spoolDir, name);
    const stat = await fs.lstat(target).catch(() => null);
    if (!stat?.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 80 * 1024 * 1024) {
      throw new AdapterError('ARTIFACT_FILE_INVALID');
    }
    files.set(name, await fs.readFile(target));
  }
  return files;
}

async function trustedRuntime(runtimeDir, requireRoot) {
  for (const name of TRUSTED_RUNTIME_FILES) {
    const file = runtimeDir instanceof URL ? new URL(name, runtimeDir) : path.join(path.resolve(runtimeDir), name);
    if (requireRoot && !(await safelyOwned(file))) throw new AdapterError('TRUSTED_RUNTIME_INVALID');
  }
}

async function quarantine(releaseDir, failedDir) {
  const present = await fs.lstat(releaseDir).catch(() => null);
  if (present?.isDirectory() && !present.isSymbolicLink()) {
    await fs.mkdir(path.dirname(failedDir), { recursive: true, mode: 0o700 });
    await fs.rename(releaseDir, failedDir);
  }
}

async function replaceCurrent(currentLink, target, requestId) {
  if (target === null) {
    const current = await fs.lstat(currentLink).catch(() => null);
    if (current && !current.isSymbolicLink()) throw new AdapterError('CURRENT_RELEASE_INVALID');
    if (current) await fs.unlink(currentLink);
    return;
  }
  const temporary = `${path.dirname(currentLink)}/.current-${requestId}-${crypto.randomBytes(6).toString('hex')}`;
  await fs.symlink(target, temporary);
  try { await fs.rename(temporary, currentLink); }
  catch (error) { await fs.unlink(temporary).catch(() => {}); throw error; }
}

async function findInterruptedReceipt(receiptsDir) {
  const names = await fs.readdir(receiptsDir).catch(() => []);
  const matches = [];
  for (const name of names.sort()) {
    if (!/^[1-9][0-9]*\.[1-9][0-9]*\.[0-9a-f]{40}\.json$/.test(name)) continue;
    const value = await fs.readFile(path.join(receiptsDir, name), 'utf8').then(jsonValue => JSON.parse(jsonValue)).catch(() => null);
    if (value?.state === 'deploying') matches.push({ name, value });
  }
  if (matches.length > 1) throw new AdapterError('MULTIPLE_INTERRUPTED_RELEASES');
  return matches[0] ?? null;
}

async function deployStagingInner(body, {
  rootDir = process.env.CNYOS_STAGING_RELEASE_ROOT || '/srv/cnyos-web-stack',
  spoolRoot = '/var/lib/cnyos-broker/spool',
  runtimeDir = new URL('../runtime/', import.meta.url),
  spawnImpl = spawn,
  webHealth = () => health(18080, '/healthz', 'ok\n'),
  supabaseHealth = () => authenticatedSupabaseHealth(),
  receiptWriter = atomicJson,
  requireRoot = true,
} = {}) {
  const candidate = body?.candidate;
  const artifact = body?.artifact;
  const requestId = body?.request_id;
  if (!body || body.environment !== 'staging' || !candidate || !artifact ||
      typeof requestId !== 'string' || !/^[1-9][0-9]*\.[1-9][0-9]*\.[0-9a-f]{40}$/.test(requestId) ||
      !COMMIT.test(candidate.source_commit) || !DIGEST.test(candidate.archive_sha256) || !DIGEST.test(candidate.release_request_sha256)) {
    throw new AdapterError('DEPLOY_REQUEST_INVALID');
  }
  if (requireRoot && spoolRoot !== '/var/lib/cnyos-broker/spool') throw new AdapterError('DEPLOY_BOUNDARY_INVALID');
  if (typeof artifact.spoolDir !== 'string' || !path.isAbsolute(artifact.spoolDir) ||
      path.dirname(path.resolve(artifact.spoolDir)) !== path.resolve(spoolRoot) ||
      !/^candidate-[A-Za-z0-9_-]{6,}$/.test(path.basename(artifact.spoolDir))) throw new AdapterError('ARTIFACT_SPOOL_INVALID');
  if (artifact.sourceCommit !== candidate.source_commit || artifact.archiveSha256 !== candidate.archive_sha256 ||
      artifact.releaseRequestSha256 !== candidate.release_request_sha256 || !Array.isArray(artifact.files) ||
      [...artifact.files].sort().join('\0') !== [`cnyos-static-${candidate.source_commit}.tar.gz`, 'release-request.json', 'SHA256SUMS'].sort().join('\0')) {
    throw new AdapterError('ARTIFACT_DESCRIPTOR_INVALID');
  }
  if (requireRoot && (rootDir !== '/srv/cnyos-web-stack' || !(await safelyOwned(artifact.spoolDir, { directory: true })))) {
    throw new AdapterError('DEPLOY_BOUNDARY_INVALID');
  }
  await trustedRuntime(runtimeDir, requireRoot);
  const releasesDir = path.join(rootDir, 'releases');
  const failedRoot = path.join(rootDir, 'failed');
  const receiptsDir = path.join(rootDir, 'state', 'receipts');
  const releaseDir = path.join(releasesDir, candidate.source_commit);
  const receiptPath = path.join(receiptsDir, `${requestId}.json`);
  await fs.mkdir(releasesDir, { recursive: true, mode: 0o700 });
  await fs.mkdir(receiptsDir, { recursive: true, mode: 0o700 });
  const existing = await fs.readFile(receiptPath, 'utf8').then(value => JSON.parse(value)).catch(() => null);
  if (existing?.state === 'completed' && existing.source_commit === candidate.source_commit &&
      existing.archive_sha256 === candidate.archive_sha256 &&
      existing.release_request_sha256 === candidate.release_request_sha256) {
    await fs.rm(artifact.spoolDir, { recursive: true, force: true });
    return { ok: true, replay: true, receipt: receiptPath, state: 'web_staged' };
  }
  if (existing) throw new AdapterError('DEPLOY_REQUEST_REPLAY');

  const archiveName = `cnyos-static-${candidate.source_commit}.tar.gz`;
  const packet = await readSpoolFiles(artifact.spoolDir, ['release-request.json', 'SHA256SUMS', archiveName]);
  const { request } = validateReleaseRequest(packet, candidate, body.producer);
  if (sha256(packet.get(archiveName)) !== candidate.archive_sha256) throw new AdapterError('ARCHIVE_DIGEST_MISMATCH');
  const distFiles = extractTarGzip(packet.get(archiveName));
  const manifests = validateManifest(distFiles, request, candidate.source_commit);

  const currentLink = path.join(rootDir, 'current');
  const dockerConfigDir = path.resolve(spoolRoot, '..', 'docker-config');
  await fs.mkdir(dockerConfigDir, { recursive: true, mode: 0o700 });
  await fs.chmod(dockerConfigDir, 0o700);
  const dockerEnv = { ...process.env, CNYOS_SOURCE_COMMIT: candidate.source_commit, DOCKER_CONFIG: dockerConfigDir };
  const interrupted = await findInterruptedReceipt(receiptsDir);
  if (interrupted) {
    if (!COMMIT.test(interrupted.value.source_commit)) throw new AdapterError('INTERRUPTED_RELEASE_INVALID');
    const interruptedRelease = path.join(releasesDir, interrupted.value.source_commit);
    const stranded = await fs.lstat(interruptedRelease).catch(() => null);
    if (!stranded?.isDirectory() || stranded.isSymbolicLink()) throw new AdapterError('INTERRUPTED_RELEASE_INVALID');
    const previousRelease = interrupted.value.previous_release;
    if (previousRelease !== null && (typeof previousRelease !== 'string' ||
        path.relative(releasesDir, previousRelease).startsWith('..'))) throw new AdapterError('INTERRUPTED_PREVIOUS_RELEASE_INVALID');
    if (previousRelease) {
      await run('docker', ['compose', '--project-name', 'cnyos-web-staging', '--env-file', path.join(previousRelease, '.env'), '--file', path.join(previousRelease, 'docker-compose.yml'), 'up', '-d', '--no-build', '--remove-orphans', '--wait', '--wait-timeout', '120'], previousRelease, { spawnImpl, env: dockerEnv });
    } else {
      await run('docker', ['compose', '--project-name', 'cnyos-web-staging', '--env-file', path.join(interruptedRelease, '.env'), '--file', path.join(interruptedRelease, 'docker-compose.yml'), 'down', '--remove-orphans'], interruptedRelease, { spawnImpl, env: dockerEnv });
    }
    await replaceCurrent(currentLink, previousRelease, requestId);
    const recoveredDir = path.join(failedRoot, `${interrupted.value.source_commit}-interrupted-${requestId}`);
    await quarantine(interruptedRelease, recoveredDir);
    await receiptWriter(path.join(receiptsDir, interrupted.name), { ...interrupted.value, state: 'recovered', recovered_by: requestId, recovered_release: recoveredDir, at: new Date().toISOString() });
  }
  if (await fs.lstat(releaseDir).catch(() => null)) throw new AdapterError('RELEASE_ALREADY_EXISTS');
  const previousLink = await fs.readlink(currentLink).catch(() => null);
  const previous = previousLink ? path.resolve(rootDir, previousLink) : null;
  const previousStat = previous ? await fs.lstat(previous).catch(() => null) : null;
  if (previous && (path.relative(releasesDir, previous).startsWith('..') || !previousStat?.isDirectory() || previousStat.isSymbolicLink())) {
    throw new AdapterError('PREVIOUS_RELEASE_INVALID');
  }
  await fs.mkdir(releaseDir, { mode: 0o700 });
  await fs.mkdir(path.join(releaseDir, 'dist'), { mode: 0o700 });
  for (const [name, data] of distFiles) await fs.writeFile(path.join(releaseDir, 'dist', name), data, { flag: 'wx', mode: 0o600 });
  for (const name of TRUSTED_RUNTIME_FILES) {
    const source = runtimeDir instanceof URL ? new URL(name, runtimeDir) : path.join(path.resolve(runtimeDir), name);
    await fs.copyFile(source, path.join(releaseDir, name), fsSync.constants.COPYFILE_EXCL);
  }
  await fs.writeFile(path.join(releaseDir, '.env'), `CNYOS_SOURCE_COMMIT=${candidate.source_commit}\n`, { flag: 'wx', mode: 0o600 });
  await receiptWriter(receiptPath, {
    schema_version: 1, request_id: requestId, source_commit: candidate.source_commit,
    archive_sha256: candidate.archive_sha256, state: 'deploying', previous_release: previous, at: new Date().toISOString(),
  });

  const compose = path.join(releaseDir, 'docker-compose.yml');
  const docker = args => run('docker', ['compose', '--project-name', 'cnyos-web-staging', '--env-file', path.join(releaseDir, '.env'), '--file', compose, ...args], releaseDir, { spawnImpl, env: dockerEnv });
  let rollbackSucceeded = false;
  try {
    await supabaseHealth();
    await docker(['config', '--quiet']);
    await docker(['build', '--pull', 'web']);
    await docker(['up', '-d', '--no-build', '--remove-orphans', '--wait', '--wait-timeout', '120']);
    await webHealth();
    await replaceCurrent(currentLink, releaseDir, requestId);
    await receiptWriter(receiptPath, {
      schema_version: 1, request_id: requestId, source_commit: candidate.source_commit,
      archive_sha256: candidate.archive_sha256, release_request_sha256: candidate.release_request_sha256,
      runtime_manifest_sha256: request.runtimeManifestSha256, file_count: manifests.runtime.fileCount,
      state: 'completed', previous_release: previous, at: new Date().toISOString(),
    });
    return { ok: true, state: 'web_staged', sourceCommit: candidate.source_commit, receipt: receiptPath, runtimeFileCount: manifests.runtime.fileCount };
  } catch (error) {
    try {
      if (previous) {
        await run('docker', ['compose', '--project-name', 'cnyos-web-staging', '--env-file', path.join(previous, '.env'), '--file', path.join(previous, 'docker-compose.yml'), 'up', '-d', '--no-build', '--remove-orphans', '--wait', '--wait-timeout', '120'], previous, { spawnImpl, env: dockerEnv });
      } else {
        await docker(['down', '--remove-orphans']);
      }
      await replaceCurrent(currentLink, previous, requestId);
      rollbackSucceeded = true;
    } catch { rollbackSucceeded = false; }
    const failedDir = path.join(failedRoot, `${candidate.source_commit}-${requestId}`);
    await quarantine(releaseDir, failedDir).catch(() => {});
    await receiptWriter(receiptPath, {
      schema_version: 1, request_id: requestId, source_commit: candidate.source_commit,
      archive_sha256: candidate.archive_sha256, state: 'failed', rollback_succeeded: rollbackSucceeded,
      failure_code: error instanceof AdapterError ? error.code : 'DEPLOYER_FAILED',
      failed_release: failedDir, at: new Date().toISOString(),
    });
    throw error;
  }
}

export async function deployStaging(body, options = {}) {
  const spoolRoot = path.resolve(options.spoolRoot || '/var/lib/cnyos-broker/spool');
  const spoolDir = body?.artifact?.spoolDir;
  const safeSpool = typeof spoolDir === 'string' && path.isAbsolute(spoolDir) &&
    path.dirname(path.resolve(spoolDir)) === spoolRoot && /^candidate-[A-Za-z0-9_-]{6,}$/.test(path.basename(spoolDir));
  try {
    return await deployStagingInner(body, options);
  } finally {
    if (safeSpool) await fs.rm(spoolDir, { recursive: true, force: true }).catch(() => {});
  }
}
