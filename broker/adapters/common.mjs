import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import zlib from 'node:zlib';

export const PRODUCER_REPOSITORY = 'apisarit/chananya-clinical-wellness-os';
export const PRODUCER_REPOSITORY_ID = 1318182797;
export const PRODUCER_BRANCH = 'codex/vps-staging-candidate-20260915';
export const PRODUCER_REF = `refs/heads/${PRODUCER_BRANCH}`;
export const PRODUCER_WORKFLOW = 'deploy-vps-staging.yml';
export const CONTROLLER_REPOSITORY = 'apisarit/cnyos-staging-deployment-control';
export const CONTROLLER_REPOSITORY_ID = 1362863285;
export const CONTROLLER_REF = 'refs/heads/main';
export const CONTROLLER_WORKFLOW = 'Admit VPS staging release';
export const CONTROLLER_WORKFLOW_FILE = 'admit-vps-staging-release.yml';
export const CONTROLLER_ACTOR = 'apisarit';
export const CONTROLLER_ACTOR_ID = 216305243;
export const ARTIFACT_NAME = (commit, runId) => `cnyos-vps-staging-${commit}-${runId}`;
export const MAX_ARCHIVE_BYTES = 80 * 1024 * 1024;
export const MAX_TAR_BYTES = 60 * 1024 * 1024;

export class AdapterError extends Error {
  constructor(code) { super(code); this.code = code; }
}

export const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const safeSha = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const safeCommit = value => typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);

export async function readRootOnlyWorkflowPin(filePath = process.env.CNYOS_CONTROLLER_WORKFLOW_SHA_FILE || '/etc/cnyos-broker/controller-workflow-sha') {
  if (!path.isAbsolute(filePath)) throw new AdapterError('CONTROLLER_WORKFLOW_PIN_PATH_INVALID');
  let stat;
  try { stat = await fs.stat(filePath); } catch { throw new AdapterError('CONTROLLER_WORKFLOW_PIN_UNAVAILABLE'); }
  if (stat.uid !== 0 || (stat.mode & 0o077) !== 0 || !stat.isFile() || stat.size !== 41) throw new AdapterError('CONTROLLER_WORKFLOW_PIN_PERMISSIONS_INVALID');
  const pin = (await fs.readFile(filePath, 'utf8')).trim();
  if (!safeCommit(pin)) throw new AdapterError('CONTROLLER_WORKFLOW_PIN_INVALID');
  return pin;
}

export async function readRootOnlyToken(filePath = process.env.CNYOS_GITHUB_TOKEN_FILE || '/etc/cnyos-broker/github-token') {
  if (!path.isAbsolute(filePath)) throw new AdapterError('GITHUB_TOKEN_PATH_INVALID');
  let stat;
  try { stat = await fs.stat(filePath); } catch { throw new AdapterError('GITHUB_TOKEN_UNAVAILABLE'); }
  if (stat.uid !== 0 || (stat.mode & 0o077) !== 0 || !stat.isFile() || stat.size < 1 || stat.size > 4096) {
    throw new AdapterError('GITHUB_TOKEN_PERMISSIONS_INVALID');
  }
  const token = (await fs.readFile(filePath, 'utf8')).trim();
  if (!/^[A-Za-z0-9_\-.]+$/.test(token)) throw new AdapterError('GITHUB_TOKEN_FORMAT_INVALID');
  return token;
}

function apiPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/repos/') || value.includes('..') || value.includes('://')) throw new AdapterError('GITHUB_PATH_INVALID');
  return value;
}

function request(url, { token, headers = {}, maxBytes = 512 * 1024, redirect = false } = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'api.github.com') throw new AdapterError('GITHUB_HOST_INVALID');
  return new Promise((resolve, reject) => {
    const req = https.get({ hostname: parsed.hostname, port: 443, path: `${parsed.pathname}${parsed.search}`, servername: parsed.hostname,
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'cnyos-staging-broker', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, timeout: 10_000 }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirect) { reject(new AdapterError('GITHUB_REDIRECT_UNEXPECTED')); return; }
        resolve(request(new URL(response.headers.location, url).toString(), { maxBytes, redirect: true }));
        return;
      }
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > maxBytes) { req.destroy(); reject(new AdapterError('GITHUB_RESPONSE_TOO_LARGE')); } else chunks.push(chunk); });
      response.on('end', () => {
        if (response.statusCode !== 200) { reject(new AdapterError(`GITHUB_HTTP_${response.statusCode}`)); return; }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new AdapterError('GITHUB_JSON_INVALID')); }
      });
    });
    req.on('timeout', () => req.destroy(new AdapterError('GITHUB_TIMEOUT')));
    req.on('error', reject);
  });
}

function download(url, { token, maxBytes = MAX_ARCHIVE_BYTES } = {}) {
  const first = new URL(url);
  if (first.protocol !== 'https:' || first.hostname !== 'api.github.com' || !first.pathname.startsWith('/repos/')) throw new AdapterError('ARTIFACT_URL_INVALID');
  return new Promise((resolve, reject) => {
    const visit = (parsed, authAllowed, redirects = 0) => {
      const allowed = parsed.hostname === 'api.github.com' || parsed.hostname === 'objects.githubusercontent.com' ||
        parsed.hostname === 'release-assets.githubusercontent.com' || parsed.hostname.endsWith('.blob.core.windows.net');
      if (parsed.protocol !== 'https:' || !allowed || redirects > 3) { reject(new AdapterError('ARTIFACT_REDIRECT_UNSAFE')); return; }
      const req = https.get({ hostname: parsed.hostname, port: parsed.port || 443, path: `${parsed.pathname}${parsed.search}`, servername: parsed.hostname,
        headers: { accept: 'application/zip', 'user-agent': 'cnyos-staging-broker', ...(authAllowed && token ? { authorization: `Bearer ${token}` } : {}) }, timeout: 20_000 }, response => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          response.resume();
          const next = new URL(response.headers.location, parsed);
          if (next.protocol !== 'https:') { reject(new AdapterError('ARTIFACT_REDIRECT_UNSAFE')); return; }
          visit(next, false, redirects + 1); // Never forward GitHub credentials across a redirect.
          return;
        }
        if (response.statusCode !== 200) { response.resume(); reject(new AdapterError(`ARTIFACT_HTTP_${response.statusCode}`)); return; }
        const chunks = []; let size = 0;
        response.on('data', chunk => { size += chunk.length; if (size > maxBytes) { req.destroy(); reject(new AdapterError('ARTIFACT_TOO_LARGE')); } else chunks.push(chunk); });
        response.on('end', () => resolve(Buffer.concat(chunks)));
      });
      req.on('timeout', () => req.destroy(new AdapterError('ARTIFACT_TIMEOUT')));
      req.on('error', reject);
    };
    visit(first, true);
  });
}

export function createGitHubClient({ token, requestImpl = request, downloadImpl = download } = {}) {
  if (typeof token !== 'string' || !token) throw new AdapterError('GITHUB_TOKEN_REQUIRED');
  const get = (pathname, options = {}) => requestImpl(`https://api.github.com${apiPath(pathname)}`, { token, ...options });
  return Object.freeze({
    repo: repo => get(`/repos/${repo}`),
    run: (repo, id) => get(`/repos/${repo}/actions/runs/${id}`),
    artifact: (repo, id) => get(`/repos/${repo}/actions/artifacts/${id}`),
    branch: (repo, branch) => get(`/repos/${repo}/branches/${branch}`),
    protection: (repo, branch) => get(`/repos/${repo}/branches/${branch}/protection`),
    downloadArtifact: (repo, id) => downloadImpl(`https://api.github.com/repos/${repo}/actions/artifacts/${id}/zip`, { token }),
  });
}

function exact(value, expected, code) { if (value !== expected) throw new AdapterError(code); }
function positive(value, code) { if (!Number.isSafeInteger(value) || value < 1) throw new AdapterError(code); }

export async function verifyCandidate(body, client, { workflowShaPin } = {}) {
  if (!body || !body.controller || !body.producer || !body.candidate) throw new AdapterError('CANDIDATE_BODY_INVALID');
  const { controller: c, producer: p, candidate: a } = body;
  exact(body.environment, 'staging', 'CANDIDATE_ENVIRONMENT_INVALID');
  exact(p.repository, PRODUCER_REPOSITORY, 'PRODUCER_REPOSITORY_INVALID');
  exact(p.ref, PRODUCER_REF, 'PRODUCER_REF_INVALID');
  exact(p.workflow_file, PRODUCER_WORKFLOW, 'PRODUCER_WORKFLOW_INVALID');
  if (!safeCommit(a.source_commit) || !safeSha(a.archive_sha256) || !safeSha(a.release_request_sha256)) throw new AdapterError('CANDIDATE_DIGEST_INVALID');
  positive(a.producer_run_id, 'PRODUCER_RUN_INVALID'); positive(a.artifact_id, 'ARTIFACT_ID_INVALID');
  exact(c.repository, CONTROLLER_REPOSITORY, 'CONTROLLER_REPOSITORY_INVALID');
  exact(c.repository_id, CONTROLLER_REPOSITORY_ID, 'CONTROLLER_REPOSITORY_ID_INVALID');
  exact(c.ref, CONTROLLER_REF, 'CONTROLLER_REF_INVALID');
  exact(c.workflow, CONTROLLER_WORKFLOW, 'CONTROLLER_WORKFLOW_INVALID');
  exact(c.workflow_ref, `${CONTROLLER_REPOSITORY}/.github/workflows/${CONTROLLER_WORKFLOW_FILE}@${CONTROLLER_REF}`, 'CONTROLLER_WORKFLOW_REF_INVALID');
  if (!safeCommit(c.workflow_sha) || c.ref_protected !== true) throw new AdapterError('CONTROLLER_IMMUTABLE_IDENTITY_INVALID');
  exact(c.actor, CONTROLLER_ACTOR, 'CONTROLLER_ACTOR_INVALID');
  exact(c.actor_id, CONTROLLER_ACTOR_ID, 'CONTROLLER_ACTOR_ID_INVALID');
  exact(c.triggering_actor, CONTROLLER_ACTOR, 'CONTROLLER_TRIGGERING_ACTOR_INVALID');
  positive(c.run_id, 'CONTROLLER_RUN_INVALID'); positive(c.run_attempt, 'CONTROLLER_ATTEMPT_INVALID');
  if (!safeCommit(workflowShaPin) || c.workflow_sha !== workflowShaPin) throw new AdapterError('CONTROLLER_WORKFLOW_PIN_MISMATCH');
  const [repo, branch, protection, controllerRun, producerRepo, producerRun, artifact] = await Promise.all([
    client.repo(CONTROLLER_REPOSITORY), client.branch(CONTROLLER_REPOSITORY, 'main').catch(() => null), client.protection(CONTROLLER_REPOSITORY, 'main').catch(() => null),
    client.run(CONTROLLER_REPOSITORY, c.run_id), client.repo(PRODUCER_REPOSITORY), client.run(PRODUCER_REPOSITORY, a.producer_run_id), client.artifact(PRODUCER_REPOSITORY, a.artifact_id)
  ]);
  exact(repo.full_name, CONTROLLER_REPOSITORY, 'CONTROLLER_REPOSITORY_MISMATCH');
  if (repo.private !== true || repo.id !== CONTROLLER_REPOSITORY_ID || repo.default_branch !== 'main') throw new AdapterError('CONTROLLER_REPOSITORY_TRUST_INVALID');
  // GitHub's branch/protection responses are advisory only: a private-repository
  // plan may return 403 even when the repository is valid. The root-owned pin
  // above is the server-side trust anchor and is never replaced by this API.
  exact(controllerRun.id, c.run_id, 'CONTROLLER_RUN_ID_MISMATCH'); exact(controllerRun.head_sha, c.workflow_sha, 'CONTROLLER_WORKFLOW_SHA_MISMATCH');
  exact(controllerRun.path, `.github/workflows/${CONTROLLER_WORKFLOW_FILE}`, 'CONTROLLER_WORKFLOW_PATH_MISMATCH');
  if (controllerRun.head_branch !== 'main' || controllerRun.event !== 'workflow_dispatch' ||
      controllerRun.actor?.id !== CONTROLLER_ACTOR_ID || controllerRun.actor?.login !== CONTROLLER_ACTOR ||
      !['queued', 'in_progress', 'completed'].includes(controllerRun.status)) throw new AdapterError('CONTROLLER_RUN_STATE_INVALID');
  exact(producerRepo.full_name, PRODUCER_REPOSITORY, 'PRODUCER_REPOSITORY_MISMATCH');
  if (producerRepo.id !== PRODUCER_REPOSITORY_ID || producerRepo.default_branch !== 'main' ||
      producerRepo.visibility !== 'public' || producerRepo.private !== false) throw new AdapterError('PRODUCER_VISIBILITY_INVALID');
  exact(producerRun.id, a.producer_run_id, 'PRODUCER_RUN_ID_MISMATCH'); exact(producerRun.head_sha, a.source_commit, 'PRODUCER_COMMIT_MISMATCH');
  exact(producerRun.head_branch, PRODUCER_BRANCH, 'PRODUCER_BRANCH_MISMATCH'); exact(producerRun.path, `.github/workflows/${PRODUCER_WORKFLOW}`, 'PRODUCER_WORKFLOW_PATH_MISMATCH');
  if (producerRun.status !== 'completed' || producerRun.conclusion !== 'success') throw new AdapterError('PRODUCER_RUN_NOT_SUCCESSFUL');
  exact(artifact.id, a.artifact_id, 'ARTIFACT_ID_MISMATCH'); exact(artifact.name, ARTIFACT_NAME(a.source_commit, a.producer_run_id), 'ARTIFACT_NAME_MISMATCH');
  if (artifact.expired === true || artifact.workflow_run?.id !== a.producer_run_id || artifact.size_in_bytes < 1) throw new AdapterError('ARTIFACT_METADATA_INVALID');
  return { ok: true, controllerRun: controllerRun.id, producerRun: producerRun.id, artifactId: artifact.id, branchProtectionObserved: branch?.protected === true && protection != null };
}

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) { crc ^= byte; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
const u16 = (b, p) => b.readUInt16LE(p); const u32 = (b, p) => b.readUInt32LE(p);
function safeName(name) { return typeof name === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(name) && name !== '.' && name !== '..'; }

export function readZipExact(buffer, expected) {
  if (!Buffer.isBuffer(buffer) || buffer.length > MAX_ARCHIVE_BYTES) throw new AdapterError('ZIP_INVALID');
  const end = Math.max(0, buffer.length - 0xffff - 22); let eocd = -1;
  for (let i = buffer.length - 22; i >= end; i--) if (buffer.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0 || eocd + 22 + u16(buffer, eocd + 20) !== buffer.length ||
      u16(buffer, eocd + 4) !== 0 || u16(buffer, eocd + 6) !== 0 ||
      u16(buffer, eocd + 8) !== u16(buffer, eocd + 10)) throw new AdapterError('ZIP_STRUCTURE_INVALID');
  const count = u16(buffer, eocd + 10); const centralSize = u32(buffer, eocd + 12); const centralOffset = u32(buffer, eocd + 16);
  if (count !== expected.length || centralOffset + centralSize > eocd) throw new AdapterError('ZIP_STRUCTURE_INVALID');
  const entries = new Map(); let pos = centralOffset; const ranges = []; let totalSize = 0;
  for (let i = 0; i < count; i++) {
    if (pos + 46 > centralOffset + centralSize || pos + 46 > eocd) throw new AdapterError('ZIP_STRUCTURE_INVALID');
    if (u32(buffer, pos) !== 0x02014b50) throw new AdapterError('ZIP_ENTRY_INVALID');
    const flags = u16(buffer, pos + 8); const method = u16(buffer, pos + 10); const crc = u32(buffer, pos + 16); const compressed = u32(buffer, pos + 20); const size = u32(buffer, pos + 24);
    const nameLen = u16(buffer, pos + 28); const extraLen = u16(buffer, pos + 30); const commentLen = u16(buffer, pos + 32); const external = u32(buffer, pos + 38); const local = u32(buffer, pos + 42);
    if (pos + 46 + nameLen + extraLen + commentLen > centralOffset + centralSize || pos + 46 + nameLen + extraLen + commentLen > eocd) throw new AdapterError('ZIP_STRUCTURE_INVALID');
    const name = buffer.subarray(pos + 46, pos + 46 + nameLen).toString('utf8'); pos += 46 + nameLen + extraLen + commentLen;
    totalSize += size;
    if (!safeName(name) || entries.has(name) || (flags & 1) || ![0, 8].includes(method) ||
        size > MAX_TAR_BYTES || totalSize > MAX_ARCHIVE_BYTES || compressed > MAX_ARCHIVE_BYTES ||
        (external & 0x10) !== 0) throw new AdapterError('ZIP_ENTRY_UNSAFE');
    const mode = external >>> 16; if (mode && ((mode & 0xf000) === 0xa000 || (mode & 0xf000) !== 0x8000)) throw new AdapterError('ZIP_ENTRY_TYPE_INVALID');
    if (local + 30 > buffer.length || u32(buffer, local) !== 0x04034b50) throw new AdapterError('ZIP_LOCAL_INVALID');
    const localNameLen = u16(buffer, local + 26); const localExtraLen = u16(buffer, local + 28); const localName = buffer.subarray(local + 30, local + 30 + localNameLen).toString('utf8');
    if (localName !== name || local + 30 + localNameLen + localExtraLen + compressed > buffer.length) throw new AdapterError('ZIP_LOCAL_INVALID');
    ranges.push([local, local + 30 + localNameLen + localExtraLen + compressed]); entries.set(name, { method, crc, size, compressed, start: local + 30 + localNameLen + localExtraLen });
  }
  if (pos !== centralOffset + centralSize) throw new AdapterError('ZIP_STRUCTURE_INVALID');
  ranges.sort((a, b) => a[0] - b[0]); for (let i = 1; i < ranges.length; i++) if (ranges[i][0] < ranges[i - 1][1]) throw new AdapterError('ZIP_OVERLAP');
  const result = new Map();
  for (const name of expected) {
    const entry = entries.get(name); if (!entry) throw new AdapterError('ZIP_FILESET_INVALID');
    let content; try { content = entry.method === 0 ? buffer.subarray(entry.start, entry.start + entry.compressed) : zlib.inflateRawSync(buffer.subarray(entry.start, entry.start + entry.compressed), { maxOutputLength: entry.size }); } catch { throw new AdapterError('ZIP_DEFLATE_INVALID'); }
    if (content.length !== entry.size || crc32(content) !== entry.crc) throw new AdapterError('ZIP_CHECKSUM_INVALID');
    result.set(name, content);
  }
  if (entries.size !== expected.length) throw new AdapterError('ZIP_FILESET_INVALID');
  return result;
}

export async function writeRootOnly(dir, files) {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 }); await fs.chmod(dir, 0o700);
  for (const [name, content] of files) { if (!safeName(name)) throw new AdapterError('SPOOL_PATH_INVALID'); const target = path.join(dir, name); await fs.writeFile(target, content, { mode: 0o600 }); await fs.chmod(target, 0o600); }
}

export function validateReleaseRequest(files, candidate, producer) {
  let request; try { request = JSON.parse(files.get('release-request.json').toString('utf8')); } catch { throw new AdapterError('RELEASE_REQUEST_INVALID'); }
  if (request.schemaVersion !== 1 || request.kind !== 'cnyos_vps_staging_candidate' || request.authorization !== false || request.productionEligible !== false ||
      Object.keys(request).sort().join('\0') !== ['schemaVersion', 'kind', 'authorization', 'productionEligible', 'source', 'workflow', 'artifact', 'runtimeManifestSha256', 'deployManifestSha256', 'note'].sort().join('\0')) throw new AdapterError('RELEASE_REQUEST_UNSAFE');
  if (request.source?.repository !== PRODUCER_REPOSITORY || request.source?.commit !== candidate.source_commit ||
      !safeCommit(request.source?.tree) || (request.workflow?.runId !== String(candidate.producer_run_id) && request.workflow?.runId !== candidate.producer_run_id) ||
      !Number.isSafeInteger(Number(request.workflow?.runAttempt)) || Number(request.workflow.runAttempt) < 1 ||
      !safeSha(request.runtimeManifestSha256) || !safeSha(request.deployManifestSha256)) throw new AdapterError('RELEASE_SOURCE_BINDING_INVALID');
  const archiveName = `cnyos-static-${candidate.source_commit}.tar.gz`; if (request.artifact?.file !== archiveName || request.artifact?.sha256 !== candidate.archive_sha256) throw new AdapterError('RELEASE_ARCHIVE_BINDING_INVALID');
  const sums = files.get('SHA256SUMS')?.toString('utf8').trim().split('\n').filter(Boolean) || []; if (sums.length !== 2) throw new AdapterError('SHA256SUMS_INVALID');
  const expected = new Map(sums.map(line => { const match = line.match(/^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/); if (!match) throw new AdapterError('SHA256SUMS_INVALID'); return [match[2], match[1]]; }));
  if (expected.size !== 2 || [...expected.keys()].sort().join('\0') !== [archiveName, 'release-request.json'].sort().join('\0') ||
      expected.get(archiveName) !== sha256(files.get(archiveName)) || expected.get('release-request.json') !== candidate.release_request_sha256 ||
      sha256(files.get('release-request.json')) !== candidate.release_request_sha256) throw new AdapterError('RELEASE_DIGEST_MISMATCH');
  if (producer?.repository !== PRODUCER_REPOSITORY) throw new AdapterError('PRODUCER_BINDING_INVALID');
  return Object.freeze({ request, archiveName });
}

export function extractTarGzip(buffer) {
  let tar; try { tar = zlib.gunzipSync(buffer); } catch { throw new AdapterError('TAR_GZIP_INVALID'); }
  if (tar.length > MAX_TAR_BYTES) throw new AdapterError('TAR_TOO_LARGE');
  const files = new Map(); let offset = 0; let totalSize = 0; let terminated = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512); if (header.every(byte => byte === 0)) { terminated = true; break; }
    const checksumText = header.subarray(148, 156).toString('ascii').replace(/\0.*$/, '').trim();
    if (!/^[0-7]+$/.test(checksumText)) throw new AdapterError('TAR_CHECKSUM_INVALID');
    const expectedChecksum = parseInt(checksumText, 8); const checksumHeader = Buffer.from(header); checksumHeader.fill(32, 148, 156);
    if ([...checksumHeader].reduce((sum, byte) => sum + byte, 0) !== expectedChecksum) throw new AdapterError('TAR_CHECKSUM_INVALID');
    const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, ''); const name = rawName.replace(/^\.\//, ''); const sizeText = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
    if (!/^[0-7]+$/.test(sizeText || '0')) throw new AdapterError('TAR_ENTRY_UNSAFE');
    const size = parseInt(sizeText || '0', 8); const type = header[156] || 48;
    const nameForCheck = name.replace(/\/$/, '');
    totalSize += size;
    if (!nameForCheck || nameForCheck.includes('/') || !safeName(nameForCheck) || !Number.isSafeInteger(size) || size < 0 || size > MAX_TAR_BYTES || totalSize > MAX_TAR_BYTES || ![48, 53].includes(type)) throw new AdapterError('TAR_ENTRY_UNSAFE');
    const storedChecksum = parseInt(header.subarray(148, 156).toString('ascii').replace(/\0.*$/, '').trim(), 8); const checkHeader = Buffer.from(header); checkHeader.fill(32, 148, 156); const computedChecksum = [...checkHeader].reduce((total, byte) => total + byte, 0);
    if (!Number.isSafeInteger(storedChecksum) || storedChecksum !== computedChecksum) throw new AdapterError('TAR_CHECKSUM_INVALID');
    if (type === 53) { offset += 512 + Math.ceil(size / 512) * 512; continue; }
    const end = offset + 512 + size; if (end > tar.length || files.has(name)) throw new AdapterError('TAR_STRUCTURE_INVALID'); files.set(name, Buffer.from(tar.subarray(offset + 512, end))); offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (!terminated || tar.length - offset < 1024 || !tar.subarray(offset).every(byte => byte === 0)) throw new AdapterError('TAR_STRUCTURE_INVALID');
  return files;
}
