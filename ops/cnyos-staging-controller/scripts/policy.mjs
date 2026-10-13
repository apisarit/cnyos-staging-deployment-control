import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rawPolicy = fs.readFileSync(path.join(packageRoot, 'controller-policy.json'), 'utf8');

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export const POLICY = deepFreeze(JSON.parse(rawPolicy));
export const POLICY_SHA256 = crypto.createHash('sha256').update(rawPolicy).digest('hex');
export const SHA40 = /^[0-9a-f]{40}$/;
export const SHA256 = /^[0-9a-f]{64}$/;
export const DEPLOY_ID = /^[0-9a-f]{24}$/;
export const SITE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
export const MAX_JSON_BYTES = 2 * 1024 * 1024;
export const MAX_FILE_BYTES = 32 * 1024 * 1024;
export const PR36_LEGACY_REQUIRED_STATE = 'open_draft_unapproved';
export const PR36_REVIEW_ONLY_REQUIRED_STATE = 'open_draft_review_only';
export const PR36_ALLOWED_REQUIRED_STATES = Object.freeze([
  PR36_LEGACY_REQUIRED_STATE,
  PR36_REVIEW_ONLY_REQUIRED_STATE
]);

export function assertPr36RequiredState(value, code = 'CNYOS_CONTROLLER_PR36_POLICY_STATE_INVALID') {
  if (typeof value !== 'string' || !PR36_ALLOWED_REQUIRED_STATES.includes(value)) fail(code);
  return value;
}

export function isPr36ReviewOnlyState(value) {
  return value === PR36_REVIEW_ONLY_REQUIRED_STATE;
}

export function assertPr36PolicyConfiguration(value, code = 'CNYOS_CONTROLLER_GITHUB_RELEASE_POLICY_INVALID') {
  if (!isPlainObject(value) || !Array.isArray(value.allowedPr36States) ||
    JSON.stringify(value.allowedPr36States) !== JSON.stringify(PR36_ALLOWED_REQUIRED_STATES)) fail(code);
  return value;
}

export const REQUIRED_REVIEW_AREAS = Object.freeze([
  'trigger_function_and_browser_rpc_acl_revocation',
  'verification_sql_enforced_read_only_transaction',
  'atomic_failure_and_rollback_behavior'
]);

export const EXPECTED_FUNCTION_NAMES = Object.freeze([
  'account-access',
  'database-backup',
  'database-backup-background',
  'database-backup-recovery',
  'evidence-search',
  'line-oa-webhook',
  'owner-drive',
  'owner-subscription',
  'patient-identity',
  'platform-console',
  'restore-source',
  'who-icd-search'
]);

export const REQUIRED_SCHEDULES = Object.freeze({
  'database-backup': '0 20 * * *',
  'database-backup-recovery': '*/15 0-2,20-23 * * *'
});

export const FUNCTIONS_REQUIRING_NO_SCHEDULE_OR_CUSTOM_ROUTE = Object.freeze([
  'database-backup-background'
]);

export function fail(code) {
  throw new Error(code);
}

export function required(value, code, maximum = 4096) {
  const normalized = String(value || '').trim();
  if (!normalized || normalized.length > maximum) fail(code);
  return normalized;
}

export function exactSha40(value, code) {
  const normalized = required(value, code).toLowerCase();
  if (!SHA40.test(normalized)) fail(code);
  return normalized;
}

export function exactSha256(value, code) {
  const normalized = required(value, code).toLowerCase();
  if (!SHA256.test(normalized)) fail(code);
  return normalized;
}

export function exactDeployId(value, code) {
  const normalized = required(value, code).toLowerCase();
  if (!DEPLOY_ID.test(normalized)) fail(code);
  return normalized;
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function sha1(value) {
  return crypto.createHash('sha1').update(value).digest('hex');
}

export function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function parseJsonObject(raw, code) {
  let parsed;
  try { parsed = JSON.parse(String(raw)); }
  catch { fail(code); }
  if (!isPlainObject(parsed)) fail(code);
  return parsed;
}

export function safeOrigin(value, code) {
  let url;
  try { url = new URL(String(value || '')); }
  catch { fail(code); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
    url.pathname !== '/' || url.search || url.hash) fail(code);
  return url.origin.toLowerCase();
}

export function assertDeploymentBoundary(
  policy,
  code = 'CNYOS_CONTROLLER_DEPLOYMENT_BOUNDARY_INVALID'
) {
  if (!isPlainObject(policy) || !isPlainObject(policy.target) ||
    !isPlainObject(policy.productionDenylist)) fail(code);
  const stagingSiteId = String(policy.target.netlifySiteId || '');
  const productionSiteId = String(policy.productionDenylist.netlifySiteId || '');
  if (!SITE_ID.test(stagingSiteId) || !SITE_ID.test(productionSiteId) ||
    stagingSiteId !== stagingSiteId.toLowerCase() ||
    productionSiteId !== productionSiteId.toLowerCase() ||
    stagingSiteId === productionSiteId) fail(code);
  const stagingOrigin = safeOrigin(policy.target.netlifyOrigin, code);
  const productionOrigin = safeOrigin(policy.productionDenylist.netlifyOrigin, code);
  if (policy.target.netlifyOrigin !== stagingOrigin ||
    policy.productionDenylist.netlifyOrigin !== productionOrigin ||
    stagingOrigin === productionOrigin) fail(code);
  return Object.freeze({
    stagingSiteId,
    stagingOrigin,
    productionSiteId,
    productionOrigin
  });
}

export const DEPLOYMENT_BOUNDARY = assertDeploymentBoundary(POLICY);

export function observedDate(value, code) {
  const result = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(result.getTime())) fail(code);
  return result;
}

export function canonicalIsoTimestamp(value, code = 'TIMESTAMP_INVALID') {
  if (typeof value !== 'string') fail(code);
  const normalized = required(value, code, 32);
  if (value !== normalized ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(normalized)) fail(code);
  const result = new Date(normalized);
  if (Number.isNaN(result.getTime()) || result.toISOString() !== normalized) fail(code);
  return result;
}

export function minimumFutureTimestamp(value, reference, minimumMilliseconds, code = 'TIMESTAMP_INVALID') {
  if (!(reference instanceof Date) || Number.isNaN(reference.getTime()) ||
    !Number.isSafeInteger(minimumMilliseconds) || minimumMilliseconds < 0) fail(code);
  const result = canonicalIsoTimestamp(value, code);
  if (result.getTime() < reference.getTime() + minimumMilliseconds) fail(code);
  return result;
}

export function recentCanonicalTimestamp(value, reference, maximumAgeMilliseconds,
  code = 'TIMESTAMP_INVALID') {
  if (!(reference instanceof Date) || Number.isNaN(reference.getTime()) ||
    !Number.isSafeInteger(maximumAgeMilliseconds) || maximumAgeMilliseconds < 0) fail(code);
  const result = canonicalIsoTimestamp(value, code);
  if (result > reference || reference.getTime() - result.getTime() > maximumAgeMilliseconds) fail(code);
  return result;
}

export function assertExactKeys(value, expected, code) {
  if (!isPlainObject(value)) fail(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((item, index) => item !== wanted[index])) fail(code);
}

export function decodeNonce(value) {
  const nonce = required(value, 'CNYOS_CONTROLLER_NONCE_REQUIRED', 256);
  if (!/^[A-Za-z0-9_-]+$/.test(nonce)) fail('CNYOS_CONTROLLER_NONCE_INVALID');
  const padding = '='.repeat((4 - (nonce.length % 4)) % 4);
  let bytes;
  try { bytes = Buffer.from(nonce.replace(/-/g, '+').replace(/_/g, '/') + padding, 'base64'); }
  catch { fail('CNYOS_CONTROLLER_NONCE_INVALID'); }
  const canonical = bytes.toString('base64url');
  if (canonical !== nonce || bytes.length < POLICY.authorization.minimumNonceBytes) {
    fail('CNYOS_CONTROLLER_NONCE_INVALID');
  }
  return Object.freeze({ value: nonce, bytes });
}

export async function readRegularFileStable(
  filename,
  maximum = MAX_FILE_BYTES,
  code = 'FILE_INVALID',
  minimum = 0
) {
  const resolved = path.resolve(filename);
  if (!Number.isSafeInteger(maximum) || maximum < 0 ||
    !Number.isSafeInteger(minimum) || minimum < 0 || minimum > maximum) fail(code);
  let handle;
  try {
    handle = await fsp.open(
      resolved,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
    );
  } catch {
    fail(code);
  }
  try {
    const [before, pathStatus] = await Promise.all([
      handle.stat({ bigint: true }),
      fsp.lstat(resolved, { bigint: true })
    ]);
    if (!before.isFile() || !pathStatus.isFile() || pathStatus.isSymbolicLink() ||
      before.dev !== pathStatus.dev || before.ino !== pathStatus.ino ||
      before.size < BigInt(minimum) || before.size > BigInt(maximum)) fail(code);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (!after.isFile() || before.dev !== after.dev || before.ino !== after.ino ||
      before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs || bytes.byteLength !== Number(before.size)) fail(code);
    return bytes;
  } catch (error) {
    if (error?.message === code) throw error;
    fail(code);
  } finally {
    await handle.close().catch(() => {});
  }
}

export async function readFileBounded(filename, maximum = MAX_JSON_BYTES, code = 'FILE_INVALID') {
  return readRegularFileStable(filename, maximum, code, 1);
}

export async function readJsonFile(filename, code, maximum = MAX_JSON_BYTES) {
  const bytes = await readFileBounded(filename, maximum, code);
  return Object.freeze({ bytes, value: parseJsonObject(bytes.toString('utf8'), code) });
}

const EVIDENCE_AMBIGUOUS = 'CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_AMBIGUOUS';

function ambiguous(error) {
  const result = new Error(EVIDENCE_AMBIGUOUS, { cause: error });
  result.code = EVIDENCE_AMBIGUOUS;
  return result;
}

async function removeOwnedTemp(filename, expectedStat) {
  try {
    const status = await fsp.lstat(filename, { bigint: true });
    if (status.isFile() && !status.isSymbolicLink() &&
      status.dev === expectedStat.dev && status.ino === expectedStat.ino) {
      await fsp.unlink(filename);
      return;
    }
    fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_TEMP_OWNERSHIP_LOST');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

export async function writeBytesExclusive(filename, bytes) {
  // This is process-interruption consistency on a trusted local filesystem;
  // it is not a universal NAS or power-loss durability guarantee. Orphaned
  // temps are never reused or blindly deleted, and ambiguous outcomes are
  // never retried automatically. Ancestor and same-UID path races are outside
  // the trust boundary; existing parents retain their permissions.
  const destination = path.resolve(filename);
  const snapshot = Buffer.isBuffer(bytes) ? Buffer.from(bytes) : Buffer.from(String(bytes), 'utf8');
  const parent = path.dirname(destination);
  await fsp.mkdir(parent, { recursive: true, mode: 0o700 });
  const parentHandle = await fsp.open(parent,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
  let parentStat;
  let publicationLinked = false;
  let publicationUncertain = false;
  try {
    parentStat = await parentHandle.stat({ bigint: true });
    const parentPathStat = await fsp.lstat(parent, { bigint: true });
    if (!parentStat.isDirectory() || parentPathStat.isSymbolicLink() ||
      !parentPathStat.isDirectory() || parentStat.dev !== parentPathStat.dev ||
      parentStat.ino !== parentPathStat.ino) fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_PARENT_INVALID');
    let temporary;
    let temporaryStat;
    let linked = false;
    try {
      let collisionAttempts = 0;
      for (;;) {
        if (collisionAttempts++ >= 8) fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_TEMP_COLLISION');
        temporary = path.join(parent, `.${path.basename(destination)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
        let opened = false;
        try {
          const handle = await fsp.open(temporary,
            fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL |
              (fs.constants.O_NOFOLLOW || 0), 0o600);
          opened = true;
          try {
            temporaryStat = await handle.stat({ bigint: true });
            if (!temporaryStat.isFile() || temporaryStat.mode !== BigInt(0o100600)) {
              fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_TEMP_INVALID');
            }
            let offset = 0;
            while (offset < snapshot.byteLength) {
              const { bytesWritten } = await handle.write(snapshot, offset, snapshot.byteLength - offset, offset);
              if (!bytesWritten) fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_WRITE_FAILED');
              offset += bytesWritten;
            }
            await handle.sync();
            const readback = await handle.readFile();
            if (!Buffer.isBuffer(readback) || !readback.equals(snapshot)) {
              fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_READBACK_FAILED');
            }
            temporaryStat = await handle.stat({ bigint: true });
            if (!temporaryStat.isFile() || temporaryStat.mode !== BigInt(0o100600) ||
              temporaryStat.size !== BigInt(snapshot.byteLength)) {
              fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_TEMP_INVALID');
            }
          } finally {
            await handle.close();
          }
          break;
        } catch (error) {
          if (!opened && error?.code === 'EEXIST') continue;
          throw error;
        }
      }
      const parentBeforeLink = await parentHandle.stat({ bigint: true });
      const parentPathBeforeLink = await fsp.lstat(parent, { bigint: true });
      if (!parentPathBeforeLink.isDirectory() || parentPathBeforeLink.isSymbolicLink() ||
        parentBeforeLink.dev !== parentStat.dev || parentBeforeLink.ino !== parentStat.ino ||
        parentPathBeforeLink.dev !== parentStat.dev || parentPathBeforeLink.ino !== parentStat.ino) {
        fail('CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_PARENT_CHANGED');
      }
      try {
        await fsp.link(temporary, destination);
      } catch (error) {
        // A wrapper or OS error may be reported after link(2) committed.  Only
        // treat it as committed when the final name is our exact inode.
        if (error?.code !== 'EEXIST') {
          publicationUncertain = true;
          throw ambiguous(error);
        }
        try {
          const finalStatus = await fsp.lstat(destination, { bigint: true });
          if (finalStatus.isFile() && !finalStatus.isSymbolicLink() &&
            finalStatus.dev === temporaryStat.dev && finalStatus.ino === temporaryStat.ino) {
            linked = true;
            publicationLinked = true;
            publicationUncertain = true;
            throw ambiguous(error);
          }
        } catch (probeError) {
          if (probeError?.code === EVIDENCE_AMBIGUOUS) throw probeError;
          if (probeError?.code !== 'ENOENT') throw error;
        }
        throw error;
      }
      linked = true;
      publicationLinked = true;
      await removeOwnedTemp(temporary, temporaryStat);
      temporary = undefined;
      await parentHandle.sync();
      return destination;
    } catch (error) {
      if (linked || publicationUncertain) {
        if (error?.code === EVIDENCE_AMBIGUOUS) throw error;
        throw ambiguous(error);
      }
      throw error;
    } finally {
      if (temporary && temporaryStat) {
        try { await removeOwnedTemp(temporary, temporaryStat); }
        catch (error) { if (linked || publicationUncertain) throw ambiguous(error); throw error; }
      }
    }
  } finally {
    try { await parentHandle.close(); }
    catch (error) {
      if (publicationLinked || publicationUncertain) throw ambiguous(error);
      throw error;
    }
  }
}

export async function writeJsonExclusive(filename, value) {
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  return writeBytesExclusive(filename, Buffer.from(serialized, 'utf8'));
}

export function normalizedRelativePath(value, code = 'ARTIFACT_PATH_INVALID') {
  const normalized = String(value || '').replaceAll('\\', '/');
  if (!normalized || normalized.startsWith('/') || normalized.includes('\0') ||
    normalized.split('/').some(part => !part || part === '.' || part === '..') ||
    normalized !== path.posix.normalize(normalized)) fail(code);
  return normalized;
}

export function portableRelativePath(value, code = 'ARTIFACT_PATH_INVALID') {
  const normalized = normalizedRelativePath(value, code);
  if (normalized !== normalized.normalize('NFC') || /[^\x20-\x7e]/.test(normalized) ||
    normalized.split('/').some(part => !/^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(part))) {
    fail(code);
  }
  return normalized;
}

export async function walkRegularFiles(rootDirectory, prefix = '') {
  const root = path.resolve(rootDirectory);
  let rootStatus;
  try { rootStatus = await fsp.lstat(root); }
  catch { fail('ARTIFACT_ROOT_INVALID'); }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail('ARTIFACT_ROOT_INVALID');
  const output = [];
  const portableNames = new Set();
  async function visit(current, relative) {
    const entries = await fsp.readdir(current, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      portableRelativePath(childRelative);
      const portableName = childRelative.toLowerCase();
      if (portableNames.has(portableName)) fail('ARTIFACT_PORTABLE_PATH_COLLISION');
      portableNames.add(portableName);
      const child = path.join(current, entry.name);
      const status = await fsp.lstat(child);
      if (status.isSymbolicLink()) fail('ARTIFACT_SYMLINK_REJECTED');
      if (status.isDirectory()) {
        await visit(child, childRelative);
      } else if (status.isFile()) {
        if (status.size > MAX_FILE_BYTES) fail('ARTIFACT_FILE_TOO_LARGE');
        output.push(Object.freeze({
          relativePath: childRelative,
          manifestPath: prefix ? `${prefix}/${childRelative}` : childRelative,
          absolutePath: child,
          status
        }));
      } else {
        fail('ARTIFACT_NON_REGULAR_FILE_REJECTED');
      }
    }
  }
  await visit(root, '');
  return output;
}

export function aggregateDigest(identity, entries) {
  const normalizedEntries = entries.map(entry => ({
    path: entry.path,
    size: entry.size,
    sha256: entry.sha256,
    ...(entry.gitObject ? { gitObject: entry.gitObject } : {})
  }));
  return sha256(JSON.stringify({ identity, files: normalizedEntries }));
}

export function assertPolicyTarget(target, code = 'CNYOS_CONTROLLER_TARGET_MISMATCH') {
  if (!isPlainObject(target)) fail(code);
  for (const [key, expected] of Object.entries(POLICY.target)) {
    if (target[key] !== expected) fail(code);
  }
}

export function deploymentMarker(runId, nonce, candidateCommit) {
  const run = required(runId, 'CNYOS_CONTROLLER_RUN_ID_INVALID', 32);
  if (!/^\d+$/.test(run)) fail('CNYOS_CONTROLLER_RUN_ID_INVALID');
  const nonceValue = decodeNonce(nonce).value;
  const commit = exactSha40(candidateCommit, 'CNYOS_CONTROLLER_CANDIDATE_COMMIT_INVALID');
  return `CNYOS-STAGING-CONTROLLER:${run}:${nonceValue}:${commit}`;
}

export function assertControllerRuntime(env, { requireActor = true } = {}) {
  const repository = required(env.GITHUB_REPOSITORY, 'CNYOS_CONTROLLER_REPOSITORY_REQUIRED', 200);
  const expectedRepository = required(
    env.CNYOS_CONTROLLER_EXPECTED_REPOSITORY,
    'CNYOS_CONTROLLER_EXPECTED_REPOSITORY_REQUIRED',
    200
  );
  if (repository !== expectedRepository || repository !== POLICY.controller.repository ||
    repository === POLICY.sourceRepository) {
    fail('CNYOS_CONTROLLER_REPOSITORY_MISMATCH');
  }
  const runId = required(env.GITHUB_RUN_ID, 'CNYOS_CONTROLLER_RUN_ID_INVALID', 32);
  if (!/^\d+$/.test(runId)) fail('CNYOS_CONTROLLER_RUN_ID_INVALID');
  if (String(env.GITHUB_RUN_ATTEMPT || '') !== '1') fail('CNYOS_CONTROLLER_RERUN_REJECTED');
  if (env.GITHUB_REF_PROTECTED !== 'true') fail('CNYOS_CONTROLLER_REF_NOT_PROTECTED');
  const expectedRef = required(env.CNYOS_CONTROLLER_PROTECTED_REF, 'CNYOS_CONTROLLER_PROTECTED_REF_REQUIRED', 300);
  if (expectedRef !== POLICY.controller.protectedRef || env.GITHUB_REF !== expectedRef) {
    fail('CNYOS_CONTROLLER_REF_MISMATCH');
  }
  const commit = exactSha40(env.GITHUB_SHA, 'CNYOS_CONTROLLER_COMMIT_INVALID');
  const workflowPath = required(
    env.CNYOS_CONTROLLER_WORKFLOW_PATH,
    'CNYOS_CONTROLLER_WORKFLOW_PATH_REQUIRED',
    300
  );
  if (!/^\.github\/workflows\/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/.test(workflowPath)) {
    fail('CNYOS_CONTROLLER_WORKFLOW_PATH_INVALID');
  }
  if (![POLICY.controller.releaseWorkflowPath, POLICY.controller.rollbackWorkflowPath]
    .includes(workflowPath)) fail('CNYOS_CONTROLLER_WORKFLOW_PATH_INVALID');
  const workflowRef = required(
    env.GITHUB_WORKFLOW_REF,
    'CNYOS_CONTROLLER_WORKFLOW_REF_REQUIRED',
    500
  );
  if (workflowRef !== `${repository}/${workflowPath}@${expectedRef}`) {
    fail('CNYOS_CONTROLLER_WORKFLOW_REF_INVALID');
  }
  let actor = null;
  if (requireActor) {
    actor = required(env.GITHUB_ACTOR, 'CNYOS_CONTROLLER_ACTOR_REQUIRED', 100);
    const triggeringActor = required(
      env.GITHUB_TRIGGERING_ACTOR,
      'CNYOS_CONTROLLER_TRIGGERING_ACTOR_REQUIRED',
      100
    );
    if (!GITHUB_LOGIN.test(actor) || !GITHUB_LOGIN.test(triggeringActor) ||
      actor.toLowerCase() !== triggeringActor.toLowerCase()) {
      fail('CNYOS_CONTROLLER_ACTOR_MISMATCH');
    }
  }
  return Object.freeze({ repository, runId, ref: expectedRef, commit, workflowPath, workflowRef, actor });
}
