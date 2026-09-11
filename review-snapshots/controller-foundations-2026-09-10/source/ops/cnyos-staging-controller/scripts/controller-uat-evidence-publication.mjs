import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';

export const MAX_UAT_EVIDENCE_BYTES = 4 * 1024 * 1024;
const PREFIX = 'CNYOS_UAT_PUBLICATION_';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const failure = suffix => Object.assign(new Error(PREFIX + suffix), { code: PREFIX + suffix });
const sameInode = (a, b) => a.dev === b.dev && a.ino === b.ino;
const privateDirectory = stat => stat.isDirectory() &&
  stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o700;

// Filesystem integrity ONLY: neither JSON parsing nor the expected digest authenticates
// UAT observations. The future trusted harness must validate their schema/provenance.
// This helper is intentionally not wired into the nine-gate UAT entrypoint/finalizer.
// Requires a trusted, pre-existing canonical 0700 directory and trusted ancestors on
// a local filesystem supporting hard links + directory fsync. It does not defend
// against a hostile same-UID/admin process swapping paths between Node path syscalls.
// Never retry AMBIGUOUS automatically: final may exist; retain it for reconciliation.
export async function publishUatEvidenceBytes({ directory, bytes, expectedSha256 }) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_UAT_EVIDENCE_BYTES ||
    typeof expectedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expectedSha256)) {
    throw failure('INPUT_INVALID');
  }
  const snapshot = Buffer.from(bytes); // Snapshot before the first asynchronous boundary.
  if (digest(snapshot) !== expectedSha256) throw failure('DIGEST_MISMATCH');
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(snapshot);
    const value = JSON.parse(text);
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw Error();
  } catch { throw failure('JSON_INVALID'); }
  if (typeof directory !== 'string' || !path.isAbsolute(directory) ||
    path.resolve(directory) !== directory || directory === path.parse(directory).root ||
    typeof process.getuid !== 'function' || !constants.O_NOFOLLOW || !constants.O_DIRECTORY) {
    throw failure('DIRECTORY_INVALID');
  }

  const finalPath = path.join(directory, 'uat.json'); // Caller cannot select/traverse a basename.
  const tempPath = path.join(directory, `.uat.${randomBytes(16).toString('hex')}.tmp`);
  let dirHandle;
  let tempHandle;
  let identity;
  let tempIdentity;
  let linked = false;
  let linkAttempted = false;
  let resultError;
  async function verifyDirectory() {
    const current = await fs.lstat(directory);
    if (!privateDirectory(current) || !sameInode(current, identity) ||
      !sameInode(await dirHandle.stat(), identity) || await fs.realpath(directory) !== directory) {
      throw failure('DIRECTORY_CHANGED');
    }
  }
  async function cleanupOwnTemp() {
    if (!tempIdentity) return;
    await verifyDirectory();
    let current;
    try { current = await fs.lstat(tempPath); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (!current.isFile() || !sameInode(current, tempIdentity)) throw failure('TEMP_CHANGED');
    await fs.unlink(tempPath);
    tempIdentity = undefined;
  }
  try {
    identity = await fs.lstat(directory);
    if (!privateDirectory(identity) || await fs.realpath(directory) !== directory) {
      throw failure('DIRECTORY_INVALID');
    }
    dirHandle = await fs.open(directory, constants.O_RDONLY | constants.O_DIRECTORY |
      constants.O_NOFOLLOW);
    await verifyDirectory();
    tempHandle = await fs.open(tempPath, constants.O_RDWR | constants.O_CREAT |
      constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    tempIdentity = await tempHandle.stat();
    if (!tempIdentity.isFile() || tempIdentity.uid !== process.getuid() ||
      (tempIdentity.mode & 0o7777) !== 0o600 || tempIdentity.nlink !== 1) {
      throw failure('TEMP_INVALID');
    }
    await tempHandle.writeFile(snapshot);
    await tempHandle.sync();
    const written = await tempHandle.stat();
    const readback = Buffer.alloc(snapshot.length);
    let offset = 0;
    while (offset < readback.length) {
      const { bytesRead } = await tempHandle.read(readback, offset, readback.length - offset, offset);
      if (bytesRead === 0) throw failure('TEMP_INVALID');
      offset += bytesRead;
    }
    if (!sameInode(written, tempIdentity) || written.size !== snapshot.length ||
      digest(readback) !== expectedSha256) throw failure('TEMP_INVALID');
    await tempHandle.close();
    tempHandle = undefined;
    await verifyDirectory();
    const ready = await fs.lstat(tempPath);
    if (!ready.isFile() || !sameInode(ready, tempIdentity) || ready.nlink !== 1 ||
      (ready.mode & 0o7777) !== 0o600) throw failure('TEMP_CHANGED');
    linkAttempted = true;
    await fs.link(tempPath, finalPath); // Atomic no-replace; never rename or remove final.
    linked = true;
    await verifyDirectory();
    const final = await fs.lstat(finalPath);
    if (!final.isFile() || !sameInode(final, tempIdentity) ||
      final.size !== snapshot.length || (final.mode & 0o7777) !== 0o600) throw failure('FINAL_INVALID');
    await cleanupOwnTemp();
    await dirHandle.sync(); // Persist the final link and temporary-name removal before success.
  } catch (error) {
    resultError = linked || (linkAttempted && error.code !== 'EEXIST') ? failure('AMBIGUOUS') :
      error.code === 'EEXIST' ? failure('EXISTS') :
        String(error.code || '').startsWith(PREFIX) ? error : failure('FAILED');
  } finally {
    try { await tempHandle?.close(); await cleanupOwnTemp(); }
    catch { resultError = failure(linkAttempted ? 'AMBIGUOUS' : 'CLEANUP_FAILED'); }
    try { await dirHandle?.close(); }
    catch { resultError = failure(linkAttempted ? 'AMBIGUOUS' : 'FAILED'); }
  }
  if (resultError) throw resultError;
  return Object.freeze({ path: finalPath, sha256: expectedSha256, byteLength: snapshot.length });
}
