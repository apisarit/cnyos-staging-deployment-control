import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  MAX_UAT_EVIDENCE_BYTES, publishUatEvidenceBytes
} from '../scripts/controller-uat-evidence-publication.mjs';

const root = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'cnyos-uat-publication-'));
const moduleUrl = new URL('../scripts/controller-uat-evidence-publication.mjs', import.meta.url).href;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
// These are IO sentinels, not successful UAT/authorization/recovery receipts.
const bytes = Buffer.from('{ "fixture": "filesystem-only", "utf8": "ไทย" }\n');
const options = directory => ({ directory, bytes, expectedSha256: hash(bytes) });
let serial = 0;
async function directory() {
  const result = path.join(root, String(++serial));
  await fs.mkdir(result, { mode: 0o700 });
  return result;
}
async function empty(dir) { assert.deepEqual(await fs.readdir(dir), []); }
async function rejects(input, code) {
  await assert.rejects(publishUatEvidenceBytes(input), { code: `CNYOS_UAT_PUBLICATION_${code}` });
}

try {
  const dir = await directory();
  const input = Buffer.from(bytes);
  const publication = publishUatEvidenceBytes({ ...options(dir), bytes: input });
  input.fill(0); // caller mutation after dispatch cannot alter the validated snapshot.
  const result = await publication;
  assert.deepEqual(result, { path: path.join(dir, 'uat.json'), sha256: hash(bytes), byteLength: bytes.length });
  assert.ok(Object.isFrozen(result));
  assert.deepEqual(await fs.readFile(result.path), bytes);
  assert.equal((await fs.stat(result.path)).mode & 0o7777, 0o600);
  assert.deepEqual(await fs.readdir(dir), ['uat.json']);
  await rejects(options(dir), 'EXISTS');
  assert.deepEqual(await fs.readFile(result.path), bytes);

  for (const bad of [Buffer.from('{'), Buffer.from('null'), Buffer.from('[]'),
    Buffer.from('1 '), Buffer.from('{}{}'), Buffer.from([0x7b, 0xff, 0x7d]),
    Buffer.from('\ufeff{}')]) {
    const target = await directory();
    await rejects({ ...options(target), bytes: bad, expectedSha256: hash(bad) },
      bad.length < 2 ? 'INPUT_INVALID' : 'JSON_INVALID');
    await empty(target);
  }
  for (const patch of [{ expectedSha256: '0'.repeat(64) }, { expectedSha256: 'A'.repeat(64) },
    { bytes: '{}' }, { bytes: Buffer.alloc(MAX_UAT_EVIDENCE_BYTES + 1) }, { bytes: Buffer.alloc(0) }]) {
    const target = await directory();
    await rejects({ ...options(target), ...patch },
      patch.expectedSha256 === '0'.repeat(64) ? 'DIGEST_MISMATCH' : 'INPUT_INVALID');
    await empty(target);
  }
  const boundary = Buffer.from('{"padding":"' + 'x'.repeat(MAX_UAT_EVIDENCE_BYTES - 14) + '"}');
  assert.equal(boundary.length, MAX_UAT_EVIDENCE_BYTES);
  const boundaryDir = await directory();
  await publishUatEvidenceBytes({ directory: boundaryDir, bytes: boundary, expectedSha256: hash(boundary) });
  assert.deepEqual(await fs.readFile(path.join(boundaryDir, 'uat.json')), boundary);

  for (const mode of [0o755, 0o770, 0o1700]) {
    const target = await directory();
    await fs.chmod(target, mode);
    await rejects(options(target), 'DIRECTORY_INVALID');
    await empty(target);
    await fs.chmod(target, 0o700);
  }
  for (const target of ['relative', '/', path.join(root, 'missing'), `${root}/../${path.basename(root)}`]) {
    await rejects(options(target), target.endsWith('/missing') ? 'FAILED' : 'DIRECTORY_INVALID');
  }
  const symlinkDir = path.join(root, 'symlink-directory');
  const actualDir = await directory();
  await fs.symlink(actualDir, symlinkDir);
  await rejects(options(symlinkDir), 'DIRECTORY_INVALID');
  await empty(actualDir);
  const symlinkParent = path.join(root, 'symlink-parent');
  await fs.symlink(root, symlinkParent);
  await rejects(options(path.join(symlinkParent, path.basename(actualDir))), 'DIRECTORY_INVALID');
  const symlinkFinalDir = await directory();
  const sentinel = path.join(root, 'sentinel');
  await fs.writeFile(sentinel, 'untouched', { flag: 'wx', mode: 0o600 });
  await fs.symlink(sentinel, path.join(symlinkFinalDir, 'uat.json'));
  await rejects(options(symlinkFinalDir), 'EXISTS');
  assert.equal(await fs.readFile(sentinel, 'utf8'), 'untouched');
  assert.ok((await fs.lstat(path.join(symlinkFinalDir, 'uat.json'))).isSymbolicLink());

  // Fault injection wraps real filesystem operations, not an injectable production writer.
  // It verifies ordering and failure aftermath without simulating a successful UAT.
  const originalOpen = fs.open;
  const originalLink = fs.link;
  for (const phase of ['success', 'partial-write', 'file-sync', 'directory-sync', 'link-after-success']) {
    const target = await directory();
    const events = [];
    fs.open = async (...args) => {
      const handle = await originalOpen(...args);
      const isDirectory = args[0] === target;
      if (!isDirectory && phase === 'partial-write') {
        handle.writeFile = async data => {
          await handle.write(data.subarray(0, 5));
          throw Error('partial write fixture');
        };
      }
      const sync = handle.sync.bind(handle);
      handle.sync = async () => {
        events.push(isDirectory ? 'directory-sync' : 'file-sync');
        if (phase === (isDirectory ? 'directory-sync' : 'file-sync')) throw Error('IO fixture');
        return sync();
      };
      return handle;
    };
    fs.link = async (...args) => {
      events.push('link');
      assert.ok(events.includes('file-sync'));
      await originalLink(...args);
      if (phase === 'link-after-success') throw Error('uncertain link fixture');
    };
    try {
      if (phase === 'success') await publishUatEvidenceBytes(options(target));
      else await rejects(options(target), ['partial-write', 'file-sync'].includes(phase) ? 'FAILED' : 'AMBIGUOUS');
    } finally { fs.open = originalOpen; fs.link = originalLink; }
    if (['partial-write', 'file-sync'].includes(phase)) {
      assert.deepEqual(events, phase === 'partial-write' ? [] : ['file-sync']);
      await empty(target);
    } else {
      assert.deepEqual(await fs.readFile(path.join(target, 'uat.json')), bytes);
      assert.deepEqual(await fs.readdir(target), ['uat.json']);
      if (['success', 'directory-sync'].includes(phase)) {
        assert.deepEqual(events, ['file-sync', 'link', 'directory-sync']);
      }
    }
  }

  // If a temp pathname is replaced, cleanup must not delete that other inode.
  const replacedDir = await directory();
  let replacedPath;
  let retainedOwnPath;
  fs.link = async (source) => {
    replacedPath = source;
    retainedOwnPath = path.join(root, 'retained-own-inode');
    await fs.rename(source, retainedOwnPath); // retain inode to preclude inode-number reuse
    await fs.writeFile(source, 'other-process-sentinel', { flag: 'wx', mode: 0o600 });
    throw Error('path replacement fixture');
  };
  try { await rejects(options(replacedDir), 'AMBIGUOUS'); }
  finally { fs.link = originalLink; }
  assert.equal(await fs.readFile(replacedPath, 'utf8'), 'other-process-sentinel');
  assert.deepEqual(await fs.readFile(retainedOwnPath), bytes);
  await assert.rejects(fs.lstat(path.join(replacedDir, 'uat.json')), { code: 'ENOENT' });

  // Two independent credential-free processes rendezvous before racing one final name.
  const racingDir = await directory();
  const childSource = `
    import { publishUatEvidenceBytes } from ${JSON.stringify(moduleUrl)};
    import { createHash } from 'node:crypto';
    const bytes = Buffer.from(JSON.stringify({ fixture: process.argv[2] }));
    process.stdout.write('ready\\n');
    process.stdin.once('data', async () => {
      try {
        await publishUatEvidenceBytes({ directory: process.argv[1], bytes,
          expectedSha256: createHash('sha256').update(bytes).digest('hex') });
        process.stdout.write('published\\n');
      } catch (error) { process.stdout.write(error.code + '\\n'); }
      process.stdin.destroy();
    });`;
  const children = ['one', 'two'].map(label => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', childSource, racingDir, label], {
      env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_ENV: 'test' },
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 15_000
    });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const ready = once(child.stdout, 'data');
    const done = once(child, 'close').then(([code, signal]) => {
      assert.equal(code, 0); assert.equal(signal, null); assert.equal(stderr, '');
      return stdout;
    });
    return { child, ready, done };
  });
  await Promise.all(children.map(child => child.ready));
  for (const { child } of children) child.stdin.write('start\n');
  const outcomes = await Promise.all(children.map(child => child.done));
  const winner = ['one', 'two'][outcomes.indexOf('ready\npublished\n')];
  assert.deepEqual([...outcomes].sort(), ['ready\nCNYOS_UAT_PUBLICATION_EXISTS\n', 'ready\npublished\n']);
  assert.deepEqual(await fs.readFile(path.join(racingDir, 'uat.json')),
    Buffer.from(JSON.stringify({ fixture: winner })));
  assert.deepEqual(await fs.readdir(racingDir), ['uat.json']);
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
process.stdout.write('CNYOS UAT evidence publication filesystem contract: passed\n');
