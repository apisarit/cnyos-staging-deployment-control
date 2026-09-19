import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { writeBytesExclusive, writeJsonExclusive } from '../scripts/policy.mjs';

const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-evidence-'));
const destination = path.join(root, 'nested', 'evidence.json');
const bytes = Buffer.from('{"ok":true}\n');

try {
  assert.equal(await writeBytesExclusive(destination, bytes), destination);
  assert.deepEqual(await fs.readFile(destination), bytes);
  assert.equal((await fs.stat(destination)).mode & 0o777, 0o600);

  await assert.rejects(writeBytesExclusive(destination, Buffer.from('different')), error =>
    error.code === 'EEXIST');
  assert.deepEqual(await fs.readFile(destination), bytes);

  const symlink = path.join(root, 'symlink');
  const sentinel = path.join(root, 'sentinel');
  await fs.writeFile(sentinel, 'untouched');
  await fs.symlink(sentinel, symlink);
  await assert.rejects(writeBytesExclusive(symlink, bytes), error => error.code === 'EEXIST');
  assert.equal(await fs.readFile(sentinel, 'utf8'), 'untouched');

  const directory = path.join(root, 'directory');
  await fs.mkdir(directory);
  await assert.rejects(writeBytesExclusive(directory, bytes), error => error.code === 'EEXIST');

  const json = path.join(root, 'legacy.json');
  await writeJsonExclusive(json, { b: 2, a: [1, true] });
  assert.equal(await fs.readFile(json, 'utf8'), '{\n  "b": 2,\n  "a": [\n    1,\n    true\n  ]\n}\n');
  const invalid = path.join(root, 'invalid.json');
  const circular = {}; circular.self = circular;
  await assert.rejects(writeJsonExclusive(invalid, circular));
  await assert.rejects(fs.lstat(invalid), error => error.code === 'ENOENT');

  const reconciler = await import('../scripts/reconcile-netlify-release-state.mjs');
  assert.equal(typeof reconciler.reconcileNetlifyReleaseState, 'function');
  const source = await fs.readFile(fileURLToPath(new URL('../scripts/reconcile-netlify-release-state.mjs', import.meta.url)), 'utf8');
  assert.match(source, /writeBytesExclusiveSafe\(required\(filename/);

  // Snapshot caller data before the first await; these are inert filesystem
  // fixtures, not successful recovery or authorization records.
  const snapshotBufferPath = path.join(root, 'snapshot-buffer.json');
  const snapshotBuffer = Buffer.from('{"buffer":true}\n');
  const snapshotBufferPublication = writeBytesExclusive(snapshotBufferPath, snapshotBuffer);
  snapshotBuffer.fill(0x78);
  await snapshotBufferPublication;
  assert.deepEqual(await fs.readFile(snapshotBufferPath), Buffer.from('{"buffer":true}\n'));
  const snapshotJsonPath = path.join(root, 'snapshot-json.json');
  const snapshotValue = { fixture: 'before-await', nested: { ok: true } };
  const snapshotJsonPublication = writeJsonExclusive(snapshotJsonPath, snapshotValue);
  snapshotValue.fixture = 'mutated-after-dispatch'; snapshotValue.nested.ok = false;
  await snapshotJsonPublication;
  assert.equal(await fs.readFile(snapshotJsonPath, 'utf8'),
    '{\n  "fixture": "before-await",\n  "nested": {\n    "ok": true\n  }\n}\n');

  // Partial write and file-sync failures leave no final or owned temp; retry works.
  for (const phase of ['partial-write', 'file-sync']) {
    const target = path.join(root, `retry-${phase}.json`);
    const originalOpen = fs.open;
    fs.open = async (...args) => {
      const handle = await originalOpen(...args);
      const isDirectory = args[0] === path.dirname(target);
      if (!isDirectory && phase === 'partial-write') {
        handle.write = async data => {
          await handle.writeFile(data.subarray(0, Math.max(1, data.length - 1)));
          throw new Error('partial-write fixture');
        };
      }
      if (!isDirectory && phase === 'file-sync') handle.sync = async () => {
        throw new Error('file-sync fixture');
      };
      return handle;
    };
    try { await assert.rejects(writeBytesExclusive(target, Buffer.from('{"retry":true}\n'))); }
    finally { fs.open = originalOpen; }
    await assert.rejects(fs.lstat(target), { code: 'ENOENT' });
    assert.deepEqual((await fs.readdir(root)).filter(name => name.includes(path.basename(target))), []);
    await writeBytesExclusive(target, Buffer.from('{"retry":true}\n'));
    assert.deepEqual(await fs.readFile(target), Buffer.from('{"retry":true}\n'));
  }

  // Post-link uncertainty retains a complete final and reports AMBIGUOUS.
  for (const phase of ['link-after-success', 'directory-sync-after-link']) {
    const target = path.join(root, `${phase}.json`);
    const originalLink = fs.link;
    const originalOpen = fs.open;
    fs.link = async (...args) => {
      await originalLink(...args);
      if (phase === 'link-after-success') throw new Error('link uncertainty fixture');
    };
    fs.open = async (...args) => {
      const handle = await originalOpen(...args);
      if (args[0] === path.dirname(target)) handle.sync = async () => {
        throw new Error('directory sync uncertainty fixture');
      };
      return handle;
    };
    try {
      await assert.rejects(writeBytesExclusive(target, Buffer.from('{"complete":true}\n')),
        error => error.code === 'CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_AMBIGUOUS');
    } finally { fs.link = originalLink; fs.open = originalOpen; }
    assert.deepEqual(await fs.readFile(target), Buffer.from('{"complete":true}\n'));
  }

  // If link reports an error and the final-name probe is EIO, never overwrite.
  const probeEioTarget = path.join(root, 'probe-eio.json');
  const originalLink = fs.link;
  const originalLstat = fs.lstat;
  fs.link = async (...args) => { await originalLink(...args); throw new Error('link committed'); };
  fs.lstat = async (...args) => {
    if (args[0] === probeEioTarget) { const error = new Error('probe EIO'); error.code = 'EIO'; throw error; }
    return originalLstat(...args);
  };
  try {
    await assert.rejects(writeBytesExclusive(probeEioTarget, Buffer.from('{"probe":true}\n')),
      error => error.code === 'CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_AMBIGUOUS');
  } finally { fs.link = originalLink; fs.lstat = originalLstat; }

  // Existing zero/truncated finals remain byte-exact and return EEXIST.
  for (const [label, existing] of [['zero', Buffer.alloc(0)], ['truncated', Buffer.from('{"')]]) {
    const target = path.join(root, `existing-${label}.json`);
    await fs.writeFile(target, existing, { flag: 'wx', mode: 0o600 });
    await assert.rejects(writeBytesExclusive(target, Buffer.from('{"replacement":true}\n')),
      error => error.code === 'EEXIST');
    assert.deepEqual(await fs.readFile(target), existing);
  }

  // Existing 0755 parent permissions remain unchanged; final is 0600.
  const inheritedParent = path.join(root, 'inherited-parent');
  await fs.mkdir(inheritedParent, { mode: 0o755 }); await fs.chmod(inheritedParent, 0o755);
  const inheritedTarget = path.join(inheritedParent, 'final.json');
  await writeBytesExclusive(inheritedTarget, Buffer.from('{"mode":true}\n'));
  assert.equal((await fs.stat(inheritedParent)).mode & 0o777, 0o755);
  assert.equal((await fs.stat(inheritedTarget)).mode & 0o777, 0o600);

  // Kill a real helper while its temp-file write is blocked after a partial
  // write. The helper's own orphan must remain untouched by a fresh retry.
  const interruptedDir = path.join(root, 'interrupted'); await fs.mkdir(interruptedDir, { mode: 0o700 });
  const interruptedTarget = path.join(interruptedDir, 'final.json');
  const interruptedChild = spawn(process.execPath, ['--input-type=module', '-e', `
    import fs from 'node:fs/promises';
    import { writeBytesExclusive } from ${JSON.stringify(fileURLToPath(new URL('../scripts/policy.mjs', import.meta.url)))};
    const originalOpen = fs.open;
    fs.open = async (...args) => {
      const handle = await originalOpen(...args);
      if (typeof args[0] === 'string' && args[0].includes('.final.json.')) {
        handle.write = async data => {
          await handle.writeFile(data.subarray(0, Math.max(1, data.length - 1)));
          process.stdout.write('paused\\n');
          await new Promise(resolve => process.stdin.once('data', resolve));
          await new Promise(() => {});
        };
      }
      return handle;
    };
    await writeBytesExclusive(process.argv[1], Buffer.from('{"partial":true}\\n'));
  `, interruptedTarget], { stdio: ['pipe', 'pipe', 'pipe'],
    env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_ENV: 'test' } });
  let interruptedSpawnError;
  interruptedChild.on('error', error => { interruptedSpawnError = error; });
  const interruptedError = new Promise(resolve => interruptedChild.once('error', resolve));
  const interruptedDone = new Promise(resolve => interruptedChild.once('close',
    (code, signal) => resolve([code, signal])));
  let interruptedClosed = false;
  const timeout = (label, milliseconds = 8000) => {
    let timer;
    const promise = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timeout`)), milliseconds);
    });
    return { promise, cancel: () => clearTimeout(timer) };
  };
  const withTimeout = async (promise, label, milliseconds = 8000) => {
    const guard = timeout(label, milliseconds);
    try { return await Promise.race([promise, guard.promise]); }
    finally { guard.cancel(); }
  };
  try {
    const readiness = Promise.race([
      once(interruptedChild.stdout, 'data'),
      interruptedError.then(error => { throw error; })
    ]);
    const [pauseChunk] = await withTimeout(readiness, 'interruption readiness');
    assert.match(String(pauseChunk), /paused/);
    interruptedChild.kill('SIGKILL');
    const [childCode, childSignal] = await withTimeout(interruptedDone, 'interruption reap');
    interruptedClosed = true;
    assert.equal(interruptedSpawnError, undefined);
    assert.equal(childCode, null); assert.equal(childSignal, 'SIGKILL');
  } finally {
    if (!interruptedClosed && interruptedChild.pid && interruptedChild.exitCode === null && interruptedChild.signalCode === null) {
      interruptedChild.kill('SIGKILL');
    }
    if (!interruptedClosed) await withTimeout(interruptedDone, 'interruption cleanup');
  }
  await assert.rejects(fs.lstat(interruptedTarget), { code: 'ENOENT' });
  const orphanNames = (await fs.readdir(interruptedDir)).filter(name => name !== 'final.json');
  assert.equal(orphanNames.length, 1);
  const orphan = path.join(interruptedDir, orphanNames[0]);
  const orphanBytes = await fs.readFile(orphan);
  const orphanBefore = await fs.stat(orphan, { bigint: true });
  assert.ok(orphanBytes.length < Buffer.byteLength('{"partial":true}\n'));
  await writeBytesExclusive(interruptedTarget, Buffer.from('{"fresh":true}\n'));
  assert.deepEqual(await fs.readFile(interruptedTarget), Buffer.from('{"fresh":true}\n'));
  assert.deepEqual(await fs.readFile(orphan), orphanBytes);
  const orphanAfter = await fs.stat(orphan, { bigint: true });
  assert.equal(orphanAfter.dev, orphanBefore.dev);
  assert.equal(orphanAfter.ino, orphanBefore.ino);

  // If a temp pathname is replaced by another inode, cleanup must not unlink it.
  const foreignTarget = path.join(root, 'foreign-replacement.json');
  const foreignLink = fs.link;
  let foreignPath;
  const retainedOwn = path.join(root, 'retained-own-temp');
  fs.link = async source => {
    foreignPath = source;
    await fs.rename(source, retainedOwn);
    await fs.writeFile(source, 'foreign-temp-sentinel', { flag: 'wx', mode: 0o600 });
    throw new Error('foreign replacement fixture');
  };
  try {
    await assert.rejects(writeBytesExclusive(foreignTarget, Buffer.from('{"foreign":true}\n')),
      error => error.code === 'CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_AMBIGUOUS');
  } finally { fs.link = foreignLink; }
  assert.equal(await fs.readFile(foreignPath, 'utf8'), 'foreign-temp-sentinel');
  assert.deepEqual(await fs.readFile(retainedOwn), Buffer.from('{"foreign":true}\n'));

  // Once publication is uncertain, a cleanup failure must not replace AMBIGUOUS.
  const chainedTarget = path.join(root, 'chained-uncertainty.json');
  const chainedLink = fs.link;
  const chainedUnlink = fs.unlink;
  fs.link = async (...args) => { await chainedLink(...args); throw new Error('unknown post-commit error'); };
  fs.unlink = async filename => {
    if (String(filename).includes(`.${path.basename(chainedTarget)}.`)) {
      throw new Error('owned-temp cleanup error');
    }
    return chainedUnlink(filename);
  };
  try {
    await assert.rejects(writeBytesExclusive(chainedTarget, Buffer.from('{"chained":true}\n')),
      error => error.code === 'CNYOS_CONTROLLER_EVIDENCE_PUBLICATION_AMBIGUOUS');
  } finally { fs.link = chainedLink; fs.unlink = chainedUnlink; }
  assert.deepEqual(await fs.readFile(chainedTarget), Buffer.from('{"chained":true}\n'));

  // Two independent child writers race on one final name: exactly one wins.
  const raceDir = path.join(root, 'child-race'); await fs.mkdir(raceDir, { mode: 0o700 });
  const raceSource = `
    import { writeBytesExclusive } from ${JSON.stringify(fileURLToPath(new URL('../scripts/policy.mjs', import.meta.url)))};
    const bytes = Buffer.from(JSON.stringify({ fixture: process.argv[2] }));
    process.stdout.write('ready\\n'); process.stdin.once('data', async () => {
      try { await writeBytesExclusive(process.argv[1], bytes); process.stdout.write('published\\n'); }
      catch (error) { process.stdout.write(error.code + '\\n'); } process.stdin.destroy();
    });`;
  const racers = ['one', 'two'].map(label => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', raceSource,
      path.join(raceDir, 'final.json'), label], {
      env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_ENV: 'test' }, stdio: ['pipe', 'pipe', 'pipe']
    });
    let spawnError;
    child.on('error', error => { spawnError = error; });
    const error = new Promise(resolve => child.once('error', resolve));
    let stdout = ''; let stderr = ''; child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const ready = Promise.race([once(child.stdout, 'data'), error.then(value => { throw value; })]);
    const closed = new Promise(resolve => child.once('close',
      (code, signal) => resolve([code, signal])));
    const done = closed.then(([code, signal]) => {
      assert.equal(spawnError, undefined);
      assert.equal(code, 0); assert.equal(signal, null); assert.equal(stderr, ''); return stdout;
    });
    // Install an observer before readiness can fail and kill this child; retain
    // the original rejecting promise so the normal reap path still asserts.
    done.catch(() => {});
    return { child, ready, closed, done };
  });
  try {
    await withTimeout(Promise.all(racers.map(racer => racer.ready)), 'race readiness');
    racers.forEach(racer => racer.child.stdin.write('go\n'));
  } catch (error) {
    racers.forEach(racer => {
      if (racer.child.pid && racer.child.exitCode === null && racer.child.signalCode === null) racer.child.kill('SIGKILL');
    });
    await withTimeout(Promise.all(racers.map(racer => racer.closed)), 'race cleanup');
    throw error;
  }
  let outcomes;
  try {
    outcomes = await withTimeout(Promise.all(racers.map(racer => racer.done)), 'race reap');
  } catch (error) {
    racers.forEach(racer => {
      if (racer.child.pid && racer.child.exitCode === null && racer.child.signalCode === null) racer.child.kill('SIGKILL');
    });
    await withTimeout(Promise.all(racers.map(racer => racer.closed)), 'race cleanup');
    throw error;
  }
  assert.deepEqual([...outcomes].sort(), ['ready\nEEXIST\n', 'ready\npublished\n']);
  assert.deepEqual((await fs.readdir(raceDir)), ['final.json']);
  const raceFinalBytes = await fs.readFile(path.join(raceDir, 'final.json'));
  assert.ok([
    Buffer.from(JSON.stringify({ fixture: 'one' })),
    Buffer.from(JSON.stringify({ fixture: 'two' }))
  ].some(candidate => candidate.equals(raceFinalBytes)));
} finally {
  await fs.rm(root, { recursive: true, force: true });
}

process.stdout.write('CNYOS evidence publication contract: passed\n');
