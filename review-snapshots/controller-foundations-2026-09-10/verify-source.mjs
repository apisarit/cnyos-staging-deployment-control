import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Integrity check only; this is not a signature or release authorization.
const root = path.dirname(fileURLToPath(import.meta.url));
const digest = data => createHash('sha256').update(data).digest('hex');
const raw = await fs.readFile(path.join(root, 'source-manifest.json'));
assert.equal(digest(raw), '0dd9e8b98a4d67ff10f1b759a31ec0e8cea2a57981505eaa57ac5f29878f4e56');
const manifest = JSON.parse(raw);
const actual = [];
async function walk(relative = '') {
  const base = path.join(root, 'source', relative);
  assert.equal((await fs.lstat(base)).isDirectory(), true);
  for (const entry of await fs.readdir(base, { withFileTypes: true })) {
    const next = relative ? `${relative}/${entry.name}` : entry.name;
    assert.equal(entry.isSymbolicLink(), false, next);
    if (entry.isDirectory()) await walk(next);
    else {
      assert.equal(entry.isFile(), true, next);
      actual.push(next);
    }
  }
}
await walk();
assert.deepEqual(actual.sort(), manifest.files.map(file => file.path).sort());
let total = 0;
for (const file of manifest.files) {
  assert.match(file.path, /^[a-zA-Z0-9_./-]+$/);
  assert.equal(file.path.split('/').some(part => !part || part === '.' || part === '..'), false);
  const bytes = await fs.readFile(path.join(root, 'source', file.path));
  assert.equal(bytes.length, file.bytes, file.path);
  assert.equal(digest(bytes), file.sha256, file.path);
  total += bytes.length;
}
assert.equal(manifest.fileCount, 96);
assert.equal(actual.length, manifest.fileCount);
assert.equal(total, manifest.totalBytes);
assert.equal(manifest.activationAuthorized, false);
assert.equal(manifest.authenticatedStagingVerified, false);
assert.equal(manifest.independentSecurityApproval, false);
assert.equal(manifest.productionAuthorization, false);
console.log('CNYOS inert review snapshot: 96 source hashes verified; activation remains blocked');
