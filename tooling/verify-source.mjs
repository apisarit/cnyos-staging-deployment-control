import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(await readFile(path.join(root, 'provenance/source-manifest.json'), 'utf8'));
const fail = code => { throw new Error(`CNYOS_SOURCE_MANIFEST_${code}`); };
const canonical = value => typeof value === 'string' && value.length > 0 && !value.startsWith('/') && !value.includes('\\') &&
  !value.split('/').includes('') && !value.split('/').some(part => part === '.' || part === '..');
const adaptations = new Set([
  'ops/cnyos-staging-controller/tests/controller-uat-access-observations-contract.mjs',
  'ops/cnyos-staging-controller/tests/controller-uat-browser-matrix-contract.mjs',
  'ops/cnyos-staging-controller/tests/controller-uat-browser-read-policy-contract.mjs',
  'ops/cnyos-staging-controller/test-support/uat-browser-local.mjs'
]);
const candidateSources = new Set(['admin.html','admin.js','app-shell.js','appointments.html','appointments.js','chananya-runtime.js','check-in.html','check-in.js','clinical-v3.html','clinical-v3.js','foundation.html','foundation.js','index.html','outcomes.html','outcomes.js','pharmacy.html','pharmacy.js','platform-config.js','production.html','production.js','quality.html','quality.js','opd-workflow.js','scripts/staging-support.mjs','scripts/verify-authenticated-staging.mjs']);
assert.equal(manifest.activationAuthorized, false);
assert.equal(manifest.deploymentAuthorized, false);
assert.equal(manifest.humanApproval, false);
assert.equal(manifest.fileCount, manifest.files.length);
const seen = new Set();
const sourceSeen = new Set();
for (const entry of manifest.files) {
  if (!canonical(entry.path) || !entry.path.startsWith('ops/')) fail('PATH');
  if (seen.has(entry.path)) fail('DUPLICATE');
  seen.add(entry.path);
  if (!canonical(entry.sourcePath) || sourceSeen.has(entry.sourcePath) || entry.mode !== '100644' || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 ||
      !/^[a-f0-9]{64}$/.test(entry.inputSha256) || !/^[a-f0-9]{64}$/.test(entry.outputSha256)) fail('ENTRY');
  sourceSeen.add(entry.sourcePath);
  const relocated = entry.sourcePath !== entry.path;
  if (relocated && (!entry.path.startsWith('ops/cnyos-staging-controller/test-support/candidate-source/') || !candidateSources.has(entry.sourcePath))) fail('SOURCE_PATH');
  if (relocated) {
    const expected = entry.sourcePath === 'scripts/staging-support.mjs' ? 'staging-support.mjs.txt' :
      entry.sourcePath === 'scripts/verify-authenticated-staging.mjs' ? 'verify-authenticated-staging.mjs.txt' : entry.sourcePath;
    if (entry.path !== `ops/cnyos-staging-controller/test-support/candidate-source/${expected}`) fail('SOURCE_PATH');
  }
  if (!relocated && entry.sourcePath !== entry.path) fail('SOURCE_PATH');
  if (entry.adaptation !== undefined && entry.adaptation !== 'path-only') fail('ADAPTATION');
  if (entry.adaptation === 'path-only' && !adaptations.has(entry.path)) fail('ADAPTATION');
  if (entry.inputSha256 !== entry.outputSha256 && entry.adaptation !== 'path-only') fail('TRANSFORM');
  for (const key of ['inputBytes', 'outputBytes']) {
    if (!Number.isSafeInteger(entry[key]) || entry[key] < 0) fail('ENTRY');
  }
  if (entry.outputBytes !== entry.bytes) fail('ENTRY');
}
async function walk(dir, relative = '') {
  const out = [];
  for (const name of await readdir(dir)) {
    const rel = relative ? `${relative}/${name}` : name;
    const stat = await lstat(path.join(dir, name));
    if (stat.isSymbolicLink()) fail('SYMLINK');
    if (stat.isDirectory()) out.push(...await walk(path.join(dir, name), rel));
    else if (stat.isFile()) out.push(`ops/${rel}`);
    else fail('NONREGULAR');
  }
  return out;
}
const opsRoot = path.join(root, 'ops');
const rootStat = await lstat(opsRoot);
if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail('ROOT');
if (JSON.stringify((await walk(opsRoot)).sort()) !== JSON.stringify([...seen].sort())) fail('TREE');

for (const entry of manifest.files) {
  const bytes = await readFile(path.join(root, entry.path));
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (bytes.length !== entry.outputBytes || sha256 !== entry.outputSha256) fail('HASH');
  if (!entry.adaptation) assert.equal(sha256, entry.inputSha256, entry.path);
}

console.log(`CNYOS inert offline source: ${manifest.fileCount} hashes verified; activation remains blocked`);
