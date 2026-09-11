import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, writeFile, symlink, rm, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const verifier = path.join(sourceRoot, 'tooling/verify-source.mjs');
const tempRoot = await mkdtemp(path.join(tmpdir(), 'cnyos-source-contract-'));
try {
  const copy = async () => { const dir = path.join(tempRoot, `case-${Date.now()}-${Math.random()}`); await cp(sourceRoot, dir, { recursive: true }); return dir; };
const run = dir => spawnSync(process.execPath, [path.join(dir, 'tooling/verify-source.mjs')], { cwd: dir, encoding: 'utf8' });
const expectFailure = result => { assert.notEqual(result.status, 0); assert.match(result.stderr, /CNYOS_SOURCE_MANIFEST_/); };
  assert.equal(run(sourceRoot).status, 0);
  const tampered = await copy(); await writeFile(path.join(tampered, 'ops/cnyos-staging-controller/controller-policy.json'), 'tampered'); expectFailure(run(tampered));
  const missing = await copy(); await rm(path.join(missing, 'ops/cnyos-staging-controller/controller-policy.json')); expectFailure(run(missing));
  const leaf = await copy(); await rm(path.join(leaf, 'ops/cnyos-staging-controller/controller-policy.json')); await symlink('README.md', path.join(leaf, 'ops/cnyos-staging-controller/controller-policy.json')); expectFailure(run(leaf));
  const parent = await copy(); const parentDir = path.join(parent, 'ops/cnyos-staging-controller'); const moved = path.join(parent, 'moved-controller'); await rename(parentDir, moved); await symlink('../moved-controller', parentDir); expectFailure(run(parent));
  const rootLink = await copy(); const opsDir = path.join(rootLink, 'ops'); await rename(opsDir, path.join(rootLink, 'moved-ops')); await symlink('moved-ops', opsDir); expectFailure(run(rootLink));
  const added = await copy(); await writeFile(path.join(added, 'ops/unlisted.txt'), 'unexpected'); expectFailure(run(added));
  const unsafe = await copy(); const manifestPath = path.join(unsafe, 'provenance/source-manifest.json'); const manifest = JSON.parse(await readFile(manifestPath, 'utf8')); manifest.files[0].path = '../escape'; await writeFile(manifestPath, JSON.stringify(manifest)); expectFailure(run(unsafe));
  const duplicate = await copy(); const duplicateManifestPath = path.join(duplicate, 'provenance/source-manifest.json'); const duplicateManifest = JSON.parse(await readFile(duplicateManifestPath, 'utf8')); duplicateManifest.files.push({ ...duplicateManifest.files[0] }); duplicateManifest.fileCount = duplicateManifest.files.length; await writeFile(duplicateManifestPath, JSON.stringify(duplicateManifest)); expectFailure(run(duplicate));
  console.log('CNYOS source verifier adversarial contract: passed');
} finally { await rm(tempRoot, { recursive: true, force: true }); }
