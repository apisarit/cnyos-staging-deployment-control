import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import zlib from 'node:zlib';
import { AdapterError, ARTIFACT_NAME, createGitHubClient, extractTarGzip, readZipExact, validateReleaseRequest, verifyCandidate, sha256 } from '../broker/adapters/common.mjs';
import { deployStaging } from '../broker/adapters/deployer-lib.mjs';

function crc32(data) { let crc = 0xffffffff; for (const byte of data) { crc ^= byte; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0); } return (crc ^ 0xffffffff) >>> 0; }
function zip(files) {
  files = [...files];
  const locals = []; const centrals = []; let offset = 0;
  for (const [name, data] of files) {
    const n = Buffer.from(name); const crc = crc32(data); const local = Buffer.alloc(30 + n.length); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(0, 8); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(n.length, 26); n.copy(local, 30); locals.push(Buffer.concat([local, data]));
    const central = Buffer.alloc(46 + n.length); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0, 8); central.writeUInt16LE(0, 10); central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(n.length, 28); central.writeUInt32LE(0x81a40000, 38); central.writeUInt32LE(offset, 42); n.copy(central, 46); centrals.push(central); offset += locals.at(-1).length;
  }
  const localBytes = Buffer.concat(locals); const centralBytes = Buffer.concat(centrals); const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(centralBytes.length, 12); end.writeUInt32LE(localBytes.length, 16); return Buffer.concat([localBytes, centralBytes, end]);
}
function tar(files) {
  const chunks = [];
  for (const [name, data] of files) { const h = Buffer.alloc(512); Buffer.from(`./${name}`).copy(h, 0); Buffer.from('0000644\0').copy(h, 100); Buffer.from('0000000\0').copy(h, 108); Buffer.from('0000000\0').copy(h, 116); Buffer.from(data.length.toString(8).padStart(11, '0') + '\0').copy(h, 124); Buffer.from('00000000000\0').copy(h, 136); h[156] = 48; Buffer.from('ustar\0').copy(h, 257); Buffer.from('00').copy(h, 263); h.fill(32, 148, 156); const sum = [...h].reduce((a, b) => a + b, 0); Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(h, 148); chunks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512)); }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}

const commit = 'a'.repeat(40); const archiveName = `cnyos-static-${commit}.tar.gz`; const archive = Buffer.from('archive'); const release = Buffer.from(JSON.stringify({ schemaVersion: 1, kind: 'cnyos_vps_staging_candidate', authorization: false, productionEligible: false, source: { repository: 'apisarit/chananya-clinical-wellness-os', commit, tree: 'e'.repeat(40) }, workflow: { runId: 42, runAttempt: 1 }, artifact: { file: archiveName, sha256: sha256(archive) }, runtimeManifestSha256: '1'.repeat(64), deployManifestSha256: '2'.repeat(64), note: 'Build evidence only. A protected controller must authorize and deploy this exact packet.' }));
const sums = Buffer.from(`${sha256(archive)}  ${archiveName}\n${sha256(release)}  release-request.json\n`);
const files = new Map([[archiveName, archive], ['release-request.json', release], ['SHA256SUMS', sums]]); const candidate = { source_commit: commit, producer_run_id: 42, artifact_id: 7, archive_sha256: sha256(archive), release_request_sha256: sha256(release) }; const producer = { repository: 'apisarit/chananya-clinical-wellness-os' };
assert.deepEqual([...readZipExact(zip(files), [archiveName, 'release-request.json', 'SHA256SUMS']).keys()], [...files.keys()]);
assert.throws(() => readZipExact(zip([...files, ['extra', Buffer.from('x')]]), [archiveName, 'release-request.json', 'SHA256SUMS']), /ZIP_STRUCTURE_INVALID|ZIP_FILESET_INVALID/);
assert.throws(() => readZipExact(zip([['../evil', Buffer.from('x')]]), ['../evil']), /ZIP_ENTRY_UNSAFE/);
assert.deepEqual([...extractTarGzip(zlib.gzipSync(tar([['index.html', Buffer.from('ok')], ['runtime-publish-manifest.json', Buffer.from('{}')]]))).keys()], ['index.html', 'runtime-publish-manifest.json']);
assert.doesNotThrow(() => validateReleaseRequest(files, candidate, producer));
assert.throws(() => validateReleaseRequest(new Map([...files, ['SHA256SUMS', Buffer.from(`${'0'.repeat(64)}  ${archiveName}\n${sha256(release)}  release-request.json\n`)]]), candidate, producer), /RELEASE_DIGEST_MISMATCH/);

const body = { environment: 'staging', controller: { repository: 'apisarit/cnyos-staging-deployment-control', repository_id: 1362863285, ref: 'refs/heads/main', ref_protected: true, workflow: 'Admit VPS staging release', workflow_ref: 'apisarit/cnyos-staging-deployment-control/.github/workflows/admit-vps-staging-release.yml@refs/heads/main', run_id: 99, run_attempt: 1, workflow_sha: 'b'.repeat(40), actor: 'apisarit', actor_id: 216305243, triggering_actor: 'apisarit' }, producer: { repository: 'apisarit/chananya-clinical-wellness-os', ref: 'refs/heads/main', workflow_file: 'deploy-vps-staging.yml' }, candidate };
const responses = { repo: { full_name: body.controller.repository, private: true, id: 1362863285, default_branch: 'main' }, branch: { protected: true }, protection: { enforce_admins: { enabled: true }, required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: true }, required_status_checks: {}, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false } }, controllerRun: { id: 99, head_sha: 'b'.repeat(40), path: '.github/workflows/admit-vps-staging-release.yml', head_branch: 'main', event: 'workflow_dispatch', actor: { id: 216305243, login: 'apisarit' }, status: 'in_progress' }, producerRepo: { id: 1318182797, full_name: producer.repository, default_branch: 'main', visibility: 'public', private: false }, producerRun: { id: 42, head_sha: commit, head_branch: 'main', path: '.github/workflows/deploy-vps-staging.yml', status: 'completed', conclusion: 'success' }, artifact: { id: 7, name: ARTIFACT_NAME(commit, 42), expired: false, size_in_bytes: 3, workflow_run: { id: 42 } } };
const client = { repo: repo => repo === body.controller.repository ? responses.repo : responses.producerRepo, branch: async () => responses.branch, protection: async () => responses.protection, run: async (repo, id) => repo === body.controller.repository && id === 99 ? responses.controllerRun : responses.producerRun, artifact: async () => responses.artifact };
assert.deepEqual((await verifyCandidate(body, client, { workflowShaPin: 'b'.repeat(40) })).ok, true);
await assert.rejects(() => verifyCandidate(body, client), /CONTROLLER_WORKFLOW_PIN_MISMATCH/);
await assert.rejects(() => verifyCandidate(body, client, { workflowShaPin: 'c'.repeat(40) }), /CONTROLLER_WORKFLOW_PIN_MISMATCH/);
await assert.rejects(() => verifyCandidate(body, { ...client, artifact: async () => ({ ...responses.artifact, expired: true }) }, { workflowShaPin: 'b'.repeat(40) }), /ARTIFACT_METADATA_INVALID/);
assert.deepEqual((await verifyCandidate(body, { ...client, branch: async () => { throw new Error('plan limitation'); }, protection: async () => { throw new Error('plan limitation'); } }, { workflowShaPin: 'b'.repeat(40) })).branchProtectionObserved, false);
assert.equal(await createGitHubClient({ token: 'fixture', requestImpl: async url => ({ url }), downloadImpl: async () => Buffer.alloc(0) }).repo('apisarit/ok').then(x => x.url), 'https://api.github.com/repos/apisarit/ok');

const deployRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-deployer-root-'));
const deploySpoolRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-deployer-spool-'));
const deploySpool = await fs.mkdtemp(path.join(deploySpoolRoot, 'candidate-'));
const tree = 'f'.repeat(40);
const indexBytes = Buffer.from('<!doctype html><title>CNYOS staging</title>');
const deployManifestBytes = Buffer.from(JSON.stringify({
  source: { commit, tree, verified: true },
  build: { context: 'production', deploymentClass: 'dedicated-staging' },
  safety: { previewLocked: false, databaseLocked: false, stagingDatabaseExplicitlyAcknowledged: true },
}));
const runtimeFiles = ['index.html', 'deploy-manifest.json'];
const runtimeManifestBytes = Buffer.from(JSON.stringify({
  schemaVersion: 2,
  integrityAlgorithm: 'sha256',
  fileCount: runtimeFiles.length,
  files: runtimeFiles,
  integrity: [
    { path: 'index.html', size: indexBytes.length, sha256: sha256(indexBytes) },
    { path: 'deploy-manifest.json', size: deployManifestBytes.length, sha256: sha256(deployManifestBytes) },
  ],
}));
const staticArchive = zlib.gzipSync(tar([
  ['index.html', indexBytes],
  ['deploy-manifest.json', deployManifestBytes],
  ['runtime-publish-manifest.json', runtimeManifestBytes],
]));
const candidateForDeploy = {
  source_commit: commit,
  producer_run_id: 42,
  artifact_id: 7,
  archive_sha256: sha256(staticArchive),
  release_request_sha256: '',
};
const releaseForDeploy = Buffer.from(JSON.stringify({
  schemaVersion: 1,
  kind: 'cnyos_vps_staging_candidate',
  authorization: false,
  productionEligible: false,
  source: { repository: 'apisarit/chananya-clinical-wellness-os', commit, tree },
  workflow: { runId: 42, runAttempt: 1 },
  artifact: { file: archiveName, sha256: candidateForDeploy.archive_sha256 },
  runtimeManifestSha256: sha256(runtimeManifestBytes),
  deployManifestSha256: sha256(deployManifestBytes),
  note: 'Build evidence only. A protected controller must authorize and deploy this exact packet.',
}));
candidateForDeploy.release_request_sha256 = sha256(releaseForDeploy);
const sumsForDeploy = Buffer.from(`${candidateForDeploy.archive_sha256}  ${archiveName}\n${candidateForDeploy.release_request_sha256}  release-request.json\n`);
await fs.writeFile(path.join(deploySpool, archiveName), staticArchive);
await fs.writeFile(path.join(deploySpool, 'release-request.json'), releaseForDeploy);
await fs.writeFile(path.join(deploySpool, 'SHA256SUMS'), sumsForDeploy);
const deployBody = {
  environment: 'staging',
  request_id: `99.1.${commit}`,
  producer,
  candidate: candidateForDeploy,
  artifact: {
    ok: true,
    spoolDir: deploySpool,
    files: [archiveName, 'release-request.json', 'SHA256SUMS'],
    archiveName,
    sourceCommit: commit,
    archiveSha256: candidateForDeploy.archive_sha256,
    releaseRequestSha256: candidateForDeploy.release_request_sha256,
  },
};
const dockerCalls = [];
const spawnImpl = (file, args, options) => {
  dockerCalls.push({ file, args, options });
  const child = new EventEmitter();
  child.kill = () => {};
  process.nextTick(() => child.emit('close', 0));
  return child;
};
const deployed = await deployStaging(deployBody, {
  rootDir: deployRoot,
  spoolRoot: deploySpoolRoot,
  runtimeDir: new URL('../broker/runtime/', import.meta.url),
  spawnImpl,
  webHealth: async () => {},
  supabaseHealth: async () => {},
  requireRoot: false,
});
assert.equal(deployed.ok, true);
assert.equal(deployed.state, 'web_staged');
assert.equal((await fs.readlink(path.join(deployRoot, 'current'))), path.join(deployRoot, 'releases', commit));
assert.equal(JSON.parse(await fs.readFile(deployed.receipt, 'utf8')).state, 'completed');
assert.ok(dockerCalls.some(call => call.args.includes('build')));
assert.ok(dockerCalls.some(call => call.args.includes('--wait')));
assert.equal((await deployStaging(deployBody, {
  rootDir: deployRoot,
  spoolRoot: deploySpoolRoot,
  runtimeDir: new URL('../broker/runtime/', import.meta.url),
  spawnImpl,
  webHealth: async () => {},
  supabaseHealth: async () => {},
  requireRoot: false,
})).replay, true);

async function seedDeploySpool(root) {
  const dir = await fs.mkdtemp(path.join(root, 'candidate-'));
  await fs.writeFile(path.join(dir, archiveName), staticArchive);
  await fs.writeFile(path.join(dir, 'release-request.json'), releaseForDeploy);
  await fs.writeFile(path.join(dir, 'SHA256SUMS'), sumsForDeploy);
  return dir;
}

const receiptFailureRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-receipt-failure-'));
const receiptFailureSpoolRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-receipt-spool-'));
const receiptFailureSpool = await seedDeploySpool(receiptFailureSpoolRoot);
const receiptFailureBody = {
  ...deployBody,
  request_id: `100.1.${commit}`,
  artifact: { ...deployBody.artifact, spoolDir: receiptFailureSpool },
};
await assert.rejects(() => deployStaging(receiptFailureBody, {
  rootDir: receiptFailureRoot,
  spoolRoot: receiptFailureSpoolRoot,
  runtimeDir: new URL('../broker/runtime/', import.meta.url),
  spawnImpl,
  webHealth: async () => {},
  supabaseHealth: async () => {},
  requireRoot: false,
  receiptWriter: async (file, value) => {
    if (value.state === 'completed') throw new Error('simulated durable receipt failure');
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, JSON.stringify(value));
  },
}), /simulated durable receipt failure/);
assert.equal(await fs.lstat(path.join(receiptFailureRoot, 'current')).catch(() => null), null);
assert.equal(JSON.parse(await fs.readFile(path.join(receiptFailureRoot, 'state', 'receipts', `${receiptFailureBody.request_id}.json`), 'utf8')).rollback_succeeded, true);
assert.equal(await fs.lstat(receiptFailureSpool).catch(() => null), null);

const crashRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-crash-recovery-'));
const crashSpoolRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cnyos-crash-spool-'));
const crashSpool = await seedDeploySpool(crashSpoolRoot);
const interruptedCommit = 'c'.repeat(40);
const strandedRelease = path.join(crashRoot, 'releases', interruptedCommit);
await fs.mkdir(strandedRelease, { recursive: true });
await fs.writeFile(path.join(strandedRelease, '.env'), `CNYOS_SOURCE_COMMIT=${commit}\n`);
await fs.writeFile(path.join(strandedRelease, 'docker-compose.yml'), 'services: {}\n');
await fs.mkdir(path.join(crashRoot, 'state', 'receipts'), { recursive: true });
const interruptedRequest = `98.1.${interruptedCommit}`;
await fs.writeFile(path.join(crashRoot, 'state', 'receipts', `${interruptedRequest}.json`), JSON.stringify({
  schema_version: 1,
  request_id: interruptedRequest,
  source_commit: interruptedCommit,
  archive_sha256: candidateForDeploy.archive_sha256,
  state: 'deploying',
  previous_release: null,
}));
await fs.symlink(strandedRelease, path.join(crashRoot, 'current'));
const recoveredBody = {
  ...deployBody,
  request_id: `101.1.${commit}`,
  artifact: { ...deployBody.artifact, spoolDir: crashSpool },
};
assert.equal((await deployStaging(recoveredBody, {
  rootDir: crashRoot,
  spoolRoot: crashSpoolRoot,
  runtimeDir: new URL('../broker/runtime/', import.meta.url),
  spawnImpl,
  webHealth: async () => {},
  supabaseHealth: async () => {},
  requireRoot: false,
})).state, 'web_staged');
assert.equal(JSON.parse(await fs.readFile(path.join(crashRoot, 'state', 'receipts', `${interruptedRequest}.json`), 'utf8')).state, 'recovered');
assert.equal(JSON.parse(await fs.readFile(path.join(crashRoot, 'state', 'receipts', `${recoveredBody.request_id}.json`), 'utf8')).state, 'completed');
process.stdout.write('CNYOS adapter contracts: passed (GitHub bindings, ZIP/TAR traversal, digest and expiry rejection)\n');
