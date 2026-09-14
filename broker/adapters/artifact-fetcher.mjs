#!/usr/bin/env node
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ARTIFACT_NAME, AdapterError, createGitHubClient, readRootOnlyToken, readZipExact, validateReleaseRequest, writeRootOnly } from './common.mjs';

async function input() { return JSON.parse(await new Promise((resolve, reject) => { const chunks = []; process.stdin.on('data', chunk => chunks.push(chunk)); process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); process.stdin.on('error', reject); })); }
async function main() {
  const body = await input(); const candidate = body.candidate || body; const producer = body.producer;
  if (!candidate || !producer || producer.repository !== 'apisarit/chananya-clinical-wellness-os') throw new AdapterError('FETCH_REQUEST_INVALID');
  const client = createGitHubClient({ token: await readRootOnlyToken() });
  const [repo, run, artifact] = await Promise.all([client.repo(producer.repository), client.run(producer.repository, candidate.producer_run_id), client.artifact(producer.repository, candidate.artifact_id)]);
  if (repo.visibility !== 'public' || repo.full_name !== producer.repository) throw new AdapterError('PRODUCER_VISIBILITY_INVALID');
  if (run.head_sha !== candidate.source_commit || run.head_branch !== 'main' || run.path !== '.github/workflows/deploy-vps-staging.yml' || run.status !== 'completed' || run.conclusion !== 'success') throw new AdapterError('PRODUCER_RUN_NOT_EXACT');
  if (artifact.id !== candidate.artifact_id || artifact.name !== ARTIFACT_NAME(candidate.source_commit, candidate.producer_run_id) || artifact.expired === true || artifact.workflow_run?.id !== candidate.producer_run_id) throw new AdapterError('ARTIFACT_METADATA_INVALID');
  const archive = await client.downloadArtifact(producer.repository, candidate.artifact_id);
  const archiveName = `cnyos-static-${candidate.source_commit}.tar.gz`;
  const files = readZipExact(archive, [archiveName, 'release-request.json', 'SHA256SUMS']);
  validateReleaseRequest(files, candidate, producer);
  const spoolRoot = process.env.CNYOS_BROKER_SPOOL_DIR || '/var/lib/cnyos-broker/spool';
  await fs.mkdir(spoolRoot, { recursive: true, mode: 0o700 });
  await fs.chmod(spoolRoot, 0o700);
  const spoolDir = await fs.mkdtemp(path.join(spoolRoot, 'candidate-')); await fs.chmod(spoolDir, 0o700);
  await writeRootOnly(spoolDir, files);
  process.stdout.write(JSON.stringify({ ok: true, spoolDir, files: [...files.keys()], archiveName, sourceCommit: candidate.source_commit, archiveSha256: candidate.archive_sha256, releaseRequestSha256: candidate.release_request_sha256 }));
}
main().catch(error => { process.stderr.write(`${error instanceof AdapterError ? error.code : 'ARTIFACT_FETCHER_FAILED'}\n`); process.exitCode = 1; });
