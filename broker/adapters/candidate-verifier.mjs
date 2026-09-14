#!/usr/bin/env node
import fs from 'node:fs/promises';
import { createGitHubClient, readRootOnlyToken, verifyCandidate, AdapterError } from './common.mjs';

async function main() {
  const input = JSON.parse(await new Promise((resolve, reject) => { const chunks = []; process.stdin.on('data', chunk => chunks.push(chunk)); process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); process.stdin.on('error', reject); }));
  const token = await readRootOnlyToken();
  const result = await verifyCandidate(input, createGitHubClient({ token }));
  process.stdout.write(JSON.stringify(result));
}
main().catch(error => { process.stderr.write(`${error instanceof AdapterError ? error.code : 'CANDIDATE_VERIFIER_FAILED'}\n`); process.exitCode = 1; });
