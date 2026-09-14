#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { deployStaging, AdapterError } from './deployer-lib.mjs';

async function readInput() { return JSON.parse(await new Promise((resolve, reject) => { const chunks = []; process.stdin.on('data', chunk => chunks.push(chunk)); process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); process.stdin.on('error', reject); })); }
try {
  const body = await readInput();
  const result = await deployStaging(body);
  process.stdout.write(JSON.stringify(result));
} catch (error) {
  process.stderr.write(`${error instanceof AdapterError ? error.code : 'DEPLOYER_FAILED'}\n`);
  process.exitCode = 1;
}
