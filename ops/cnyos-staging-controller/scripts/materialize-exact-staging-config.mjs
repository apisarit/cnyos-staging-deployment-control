import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import {
  EXACT_STAGING_PRODUCTION_DENYLIST,
  EXACT_STAGING_TARGET
} from './exact-staging-release.mjs';

const [source, destination] = process.argv.slice(2);
if (!source || !destination || !path.isAbsolute(source) || !path.isAbsolute(destination)) {
  throw new Error('CNYOS_EXACT_STAGING_CONFIG_PATHS_REQUIRED');
}
const publishableKey = String(process.env.CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY || '').trim();
if (!/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(publishableKey)) {
  throw new Error('CNYOS_EXACT_STAGING_PUBLISHABLE_KEY_INVALID');
}
const input = JSON.parse(await fs.readFile(source, 'utf8'));
if (input.deploymentId !== EXACT_STAGING_TARGET.deploymentId ||
  input?.tenant?.expectedClinicId !== EXACT_STAGING_TARGET.clinicId ||
  input?.tenant?.expectedClinicCode !== EXACT_STAGING_TARGET.clinicCode ||
  input?.database?.url !== EXACT_STAGING_TARGET.supabaseOrigin ||
  input?.auth?.redirectOrigin !== EXACT_STAGING_TARGET.origin ||
  input?.identity?.qrIssuer !== EXACT_STAGING_TARGET.qrIssuer ||
  EXACT_STAGING_PRODUCTION_DENYLIST.supabaseProjectRefs.some(ref =>
    String(input?.database?.url || '').includes(ref)) ||
  EXACT_STAGING_PRODUCTION_DENYLIST.origins.includes(input?.auth?.redirectOrigin)) {
  throw new Error('CNYOS_EXACT_STAGING_CONFIG_TARGET_INVALID');
}
const output = {
  ...input,
  database: { ...input.database, publishableKey },
  safety: { previewLocked: false }
};
await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
await fs.writeFile(destination, `${JSON.stringify(output, null, 2)}\n`, {
  flag: 'wx', mode: 0o600
});
