import { handleBackupRecovery } from './_shared/database-backup-runtime.mjs';

// Monitor only the six-hour window around the daily 20:00 UTC backup slot.
// A stale same-slot lease is re-dispatched with a fresh signed request; the
// database lease remains the final idempotency and stale-recovery authority.
export default async (request, context) => handleBackupRecovery(request, context);

export const config = {
  schedule: '*/15 0-2,20-23 * * *'
};
