import { handleScheduledBackup } from './_shared/database-backup-runtime.mjs';

export {
  assertBackupDatabaseContract,
  assertBackupExportPayload,
  assertDispatchBinding,
  backupEnabled,
  configuration,
  createDispatchJob,
  createSignedDispatch,
  handleBackupRecovery,
  handleScheduledBackup,
  listBackupSlotRuns,
  mostRecentBackupSlot,
  resolveClinicDriveDestination,
  resolveClinicFolderIds,
  runBackupClinicJob,
  validateClinicList,
  verifySignedDispatch
} from './_shared/database-backup-runtime.mjs';

export default async (request, context) => handleScheduledBackup(request, context);

export const config = {
  schedule: '0 20 * * *'
};
