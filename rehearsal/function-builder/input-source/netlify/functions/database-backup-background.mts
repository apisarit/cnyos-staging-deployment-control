import { handleBackgroundBackup } from './_shared/database-backup-runtime.mjs';

// Netlify recognizes the `-background` filename suffix and grants this worker
// the background-function execution budget. The handler still authenticates
// every dispatch; the generated function URL is never a browser/API surface.
export default async (request, context) => handleBackgroundBackup(request, context);
