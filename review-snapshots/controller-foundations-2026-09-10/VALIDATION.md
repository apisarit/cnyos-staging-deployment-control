# Local validation of this frozen review snapshot

Date: 10 September 2026 (Asia/Bangkok). Performed by Astra-assisted automation.
This is an AI technical record, not an independent human security approval,
hosted CI attestation, staging receipt or production authorization.

Source manifest SHA-256:
`747a395a3ae07da0c47ceb4f7bcf7d486917a8ec1268194717158ccca903cf7a`.

Checks actually run against the copied, nested source package with a scrubbed
environment, Node.js 24.20.0 and npm 11.19.0:

- `npm test`: exit 0; all 28 contract programs passed.
- `npm run test:activation`: exit 0; exact script/test inventory and all refusal
  contracts passed. The runner remains blocked by design.
- `node verify-source.mjs`: exit 0; all 82 source files and hashes verified.
- A separate Astra agent independently compared all 82 exported files to the
  explicit manifest and original engineering bytes; no publication-scope blocker
  was found. This is a second AI assessment, not human independent approval.

No dependencies were installed, no credentials were supplied, and no live SQL,
application staging UAT, browser test or deployment was run for these checks.
Earlier localhost browser testing is described in the controller README but was
not rerun as part of this frozen export validation. No source changes were made
to the exported files to make the checks pass.

Narrow source scans found no embedded live key material. Synthetic credential
strings and a private-key-marker *rejection assertion* are intentionally present
in tests. This is not a comprehensive secret-scanner certification.

Publication boundary inspected before upload:

- Controller repository is private; connected GitHub actor is `apisarit`.
- Default branch `6e28f00cceee6951718556d9d4049b88eb4afd14` contains only two
  documents and no active workflows. Both documents are preserved.
- Existing build-rehearsal workflow is restricted to its exact rehearsal branch;
  this snapshot adds no active workflow and does not use that branch.
- Repository Webhooks settings showed no configured webhook. Installed Apps
  include Netlify and Supabase; installation alone does not establish deployment
  linkage, and no claim is made that it excludes every external integration.
- Netlify's `cnyos` overview showed the existing manual Netlify Drop deployment.
  Neither the application repository nor any Netlify setting is changed by this
  source publication. No build/deploy API is invoked.

Outstanding gates remain explicit: enforceable control-plane protection,
protected UAT lifecycle integration, reviewed runtime and external recovery
authority, authorized staging migrations/recovery/UAT, and current-head
independent review of PR #36. This snapshot does not satisfy those gates.
