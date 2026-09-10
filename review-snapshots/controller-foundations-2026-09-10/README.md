# Controller foundations — inert source review snapshot

This is a draft source-review package, not an activated controller, deployable
application, migration promotion, security sign-off, or production release.
The controller repository's existing root README and release plan are preserved.
Nothing is added to `.github/workflows`; all workflow templates remain dormant.

## Provenance and contents

`source-manifest.json` identifies 82 exact files (2,456,092 bytes): 70 controller
files and 12 source-text dependencies needed by its offline tests. They were
copied byte-for-byte from the dirty engineering checkout based on application
commit `4e98152f91c65bb7089222145b04620ba919306a`. The manifest hashes, not that
unchanged base commit, identify the exported work. This package does not change
the application repository or PR #36 at `dc6c8c776909ed8a3280765d7232ed8eacba955c`.

The ten HTML files and two files under `source/scripts/` are read as test context.
They are not a runnable application or a complete credentialed verifier. Do not
serve this snapshot or execute the candidate staging scripts. There are no root
application build files, database migrations, deployment credentials, live
evidence, browser profiles, installed dependencies or browser binaries here.
Controller target identifiers and synthetic test credentials are source code,
not authority to act on those targets.

## Reproduce the offline checks

Use Node.js 24 and Git in a disposable, credential-free environment. No dependency
installation, GitHub token, database connection, browser or deployment is needed.
From this snapshot directory:

```sh
node verify-source.mjs
cd source/ops/cnyos-staging-controller
npm test
npm run test:activation
```

The activation test checks the exact script/test inventory and refusal contracts;
its passing name does **not** mean activation is permitted. The optional browser
fixture remains opt-in and needs a separately supplied isolated runtime. Earlier
local browser evidence concerns inert localhost content, not authenticated staging.

## What is implemented, and what is still disconnected

The source includes request allowlisting, bounded CDP browser transport, browser
termination checks, access-observation comparison, atomic evidence publication,
source/build comparison, and deployment/recovery boundary foundations. Offline
tests exercise those components and their refusal paths with synthetic fixtures.

`controller-authenticated-uat.mjs` still unconditionally refuses live UAT. The
browser transport is not yet wired into an authorized protected lifecycle with
ephemeral users, cross-tenant fixtures, complete journey execution, screenshots,
durable recovery and verified credential cleanup. No placeholder policy value,
trust root, workflow stop, readiness flag or review requirement is changed here.

## Review handoff and ordered next steps

1. Review this exact snapshot and test results. AI technical review is labeled as
   such; it is not Jaoball's independent approval.
2. Establish an enforceable control-plane boundary. On 10 September 2026 the
   private repository's `main` was unprotected; GitHub's UI said its plan would
   not enforce protection. Do not make the repository public or treat a saved
   but unenforced rule as protection. An eligible plan still does not, by itself,
   satisfy the separate private Environment-review and executor requirements.
3. Obtain independent current-head review of PR #36's trigger/browser-RPC ACLs,
   enforced read-only verification transaction, and atomic failure/rollback.
   Keep PR #36 draft and unmerged. Existing owner consent and old dismissed or
   unrelated reviews do not meet this requirement.
4. Complete and review the controller lifecycle integration, runtime/trust pins,
   isolated identities, exact target binding, and independently administered
   recovery authority before any credentialed run.
5. Follow the maintained PR #36 protocol for Chananya staging verification and
   ledger reconciliation; assess Jitarsa independently. Approved candidates then
   need a separate ordered-migration PR, staging application and recovery proof.
6. Run authorized full synthetic staging UAT and regression testing. Production
   authorization/deployment and permission for real patient data remain separate.

Copying these files into an active control plane requires the prerequisite review
and protections documented in `source/ops/cnyos-staging-controller/README.md`.
Publishing or merging this inert review snapshot cannot supply those prerequisites.
