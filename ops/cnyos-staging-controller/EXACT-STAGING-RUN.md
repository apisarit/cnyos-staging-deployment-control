# Exact staging deploy and role-separated UAT

`cnyos-exact-staging-deploy-uat.yml` is a manual, staging-only release path.
It uses two fresh GitHub-hosted runners. The first runner checks out one exact
private application commit with a repository-scoped read-only source token,
verifies its tree, runs its contracts, builds a
closed-world staging artifact, and uploads it without access to the protected
Environment or its secrets. The second runner checks out only the exact trusted
controller, downloads that artifact by immutable artifact ID, re-verifies its
complete content before a protected secret is scoped, publishes it to the fixed
isolated staging site, and runs one bounded synthetic journey against the
immutable deploy URL and the canonical staging URL.

This workflow does **not** authorize or deploy Production. The target is closed
in controller code and workflow YAML:

- Netlify site: `887e058b-6e13-461f-b3c7-ae096b7046fe`
- origin: `https://cnyos-clinical-staging.netlify.app`
- Supabase project: `hsmnjwxurlmsizndjlun`
- GitHub Environment: `cnyos-staging-publish`

The Production Netlify site `7da5e39e-580d-44f1-8623-605313e2fb2b` and
Supabase project `qptxnrldzzinlcabudjv` are explicit hard denials. Site,
origin, project, clinic, and deployment class are not dispatch inputs.

## Manual inputs

- `controller_commit`: approved 40-character commit currently at controller
  `main`; the run rejects a stale or different workflow/controller SHA
- `app_commit`: reviewed 40-character application commit
- `app_tree`: reviewed 40-character tree for that commit
- `rollback_deploy_id`: currently published, known-good 24-character staging
  deploy ID; the run stops before publishing if it changed
- `run_reference`: non-clinical opaque reference used only to derive unique
  synthetic identities

This private repository does not currently expose a protected `main` ref. The
admission contract therefore binds the dispatch to the repository owner actor,
`refs/heads/main`, attempt 1, the exact supplied controller commit, the workflow
SHA, and the checked-out controller HEAD. Protected credentials remain scoped
to the `cnyos-staging-publish` Environment on the second runner only. No branch
name or “latest” commit is accepted as application release identity: the
reviewed application commit and tree must still match byte-for-byte. The upload
action exposes an immutable artifact ID and transport digest; the protected job
downloads that exact ID, re-fetches its archive with a read-only Actions token,
and fails closed unless the raw archive SHA-256 equals the upload digest. It
then independently proves content identity from the closed-world runtime and
function manifests. Candidate repository scripts do not run on the protected
runner.

## Protected secret names

- `CNYOS_STAGING_NETLIFY_AUTH_TOKEN`
- `CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY`
- `CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD`

The controller repository also requires the repository secret
`CNYOS_APP_SOURCE_READ_TOKEN`. It must be a short-lived fine-grained token whose
resource owner is `apisarit`, whose only selected repository is
`chananya-clinical-wellness-os`, and whose only repository permission is
`Contents: Read`. The workflow references it exactly once as the pinned
`actions/checkout` token. It is not placed in job or step environment, is not
available to candidate commands, and checkout uses `persist-credentials: false`.
Prefer a one-repository GitHub App installation token when that boundary is
available; the fine-grained token is the reviewed bounded staging bridge.

`CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY` is public browser configuration and is
supplied only as a repository variable, never as an Environment secret. The
last protected secret is the existing staging-only password. The controller
creates seven distinct emails and role assignments from the run reference; it
never prints the password or writes it to retained evidence.

## Bounded proof

The run provisions exactly one synthetic case and distinct receptionist,
source practitioner, attending clinician, pharmacy reviewer, pharmacy
dispenser, billing, and administrator accounts. It proves:

`appointment -> check-in -> OPD save -> fresh reload -> amend -> fresh reload
-> consult -> IPD admission/handoff -> pharmacy review -> separate dispense
-> billing/payment`

Limits are seven accounts, one case, two browser OPD writes, 48 total
mutations, zero write retries, 20-second request timeouts, and a 25-minute UAT
budget. Patient national ID and phone are absent. Synthetic markers are present
on both auth metadata sets and retained evidence contains only account IDs and
email hashes. The database must generate the patient HN in the exact
`CHANANYASTG-########` form. UAT and fixture evidence both bind that server HN,
the fixed clinic and `SYNTHETIC-E2E` payment scope, and the final eight
characters derived from the hashed run ID; fabricated HNs or suffixes fail the
terminal evidence check.

The rollback baseline is observed before publication and retained with the
candidate binding, exact deploy receipt, fixture proof, UAT proof, and evidence
manifest. A failed or uncertain write stops without retry. The workflow does
not auto-promote any Production environment and does not auto-rollback because
rollback is a separate externally authorized mutation.
