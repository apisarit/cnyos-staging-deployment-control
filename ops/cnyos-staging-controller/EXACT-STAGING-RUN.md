# Exact staging deploy and role-separated UAT

`cnyos-exact-staging-deploy-uat.yml` is a manual, staging-only release path.
It checks out one exact public application commit, verifies its tree, builds the
connected staging artifact, publishes that artifact to the fixed isolated
staging site, and runs one bounded synthetic journey against the immutable
deploy URL and the canonical staging URL.

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

- `app_commit`: reviewed 40-character application commit
- `app_tree`: reviewed 40-character tree for that commit
- `rollback_deploy_id`: currently published, known-good 24-character staging
  deploy ID; the run stops before publishing if it changed
- `run_reference`: non-clinical opaque reference used only to derive unique
  synthetic identities

## Protected secret names

- `CNYOS_STAGING_NETLIFY_AUTH_TOKEN`
- `CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY`
- `CNYOS_STAGING_SUPABASE_PUBLISHABLE_KEY`
- `CNYOS_STAGING_SYNTHETIC_PRACTITIONER_PASSWORD`

The last secret is the existing staging-only password. The controller creates
seven distinct emails and role assignments from the run reference; it never
prints the password or writes it to retained evidence.

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
email hashes.

The rollback baseline is observed before publication and retained with the
candidate binding, exact deploy receipt, fixture proof, UAT proof, and evidence
manifest. A failed or uncertain write stops without retry. The workflow does
not auto-promote any Production environment and does not auto-rollback because
rollback is a separate externally authorized mutation.
