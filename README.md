# CNYOS controller — offline source preparation

This directory is an inert, source-only preparation package. It is not a
deployment, does not publish a site, and does not authorize controller
activation. Both workflow files under `ops/cnyos-staging-controller/workflow/`
are retained as dormant templates.

The 99-file package preserves runtime, policy, dormant-template files, and
candidate fixture bytes byte-for-byte. Four test/helper files have only
path adaptations for relocated inert fixtures; original/package input/output
digests are recorded separately in the manifest. The 30-contract activation
runner is invoked by CI. Run
`node tooling/verify-source.mjs` from this directory to verify the provenance
manifest and the activation-blocked state. The offline CI workflow runs the
existing activation contract runner on `pull_request` with read-only contents,
no secrets, no environment or OIDC access, no cache, and no artifact upload.

## Install checklist (not an activation procedure)

- [ ] Obtain an independently reviewed source manifest and verify it locally.
- [ ] Confirm all existing CNYOS controls and refusal contracts remain present.
- [ ] Confirm the target private-repository plan supports required branch rules.
- [ ] Record explicit owner approval before any future deployment or activation.
- [ ] Keep activation blocked until every release, authority, and broker gate is
      satisfied; this package supplies none of those approvals.

GitHub protected-branch enforcement remains unavailable for this private
repository under its current plan. Do not weaken controls or change repository
visibility to work around that limitation.
