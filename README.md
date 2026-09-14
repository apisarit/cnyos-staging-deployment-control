# cnyos-staging-deployment-control

Private CNYOS staging deployment controller. Bootstrap only; no production
authorization.

## VPS staging admission

`.github/workflows/admit-vps-staging-release.yml` is the unprivileged admission
request half of the staging deployment path. It is deliberately `workflow_dispatch` only and
accepts the exact producer commit, run/artifact IDs, archive digest, and release
request digest. It separately binds the private controller identity and the
public app producer identity. It runs on the dedicated `cnyos-staging-deployer` runner and
requests a short-lived GitHub OIDC token for the audience
`cnyos-vps-staging-broker`.

The runner must have no Docker or sudo capability. The workflow never checks
out or executes candidate code. It sends the signed admission request over
TLS to the root-owned broker at `https://127.0.0.1:9443` using the pinned
`/etc/cnyos-broker/ca.pem`. The broker must validate the OIDC claims, producer
commit/artifact bindings, environment, and single-use request ID before it
downloads or invokes any deployer. A missing CA, unavailable broker, invalid
digest, or rejected claim fails closed.

The root-owned broker, candidate verifier, artifact fetcher, trusted static-web
runtime, and rollback-capable deployer are included under `broker/`. They must
still be installed from an exact reviewed controller commit, supplied with a
least-privilege GitHub token and private TLS material, and pass live readiness
checks before this workflow can succeed. Candidate artifacts cannot replace
the trusted runtime or execute scripts. No workflow in this repository
authorizes Production or edits the VPS's existing Caddy configuration.

## Local contract check

Run the bounded admission workflow contract without network access:

```bash
npm --prefix broker test
node tests/vps-staging-admission-workflow-contract.mjs
```
