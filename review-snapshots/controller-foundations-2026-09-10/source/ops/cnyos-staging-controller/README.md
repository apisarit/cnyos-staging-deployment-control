# CNYOS staging protected-controller bootstrap

This directory is a dormant bootstrap package. Nothing here is an active GitHub
workflow, and nothing in this package authorizes a deployment. Copy it into a
**separate deployment-control repository** only after the controls below have
been established. Do not activate it from a pull-request branch of the CNYOS
application repository.

The separation is mandatory: the CNYOS `main` branch automatically publishes to
Netlify, while a candidate branch must not define the workflow or scripts that
receive deployment and database credentials. PR #36 remains draft and
unapproved. This package neither merges it nor grants Production access.

## Activation status: blocked by design

The templates contain an unconditional bootstrap stop. Do not change its state
until every placeholder Action SHA is pinned and all controller-owned scripts
and contracts named by the bootstrap job exist and pass. In particular, this
package intentionally does **not** claim that a normal Netlify deploy token can
prove or enforce any of these controls:

- deterministic, source-reproducible, dependency-lock-bound Function archives;
- a hermetic independent rebuild and byte comparison for the static site;
- a private draft URL and automatic deletion/revocation of every rejected draft;
- a controller-owned draft access boundary that consumes its bearer credential
  and forwards no Authorization header, cookie, or redirect to candidate routing;
- an independent, server-enforced, compare-and-swap publish lease that excludes
  Netlify Git, UI, build-hook, and other publishers;
- authenticated rollback artifacts immune to same-run artifact-name poisoning;
- an immutable rollback-attestation broker deposit, made before any Netlify
  credential is used, that retains the raw signed recovery inputs out of band;
- a separate staging-only rollback principal and a noninteractive rollback
  Environment; or
- controller-owned authenticated synthetic UAT, public scheduled-Function route
  denial, and closed-world runtime capability validation; or
- removal or broker-enforced denial of every legacy Git, UI, preview, build-hook,
  token, and workflow publisher that can mutate the same Netlify site; or
- cryptographically verified, pinned trust boundaries for every external
  publish/reconciliation, draft-lifecycle, and rollback-membership broker client;
  or
- a fresh live GitHub release-state proof that PR #36 remains open, draft,
  unmerged, and unapproved and that a separate ordered-migration staging
  promotion proposal exactly matches the signed authorization.

Those are activation prerequisites, not risk acceptances. The draft lifecycle
must persist an external write-ahead intent before the first Netlify mutation and
must reconcile a runner loss by controller run ID: restore an owned current
deploy, delete or revoke every non-current draft, and release any publisher
lease. If any prerequisite is unavailable, the draft must not be created and the
controller must remain blocked.

## Security boundary

The controller's default branch, workflow templates, policy, scripts, dependency
lock, and approver trust roots are part of one protected control plane. Configure
all of the following before removing the template's bootstrap stop:

Treat `id-token: write` as a job-wide capability. Broker jobs that need OIDC
must receive no Netlify, Supabase, draft-access, password, or rollback secret;
jobs holding any of those credentials must omit OIDC permission and reject the
two `ACTIONS_ID_TOKEN_REQUEST_*` variables. Only signed, hash-bound sanitized
receipts cross between those jobs.

1. Create a separate controller repository with branch protection, CODEOWNERS,
   two-person review, signed commits, no force pushes, and no administrator
   bypass. Put the copied workflow on its protected default branch.
2. Create a `cnyos-staging-publish` GitHub Environment. Allow deployment only
   from the controller's protected default branch, require independent approval,
   prevent self-review, and do not permit administrator bypass.
3. Use a dedicated Netlify identity whose complete accessible-site inventory is
   exactly `7da5e39e-580d-44f1-8623-605313e2fb2b` (`cnyos`). It must not belong
   to a team or role that can reach Chananya Production. If this cannot be
   demonstrated, the controller stays blocked.
   Use a different subject and token for rollback; equality between the publish
   and rollback subjects is a hard failure.
   A normal Netlify personal access token is not a documented deploy-only
   credential: a Developer is over-capable, while the documented Publisher role
   does not establish API/CLI deployment authority. Therefore the template must
   remain blocked until an independently reviewed authority broker can freshly
   attest the subject, role, absence of owner/team/configuration capability, the
   exact one-site inventory, and denial of every alternate publisher. Signed
   booleans and `/user` plus `/sites` responses alone are insufficient.
4. Review and commit this package's `package-lock.json`, then pin every GitHub
   Action in the templates to a full commit SHA. The publisher
   runs only the locally installed `netlify` binary; it never uses `npx`,
   `npm exec --yes`, a tag, or a runtime package install while holding a token.
   Replace `__AUDITED_NETLIFY_CLI_VERSION__` in the policy and workflow only
   after adding that exact CLI release to the lock and obtaining a clean
   high/critical dependency audit plus an independent candidate-input
   reachability review. At the 2026-09-08 checkpoint, the current official
   `netlify-cli` 27.5.0 lock reported ten high-severity transitive advisories,
   including vulnerable TOML parsing and Sharp/libvips paths, so it was removed
   from this bootstrap lock and is not authorized for credentialed execution.
5. Commit the approver public-key registry as a reviewed trust root in the
   protected controller repository; do not supply it as a sibling Environment
   secret. Keep the two Ed25519 private keys with different people. A Jaoball
   approval of PR #38 is not PR #36 security review.
6. Port every credentialed verifier, including authenticated UAT, static
   reproducibility, draft-boundary canary, runtime-capability proof, and
   scheduled-route denial, into reviewed controller-owned code. Candidate scripts
   may run only in the unprivileged producer. Until all ports and their activation
   contracts exist and pass, this bootstrap proves no live deployment gate.
7. Bind an immutable external reconciliation-broker policy/version into the
   signed authorization and durable draft intent. The broker, not code from the
   failed candidate or a later controller revision, owns recovery. It must reject
   a new publish while any earlier run remains unreconciled. Acquisition must
   atomically create a per-run reconciliation barrier in the same lease
   generation. Releasing the lease must atomically retain that barrier; no TTL
   may silently make a barrier-held generation publishable.
8. Provision the separately administered rollback-attestation broker and pin its
   exact HTTPS origin, policy digest, OIDC audience, Ed25519 receipt key ID, and
   SPKI digest in `controller-policy.json`. Before preflight, the controller must
   deposit the canonical authorization, both detached authorization signatures,
   exact known-good bytes, the authorization-verification bundle, and the
   protected approver registry. The post-deposit client validation is derived
   locally and is not broker recovery material. Only the broker-signed sanitized
   receipt and its validation evidence may enter GitHub artifacts. The offline deposit client and
   adversarial contract fail closed while those policy values remain placeholders;
   their fixture signature is not an external broker attestation, so activation
   remains blocked until the real broker and reviewed trust values exist.
9. Replace every field in `externalReconciliationBroker`, `draftLifecycleBroker`,
   and `rollbackPrincipalMembershipBroker` atomically with independently reviewed
   trust values. The cross-cutting `external-broker-trust-boundaries` activation
   contract must then prove every client uses only the exact HTTPS origin and
   operation path/domain, disables redirects, verifies a bounded canonical
   Ed25519-signed response against the pinned key ID and SPKI digest, binds the
   policy, controller run/ref/attempt/nonce, source, artifact, staging site, and
   operation, rejects stale/replayed/conflicting state with compare-and-swap where
   mutation occurs, and permits no credential forwarding or serialization.
10. Retain and independently review the controller-owned
    `live-github-release-boundary` script and adversarial contract. The implemented
    pair completes deterministic recovery, authority-broker, and locked-runtime
    preparation first, then queries GitHub in an isolated job. A minimal
    publisher job must consume that proof within five minutes and revalidate it
    immediately before its first Netlify-token read. Later preflight and draft
    jobs may validate that first record only as historical, exact-byte evidence;
    they must retain its hash, the Function-environment receipt must name that
    hash, and the receipt timestamp must remain within the original five-minute
    window. A queued publisher job that misses the window fails closed and must
    be retried. The second isolated job makes a fresh query immediately before
    promotion. Each query uses a read-only identity isolated from deployment and
    database secrets. Its exact-run evidence must prove PR #36 is open, draft,
    unmerged, and unapproved and bind the independently reviewed, separate ordered-
    migration staging promotion PR/ref/state to the signed source authorization.
    The first and second evidence records must be hash-bound through preflight,
    promotion-attempt, promotion, and final retained evidence.
    The current template still transfers the second observation across jobs and
    permits up to five minutes before the Netlify mutation. That retained record
    is audit evidence only; it is not sufficient mutation authority. Activation
    additionally requires the independently reviewed publish broker to perform
    its own fresh live GitHub read and the exact Netlify promotion as one
    fail-closed operation under a single-use admission bound to the run,
    attempt, commit, nonce, promotion PR head/state, draft deploy, site, and
    barrier generation. The admission may not be replayed, refreshed, or
    separated from its mutation, and any GitHub read failure or state change
    before the broker's mutation must produce no Netlify write. The mandatory
    `external-broker-trust-boundaries` contract must prove these cases; the
    present cross-job five-minute design is therefore an activation blocker.
    Merging PR #36 or using application `main` as a staging gate is prohibited
    because that branch automatically deploys Production. Until this design,
    implementation, evidence binding, and contract exist, activation stays blocked.

## Two-phase release

The first job is an unprivileged producer. It checks out a full candidate commit
SHA, runs locked checks/builds with no Netlify token, Supabase service-role key,
database password, signing key, or Environment secret, then calls
`create-producer-bundle.mjs`. The resulting manifest binds:

- controller run ID, attempt one, and a 32-byte-or-longer nonce;
- exact candidate commit and tree;
- every byte under `dist/`;
- every tracked Function source byte and Git object under
  `netlify/functions/`;
- every controller-produced self-contained Function archive and the exact
  reviewed dependency-lock digest; and
- a deterministic aggregate artifact digest.

After the producer finishes, the independent security reviewer and managed
platform risk owner sign the exact authorization JSON for that controller run,
nonce, source tree, producer-manifest digest, artifact digest, prior known-good
deploy, and fixed staging targets. Only then may the protected Environment
release secrets to a fresh publisher job.

`verify-authorization.mjs` requires two distinct pinned Ed25519 public keys in
canonical SPKI form, rejects private-key PEM input, retains no raw signatures or
raw authorization/known-good payloads, and requires a maximum 30-minute
authorization lifetime, the dispatching risk owner, attempt one, a
protected controller ref, an exact artifact re-hash, a staging-only principal
proof, the three required PR #36 SQL-security review areas, explicit acceptance
of the Function-byte provenance limitation, and an exact known-good rollback
target. A new GitHub run cannot replay the packet because the signed run ID and
nonce must match.

## Protected configuration

Repository variables may contain only browser-public staging configuration used
by the producer. Never put an admin password, service-role key, Netlify token, or
signing key in a producer variable.

The `cnyos-staging-publish` Environment supplies these secrets only to trusted
controller steps:

| Secret | Purpose |
| --- | --- |
| `CNYOS_STAGING_NETLIFY_AUTH_TOKEN` | Proposed staging-only Netlify principal; unusable until the external authority boundary proves a provider-supported least-privilege model |
| `CNYOS_CONTROLLER_AUTHORIZATION_JSON` | Exact signed run/artifact authorization |
| `CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64` | Independent reviewer signature |
| `CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64` | Named risk-owner signature |
| `CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN` | Opaque bearer accepted only by the separate reviewed draft-access boundary; never send it to, or reuse it as a credential for, a candidate Netlify origin |
| `CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY` | Independent random key encoded as canonical unpadded base64url: 43–128 characters, decoding to at least 32 bytes. Generate a compliant 32-byte value with `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`; store the command output only as the protected secret. It is used solely to compare opaque credential identities across isolated publisher and draft-access verification jobs/runners; never serialize the key |
| `CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY` | Server-only key for controller-owned synthetic UAT |
| `CNYOS_STAGING_TEST_PASSWORD` | Password for synthetic staging identities only |

Each isolated live-GitHub boundary job maps only its job-scoped `github.token`.
The jobs declare only `contents: read` and `pull-requests: read`, request no OIDC
identity, use no Environment or separately provisioned token, issue only
fixed-origin `GET` requests, and emit no credential value. The source repository
must remain publicly readable; a future private-source design requires a
separately reviewed GitHub App boundary and is not authorized by this template.

The protected repository variable `CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL`
must equal the exact reviewed origin pinned in `controller-policy.json`. The
boundary policy ID and SHA-256 are signed release inputs. The boundary must use a
fixed site/deploy target, reject redirects, return only exact response bytes or
bounded sanitized response evidence, and prove with a candidate-Function canary
that it forwarded no bearer, Authorization header, or cookie. A request from the
controller directly to a candidate origin with this credential is prohibited.

The reviewed boundary exposes only `POST /v1/read-netlify-draft-file`. The
`read_exact_netlify_draft_file` operation returns bytes only after matching the
exact run, staging site, immutable deploy origin, path, size and SHA-256. The
`probe_exact_netlify_draft_request` operation returns canonical JSON containing
only the upstream status, body size/SHA-256, `location`, and the closed header
allowlist used by the control verifier; it never serializes upstream body bytes.
Every probe request carries a controller-generated 32-byte random
`requestNonce`. The candidate canary must echo that exact nonce and its
canonical `verifiedAt` may neither predate the local request start nor postdate
the response observation. A prior canary is therefore not reusable. The
controller rejects a boundary origin equal to either the mutable staging origin
or the exact candidate deploy origin before reading the bearer.
Both operations consume the boundary bearer locally, send no Authorization or
cookie upstream, omit ambient credentials/referrers, and never follow a
redirect. Missing and invalid bearer probes must return the fixed fail-closed
401 contract before the controller accepts the boundary; every response body
and header is scanned for both the real and invalid bearer. Boundary evidence
also hash-binds the preflight and draft receipt, whose provider commit and
deployment title must match the exact candidate/marker and whose timestamp may
not predate preflight.

Control behavior is closed-world: the protected controller binds the exact 11
header-rule and seven redirect/rewrite-rule inventories before probing them.
Static header routes must return 200, redirects must return their declared first
hop without following it, and the `/` rewrite body must match the exact bundled
`index.html`. Because Netlify `_headers` rules do not apply to Function
responses, `/api/owner-subscription` and `/api/patient-identity` are explicitly
classified and checked as effective Function response-header contracts, not as
proof that `_headers` configured them.
Promotion and finalization must independently revalidate the complete control
evidence schema, including every probe, count, digest, policy target, evidence
pointer, and credential/redirect claim; a producer `passed` flag alone is not
sufficient.

This repository contains the fail-closed clients and offline wire-contract
tests, not the independently administered boundary service or its fixed canary
route. The placeholder boundary policy therefore remains an activation blocker
until that external implementation is independently reviewed and pinned.

`CNYOS_NETLIFY_AUTHORITY_BROKER_URL` must identify a separately administered
attestation service whose reviewed policy ID and SHA-256 exactly match
`controller-policy.json`; its origin and Ed25519 signing-key SPKI fingerprint
must also be pinned there. Immediately before preflight it must issue a maximum
10-minute, exact-run proof of the live principal role/capabilities, staging-only
site inventory, same-site Production conflict resolution, and closed alternate
publisher inventory. Missing, stale, self-issued, or mismatched evidence blocks
the draft.

`CNYOS_NETLIFY_PUBLISH_BROKER_URL`, `CNYOS_DRAFT_LIFECYCLE_BROKER_URL`, and
`CNYOS_NETLIFY_PRINCIPAL_MEMBERSHIP_BROKER_URL` are untrusted configuration until
each exactly equals the HTTPS URL formed from its corresponding policy `origin`
and `operationPath`. The protected policy also pins a fixed operation domain,
policy ID/SHA-256, canonical Ed25519 public key, key ID/SPKI SHA-256, OIDC
audience, ten-minute evidence ceiling, and response-size ceiling. Broker clients
must reject redirects and noncanonical, unsigned, stale, replayed, cross-run,
cross-source, cross-artifact, cross-site, or wrong-operation responses. A client
running beside a Netlify token must prove it performs no credential forwarding or
serialization; merely keeping a token out of the broker URL is insufficient.
The mandatory `release-state-reconciliation` activation contract must exercise
both commit/recovery CAS interleavings, signature and canonical-schema failures,
exact run/ref/attempt/nonce/site/deploy/lease-generation and final/release-hash
binding, identical-retry idempotency, conflicting retries, no automatic barrier
expiry, draft-intent terminality, and rehydration after a lost response or
terminal-receipt upload. It must prove that `terminal_success_rehydrated` and
`terminal_recovery_rehydrated` never schedule or execute a rollback-token job,
that a `recovery_required` claim makes a delayed successful-release commit
conflict, and that successful recovery finalization remains an exact-retry,
signed terminal no-op when the failed source workflow later triggers its
watchdog. It must also inject loss after recovery-claim/plan-core persistence
but before response and artifact upload; prove that main and watchdog races
create exactly one claim; resume the same claim under a different watchdog run
ID; refresh only the signed envelope after expiry; preserve claim ID,
generation, plan-core digest, actions, and barrier through incomplete records;
reject every changed claim binding, action set, resumer identity, or generation;
and prove claim plus plan-core persistence commits both or neither.

`CNYOS_ROLLBACK_ATTESTATION_BROKER_URL` must resolve to the exact origin pinned
in `rollbackAttestationBroker`. Its write endpoint authenticates the protected
controller by OIDC, accepts one immutable deposit per exact repository/ref/
workflow/run/attempt/nonce, rejects conflicting overwrites, and retains the raw
recovery inputs until a timestamp at least the policy retention period after the
signed deposit time. The broker-signed deposit time must be no earlier than the
authorization verification and strictly earlier than the authorization expiry;
later idempotent retrieval may occur after that expiry. Later verification also
requires that retention not be expired; it does not restart the full retention
clock. Its signed receipt
binds the controller and candidate identities, full producer artifact hashes,
fixed staging target, prior deploy, authorization/registry/known-good hashes,
both authorization key IDs and signature hashes, and the external reconciliation
policy. Broker unavailability, redirect, stale receipt, wrong signing key,
insufficient retention, or a missing deposit blocks preflight and therefore
blocks every Netlify mutation.

The separate, noninteractive `cnyos-staging-rollback` Environment supplies only
the recovery credential:

| Secret | Purpose |
| --- | --- |
| `CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN` | Separate staging-only, noninteractive rollback principal |

Never copy the rollback token into the publish Environment, and never configure
both tokens for the same Netlify subject.

The key registry has this shape:

```json
{
  "schemaVersion": 1,
  "environment": "cnyos-staging",
  "keys": [
    {
      "id": "unique-key-id",
      "role": "independent_security_reviewer",
      "githubLogin": "reviewer-login",
      "ownerName": "Reviewer name",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
      "spkiSha256": "64-lowercase-hex"
    }
  ]
}
```

The second record uses role `managed_platform_risk_owner`. Store the real file as
`ops/cnyos-staging-controller/approver-registry.json` on the protected controller
branch. The signed authorization must also bind the exact controller repository,
workflow path, and commit; candidate SHA is data only.

## Publish and rollback contract

Before mutation, the controller must persist a preflight artifact that proves:

- a fresh external authority attestation re-proves role/capability and all
  publisher-exclusion facts instead of trusting only the signed packet;
- the token can list exactly the one fixed staging site;
- site ID, name, and canonical origin are exact;
- `BACKUP_ENABLED=false` in the published Functions context, an exact active
  deploy created after that setting, and runtime fail-closed behavior for the
  daily backup, recovery scheduler, and background worker;
- the signed prior deploy is still current, ready, belongs to the site, and is a
  known-good rollback target; and
- authorization and producer-bundle digests match.

The only permitted sequence is live rollback-readiness proof -> draft ->
publisher-only draft metadata verification -> reviewed boundary canary -> keyed
opaque credential-identity inequality check and immutable draft verification through that boundary -> control
file behavior verification -> private-draft lifecycle proof -> independent
exclusive-publisher lease -> revalidation of the exact rollback-readiness and
draft-gate digests within the broker's ten-minute window -> promotion of that
exact deploy ID -> post-promotion
closed-world file/API byte and Function/schedule verification -> public GET and
malformed-POST denial on both immutable and canonical origins, bracketed by
exact-byte deploy-manifest observations -> synthetic UAT -> final
publisher-only exact-current check -> atomic publisher-lease release/barrier-retention
receipt -> evidence closure -> independently re-downloaded evidence hashes ->
atomic broker terminal commit. `_headers` and `_redirects` are
Netlify control inputs rather than public files; verify their resulting behavior
on the immutable draft. When anonymous draft access is denied, only the separate
reviewed boundary may consume its access credential. Never use `netlify deploy
--prod` for the draft.
Post-promotion and final-current `verifiedAt` values describe completion of the
last publisher-current check, not its start. The controller rechecks the
authorization/principal/deployment-control expiry after those remote checks and
accepts final-current evidence only under its exact closed-world schema and
producer-manifest-bound static inventory digest.

Credential isolation in that sequence is runner-wide, not merely step-wide.
Publisher-only metadata, draft-access byte/control verification, and
publisher-only lifecycle closure run as three distinct jobs. Promotion and
post-promotion byte verification, credential-free scheduled-route denial,
database-only synthetic UAT, and publisher-only final-current verification run
as four distinct jobs. Only exact, regular, non-symlink JSON evidence and its
producer-exported lowercase SHA-256 cross those runner boundaries. No runner may
receive more than one bearer-authority class.

Every rejected pre-promotion draft must be deleted or access-revoked. A durable
external intent must make the draft discoverable even if the publisher exits
after Netlify accepts it but before a local receipt or job output is written.
Every failure, cancellation, or timeout after the preflight invokes
reconciliation, including failure after draft intent, publisher-lease
acquisition, promotion, lease release, final evidence upload, or the terminal
broker commit/receipt upload. Rollback may
restore the signed prior deploy only when the current deploy is both the exact
receipt deploy **and** has the controller's exact run/nonce ownership marker. It
must first obtain the exact signed packet, both signatures, known-good bytes,
authorization-verification bundle, and protected public-key registry from the
immutable rollback-attestation broker and match their SHA-256 values to the
signed receipt. The locally derived post-deposit validation is independently
recomputed and is never required as broker recovery material. Raw
authorization, signature, private-key, and known-good payloads must never be
uploaded as workflow artifacts. Before any mutation, the publisher must already
hold a fresh, broker-signed receipt proving that deposit. Recovery must retrieve
by the exact run/nonce and OIDC controller identity, hash-match every returned
raw byte sequence to that receipt and the sanitized bundle, and independently
repeat canonical schema, Ed25519 signature, registry, known-good, source,
artifact, and run-binding verification. Authorization expiry may be ignored only
for this recovery verification; scope and identity checks remain mandatory. It
must then retain that exact authenticated rollback-chain validation for 365
days, even when later reconciliation fails, verify privileged artifact
provenance, and never overwrite a different external deploy.

Both in-run recovery and the protected `workflow_run` watchdog use three
credential-isolated jobs. First, an OIDC-only preparation job retrieves broker
state by exact run/nonce, authenticates the recovery inputs, and emits only a
short-lived signed `reconciliation-plan.json` plus a sanitized
`rollback-authorization-chain.json`. The signed plan carries the closed enum
`recoveryDisposition=recovery_required|terminal_success_rehydrated|terminal_recovery_rehydrated`.
The broker atomically grants either a recovery claim or the matching terminal
success/recovery record for one barrier generation; those outcomes are mutually
exclusive.
Claim creation and immutable plan-core persistence must be one durable CAS. The
claim key binds the broker policy, target repository/ref/workflow/run/attempt/
commit/dispatch nonce, staging site, and barrier generation. Its plan core also
binds previous/current deploys, known-good baseline, rollback-chain digest,
ordered actions, and every exact run-owned draft intent. If preparation loses
the broker response or dies before artifact upload, an authorized run of either
the protected release workflow or protected watchdog must receive
`recovery_required` with the identical claim ID, generation, plan-core SHA-256,
and actions rather than creating a second claim. An expired short-lived envelope
may be refreshed, but the claim and plan core must remain byte-identical. Any
changed binding, action set, unauthorized resumer, or different generation
conflicts without mutation. Neither a TTL nor an incomplete-recovery record may
replace, release, or expire the claim, plan, lease, or run barrier.
Missing local draft or lease artifacts are
recovered from the brokers; optional artifact downloads are selected by the
direct producer job result, never an indirect empty output. Second, a job with
only the dedicated rollback principal, no OIDC request variables, and no broker
URLs is scheduled only for exact `recovery_required`, then re-hashes and
semantically validates that disposition immediately before any
conditional rollback or rejected-draft cleanup. It emits a hash-bound execution
receipt and cannot release the publisher lease or reconciliation barrier. Third,
an OIDC-only finalizer releases or closes broker state only after the execution
job succeeded and the downloaded receipt matches its exact lowercase SHA-256.
For either terminal disposition, no rollback-token job is scheduled; the
OIDC-only finalizer independently validates the corresponding signed terminal
record and records a no-op. A recovery-terminal record must also bind the exact
execution receipt and recovery-finalization generation. A recovery claim makes
any delayed terminal commit conflict, and terminal success or terminal recovery
is never rollback-eligible.
Cancellation, failure, missing or tampered evidence records incomplete recovery
and keeps either the lease or, when lease release already occurred, the per-run
barrier active for watchdog retry. If the broker has already persisted an
immutable terminal record, the incomplete recorder must not reactivate or
rewrite that terminal state and must not emit misleading incomplete evidence;
the watchdog/manual retry must use the signed terminal-rehydration path.

The normal success path also keeps that barrier active after lease release.
`publisher-release.json` must prove the atomic transition from `{lease active,
barrier active}` to `{lease inactive, barrier active, immutable release receipt}`
for the same site and lease generation. After `final.json` is durably uploaded,
a separate OIDC-only job re-downloads it, validates both its SHA-256 and the
release-receipt SHA-256, and requests one atomic broker terminal commit. The
broker may clear the barrier only after it has semantically validated those
hash-bound records and atomically established that every run-owned draft intent
is terminal. It must persist an independently retrievable signed terminal record
binding the controller run/attempt/nonce, site, deploy, lease generation and both
hashes. Identical retries are idempotent; any differing identity, generation or
hash conflicts. If the broker committed but its response or terminal-receipt
artifact upload was lost, recovery must rehydrate the signed `committed_success`
record and perform a terminal no-op rather than roll back the successful deploy.

The watchdog repeats those three effects after the primary run ends. Its
per-target-run concurrency key cannot be displaced by a newer publish dispatch.
Its `cnyos-staging-rollback` Environment must have no reviewer or wait timer.
Before any recovery capability is used, it independently repeats the release
workflow's protected-file, placeholder, locked-dependency, base-test, and
closed-world activation checks. Netlify or GitHub control-plane loss still
requires a separately reviewed manual restore runbook and alerting.

Database rehearsal, quiescence, fresh-observer, and strict post-remediation
evidence must be canonical and no more than 30 minutes old when authorization is
validated. Exact catalog counts are not timeless constants: the signed packet
must also bind the reviewed baseline schema version and SHA-256. Any age,
baseline, or digest mismatch blocks the run.

At the 2026-09-08T05:13:52Z read-only checkpoint, the live Netlify control plane
showed distinct projects: staging `cnyos` is Site ID
`7da5e39e-580d-44f1-8623-605313e2fb2b` at `https://cnyos.netlify.app`, while
Production `chananya` is Site ID `f1a31624-f90b-4d72-be3d-e91b7e2b2f38` at
`https://chananya.netlify.app`. The exact Production ID is pinned in this
policy's denylist. This observation resolves only the previously suspected live
site-ID collision; it is not deployment authority and must be freshly verified
before activation.

The application repository still contains legacy Production and preview
workflows that can expose credentials to candidate-owned commands, and its
Production setup helper incorrectly names the staging Site ID/origin. Pushing
the PR #36 branch also caused the Git-linked Production project to build Deploy
Preview #36, although it did not update `main` or the Production URL. This
package does not edit or authorize those Production paths. Before activation,
signed deployment-boundary evidence and the independent publisher broker must
prove that the target is staging-only with no real patient data, that every
candidate-repository Production/preview workflow and alternate credential is
unable to publish to the target, and that the current live IDs/origins still
match the pinned pair. A documentation assertion or hard-coded ID is not
enforcement; failure to prove any item blocks the draft before its first
mutation.

`CNYOS_OWNER_CONTROL_ENABLED` remains `false` in the releasable staging
configuration. Enabling it for a synthetic test would require a separately
reviewed ephemeral capability with enforced expiry and post-UAT revocation; this
bootstrap does not provide or authorize that capability.

Success evidence is fail-closed: missing files are errors, not warnings. UAT
evidence must bind all 11 provisioned identities, the access-context and
department checks, ten-route matrix, ten synthetic journeys, subscription OFF/ON
restoration, per-gate evidence hashes, and zero unresolved failures. The final
manifest directly re-hashes the pre-release reconciliation, authorization
verification bundle, rollback-attestation receipt and validation, live Netlify
authority proof, both live GitHub release-boundary records,
function-environment validation, backup-disable boundary,
runtime-capability boundary, rollback readiness, draft gate, durable draft
intent, private draft-access boundary, draft metadata verification, promotion
attempt, and every subsequent
receipt through publisher-lease release. It also
cross-links source, run, nonce, artifact, authorization, preflight, new deploy,
current-deploy verification, Function metadata/process provenance,
draft-boundary canary, scheduled-route denial, and rollback target hashes.
Netlify does not expose independently
retrievable Function bundle bytes in the current design, so the evidence must
say `functionByteAttestationAvailable: false`; names, schedules, route denial,
clean source and a pinned publisher are process provenance, not a byte proof.

## Local, offline validation

The controller now owns immutable Function recipe-input preparation through
`scripts/materialize-function-recipe-input.mjs`. Its API and explicit local CLI
read the selected full commit with the existing transport-disabled Git reader;
they never import candidate code or run a compiler. Output must be a fresh
canonical directory outside the candidate checkout. The exact recipe-compatible
`source/` tree contains only the 11 Function entrypoints, permitted shared
modules and `platform-config.js`; ambient/ignored checkout overlays are excluded.
Source files are read back and verified, nested directories and their parent are
synced, and `input-manifest.json` is written last. Partial failures keep source
files for diagnosis but do not report completed preparation or replace existing
output. Error messages and CLI output do not serialize input paths or credentials.
The comparison handoff uses the same source selector, so preparation and
comparison cannot silently diverge in their accepted source layout. The resulting
manifest fits the existing recipe's `--source`/`--input-manifest` inputs; no new
recipe interface, trusted build pin, producer eligibility or deployment authority
is implied. This is source preparation, not execution provenance or import closure.
At the 2026-09-10 02:44 ICT checkpoint, the actual local CLI prepared the clean
PR #36 source commit `dc6c8c776909ed8a3280765d7232ed8eacba955c`: 21 files,
225,318 bytes, independently rehashed after preparation. Its manifest bytes exactly
matched the previously retained hosted-rehearsal input manifest, SHA-256
`03d815265f93d4dc25d73d7614e931bcbb3b91054f882d8aa43d9f5b34981e1f`.
No compiler or application handler was invoked for this local preparation.

The nine previously absent controller script files now have local implementations:
live authority observation; backup-disable/runtime-capability proof acquisition
and verification; durable draft intent, draft publishing, lifecycle verification
and guarded cleanup; publisher lease acquisition/release; and rollback readiness.
These implementations are clients and validators for explicitly reviewed service
protocols, not an implementation or attestation of those external services.

Authority evidence retains its actual canonical Ed25519-signed broker envelope;
consumers revalidate both the signed statement and the normalized summary against
the loaded authorization/deposit hashes. Runtime proof uses a separate trust
scope and OIDC-only acquisition job. Credential-free verification and later
preflight/finalization revalidate the same retained envelope, exact provenance,
handler observations, secret inventory and egress boundary. Historic validation
is anchored to the preflight observation and still requires signed chronology
and retention. None of this upgrades the explicitly accepted absence of remote
Function-byte attestation to a byte-level proof.

Draft mutation requires a signed, durable intent before the CLI invocation, an
exclusive unknown-outcome journal, and no automatic replay. Provider ownership
markers and timestamps bind the draft receipt and lifecycle to that intent; they
do not claim that a broker independently observed the resulting deploy ID.
Rollback readiness separates OIDC proof preparation from read-only provider-token
verification. Publisher release checks the UAT/final-current chain and retains
the run barrier. A signed lease still does not solve the separately documented
atomic fresh-GitHub-check-plus-promotion requirement.

The static reproducibility runner reads the exact candidate Git commit and
reconstructs its source tree and minimal Git object store without copying the
checkout's Git configuration. It refuses placeholder image/configuration pins
before creating build output. On a protected Linux runner it requires a locally
available, reviewed Docker image ID, a credential-free environment, read-only
input mounts, no network, and a bounded temporary container filesystem. Candidate
build scripts never run on the host. The controller compares exact output bytes
with the comparison-only artifact and publishes evidence without overwriting an
existing receipt, only after verified container removal. If container creation
or ownership is uncertain, it does not delete an unverified container.

The static runner's container adapter is injectable only through its library API
for offline fixtures; the CLI always uses the checked local Docker boundary.
Fixture results are not an observed container build. The reviewed image and
configuration pins, protected runner setup and a real isolated-build rehearsal
are still required before this capability can support deployment activation.

The rollback authorization chain module is a shared library used by recovery
execution and finalization. It validates the sanitized schema, staging target,
signer identities and evidence digests, and computes the stable chain digest.
It does not issue an approval or verify signatures by itself. Its callers verify
the broker-signed recovery plan and require that plan to authenticate the same
chain digest before any provider operation. The dedicated contract covers the
schema and digest rules; the reconciliation contract checks that altered chain
files fail before a provider request, even when their local file hash is updated.

From this directory:

```sh
npm test
```

The tests use temporary directories, real local filesystem/Git operations, and
static/mocked service inputs. They do not connect
to GitHub, Netlify, Supabase, Google Drive, or a database. The workflow templates
remain inactive. The default command runs all 26 currently implemented contract
files, including static reproducibility, the bundle, authenticated-UAT refusal,
rollback deposit, reconciliation, private-draft access, control-file,
scheduled-route, external-broker trust-boundary, UAT evidence-publication,
Function recipe-input, comparison-handoff and UAT access-observation contracts.
The foundation contract rejects an omitted or duplicated implemented test.
This default-suite coverage does not replace `npm run test:activation`: the
separate activation gate still checks prerequisites and its closed-world
inventory. Both earlier 23-contract suites and the combined application check
passed locally at the preceding 2026-09-10 component checkpoint. After the two
comparison integrations and AI-review fixes, the combined application check
(including all 25 default contracts) and the separate 25-contract activation
suite were rerun successfully. These results belong to the dirty engineering
checkout, not its unchanged baseline commit. The later recipe-input continuation
reran the combined application check (all 26 default contracts) and separate
26-contract activation suite successfully after final AI review. An
offline passing result does not attest a real builder, broker, UAT run or deployment.
The workflow templates
deliberately contain pinned-SHA placeholders; the tests require the bootstrap
stop and every missing activation prerequisite to remain fail closed until an
independent controller review replaces them with passing implementations.
The Function-output collector assembles canonical archives from bounded regular
files for the exact 11-Function set and compares two disjoint directory snapshots.
It recognizes both legacy named handlers and complete ZISI V2 ESM layouts;
partial V2 output cannot fall back to a legacy handler. These are structural
checks only, not authentication of generated bootstrap or application code.
It does not execute a compiler or establish independent build/source provenance.
The comparison-handoff library now connects that collector to the immutable Git
snapshot and the candidate recipe's two stopped output directories. It checks the
source/input/lock claims against supplied byte constraints, verifies the actual
output inventories, and writes 11 canonical ZIPs to a fresh private directory.
A separate comparison-only manifest is written last after readback and input
revalidation, file/output-directory sync and inode-checked parent-directory sync.
Filesystem failures expose fixed error codes rather than raw input paths.
Existing output is never overwritten; partial failures do not claim a completed
handoff. Fault-injection tests are not physical power-loss certification.
Caller-supplied recipe/lock hashes and observations
are not trusted execution attestations. The manifest explicitly sets
`authorization: false` and `producerEligible: false`; it is not the protected
producer's accepted manifest and does not activate the Function CLI.
The pure UAT access comparator checks exactly 11 roles, one matching access
context row per role, and 132 strict boolean capability observations. The
candidate staging verifier uses it without changing the valid request order or
the later mutation/browser phase. Its contract executes the actual read phase
with offline, in-memory responses and rejects malformed denial values and
multirow contexts. A matching matrix does not prove authenticated identities,
cross-tenant denials or completed UAT; those claims remain explicitly false.
The UAT publication foundation uses a private-directory temporary file, file sync,
atomic no-replace link and directory sync. Its tests cover real concurrent writers
and injected I/O failures; they do not prove physical power-loss recovery. This is
file integrity only, not evidence authenticity, and it is not wired into the
nine-gate authenticated-UAT entrypoint or finalizer. Both live entrypoints remain
fail closed on their unavailable prerequisites.
The `external-broker-trust-boundaries` contract now exercises the real shared
client with ephemeral signing keys and injected transports for all six broker
families. It covers URL pinning before credential acquisition, disabled redirects,
bounded canonical signature verification, signed-request binding for changed
run/ref/nonce/source/artifact/site values, operation and policy binding, freshness,
replay rejection, and credential reflection/serialization refusal. Injected trust
roots and transports do not prove live policy/key provisioning, actual OIDC,
remote authority, or durable compare-and-swap behavior. Family-specific fixtures
remain distinct from observation of an actual external service.
The offline rollback-attestation deposit contract exercises exact hash/
run/nonce/OIDC binding, conflict and replay handling, broker redirect or
unavailability failure, retention-from-deposit enforcement, and absence of raw
inputs from logs, outputs, and artifacts. It cannot attest a real external broker
while the trust values remain placeholders. The missing cross-cutting contract
and success-marker mismatches have been repaired; none were skipped.
All required script paths being present is not proof of
operational completeness: the Function-bundle/UAT entrypoints still reject
unavailable prerequisites, trusted-builder integration and live staging evidence
remain outstanding, and independent human security approval is not supplied by
the offline fixtures or an AI source review.

### Browser UAT foundations — local implementation, not activation

`scripts/controller-uat-browser-read-policy.mjs` now compiles a default-deny boot
request policy for the ten workspaces and eleven roles. It pins exact HTML asset
versions, self-profile selection, role-specific read queries, named read RPCs,
bounded pagination, request bodies and CORS preflights. Date filters preserve the
actual Bangkok/UTC source behavior using a controller-selected `bootInstant`.
Target, role and user inputs are request constraints, not identity authorization.
The source-derived asset test and 110 role/workspace identity-read cases establish
positive coverage; they are not an authenticated role matrix. Interactive writes,
auth/refresh, unreviewed branding and print popups remain denied. In particular,
`account-access: status` is excluded because it can create a missing profile;
this mode requires pre-provisioned identities rather than silently repairing them.

`scripts/controller-uat-browser-transport.mjs` owns a dedicated raw CDP lifecycle.
It rejects existing or unexpected targets and configures interception, service
worker bypass, WebSocket/download guards, Thai locale, Bangkok timezone and the
390×844 viewport before resuming the one owned page. Accepted responses are read
through bounded streams with count/byte/concurrency/deadline limits. The adapter
must implement `send`, `onEvent` and **`terminate`**: termination must force-stop
only the exclusively owned disposable browser and confirm its exit **before**
disconnecting. An ordinary CDP connection close is not an implementation of this
contract. Denied and other non-streaming pauses are explicitly canceled first;
active/opening streams avoid conflicting Fetch operations. Graceful context
disposal/detachment is never used, including on success, because a real local test
showed it could release a denied paused request. Unconfirmed cancellation or
termination is a failure, not a successful cleanup receipt. `navigate()` dispatches
navigation; the caller must separately bind and await actual document readiness.

The protocol contract checks the actual policy-to-transport boundary, including
Chromium's XHR preflight label, 204 responses, burst limits, late events and cleanup
faults. The optional `test-support/uat-browser-local.mjs` additionally exercises
real browser/loopback HTTP behavior, outside the default offline test inventory:

```sh
node test-support/uat-browser-local.mjs --chrome-binary /ABSOLUTE/PATH/TO/headless_shell
```

It requires an explicitly selected binary, launches a fresh private profile with
debugging pipes, supplies no real credentials, serves only inert local content,
and checks recorder state after force termination. The project-matched Playwright
1.55.1 headless shell is Chromium 140.0.7339.186/revision1193. The separately installed
Chrome152 creates unsupported browser-UI targets and is correctly refused; a
hidden-target workaround was tested and reverted because it requires an existing
frame, conflicting with empty-inventory startup. No target check was bypassed.
The fixture's CSP overlay changes worker/frame behavior; it is not proof of exact
published response equivalence. Download denial and bounded accepted bytes are
not OS-level network isolation, disk quotas or complete browser-process egress
coverage. The runtime used locally is not an approved protected-runner pin.

These components are **not wired into the candidate browser matrix or the
nine-gate protected authenticated-UAT entrypoint**. Real application boot and
clinical journeys, isolated synthetic identities/session revocation, approved
runtime/network isolation, recovery and genuine staging evidence remain required.
AI technical review cannot supply independent human security approval. The
protected entrypoint, workflow and deployment gate remain unchanged and inactive.
Protocol behavior was checked against the official
[Fetch](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/),
[IO](https://chromedevtools.github.io/devtools-protocol/tot/IO/) and
[Target](https://chromedevtools.github.io/devtools-protocol/tot/Target/) references;
actual fixture results, not those references alone, establish local compatibility.

The separate local `work/function-builder-toolchain-candidate-2026-09-10` folder
is an unreviewed dependency candidate, not part of the controller's trusted
dependencies. Its initial ZISI 15.4.0 resolution had HIGH transitive TOML findings;
the exact 15.5.1 candidate plus existing application runtime pins now has zero
reported exact-lock audit findings at the recorded audit checkpoint. No candidate
toolchain was installed or executed locally. The separately authorized hosted
rehearsal did install and execute that toolchain in isolated containers and
reported equal output inventories for 11 Functions (166 files); it did not invoke
application handlers or deploy those outputs. The local technical progress
report records the exact lock, audit and hosted-run history. That comparison-only
rehearsal must not supply activation pins or be treated as a reviewed protected
builder.
