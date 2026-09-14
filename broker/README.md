# CNYOS VPS staging OIDC broker

This package is a deliberately inert, dependency-free admission broker. It
binds only to `127.0.0.1:9443` with TLS 1.3 and accepts one exact POST route.
It verifies a GitHub Actions RS256 OIDC token against the pinned GitHub issuer,
audience, workflow, `main` ref, self-hosted runner, run identity, and staging
environment. The controller workflow SHA must also match the root-owned
server-side pin file; GitHub branch protection responses are advisory because
private-repository plan limits may prevent enforcement. It then verifies the producer candidate through an
injected root-owned adapter, reserves a request in an append-only journal, and
invokes separate artifact/deployer adapters. A failed adapter is permanently
recorded as failed, so the same request cannot be replayed.

No default adapter can deploy anything. The production entrypoint refuses
readiness unless the TLS files, CA, state directory, credential file, and all
three root-owned executable adapters exist with safe permissions. The adapters
must be separately reviewed and installed on the VPS; this repository does not
pretend that they are present.

## Required VPS paths

The systemd template uses these paths:

```text
/etc/cnyos-broker/tls/server.crt       root:root, not group/world writable
/etc/cnyos-broker/tls/server.key       root:root, not group/world writable
/etc/cnyos-broker/ca.pem               root:root, not group/world writable
/etc/cnyos-broker/github-token        root:root, mode 0600; never printed
/etc/cnyos-broker/controller-workflow-sha
                                      root:root, mode 0600; exact reviewed 40-character commit SHA
/var/lib/cnyos-broker                  root:root, mode 0700
/opt/cnyos-staging-controller/broker/adapters/candidate-verifier.mjs
/opt/cnyos-staging-controller/broker/adapters/artifact-fetcher.mjs
/opt/cnyos-staging-controller/broker/adapters/deployer.mjs
```

The unit deliberately pins the Node.js runtime already installed on the CNYOS
VPS at `/opt/cnyos-validation/node-v24.20.0-linux-x64/bin/node`. Replacing or
upgrading that runtime requires a separately reviewed controller change.

The executable adapters receive the validated JSON on stdin and must return
exactly JSON containing `{"ok":true}`. Their stderr is discarded and their
stdout is size-limited. They must implement their own artifact digest and
release-request binding checks; a successful response is not an independent
security approval.

## Adapter boundary (staging only)

The reference adapters in `broker/adapters/` are fail-closed and are intended
to be installed by a root-owned VPS service account. The candidate verifier
accepts the complete admission body, not an untrusted subset. It requires the
exact SHA in the root-owned `/etc/cnyos-broker/controller-workflow-sha` pin
file and binds the controller run's `head_sha` to that pin. It checks the
private controller repository and queries `main` branch protection through the
GitHub API as advisory evidence; a plan-limited API response is not treated as
enforcement. It separately checks that the public producer repository's
`deploy-vps-staging.yml` run completed successfully at the requested commit.
The GitHub token is read only from `CNYOS_GITHUB_TOKEN_FILE`; that file must be
root-owned and mode 0600 (or stricter), and is never printed.

The artifact fetcher repeats the producer run and artifact metadata checks,
downloads the GitHub Actions artifact with credentials removed on every
redirect, and accepts exactly these three regular files:

```text
cnyos-static-<40-character-source-commit>.tar.gz
release-request.json
SHA256SUMS
```

It rejects traversal, symlink/device entries, duplicate/overlapping ZIP
ranges, ZIP bombs over the fixed limits, expired artifacts, mismatched run or
source bindings, and digest mismatches. Files are extracted into a 0700 spool
directory and the returned descriptor contains only that directory and fixed
names. The deployer revalidates this descriptor and the release packet before
using it.

The deployer never executes candidate code or candidate configuration. It
extracts only the static tarball, verifies `runtime-publish-manifest.json` and
`deploy-manifest.json`, and copies the trusted templates from `broker/runtime/`
into an immutable commit-named release directory. Docker Compose is invoked
with `spawn` and `shell:false`; the web image is loopback-only and uses the
existing native Caddy route. A failed health check attempts to bring the
previous release back, and a durable request receipt prevents a completed
request from being replayed. No production target, Caddy whole-file cutover,
raw-volume backup, or human security approval is implemented by these
adapters.

Example installation (performed separately on the VPS, after review):

```text
install -d -o root -g root -m 0755 /opt/cnyos-staging-controller/broker/adapters
install -o root -g root -m 0755 broker/adapters/candidate-verifier.mjs /opt/cnyos-staging-controller/broker/adapters/candidate-verifier.mjs
install -o root -g root -m 0755 broker/adapters/artifact-fetcher.mjs /opt/cnyos-staging-controller/broker/adapters/artifact-fetcher.mjs
install -o root -g root -m 0755 broker/adapters/deployer.mjs /opt/cnyos-staging-controller/broker/adapters/deployer.mjs
install -o root -g root -m 0644 broker/adapters/common.mjs /opt/cnyos-staging-controller/broker/adapters/common.mjs
install -o root -g root -m 0644 broker/adapters/deployer-lib.mjs /opt/cnyos-staging-controller/broker/adapters/deployer-lib.mjs
install -d -o root -g root -m 0700 /var/lib/cnyos-broker/spool
```

The VPS must provide a root-owned token file, CA/TLS files, and the exact
reviewed controller workflow pin before the systemd unit's readiness checks
can make `/readyz` healthy. Contract tests use
fixtures and mocked GitHub responses only; passing them is not live staging
evidence or a release authorization.

After installing this exact controller commit, update the pin atomically and
restart the broker. Never use a branch name or an unreviewed SHA:

```bash
install -o root -g root -m 0600 /path/to/reviewed/controller-workflow-sha /etc/cnyos-broker/controller-workflow-sha
systemctl restart cnyos-staging-broker.service
curl --fail --silent --show-error --cacert /etc/cnyos-broker/ca.pem https://127.0.0.1:9443/readyz
```

The pin is an independent server-side trust anchor; it does not create a
human security approval and does not make Production eligible.
