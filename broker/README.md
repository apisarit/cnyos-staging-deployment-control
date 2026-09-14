# CNYOS VPS staging OIDC broker

This package is a deliberately inert, dependency-free admission broker. It
binds only to `127.0.0.1:9443` with TLS 1.3 and accepts one exact POST route.
It verifies a GitHub Actions RS256 OIDC token against the pinned GitHub issuer,
audience, workflow, protected `main` ref, self-hosted runner, run identity, and
staging environment. It then verifies the producer candidate through an
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
/etc/cnyos-broker/github-app-credentials.json
/var/lib/cnyos-broker                  root:root, mode 0700
/usr/local/libexec/cnyos-staging-candidate-verifier
/usr/local/libexec/cnyos-staging-artifact-fetcher
/usr/local/libexec/cnyos-staging-deployer
```

The executable adapters receive the validated JSON on stdin and must return
exactly JSON containing `{"ok":true}`. Their stderr is discarded and their
stdout is size-limited. They must implement their own artifact digest and
release-request binding checks; a successful response is not an independent
security approval.
