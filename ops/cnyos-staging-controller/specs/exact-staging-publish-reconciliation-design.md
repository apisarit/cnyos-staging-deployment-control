# Exact staging publish reconciliation

## Acceptance criteria

- Persist a source/tree/artifact/target/baseline-bound intent before invoking
  `netlify deploy --prod` against the fixed isolated staging site.
- Treat CLI success, timeout and non-zero exit as observations, never as the
  authoritative canonical outcome.
- Always read the Netlify site and current deploy after the attempt. A candidate
  passes only when both canonical and immutable deploy origins serve the exact
  expected source tree and runtime-manifest digest.
- Preserve `UNCERTAIN` when the attempt may have taken effect but its deploy ID
  or canonical state cannot be resolved. A known terminal failed/non-canonical
  deploy is `FAIL`; an exact canonical candidate is `PASS`.
- Never retry or roll back automatically. Recovery remains a separately
  authorized action.
- Run role-separated browser UAT only after publish reconciliation is `PASS`.
  Always retain secret-free terminal evidence and fail the workflow unless both
  publication and UAT pass.
- Before either of the two permitted OPD browser writes, parse the JSON body and
  require the synthetic encounter ID. Any patient, practitioner, actor or user
  identifier that appears anywhere in the body must match the verified run
  scope. Reject malformed, oversized or ambiguous bodies before `route.fetch`.
- Reserve both permitted writes in one run-level ledger shared by every browser
  context. Retained evidence lists all contexts, including contexts with zero
  writes; a third attempted write is blocked before transport.

## Boundaries

- Frontend: Playwright request interception validates the request body and
  preserves one shared two-write budget across save, reopen and verify contexts.
- Backend/provider: Netlify API state and served immutable bytes are the
  authority for publish reconciliation; CLI output is supporting evidence only.
- Security: fixed staging IDs and production denylist remain hard-coded; only
  hashes and non-secret identifiers enter retained evidence; no patient data,
  credentials, auto-retry or auto-rollback is allowed.

## Terminal states

- `PASS`: exact candidate is canonical and hosted UAT passed.
- `FAIL`: a known attempted deploy is terminal/non-canonical, or UAT/evidence
  validation failed after a verified publish.
- `UNCERTAIN`: canonical or attempted mutation state cannot be proved. This
  takes precedence over other failures and blocks retry until readback resolves
  it.
