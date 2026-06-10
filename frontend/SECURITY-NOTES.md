# Frontend Security Notes

Triage log for dependency advisories that the `npm audit` CI gate
treats as non-blocking. One entry per advisory; remove the entry
when the finding is resolved (dep bumped, advisory withdrawn, or
risk model changes).

## Open advisories

### GHSA-67mh-4wv8-2f99 — esbuild dev server CORS (×2, via vite)

- **Severity (npm registry):** moderate
- **Reachable via:** `esbuild` (transitively pulled by `vite`)
- **Impact in this project:** dev-only. The advisory describes a
  cross-origin request issue against the `esbuild` development
  server — i.e., `vite dev`. The production bundle is built with
  `vite build`, which doesn't run the dev server at all; the
  vulnerability has no path into deployed artifacts.
- **Why we are not patching:** the available fix is `vite@8`, which
  is a major version bump (breaking changes against the current
  `vite@5` config). Pulling that in for a dev-only issue is poor
  cost/benefit — particularly when the dev server only runs on a
  developer's localhost.
- **Action:** revisit when we next routinely upgrade vite (e.g.
  during a tooling refresh), or sooner if the advisory's scope is
  rescored to cover production.

## Conventions

- Keep entries brief and decision-focused. The advisory page itself
  has the technical detail; this file records what we decided and
  why.
- New advisories with `high` or `critical` severity must be fixed
  (or escalated) — the CI gate at `.github/workflows/npm-audit.yml`
  fails on those.
- New `moderate` advisories should land here with a triage decision
  before merging the PR that would otherwise expose them.
