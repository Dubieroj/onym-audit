# Methodology: hub conformance-run v1

Version 1, 23 September 2026. Published by the Onym audit hub at
`https://foldy.io/audit/hub/` for any auditor who pins it. The auditor who
signs an attestation under this document is the one who ran the suite,
read its report, and chose to sign it; the hub signs no attestation.

Methodology class `conformance-run` (Onym Audit.md §2): *a component passed
a named, versioned conformance suite.*

## What is examined

A named, versioned suite is run black-box against the subject exactly as a
relying client would meet it: public HTTPS documents, fetched without
credentials. On the hub the suite runs on the hub's server (suite id and
version are in every report), and the report is returned to the auditor's
browser unchanged. The auditor's judgment is limited to the choices this
document fixes in advance.

Each check names the clause it tests, its level (`MUST` or `SHOULD`), and
one outcome: `pass`, `fail`, `not-applicable`, or `inconclusive`.

## From checks to a result class

| Outcome of the run | Result class |
|---|---|
| Any `MUST` check fails | `fail` |
| No `MUST` fails, but a `MUST` check is `inconclusive` | `inconclusive` |
| Only `SHOULD` checks fail | `findings-noted` |
| Every check passes or is `not-applicable` | `clear` |

## Severity (scale severity-v1)

| Finding | Severity |
|---|---|
| A `MUST` check fails | `high` |
| A `SHOULD` check fails | `low` |

`severityFloor` is `low`. `findingsSummary` counts failed checks by
severity.

## Binding

A conformance run examines a **deployment**. The attestation binds the
component's signed manifest (`artifact.revision`, its exact-bytes digest)
and, when the run examined exactly one catalog snapshot, that snapshot
(`artifact.artifactHash`).

## Evidence

The findings report, published content-addressed at
`reports/<sha256>.json` in the auditor's tree, holds `suiteReport` — the
suite's own output, unedited: suite id and version, run time, every check
with clause, level, outcome, and detail, and every fetched document's URI,
exact-bytes digest, size, and role. Anyone can re-run the suite and compare
against the same bytes.

## Expiry

30 days: a deployment changes without asking.

## Suites

| Suite id | Version | Subject |
|---|---|---|
| `onym:conformance-suite:discovery-static-ed25519-provider` | 1.0.0 | A Discovery provider deployment under Discovery-Static-Ed25519 — see `https://foldy.io/audit/scopes/discovery-static-ed25519-provider.md` |
