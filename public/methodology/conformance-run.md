# Methodology: conformance-run v1

Auditor: AUDITOR_NAME (`AUDITOR_COMPONENT`). Version 1, 24 September 2026.
Methodology class `conformance-run` (Onym Audit.md §2): *a component passed
a named, versioned conformance suite.*

## What is examined

A **named, versioned suite** is run black-box against the subject exactly as
a relying client would meet it: public HTTPS documents, fetched without
credentials, under the bounds of Discovery-Static-Ed25519 §7. The run is
mechanical; the auditor's judgment is limited to the choices this document
fixes in advance.

Each check in a suite names the clause it tests, its level (`MUST` or
`SHOULD`), and one outcome: `pass`, `fail`, `not-applicable`, or
`inconclusive` (the check could not complete — for example a network error
— and says why).

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
| A `MUST` check fails because the component as served would be rejected by a conforming client, or a `MUST` obligation is not met | `high` |
| A `MUST` obligation is met only partially, or its failure depends on circumstances outside the run | `medium` |
| A `SHOULD` check fails | `low` |
| An observation outside the suite, recorded by the auditor | `informational` |

The attestation's `severityFloor` is `low`: a `clear` result means no check
failed at `SHOULD` level or above. `findingsSummary` counts findings by
severity.

## Binding

A conformance run examines a **deployment**. The attestation binds the
component's signed manifest (`artifact.revision`, its exact-bytes digest)
and, when the result depends on a further served document, that document
(`artifact.artifactHash`) — for a Discovery provider, the latest snapshot
of the examined catalog. The findings report lists every document fetched
with its digest, so the run can be re-checked against the same bytes.

## Evidence

The findings report is the suite's canonical JSON output: suite id and
version, run time, every check with clause, level, outcome, and detail, and
every fetched document's URI, digest, and size. It is published
content-addressed at `reports/<sha256>.json`.

## Expiry

A conformance run of a deployment expires after **30 days**: a deployment
changes without asking, and a month-old run says little about today.

## Suites

| Suite id | Version | Subject |
|---|---|---|
| `onym:conformance-suite:discovery-static-ed25519-provider` | 1.0.0 | A Discovery provider deployment under Discovery-Static-Ed25519 — see `scopes/discovery-static-ed25519-provider.md` |
