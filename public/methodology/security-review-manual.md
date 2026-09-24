# Methodology: security-review-manual v1

Auditor: onym audit (`onym:component:onym-audit`). Version 1, 24 September 2026.
Methodology class `security-review` (Onym Audit.md §2): *manual examination
of code for vulnerability classes in scope.*

No language model takes part in an examination under this method. The
auditor reads the code and records every finding by hand.

## Subject and binding

A repository at one exact commit (`artifact.kind = "source"`,
`artifact.revision` = the full commit id), checked out and verified to be
that commit before the examination starts. The attestation says nothing
about any other commit, fork, build, or deployment.

## Evidence rule

The same rule as the LLM-assisted method: every finding cites a path and a
line range, and quotes those lines verbatim. The quote is checked
mechanically against the pinned bytes when the finding is recorded; a
finding whose quote is not found there cannot be recorded.

## Coverage

Before signing, the auditor states what was examined and what was not. The
"not examined" list travels with the attestation as exclusions.

## From findings to a result class

| Findings | Result class |
|---|---|
| Any `critical` | `fail` |
| Any `high`, `medium`, or `low` | `findings-noted` |
| None at or above `low`, coverage declared complete | `clear` |
| Coverage partial | `inconclusive` |

`severityFloor` is `low` on scale severity-v1.

## Evidence published

The findings report (`reports/<sha256>.json`) holds the scope, the coverage
statement, and every finding with its quote. Findings the auditor withdrew
before signing are listed with the reason.

## Limits

A manual review can miss defects; `clear` means only that the auditor found
nothing at or above the floor in the declared coverage. Standing exclusions:
anything outside the scope; runtime behaviour (the review reads source at
one commit and executes nothing); dependencies not vendored in the
repository; defects the examination did not find.

## Expiry

180 days.
