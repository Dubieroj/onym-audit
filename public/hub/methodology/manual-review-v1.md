# Methodology: hub manual-review v1

Version 1, 23 September 2026. Published by the Onym audit hub at
`https://foldy.io/audit/hub/` for any auditor who pins it. The auditor who
signs an attestation under this document is the one who applied it; the
hub examines nothing and signs no attestation.

Methodology class `security-review` (Onym Audit.md §2): *manual
examination for vulnerability classes in scope.* No language model takes
part in an examination under this method.

## Subjects and binding

| `artifact.kind` | What is examined | What the attestation binds |
|---|---|---|
| `source` | A repository at one exact commit | `artifact.revision` = the full commit id; the files are read at that commit |
| `deployment` | A running component, through the documents it serves | `artifact.revision` = sha256 of the exact bytes of its signed manifest as fetched |
| `build` | A released file (APK, IPA, archive…) | `artifact.artifactHash` = sha256 of the exact bytes of the file; `artifact.revision` = the commit it claims to be built from |

The attestation says nothing about any other commit, fork, build, deployment,
or state of the subject.

## Evidence rule

Every finding rests on quoted bytes:

- **source** — a path and a line range at the pinned commit, and those lines
  verbatim;
- **deployment** — a served document named by its exact-bytes digest in the
  findings report's `evidence`. A document served as one line (as signed
  canonical JSON is) is read and quoted re-indented: parsed and
  re-serialized with two-space indentation, members in document order.
  Anyone reproduces the quote by re-indenting the same bytes;
- **build** — the file's digest. A finding about a build states what the
  auditor did with those bytes (for example, rebuilt the claimed commit and
  compared digests) in its description.

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

The findings report (`reports/<sha256>.json`, in the auditor's own tree)
holds the artifact, the scope, the coverage statement, the evidence
documents by digest, and every finding with its quote.

## Limits

A manual review can miss defects; `clear` means only that the auditor found
nothing at or above the floor in the declared coverage. Standing exclusions:
anything outside the scope; runtime behaviour beyond the examined bytes;
defects the examination did not find.

## Expiry

180 days.
