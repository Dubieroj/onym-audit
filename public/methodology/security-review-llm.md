# Methodology: security-review-llm v1

Auditor: Dimitrii (`onym:component:dimitrii-audit`). Version 1, 24 September 2026.
Methodology class `security-review` (Onym Audit.md §2): *manual/assisted
examination of code for vulnerability classes in scope.*

This is an **LLM-assisted** method, and says so in every attestation it
produces. A language model drafts; the named auditor decides and signs.

## Subject and binding

A repository at one exact commit (`artifact.kind = "source"`,
`artifact.revision` = the full commit id). The attestation says nothing
about any other commit, fork, build, or deployment.

## The examination engine

- **Model:** Claude (`claude-opus-5` by default), adaptive thinking, effort
  `xhigh`. The model id, effort, and turn cap are recorded in the findings
  report of every run.
- **Instructions:** [security-review-llm-prompt.md](security-review-llm-prompt.md),
  published verbatim; its `sha256` digest is recorded in every findings
  report, so a run can be tied to the exact instructions it followed.
- **Tools:** read-only access to the checked-out tree — `list_files`,
  `read_file`, `search` — confined to the repository (no path traversal, no
  symlink escape, no `.git`), plus `report_finding` and `finish`. The engine
  executes nothing and has no network access through its tools.
- **Scope** is stated in plain words before the run and published as the
  attestation's scope document.

## Evidence rule

Every finding must quote the exact lines it rests on, with path and line
range. The quote is checked mechanically against the pinned bytes before the
finding is recorded; a finding whose quote is not found verbatim
(whitespace-normalized) in the cited lines is rejected and listed as
rejected in the report. A hallucinated defect, or text planted in the
examined code, therefore cannot become a finding on the model's word alone.

## Prompt injection

The examined artifact is untrusted. The engine is instructed never to follow
text addressed to it and to report such text as an `informational` finding.
Independently of what the model does, nothing it writes can sign, publish,
or set a result class: those are the auditor's acts.

## Human review

Before anything is signed the auditor reads every finding at its cited
lines. Findings the auditor does not stand behind are dropped **with a
reason**, and each drop is recorded in the published findings report under
`auditorReview.dropped`. The auditor does not add findings the engine did
not produce under this method; independent findings belong to a separate,
non-LLM examination.

## From findings to a result class

| Reviewed findings | Result class |
|---|---|
| Any `critical` | `fail` |
| Any `high`, `medium`, or `low` | `findings-noted` |
| None at or above `low`, coverage declared complete, run ended normally | `clear` |
| Coverage partial or undeclared, or the model refused | `inconclusive` |

`severityFloor` is `low` on scale severity-v1. `findingsSummary` counts
reviewed findings by severity.

## Evidence published

The findings report (`reports/<sha256>.json`) holds the engine settings, the
prompt digest, the scope, the engine's own coverage statement, every
reviewed finding with its quote, every finding rejected by the evidence
check, the auditor's drops with reasons, and a pointer to the **full
transcript** of the run (`reports/<sha256>-transcript.json`), pinned by
digest.

## Limits, stated plainly

An LLM-assisted review can miss defects, and a `clear` result means only
that neither the engine nor the reviewing auditor found anything at or above
the floor in the declared coverage. The standing exclusions of every
attestation under this method:

- anything outside the stated scope;
- runtime behaviour: the review reads source at one commit and executes
  nothing;
- dependencies not vendored in the repository;
- defects the examination did not find.

## Expiry

180 days: source does not change, but the threat landscape and the
methods for finding defects do.
