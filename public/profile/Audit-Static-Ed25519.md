---
status: draft
proposed: Dimitrii, with Claude
date: 24.09.2026
---

# Onym Audit: Static Attestation / Ed25519 Implementation Profile

**Implementation profile draft 0.1 — September 2026**

> This profile maps the technology-neutral audit boundary onto signed
> static JSON files served over HTTPS: an Ed25519-signed auditor manifest,
> immutable attestations bound to exact bytes, and a status list re-signed
> on a schedule by a delegated key, so the auditor's own key can stay
> offline while freshness stays live.

This document is a concrete implementation of
[Audit.md](https://github.com/onymchat/onym-system/blob/main/audit/Audit.md),
which remains authoritative for roles, authority, economics, and error
semantics. Audit.md §15 states that no concrete profile existed and names
`conformance-run` as the natural first methodology; this profile carries all
five methodology classes and ships the first `conformance-run` methodology
with it.

It deliberately reuses the encoding, identifier, and URI rules of
[Discovery-Static-Ed25519.md](https://github.com/onymchat/onym-system/blob/main/discovery/Discovery-Static-Ed25519.md)
(§2, §3, §7) instead of restating them, so that one canonicalizer and one
URI checker serve both seats — and so a Discovery provider citing
attestations (Audit.md §10) verifies them with code it already has.

The document distinguishes **profile requirements** (normative) from
**gaps** (§11 is the single source of truth for implementation status).

## 1. Conformance declaration

| Abstract concept (Audit.md) | This profile's mapping |
|---|---|
| Auditor identity | `onym:key:<64 lowercase hex Ed25519 public key>` — the manifest `operator` |
| Audit profile (§5.1) | Static `profile.json`, signed by the profile publisher |
| Auditor manifest (§5.2) | Static `manifest.json`, self-signed by the operator key |
| Audit order (§5.3) | JSON document signed by auditor, subject, and sponsor (§4.3) |
| Attestation (§5.4) | Static `attestations/<attestationId>.json`, immutable, operator-signed |
| Revocation (§5.5) | Static `revocations/<attestationId>.json`, operator-signed |
| Signed status list (§5.5) | Static `status.json`, signed by a **delegated status key** (§5.2) |
| Subject response (§5.7.5) | `responses/<attestationId>/<responseId>.json`, signed by the subject's operator key |
| `query-status` (§6) | Full-list retrieval only; **no per-ID endpoint exists** (Audit.md §7.8) |
| `verify` (§6) | Local, per §6 of this profile |
| Signature suite | Ed25519 over canonical bytes (Discovery-Static-Ed25519 §3) |
| Digest | `sha256:<64 lowercase hex>` over exact published bytes |
| Transport | HTTPS static files; two write endpoints (`POST orders`, `POST responses`) |

Every document's version field is exactly `1`; any other value is invalid
for the document carrying it. The profile identifier is:

```text
onym:audit-profile:static-ed25519-v1
```

Out of scope for v1, stated so their absence reads as a decision:
key rotation statements (re-publishing under a new key is a new auditor
identity; see §11), transparency logs for status lists, encrypted
delivery of embargoed reports (reports under embargo are simply not
published — `findingsReport` is null), and payment rails (offers are
published; settlement follows the whitepaper's seat-payment model outside
this profile).

## 2. Identifiers

Identifiers, digests, and timestamps follow Discovery-Static-Ed25519 §2
exactly: `onym:key:<hex>`, `onym:component:[a-z0-9-]{1,64}`,
`sha256:<hex>` over **exact published bytes**, RFC 3339 UTC timestamps with
`Z` and second precision. Additionally:

- `attestationId`, `orderId`, `responseId`: `[A-Za-z0-9_-]{16,128}`, chosen
  by the issuer, never reused. An attestation's file name is its id.
- Offer ids: `[a-z0-9-]{1,64}`.
- A git revision is the full 40- (or 64-) character lowercase hex commit id.

## 3. Canonical encoding and signing

Signing bytes are produced **exactly** as in Discovery-Static-Ed25519 §3:
structural removal of the top-level signature field only, compact
re-serialization with keys sorted by UTF-8 byte order at every depth, the
pinned escaping set, duplicate keys invalid, numbers restricted to
non-negative integers within 2^53 − 1. Published bytes are the canonical
serialization **including** the signature field, which makes every served
file byte-deterministic.

The reference implementation proves agreement with the Discovery reference
by reproducing its published canonical, case-divergence, escaping, and
cross-language vectors byte-for-byte, and by verifying its signed fixtures
and the live Onym provider manifest (§10).

Two refinements:

1. **Multi-party orders.** An `AuditOrder` carries `signatures`, an array of
   `{role, key, signature}` objects. Every party signs the order's canonical
   bytes with the top-level `signatures` field removed, so signatures are
   independent and can be added in any order.
2. **Detached signatures.** Every signed static file MAY have a
   `<name>.json.sig` sibling holding the embedded signature as standard
   padded base64 plus one newline. Agreement is defined after base64
   decoding; disagreement fails closed.

## 4. Document shapes

Unknown keys are rejected at **every** level of every document in this
profile — including keys that differ only by letter case from a known key,
which a case-insensitive decoder would otherwise silently accept (fixture
`invalid-case-variant-key.json`). A signed claim the relying client cannot
render is a claim the user never saw.

### 4.1 Audit profile — `profile.json`

Audit.md §5.1 verbatim, with `specification` pinned as
`{uri, digest}` of this document and `publisher` naming the signing key:

```json
{
  "profileVersion": 1,
  "profileId": "onym:audit-profile:static-ed25519-v1",
  "interface": "onym-audit-v1",
  "operations": ["offer-engagement", "accept-order", "issue-attestation",
                 "supersede-attestation", "revoke-attestation", "query-status"],
  "methodologyClasses": ["security-review", "conformance-run", "build-provenance",
                         "privacy-review", "availability-measurement"],
  "attestationSchema": "onym-attestation-v1",
  "resultClasses": ["clear", "findings-noted", "fail", "inconclusive"],
  "freshness": "onym:audit-freshness:signed-status-list-v1",
  "errorSchema": "onym-audit-errors-v1",
  "specification": {"uri": "https://…/profile/Audit-Static-Ed25519.md", "digest": "sha256:…"},
  "publisher": "onym:key:<hex>",
  "signature": "<base64-ed25519>"
}
```

### 4.2 Auditor manifest — `manifest.json`

Audit.md §5.2 with these refinements, each for a stated reason:

| Field | Refinement | Why |
|---|---|---|
| `displayName`, `contact` | Required | §5.2 "declaring its identity": a key is not a name someone answers for |
| `independencePolicy`, `unsolicitedPolicy`, `liability` | `{uri, digest}` instead of hash-or-url | The pinned bytes are the policy; a URL alone can change under the signature |
| `auditProfile` | `{uri, digest}` beside `auditProfileId` | The profile document itself is pinned |
| `severityScale` | Required `{uri, digest}` | §5.4.3 makes the scale part of every judgment; the auditor declares one |
| `privacyProfile` | Required `{uri, digest}` | What the status endpoint and write endpoints record (Audit.md §7.8) |
| `statusKey` | Required `onym:key`, ≠ `operator` | §5.2 of this profile |
| `methodologies[].specification` | `{uri, digest}` | Methodology versions are content-addressed |

`offers` lists offer ids; each offer is published at
`<manifest directory>/offers/<offerId>.json`. `validUntil` is enforced with
the 10-minute skew allowance; an expired manifest is
`auditor_manifest_invalid`.

**Delegated status key.** The status list is the only document that must be
re-signed on a schedule (Audit.md §5.5, §8.7). Signing it with the operator
key would force that key online. The manifest therefore names a separate
`statusKey`, which signs **only** status lists. It cannot issue, alter, or
revoke an attestation: those are operator-signed and the status list pins
each attestation and revocation by digest (§5.1). A stolen status key can at
worst withhold freshness or claim a revoked attestation active — and the
latter is detectable, because the operator-signed revocation document
remains published and relying clients that fetch it reject the claim.

### 4.3 Audit order

Audit.md §5.3 with:

- `artifact` as in §4.4;
- `scope` as `{uri, digest}` — "exact and content-addressed before work
  begins" (§5.3.2);
- `cooperation` — the subject's cooperation duties as text (§5.3.4);
- `fee.model` from a **closed set**: `fixed-verdict-independent`,
  `pro-bono`. There is no field in which a result-contingent fee can be
  written; any other model or any extra fee field is invalid (Audit.md
  acceptance criterion 7; fixture `invalid-order-contingent-fee.json`);
- `signatures` per §3. An order is complete when the auditor, the subject,
  and the sponsor (`key` equal to `sponsor`) have all signed.

### 4.4 Attestation

Audit.md §5.4, all fields kept, with these additions:

```json
{
  "attestationVersion": 1,
  "attestationId": "…",
  "auditor": "onym:component:…",
  "auditorKey": "onym:key:…",
  "subject": "onym:component:…",
  "subjectOperator": "onym:key:…",
  "artifact": {"kind": "deployment", "source": "https://…/manifest.json",
               "revision": "sha256:…", "artifactHash": null},
  "methodologyClass": "conformance-run",
  "methodology": {"uri": "…", "digest": "sha256:…"},
  "scope": {"uri": "…", "digest": "sha256:…"},
  "scopeSummary": "…",
  "exclusions": ["…"],
  "result": "fail",
  "severityScale": {"uri": "…", "digest": "sha256:…"},
  "severityFloor": "low",
  "findingsReport": {"uri": "…", "digest": "sha256:…"},
  "findingsSummary": {"high": 1},
  "engagement": "unsolicited",
  "sponsor": "onym:key:…",
  "sponsorName": "…",
  "relationships": "…",
  "orderRef": null,
  "unsolicited": {"policy": "sha256:…", "subjectContact": "mailto:…",
                  "subjectNotifiedAt": "…", "embargoUntil": null},
  "issuedAt": "…",
  "expiresAt": "…",
  "supersedes": null,
  "status": "https://…/status.json",
  "signature": "…"
}
```

**Artifact kinds.** Audit.md binds `source`, `revision`, and
`artifactHash` without saying what they mean for a running service. This
profile fixes three kinds:

| `kind` | `source` | `revision` | `artifactHash` |
|---|---|---|---|
| `source` | repository HTTPS URI | full git commit id | `null` |
| `build` | repository HTTPS URI | full git commit id | `sha256` of the distributed bytes (required) |
| `deployment` | HTTPS URI of the component's **signed manifest** | `sha256` of that manifest's exact bytes | `null`, or `sha256` of the one further served document whose state the result depends on |

For a deployment, the component manifest is what a relying client is
"actually about to use" (Audit.md §6): any change to the deployment's
declared identity, endpoints, keys, or policies changes its digest. But a
deployment also serves documents that change without the manifest
changing — a Discovery provider's catalog snapshot is the example. When the
result depends on such a document, the attestation pins it in
`artifactHash`, and it applies **only while those exact bytes are served**:
a republished snapshot makes the attestation a non-match, so a `fail`
cannot follow a fixed deployment, nor a `clear` a broken one (Audit.md
§3.4, §13.7). Every document the examination read is listed with its
digest in the findings report.

**Other additions.** `auditorKey` names the signing key (it must equal the
manifest's `operator`). `subjectOperator` is the subject's operator key,
which is the only key whose `SubjectResponse` is accepted. `scopeSummary`
and inline `exclusions` make §5.4.2 renderable: a relying party must be
able to read what was and was not examined without fetching anything.
`sponsorName` accompanies `sponsor`. `relationships` is `"none"` when there
are none — never empty.

**Normative checks** (all enforced at parse time):

1. `clear` and `findings-noted` require both `severityScale` and
   `severityFloor` (§5.4.3); `findingsSummary` buckets are levels of the
   named scale or `resolved`.
2. `expiresAt` is mandatory for every class except `build-provenance`
   (§5.4.5) and must be after `issuedAt`.
3. `engagement: "commissioned"` requires `orderRef` (the digest of the
   complete order) and no `unsolicited` block.
4. `engagement: "unsolicited"` requires `orderRef: null` and an
   `unsolicited` block recording the published policy digest, the subject
   contact used, and `subjectNotifiedAt` **not later than** `issuedAt`
   (§5.7.1–§5.7.3).

### 4.5 Severity scale — `severity-v1.json`

An ordered scale, highest first: `critical`, `high`, `medium`, `low`,
`informational`, each with a published definition. `severityFloor` and
`findingsSummary` use its level names.

### 4.6 Revocation

Audit.md §5.5 verbatim, plus `auditorKey`, with `detail` as
`{uri, digest}` or `null` and `reason` from the closed set
`methodology-error`, `new-information`, `compromise-of-auditor-key`,
`withdrawal`. `statusEpoch` is the Unix time at which the revocation was
signed; the status list that first carries it has an epoch no lower.

### 4.7 Subject response

```json
{
  "responseVersion": 1,
  "responseId": "…",
  "attestationId": "…",
  "attestation": "sha256:<exact bytes of the attestation answered>",
  "subject": "onym:component:…",
  "respondent": "onym:key:<must equal the attestation's subjectOperator>",
  "issuedAt": "…",
  "text": "<at most 8000 bytes, untrusted>",
  "signature": "…"
}
```

The auditor must accept and publish any valid response (Audit.md §5.7.5)
and cannot edit it: responses are immutable, and a second response is a new
`responseId`.

## 5. Serving and freshness

### 5.1 Layout

All paths are relative to the manifest's directory:

```text
manifest.json(.sig)            profile.json(.sig)      profile/Audit-Static-Ed25519.md
status.json(.sig)              severity-v1.json        privacy.md
policies/{independence,unsolicited,liability}.md
methodology/<class>.md         scopes/<scope>.md       offers/<offerId>.json
attestations/<attestationId>.json(.sig)
revocations/<attestationId>.json(.sig)
responses/<attestationId>/<responseId>.json
reports/<sha256-hex>.json      (content-addressed findings reports)
```

Files are served byte-for-byte over HTTPS with no cookies and no
authentication. Attestations, revocations, responses, and reports are
never modified after publication.

### 5.2 The status list

```json
{
  "statusVersion": 1,
  "auditor": "onym:component:…",
  "auditorKey": "onym:key:<operator>",
  "statusKey": "onym:key:<delegated>",
  "statusEpoch": 1790000000,
  "issuedAt": "…",
  "nextUpdate": "…",
  "entries": [{
    "attestationId": "…",
    "attestation": {"uri": "…", "digest": "sha256:…"},
    "state": "active | superseded | revoked | expired",
    "supersededBy": null,
    "revocation": null,
    "responses": [{"uri": "…", "digest": "sha256:…"}]
  }],
  "signature": "<statusKey signature>"
}
```

- It covers **every** attestation the auditor has published, so a single
  fetch answers `query-status` for all of them and reveals nothing about
  which one a client cares about (Audit.md §7.8). There is no per-ID query
  endpoint in this profile.
- `statusEpoch` is the Unix time of signing, never lower than any epoch the
  auditor published before or any revocation's `statusEpoch`. Clients retain
  the highest epoch seen per auditor and reject a lower one
  (`status_rollback`).
- `nextUpdate` lies in `(issuedAt, issuedAt + 7 days]`. The auditor re-signs
  at least every 6 hours with `nextUpdate = issuedAt + 48 hours`, so a day
  of host outage does not make any attestation stale.
- A list is **stale** once `now > nextUpdate + 10 minutes`. A stale list is
  never read as `active` (Audit.md §5.5); clients degrade to
  `status-unknown` (§6).
- `state` and references must agree: `revoked` ⇔ `revocation` set,
  `superseded` ⇔ `supersededBy` set.
- **Stapling:** any party may serve the latest `status.json` beside a
  component manifest. It verifies against the auditor manifest alone.

### 5.3 Write endpoints

Relative to the manifest directory, both bounded and rate-limited:

- `POST orders` — `accept-order` intake. Body: an `AuditOrder` signed by
  its subject and sponsor (≤ 64 KiB). A valid order is queued for the
  auditor's review, never auto-accepted; the reply is `202` with the
  order digest. The auditor countersigns offline after checking its
  independence policy (Audit.md §8.4). Queued orders are not published.
  A subject that cannot host its own scope document may send an envelope
  `{"order": …, "scopeText": …, "contact": "mailto:…"}`: the order then pins
  `scopes/order-<orderId>.md` on the auditor's base URI, `scopeText` must hash
  to that pin, and the auditor publishes it byte-for-byte on acceptance. The
  contact is kept with the queued order and never published.
- `POST responses` — the subject's right of reply. Body: a
  `SubjectResponse` (≤ 16 KiB) verified against the published attestation
  and its `subjectOperator`. A valid response is published immutably and
  the status list is re-signed at once, so conforming clients display it
  beside the attestation from the next fetch.

## 6. Relying-client verification

Given an attestation, the auditor manifest, optionally a status list, and
the **target** — the exact component the client is about to use:

1. Verify the auditor manifest (schema, operator signature, `validUntil`).
2. Verify the attestation (schema, §4.4 checks, signature by
   `auditorKey`), and require `auditorKey` = manifest `operator` and
   `auditor` = manifest `componentId`.
3. **Match exactly.** `kind`, `source`, `revision`, and `artifactHash` must
   all be equal — for a deployment that pins a served document, the client
   supplies the digest of the copy it is about to use. Anything else is
   `artifact_mismatch`
   and renders as **no attestation**, with an optional note that another
   revision was attested — never a degraded pass (Audit.md §7.3).
4. Verify the status list against the manifest's `statusKey`, apply epoch
   monotonicity and freshness, and find the entry, whose `attestation.digest`
   must equal the digest of the attestation bytes.
5. Decide: `revoked` → stop displaying, show the reason class;
   `superseded` → re-resolve and show the successor; `expired` (by the list
   or by `expiresAt` locally) → shown as expired.
6. Fetch listed subject responses and display each valid one beside the
   attestation.
7. Apply the relying party's issuer policy: credited issuers render
   normally; uncredited ones are either labelled as uncredited or omitted —
   the user's choice, with no hardcoded mandatory issuer (Audit.md §7.7).

Display decisions:

| Decision | Meaning |
|---|---|
| `attested` | Matched, active, fresh status, credited issuer |
| `uncredited` | As above, but from an issuer the user has not credited |
| `status-unknown` | Matched and valid, but no fresh verified status: shown, never for high-stakes reliance |
| `expired` / `superseded` / `revoked` | Per step 5 |
| `no-attestation` | Absence, mismatch, invalid documents, or an omitted issuer |

High-stakes reliance (purchase, group creation, custody; Audit.md §7.6)
requires `attested` — a credited issuer **and** a fresh verified status.

Every attestation renders as *who* attested *what*, *how*, *paid by whom*,
and *when* — issuer name and key fingerprint, methodology class, scope
summary, exclusions, result class and floor, findings counts, sponsor,
relationships, age, expiry, and subject responses — never a bare
checkmark. `fail` and `findings-noted` render exactly where `clear` would
(Audit.md §7.5). Absence renders as absence. Every string is untrusted
text.

## 7. Bounds and URI rules

Discovery-Static-Ed25519 §7 applies to every URI in every document of this
profile (https only, DNS hosts only, no IP literals in any form, no
userinfo, query, fragment, or port — checked on the raw string, ≤ 3
HTTPS-to-HTTPS redirects, 60 s timeout). Size bounds: manifest, profile,
attestation, revocation 256 KiB; status list 4 MiB; order 64 KiB; subject
response 16 KiB; findings report 4 MiB.

## 8. Engagements and offers

An offer (`offers/<offerId>.json`, operator-signed) declares methodology
class, scope, fee model from §4.3's closed set, amount and currency when
not `pro-bono`, timeline, and default disclosure terms. `accept-order`
follows §5.3; the countersigned order is published only when its
disclosure terms say the attestation is published, and its digest is the
attestation's `orderRef`.

## 9. Error mapping

Audit.md §12 codes apply unchanged. This profile adds codes for failures
§12 leaves implicit, all of which a client renders as **no attestation**:

| Code | Trigger |
|---|---|
| `attestation_invalid` | Schema, §4.4 check, or signature failure; signer ≠ manifest operator |
| `auditor_manifest_invalid` | Manifest schema, signature, or `validUntil` failure |
| `unsupported_profile` | `auditProfileId` ≠ this profile |
| `status_list_invalid` | Status schema or signature failure, wrong status key, entry pins other bytes |
| `status_rollback` | Epoch lower than one retained — the list is rejected; status becomes unknown |
| `status_unavailable` | No list, or a stale one; degrade to `status-unknown` |
| `subject_response_invalid` | Response not signed by the subject operator, or answers other bytes |

## 10. Conformance fixtures

Published byte-pinned under `fixtures/` in the reference repository and
regenerated deterministically from seeded keys (`cases.json` documents
each case). They cover the full Audit.md §14 list:

| Audit.md §14 item | Fixture cases |
|---|---|
| Canonical encoding and signature verification | every signed file; plus the Discovery reference vectors reproduced byte-for-byte |
| Exact-hash matching and near-miss vectors | `build-exact`, `build-right-repo-wrong-revision`, `build-right-revision-wrong-build`, `build-fork-same-bytes`, `deployment-manifest-drift`, `deployment-pinned-document-served`, `deployment-pinned-document-replaced`, `deployment-pinned-document-unknown` |
| Expiry, supersession, revocation display | `expired`, `superseded`, `revoked` |
| Status epoch monotonicity, rollback, stapled status | `status-rollback`, `status-stale`, `status-absent`, `status-wrong-key` |
| Unsolicited-form validation, subject-response display | `invalid-notified-after-publication`, `invalid-unsolicited-without-disclosure`, `invalid-unsolicited-with-order`, `subject-response-shown`, `response-by-subject`, `response-forged` |
| Embargoed-report handling | `embargoed-report` |
| Sponsor and conflict rendering | `active-fresh-credited` (render carries sponsor and relationships), `invalid-no-relationships` |
| Absence-vs-fail rendering | `adverse-result-rendered` |
| Issuer-trust filtering | `uncredited-issuer-shown`, `uncredited-issuer-omitted`, `foreign-signer` |
| Verdict-independent fees (acceptance 7) | `order-all-signatures`, `invalid-order-contingent-fee` |

A conforming implementation reproduces every `expectDisplay`,
`expectError`, and `expectHighStakesOK` from the files alone.

## 11. Gaps

As of this revision:

- **One implementation.** Audit.md §14 asks for a relying client, an
  auditor, and a Discovery provider from three different authors to
  interoperate. The reference auditor and its relying-client `verify` share
  an author; the canonical layer is proven against the Discovery
  reference's vectors, but no independent audit client exists yet.
- **No shipping client consumes attestations.** Discovery-Static-Ed25519
  §4.2 defers the `evidence` shape to v2, and onym-ios shows "Pending — no
  audits yet" for contracts. This profile's attestation fields are the
  candidate for that v2 shape.
- **Key rotation** is out of scope: a new operator key is a new auditor.
- **Single host.** The reference deployment serves from one host; mirrors
  are permitted (bytes are location-independent) but none is configured.
- **Only `conformance-run` has a published methodology.** The other four
  classes are carried by the schema and verification rules; their
  methodology documents are not written.

## 12. Acceptance criteria (Audit.md §16)

| # | Criterion | How this profile meets it |
|---|---|---|
| 1 | Publish, take an order, issue; conforming clients match or refuse | §4–§6; fixtures |
| 2 | Absence never blocks direct import; no mandatory issuer | §6 step 7; `no-attestation` is absence |
| 3 | Rendered attestations expose issuer, scope, exclusions, sponsor, relationships, result, age | §6 render rule; required fields in §4.4 |
| 4 | A new release displays as unattested until re-examined | §6 step 3; `deployment-manifest-drift`, near-miss fixtures |
| 5 | Revocations and supersessions propagate within freshness bounds | §5.2: ≤ 6 h re-sign, 48 h `nextUpdate` |
| 6 | Adverse results render wherever favorable ones would | §6; `adverse-result-rendered` |
| 7 | Contingent fees expressible nowhere | §4.3 closed set; `invalid-order-contingent-fee` |
| 8 | Unsolicited attestations verify and display, with the subject's reply, no subject signature required | §4.4 check 4, §4.7, §5.3 |
| 9 | Two auditors' attestations of the same artifact display side by side | Attestations are independent documents keyed by issuer; nothing makes one final |
