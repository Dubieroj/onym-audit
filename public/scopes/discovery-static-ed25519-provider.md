# Scope: onym:conformance-suite:discovery-static-ed25519-provider 1.0.0

Methodology class `conformance-run`. Subject: one **Discovery provider
deployment** under Discovery-Static-Ed25519 (onym-system
`discovery/Discovery-Static-Ed25519.md`), examined black-box from its
provider-manifest URL as any client would meet it: public HTTPS, no
credentials, the §7 bounds.

## The bar

A run passes when both hold:

1. **Publisher obligations.** Every provider-side MUST of the profile and of
   Discovery.md §14.1 that can be observed from outside is met.
2. **Client acceptance.** A conforming client performing the profile's §6
   procedure at run time accepts every declared public catalog as current —
   no §9 error. Where no clause obliges the provider directly (for example,
   republishing before expiry), the check says so and applies this bar.

SHOULD-level checks produce findings, never a `fail`.

## Checks

| ID | Level | Clause | What passes |
|---|---|---|---|
| `manifest.uri` | MUST | Discovery-Static-Ed25519 §5, §7 | Provider manifest URL is https and obeys the §7 URI rules (raw-string port check, no IP literal, no userinfo/query/fragment) |
| `manifest.fetch` | MUST | Discovery-Static-Ed25519 §5, §6 (add step 1), §7 | Provider manifest is served: HTTP 200 within ≤ 3 HTTPS→HTTPS redirects |
| `manifest.size` | MUST | Discovery-Static-Ed25519 §7, §9 provider_manifest_invalid | Provider manifest is at most 64 KiB |
| `manifest.schema` | MUST | Discovery-Static-Ed25519 §3, §4.1 (strictness table), §2, §9 | Provider manifest is strict §3 JSON with exactly the required top-level fields, correctly typed; unknown top-level fields rejected |
| `manifest.identity` | MUST | Discovery-Static-Ed25519 §1, §2, §6 (add step 2), §9 | version is 1, implementationProfileId is the v1 profile, seat is "discovery", providerId and operator have §2 syntax |
| `manifest.signature` | MUST | Discovery-Static-Ed25519 §3, §6 (add step 3); Discovery.md §14.1(1) | Embedded signature verifies under the manifest's own operator key over §3 canonical bytes |
| `manifest.detached-sig` | MUST | Discovery-Static-Ed25519 §3, §9 | A published manifest .sig is standard padded base64 plus exactly one newline and decodes to the embedded signature's 64 bytes |
| `manifest.valid-until` | MUST | Discovery-Static-Ed25519 §2, §6, §9 | validUntil is a §2 timestamp that has not passed |
| `catalog.descriptor-fields` | MUST | Discovery-Static-Ed25519 §4.1 (table, catalogId, seatTypes), §2 | Every catalogs[] descriptor carries each required field with valid type and syntax |
| `catalog.descriptor-unknown-keys` | SHOULD | Discovery-Static-Ed25519 §4.1 (table: unknown keys skip the descriptor), §1 | No catalogs[] descriptor carries keys undefined in v1 (conforming clients skip such a descriptor) |
| `catalog.decodable` | MUST | Discovery-Static-Ed25519 §4.1 (table), §9 | At least one catalogs[] descriptor decodes |
| `catalog.duplicate-id` | MUST | Discovery-Static-Ed25519 §4.1 | No catalogId repeats among decoded descriptors |
| `uri.rules` | MUST | Discovery-Static-Ed25519 §7, §9 | Every URI in the provider's documents (privacyProfileUri, snapshot, policyUri, entry manifest.uri, status.uri) obeys the §7 URI rules |
| `policy.document` | MUST | Discovery-Static-Ed25519 §2, §4.1, §7, §9 policy_unavailable; Discovery.md §14.1(2) | Each public catalog's policyUri serves (HTTP 200, ≤ 1 MiB) bytes hashing to the declared policy digest |
| `privacy.document` | MUST | Discovery-Static-Ed25519 §2, §4.1, §7; Discovery.md §10, §14.1(8) | privacyProfileUri serves (HTTP 200, ≤ 1 MiB) bytes hashing to the declared privacyProfile digest |
| `snapshot.fetch` | MUST | Discovery-Static-Ed25519 §5, §6 (refresh step 1), §7 | Each public catalog's snapshot URL serves the latest snapshot: HTTP 200 within redirect bounds |
| `snapshot.size` | MUST | Discovery-Static-Ed25519 §7, §9 | Snapshot is at most 1 MiB |
| `snapshot.schema` | MUST | Discovery-Static-Ed25519 §3, §4.2 (strictness table), §2, §9 | Snapshot is strict §3 JSON with exactly the required top-level fields, correctly typed; unknown top-level fields rejected |
| `snapshot.identity` | MUST | Discovery-Static-Ed25519 §1, §6 (refresh step 3) | Snapshot version is 1, profile is v1, catalogId matches its descriptor, providerId matches the manifest |
| `snapshot.signature` | MUST | Discovery-Static-Ed25519 §3, §6 (refresh step 2); Discovery.md §14.1(1) | Snapshot is signed by the provider manifest's operator key |
| `snapshot.detached-sig` | MUST | Discovery-Static-Ed25519 §3, §9 | Every published snapshot .sig (latest and retained) is standard padded base64 plus exactly one newline and agrees with the embedded signature |
| `snapshot.policy-digest` | MUST | Discovery-Static-Ed25519 §4.2 (chain rules), §9 | Snapshot policyDigest equals the manifest's declared policy for its catalogId |
| `snapshot.chain-fields` | MUST | Discovery-Static-Ed25519 §4.2 (chain rules), §9 | sequence ≥ 1; previousDigest present iff sequence > 1 |
| `snapshot.dates` | MUST | Discovery-Static-Ed25519 §4.2, §9 | generatedAt is not more than 10 minutes in the future and expiresAt is strictly after generatedAt |
| `snapshot.window-max` | MUST | Discovery-Static-Ed25519 §4.2 | expiresAt − generatedAt does not exceed 90 days |
| `snapshot.window-short` | SHOULD | Discovery-Static-Ed25519 §4.2 ("days to a few weeks"); Discovery.md §13 | Expiry window is at most six weeks (flags only windows no reading of "days to a few weeks" covers) |
| `snapshot.fresh` | MUST | Suite bar: client acceptance — Discovery-Static-Ed25519 §4.2, §9 snapshot_expired; Discovery.md §9, §12, invariant 9 | A conforming client refreshing at run time accepts the served latest snapshot as current (not expired, 10-minute skew allowance) |
| `snapshot.entry-count` | MUST | Discovery-Static-Ed25519 §7, §9 | At most 512 entries |
| `snapshot.duplicate-component` | MUST | Discovery-Static-Ed25519 §4.2 (entry rules), §9 | No componentId repeats among decoded-and-surviving entries |
| `entry.fields` | MUST | Discovery-Static-Ed25519 §4.1 (table), §4.2 (entry rules), §2, §9 result_incomplete | Every entry decodes: required fields, §2 syntax, closed relationship/placement sets, evidence absent or empty, status shape |
| `entry.unknown-keys` | SHOULD | Discovery-Static-Ed25519 §4 (lossy entry decoding), §4.1 (table), §9 result_incomplete | No entry (or its manifest/status object) carries keys undefined in v1 (conforming clients skip such an entry) |
| `entry.seat-type-declared` | SHOULD | Discovery-Static-Ed25519 §4.1 (seatTypes); Discovery.md §5.1, §7 | Each entry's seatType is within its catalog descriptor's seatTypes (or the catalog declares "*") |
| `provider.cross-catalog-digest` | MUST | Discovery-Static-Ed25519 §4.2 (entry rules) | The same componentId carries the same manifest.digest across the provider's catalogs |
| `chain.retention` | MUST | Discovery-Static-Ed25519 §5, §6 (forward jump) | Every superseded snapshot that has not yet expired is served as <catalogId>-<sequence>.json |
| `chain.sibling-valid` | MUST | Discovery-Static-Ed25519 §3, §4.2, §5, §6 (intermediates: signature, chain, schema), §7 | Every retained sibling is ≤ 1 MiB, strict-schema, the named catalog's sequence, and signed by the operator key |
| `chain.links` | MUST | Discovery-Static-Ed25519 §4.2 (chain rules), §6 (fork, provable break) | previousDigest of sequence k+1 is the SHA-256 of the exact served bytes of sequence k |
| `chain.latest-sibling` | MUST | Discovery-Static-Ed25519 §4.2 (published bytes immutable), §5 | If the latest sequence N is also served as <catalogId>-<N>.json, those bytes are identical to the latest snapshot |
| `dest.retrievable` | SHOULD | Discovery-Static-Ed25519 §6 (before presenting, step 1), §7, §9 entry_manifest_unavailable; Discovery.md §14.1(6) | Each surviving entry's manifest.uri serves its destination manifest (HTTP 200, ≤ 256 KiB) |
| `dest.digest` | SHOULD | Discovery-Static-Ed25519 §4.2 (manifest.digest), §6 (step 2), §9 entry_manifest_mismatch; Discovery.md §14.1(4), §14.1(6) | Served destination bytes hash to the entry's manifest.digest |
| `dest.fields` | MUST | Discovery-Static-Ed25519 §6 (before presenting, step 3), §9 entry_manifest_mismatch; Discovery.md §5.3, §14.1(3) | In the reviewed (digest-matching) bytes, seat, operator and every entry profile agree with the entry |
| `dest.signature` | MUST | Discovery-Static-Ed25519 §4.3, §6 (step 4), §9 entry_manifest_invalid; Discovery.md §14.1(4) | The reviewed destination bytes carry a valid signature by their own operator key |
| `serving.no-cookies` | MUST | Discovery-Static-Ed25519 §5; Discovery.md §10 | No response from the provider's documents sets a cookie |

## Outcomes

Each check reports `pass`, `fail`, `not-applicable` (nothing to examine), or
`inconclusive` (the check could not complete; the detail says why). A check
blocked because an earlier document failed to verify is `inconclusive`,
never a failure attributed to the operator.

## Not examined

- Client behaviour (any client's handling of the catalog).
- Whether listed instances are available, honest, or secure — only their
  signed manifests' digests, fields, and signatures are checked.
- Host security, key custody, and anything not publicly served.
- Destination manifests' conformance to their own seat contracts beyond the
  digest, the entry-vs-manifest fields, and the operator signature.
- History: the run examines the deployment as served at run time.
