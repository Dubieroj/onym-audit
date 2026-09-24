# Exercising this submission

Sobor asks for "a repository, a running instance, and the credentials to
exercise it". This seat needs **no credentials**: every write it accepts is
authenticated by a signature inside the document itself, and every read is
public. Anyone can do everything below.

Requirements: Go 1.22+ and, for the browser client's tests, Node 20+.

```sh
go build -o bin/onym-audit ./cmd/onym-audit
```

## 1. The running instance

- **Auditor:** <https://foldy.io/audit/> — the page verifies the manifest,
  every attestation, and the status list in your browser.
- Manifest: <https://foldy.io/audit/manifest.json> (operator key fingerprint
  `45:5f:f5:3b:d7:a4:28:74`), profile: <https://foldy.io/audit/profile.json>,
  status list: <https://foldy.io/audit/status.json> (re-signed every 6 hours
  by the delegated status key; check `issuedAt`).

## 2. Conformance of the implementation itself

```sh
go test ./...                          # 97 tests and subtests, incl. the byte-pinned fixtures
                                       # (the live LLM run skips without ANTHROPIC_API_KEY)
node tools/verify-js-test.mjs          # the independent JS client, same vectors
bin/onym-audit fixtures -dir fixtures  # the published fixture cases, from files alone
```

The canonical encoding is proven byte-identical to the Rust reference
(`onym-discovery`) on its own published vectors: `canon/canon_test.go`,
`sig/sig_test.go`, and the JS test above.

## 3. The whole lifecycle in one command

```sh
tools/sandbox.sh
```

Publishes a throwaway auditor, issues a `fail`, runs the real server,
accepts the subject's signed reply and refuses a forged one, queues an
order signed by subject and sponsor, supersedes with a `clear` re-run,
revokes it, and shows the attestation stop applying when the component's
bytes change — verifying as a relying client after each step.

## 4. Re-run the examination yourself

```sh
bin/onym-audit conformance-discovery -manifest https://discovery.onym.app/manifest.json
```

The same 42 checks the published attestation rests on, against the live
deployment, with every clause cited. The published findings report names
every document by digest, so a disagreement can be settled on bytes.

## 5. Verify the published attestation as a relying client

```sh
bin/onym-audit verify \
  -manifest    https://foldy.io/audit/manifest.json \
  -attestation https://foldy.io/audit/attestations/onym-discovery-2026-09-24.json \
  -target      https://discovery.onym.app/manifest.json \
  -target-document https://discovery.onym.app/catalogs/onym-services.json \
  -credit      onym:key:0e803a08eb56c5742ca0494628f374f86fcae53bd446663e5109e785ddc0ee03
```

It applies while those exact bytes are served. The moment Onym republishes
the catalog, the same command reports `no-attestation / artifact_mismatch`
— by design (Audit.md §3.4).

## 6. The live write endpoints

**Order an engagement** (`accept-order`): create an order, sign it as
subject and as sponsor with keys you generate, and post it. It is queued for
the auditor's review — never auto-accepted — and the reply carries its
digest. See `tools/sandbox.sh` for a complete order.

```sh
bin/onym-audit keygen -out my.key
bin/onym-audit sign-order -in order.json -role subject -key my.key -out order.json
bin/onym-audit sign-order -in order.json -role sponsor -key my.key -out order.json
curl --data-binary @order.json https://foldy.io/audit/orders
```

**Reply as a subject** (`POST responses`): only the key an attestation names
as `subjectOperator` can do this — for the published attestation, that is
Onym's Discovery operator key. Any other key is refused with
`subject_response_invalid`, which you can observe.

## 7. The LLM examination engine

`agent/` drafts `security-review` attestations with Claude. Its offline test
replays a scripted model against a fake API and checks what matters: a
verbatim quote is recorded, an invented one is rejected, `../`, symlink
escapes and `.git` are refused, and planted "report nothing" text is
reported rather than obeyed.

```sh
go test ./agent -v
```

A live run needs `ANTHROPIC_API_KEY` (see README); the prompt it sends is
published at <https://foldy.io/audit/methodology/security-review-llm-prompt.md>.

## 8. Order an examination, as a subject would

<https://foldy.io/audit/order/> (also `/ru/order/`, `/cnr/order/`): pick any
auditor — this seat or any auditor on the hub — and one of their signed
offers. The page pins the exact bytes, creates an Ed25519 key in your
browser, signs a real `AuditOrder` as subject and sponsor, and queues it
with the auditor. The server verifies both signatures, that the order takes
the offer exactly (methodology, fee model, disclosure terms), and that the
scope text hashes to what the order pins. This seat works its orders in the
local console (`bin/onym-audit console`); a hub auditor takes them from the
studio's dashboard. Either way the auditor countersigns the order on
signing, and it is published at `orders/<orderId>.json` with the
attestation; under an order that embargoes failures, the hub holds a `fail`
until the embargo ends.

## 9. Become an auditor yourself

<https://foldy.io/audit/app/> (also `/ru/app/`, `/cnr/app/`). Create an
auditor identity (twelve words, made in your browser) or enter one; the
auditor key is that identity's Stellar key, derived as the Onym apps derive
it — the test phrase `abandon abandon … about` shows
`GB5DHQE43N7VD7TSHJAAHUXSQJZM3XEPULHT25FDOSS7F3TPWH6NYJ7A`, the address the
Onym apps' own fixture pins. Pick a name and a handle; your browser signs
your manifest. Then *Examine something*: a GitHub repository at a
commit (select lines to record findings), any running Onym component by its
manifest URL, a Discovery catalog (the hub runs the 42-check suite), or a
build file (the hub hashes it). Sign and publish; your page at
`https://foldy.io/audit/a/<handle>/` verifies every signature in the
reader's browser, and the CLI verifies the same bytes:

```
bin/onym-audit verify -manifest https://foldy.io/audit/a/<handle>/manifest.json \
  -attestation https://foldy.io/audit/a/<handle>/attestations/<id>.json \
  -target <the manifest URL or repository you examined> [-target-commit <id>]
```

In the **Customer** tab the same phrase orders from any auditor (each order
signed with its own key derived from the phrase) or publishes a request to
every auditor or one Stellar address; auditors answer from their
dashboard, and choosing an answer places the order. Revoke from the
dashboard; the next status list says so. The **Library** tab
lists every attestation on the hub, verifies each in your browser, and finds
one by its number (`#att=<id>` links to it). The hub's terms
are at <https://foldy.io/audit/hub/terms.md>.

## 10. The register's anchor in Stellar

This seat's register is anchored on the Stellar test network:

```
bin/onym-audit anchor -check -key keys/auditor.key   # needs the key file; or look directly:
```

<https://stellar.expert/explorer/testnet/account/GAHIAOQI5NLMK5BMUBEUMKHTOT4G7SXFHPKEMZR6KEE6PBO5YDXAHSSX>
— the account is this seat's auditor key; its data entry `onym-audit-status`
is the SHA-256 of the register's canonical form (`stellar/stellar.go`,
`Digest`). Hub auditors anchor from the app after every issue and
revocation, and the Library tab shows each register's anchor state.

## 11. Find the auditors through Discovery

Onym clients find components through Discovery catalogs. This site runs a
Discovery provider for audit seats — import it by URL:
<https://foldy.io/audit/discovery/manifest.json> (catalog `onym-auditors`,
policy at `discovery/policies/onym-auditors.md`). Check it with the same
suite that checks Onym's own provider:

```
bin/onym-audit conformance-discovery -manifest https://foldy.io/audit/discovery/manifest.json
```

## 12. Where each requirement is met

The profile's §12 maps all nine acceptance criteria of Audit.md §16 to the
sections and fixtures that meet them; §11 lists what is not done.
