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
  `ea:ef:cb:ce:6e:48:ed:c1`), profile: <https://foldy.io/audit/profile.json>,
  status list: <https://foldy.io/audit/status.json> (re-signed every 6 hours
  by the delegated status key; check `issuedAt`).

## 2. Conformance of the implementation itself

```sh
go test ./...                          # 66 tests and subtests, incl. the byte-pinned fixtures
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
  -attestation https://foldy.io/audit/attestations/<id>.json \
  -target      https://discovery.onym.app/manifest.json \
  -target-document https://discovery.onym.app/catalogs/onym-services.json \
  -credit      onym:key:47fc089af02a1435d3b7f98b17d7c53b26853986b535d66249f63916cb8a082b
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

## 8. Where each requirement is met

The profile's §12 maps all nine acceptance criteria of Audit.md §16 to the
sections and fixtures that meet them; §11 lists what is not done.
