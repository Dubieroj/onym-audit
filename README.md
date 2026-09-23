# onym-audit

A working **audit & attestation seat** for the [Onym](https://onym.foundation)
network, built for [Sobor 2026](https://sobor.io): the first concrete
implementation profile of
[`audit/Audit.md`](https://github.com/onymchat/onym-system/blob/main/audit/Audit.md),
a reference auditor, a relying-client verifier in two languages, a
conformance suite, and a live instance.

> An auditor examines exact bytes under a declared scope and signs what it
> found. The attestation is one institution's visible opinion — never a
> license, a gate, or a substitute for the reader's own trust decision.
> — Audit.md

Before this, the seat had a contract and no code, and the Onym iOS app
showed **"Audit report: Pending — no audits yet"**.

## What is here

| Path | What it is |
|---|---|
| [`public/profile/Audit-Static-Ed25519.md`](public/profile/Audit-Static-Ed25519.md) | **The implementation profile** (Audit.md §15 said none existed): documents, signing, serving, freshness, verification, errors, fixtures, gaps, and a line-by-line map to Audit.md §16's acceptance criteria |
| `canon/`, `sig/`, `urirule/` | Canonical JSON, Ed25519, and URI rules — shared with Discovery-Static-Ed25519 and proven **byte-identical** to the Rust reference (`onym-discovery`) on its published vectors |
| `audit/` | Every boundary object of Audit.md §5 with strict decoding, the signed status list, and the relying-client `verify` of §6–§7 |
| `fixtures/` | 34 byte-pinned cross-platform fixtures (22 decision cases, 12 parse cases) covering the whole Audit.md §14 list — `cases.json` states every expected outcome |
| `public/verify.js` | A **second, independent** relying client in JavaScript (WebCrypto), passing the same reference vectors and fixtures — `node tools/verify-js-test.mjs` |
| `conformance/discovery/` | A black-box conformance suite for Discovery providers: 42 checks, each citing its clause (Discovery-Static-Ed25519, Discovery.md §14.1) — the examination behind this auditor's first attestation; its scope document is generated from the code |
| `tools/sandbox.sh` | The whole lifecycle on your machine in one command: issue, reply, order, supersede, revoke, byte drift |
| [`EXERCISE.md`](EXERCISE.md) | How to exercise the submission — no credentials needed |
| `agent/` | An **LLM examination engine** (Claude, via the Anthropic Go SDK) for the `security-review` methodology: read-only tools confined to a repository checked out at an exact commit; every finding must quote the lines it rests on and is checked mechanically against the pinned bytes; the prompt is published and its digest recorded; the auditor reviews, drops with reasons, and signs |
| `review/`, `console/` | **The auditor console**: a local web UI (loopback only, per-start token, Host check) for the order queue, manual reviews (select lines → the quote is checked against the pinned bytes), LLM-assisted reviews (run the engine, keep or drop each finding with a published reason), signing with the offline key — including countersigning commissioned orders and holding embargoed reports — and publishing |
| `public/order/` | **Order page** (EN/RU/CNR): order from **any auditor** — this seat or any hub auditor — under one of their signed offers (each verified in the browser). The page pins the exact bytes (a commit, a service's manifest digest, a build's digest), the subject's browser creates an Ed25519 key, signs the `AuditOrder` as subject and sponsor, and queues it with its scope text; the key is downloaded, never sent |
| `onymid/`, `public/onym-id.js` | **Onym identity keys**, derived exactly as the Onym apps derive them (BIP-39 → HKDF `nostr-secp256k1-v1` → HKDF `stellar-ed25519-v1`), in Go and in the browser, both pinned to the apps' cross-platform fixture (`abandon … about` → `GB5DHQE43…YJ7A`). An auditor signs in with a phrase of its own — never a main Onym identity (Identity-BIP39 §9–10) — and its auditor key is that identity's Stellar key; orders are signed with per-order keys derived from the same phrase, unlinkable to the auditor |
| `public/hub/`, `hub/`, `netguard/` | **The audit app and hub**: anyone can take the audit seat from a browser at <https://foldy.io/audit/app/> (EN/RU/CNR) — an auditor's cabinet with a pipeline (new orders → held → active → revoked) and a **library** of every attestation the hub serves, searchable by number, component or auditor and verified in the reader's browser. The app keeps only non-extractable keys, signs the manifest and every attestation there, and examines a repository at a commit, any running Onym component by its signed manifest, a Discovery catalog (the 42-check suite, run by the hub), or a build file (hashed by the hub). The hub validates everything against the profile before publishing it under `a/<handle>/`, holds only each auditor's delegated status key, and fetches only public addresses (`netguard` checks the dialed IP). Hub auditors publish signed offers (pro bono or a fixed, verdict-independent price); the hub accepts an order only if it takes an offer exactly, keeps it in an inbox that opens only to the auditor's signed request, checks a commissioned attestation against the countersigned order, and holds a `fail` until the order's embargo ends |
| `server/`, `cmd/onym-audit` | The auditor CLI and the online server (status re-signing, `POST orders`, `POST responses`) |
| `public/` | The published tree: manifest, profile, policies, methodology, scope, severity scale, privacy profile, landing page (EN, RU, CNR) |
| `web/` | The landing's single template and its strings in all three languages — `python3 tools/build_landing.py` renders `public/{,ru/,cnr/}index.html`; `--check` fails on drift |
| `deploy/` | systemd unit, nginx snippet, idempotent deploy script |

## Design in five decisions

1. **Bytes, not brands.** An attestation binds a git commit, a build hash,
   or a deployment's signed-manifest digest — plus, for a deployment, the
   one served document its result depends on (a catalog snapshot). When the
   bytes change, the attestation stops matching: a `fail` cannot follow a
   fixed deployment, nor a `clear` a broken one.
2. **The auditor key stays offline.** A delegated `statusKey`, named in the
   manifest, re-signs the status list every 6 hours on the server. It can
   refresh freshness but cannot mint, alter, or revoke an attestation.
3. **No per-attestation status query.** One signed list covers every
   attestation, so checking status never tells the auditor which component
   a user is about to rely on (Audit.md §7.8).
4. **Verdict-independent fees are the only expressible fees.** The fee model
   is a closed set; a contingent fee fails to parse (acceptance criterion 7).
5. **Absence is absence.** An unattested component renders as unattested,
   never as failed; an adverse result renders exactly where a favorable one
   would; an uncredited issuer is labelled or omitted by the user's choice.

## Live

<https://foldy.io/audit/> — auditor manifest, signed status list, published
attestations, and a page that verifies all of them in your browser.
<https://foldy.io/audit/app/> — become an auditor yourself, or browse the library.

## Run it

```sh
go test ./...                      # all packages, incl. byte-pinned fixtures
node tools/verify-js-test.mjs      # the JavaScript client against the same vectors
go build -o bin/onym-audit ./cmd/onym-audit
bin/onym-audit fixtures -dir fixtures
```

Verify a live attestation as a relying client:

```sh
bin/onym-audit verify \
  -manifest    https://…/manifest.json \
  -attestation https://…/attestations/<id>.json \
  -target      <component manifest URL> \
  -target-document <pinned document URL, if the attestation names one> \
  -credit      <operator key you choose to credit>
```

Run the auditor console (holds the auditor key; loopback only):

```sh
export OPENROUTER_API_KEY=…      # for LLM-assisted reviews; in your own terminal
bin/onym-audit console           # → http://127.0.0.1:8790/
```

Operate an auditor from the command line:

```sh
bin/onym-audit keygen  -out keys/auditor.key         # stays on your machine
bin/onym-audit keygen  -out keys/status.key          # goes to the server
bin/onym-audit publish -root public -config config.json -key keys/auditor.key -status-key keys/status.key
bin/onym-audit attest  -root public -config config.json -key keys/auditor.key -in draft.json
bin/onym-audit revoke  -root public -config config.json -key keys/auditor.key -id <id> -reason new-information
deploy/deploy.sh
```

LLM-assisted security review (needs `ANTHROPIC_API_KEY` in your environment):

```sh
bin/onym-audit agent-review -repo https://github.com/<org>/<repo> -commit <sha> -scope "…" -out review/
# read review/summary.md, then:
bin/onym-audit draft-review -root public -config config.json -findings review/findings.json -id <id> \
  -subject onym:component:<id> -subject-operator onym:key:<hex> -relationships none \
  -contact mailto:<security contact> -notified-at <time> [-drop F2:reason] -out draft.json
bin/onym-audit attest -root public -config config.json -key keys/auditor.key -in draft.json
```

A subject answers an attestation with a signed reply, which the server
publishes beside it:

```sh
bin/onym-audit respond -attestation <url> -key <subject operator key> -id <response id> -text "…" -out reply.json
curl --data-binary @reply.json https://…/responses
```

## Honest limits

See the profile's §11. In short: one author wrote both relying clients;
no shipping Onym client consumes attestations yet (Discovery's `evidence`
field is deferred to its v2, and this profile's attestation is the
candidate shape); key rotation is out of scope for v1; one host. A hub
auditor's key lives in one browser and a backup file the hub cannot
recover; the hub's conformance runs and build hashes happen on the hub's
server, and its reports say so.

## License

MIT. `testdata/discovery-reference/` holds unmodified MIT-licensed fixtures
from `onymchat/onym-discovery` (see its `SOURCE.md`).
