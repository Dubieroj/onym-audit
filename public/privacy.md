# Privacy profile

Auditor: Dimitrii (`onym:component:dimitrii-audit`). Version 1, 24 September 2026.

- **Static files** (manifest, attestations, status list, reports) are served
  without cookies, accounts, or per-user URLs. The host keeps **no access
  logs** for this service.
- **No per-attestation status query exists.** The status list covers every
  attestation at once, so fetching it tells the auditor nothing about which
  component a client is about to rely on (Onym Audit.md §7.8).
- **Orders** (`POST orders`) are stored unpublished for review: what the
  parties signed into them, the scope text they pin, and — for orders placed
  through the order page — the contact address the subject gave, which is
  used only to discuss that order and is never published. All of it is
  deleted 90 days after a decision, except what the order's disclosure terms
  publish (the order, its scope, the attestation).
- **Subject responses** (`POST responses`) are published: that is their
  purpose.
- Error logs record failures of the auditor's own processes (for example a
  failed status re-signing), never request metadata.
