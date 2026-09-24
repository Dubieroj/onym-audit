# Inclusion and ranking policy: the `onym-auditors` catalog

Published by the Discovery provider `onym:component:onym-audit-discovery` at `https://foldy.io/audit/discovery/`.
Every snapshot of this catalog pins these exact bytes by digest.

A Discovery catalog is a signed list of references. Inclusion here is a
recommendation by this provider and nothing more: not certification, not
protocol approval, not a statement that an auditor's opinions are right.
Clients verify each auditor's own signed manifest before using it, and
whom to credit stays the user's decision (Audit.md §7).

## What is listed

Audit seats only (seat type `audit`): this site's own auditor seat and
every auditor hosted on this site's audit hub.

## What it takes to get in

An auditor is listed while its manifest, as served, parses under the
Audit-Static-Ed25519 profile (onym:audit-profile:static-ed25519-v1) and
verifies under its operator key. Each entry pins the digest of the exact
manifest bytes reviewed. Nothing else is judged: not the quality of the
auditor's work, not its results, not its prices.

## Ranking

None. Entries are ordered by component id; every entry's placement is
`policy-ranked` under this rule. No fees, sponsorship or referral
arrangements exist.

## Relationships

This provider operates the audit hub that hosts the listed hub auditors
(relationship `other-disclosed`: hosting only — the hub holds none of
their auditor keys and cannot sign for them), and it operates its own
auditor seat (relationship `common-owner`).

## Removal and freshness

An auditor is dropped from the next snapshot when its manifest stops
verifying, expires, or is taken off the hub under the hub's terms. A new
snapshot is published when the listed auditors change, and otherwise once
less than 7 days of the current one remain; each snapshot is valid for 30
days, and clients treat an expired one as stale. Superseded snapshots are
retained as <catalogId>-<sequence>.json.
