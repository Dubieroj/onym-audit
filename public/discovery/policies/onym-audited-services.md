# Inclusion policy: the `onym-audited-services` catalog

Published by the Discovery provider `onym:component:onym-audit-discovery` at `https://foldy.io/audit/discovery/`.
Every snapshot of this catalog pins these exact bytes by digest.

This catalog exists to show audits where Onym's apps already look: on the
row of a service. Inclusion is not a recommendation of the service and not
a certification; it says only that an auditor named below has published an
attestation about it.

## What is listed

A service is listed while both hold:

1. Onym's own default Discovery catalog lists it. That catalog is read from
   `https://discovery.onym.app/manifest.json`, verified under the operator key
   `onym:key:42b0da001104dd03052c7feddab9520c920c9e40d11b245c46c27cf6be853f24`, and used only as a list of where each
   service's manifest lives.
2. At least one active, unexpired attestation about its component id has
   been published by one of these auditors, verified against the auditor's
   signed status list and operator key:

- `onym:component:llm-audit`, operator key `onym:key:f3c570a461c6901c48750015783e18e0fbaa827a5061e4a3880fb2636e73d006`
- `onym:component:onym-audit`, operator key `onym:key:0e803a08eb56c5742ca0494628f374f86fcae53bd446663e5109e785ddc0ee03`

Each entry pins the digest of the service's manifest bytes as this provider
fetched them, after checking what a client checks: the component id, the
operator key Onym's catalog names, the seat, the embedded signature, and
expiry. Entries are listed with the same seat type Onym's catalog gives them.

## Status

- `warning`: an active attestation's result is `fail`.
- `review`: an active attestation's result is `findings-noted` or
  `inconclusive`, and none is a fail.
- no status: every active attestation is `clear`.

The status `uri` opens a page listing those attestations; each links to a
page that fetches the signed documents and verifies them in the reader's
browser. Which auditors to credit stays the reader's decision (Audit.md §7).

## Relationships

Every entry's relationship is `other-disclosed`: this provider takes no
payment from and has no commercial tie to any listed service, but its
operator takes part in Sobor 2026, a contest organized by the maintainer of
Onym's reference services. The credited auditors state their own
relationships in each attestation.

## Ranking, removal and freshness

No ranking: entries are ordered by component id, placement
`policy-ranked`. A service drops out when its attestations are revoked,
superseded or expire, when Onym's catalog stops listing it, or when its
manifest stops verifying. The provider re-reads everything every six hours
and when an auditor on its hub publishes; a new snapshot follows any change,
and otherwise once less than 7 days of the current one remain; each is
valid for 30 days.
