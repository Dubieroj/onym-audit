# Onym audit hub — terms

Operated by Dimitrii (dubieroj@gmail.com) at `https://foldy.io/audit/hub/`.
Version 3, 24 September 2026 (adds requests for proposals).

## What the hub is

A place to host an auditor's tree — manifest, policies, attestations,
findings reports, status list — under `https://foldy.io/audit/a/<handle>/`,
and a browser studio for producing it. It is a convenience, not an
authority: every document it serves is signed by the auditor's own key and
verified by readers, and the Onym audit profile works the same for an
auditor who hosts their tree anywhere else.

## Keys

- **Your auditor key** is created in your browser, kept there as a
  non-extractable key, and offered to you once as a backup file. The hub
  never receives it. The hub cannot sign, alter, or revoke anything in your
  name, and cannot recover your key.
- **Your status key** is created and held by the hub, and delegated to it by
  your signed manifest. It only re-signs your status list (every 6 hours) so
  that readers see a fresh one. Revocations are signed by your auditor key
  in your browser; the hub only publishes them.

## What you may publish

Only attestations you stand behind, under the methodology you pin, about
bytes you examined. The unsolicited policy you publish binds you: notify the
subject before publishing and give them the notice period it names. You are
responsible for what you sign; the hub is not a party to any attestation.

## What the hub may do

- refuse a registration, a handle, or a document that fails the profile's
  rules, exceeds 20 MiB per auditor, or points outside the hub;
- **disable** an auditor's tree that is used for impersonation, spam,
  unlawful content, or attestations published in breach of their own
  unsolicited policy. A disabled tree stops being served and its status list
  stops being re-signed, so readers see its attestations as unverifiable
  rather than silently altered. The hub never edits or deletes a signed
  document to take it down.

## Orders

An auditor who publishes signed offers can be ordered from by anyone, at
`https://foldy.io/audit/order/`. The hub accepts an order only if it takes
one of the auditor's offers exactly — methodology, fee model, and disclosure
terms. Queued orders, with the orderer's contact, wait in an inbox that
opens only to a request signed by the auditor's key; the hub's operator can
technically read them, and the hub deletes an order when the auditor takes
or declines it.

The hub enforces the order's disclosure terms: a `fail` under an order that
embargoes failures is held — the countersigned order is published at once,
the attestation and its report when the embargo ends (checked every six
hours). The hub takes no part in payment and handles no money; a fixed fee
is settled between orderer and auditor, and can never depend on the result.

## Requests for proposals

An orderer may publish a request — exact bytes, a subject, a scope — to
every auditor, or address it to one Stellar account. A public request is
public; an addressed one is shown only to a request signed by its
addressee's key. Auditors answer with an offer made for that request, and
only the request's own key can read the answers. Choosing one places an
ordinary order under that offer and closes the request. Requests expire
after at most 30 days. No contact details are part of a request: the email
is given with the order, to the chosen auditor only.

## Vaults

So that one phrase finds its orders and requests on any device, the app
keeps that list on the hub encrypted with AES-256-GCM, under a key derived
from the phrase for this purpose alone. The hub stores ciphertext it cannot
read, under a signing key that appears in no order, request, or manifest,
and opens it only to that key's fresh signature. A vault holds at most
256 KiB.

## Anchors in Stellar

After an auditor issues or revokes an attestation, the app writes the hash of
its register to the auditor's own account on the Stellar test network,
signed by the auditor key in the browser; test-network accounts are funded
by the network's free Friendbot. The hub takes no part: anchors are
written to and read from public Stellar nodes. The library asks a public
Stellar node for each auditor's anchor, which tells that node which
auditors are being looked at — never which attestation.

## Shared documents

The audit profile, severity scale, and hub methodologies under
`https://foldy.io/audit/` are pinned by digest in the manifests and
attestations that use them. They are never changed in place; a new version
is a new document at a new path.

## Leaving

`Export my tree` in the studio downloads every document the hub holds for
you. Host it at any HTTPS base, re-sign your manifest with the new
`statusEndpoint` and a status key you hold, and publish — attestations are
signed bytes and do not depend on where they are served.

## Privacy

No cookies, no analytics, no third-party requests from the hub's pages.
Requests to the hub API are rate-limited per IP address in memory only; no
access logs are kept for the hub. Your contact email is public by design —
it is in your manifest.

## No warranty

The hub is provided as is, without availability guarantees. It is run as
part of Sobor 2026 and may be discontinued with 30 days' notice on this
page; exporting your tree is always available until then.
