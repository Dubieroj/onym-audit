# Onym audit hub — terms

Operated by Dimitrii (dubieroj@gmail.com) at `https://foldy.io/audit/hub/`.
Version 1, 23 September 2026.

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
