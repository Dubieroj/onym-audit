# Unsolicited examination and disclosure policy

Auditor: Dimitrii (`onym:component:dimitrii-audit`). Version 1, 24 September 2026.

Pinned by digest in the auditor manifest and in every unsolicited
attestation (Onym Audit.md §5.7).

1. **Public artifacts only.** The auditor examines uninvited only what is
   publicly available exactly as hashed: published source at a commit, or
   documents a deployment serves to anyone. No credentials, no private
   endpoints, no load beyond what an ordinary client generates.
2. **Notice before publication.** Before publishing, the auditor sends the
   findings to the subject's published security contact — its
   `security.txt`, or failing that the contact its manifest or repository
   names — and records the contact and time in the attestation
   (`unsolicited.subjectContact`, `unsolicited.subjectNotifiedAt`).
3. **Embargo for exploitable findings.** A finding that lets a third party
   deceive or harm users now is embargoed for up to 90 days: the
   attestation may circulate with `findingsReport: null` and severity
   counts only, and the report is published when the embargo ends or the
   subject confirms a fix, whichever comes first.
4. **No embargo for observable non-conformance.** A finding that anyone can
   observe from outside and that gives an attacker nothing new — an expired
   document, a missing required field — is published no sooner than
   12 hours after notice.
5. **Right of reply.** The subject may publish a signed `SubjectResponse`
   at any time by `POST responses`; the auditor serves it beside the
   attestation and cannot edit it.
6. **No sale of silence.** Offering to withhold, soften, or delay an
   attestation in exchange for anything is a violation of this policy.
