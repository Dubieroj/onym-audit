package discovery

import (
	"fmt"
	"strings"
)

// Spec lists every check of this suite version, in report order, without
// outcomes: the published scope document is generated from it, so the
// scope an attestation pins is exactly what the code runs.
func Spec() []Check {
	out := make([]Check, len(checkSpecs))
	for i, c := range checkSpecs {
		out[i] = Check{ID: c.id, Level: c.level, Clause: c.clause, Title: c.title}
	}
	return out
}

// ScopeMarkdown renders the scope document for this suite version.
func ScopeMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Scope: %s %s\n\n", SuiteID, SuiteVersion)
	b.WriteString(`Methodology class ` + "`conformance-run`" + `. Subject: one **Discovery provider
deployment** under Discovery-Static-Ed25519 (onym-system
` + "`discovery/Discovery-Static-Ed25519.md`" + `), examined black-box from its
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

SHOULD-level checks produce findings, never a ` + "`fail`" + `.

## Checks

| ID | Level | Clause | What passes |
|---|---|---|---|
`)
	for _, c := range Spec() {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", c.ID, c.Level, strings.ReplaceAll(c.Clause, "|", "\\|"), strings.ReplaceAll(c.Title, "|", "\\|"))
	}
	b.WriteString(`
## Outcomes

Each check reports ` + "`pass`" + `, ` + "`fail`" + `, ` + "`not-applicable`" + ` (nothing to examine), or
` + "`inconclusive`" + ` (the check could not complete; the detail says why). A check
blocked because an earlier document failed to verify is ` + "`inconclusive`" + `,
never a failure attributed to the operator.

## Not examined

- Client behaviour (any client's handling of the catalog).
- Whether listed instances are available, honest, or secure — only their
  signed manifests' digests, fields, and signatures are checked.
- Host security, key custody, and anything not publicly served.
- Destination manifests' conformance to their own seat contracts beyond the
  digest, the entry-vs-manifest fields, and the operator signature.
- History: the run examines the deployment as served at run time.
`)
	return b.String()
}
