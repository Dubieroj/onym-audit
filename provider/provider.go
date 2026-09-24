// Package provider publishes a Discovery provider (Discovery-Static-Ed25519)
// for audit seats: the catalog "onym-auditors" lists this site's own seat
// and every auditor hosted on its hub whose manifest verifies under the
// audit profile. Onym's default catalog lists four seat types and no audit
// seat; the Discovery contract keeps direct import open, so any client can
// add this provider by its manifest URL.
//
// The provider manifest, inclusion policy and privacy profile are static
// and signed once; snapshots are signed by the server with the provider
// key, chained by sequence and previousDigest, retained as <id>-<k>.json,
// and renewed when the listed auditors change or expiry nears.
package provider

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"onym-audit/audit"
	"onym-audit/sig"
	"onym-audit/site"
)

const (
	ProfileID = "onym:discovery-implementation:static-ed25519-v1"
	SeatType  = "audit"
)

// Config names the provider and its one catalog.
type Config struct {
	Base       string        // https://foldy.io/audit/discovery/
	ProviderID string        // onym:component:onym-audit-discovery
	CatalogID  string        // onym-auditors
	Window     time.Duration // snapshot lifetime
	Renew      time.Duration // renew when less than this remains
}

// Default is this site's provider.
var Default = Config{
	Base: "https://foldy.io/audit/discovery/", ProviderID: "onym:component:onym-audit-discovery", CatalogID: "onym-auditors",
	Window: 30 * 24 * time.Hour, Renew: 7 * 24 * time.Hour,
}

func (c Config) snapshotURI() string { return c.Base + "catalogs/" + c.CatalogID + ".json" }

// PublishStatic writes the provider manifest (and its .sig), the catalog's
// inclusion policy and the privacy profile into dir, the directory served
// at c.Base.
func PublishStatic(dir string, c Config, key ed25519.PrivateKey, validUntil time.Time) error {
	policy := []byte(fmt.Sprintf(policyText, c.CatalogID, c.ProviderID, c.Base, int(c.Renew.Hours()/24), int(c.Window.Hours()/24)))
	privacy := []byte(privacyText)
	for p, b := range map[string][]byte{"policies/" + c.CatalogID + ".md": policy, "privacy.md": privacy} {
		if err := site.WriteAtomic(filepath.Join(dir, filepath.FromSlash(p)), b); err != nil {
			return err
		}
	}
	m := map[string]any{
		"version": 1, "seat": "discovery", "implementationProfileId": ProfileID, "providerId": c.ProviderID,
		"operator": string(site.KeyOf(key)), "capabilities": []string{"signed-snapshot-v1", "local-filtering-v1"},
		"catalogs": []map[string]any{{
			"catalogId": c.CatalogID, "audience": "public", "seatTypes": []string{SeatType},
			"policy": sig.Digest(policy), "policyUri": c.Base + "policies/" + c.CatalogID + ".md", "snapshot": c.snapshotURI(),
		}},
		"offers": []any{}, "privacyProfile": sig.Digest(privacy), "privacyProfileUri": c.Base + "privacy.md",
		"validUntil": sig.FormatTime(validUntil),
	}
	raw, err := audit.SignDoc(m, key)
	if err != nil {
		return err
	}
	return site.WriteSigned(filepath.Join(dir, "manifest.json"), raw)
}

// Source is one auditor tree: the base its documents are named under and
// the directory they are served from.
type Source struct {
	Base, Dir   string
	CommonOwner bool // operated by the provider itself
}

type entry struct {
	ComponentID  string       `json:"componentId"`
	SeatType     string       `json:"seatType"`
	Manifest     audit.DocRef `json:"manifest"`
	Operator     sig.Key      `json:"operator"`
	ListedAt     string       `json:"listedAt"`
	Relationship string       `json:"relationship"`
	Placement    string       `json:"placement"`
	Profiles     []string     `json:"profiles"`
	Evidence     []any        `json:"evidence"`
}

type snapshot struct {
	Version                 int     `json:"version"`
	ImplementationProfileID string  `json:"implementationProfileId"`
	ProviderID              string  `json:"providerId"`
	CatalogID               string  `json:"catalogId"`
	Sequence                int64   `json:"sequence"`
	PreviousDigest          *string `json:"previousDigest,omitempty"`
	PolicyDigest            string  `json:"policyDigest"`
	GeneratedAt             string  `json:"generatedAt"`
	ExpiresAt               string  `json:"expiresAt"`
	Entries                 []entry `json:"entries"`
	Signature               string  `json:"signature,omitempty"`
}

// entries lists every source whose manifest verifies under the audit
// profile now, bound to the exact bytes served.
func entries(sources []Source, now time.Time, listed map[string]string) []entry {
	out := []entry{}
	for _, s := range sources {
		raw, err := os.ReadFile(filepath.Join(s.Dir, "manifest.json"))
		if err != nil {
			continue
		}
		m, err := audit.ParseManifest(raw, now)
		if err != nil {
			continue
		}
		at, ok := listed[m.ComponentID]
		if !ok {
			at = sig.FormatTime(now)
		}
		rel := "other-disclosed" // hosted on the provider's hub; the policy says so
		if s.CommonOwner {
			rel = "common-owner"
		}
		out = append(out, entry{
			ComponentID: m.ComponentID, SeatType: SeatType, Manifest: audit.DocRef{URI: s.Base + "manifest.json", Digest: sig.Digest(raw)},
			Operator: m.Operator, ListedAt: at, Relationship: rel, Placement: "policy-ranked", Profiles: []string{m.AuditProfileID}, Evidence: []any{},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ComponentID < out[j].ComponentID })
	return out
}

// Refresh writes a new snapshot when the listed auditors changed or the
// current one nears expiry; it reports whether it did.
func Refresh(dir string, c Config, key ed25519.PrivateKey, sources []Source, now time.Time) (bool, error) {
	policy, err := os.ReadFile(filepath.Join(dir, "policies", c.CatalogID+".md"))
	if err != nil {
		return false, errors.New("publish the provider's static documents first")
	}
	latestPath := filepath.Join(dir, "catalogs", c.CatalogID+".json")
	var prev snapshot
	prevRaw, err := os.ReadFile(latestPath)
	havePrev := err == nil && json.Unmarshal(prevRaw, &prev) == nil
	listed := map[string]string{}
	if havePrev {
		for _, e := range prev.Entries {
			listed[e.ComponentID] = e.ListedAt
		}
	}
	es := entries(sources, now, listed)
	if havePrev {
		a, _ := json.Marshal(es)
		b, _ := json.Marshal(prev.Entries)
		exp, err := sig.ParseTime(prev.ExpiresAt)
		if string(a) == string(b) && err == nil && exp.Sub(now) > c.Renew && prev.PolicyDigest == sig.Digest(policy) {
			return false, nil
		}
	}
	s := snapshot{
		Version: 1, ImplementationProfileID: ProfileID, ProviderID: c.ProviderID, CatalogID: c.CatalogID, Sequence: 1,
		PolicyDigest: sig.Digest(policy), GeneratedAt: sig.FormatTime(now), ExpiresAt: sig.FormatTime(now.Add(c.Window)), Entries: es,
	}
	if havePrev {
		d := sig.Digest(prevRaw)
		s.Sequence, s.PreviousDigest = prev.Sequence+1, &d
	}
	raw, err := audit.SignDoc(s, key)
	if err != nil {
		return false, err
	}
	// The sibling first: a reader who sees sequence N can always walk back.
	if err := site.WriteAtomic(filepath.Join(dir, "catalogs", fmt.Sprintf("%s-%d.json", c.CatalogID, s.Sequence)), raw); err != nil {
		return false, err
	}
	return true, site.WriteSigned(latestPath, raw)
}

const policyText = `# Inclusion and ranking policy: the ` + "`%s`" + ` catalog

Published by the Discovery provider ` + "`%s`" + ` at ` + "`%s`" + `.
Every snapshot of this catalog pins these exact bytes by digest.

A Discovery catalog is a signed list of references. Inclusion here is a
recommendation by this provider and nothing more: not certification, not
protocol approval, not a statement that an auditor's opinions are right.
Clients verify each auditor's own signed manifest before using it, and
whom to credit stays the user's decision (Audit.md §7).

## What is listed

Audit seats only (seat type ` + "`audit`" + `): this site's own auditor seat and
every auditor hosted on this site's audit hub.

## What it takes to get in

An auditor is listed while its manifest, as served, parses under the
Audit-Static-Ed25519 profile (onym:audit-profile:static-ed25519-v1) and
verifies under its operator key. Each entry pins the digest of the exact
manifest bytes reviewed. Nothing else is judged: not the quality of the
auditor's work, not its results, not its prices.

## Ranking

None. Entries are ordered by component id; every entry's placement is
` + "`policy-ranked`" + ` under this rule. No fees, sponsorship or referral
arrangements exist.

## Relationships

This provider operates the audit hub that hosts the listed hub auditors
(relationship ` + "`other-disclosed`" + `: hosting only — the hub holds none of
their auditor keys and cannot sign for them), and it operates its own
auditor seat (relationship ` + "`common-owner`" + `).

## Removal and freshness

An auditor is dropped from the next snapshot when its manifest stops
verifying, expires, or is taken off the hub under the hub's terms. A new
snapshot is published when the listed auditors change, and otherwise once
less than %d days of the current one remain; each snapshot is valid for %d
days, and clients treat an expired one as stale. Superseded snapshots are
retained as <catalogId>-<sequence>.json.
`

const privacyText = `# Privacy profile: Onym audit Discovery provider

The provider manifest, the catalog snapshots, the inclusion policy and this
document are static files served without cookies, access logs, or
third-party requests. Fetching them tells this provider nothing about who
fetched them. Clients choose which listed auditors to credit locally; the
provider never learns it.
`
