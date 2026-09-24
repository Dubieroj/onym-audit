// Package provider publishes a Discovery provider (Discovery-Static-Ed25519)
// with two catalogs. "onym-auditors" lists this site's own seat and every
// auditor hosted on its hub whose manifest verifies under the audit profile.
// "onym-audited-services" (services.go) lists the Onym services that a
// credited auditor has attested, with the attestations surfaced as entry
// status. The Discovery contract keeps direct import open, so any client can
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

// Config names the provider and its catalogs.
type Config struct {
	Base       string        // https://foldy.io/audit/discovery/
	ProviderID string        // onym:component:onym-audit-discovery
	CatalogID  string        // onym-auditors
	Window     time.Duration // snapshot lifetime
	Renew      time.Duration // renew when less than this remains

	// The services catalog; empty ServicesCatalogID publishes none.
	ServicesCatalogID string             // onym-audited-services
	Directory         string             // Onym's default provider manifest, read for where services live
	DirectoryKey      sig.Key            // its operator key, pinned
	Credited          map[string]sig.Key // auditors (component id → operator key) whose attestations set a service's status
}

// Default is this site's provider.
var Default = Config{
	Base: "https://foldy.io/audit/discovery/", ProviderID: "onym:component:onym-audit-discovery", CatalogID: "onym-auditors",
	Window: 30 * 24 * time.Hour, Renew: 7 * 24 * time.Hour,
	ServicesCatalogID: "onym-audited-services",
	Directory:         "https://discovery.onym.app/manifest.json",
	DirectoryKey:      "onym:key:42b0da001104dd03052c7feddab9520c920c9e40d11b245c46c27cf6be853f24",
	Credited: map[string]sig.Key{
		"onym:component:llm-audit":  "onym:key:f3c570a461c6901c48750015783e18e0fbaa827a5061e4a3880fb2636e73d006",
		"onym:component:onym-audit": "onym:key:0e803a08eb56c5742ca0494628f374f86fcae53bd446663e5109e785ddc0ee03",
	},
}

// PublishStatic writes the provider manifest (and its .sig), the catalog's
// inclusion policy and the privacy profile into dir, the directory served
// at c.Base.
func PublishStatic(dir string, c Config, key ed25519.PrivateKey, validUntil time.Time) error {
	days := func(d time.Duration) int { return int(d.Hours() / 24) }
	policy := []byte(fmt.Sprintf(policyText, c.CatalogID, c.ProviderID, c.Base, days(c.Renew), days(c.Window)))
	privacy := []byte(privacyText)
	docs := map[string][]byte{"policies/" + c.CatalogID + ".md": policy, "privacy.md": privacy}
	descriptor := func(id string, seats []string, policy []byte) map[string]any {
		return map[string]any{
			"catalogId": id, "audience": "public", "seatTypes": seats,
			"policy": sig.Digest(policy), "policyUri": c.Base + "policies/" + id + ".md", "snapshot": c.Base + "catalogs/" + id + ".json",
		}
	}
	catalogs := []map[string]any{descriptor(c.CatalogID, []string{SeatType}, policy)}
	if c.ServicesCatalogID != "" {
		ids := make([]string, 0, len(c.Credited))
		for id := range c.Credited {
			ids = append(ids, id)
		}
		sort.Strings(ids) // the policy's bytes, and so its digest, must not vary
		credited := ""
		for _, id := range ids {
			credited += "- `" + id + "`, operator key `" + string(c.Credited[id]) + "`\n"
		}
		sp := []byte(fmt.Sprintf(servicesPolicyText, c.ServicesCatalogID, c.ProviderID, c.Base, c.Directory, c.DirectoryKey, credited, days(c.Renew), days(c.Window)))
		docs["policies/"+c.ServicesCatalogID+".md"] = sp
		catalogs = append(catalogs, descriptor(c.ServicesCatalogID, ServiceSeats, sp))
	}
	for p, b := range docs {
		if err := site.WriteAtomic(filepath.Join(dir, filepath.FromSlash(p)), b); err != nil {
			return err
		}
	}
	m := map[string]any{
		"version": 1, "seat": "discovery", "implementationProfileId": ProfileID, "providerId": c.ProviderID,
		"operator": string(site.KeyOf(key)), "capabilities": []string{"signed-snapshot-v1", "local-filtering-v1"},
		"catalogs": catalogs, "offers": []any{}, "privacyProfile": sig.Digest(privacy), "privacyProfileUri": c.Base + "privacy.md",
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
	Profiles     []string     `json:"profiles,omitempty"`
	Evidence     []any        `json:"evidence"`
	Status       *entryStatus `json:"status,omitempty"`
}

// entryStatus is the §4.2 disclosed warning or review on an entry.
type entryStatus struct {
	State string `json:"state"`
	URI   string `json:"uri"`
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
	// The profile bounds a snapshot at 512 entries; past that a client rejects
	// the whole catalog. Keep this site's own seat, then the longest listed.
	if len(out) > MaxEntries {
		sort.SliceStable(out, func(i, j int) bool {
			if (out[i].Relationship == "common-owner") != (out[j].Relationship == "common-owner") {
				return out[i].Relationship == "common-owner"
			}
			return out[i].ListedAt < out[j].ListedAt
		})
		out = out[:MaxEntries]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ComponentID < out[j].ComponentID })
	return out
}

// MaxEntries is Discovery-Static-Ed25519's bound on entries per snapshot.
const MaxEntries = 512

// Refresh writes a new auditors snapshot when the listed auditors changed or
// the current one nears expiry; it reports whether it did.
func Refresh(dir string, c Config, key ed25519.PrivateKey, sources []Source, now time.Time) (bool, error) {
	return writeCatalog(dir, c, c.CatalogID, key, func(listed map[string]string) []entry { return entries(sources, now, listed) }, now)
}

// writeCatalog builds a catalog's entries (keeping each component's first
// listing time) and writes a new snapshot when they changed, the policy
// changed, or the current snapshot nears expiry.
func writeCatalog(dir string, c Config, catalogID string, key ed25519.PrivateKey, build func(listed map[string]string) []entry, now time.Time) (bool, error) {
	policy, err := os.ReadFile(filepath.Join(dir, "policies", catalogID+".md"))
	if err != nil {
		return false, errors.New("publish the provider's static documents first")
	}
	latestPath := filepath.Join(dir, "catalogs", catalogID+".json")
	var prev snapshot
	prevRaw, err := os.ReadFile(latestPath)
	havePrev := err == nil && json.Unmarshal(prevRaw, &prev) == nil
	listed := map[string]string{}
	if havePrev {
		for _, e := range prev.Entries {
			listed[e.ComponentID] = e.ListedAt
		}
	}
	es := build(listed)
	if havePrev {
		a, _ := json.Marshal(es)
		b, _ := json.Marshal(prev.Entries)
		exp, err := sig.ParseTime(prev.ExpiresAt)
		if string(a) == string(b) && err == nil && exp.Sub(now) > c.Renew && prev.PolicyDigest == sig.Digest(policy) {
			return false, nil
		}
	}
	s := snapshot{
		Version: 1, ImplementationProfileID: ProfileID, ProviderID: c.ProviderID, CatalogID: catalogID, Sequence: 1,
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
	if err := site.WriteAtomic(filepath.Join(dir, "catalogs", fmt.Sprintf("%s-%d.json", catalogID, s.Sequence)), raw); err != nil {
		return false, err
	}
	if err := site.WriteSigned(latestPath, raw); err != nil {
		return false, err
	}
	pruneExpired(dir, catalogID, s.Sequence, now)
	return true, nil
}

// pruneExpired removes retained snapshots that have expired: the profile
// asks only for superseded snapshots that have not (§5), and without this
// they accumulate with every change.
func pruneExpired(dir, catalogID string, latest int64, now time.Time) {
	paths, _ := filepath.Glob(filepath.Join(dir, "catalogs", catalogID+"-*.json"))
	for _, p := range paths {
		var s struct {
			Sequence  int64  `json:"sequence"`
			ExpiresAt string `json:"expiresAt"`
		}
		b, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(b, &s) != nil || s.Sequence == latest {
			continue
		}
		if exp, err := sig.ParseTime(s.ExpiresAt); err == nil && now.After(exp) {
			os.Remove(p)
			os.Remove(p + ".sig")
		}
	}
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

const servicesPolicyText = `# Inclusion policy: the ` + "`%s`" + ` catalog

Published by the Discovery provider ` + "`%s`" + ` at ` + "`%s`" + `.
Every snapshot of this catalog pins these exact bytes by digest.

This catalog exists to show audits where Onym's apps already look: on the
row of a service. Inclusion is not a recommendation of the service and not
a certification; it says only that an auditor named below has published an
attestation about it.

## What is listed

A service is listed while both hold:

1. Onym's own default Discovery catalog lists it. That catalog is read from
   ` + "`%s`" + `, verified under the operator key
   ` + "`%s`" + `, and used only as a list of where each
   service's manifest lives.
2. At least one active, unexpired attestation about its component id has
   been published by one of these auditors, verified against the auditor's
   signed status list and operator key:

%s
Each entry pins the digest of the service's manifest bytes as this provider
fetched them, after checking what a client checks: the component id, the
operator key Onym's catalog names, the seat, the embedded signature, and
expiry. Entries are listed with the same seat type Onym's catalog gives them.

## Status

- ` + "`warning`" + `: an active attestation's result is ` + "`fail`" + `.
- ` + "`review`" + `: an active attestation's result is ` + "`findings-noted`" + ` or
  ` + "`inconclusive`" + `, and none is a fail.
- no status: every active attestation is ` + "`clear`" + `.

The status ` + "`uri`" + ` opens a page listing those attestations; each links to a
page that fetches the signed documents and verifies them in the reader's
browser. Which auditors to credit stays the reader's decision (Audit.md §7).

## Relationships

Every entry's relationship is ` + "`other-disclosed`" + `: this provider takes no
payment from and has no commercial tie to any listed service, but its
operator takes part in Sobor 2026, a contest organized by the maintainer of
Onym's reference services. The credited auditors state their own
relationships in each attestation.

## Ranking, removal and freshness

No ranking: entries are ordered by component id, placement
` + "`policy-ranked`" + `. A service drops out when its attestations are revoked,
superseded or expire, when Onym's catalog stops listing it, or when its
manifest stops verifying. The provider re-reads everything every six hours
and when an auditor on its hub publishes; a new snapshot follows any change,
and otherwise once less than %d days of the current one remain; each is
valid for %d days.
`

const privacyText = `# Privacy profile: Onym audit Discovery provider

The provider manifest, the catalog snapshots, the inclusion policies, the
status pages and this document are static files served without cookies,
access logs, or third-party requests. Fetching them tells this provider
nothing about who fetched them. Clients choose which listed auditors to
credit locally; the provider never learns it.

To build its services catalog, the provider's own server fetches Onym's
default Discovery catalog and the listed services' manifests. Those
requests carry no information about any client.
`
