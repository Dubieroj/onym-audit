package provider

// The "onym-audited-services" catalog: the services Onym's default Discovery
// catalog lists that an auditor this provider credits has attested, each
// pinned to the manifest bytes this provider fetched and verified. Entries
// carry the `status` Discovery-Static-Ed25519 §4.2 defines for disclosed
// warnings and reviews — "warning" when an active attestation is a fail,
// "review" when one notes findings or is inconclusive — and its `uri`
// opens a page listing those attestations. Onym's apps render the status on
// the service's row and link the uri, so a user who adds this provider sees
// the audits without any change to the apps.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"onym-audit/audit"
	"onym-audit/canon"
	"onym-audit/conformance/discovery"
	"onym-audit/sig"
	"onym-audit/site"
)

// ServiceSeats are the seat types this catalog may list: the ones Onym's
// apps offer services for.
var ServiceSeats = []string{"blob.storage", "moderation", "notary", "storage.backup", "transport.message"}

// seatAliases mirrors the Onym apps' seat vocabulary: the manifest `seat`
// values each catalog seat type accepts.
var seatAliases = map[string][]string{
	"notary":            {"notary"},
	"transport.message": {"transport.message", "courier"},
	"blob.storage":      {"blob.storage", "blossom"},
	"moderation":        {"moderation", "authority"},
	"storage.backup":    {"storage.backup"},
}

// Attestation is one active attestation by a credited auditor, as the
// services catalog uses it.
type Attestation struct {
	ID, Slug, Auditor, Subject, Result, Scope, IssuedAt string
}

// CreditedAttestations reads the active, unexpired attestations of the
// sources whose auditor this provider credits (Config.Credited), each
// checked against the auditor's signed status list and its operator key.
func CreditedAttestations(sources []Source, c Config, now time.Time) []Attestation {
	credited := map[string]bool{}
	for _, id := range c.Credited {
		credited[id] = true
	}
	var out []Attestation
	for _, s := range sources {
		raw, err := os.ReadFile(filepath.Join(s.Dir, "manifest.json"))
		if err != nil {
			continue
		}
		m, err := audit.ParseManifest(raw, now)
		if err != nil || !credited[m.ComponentID] {
			continue
		}
		stRaw, err := os.ReadFile(filepath.Join(s.Dir, "status.json"))
		if err != nil {
			continue
		}
		st, err := audit.ParseStatus(stRaw, m, nil, now)
		if err != nil {
			continue
		}
		slug := strings.TrimSuffix(strings.TrimPrefix(s.Base, c.siteRoot()+"a/"), "/")
		if s.Base == c.siteRoot() {
			slug = ""
		}
		for _, e := range st.Entries {
			if e.State != "active" || !strings.HasPrefix(e.Attestation.URI, s.Base) {
				continue
			}
			ar, err := os.ReadFile(filepath.Join(s.Dir, filepath.FromSlash(strings.TrimPrefix(e.Attestation.URI, s.Base))))
			if err != nil || sig.Digest(ar) != e.Attestation.Digest {
				continue
			}
			a, err := audit.ParseAttestation(ar)
			if err != nil || a.AuditorKey != m.Operator || a.AttestationID != e.AttestationID {
				continue
			}
			if a.ExpiresAt != nil {
				if exp, err := sig.ParseTime(*a.ExpiresAt); err != nil || !now.Before(exp) {
					continue
				}
			}
			out = append(out, Attestation{ID: a.AttestationID, Slug: slug, Auditor: m.DisplayName, Subject: a.Subject, Result: a.Result, Scope: a.ScopeSummary, IssuedAt: a.IssuedAt})
		}
	}
	return out
}

func (c Config) siteRoot() string { return strings.TrimSuffix(c.Base, "discovery/") }

// verdictURL is the page that verifies one attestation in the reader's
// browser.
func (c Config) verdictURL(a Attestation) string {
	if a.Slug == "" {
		return c.siteRoot() + "verdict/?id=" + a.ID
	}
	return c.siteRoot() + "verdict/?a=" + a.Slug + "&id=" + a.ID
}

// statusPath names a component's status page under the provider's base.
func statusPath(componentID string) string {
	return "status/" + strings.TrimPrefix(componentID, "onym:component:") + "/"
}

type listing struct {
	componentID, seatType, manifestURI string
	operator                           sig.Key
	profiles                           []string
}

// directory reads the service entries of Onym's default catalog: the
// provider manifest and each catalog snapshot, both verified under the
// operator key pinned in Config.DirectoryKey. It is used only as a list of
// where each service's manifest lives; every manifest is fetched and
// verified again before it is listed.
func directory(ctx context.Context, fetch discovery.Fetcher, c Config) (map[string]listing, error) {
	get := func(uri string, limit int64) (canon.Object, error) {
		r, err := fetch.Get(discovery.WithLimit(ctx, limit), uri)
		if err != nil {
			return nil, err
		}
		if r.Status != 200 || r.Truncated {
			return nil, fmt.Errorf("%s: HTTP %d", uri, r.Status)
		}
		if err := sig.Verify(r.Body, "signature", c.DirectoryKey); err != nil {
			return nil, fmt.Errorf("%s: %v", uri, err)
		}
		return canon.Parse(r.Body)
	}
	pm, err := get(c.Directory, 64<<10)
	if err != nil {
		return nil, err
	}
	out := map[string]listing{}
	cats, _ := pm["catalogs"].([]any)
	for _, cv := range cats {
		d, _ := cv.(canon.Object)
		snap, _ := d["snapshot"].(string)
		if snap == "" {
			continue
		}
		so, err := get(snap, 1<<20)
		if err != nil {
			return nil, err
		}
		es, _ := so["entries"].([]any)
		for _, ev := range es {
			e, _ := ev.(canon.Object)
			id, _ := e["componentId"].(string)
			seat, _ := e["seatType"].(string)
			op, _ := e["operator"].(string)
			mo, _ := e["manifest"].(canon.Object)
			uri, _ := mo["uri"].(string)
			if id == "" || seatAliases[seat] == nil || uri == "" || op == "" {
				continue
			}
			if _, seen := out[id]; seen {
				continue
			}
			l := listing{componentID: id, seatType: seat, manifestURI: uri, operator: sig.Key(op)}
			if ps, ok := e["profiles"].([]any); ok {
				for _, p := range ps {
					if s, ok := p.(string); ok {
						l.profiles = append(l.profiles, s)
					}
				}
			}
			out[id] = l
		}
	}
	return out, nil
}

// review fetches a service's manifest and checks what the Onym apps check
// before using it: its component id, its operator (the key Onym's catalog
// names), its seat against the entry's seat type, its embedded signature
// over the exact bytes, and its expiry. It returns the bytes' digest.
func review(ctx context.Context, fetch discovery.Fetcher, l listing, now time.Time) (string, error) {
	r, err := fetch.Get(discovery.WithLimit(ctx, 256<<10), l.manifestURI)
	if err != nil {
		return "", err
	}
	if r.Status != 200 || r.Truncated {
		return "", fmt.Errorf("HTTP %d", r.Status)
	}
	m, err := canon.Parse(r.Body)
	if err != nil {
		return "", err
	}
	id, _ := m["componentId"].(string)
	op, _ := m["operator"].(string)
	seat, _ := m["seat"].(string)
	switch {
	case id != l.componentID:
		return "", fmt.Errorf("manifest names %q", id)
	case sig.Key(op) != l.operator:
		return "", errors.New("manifest operator differs from the catalog's")
	case !contains(seatAliases[l.seatType], seat):
		return "", fmt.Errorf("seat %q is not a %s seat", seat, l.seatType)
	}
	if err := sig.Verify(r.Body, "signature", l.operator); err != nil {
		return "", err
	}
	if vu, ok := m["validUntil"].(string); ok {
		if t, err := sig.ParseTime(vu); err != nil || !now.Before(t) {
			return "", errors.New("manifest expired")
		}
	}
	return sig.Digest(r.Body), nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// statusOf is the entry status for a component's attestations: a fail
// warns; findings noted or an inconclusive result put it under review; a
// clear result carries no status.
func statusOf(atts []Attestation, uri string) *entryStatus {
	state := ""
	for _, a := range atts {
		switch a.Result {
		case "fail":
			state = "warning"
		case "findings-noted", "inconclusive":
			if state == "" {
				state = "review"
			}
		}
	}
	if state == "" {
		return nil
	}
	return &entryStatus{State: state, URI: uri}
}

// RefreshServices rebuilds the services catalog and its status pages from
// the credited attestations, and writes a new snapshot when the entries
// changed or the current one nears expiry. If Onym's catalog cannot be
// read, the current snapshot stays.
func RefreshServices(ctx context.Context, dir string, c Config, key ed25519.PrivateKey, atts []Attestation, fetch discovery.Fetcher, now time.Time) (bool, error) {
	if c.ServicesCatalogID == "" {
		return false, nil
	}
	bySubject := map[string][]Attestation{}
	for _, a := range atts {
		bySubject[a.Subject] = append(bySubject[a.Subject], a)
	}
	listings, err := directory(ctx, fetch, c)
	if err != nil {
		return false, fmt.Errorf("onym catalog: %w", err)
	}
	pages := map[string][]Attestation{}
	build := func(listed map[string]string) []entry {
		out := []entry{}
		for id, as := range bySubject {
			l, ok := listings[id]
			if !ok {
				continue
			}
			digest, err := review(ctx, fetch, l, now)
			if err != nil {
				continue
			}
			at, ok := listed[id]
			if !ok {
				at = sig.FormatTime(now)
			}
			pages[id] = as
			out = append(out, entry{
				ComponentID: id, SeatType: l.seatType, Manifest: audit.DocRef{URI: l.manifestURI, Digest: digest}, Operator: l.operator,
				ListedAt: at, Relationship: "other-disclosed", Placement: "policy-ranked", Profiles: l.profiles, Evidence: []any{},
				Status: statusOf(as, c.Base+statusPath(id)),
			})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ComponentID < out[j].ComponentID })
		return out
	}
	changed, err := writeCatalog(dir, c, c.ServicesCatalogID, key, build, now)
	if err != nil {
		return false, err
	}
	return changed, writeStatusPages(dir, c, pages)
}

var statusPage = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audits of {{.Component}} · onym audit</title>
<meta name="color-scheme" content="light dark">
<link rel="stylesheet" href="../../../style.css">
</head>
<body>
<main class="wrap verdict-main">
<p class="kicker">Attestations about</p>
<h1 class="verdict-h1">{{.Component}}</h1>
<p class="lede">This service is listed in the <code>{{.Catalog}}</code> Discovery catalog because the auditors below attested it. Each link opens the attestation's page, which fetches the signed documents and verifies them in your browser; this list itself is not signed. Which auditors to trust is your decision.</p>
{{range .Atts}}<article class="entry">
<div class="entry-side"><span class="stamp r-{{.Result}}">{{.Result}}</span></div>
<div><h3><a href="{{.URL}}">{{.Scope}}</a></h3><p class="who">{{.Auditor}} · issued {{.IssuedAt}}</p></div>
</article>
{{end}}<p class="small muted"><a href="{{.Policy}}">Inclusion policy</a> · <a href="{{.Root}}">onym audit</a></p>
</main>
</body>
</html>
`))

// writeStatusPages writes one page per listed component and removes the
// pages of components no longer listed.
func writeStatusPages(dir string, c Config, pages map[string][]Attestation) error {
	type att struct{ Result, Scope, Auditor, IssuedAt, URL string }
	keep := map[string]bool{}
	for id, as := range pages {
		sort.Slice(as, func(i, j int) bool { return as[i].IssuedAt > as[j].IssuedAt })
		view := struct {
			Component, Catalog, Policy, Root string
			Atts                             []att
		}{Component: id, Catalog: c.ServicesCatalogID, Policy: c.Base + "policies/" + c.ServicesCatalogID + ".md", Root: c.siteRoot()}
		for _, a := range as {
			view.Atts = append(view.Atts, att{Result: a.Result, Scope: a.Scope, Auditor: a.Auditor, IssuedAt: a.IssuedAt, URL: c.verdictURL(a)})
		}
		var b strings.Builder
		if err := statusPage.Execute(&b, view); err != nil {
			return err
		}
		p := statusPath(id)
		keep[strings.TrimSuffix(strings.TrimPrefix(p, "status/"), "/")] = true
		if err := site.WriteAtomic(filepath.Join(dir, filepath.FromSlash(p), "index.html"), []byte(b.String())); err != nil {
			return err
		}
	}
	ds, _ := os.ReadDir(filepath.Join(dir, "status"))
	for _, d := range ds {
		if d.IsDir() && !keep[d.Name()] {
			os.RemoveAll(filepath.Join(dir, "status", d.Name()))
		}
	}
	return nil
}
