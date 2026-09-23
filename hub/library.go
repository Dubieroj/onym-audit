package hub

// The library lists every attestation this hub serves — the operator's seat
// and every hosted auditor — with its current state, so readers can find a
// verdict by its id, subject, or auditor. It is an index, not an authority:
// each entry names the documents a reader's browser verifies itself, and
// failing and revoked results are listed exactly like favorable ones
// (Audit.md §7: hiding adverse attestations is nonconforming curation).

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"onym-audit/audit"
)

type libraryEntry struct {
	AttestationID string `json:"attestationId"`
	Auditor       string `json:"auditor"`     // display name
	AuditorSlug   string `json:"auditorSlug"` // "" for the operator's seat
	AuditorBase   string `json:"auditorBase"`
	Fingerprint   string `json:"fingerprint"`
	Subject       string `json:"subject"`
	Result        string `json:"result"`
	State         string `json:"state"`
	Methodology   string `json:"methodologyClass"`
	Kind          string `json:"kind"`
	Source        string `json:"source"`
	Engagement    string `json:"engagement"`
	IssuedAt      string `json:"issuedAt"`
	ExpiresAt     string `json:"expiresAt"`
	OrderRef      string `json:"orderRef"` // the countersigned order's digest, for commissioned results
	URI           string `json:"uri"`
}

// tree reads one auditor tree: its manifest, its status list's entries, and
// the attestations they name. Signatures are the reader's to check; the
// entry's state is what the status list says.
func (h *Hub) tree(dir, base, slug string) ([]libraryEntry, *audit.AuditorManifest) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, nil
	}
	m, err := audit.ParseManifest(raw, h.Now())
	if err != nil {
		return nil, nil
	}
	var st audit.StatusList
	sb, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil || json.Unmarshal(sb, &st) != nil {
		return nil, m
	}
	var out []libraryEntry
	for _, e := range st.Entries {
		if !strings.HasPrefix(e.Attestation.URI, base) {
			continue
		}
		ab, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(filepath.Clean("/"+strings.TrimPrefix(e.Attestation.URI, base)))))
		if err != nil {
			continue
		}
		a, err := audit.ParseAttestation(ab)
		if err != nil {
			continue
		}
		exp, ref := "", ""
		if a.ExpiresAt != nil {
			exp = *a.ExpiresAt
		}
		if a.OrderRef != nil {
			ref = *a.OrderRef
		}
		out = append(out, libraryEntry{
			AttestationID: a.AttestationID, Auditor: m.DisplayName, AuditorSlug: slug, AuditorBase: base, Fingerprint: m.Operator.Fingerprint(),
			Subject: a.Subject, Result: a.Result, State: e.State, Methodology: a.MethodologyClass, Kind: a.Artifact.Kind, Source: a.Artifact.Source,
			Engagement: a.Engagement, IssuedAt: a.IssuedAt, ExpiresAt: exp, OrderRef: ref, URI: e.Attestation.URI,
		})
	}
	return out, m
}

// orderStats counts an auditor's fulfilled orders — countersigned orders it
// published — and the distinct sponsors among them. Both are public facts
// anyone can recount from the tree; neither measures quality, and keys are
// free, so both can be inflated.
func orderStats(dir string) (orders, customers int) {
	paths, _ := filepath.Glob(filepath.Join(dir, "orders", "*.json"))
	seen := map[string]bool{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		o, err := audit.ParseOrder(b)
		if err != nil {
			continue
		}
		orders++
		seen[string(o.Sponsor)] = true
	}
	return orders, len(seen)
}

func (h *Hub) library(w http.ResponseWriter, r *http.Request) {
	all, _ := h.tree(h.PublicRoot, h.PublicBase, "")
	entries, _ := os.ReadDir(filepath.Join(h.Root, "tenants"))
	for _, e := range entries {
		slug := e.Name()
		if !slugRE.MatchString(slug) || h.disabled(slug) {
			continue
		}
		es, _ := h.tree(h.tenantDir(slug), h.base(slug), slug)
		all = append(all, es...)
	}
	if all == nil {
		all = []libraryEntry{}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].IssuedAt > all[j].IssuedAt })
	reply(w, 200, all)
}

// seat describes the operator's own auditor seat with the same public facts
// the hub lists for hosted auditors.
func (h *Hub) seat(w http.ResponseWriter, r *http.Request) {
	es, m := h.tree(h.PublicRoot, h.PublicBase, "")
	if m == nil {
		fail(w, 404, errors.New("this hub's operator runs no auditor seat"))
		return
	}
	orders, customers := orderStats(h.PublicRoot)
	reply(w, 200, map[string]any{"slug": "", "name": m.DisplayName, "operator": m.Operator, "fingerprint": m.Operator.Fingerprint(), "page": h.PublicBase, "attestations": len(es), "offers": len(m.Offers), "completedOrders": orders, "customers": customers})
}
