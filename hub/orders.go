package hub

// Orders: anyone may order an examination from any hosted auditor under one
// of the offers the auditor signed. Orders wait in a private inbox that only
// the auditor's key can read; the auditor countersigns an order when it signs
// the commissioned attestation, and the hub publishes both. A failing result
// under an order whose disclosure terms embargo failures is held by the hub
// and released when the embargo ends — the terms bind the hub, not only the
// auditor's good intentions.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"onym-audit/audit"
	"onym-audit/sig"
)

const (
	MaxInbox     = 100  // queued orders per auditor
	MaxScopeText = 8000 // bytes of an order's scope text
	RequestSkew  = 10 * time.Minute
)

var (
	contactRE = regexp.MustCompile(`^mailto:[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$`)
	orderIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

func (h *Hub) inboxDir(slug string) string { return filepath.Join(h.Root, "inbox", slug) }
func (h *Hub) heldDir(slug string) string  { return filepath.Join(h.Root, "held", slug) }

// offer reads and checks one of a tenant's published offers.
func (h *Hub) offer(slug string, m *audit.AuditorManifest, id string) (*audit.Offer, error) {
	listed := false
	for _, o := range m.Offers {
		listed = listed || o == id
	}
	// An offer made for a request is not listed in the manifest; it stands
	// while its request is open.
	if strings.HasPrefix(id, "rsp-") {
		q, err := h.loadRequest(requestOf(id))
		listed = err == nil && h.open(q)
	}
	if !listed {
		return nil, fmt.Errorf("this auditor offers no %q", id)
	}
	raw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "offers", id+".json"))
	if err != nil {
		return nil, fmt.Errorf("offer %s is not published", id)
	}
	of, err := audit.ParseOffer(raw)
	if err != nil {
		return nil, err
	}
	if of.OfferID != id || of.Auditor != m.ComponentID || of.AuditorKey != m.Operator {
		return nil, fmt.Errorf("offer %s is not this auditor's", id)
	}
	return of, nil
}

// postOrder queues an order signed by its subject and sponsor, with its scope
// text and the orderer's contact (the envelope form of profile §5.3).
func (h *Hub) postOrder(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in struct {
		Order     json.RawMessage `json:"order"`
		ScopeText string          `json:"scopeText"`
		Contact   string          `json:"contact"`
	}
	if !h.body(w, r, 10, &in) {
		return
	}
	l := h.lock(slug)
	l.Lock()
	defer l.Unlock()
	m, ok := h.tenant(w, slug)
	if !ok {
		return
	}
	raw, err := canonical(in.Order)
	if err != nil {
		fail(w, 422, err)
		return
	}
	o, err := audit.ParseOrderRequest(raw, m.ComponentID)
	if err == nil {
		var of *audit.Offer
		if of, err = h.offer(slug, m, o.Fee.OfferID); err == nil {
			err = audit.OrderMatchesOffer(o, of, h.Now())
		}
	}
	if err == nil {
		switch want := h.base(slug) + "scopes/order-" + o.OrderID + ".md"; {
		case o.Scope.URI != want:
			err = fmt.Errorf("the order's scope must be %s", want)
		case strings.TrimSpace(in.ScopeText) == "" || len(in.ScopeText) > MaxScopeText:
			err = fmt.Errorf("scopeText must be 1–%d bytes", MaxScopeText)
		case sig.Digest([]byte(in.ScopeText)) != o.Scope.Digest:
			err = errors.New("scopeText does not hash to the order's scope digest")
		case !contactRE.MatchString(in.Contact):
			err = errors.New("contact must be a mailto: address")
		}
	}
	// An offer made for a request is taken only by that request's author,
	// for what the request asked: its sponsor key is the request's key.
	if err == nil && strings.HasPrefix(o.Fee.OfferID, "rsp-") {
		q, qerr := h.loadRequest(requestOf(o.Fee.OfferID))
		switch {
		case qerr != nil:
			err = errors.New("the request this offer answers is gone")
		case o.Sponsor != q.Requester:
			err = errors.New("only the request's author can order under its responses (sponsor must be the requester key)")
		case o.Subject != q.Subject || o.MethodologyCls != q.MethodologyCls || !sameArtifact(o.Artifact, q.Artifact):
			err = errors.New("the order must be for the subject and artifact the request named")
		}
	}
	if err != nil {
		fail(w, 422, err)
		return
	}
	if _, err := os.Stat(filepath.Join(h.tenantDir(slug), "orders", o.OrderID+".json")); err == nil || h.heldOrder(slug, o.OrderID) != nil {
		fail(w, 409, errors.New("this order has already been fulfilled"))
		return
	}
	dir := filepath.Join(h.inboxDir(slug), o.OrderID)
	if prev, err := os.ReadFile(filepath.Join(dir, "order.json")); err == nil {
		if !bytes.Equal(prev, raw) {
			fail(w, 409, errors.New("a different order with this id is already queued"))
			return
		}
	} else {
		if n, _ := os.ReadDir(h.inboxDir(slug)); len(n) >= MaxInbox {
			fail(w, 503, errors.New("this auditor's order inbox is full; use the contact in their manifest"))
			return
		}
		meta, _ := json.Marshal(map[string]string{"contact": in.Contact, "receivedAt": sig.FormatTime(h.Now())})
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fail(w, 500, errors.New("could not queue the order"))
			return
		}
		for name, b := range map[string][]byte{"order.json": raw, "scope.md": []byte(in.ScopeText), "meta.json": meta} {
			if err := writeFile(filepath.Join(dir, name), b); err != nil {
				fail(w, 500, errors.New("could not queue the order"))
				return
			}
		}
	}
	h.closeRequest(o.Fee.OfferID)
	reply(w, 202, map[string]string{"orderId": o.OrderID, "state": "queued-for-review", "digest": sig.Digest(raw)})
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// inbox answers requests signed by the auditor's own key: list the queued
// orders (with the orderers' contacts, which only the auditor sees) and the
// attestations held under embargo, or decline an order.
func (h *Hub) inbox(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in struct {
		Request json.RawMessage `json:"request"`
	}
	if !h.body(w, r, 2, &in) {
		return
	}
	l := h.lock(slug)
	l.Lock()
	defer l.Unlock()
	m, ok := h.tenant(w, slug)
	if !ok {
		return
	}
	raw, err := canonical(in.Request)
	if err != nil {
		fail(w, 422, err)
		return
	}
	var q struct {
		Action    string  `json:"action"`
		Auditor   string  `json:"auditor"`
		OrderID   *string `json:"orderId"`
		IssuedAt  string  `json:"issuedAt"`
		Signature string  `json:"signature"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		fail(w, 422, err)
		return
	}
	at, terr := sig.ParseTime(q.IssuedAt)
	switch {
	case q.Auditor != m.ComponentID:
		err = errors.New("the request names another auditor")
	case sig.Verify(raw, "signature", m.Operator) != nil:
		err = errors.New("the request is not signed by this auditor's key")
	case terr != nil || at.Sub(h.Now()).Abs() > RequestSkew:
		err = errors.New("the request is too old or from the future; check this device's clock")
	}
	if err != nil {
		fail(w, 403, err)
		return
	}
	switch q.Action {
	case "list":
		reply(w, 200, map[string]any{"orders": h.queued(slug), "held": h.held(slug)})
	case "decline":
		if q.OrderID == nil || !orderIDRE.MatchString(*q.OrderID) {
			fail(w, 422, errors.New("orderId"))
			return
		}
		os.RemoveAll(filepath.Join(h.inboxDir(slug), *q.OrderID))
		reply(w, 200, map[string]string{"declined": *q.OrderID})
	default:
		fail(w, 422, fmt.Errorf("action %q", q.Action))
	}
}

type queuedOrder struct {
	Order      json.RawMessage `json:"order"`
	ScopeText  string          `json:"scopeText"`
	Contact    string          `json:"contact"`
	ReceivedAt string          `json:"receivedAt"`
}

func (h *Hub) queued(slug string) []queuedOrder {
	out := []queuedOrder{}
	entries, _ := os.ReadDir(h.inboxDir(slug))
	for _, e := range entries {
		dir := filepath.Join(h.inboxDir(slug), e.Name())
		o, err1 := os.ReadFile(filepath.Join(dir, "order.json"))
		s, err2 := os.ReadFile(filepath.Join(dir, "scope.md"))
		mb, err3 := os.ReadFile(filepath.Join(dir, "meta.json"))
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		var meta struct{ Contact, ReceivedAt string }
		json.Unmarshal(mb, &meta)
		out = append(out, queuedOrder{Order: o, ScopeText: string(s), Contact: meta.Contact, ReceivedAt: meta.ReceivedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt < out[j].ReceivedAt })
	return out
}

// ---------------------------------------------------------------- commissioned attestations

// commissioned checks a commissioned attestation against the order it
// names: the order must travel with it, carry all three signatures (the
// auditor's by this auditor's key), and bind exactly what the attestation
// binds. It returns the order and its published path.
func (h *Hub) commissioned(m *audit.AuditorManifest, a *audit.Attestation, offered map[string][]byte) (*audit.AuditOrder, string, error) {
	var opath string
	for p := range offered {
		if strings.HasPrefix(p, "orders/") {
			if opath != "" {
				return nil, "", errors.New("one order per attestation")
			}
			opath = p
		}
	}
	if a.Engagement != "commissioned" {
		if opath != "" {
			return nil, "", errors.New("orders are published only with the commissioned attestation they commission")
		}
		return nil, "", nil
	}
	if opath == "" {
		return nil, "", errors.New("a commissioned attestation is published with its countersigned order")
	}
	raw := offered[opath]
	o, err := audit.ParseOrder(raw)
	if err != nil {
		return nil, "", fmt.Errorf("order: %w", err)
	}
	keys := map[string]sig.Key{}
	for _, s := range o.Signatures {
		keys[s.Role] = s.Key
	}
	ah := func(x audit.Artifact) string {
		if x.ArtifactHash == nil {
			return x.Kind + " " + x.Source + " " + x.Revision
		}
		return x.Kind + " " + x.Source + " " + x.Revision + " " + *x.ArtifactHash
	}
	switch {
	case opath != "orders/"+o.OrderID+".json":
		err = fmt.Errorf("the order is published at orders/%s.json", o.OrderID)
	case sig.Digest(raw) != *a.OrderRef:
		err = errors.New("orderRef is not the digest of the countersigned order")
	case o.Auditor != m.ComponentID || keys["auditor"] != m.Operator:
		err = errors.New("the order is not countersigned by this auditor's key")
	case o.Subject != a.Subject || keys["subject"] != a.SubjectOperator:
		err = errors.New("subject and subjectOperator must be the order's subject and its signing key")
	case o.Sponsor != a.Sponsor:
		err = errors.New("sponsor must be the order's sponsor")
	case ah(o.Artifact) != ah(a.Artifact):
		err = errors.New("the attestation must bind exactly the artifact the order binds")
	case o.MethodologyCls != a.MethodologyClass:
		err = errors.New("the attestation must use the order's methodology class")
	case o.Scope != a.Scope:
		err = errors.New("the attestation's scope must be the order's scope document")
	}
	if err != nil {
		return nil, "", err
	}
	return o, opath, nil
}

type heldFile struct {
	ReleaseAt string            `json:"releaseAt"`
	Files     map[string]string `json:"files"`
}

// hold keeps an attestation and its report unpublished until releaseAt.
func (h *Hub) hold(slug, id string, releaseAt time.Time, files map[string][]byte) error {
	hf := heldFile{ReleaseAt: sig.FormatTime(releaseAt), Files: map[string]string{}}
	for p, b := range files {
		hf.Files[p] = string(b)
	}
	b, err := json.Marshal(hf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.heldDir(slug), 0o700); err != nil {
		return err
	}
	return writeFile(filepath.Join(h.heldDir(slug), id+".json"), b)
}

type heldEntry struct {
	AttestationID string `json:"attestationId"`
	ReleaseAt     string `json:"releaseAt"`
}

func (h *Hub) held(slug string) []heldEntry {
	out := []heldEntry{}
	paths, _ := filepath.Glob(filepath.Join(h.heldDir(slug), "*.json"))
	for _, p := range paths {
		var hf heldFile
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &hf) == nil {
			out = append(out, heldEntry{AttestationID: strings.TrimSuffix(filepath.Base(p), ".json"), ReleaseAt: hf.ReleaseAt})
		}
	}
	return out
}

// heldOrder returns the countersigned order held with an embargoed
// attestation, if any.
func (h *Hub) heldOrder(slug, orderID string) []byte {
	paths, _ := filepath.Glob(filepath.Join(h.heldDir(slug), "*.json"))
	for _, p := range paths {
		var hf heldFile
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &hf) == nil {
			if o, ok := hf.Files["orders/"+orderID+".json"]; ok {
				return []byte(o)
			}
		}
	}
	return nil
}

func sameArtifact(a, b audit.Artifact) bool {
	return a.Kind == b.Kind && a.Source == b.Source && a.Revision == b.Revision &&
		(a.ArtifactHash == nil) == (b.ArtifactHash == nil) && (a.ArtifactHash == nil || *a.ArtifactHash == *b.ArtifactHash)
}

func (h *Hub) isHeld(slug, id string) bool {
	_, err := os.Stat(filepath.Join(h.heldDir(slug), id+".json"))
	return err == nil
}

// release publishes held attestations whose embargo has ended. The caller
// holds the tenant's lock and re-signs the status list afterwards.
func (h *Hub) release(slug string) {
	paths, _ := filepath.Glob(filepath.Join(h.heldDir(slug), "*.json"))
	for _, p := range paths {
		var hf heldFile
		b, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(b, &hf) != nil {
			continue
		}
		at, err := sig.ParseTime(hf.ReleaseAt)
		if err != nil || h.Now().Before(at) {
			continue
		}
		files := map[string][]byte{}
		for f, s := range hf.Files {
			files[f] = []byte(s)
		}
		if err := h.write(slug, files); err != nil {
			log.Printf("hub: %s: held %s not released: %v", slug, filepath.Base(p), err)
			continue
		}
		os.Remove(p)
	}
}

// orderStatus tells an orderer whether their order still waits in the
// auditor's queue. The request is signed by the order's sponsor key — the
// per-order key only the orderer holds — so nobody else learns it.
func (h *Hub) orderStatus(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in struct {
		Request json.RawMessage `json:"request"`
	}
	if !h.body(w, r, 1, &in) {
		return
	}
	if _, ok := h.tenant(w, slug); !ok {
		return
	}
	raw, err := canonical(in.Request)
	if err != nil {
		fail(w, 422, err)
		return
	}
	var q struct {
		Action    string  `json:"action"`
		OrderID   string  `json:"orderId"`
		Sponsor   sig.Key `json:"sponsor"`
		IssuedAt  string  `json:"issuedAt"`
		Signature string  `json:"signature"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil || q.Action != "order-status" || !orderIDRE.MatchString(q.OrderID) {
		fail(w, 422, errors.New("malformed status request"))
		return
	}
	at, terr := sig.ParseTime(q.IssuedAt)
	if terr != nil || at.Sub(h.Now()).Abs() > RequestSkew || sig.Verify(raw, "signature", q.Sponsor) != nil {
		fail(w, 403, errors.New("the request must be signed by the order's sponsor key, now"))
		return
	}
	queued, held := false, false
	if b, err := os.ReadFile(filepath.Join(h.inboxDir(slug), q.OrderID, "order.json")); err == nil {
		if o, err := audit.ParseOrderRequest(b, "onym:component:"+slug); err == nil && o.Sponsor == q.Sponsor {
			queued = true
		}
	}
	if b := h.heldOrder(slug, q.OrderID); b != nil {
		var o struct {
			Sponsor sig.Key `json:"sponsor"`
		}
		held = json.Unmarshal(b, &o) == nil && o.Sponsor == q.Sponsor
	}
	reply(w, 200, map[string]bool{"queued": queued, "held": held})
}
