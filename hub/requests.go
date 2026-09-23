package hub

// Requests for proposals: an orderer publishes what they want examined —
// exact bytes, a subject, a methodology class, a scope — either to every
// auditor or to one Stellar account. Auditors answer with a signed offer
// made for that request; the orderer picks one and orders under it, which
// closes the request. A request is signed with a key of its own; responses
// are shown only to that key, and a directed request only to its addressee.
// The offer, not the request, is what the order binds — so the hub checks
// the order exactly as it checks orders under published offers.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	MaxOpenRequests = 500
	MaxRequestDays  = 30
)

var (
	requestIDRE   = regexp.MustCompile(`^req-[a-z0-9]{20}$`)
	componentIDRE = regexp.MustCompile(`^onym:component:[a-z0-9-]{1,64}$`)
	keyRE         = regexp.MustCompile(`^onym:key:[0-9a-f]{64}$`)
)

// Request is a request for proposals.
type Request struct {
	RequestVersion int            `json:"requestVersion"`
	RequestID      string         `json:"requestId"`
	To             *sig.Key       `json:"to"` // null: every auditor
	Subject        string         `json:"subject"`
	MethodologyCls string         `json:"methodologyClass"`
	Artifact       audit.Artifact `json:"artifact"`
	ScopeText      string         `json:"scopeText"`
	Requester      sig.Key        `json:"requester"`
	IssuedAt       string         `json:"issuedAt"`
	ExpiresAt      string         `json:"expiresAt"`
	Signature      string         `json:"signature"`
}

// ResponseOfferID names the offer an auditor makes for a request.
func ResponseOfferID(requestID string) string { return "rsp-" + strings.TrimPrefix(requestID, "req-") }

func requestOf(offerID string) string { return "req-" + strings.TrimPrefix(offerID, "rsp-") }

func (h *Hub) requestPath(id string) string { return filepath.Join(h.Root, "requests", id+".json") }

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// signedRequest checks a small signed API request: known fields, the named
// key's signature, and a fresh timestamp.
func (h *Hub) signedRequest(raw json.RawMessage, v any, key func() sig.Key, issuedAt func() string) error {
	c, err := canonical(raw)
	if err != nil {
		return err
	}
	if err := strictDecode(c, v); err != nil {
		return err
	}
	at, err := sig.ParseTime(issuedAt())
	if err != nil || at.Sub(h.Now()).Abs() > RequestSkew {
		return errors.New("the request is too old or from the future; check this device's clock")
	}
	if sig.Verify(c, "signature", key()) != nil {
		return errors.New("the request is not signed by the key it names")
	}
	return nil
}

func (h *Hub) loadRequest(id string) (*Request, error) {
	if !requestIDRE.MatchString(id) {
		return nil, errors.New("no such request")
	}
	b, err := os.ReadFile(h.requestPath(id))
	if err != nil {
		return nil, errors.New("no such request")
	}
	var q Request
	if err := json.Unmarshal(b, &q); err != nil {
		return nil, err
	}
	return &q, nil
}

func (h *Hub) open(q *Request) bool {
	exp, err := sig.ParseTime(q.ExpiresAt)
	if err != nil || !h.Now().Before(exp) {
		return false
	}
	_, err = os.Stat(filepath.Join(h.Root, "requests", q.RequestID+".closed"))
	return err != nil
}

func (h *Hub) postRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Request json.RawMessage `json:"request"`
	}
	if !h.body(w, r, 20, &in) {
		return
	}
	raw, err := canonical(in.Request)
	if err != nil {
		fail(w, 422, err)
		return
	}
	var q Request
	if err := strictDecode(raw, &q); err != nil {
		fail(w, 422, fmt.Errorf("malformed request: %v", err))
		return
	}
	issued, ierr := sig.ParseTime(q.IssuedAt)
	exp, eerr := sig.ParseTime(q.ExpiresAt)
	switch {
	case q.RequestVersion != 1 || !requestIDRE.MatchString(q.RequestID):
		err = errors.New("requestVersion/requestId")
	case q.To != nil && !keyRE.MatchString(string(*q.To)):
		err = errors.New("to must be null or an onym:key")
	case !componentIDRE.MatchString(q.Subject):
		err = errors.New("subject must be onym:component:<name>")
	case q.MethodologyCls != audit.SecurityReview && q.MethodologyCls != audit.ConformanceRun:
		err = errors.New("methodologyClass must be security-review or conformance-run")
	case q.Artifact.Validate() != nil:
		err = fmt.Errorf("artifact: %v", q.Artifact.Validate())
	case q.MethodologyCls == audit.ConformanceRun && q.Artifact.Kind != audit.KindDeployment:
		err = errors.New("a conformance run examines a deployment")
	case strings.TrimSpace(q.ScopeText) == "" || len(q.ScopeText) > MaxScopeText:
		err = fmt.Errorf("scopeText must be 1–%d bytes", MaxScopeText)
	case ierr != nil || eerr != nil || issued.Sub(h.Now()).Abs() > RequestSkew || !exp.After(h.Now()) || exp.Sub(issued) > MaxRequestDays*24*time.Hour:
		err = fmt.Errorf("issuedAt must be now and expiresAt within %d days", MaxRequestDays)
	case sig.Verify(raw, "signature", q.Requester) != nil:
		err = errors.New("the request is not signed by its requester key")
	}
	if err != nil {
		fail(w, 422, err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := os.Stat(h.requestPath(q.RequestID)); err == nil {
		fail(w, 409, errors.New("a request with this id exists"))
		return
	}
	if n, _ := filepath.Glob(filepath.Join(h.Root, "requests", "*.json")); len(n) >= MaxOpenRequests {
		fail(w, 503, errors.New("the hub holds too many requests; try again later"))
		return
	}
	if err := os.MkdirAll(filepath.Join(h.Root, "requests"), 0o700); err != nil || writeFile(h.requestPath(q.RequestID), raw) != nil {
		fail(w, 500, errors.New("could not store the request"))
		return
	}
	reply(w, 201, map[string]string{"requestId": q.RequestID, "digest": sig.Digest(raw)})
}

type requestView struct {
	*Request
	Responses int `json:"responses"`
}

// requests lists open requests: every public one, or — for a list request
// signed by a key — the ones addressed to that key.
func (h *Hub) listRequests(to *sig.Key) []requestView {
	paths, _ := filepath.Glob(filepath.Join(h.Root, "requests", "req-*.json"))
	out := []requestView{}
	for _, p := range paths {
		q, err := h.loadRequest(strings.TrimSuffix(filepath.Base(p), ".json"))
		if err != nil || !h.open(q) {
			continue
		}
		if (to == nil) != (q.To == nil) || (to != nil && *to != *q.To) {
			continue
		}
		n, _ := os.ReadDir(filepath.Join(h.Root, "requests", q.RequestID+".responses"))
		out = append(out, requestView{q, len(n)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt > out[j].IssuedAt })
	return out
}

func (h *Hub) publicRequests(w http.ResponseWriter, r *http.Request) {
	reply(w, 200, h.listRequests(nil))
}

func (h *Hub) requestsFor(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Request json.RawMessage `json:"request"`
	}
	if !h.body(w, r, 2, &in) {
		return
	}
	var q struct {
		Action    string  `json:"action"`
		Key       sig.Key `json:"key"`
		IssuedAt  string  `json:"issuedAt"`
		Signature string  `json:"signature"`
	}
	if err := h.signedRequest(in.Request, &q, func() sig.Key { return q.Key }, func() string { return q.IssuedAt }); err != nil || q.Action != "requests-for" {
		fail(w, 403, fmt.Errorf("a list of requests addressed to a key opens only to that key: %v", err))
		return
	}
	reply(w, 200, h.listRequests(&q.Key))
}

// respond stores an auditor's offer for a request, in the auditor's tree.
func (h *Hub) respond(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Slug  string          `json:"slug"`
		Offer json.RawMessage `json:"offer"`
	}
	if !h.body(w, r, 5, &in) {
		return
	}
	q, err := h.loadRequest(id)
	if err != nil || !h.open(q) {
		fail(w, 404, errors.New("no such open request"))
		return
	}
	l := h.lock(in.Slug)
	l.Lock()
	defer l.Unlock()
	m, ok := h.tenant(w, in.Slug)
	if !ok {
		return
	}
	raw, err := canonical(in.Offer)
	if err != nil {
		fail(w, 422, err)
		return
	}
	of, err := audit.ParseOffer(raw)
	if err == nil {
		switch {
		case of.OfferID != ResponseOfferID(id) || of.Auditor != m.ComponentID || of.AuditorKey != m.Operator:
			err = fmt.Errorf("the offer must be %s, signed by this auditor's key", ResponseOfferID(id))
		case of.MethodologyClass != q.MethodologyCls:
			err = fmt.Errorf("the request asks for %s", q.MethodologyCls)
		case q.To != nil && *q.To != m.Operator:
			err = errors.New("this request is addressed to another key")
		}
	}
	if err == nil {
		err = h.pinned(in.Slug, of.Scope, map[string][]byte{})
	}
	if err != nil {
		fail(w, 422, err)
		return
	}
	if err := h.write(in.Slug, map[string][]byte{"offers/" + of.OfferID + ".json": raw}); err != nil {
		fail(w, 507, err)
		return
	}
	dir := filepath.Join(h.Root, "requests", id+".responses")
	os.MkdirAll(dir, 0o700)
	writeFile(filepath.Join(dir, in.Slug), []byte(sig.Digest(raw)))
	reply(w, 201, map[string]string{"offer": h.base(in.Slug) + "offers/" + of.OfferID + ".json"})
}

// responses shows a request's responses to the requester's key only.
func (h *Hub) responses(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Request json.RawMessage `json:"request"`
	}
	if !h.body(w, r, 2, &in) {
		return
	}
	req, err := h.loadRequest(id)
	if err != nil {
		fail(w, 404, err)
		return
	}
	var q struct {
		Action    string `json:"action"`
		RequestID string `json:"requestId"`
		IssuedAt  string `json:"issuedAt"`
		Signature string `json:"signature"`
	}
	if err := h.signedRequest(in.Request, &q, func() sig.Key { return req.Requester }, func() string { return q.IssuedAt }); err != nil || q.Action != "responses" || q.RequestID != id {
		fail(w, 403, errors.New("responses open only to the request's own key"))
		return
	}
	out := []map[string]any{}
	entries, _ := os.ReadDir(filepath.Join(h.Root, "requests", id+".responses"))
	for _, e := range entries {
		slug := e.Name()
		raw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "offers", ResponseOfferID(id)+".json"))
		if err != nil || !slugRE.MatchString(slug) || h.disabled(slug) {
			continue
		}
		mraw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "manifest.json"))
		if err != nil {
			continue
		}
		m, err := audit.ParseManifest(mraw, h.Now())
		if err != nil {
			continue
		}
		orders, customers := orderStats(h.tenantDir(slug))
		out = append(out, map[string]any{"slug": slug, "name": m.DisplayName, "operator": m.Operator, "fingerprint": m.Operator.Fingerprint(), "page": h.base(slug), "completedOrders": orders, "customers": customers, "offer": json.RawMessage(raw)})
	}
	reply(w, 200, map[string]any{"open": h.open(req), "responses": out})
}

// close marks a request answered once an order under one of its responses
// is queued.
func (h *Hub) closeRequest(offerID string) {
	if strings.HasPrefix(offerID, "rsp-") {
		writeFile(filepath.Join(h.Root, "requests", requestOf(offerID)+".closed"), []byte(sig.FormatTime(h.Now())))
	}
}
