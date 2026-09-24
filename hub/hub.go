// Package hub hosts auditors other than the operator: anyone can take the
// audit seat through the web studio, keeping their auditor key in their own
// browser. The hub publishes each auditor's signed documents byte-for-byte
// under a/<slug>/, and holds only a per-auditor delegated status key — the
// profile's §4.2 design — so it can keep status lists fresh but cannot
// issue, alter, or revoke anything an auditor did not sign.
//
// The hub is a replaceable default, like Onym's own default deployments:
// every auditor can download their tree and serve it elsewhere.
package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"onym-audit/audit"
	"onym-audit/canon"
	"onym-audit/conformance/discovery"
	"onym-audit/netguard"
	"onym-audit/sig"
	"onym-audit/site"
	"onym-audit/urirule"
)

// Limits on what one auditor may store and send.
const (
	MaxTenantBytes = 20 << 20
	MaxDocBytes    = 1 << 20
	MaxBodyBytes   = 4 << 20
	MaxFetchBytes  = 1 << 20
	MaxHashBytes   = 300 << 20
	ClaimTTL       = 30 * time.Minute
)

// Hub serves the studio's API and every hosted auditor's tree.
type Hub struct {
	Root       string // tenants/<slug>/, keys/<slug>.key, claims/, inbox/<slug>/, held/<slug>/
	PublicRoot string // the operator's public tree: shared profile, scale, docs
	PublicBase string // https://foldy.io/audit/
	Now        func() time.Time
	OnChange   func() // called after an auditor registers, publishes, or revokes

	mu      sync.Mutex
	stripes [256]sync.Mutex // per-tenant locks, by hash of the name
	limiter *limiter
	client  *http.Client
	heavy   chan struct{} // bounds concurrent digests and conformance runs
}

// New prepares the hub's directories.
func New(root, publicRoot, publicBase string) (*Hub, error) {
	for _, d := range []string{"tenants", "keys", "claims", "inbox", "held", "requests", "vaults"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			return nil, err
		}
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: 15 * time.Second, Control: netguard.Control}
	t.DialContext = d.DialContext
	return &Hub{
		Root: root, PublicRoot: publicRoot, PublicBase: publicBase, Now: time.Now,
		limiter: newLimiter(), heavy: make(chan struct{}, 2),
		client: &http.Client{Transport: t, Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return errors.New("more than 3 redirects")
			}
			return urirule.Check(req.URL.String())
		}},
	}, nil
}

var (
	slugRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)
	reserved  = map[string]bool{"admin": true, "api": true, "hub": true, "audit": true, "onym": true, "onym-audit": true, "foundation": true, "sobor": true, "root": true, "status": true, "www": true}
	docPathRE = regexp.MustCompile(`^(policies|methodology|scopes|reports|offers|notes|orders)/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(md|json)$`)
)

func (h *Hub) base(slug string) string      { return h.PublicBase + "a/" + slug + "/" }
func (h *Hub) tenantDir(slug string) string { return filepath.Join(h.Root, "tenants", slug) }

// lock returns the tenant's lock: one of a fixed set, so names taken from
// requests cannot grow memory.
func (h *Hub) lock(slug string) *sync.Mutex {
	f := fnv.New32a()
	f.Write([]byte(slug))
	return &h.stripes[f.Sum32()%uint32(len(h.stripes))]
}

func (h *Hub) config(slug string, m *audit.AuditorManifest) *site.Config {
	return &site.Config{BaseURI: h.base(slug), ComponentID: m.ComponentID, DisplayName: m.DisplayName, Contact: m.Contact}
}

func (h *Hub) statusKey(slug string) (ed25519.PrivateKey, error) {
	return site.LoadKey(filepath.Join(h.Root, "keys", slug+".key"))
}

func (h *Hub) disabled(slug string) bool {
	_, err := os.Stat(filepath.Join(h.Root, "tenants", slug, ".disabled"))
	return err == nil
}

// ---------------------------------------------------------------- HTTP

// Handler serves hub/api/… and a/<slug>/… (paths relative to the operator's
// base; the reverse proxy strips the public prefix).
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hub/api/claim", h.claim)
	mux.HandleFunc("POST /hub/api/register", h.register)
	mux.HandleFunc("POST /hub/api/a/{slug}/publish", h.publish)
	mux.HandleFunc("POST /hub/api/a/{slug}/revoke", h.revoke)
	mux.HandleFunc("POST /hub/api/fetch", h.fetch)
	mux.HandleFunc("POST /hub/api/digest", h.digest)
	mux.HandleFunc("POST /hub/api/conformance/discovery", h.conformance)
	mux.HandleFunc("GET /hub/api/auditors", h.auditors)
	mux.HandleFunc("GET /hub/api/library", h.library)
	mux.HandleFunc("GET /hub/api/seat", h.seat)
	mux.HandleFunc("GET /hub/api/requests", h.publicRequests)
	mux.HandleFunc("POST /hub/api/requests", h.postRequest)
	mux.HandleFunc("POST /hub/api/requests/for", h.requestsFor)
	mux.HandleFunc("POST /hub/api/requests/{id}/responses", h.respond)
	mux.HandleFunc("POST /hub/api/requests/{id}/mine", h.responses)
	mux.HandleFunc("POST /hub/api/vault", h.vault)
	mux.HandleFunc("POST /hub/api/a/{slug}/order-status", h.orderStatus)
	mux.HandleFunc("GET /hub/api/a/{slug}/export", h.export)
	mux.HandleFunc("POST /hub/api/a/{slug}/inbox", h.inbox)
	mux.HandleFunc("POST /a/{slug}/orders", h.postOrder)
	mux.HandleFunc("POST /a/{slug}/responses", h.response)
	mux.HandleFunc("GET /a/{slug}/{path...}", h.static)
	mux.HandleFunc("GET /a/{slug}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.PathValue("slug")+"/", http.StatusMovedPermanently)
	})
	return mux
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	reply(w, code, map[string]string{"error": err.Error()})
}

// client identifies the caller for rate limiting: nginx sets X-Real-IP; it is
// trusted only when the request reached us over loopback.
func client(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "127.0.0.1" || host == "::1" {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			host = ip
		}
	}
	// One IPv6 holder has a whole /64: count it as one address.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return host
}

func (h *Hub) body(w http.ResponseWriter, r *http.Request, cost int, v any) bool {
	if !h.limiter.allow(client(r), cost) {
		fail(w, http.StatusTooManyRequests, errors.New("slow down: too many requests from this address"))
		return false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(b) > MaxBodyBytes {
		fail(w, http.StatusRequestEntityTooLarge, errors.New("request too large"))
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("malformed request: %v", err))
		return false
	}
	return true
}

// ---------------------------------------------------------------- claim & register

type claimFile struct {
	StatusKey sig.Key `json:"statusKey"`
	Expires   string  `json:"expires"`
}

// claim reserves a slug and mints its delegated status key, which the
// auditor's manifest must name before it is signed.
func (h *Hub) claim(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Slug string `json:"slug"`
	}
	if !h.body(w, r, 5, &in) {
		return
	}
	if !slugRE.MatchString(in.Slug) || reserved[in.Slug] {
		fail(w, 422, errors.New("the name must be 3–32 lowercase letters, digits or dashes, start with a letter, and not be reserved"))
		return
	}
	l := h.lock(in.Slug)
	l.Lock()
	defer l.Unlock()
	if _, err := os.Stat(filepath.Join(h.tenantDir(in.Slug), "manifest.json")); err == nil {
		fail(w, 409, errors.New("that name is taken"))
		return
	}
	cpath := filepath.Join(h.Root, "claims", in.Slug+".json")
	now := h.Now()
	if b, err := os.ReadFile(cpath); err == nil {
		var c claimFile
		json.Unmarshal(b, &c)
		if exp, _ := sig.ParseTime(c.Expires); now.Before(exp) {
			// An unexpired claim is returned as is: the studio may retry.
			reply(w, 200, map[string]string{"slug": in.Slug, "statusKey": string(c.StatusKey), "base": h.base(in.Slug), "componentId": "onym:component:" + in.Slug, "expires": c.Expires})
			return
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	key := site.KeyOf(ed25519.NewKeyFromSeed(seed))
	if err := os.WriteFile(filepath.Join(h.Root, "keys", in.Slug+".key"), []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		fail(w, 500, errors.New("could not store the status key"))
		return
	}
	c := claimFile{StatusKey: key, Expires: sig.FormatTime(now.Add(ClaimTTL))}
	b, _ := json.Marshal(c)
	os.WriteFile(cpath, b, 0o600)
	reply(w, 200, map[string]string{"slug": in.Slug, "statusKey": string(key), "base": h.base(in.Slug), "componentId": "onym:component:" + in.Slug, "expires": c.Expires})
}

// docs checks a set of documents offered for a tenant tree.
func (h *Hub) docs(in map[string]string) (map[string][]byte, error) {
	out := map[string][]byte{}
	total := 0
	for p, text := range in {
		if !docPathRE.MatchString(p) || strings.Contains(p, "..") {
			return nil, fmt.Errorf("document path %q is not allowed", p)
		}
		if len(text) > MaxDocBytes {
			return nil, fmt.Errorf("%s is larger than 1 MiB", p)
		}
		if strings.HasSuffix(p, ".json") {
			if _, err := canon.Parse([]byte(text)); err != nil {
				return nil, fmt.Errorf("%s: %v", p, err)
			}
		}
		total += len(text)
		out[p] = []byte(text)
	}
	if total > MaxBodyBytes {
		return nil, errors.New("documents too large")
	}
	return out, nil
}

// pinned checks that ref names bytes the hub can serve: a document of this
// tenant (offered now or stored before) or a shared document of the
// operator's tree, with a matching digest.
func (h *Hub) pinned(slug string, ref audit.DocRef, offered map[string][]byte) error {
	tb := h.base(slug)
	switch {
	case strings.HasPrefix(ref.URI, tb):
		p := strings.TrimPrefix(ref.URI, tb)
		b, ok := offered[p]
		if !ok {
			var err error
			if b, err = os.ReadFile(filepath.Join(h.tenantDir(slug), filepath.FromSlash(p))); err != nil || !docPathRE.MatchString(p) {
				return fmt.Errorf("%s is neither offered nor stored", ref.URI)
			}
		}
		if sig.Digest(b) != ref.Digest {
			return fmt.Errorf("%s does not match its digest", ref.URI)
		}
	case strings.HasPrefix(ref.URI, h.PublicBase) && !strings.HasPrefix(ref.URI, h.PublicBase+"a/"):
		p := strings.TrimPrefix(ref.URI, h.PublicBase)
		b, err := os.ReadFile(filepath.Join(h.PublicRoot, filepath.FromSlash(filepath.Clean("/"+p))))
		if err != nil || sig.Digest(b) != ref.Digest {
			return fmt.Errorf("%s is not the shared document it pins", ref.URI)
		}
	default:
		return fmt.Errorf("%s is outside this hub; host it here or self-host the whole tree", ref.URI)
	}
	return nil
}

func (h *Hub) usage(slug string) int64 {
	var n int64
	filepath.WalkDir(h.tenantDir(slug), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

func (h *Hub) write(slug string, files map[string][]byte) error {
	return h.writeFiles(slug, files, true)
}

// writeFiles writes a tenant's files, within its quota when quota is set.
func (h *Hub) writeFiles(slug string, files map[string][]byte, quota bool) error {
	var add int64
	for p, b := range files {
		add += int64(len(b))
		if fi, err := os.Stat(filepath.Join(h.tenantDir(slug), filepath.FromSlash(p))); err == nil {
			add -= fi.Size()
		}
	}
	if quota && h.usage(slug)+add > MaxTenantBytes {
		return errors.New("this auditor's storage on the hub is full (20 MiB); self-host the tree to grow")
	}
	for p, b := range files {
		full := filepath.Join(h.tenantDir(slug), filepath.FromSlash(p))
		if strings.HasPrefix(p, "attestations/") || strings.HasPrefix(p, "revocations/") || strings.HasPrefix(p, "offers/") || p == "manifest.json" {
			if err := site.WriteSigned(full, b); err != nil {
				return err
			}
			continue
		}
		if err := site.WriteAtomic(full, b); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hub) resign(slug string) error {
	raw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "manifest.json"))
	if err != nil {
		return err
	}
	m, err := audit.ParseManifest(raw, h.Now())
	if err != nil {
		return err
	}
	k, err := h.statusKey(slug)
	if err != nil {
		return err
	}
	return site.ResignStatus(h.tenantDir(slug), h.config(slug, m), k, h.Now())
}

// register publishes (or replaces) an auditor manifest. The first manifest
// pins the operator key to the name; later ones must be signed by it.
func (h *Hub) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Slug     string            `json:"slug"`
		Manifest json.RawMessage   `json:"manifest"`
		Docs     map[string]string `json:"docs"`
	}
	if !h.body(w, r, 10, &in) {
		return
	}
	if !slugRE.MatchString(in.Slug) || reserved[in.Slug] || h.disabled(in.Slug) {
		fail(w, 422, errors.New("that name cannot be registered"))
		return
	}
	l := h.lock(in.Slug)
	l.Lock()
	defer l.Unlock()
	mraw, err := canonical(in.Manifest)
	if err != nil {
		fail(w, 422, err)
		return
	}
	m, err := audit.ParseManifest(mraw, h.Now())
	if err != nil {
		fail(w, 422, err)
		return
	}
	k, err := h.statusKey(in.Slug)
	if err != nil {
		fail(w, 422, errors.New("claim the name first"))
		return
	}
	switch {
	case m.ComponentID != "onym:component:"+in.Slug:
		err = fmt.Errorf("componentId must be onym:component:%s", in.Slug)
	case m.StatusEndpoint != h.base(in.Slug)+"status.json":
		err = fmt.Errorf("statusEndpoint must be %sstatus.json", h.base(in.Slug))
	case m.StatusKey != site.KeyOf(k):
		err = errors.New("statusKey must be the key the hub issued for this name")
	case !contactRE.MatchString(m.Contact) && urirule.Check(m.Contact) != nil:
		// Pages render the contact as a link: only mailto: or https:.
		err = errors.New("contact must be a mailto: address or an https:// URL")
	}
	if err != nil {
		fail(w, 422, err)
		return
	}
	if prev, perr := os.ReadFile(filepath.Join(h.tenantDir(in.Slug), "manifest.json")); perr == nil {
		var p struct {
			Operator   sig.Key `json:"operator"`
			ValidUntil string  `json:"validUntil"`
		}
		json.Unmarshal(prev, &p)
		if p.Operator != m.Operator {
			fail(w, 403, errors.New("this name belongs to another key"))
			return
		}
		// Manifests are public, so a replayed older one must not roll the
		// auditor back: each re-signing moves validUntil forward.
		if pu, err := sig.ParseTime(p.ValidUntil); err == nil {
			if nu, err := sig.ParseTime(m.ValidUntil); err != nil || nu.Before(pu) {
				fail(w, 409, errors.New("an older manifest than the one registered"))
				return
			}
		}
	}
	offered, err := h.docs(in.Docs)
	if err != nil {
		fail(w, 422, err)
		return
	}
	for p := range offered {
		if strings.HasPrefix(p, "orders/") {
			fail(w, 422, errors.New("orders are published with the attestation they commission"))
			return
		}
	}
	refs := []audit.DocRef{m.AuditProfile, m.IndependencePolicy, m.UnsolicitedPolicy, m.Liability, m.SeverityScale, m.PrivacyProfile}
	classes := map[string]bool{}
	for _, mt := range m.Methodologies {
		refs = append(refs, mt.Specification)
		classes[mt.Class] = true
	}
	// Every listed offer is a document signed by this key, for a methodology
	// the manifest names.
	for _, id := range m.Offers {
		p := "offers/" + id + ".json"
		b, ok := offered[p]
		if !ok {
			var rerr error
			if b, rerr = os.ReadFile(filepath.Join(h.tenantDir(in.Slug), filepath.FromSlash(p))); rerr != nil {
				fail(w, 422, fmt.Errorf("offer %s is neither offered nor stored", id))
				return
			}
		}
		of, err := audit.ParseOffer(b)
		if err == nil && (of.OfferID != id || of.Auditor != m.ComponentID || of.AuditorKey != m.Operator || !classes[of.MethodologyClass]) {
			err = errors.New("it must be signed by this auditor's key, for a methodology the manifest names")
		}
		if err != nil {
			fail(w, 422, fmt.Errorf("offer %s: %v", id, err))
			return
		}
		refs = append(refs, of.Scope)
	}
	for _, ref := range refs {
		if err := h.pinned(in.Slug, ref, offered); err != nil {
			fail(w, 422, err)
			return
		}
	}
	// Only documents this manifest pins or lists are written. Anyone can
	// resend a public manifest, so it must not carry other files into the
	// auditor's tree (an attestation's scope or report, notes, …).
	wanted := map[string]bool{}
	for _, ref := range refs {
		if strings.HasPrefix(ref.URI, h.base(in.Slug)) {
			wanted[strings.TrimPrefix(ref.URI, h.base(in.Slug))] = true
		}
	}
	for _, id := range m.Offers {
		wanted["offers/"+id+".json"] = true
	}
	for p := range offered {
		if !wanted[p] {
			fail(w, 422, fmt.Errorf("%s is not a document this manifest references", p))
			return
		}
	}
	offered["manifest.json"] = mraw
	if err := h.write(in.Slug, offered); err != nil {
		fail(w, 507, err)
		return
	}
	os.Remove(filepath.Join(h.Root, "claims", in.Slug+".json"))
	if err := h.resign(in.Slug); err != nil {
		fail(w, 500, fmt.Errorf("registered, but the status list was not signed: %v", err))
		return
	}
	h.changed()
	reply(w, 201, map[string]string{"page": h.base(in.Slug), "manifest": h.base(in.Slug) + "manifest.json", "digest": sig.Digest(mraw)})
}

// changed tells the operator (the Discovery provider) that an auditor's
// manifest or register changed.
func (h *Hub) changed() {
	if h.OnChange != nil {
		go h.OnChange()
	}
}

func canonical(raw json.RawMessage) ([]byte, error) {
	obj, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canon.Encode(obj)
}

func (h *Hub) tenant(w http.ResponseWriter, slug string) (*audit.AuditorManifest, bool) {
	if !slugRE.MatchString(slug) || h.disabled(slug) {
		fail(w, 404, errors.New("no such auditor"))
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "manifest.json"))
	if err != nil {
		fail(w, 404, errors.New("no such auditor"))
		return nil, false
	}
	m, err := audit.ParseManifest(raw, h.Now())
	if err != nil {
		fail(w, 409, fmt.Errorf("the auditor's manifest no longer verifies: %v", err))
		return nil, false
	}
	return m, true
}

// ---------------------------------------------------------------- publish & revoke

func (h *Hub) publish(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in struct {
		Attestation json.RawMessage   `json:"attestation"`
		Docs        map[string]string `json:"docs"`
	}
	if !h.body(w, r, 5, &in) {
		return
	}
	l := h.lock(slug)
	l.Lock()
	defer l.Unlock()
	m, ok := h.tenant(w, slug)
	if !ok {
		return
	}
	araw, err := canonical(in.Attestation)
	if err != nil {
		fail(w, 422, err)
		return
	}
	a, err := audit.ParseAttestation(araw)
	if err != nil {
		fail(w, 422, err)
		return
	}
	switch {
	case a.AuditorKey != m.Operator || a.Auditor != m.ComponentID:
		err = errors.New("the attestation is not signed by this auditor's key")
	case a.Status != m.StatusEndpoint:
		err = fmt.Errorf("status must be %s", m.StatusEndpoint)
	case a.Unsolicited != nil && a.Unsolicited.Policy != m.UnsolicitedPolicy.Digest:
		err = errors.New("unsolicited.policy must be the digest of this auditor's published unsolicited policy")
	}
	if err != nil {
		fail(w, 422, err)
		return
	}
	apath := "attestations/" + a.AttestationID + ".json"
	if _, err := os.Stat(filepath.Join(h.tenantDir(slug), apath)); err == nil || h.isHeld(slug, a.AttestationID) {
		fail(w, 409, errors.New("an attestation with this id exists; attestations are immutable — supersede it"))
		return
	}
	offered, err := h.docs(in.Docs)
	if err != nil {
		fail(w, 422, err)
		return
	}
	order, opath, err := h.commissioned(m, a, offered)
	if err != nil {
		fail(w, 422, err)
		return
	}
	if order != nil {
		if prev, err := os.ReadFile(filepath.Join(h.tenantDir(slug), filepath.FromSlash(opath))); err == nil && !bytes.Equal(prev, offered[opath]) {
			fail(w, 409, errors.New("a different countersigned order with this id is published"))
			return
		}
	}
	refs := []audit.DocRef{a.Methodology, a.Scope}
	if a.SeverityScale != nil {
		refs = append(refs, *a.SeverityScale)
	}
	if a.FindingsReport != nil {
		refs = append(refs, *a.FindingsReport)
	}
	for _, ref := range refs {
		if err := h.pinned(slug, ref, offered); err != nil {
			fail(w, 422, err)
			return
		}
	}
	offered[apath] = araw
	fulfilled := func() {
		if order != nil {
			os.RemoveAll(filepath.Join(h.inboxDir(slug), order.OrderID))
		}
	}
	// A failing result under an order that embargoes failures is held:
	// the attestation, its report, the countersigned order and its scope
	// are all published when the embargo ends. Publishing the order alone
	// would tell everyone that the result was a fail.
	if order != nil && a.Result == audit.Fail && order.Disclosure.FailPublication == "public-after-embargo" && order.Disclosure.EmbargoDays > 0 {
		releaseAt := h.Now().Add(time.Duration(order.Disclosure.EmbargoDays) * 24 * time.Hour)
		if err := h.hold(slug, a.AttestationID, releaseAt, offered); err != nil {
			fail(w, 500, err)
			return
		}
		fulfilled()
		reply(w, 202, map[string]any{"uri": h.base(slug) + apath, "digest": sig.Digest(araw), "held": true, "releaseAt": sig.FormatTime(releaseAt)})
		return
	}
	if err := h.write(slug, offered); err != nil {
		fail(w, 507, err)
		return
	}
	fulfilled()
	if err := h.resign(slug); err != nil {
		fail(w, 500, fmt.Errorf("published, but the status list was not re-signed: %v", err))
		return
	}
	h.changed()
	reply(w, 201, map[string]string{"uri": h.base(slug) + apath, "digest": sig.Digest(araw)})
}

func (h *Hub) revoke(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in struct {
		Revocation json.RawMessage `json:"revocation"`
	}
	if !h.body(w, r, 5, &in) {
		return
	}
	l := h.lock(slug)
	l.Lock()
	defer l.Unlock()
	m, ok := h.tenant(w, slug)
	if !ok {
		return
	}
	rraw, err := canonical(in.Revocation)
	if err != nil {
		fail(w, 422, err)
		return
	}
	rv, err := audit.ParseRevocation(rraw)
	if err != nil {
		fail(w, 422, err)
		return
	}
	if rv.AuditorKey != m.Operator || rv.Auditor != m.ComponentID {
		fail(w, 422, errors.New("the revocation is not signed by this auditor's key"))
		return
	}
	if _, err := os.Stat(filepath.Join(h.tenantDir(slug), "attestations", rv.AttestationID+".json")); err != nil {
		fail(w, 404, errors.New("no such attestation"))
		return
	}
	rpath := "revocations/" + rv.AttestationID + ".json"
	if _, err := os.Stat(filepath.Join(h.tenantDir(slug), rpath)); err == nil {
		fail(w, 409, errors.New("already revoked"))
		return
	}
	if err := h.write(slug, map[string][]byte{rpath: rraw}); err != nil {
		fail(w, 507, err)
		return
	}
	if err := h.resign(slug); err != nil {
		fail(w, 500, err)
		return
	}
	h.changed()
	reply(w, 201, map[string]string{"uri": h.base(slug) + rpath})
}

// response takes a subject's signed reply to one of a hosted auditor's
// attestations (Audit.md §5.7.5).
func (h *Hub) response(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in json.RawMessage
	if !h.body(w, r, 5, &in) {
		return
	}
	l := h.lock(slug)
	l.Lock()
	defer l.Unlock()
	if _, ok := h.tenant(w, slug); !ok {
		return
	}
	raw, err := canonical(in)
	if err != nil {
		fail(w, 422, err)
		return
	}
	var head struct {
		AttestationID string `json:"attestationId"`
		ResponseID    string `json:"responseId"`
	}
	json.Unmarshal(raw, &head)
	attRaw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "attestations", filepath.Base(head.AttestationID)+".json"))
	if err != nil {
		fail(w, 404, errors.New("no such attestation"))
		return
	}
	att, err := audit.ParseAttestation(attRaw)
	if err != nil {
		fail(w, 500, err)
		return
	}
	if _, err := audit.ParseResponse(raw, att, sig.Digest(attRaw)); err != nil {
		fail(w, 422, err)
		return
	}
	p := "responses/" + att.AttestationID + "/" + head.ResponseID + ".json"
	if _, err := os.Stat(filepath.Join(h.tenantDir(slug), p)); err == nil {
		fail(w, 409, errors.New("responses are immutable; use a new responseId"))
		return
	}
	if err := h.write(slug, map[string][]byte{p: raw}); err != nil {
		fail(w, 507, err)
		return
	}
	if err := h.resign(slug); err != nil {
		log.Printf("hub %s: re-sign after response: %v", slug, err)
	}
	reply(w, 201, map[string]string{"uri": h.base(slug) + p})
}

// ---------------------------------------------------------------- examination helpers

func (h *Hub) get(ctx context.Context, uri string, limit int64) (*http.Response, []byte, error) {
	if err := urirule.Check(uri); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "onym-audit-hub/1.0")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > limit {
		return resp, nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return resp, b, nil
}

// fetch lets the studio read a public Onym document the browser cannot
// fetch itself (most hosts send no CORS headers). Public HTTPS only, no
// cookies, ≤ 1 MiB, never inside the hub's own network.
func (h *Hub) fetch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
	}
	if !h.body(w, r, 2, &in) {
		return
	}
	resp, b, err := h.get(r.Context(), in.URL, MaxFetchBytes)
	if err != nil {
		fail(w, 502, err)
		return
	}
	// Documents only: this is not a general proxy.
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !(strings.HasPrefix(ct, "application/json") || strings.HasPrefix(ct, "text/") || ct == "") || !utf8.Valid(b) {
		fail(w, 415, fmt.Errorf("only JSON and text documents can be fetched (got %q)", ct))
		return
	}
	reply(w, 200, map[string]any{"url": resp.Request.URL.String(), "status": resp.StatusCode, "contentType": resp.Header.Get("Content-Type"), "setsCookie": resp.Header.Get("Set-Cookie") != "", "digest": sig.Digest(b), "size": len(b), "body": string(b)})
}

// digest hashes a large public file (a release build) without returning it.
func (h *Hub) digest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
	}
	if !h.body(w, r, 20, &in) {
		return
	}
	if !h.acquire(w) {
		return
	}
	defer func() { <-h.heavy }()
	// Hashed as it streams: a file up to MaxHashBytes is never held in memory.
	if err := urirule.Check(in.URL); err != nil {
		fail(w, 502, err)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, in.URL, nil)
	if err != nil {
		fail(w, 502, err)
		return
	}
	req.Header.Set("User-Agent", "onym-audit-hub/1.0")
	resp, err := h.client.Do(req)
	if err != nil {
		fail(w, 502, err)
		return
	}
	defer resp.Body.Close()
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(resp.Body, MaxHashBytes+1))
	switch {
	case err != nil:
		fail(w, 502, err)
		return
	case n > MaxHashBytes:
		fail(w, 502, fmt.Errorf("larger than %d bytes", MaxHashBytes))
		return
	}
	reply(w, 200, map[string]any{"url": resp.Request.URL.String(), "status": resp.StatusCode, "digest": "sha256:" + hex.EncodeToString(sum.Sum(nil)), "size": n})
}

// conformance runs the Discovery provider suite for the studio.
func (h *Hub) conformance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ManifestURL string `json:"manifestUrl"`
	}
	if !h.body(w, r, 20, &in) {
		return
	}
	if err := urirule.Check(in.ManifestURL); err != nil {
		fail(w, 422, err)
		return
	}
	if !h.acquire(w) {
		return
	}
	defer func() { <-h.heavy }()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	// The suite judges Discovery providers only: run on any other component
	// its every check would "fail", and an attestation built on that would be
	// a false adverse verdict about a component the suite does not cover.
	if _, b, err := h.get(ctx, in.ManifestURL, MaxFetchBytes); err != nil {
		fail(w, 502, err)
		return
	} else if err := discoveryProvider(b); err != nil {
		fail(w, 422, err)
		return
	}
	rep := discovery.Run(ctx, discovery.NewHTTPFetcher(), in.ManifestURL, h.Now())
	b, err := rep.Canonical()
	if err != nil {
		fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// discoveryProvider accepts a document the Discovery suite applies to: a
// JSON object that says it is a Discovery provider's manifest.
func discoveryProvider(b []byte) error {
	var m struct {
		Seat any `json:"seat"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return errors.New("this address does not serve a JSON manifest; the Discovery suite needs a provider manifest")
	}
	if m.Seat != "discovery" {
		return fmt.Errorf("this is not a Discovery provider (seat %v); the Discovery suite does not apply to it — examine it as a running service instead", m.Seat)
	}
	return nil
}

func (h *Hub) acquire(w http.ResponseWriter) bool {
	select {
	case h.heavy <- struct{}{}:
		return true
	default:
		fail(w, http.StatusServiceUnavailable, errors.New("the hub is busy with other examinations; try again in a minute"))
		return false
	}
}

// ---------------------------------------------------------------- listing, export, static

func (h *Hub) auditors(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(filepath.Join(h.Root, "tenants"))
	out := []map[string]any{}
	for _, e := range entries {
		slug := e.Name()
		if h.disabled(slug) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(h.tenantDir(slug), "manifest.json"))
		if err != nil {
			continue
		}
		m, err := audit.ParseManifest(raw, h.Now())
		if err != nil {
			continue
		}
		atts, _ := filepath.Glob(filepath.Join(h.tenantDir(slug), "attestations", "*.json"))
		orders, customers := orderStats(h.tenantDir(slug))
		out = append(out, map[string]any{"slug": slug, "name": m.DisplayName, "operator": m.Operator, "fingerprint": m.Operator.Fingerprint(), "page": h.base(slug), "attestations": len(atts), "offers": len(m.Offers), "completedOrders": orders, "customers": customers})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["slug"].(string) < out[j]["slug"].(string) })
	reply(w, 200, out)
}

// export lists every file of an auditor's tree, for self-hosting.
func (h *Hub) export(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if _, ok := h.tenant(w, slug); !ok {
		return
	}
	var files []string
	root := h.tenantDir(slug)
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.HasPrefix(d.Name(), ".") {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(files)
	reply(w, 200, map[string]any{"base": h.base(slug), "files": files})
}

func (h *Hub) static(w http.ResponseWriter, r *http.Request) {
	slug, p := r.PathValue("slug"), r.PathValue("path")
	if !slugRE.MatchString(slug) || h.disabled(slug) {
		http.NotFound(w, r)
		return
	}
	if p == "" || p == "index.html" {
		// Every hosted auditor gets the same public page, reading its own tree.
		if _, err := os.Stat(filepath.Join(h.tenantDir(slug), "manifest.json")); err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(h.PublicRoot, "hub", "auditor.html"))
		return
	}
	clean := filepath.Clean("/" + p)
	if strings.Contains(clean, "/.") {
		http.NotFound(w, r)
		return
	}
	full := filepath.Join(h.tenantDir(slug), filepath.FromSlash(clean))
	if fi, err := os.Stat(full); err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch filepath.Ext(p) {
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".md", ".sig":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	if strings.HasSuffix(p, "status.json") {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, full)
}

// Trees lists the hosted auditors that are not disabled: the base their
// documents are named under and the directory they are served from.
func (h *Hub) Trees() (bases, dirs []string) {
	entries, _ := os.ReadDir(filepath.Join(h.Root, "tenants"))
	for _, e := range entries {
		slug := e.Name()
		if !slugRE.MatchString(slug) || h.disabled(slug) {
			continue
		}
		bases, dirs = append(bases, h.base(slug)), append(dirs, h.tenantDir(slug))
	}
	return bases, dirs
}

// ResignAll releases held attestations whose embargo has ended and
// refreshes every hosted auditor's status list.
func (h *Hub) ResignAll() {
	entries, _ := os.ReadDir(filepath.Join(h.Root, "tenants"))
	for _, e := range entries {
		slug := e.Name()
		if h.disabled(slug) {
			continue
		}
		if _, err := os.Stat(filepath.Join(h.tenantDir(slug), "manifest.json")); err != nil {
			continue
		}
		l := h.lock(slug)
		l.Lock()
		h.release(slug)
		if err := h.resign(slug); err != nil {
			log.Printf("hub %s: status re-sign failed: %v", slug, err)
		}
		l.Unlock()
	}
}

// Disable takes an auditor off the hub (terms of use); the tree is kept.
func (h *Hub) Disable(slug, reason string) error {
	if !slugRE.MatchString(slug) {
		return errors.New("no such auditor")
	}
	return os.WriteFile(filepath.Join(h.tenantDir(slug), ".disabled"), []byte(reason+"\n"), 0o600)
}

// limiter is a per-address token bucket.
type limiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	rate, burst float64 // tokens per second; bucket size
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*bucket{}, rate: 1, burst: 60} }

func (l *limiter) allow(key string, cost int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 10000 {
			// Drop buckets that have refilled: forgetting them changes nothing.
			for k, x := range l.buckets {
				if x.tokens+now.Sub(x.last).Seconds()*l.rate >= l.burst {
					delete(l.buckets, k)
				}
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < float64(cost) {
		return false
	}
	b.tokens -= float64(cost)
	return true
}
