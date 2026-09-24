// Package console is the auditor's local web console: order queue, manual
// and LLM-assisted reviews, signing, and publishing. It holds the auditor
// key, so it listens on loopback only, refuses foreign Host headers (DNS
// rebinding), and requires a per-start token on every state-changing call
// (so no web page the auditor visits can drive it).
package console

import (
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"onym-audit/agent"
	"onym-audit/audit"
	"onym-audit/review"
	"onym-audit/sig"
	"onym-audit/site"
)

//go:embed ui
var uiFS embed.FS

// Console is one running console.
type Console struct {
	PublicRoot string
	Config     *site.Config
	AuditorKey ed25519.PrivateKey
	StatusKey  ed25519.PrivateKey
	Reviews    string // review directories
	Inbox      string // orders pulled from the server
	RepoRoot   string // where deploy/deploy.sh lives
	DeployHost string
	Provider   string

	token string
	addr  string
	mu    sync.Mutex
	jobs  map[string]*job
}

type job struct {
	State  string `json:"state"` // running | done | error
	Output string `json:"output"`
}

// Handler returns the console's HTTP handler for addr (host:port).
func (c *Console) Handler(addr string) http.Handler {
	b := make([]byte, 24)
	rand.Read(b)
	c.token, c.addr, c.jobs = hex.EncodeToString(b), addr, map[string]*job{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", c.index)
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /api/state", c.state)
	mux.HandleFunc("POST /api/orders/pull", c.pullOrders)
	mux.HandleFunc("POST /api/reviews", c.createReview)
	mux.HandleFunc("GET /api/reviews/{id}", c.getReview)
	mux.HandleFunc("GET /api/reviews/{id}/tree", c.tree)
	mux.HandleFunc("GET /api/reviews/{id}/file", c.file)
	mux.HandleFunc("POST /api/reviews/{id}/findings", c.addFinding)
	mux.HandleFunc("POST /api/reviews/{id}/findings/{fid}", c.decide)
	mux.HandleFunc("POST /api/reviews/{id}/coverage", c.coverage)
	mux.HandleFunc("POST /api/reviews/{id}/agent", c.runAgent)
	mux.HandleFunc("POST /api/reviews/{id}/sign", c.sign)
	mux.HandleFunc("POST /api/reviews/{id}/release", c.release)
	mux.HandleFunc("POST /api/publish", c.publish)
	mux.HandleFunc("GET /api/jobs/{id}", c.getJob)
	return c.guard(mux)
}

func (c *Console) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		_, port, _ := net.SplitHostPort(c.addr)
		if host != "127.0.0.1:"+port && host != "localhost:"+port {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Console-Token") != c.token {
			http.Error(w, "missing console token", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (c *Console) index(w http.ResponseWriter, r *http.Request) {
	b, _ := uiFS.ReadFile("ui/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strings.Replace(string(b), "{{TOKEN}}", c.token, 1)))
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---------------------------------------------------------------- state

type orderView struct {
	ID         string `json:"id"`
	Repo       string `json:"repo"`
	Commit     string `json:"commit"`
	Subject    string `json:"subject"`
	SubjectKey string `json:"subjectKey"`
	Scope      string `json:"scope"`
	Contact    string `json:"contact"`
	Terms      string `json:"terms"` // everything the auditor's countersignature covers
	ReceivedAt string `json:"receivedAt"`
	Valid      bool   `json:"valid"`
	Problem    string `json:"problem,omitempty"`
	ReviewID   string `json:"reviewId,omitempty"`
}

func (c *Console) orders(reviews []*review.Review) []orderView {
	byOrder := map[string]string{}
	for _, r := range reviews {
		if r.OrderID != "" {
			byOrder[r.OrderID] = r.ID
		}
	}
	entries, _ := os.ReadDir(c.Inbox)
	out := []orderView{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(c.Inbox, e.Name())
		v := orderView{ID: e.Name(), ReviewID: byOrder[e.Name()]}
		ob, err := os.ReadFile(filepath.Join(dir, "order.json"))
		if err != nil {
			continue
		}
		o, err := audit.ParseOrderRequest(ob, c.Config.ComponentID)
		if err != nil {
			v.Problem = err.Error()
		} else {
			v.Valid = true
			v.Repo, v.Commit, v.Subject = o.Artifact.Source, o.Artifact.Revision, o.Subject
			d := o.Disclosure
			v.Terms = fmt.Sprintf("Methodology: %s\nCooperation: %s\nDisclosure: findings to the subject first: %v; embargo %d days; attestation %s; a fail %s\nFee: %s (offer %s)\nTimeline: %v\nSponsor: %s",
				o.MethodologyCls, o.Cooperation, d.FindingsToSubjectFirst, d.EmbargoDays, d.AttestationPublication, d.FailPublication, o.Fee.Model, o.Fee.OfferID, o.Timeline, o.Sponsor)
			for _, s := range o.Signatures {
				if s.Role == "subject" {
					v.SubjectKey = string(s.Key)
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "scope.md")); err == nil {
			v.Scope = string(b)
		}
		var meta struct{ Contact, ReceivedAt string }
		if b, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
			json.Unmarshal(b, &meta)
		}
		v.Contact, v.ReceivedAt = meta.Contact, meta.ReceivedAt
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt > out[j].ReceivedAt })
	return out
}

type reviewView struct {
	*review.Review
	ResultClass string   `json:"resultClass"`
	Blockers    []string `json:"blockers"`
}

func (c *Console) state(w http.ResponseWriter, r *http.Request) {
	reviews, _ := review.List(c.Reviews)
	views := []reviewView{}
	for _, rv := range reviews {
		views = append(views, reviewView{rv, rv.ResultClass(), rv.Blockers()})
	}
	key := site.KeyOf(c.AuditorKey)
	_, keyErr := agent.NewClient(c.Provider)
	reply(w, map[string]any{
		"auditor":    map[string]string{"name": c.Config.DisplayName, "component": c.Config.ComponentID, "key": string(key), "fingerprint": key.Fingerprint(), "base": c.Config.BaseURI},
		"reviews":    views,
		"orders":     c.orders(reviews),
		"engine":     map[string]any{"provider": c.Provider, "ready": keyErr == nil, "problem": errString(keyErr)},
		"deployHost": c.DeployHost,
		"severities": agent.Severities,
		"now":        sig.FormatTime(time.Now()),
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// pullOrders copies the server's queued orders here over SSH.
func (c *Console) pullOrders(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(c.Inbox, 0o700); err != nil {
		fail(w, 500, err)
		return
	}
	// Regular files only (no -l: symlinks are skipped), and only the three
	// an order consists of: the server holding the inbox is not trusted
	// with this machine's files.
	cmd := exec.Command("rsync", "-rt", "--include=*/", "--include=order.json", "--include=scope.md", "--include=meta.json", "--exclude=*",
		"-e", "ssh -o BatchMode=yes -o ConnectTimeout=15", c.DeployHost+":/var/lib/onym-audit/inbox/", c.Inbox+"/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fail(w, 502, fmt.Errorf("rsync: %v: %s", err, strings.TrimSpace(string(out))))
		return
	}
	c.state(w, r)
}

// ---------------------------------------------------------------- reviews

func (c *Console) load(w http.ResponseWriter, r *http.Request) *review.Review {
	rv, err := review.Load(c.Reviews, r.PathValue("id"))
	if err != nil {
		fail(w, 404, err)
		return nil
	}
	return rv
}

func (c *Console) createReview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind, Repo, Commit, Scope, OrderID string
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if in.OrderID != "" {
		ov := c.findOrder(in.OrderID)
		if ov == nil || !ov.Valid {
			fail(w, 400, errors.New("no valid queued order with that id"))
			return
		}
		in.Repo, in.Commit, in.Scope = ov.Repo, ov.Commit, ov.Scope
	}
	rv, err := review.Create(c.Reviews, in.Kind, in.Repo, in.Commit, in.Scope, in.OrderID)
	if err != nil {
		fail(w, 400, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

func (c *Console) findOrder(id string) *orderView {
	reviews, _ := review.List(c.Reviews)
	for _, o := range c.orders(reviews) {
		if o.ID == id {
			return &o
		}
	}
	return nil
}

func (c *Console) getReview(w http.ResponseWriter, r *http.Request) {
	if rv := c.load(w, r); rv != nil {
		reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
	}
}

func (c *Console) tree(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	root := rv.Workspace()
	files := []string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() && len(files) < 5000 {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(files)
	reply(w, files)
}

func (c *Console) file(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	lines, err := agent.ReadLines(rv.Workspace(), r.URL.Query().Get("path"))
	if err != nil {
		fail(w, 404, err)
		return
	}
	reply(w, lines)
}

func (c *Console) addFinding(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	var f agent.Finding
	if err := decode(r, &f); err != nil {
		fail(w, 400, err)
		return
	}
	if err := rv.AddManual(f); err != nil {
		fail(w, 422, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

func (c *Console) decide(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	var in struct{ Action, Reason string }
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := rv.Decide(r.PathValue("fid"), in.Action, in.Reason); err != nil {
		fail(w, 422, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

func (c *Console) coverage(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	var cov agent.Coverage
	if err := decode(r, &cov); err != nil {
		fail(w, 400, err)
		return
	}
	if err := rv.SetCoverage(cov); err != nil {
		fail(w, 422, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

func (c *Console) runAgent(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	var in struct{ Model, Effort string }
	decode(r, &in)
	client, err := agent.NewClient(c.Provider)
	if err != nil {
		fail(w, 412, fmt.Errorf("%w — then restart the console", err))
		return
	}
	model := in.Model
	if model == "" {
		model = agent.DefaultModel
		if c.Provider == agent.ProviderOpenRouter {
			model = agent.DefaultOpenRouterModel
		}
	}
	effort := in.Effort
	if effort == "" {
		effort = agent.DefaultEffort
	}
	if err := rv.StartAgent(client, c.Provider, model, effort); err != nil {
		fail(w, 409, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

var attIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func (c *Console) sign(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	var in struct {
		AttestationID, Relationships                  string
		Subject, SubjectOperator, Contact, NotifiedAt string
		FindingsSentAt, HoldReportUntil               string
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if !attIDRE.MatchString(in.AttestationID) {
		fail(w, 422, errors.New("attestation id: 16–128 of A-Za-z0-9_-"))
		return
	}
	if strings.TrimSpace(in.Relationships) == "" {
		fail(w, 422, errors.New(`state the relationships with the subject ("none" when none)`))
		return
	}
	opts := review.SignOptions{
		PublicRoot: c.PublicRoot, Config: c.Config, AuditorKey: c.AuditorKey, StatusKey: c.StatusKey,
		AttestationID: in.AttestationID, Relationships: in.Relationships,
		Subject: in.Subject, SubjectOperator: sig.Key(in.SubjectOperator), Contact: in.Contact, NotifiedAt: in.NotifiedAt,
		FindingsSentAt: in.FindingsSentAt, HoldReportUntil: in.HoldReportUntil,
	}
	if rv.OrderID != "" {
		opts.OrderDir = filepath.Join(c.Inbox, rv.OrderID)
	}
	if _, err := rv.Sign(opts); err != nil {
		fail(w, 422, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

func (c *Console) release(w http.ResponseWriter, r *http.Request) {
	rv := c.load(w, r)
	if rv == nil {
		return
	}
	if err := rv.Release(c.PublicRoot, c.Config, c.StatusKey, time.Now()); err != nil {
		fail(w, 422, err)
		return
	}
	reply(w, reviewView{rv, rv.ResultClass(), rv.Blockers()})
}

// publish runs deploy/deploy.sh: tests, the page check, then the push.
func (c *Console) publish(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 6)
	rand.Read(b)
	id := hex.EncodeToString(b)
	j := &job{State: "running"}
	c.mu.Lock()
	c.jobs[id] = j
	c.mu.Unlock()
	go func() {
		cmd := exec.Command(filepath.Join(c.RepoRoot, "deploy", "deploy.sh"))
		cmd.Dir = c.RepoRoot
		cmd.Env = append(os.Environ(), "DEPLOY_HOST="+c.DeployHost)
		out, err := cmd.CombinedOutput()
		c.mu.Lock()
		defer c.mu.Unlock()
		j.Output = string(out)
		if len(j.Output) > 20000 {
			j.Output = "…" + j.Output[len(j.Output)-20000:]
		}
		j.State = "done"
		if err != nil {
			j.State, j.Output = "error", j.Output+"\n"+err.Error()
		}
	}()
	reply(w, map[string]string{"job": id})
}

func (c *Console) getJob(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, ok := c.jobs[r.PathValue("id")]
	if !ok {
		fail(w, 404, errors.New("no such job"))
		return
	}
	reply(w, j)
}
