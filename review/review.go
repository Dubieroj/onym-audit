// Package review keeps one examination of a repository at an exact commit —
// manual (security-review-manual-v1) or LLM-assisted (security-review-llm-v1)
// — from checkout to signed attestation. It is the model behind the local
// auditor console; the auditor key never leaves the machine it runs on.
package review

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"

	"onym-audit/agent"
	"onym-audit/audit"
	"onym-audit/sig"
	"onym-audit/urirule"
)

// Kinds and their methodologies.
const (
	KindManual = "manual"
	KindLLM    = "llm"
)

var methodology = map[string]string{
	KindManual: "security-review-manual-v1",
	KindLLM:    agent.Version,
}

var methodologyDoc = map[string]string{
	KindManual: "methodology/security-review-manual.md",
	KindLLM:    "methodology/security-review-llm.md",
}

// Finding statuses. Every engine finding starts pending: nothing is signed
// until the auditor has kept or dropped each one.
const (
	Pending = "pending"
	Kept    = "kept"
	Dropped = "dropped"
)

// Finding is an engine or auditor finding and the auditor's decision on it.
type Finding struct {
	agent.Finding
	Source     string `json:"source"` // "engine" or "auditor"
	Status     string `json:"status"`
	DropReason string `json:"dropReason,omitempty"`
}

// AgentRun records one engine run.
type AgentRun struct {
	State            string `json:"state"` // running | done | error
	Error            string `json:"error,omitempty"`
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	Effort           string `json:"effort"`
	PromptDigest     string `json:"promptDigest"`
	Iterations       int    `json:"iterations"`
	StopReason       string `json:"stopReason"`
	TranscriptDigest string `json:"transcriptDigest,omitempty"`
	Started          string `json:"started"`
	Finished         string `json:"finished,omitempty"`
}

// Signed records the published attestation, and any files held back under
// embargo until Until.
type Signed struct {
	AttestationID string            `json:"attestationId"`
	Attestation   audit.DocRef      `json:"attestation"`
	Result        string            `json:"result"`
	HeldUntil     string            `json:"heldUntil,omitempty"`
	Held          map[string]string `json:"held,omitempty"` // published path -> file in the review dir
}

// Review is persisted as review.json in its own directory.
type Review struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Repo      string          `json:"repo"`
	Commit    string          `json:"commit"`
	Scope     string          `json:"scope"`
	CreatedAt string          `json:"createdAt"`
	OrderID   string          `json:"orderId,omitempty"`
	Agent     *AgentRun       `json:"agent,omitempty"`
	Coverage  agent.Coverage  `json:"coverage"`
	Findings  []Finding       `json:"findings"`
	Rejected  []agent.Finding `json:"rejected"`
	Signed    *Signed         `json:"signed,omitempty"`

	dir string
	mu  *sync.Mutex
}

var locks sync.Map // review dir -> *sync.Mutex

func lockFor(dir string) *sync.Mutex {
	m, _ := locks.LoadOrStore(dir, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// Dir is the review's directory; Workspace its checkout.
func (r *Review) Dir() string       { return r.dir }
func (r *Review) Workspace() string { return filepath.Join(r.dir, "workspace") }

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	idRE     = regexp.MustCompile(`^rv-[0-9]{8}-[0-9a-f]{8}$`)
)

// Create checks the repository out at commit and starts a review.
func Create(root, kind, repo, commit, scope, orderID string) (*Review, error) {
	if kind != KindManual && kind != KindLLM {
		return nil, fmt.Errorf("kind must be %s or %s", KindManual, KindLLM)
	}
	repo = strings.TrimSuffix(strings.TrimRight(repo, "/"), ".git")
	if err := urirule.Check(repo); err != nil {
		return nil, err
	}
	if !commitRE.MatchString(commit) {
		return nil, errors.New("commit must be the full 40-character id")
	}
	if strings.TrimSpace(scope) == "" {
		return nil, errors.New("state the scope")
	}
	b := make([]byte, 4)
	rand.Read(b)
	now := time.Now().UTC()
	r := &Review{
		ID: "rv-" + now.Format("20060102") + "-" + hex.EncodeToString(b), Kind: kind,
		Repo: repo, Commit: commit, Scope: strings.TrimSpace(scope) + "\n", CreatedAt: sig.FormatTime(now), OrderID: orderID,
		Findings: []Finding{}, Rejected: []agent.Finding{},
		Coverage: agent.Coverage{Examined: []string{}, NotExamined: []string{}},
		dir:      filepath.Join(root, "rv-"+now.Format("20060102")+"-"+hex.EncodeToString(b)),
	}
	r.mu = lockFor(r.dir)
	if err := checkout(repo, commit, r.Workspace()); err != nil {
		os.RemoveAll(r.dir)
		return nil, err
	}
	return r, r.save()
}

func checkout(repo, commit, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	// core.symlinks=false: a symlink in the repository is checked out as a
	// plain file holding its target, never as a link out of the workspace.
	for _, a := range [][]string{{"init", "-q"}, {"config", "core.symlinks", "false"}, {"remote", "add", "origin", repo}, {"fetch", "-q", "--depth", "1", "origin", commit}, {"checkout", "-q", "--detach", "FETCH_HEAD"}} {
		if _, err := run(a...); err != nil {
			return err
		}
	}
	head, err := run("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if head != commit {
		return fmt.Errorf("checked out %s, not %s", head, commit)
	}
	return nil
}

// Load reads one review.
func Load(root, id string) (*Review, error) {
	if !idRE.MatchString(id) {
		return nil, errors.New("no such review")
	}
	dir := filepath.Join(root, id)
	b, err := os.ReadFile(filepath.Join(dir, "review.json"))
	if err != nil {
		return nil, errors.New("no such review")
	}
	var r Review
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	r.dir, r.mu = dir, lockFor(dir)
	return &r, nil
}

// List returns every review, newest first.
func List(root string) ([]*Review, error) {
	entries, _ := os.ReadDir(root)
	var out []*Review
	for _, e := range entries {
		if r, err := Load(root, e.Name()); err == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

func (r *Review) save() error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(r.dir, ".review.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.dir, "review.json"))
}

// Update applies f under the review's lock and saves; a signed review is
// frozen.
func (r *Review) Update(f func(*Review) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	fresh, err := Load(filepath.Dir(r.dir), r.ID)
	if err != nil {
		return err
	}
	if fresh.Signed != nil {
		return errors.New("this review is signed; start a new one to supersede it")
	}
	if err := f(fresh); err != nil {
		return err
	}
	*r = *fresh
	return r.save()
}

func renumber(fs []Finding) {
	rank := map[string]int{}
	for i, s := range agent.Severities {
		rank[s] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.LineStart < b.LineStart
	})
	for i := range fs {
		fs[i].ID = fmt.Sprintf("F%d", i+1)
	}
}

// AddManual records an auditor finding in a manual review, under the same
// evidence rule as the engine's.
func (r *Review) AddManual(f agent.Finding) error {
	return r.Update(func(x *Review) error {
		if x.Kind != KindManual {
			return errors.New("findings are added by hand only in a manual review; an LLM review's findings come from the engine")
		}
		if !contains([]string{"high", "medium", "low"}, f.Confidence) || strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Description) == "" {
			return errors.New("give a title, a description, and a confidence")
		}
		agent.VerifyEvidence(x.Workspace(), &f)
		if !f.Verified {
			return errors.New("evidence rejected: " + f.Rejection)
		}
		x.Findings = append(x.Findings, Finding{Finding: f, Source: "auditor", Status: Kept})
		renumber(x.Findings)
		return nil
	})
}

// Decide keeps or drops a finding; dropping needs a reason, which is
// published. An auditor's own finding may also be deleted before signing.
func (r *Review) Decide(id, action, reason string) error {
	return r.Update(func(x *Review) error {
		for i := range x.Findings {
			f := &x.Findings[i]
			if f.ID != id {
				continue
			}
			switch action {
			case "keep":
				f.Status, f.DropReason = Kept, ""
			case "drop":
				if strings.TrimSpace(reason) == "" {
					return errors.New("a dropped finding needs a reason; it is published")
				}
				f.Status, f.DropReason = Dropped, strings.TrimSpace(reason)
			case "delete":
				if f.Source != "auditor" {
					return errors.New("engine findings cannot be deleted, only dropped with a reason")
				}
				x.Findings = append(x.Findings[:i], x.Findings[i+1:]...)
				renumber(x.Findings)
			default:
				return fmt.Errorf("unknown action %q", action)
			}
			return nil
		}
		return fmt.Errorf("no finding %s", id)
	})
}

// SetCoverage records the manual examiner's coverage statement.
func (r *Review) SetCoverage(c agent.Coverage) error {
	return r.Update(func(x *Review) error {
		if x.Kind != KindManual {
			return errors.New("an LLM review's coverage is the engine's own statement")
		}
		if strings.TrimSpace(c.Summary) == "" {
			return errors.New("summarize the examination")
		}
		if c.Examined == nil {
			c.Examined = []string{}
		}
		if c.NotExamined == nil {
			c.NotExamined = []string{}
		}
		c.Declared = true
		x.Coverage = c
		return nil
	})
}

// StartAgent runs the engine in the background; progress is in r.Agent.
func (r *Review) StartAgent(client anthropic.Client, provider, model, effort string) error {
	err := r.Update(func(x *Review) error {
		if x.Kind != KindLLM {
			return errors.New("the engine runs only in an LLM review")
		}
		if x.Agent != nil && x.Agent.State == "running" {
			return errors.New("the engine is already running")
		}
		if x.Agent != nil && x.Agent.State == "done" {
			return errors.New("the engine has run; start a new review to run it again")
		}
		x.Agent = &AgentRun{State: "running", Provider: provider, Model: model, Effort: effort, PromptDigest: agent.PromptDigest(), Started: sig.FormatTime(time.Now())}
		return nil
	})
	if err != nil {
		return err
	}
	go func() {
		res, err := agent.Review(context.Background(), client, agent.Config{
			Provider: provider, Model: model, Effort: effort,
			RepoDir: r.Workspace(), Source: r.Repo, Revision: r.Commit, Scope: r.Scope,
		})
		r.mu.Lock()
		defer r.mu.Unlock()
		x, lerr := Load(filepath.Dir(r.dir), r.ID)
		if lerr != nil {
			return
		}
		x.Agent.Finished = sig.FormatTime(time.Now())
		if err != nil {
			x.Agent.State, x.Agent.Error = "error", err.Error()
			x.save()
			return
		}
		if werr := os.WriteFile(filepath.Join(x.dir, "transcript.json"), res.Transcript, 0o600); werr != nil {
			x.Agent.State, x.Agent.Error = "error", werr.Error()
			x.save()
			return
		}
		x.Agent.State, x.Agent.Iterations, x.Agent.StopReason = "done", res.Iterations, res.StopReason
		x.Agent.TranscriptDigest = sig.Digest(res.Transcript)
		x.Coverage, x.Rejected = res.Coverage, res.Rejected
		for _, f := range res.Findings {
			x.Findings = append(x.Findings, Finding{Finding: f, Source: "engine", Status: Pending})
		}
		renumber(x.Findings)
		x.save()
	}()
	return nil
}

// ResultClass follows the review's methodology over the kept findings.
func (r *Review) ResultClass() string {
	var kept []agent.Finding
	for _, f := range r.Findings {
		if f.Status == Kept {
			kept = append(kept, f.Finding)
		}
	}
	stop := "end_turn"
	if r.Agent != nil {
		stop = r.Agent.StopReason
	}
	return (&agent.Result{Findings: kept, Coverage: r.Coverage, StopReason: stop}).ResultClass()
}

// Blockers lists what must happen before the review can be signed.
func (r *Review) Blockers() []string {
	out := []string{}
	if r.Signed != nil {
		return []string{"already signed"}
	}
	if r.Kind == KindLLM && (r.Agent == nil || r.Agent.State != "done") {
		out = append(out, "run the engine to completion")
	}
	if !r.Coverage.Declared {
		out = append(out, "state the coverage")
	}
	for _, f := range r.Findings {
		if f.Status == Pending {
			out = append(out, "decide every engine finding (keep, or drop with a reason)")
			break
		}
	}
	return out
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
