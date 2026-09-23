// Package agent is an LLM-assisted examination engine for the audit seat's
// security-review methodology (public/methodology/security-review-llm.md).
//
// It drafts; it never decides. The agent reads a repository checked out at
// an exact commit through three read-only tools, reports findings through a
// fourth, and declares its coverage through a fifth. Every finding must quote
// the exact lines it rests on, and the quote is checked mechanically against
// the pinned bytes before it is recorded — so neither a hallucination nor
// text planted in the examined code can become a finding on the model's word
// alone. The human auditor reviews the draft and signs, or does not.
package agent

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/toolrunner"

	"onym-audit/sig"
)

// SystemPrompt is published verbatim as part of the methodology; its digest
// goes into every findings report.
//
//go:embed prompt.md
var SystemPrompt string

// Defaults: Claude Opus 5 with adaptive thinking; xhigh effort suits long
// agentic code review. The engine reaches Claude either directly or through
// OpenRouter's Anthropic-compatible endpoint (the "Anthropic Skin"), which
// takes the same Messages API requests under its own model slugs.
const (
	ProviderAnthropic      = "anthropic"
	ProviderOpenRouter     = "openrouter"
	DefaultModel           = "claude-opus-5"
	DefaultOpenRouterModel = "anthropic/claude-opus-5"
	OpenRouterBaseURL      = "https://openrouter.ai/api/"
	DefaultEffort          = "xhigh"
	DefaultMaxIterations   = 80
	Version                = "security-review-llm-v1"
)

// NewClient returns a Messages API client for the provider, reading the key
// from the environment: ANTHROPIC_API_KEY, or OPENROUTER_API_KEY sent as a
// bearer token to OpenRouter.
func NewClient(provider string) (anthropic.Client, error) {
	switch provider {
	case ProviderAnthropic:
		if os.Getenv("ANTHROPIC_API_KEY") == "" && os.Getenv("ANTHROPIC_AUTH_TOKEN") == "" {
			return anthropic.Client{}, errors.New("export ANTHROPIC_API_KEY in your own terminal")
		}
		return anthropic.NewClient(), nil
	case ProviderOpenRouter:
		key := os.Getenv("OPENROUTER_API_KEY")
		if key == "" {
			return anthropic.Client{}, errors.New("export OPENROUTER_API_KEY in your own terminal")
		}
		return anthropic.NewClient(
			option.WithBaseURL(OpenRouterBaseURL),
			option.WithAuthToken(key),
			option.WithHeader("X-Title", "onym-audit"),
		), nil
	}
	return anthropic.Client{}, fmt.Errorf("unknown provider %q", provider)
}

// Bounds on what a single tool call returns.
const (
	maxReadLines     = 400
	maxReadBytes     = 64 << 10
	maxListEntries   = 600
	maxSearchResults = 120
	maxQuoteLines    = 60
	minQuoteChars    = 8
)

// Severity levels of severity-v1, highest first.
var Severities = []string{"critical", "high", "medium", "low", "informational"}

// Config describes one examination.
type Config struct {
	Provider      string // ProviderAnthropic (default) or ProviderOpenRouter
	Model         string
	Effort        string
	MaxIterations int
	RepoDir       string // checked out at Revision; read-only to the agent
	Source        string // repository URI
	Revision      string // full commit id
	Scope         string // what is in scope, in plain words
}

// Finding is one reported defect. Verified is set only when the quote was
// found verbatim (whitespace-normalized) inside the cited lines.
type Finding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Confidence     string `json:"confidence"`
	Title          string `json:"title"`
	Path           string `json:"path"`
	LineStart      int    `json:"lineStart"`
	LineEnd        int    `json:"lineEnd"`
	Quote          string `json:"quote"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Verified       bool   `json:"verified"`
	Rejection      string `json:"rejection,omitempty"`
}

// Coverage is the agent's own statement of what it did and did not examine.
type Coverage struct {
	Summary     string   `json:"summary"`
	Examined    []string `json:"examined"`
	NotExamined []string `json:"notExamined"`
	Complete    bool     `json:"complete"`
	Declared    bool     `json:"declared"`
}

// Result is the draft handed to the human auditor.
type Result struct {
	Findings   []Finding       `json:"findings"`
	Rejected   []Finding       `json:"rejected"`
	Coverage   Coverage        `json:"coverage"`
	StopReason string          `json:"stopReason"`
	Iterations int             `json:"iterations"`
	Transcript json.RawMessage `json:"-"`
}

// workspace confines every read to the checked-out tree.
type workspace struct {
	root string
}

func (w workspace) resolve(rel string) (string, error) {
	if rel == "" {
		rel = "."
	}
	if filepath.IsAbs(rel) {
		return "", errors.New("paths are relative to the repository root")
	}
	full := filepath.Join(w.root, filepath.Clean("/"+rel))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", fmt.Errorf("no such path: %s", rel)
	}
	rootReal, _ := filepath.EvalSymlinks(w.root)
	if r, err := filepath.Rel(rootReal, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("path leaves the repository")
	}
	if strings.Contains(filepath.ToSlash(real), "/.git/") || strings.HasSuffix(real, "/.git") {
		return "", errors.New("the .git directory is not part of the artifact")
	}
	return real, nil
}

func (w workspace) lines(rel string) ([]string, error) {
	p, err := w.resolve(rel)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s", rel)
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, fmt.Errorf("%s is binary", rel)
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}

var ws = regexp.MustCompile(`\s+`)

func normalize(s string) string { return strings.TrimSpace(ws.ReplaceAllString(s, " ")) }

// verify checks a finding's evidence against the pinned bytes.
func (w workspace) verify(f *Finding) {
	f.Verified = false
	switch {
	case !contains(Severities, f.Severity):
		f.Rejection = "severity is not on severity-v1"
		return
	case f.LineStart < 1 || f.LineEnd < f.LineStart:
		f.Rejection = "invalid line range"
		return
	case f.LineEnd-f.LineStart+1 > maxQuoteLines:
		f.Rejection = fmt.Sprintf("cite at most %d lines", maxQuoteLines)
		return
	case len(normalize(f.Quote)) < minQuoteChars:
		f.Rejection = "quote too short to identify the code"
		return
	}
	lines, err := w.lines(f.Path)
	if err != nil {
		f.Rejection = err.Error()
		return
	}
	if f.LineEnd > len(lines) {
		f.Rejection = fmt.Sprintf("%s has %d lines", f.Path, len(lines))
		return
	}
	span := normalize(strings.Join(lines[f.LineStart-1:f.LineEnd], "\n"))
	if !strings.Contains(span, normalize(f.Quote)) {
		f.Rejection = fmt.Sprintf("quote not found in %s:%d-%d", f.Path, f.LineStart, f.LineEnd)
		return
	}
	f.Rejection = ""
	f.Verified = true
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// state accumulates what the tools record during one run.
type state struct {
	mu       sync.Mutex
	w        workspace
	findings []Finding
	rejected []Finding
	coverage Coverage
}

func text(s string) anthropic.BetaToolResultBlockParamContentUnion {
	return anthropic.BetaToolResultBlockParamContentUnion{OfText: &anthropic.BetaTextBlockParam{Text: s}}
}

type listInput struct {
	Dir string `json:"dir" jsonschema:"description=Directory relative to the repository root; '.' for the root"`
}

type readInput struct {
	Path      string `json:"path" jsonschema:"required,description=File path relative to the repository root"`
	StartLine int    `json:"start_line" jsonschema:"description=First line to return (1-based); default 1"`
	EndLine   int    `json:"end_line" jsonschema:"description=Last line to return; at most 400 lines per call"`
}

type searchInput struct {
	Pattern  string `json:"pattern" jsonschema:"required,description=RE2 regular expression matched line by line"`
	PathGlob string `json:"path_glob" jsonschema:"description=Optional glob on the relative path — e.g. src/*.rs"`
}

type findingInput struct {
	Severity       string `json:"severity" jsonschema:"required,enum=critical,enum=high,enum=medium,enum=low,enum=informational"`
	Confidence     string `json:"confidence" jsonschema:"required,enum=high,enum=medium,enum=low"`
	Title          string `json:"title" jsonschema:"required,description=One line naming the defect"`
	Path           string `json:"path" jsonschema:"required,description=File the evidence is in"`
	LineStart      int    `json:"line_start" jsonschema:"required,description=First cited line (1-based)"`
	LineEnd        int    `json:"line_end" jsonschema:"required,description=Last cited line; at most 60 lines after line_start"`
	Quote          string `json:"quote" jsonschema:"required,description=The cited code copied verbatim from read_file output without line-number prefixes"`
	Description    string `json:"description" jsonschema:"required,description=What is wrong — why it matters — and how it is reached"`
	Recommendation string `json:"recommendation" jsonschema:"required,description=What would fix it"`
}

type finishInput struct {
	Summary     string   `json:"summary" jsonschema:"required,description=Two or three sentences on what the examination found"`
	Examined    []string `json:"examined" jsonschema:"required,description=Files or areas actually read"`
	NotExamined []string `json:"not_examined" jsonschema:"required,description=Parts of the scope not examined — and why"`
	Complete    bool     `json:"complete" jsonschema:"required,description=True only if the whole stated scope was examined"`
}

func (s *state) tools() ([]anthropic.BetaTool, error) {
	list, err := toolrunner.NewBetaToolFromJSONSchema("list_files",
		"List files and directories under a directory of the checked-out artifact, with sizes.",
		func(_ context.Context, in listInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			dir, err := s.w.resolve(in.Dir)
			if err != nil {
				return text("error: " + err.Error()), nil
			}
			rootReal, _ := filepath.EvalSymlinks(s.w.root)
			var out []string
			filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() && d.Name() == ".git" {
					return filepath.SkipDir
				}
				if len(out) >= maxListEntries {
					return filepath.SkipAll
				}
				rel, _ := filepath.Rel(rootReal, p)
				if d.IsDir() {
					if rel != "." {
						out = append(out, rel+"/")
					}
					return nil
				}
				if info, err := d.Info(); err == nil {
					out = append(out, fmt.Sprintf("%s (%d bytes)", rel, info.Size()))
				}
				return nil
			})
			sort.Strings(out)
			if len(out) >= maxListEntries {
				out = append(out, fmt.Sprintf("… listing truncated at %d entries; list a subdirectory", maxListEntries))
			}
			return text(strings.Join(out, "\n")), nil
		})
	if err != nil {
		return nil, err
	}
	read, err := toolrunner.NewBetaToolFromJSONSchema("read_file",
		"Read a text file of the artifact with 1-based line numbers, at most 400 lines per call.",
		func(_ context.Context, in readInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			lines, err := s.w.lines(in.Path)
			if err != nil {
				return text("error: " + err.Error()), nil
			}
			start, end := in.StartLine, in.EndLine
			if start < 1 {
				start = 1
			}
			if end < start || end-start+1 > maxReadLines {
				end = start + maxReadLines - 1
			}
			if end > len(lines) {
				end = len(lines)
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s — lines %d-%d of %d\n", in.Path, start, end, len(lines))
			for i := start; i <= end && b.Len() < maxReadBytes; i++ {
				fmt.Fprintf(&b, "%6d\t%s\n", i, lines[i-1])
			}
			return text(b.String()), nil
		})
	if err != nil {
		return nil, err
	}
	search, err := toolrunner.NewBetaToolFromJSONSchema("search",
		"Search the artifact line by line with an RE2 regular expression; returns path:line: text.",
		func(_ context.Context, in searchInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			re, err := regexp.Compile(in.Pattern)
			if err != nil {
				return text("error: invalid pattern: " + err.Error()), nil
			}
			rootReal, _ := filepath.EvalSymlinks(s.w.root)
			var hits []string
			filepath.WalkDir(rootReal, func(p string, d fs.DirEntry, err error) error {
				if err != nil || len(hits) >= maxSearchResults {
					return nil
				}
				if d.IsDir() {
					if d.Name() == ".git" {
						return filepath.SkipDir
					}
					return nil
				}
				rel, _ := filepath.Rel(rootReal, p)
				if in.PathGlob != "" {
					if ok, _ := filepath.Match(in.PathGlob, rel); !ok {
						return nil
					}
				}
				f, err := os.Open(p)
				if err != nil {
					return nil
				}
				defer f.Close()
				sc := bufio.NewScanner(f)
				sc.Buffer(make([]byte, 64<<10), 1<<20)
				for n := 1; sc.Scan(); n++ {
					line := sc.Text()
					if strings.IndexByte(line, 0) >= 0 {
						return nil
					}
					if re.MatchString(line) {
						if len(line) > 240 {
							line = line[:240] + "…"
						}
						hits = append(hits, fmt.Sprintf("%s:%d: %s", rel, n, line))
						if len(hits) >= maxSearchResults {
							break
						}
					}
				}
				return nil
			})
			if len(hits) == 0 {
				return text("no matches"), nil
			}
			return text(strings.Join(hits, "\n")), nil
		})
	if err != nil {
		return nil, err
	}
	report, err := toolrunner.NewBetaToolFromJSONSchema("report_finding",
		"Record one defect with verbatim evidence. The quote is checked against the pinned file; a mismatch is rejected and you may resubmit.",
		func(_ context.Context, in findingInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			f := Finding{Severity: in.Severity, Confidence: in.Confidence, Title: in.Title, Path: in.Path, LineStart: in.LineStart, LineEnd: in.LineEnd, Quote: in.Quote, Description: in.Description, Recommendation: in.Recommendation}
			s.w.verify(&f)
			if !f.Verified {
				s.rejected = append(s.rejected, f)
				return text("REJECTED: " + f.Rejection + ". Re-read the file and resubmit with a verbatim quote, or drop the finding."), nil
			}
			s.findings = append(s.findings, f)
			return text("recorded (evidence verified)"), nil
		})
	if err != nil {
		return nil, err
	}
	finish, err := toolrunner.NewBetaToolFromJSONSchema("finish",
		"Declare the examination finished and state its coverage. Call once, at the end.",
		func(_ context.Context, in finishInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.coverage = Coverage{Summary: in.Summary, Examined: in.Examined, NotExamined: in.NotExamined, Complete: in.Complete, Declared: true}
			return text("coverage recorded; the examination is closed. Reply with a one-line summary and no further tool calls."), nil
		})
	if err != nil {
		return nil, err
	}
	return []anthropic.BetaTool{list, read, search, report, finish}, nil
}

// Review runs one examination.
func Review(ctx context.Context, client anthropic.Client, cfg Config, opts ...option.RequestOption) (*Result, error) {
	if cfg.Provider == "" {
		cfg.Provider = ProviderAnthropic
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
		if cfg.Provider == ProviderOpenRouter {
			cfg.Model = DefaultOpenRouterModel
		}
	}
	if cfg.Effort == "" {
		cfg.Effort = DefaultEffort
	}
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = DefaultMaxIterations
	}
	if _, err := os.Stat(cfg.RepoDir); err != nil {
		return nil, err
	}
	s := &state{w: workspace{root: cfg.RepoDir}}
	tools, err := s.tools()
	if err != nil {
		return nil, err
	}
	task := fmt.Sprintf("Artifact: %s at commit %s.\n\nScope:\n%s\n\nExamine the scope, report findings with verbatim evidence, then call finish.", cfg.Source, cfg.Revision, cfg.Scope)
	params := anthropic.BetaToolRunnerParams{
		BetaMessageNewParams: anthropic.BetaMessageNewParams{
			Model:     anthropic.Model(cfg.Model),
			MaxTokens: 16000,
			System:    []anthropic.BetaTextBlockParam{{Text: SystemPrompt}},
			Messages:  []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(task))},
			Thinking:  anthropic.BetaThinkingConfigParamUnion{OfAdaptive: &anthropic.BetaThinkingConfigAdaptiveParam{}},
			OutputConfig: anthropic.BetaOutputConfigParam{
				Effort: anthropic.BetaOutputConfigEffort(cfg.Effort),
			},
			// Auto-placed breakpoint: every turn re-reads the growing history
			// from cache instead of paying for it again.
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		},
		MaxIterations: cfg.MaxIterations,
	}
	if cfg.Provider == ProviderAnthropic {
		// A refused turn is re-served by a fallback model within the same
		// call. OpenRouter routes around failing providers itself and does
		// not take Anthropic's fallback beta.
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
	}
	runner := client.Beta.Messages.NewToolRunner(tools, params, opts...)

	res := &Result{}
	var last *anthropic.BetaMessage
	for msg, err := range runner.All(ctx) {
		if err != nil {
			return nil, err
		}
		res.Iterations++
		last = msg
	}
	if last != nil {
		res.StopReason = string(last.StopReason)
		runner.Params.Messages = append(runner.Params.Messages, last.ToParam())
	}
	s.mu.Lock()
	res.Findings, res.Rejected, res.Coverage = s.findings, s.rejected, s.coverage
	s.mu.Unlock()
	// Tools run concurrently, so arrival order is not reproducible; number
	// findings by severity, then location.
	rank := map[string]int{}
	for i, v := range Severities {
		rank[v] = i
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.LineStart < b.LineStart
	})
	for i := range res.Findings {
		res.Findings[i].ID = fmt.Sprintf("F%d", i+1)
	}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	if res.Rejected == nil {
		res.Rejected = []Finding{}
	}
	if res.Coverage.Examined == nil {
		res.Coverage.Examined = []string{}
	}
	if res.Coverage.NotExamined == nil {
		res.Coverage.NotExamined = []string{}
	}
	res.Transcript, err = json.Marshal(runner.Params.Messages)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ResultClass maps a draft to methodology's result class (security-review-llm
// v1): a verified critical fails; any other verified finding at or above
// the floor is findings-noted; nothing found is clear only when coverage was
// declared complete and the run ended normally; anything else is
// inconclusive.
func (r *Result) ResultClass() string {
	sev := map[string]int{}
	for _, f := range r.Findings {
		sev[f.Severity]++
	}
	switch {
	case r.StopReason == "refusal" || !r.Coverage.Declared:
		return "inconclusive"
	case sev["critical"] > 0:
		return "fail"
	case sev["high"]+sev["medium"]+sev["low"] > 0:
		return "findings-noted"
	case !r.Coverage.Complete:
		return "inconclusive"
	default:
		return "clear"
	}
}

// Summary counts verified findings by severity, as findingsSummary does.
func (r *Result) Summary() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// PromptDigest identifies the exact system prompt the run used.
func PromptDigest() string { return sig.Digest([]byte(SystemPrompt)) }
