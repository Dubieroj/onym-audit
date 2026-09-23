// Command onym-audit operates an Onym audit seat under the static-Ed25519
// profile: key generation, manifest publication, attestation issuance,
// supersession and revocation, status-list signing, the online server, the
// relying-client verify, and conformance runs.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"onym-audit/agent"
	"onym-audit/audit"
	"onym-audit/canon"
	"onym-audit/conformance/discovery"
	"onym-audit/console"
	"onym-audit/hub"
	"onym-audit/server"
	"onym-audit/sig"
	"onym-audit/site"
	"onym-audit/urirule"
)

const usage = `onym-audit — Onym audit seat, static-Ed25519 profile

Auditor (offline, holds the auditor key):
  keygen      -out FILE                              new Ed25519 seed (hex, 0600)
  publish     -root DIR -config FILE -key FILE -status-key FILE
                                                     sign profile.json and manifest.json
  attest      -root DIR -config FILE -key FILE -in DRAFT.json
                                                     sign and publish an attestation
  offer       -root DIR -config FILE -key FILE -in DRAFT.json   sign and publish an engagement offer
  revoke      -root DIR -config FILE -key FILE -id ID -reason REASON [-detail-uri U -detail FILE]
  countersign -in ORDER.json -key FILE -out FILE     accept a reviewed order (auditor role)

Online (holds only the delegated status key):
  status      -root DIR -config FILE -status-key FILE    re-sign status.json now
  serve       -root DIR -config FILE -status-key FILE -inbox DIR [-hub-root DIR] [-listen ADDR]
  hub-disable -hub-root DIR -slug NAME -reason TEXT      take a hosted auditor off the hub

Anyone:
  verify      -manifest URI|FILE -attestation URI|FILE -target URI [-status URI|FILE] [-credit onym:key:..]
  respond     -attestation URI|FILE -key FILE -id ID -text TEXT -out FILE   (subject's signed reply)
  sign-order  -in ORDER.json -role subject|sponsor -key FILE -out FILE
  fixtures    -dir DIR                               run the published fixture cases
  conformance-discovery -manifest URL [-out FILE]    run the Discovery provider suite
  conformance-discovery -scope-doc                   print the suite's scope document
  draft-conformance -root DIR -config FILE -report FILE -id ID -contact C -notified-at T
                    -relationships TEXT [-observations FILE] -out DRAFT.json

Local auditor console (web UI on loopback; holds the auditor key):
  console -root DIR -config FILE -key FILE -status-key FILE [-reviews DIR] [-inbox DIR]
          [-deploy-host HOST] [-provider openrouter|anthropic] [-listen 127.0.0.1:8790]

LLM-assisted security review (drafts only; the auditor reviews and signs):
  agent-review -repo URL -commit SHA -scope TEXT|-scope-file FILE -out DIR [-provider openrouter|anthropic] [-model M] [-effort E]
  draft-review -root DIR -config FILE -findings DIR/findings.json -id ID -relationships TEXT
               -contact C -notified-at T -subject ID -subject-operator KEY [-drop F2:reason ...] -out DRAFT.json
`

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"keygen": keygen, "publish": publish, "attest": attest, "revoke": revoke,
		"countersign": countersign, "offer": offer, "status": status, "serve": serve, "verify": verify,
		"respond": respond, "sign-order": signOrder, "fixtures": fixtures,
		"conformance-discovery": conformanceDiscovery, "draft-conformance": draftConformance,
		"agent-review": agentReview, "draft-review": draftReview, "console": runConsole, "hub-disable": hubDisable,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(os.Args[2:]); err != nil {
		log.Fatalf("onym-audit %s: %v", os.Args[1], err)
	}
}

func need(fs *flag.FlagSet, names ...string) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, n := range names {
		if !set[n] {
			return fmt.Errorf("-%s is required", n)
		}
	}
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "seed file to create")
	fs.Parse(args)
	if err := need(fs, "out"); err != nil {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	k := site.KeyOf(ed25519.NewKeyFromSeed(seed))
	fmt.Printf("%s\nfingerprint %s\n", k, k.Fingerprint())
	return nil
}

func loadAll(root, config, key string) (*site.Config, ed25519.PrivateKey, error) {
	c, err := site.LoadConfig(config)
	if err != nil {
		return nil, nil, err
	}
	var k ed25519.PrivateKey
	if key != "" {
		if k, err = site.LoadKey(key); err != nil {
			return nil, nil, err
		}
	}
	return c, k, nil
}

func publish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	key := fs.String("key", "", "auditor key")
	statusKey := fs.String("status-key", "", "status key (only its public half is published)")
	fs.Parse(args)
	if err := need(fs, "root", "config", "key", "status-key"); err != nil {
		return err
	}
	c, k, err := loadAll(*root, *config, *key)
	if err != nil {
		return err
	}
	sk, err := site.LoadKey(*statusKey)
	if err != nil {
		return err
	}
	prof, err := site.BuildProfile(*root, c, k)
	if err != nil {
		return err
	}
	if _, err := audit.ParseProfile(prof); err != nil {
		return err
	}
	if err := site.WriteSigned(filepath.Join(*root, site.ProfilePath), prof); err != nil {
		return err
	}
	man, err := site.BuildManifest(*root, c, k, site.KeyOf(sk))
	if err != nil {
		return err
	}
	if _, err := audit.ParseManifest(man, time.Now()); err != nil {
		return err
	}
	if err := site.WriteSigned(filepath.Join(*root, site.ManifestPath), man); err != nil {
		return err
	}
	fmt.Printf("manifest %s\noperator %s (%s)\nstatus key %s\n", sig.Digest(man), site.KeyOf(k), site.KeyOf(k).Fingerprint(), site.KeyOf(sk))
	return nil
}

func attest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	key := fs.String("key", "", "auditor key")
	in := fs.String("in", "", "attestation draft (JSON, unsigned)")
	fs.Parse(args)
	if err := need(fs, "root", "config", "key", "in"); err != nil {
		return err
	}
	c, k, err := loadAll(*root, *config, *key)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var a audit.Attestation
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return err
	}
	a.Auditor, a.AuditorKey, a.Status, a.Signature = c.ComponentID, site.KeyOf(k), c.BaseURI+site.StatusPath, ""
	raw, err := audit.SignDoc(a, k)
	if err != nil {
		return err
	}
	if _, err := audit.ParseAttestation(raw); err != nil {
		return err
	}
	path := filepath.Join(*root, "attestations", a.AttestationID+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists: attestations are immutable (§14); supersede instead", path)
	}
	if err := site.WriteSigned(path, raw); err != nil {
		return err
	}
	fmt.Printf("%s%s\n%s\n", c.BaseURI, "attestations/"+a.AttestationID+".json", sig.Digest(raw))
	return nil
}

func offer(args []string) error {
	fs := flag.NewFlagSet("offer", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	key := fs.String("key", "", "auditor key")
	in := fs.String("in", "", "offer draft (JSON, unsigned)")
	fs.Parse(args)
	if err := need(fs, "root", "config", "key", "in"); err != nil {
		return err
	}
	c, k, err := loadAll(*root, *config, *key)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var o audit.Offer
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return err
	}
	o.Auditor, o.AuditorKey, o.Signature = c.ComponentID, site.KeyOf(k), ""
	raw, err := audit.SignDoc(o, k)
	if err != nil {
		return err
	}
	if _, err := audit.ParseOffer(raw); err != nil {
		return err
	}
	return site.WriteSigned(filepath.Join(*root, "offers", o.OfferID+".json"), raw)
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	key := fs.String("key", "", "auditor key")
	id := fs.String("id", "", "attestation id")
	reason := fs.String("reason", "", strings.Join(audit.RevocationReasons, " | "))
	detailURI := fs.String("detail-uri", "", "published URI of a detail document")
	detail := fs.String("detail", "", "local copy of that document")
	fs.Parse(args)
	if err := need(fs, "root", "config", "key", "id", "reason"); err != nil {
		return err
	}
	c, k, err := loadAll(*root, *config, *key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(*root, "attestations", *id+".json")); err != nil {
		return fmt.Errorf("no attestation %s in this tree", *id)
	}
	now := time.Now()
	rv := audit.Revocation{RevocationVersion: 1, AttestationID: *id, Auditor: c.ComponentID, AuditorKey: site.KeyOf(k), IssuedAt: sig.FormatTime(now), StatusEpoch: now.Unix(), EffectiveFrom: sig.FormatTime(now), Reason: *reason}
	if *detailURI != "" {
		b, err := os.ReadFile(*detail)
		if err != nil {
			return err
		}
		if err := urirule.Check(*detailURI); err != nil {
			return err
		}
		rv.Detail = &audit.DocRef{URI: *detailURI, Digest: sig.Digest(b)}
	}
	raw, err := audit.SignDoc(rv, k)
	if err != nil {
		return err
	}
	if _, err := audit.ParseRevocation(raw); err != nil {
		return err
	}
	return site.WriteSigned(filepath.Join(*root, "revocations", *id+".json"), raw)
}

func countersign(args []string) error {
	fs := flag.NewFlagSet("countersign", flag.ExitOnError)
	in := fs.String("in", "", "queued order")
	key := fs.String("key", "", "auditor key")
	out := fs.String("out", "", "output")
	fs.Parse(args)
	if err := need(fs, "in", "key", "out"); err != nil {
		return err
	}
	return signAs(*in, "auditor", *key, *out, true)
}

func signOrder(args []string) error {
	fs := flag.NewFlagSet("sign-order", flag.ExitOnError)
	in := fs.String("in", "", "order")
	role := fs.String("role", "", "subject | sponsor")
	key := fs.String("key", "", "signing key")
	out := fs.String("out", "", "output")
	fs.Parse(args)
	if err := need(fs, "in", "role", "key", "out"); err != nil {
		return err
	}
	if *role != "subject" && *role != "sponsor" {
		return errors.New("-role must be subject or sponsor")
	}
	return signAs(*in, *role, *key, *out, false)
}

func signAs(in, role, keyPath, out string, final bool) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	k, err := site.LoadKey(keyPath)
	if err != nil {
		return err
	}
	signed, err := audit.SignOrder(b, role, k)
	if err != nil {
		return err
	}
	if final {
		if _, err := audit.ParseOrder(signed); err != nil {
			return err
		}
	}
	return site.WriteAtomic(out, signed)
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	statusKey := fs.String("status-key", "", "status key")
	fs.Parse(args)
	if err := need(fs, "root", "config", "status-key"); err != nil {
		return err
	}
	c, k, err := loadAll(*root, *config, *statusKey)
	if err != nil {
		return err
	}
	return site.ResignStatus(*root, c, k, time.Now())
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	statusKey := fs.String("status-key", "", "status key")
	inbox := fs.String("inbox", "", "order inbox (not published)")
	listen := fs.String("listen", "127.0.0.1:8787", "listen address (behind a TLS reverse proxy)")
	hubRoot := fs.String("hub-root", "", "host other auditors here (studio API and a/<slug>/ trees)")
	fs.Parse(args)
	if err := need(fs, "root", "config", "status-key", "inbox"); err != nil {
		return err
	}
	c, k, err := loadAll(*root, *config, *statusKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*inbox, 0o700); err != nil {
		return err
	}
	s, err := server.New(*root, *inbox, c, k)
	if err != nil {
		return err
	}
	if *hubRoot != "" {
		h, err := hub.New(*hubRoot, *root, c.BaseURI)
		if err != nil {
			return err
		}
		h.ResignAll()
		s.Hub, s.HubResign = h.Handler(), h.ResignAll
	}
	stop := make(chan struct{})
	go s.Loop(audit.ResignInterval, stop)
	hs := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for sgn := range ch {
			if sgn == syscall.SIGHUP {
				if err := s.Resign(); err != nil {
					log.Printf("re-sign on SIGHUP failed: %v", err)
				}
				continue
			}
			close(stop)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			hs.Shutdown(ctx)
			cancel()
			return
		}
	}()
	log.Printf("serving %s on %s", c.BaseURI, *listen)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// fetch reads a local file, or GETs an https URI under the §7 rules.
func fetch(ref string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(ref, "https://") {
		return os.ReadFile(ref)
	}
	if err := urirule.Check(ref); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("more than 3 redirects")
		}
		return urirule.Check(req.URL.String())
	}}
	resp, err := client.Get(ref)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", ref, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", ref, limit)
	}
	return b, nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	manifest := fs.String("manifest", "", "auditor manifest URI or file")
	att := fs.String("attestation", "", "attestation URI or file")
	target := fs.String("target", "", "HTTPS URI of the component manifest you are about to use")
	targetCommit := fs.String("target-commit", "", "for source attestations: the full commit id of the repository named by -target")
	targetFile := fs.String("target-file", "", "local copy of the component manifest's bytes (then -target is only its identity URI)")
	pinned := fs.String("target-document", "", "URI or file of the further served document you are about to use (e.g. the current catalog snapshot), when the attestation pins one")
	statusRef := fs.String("status", "", "status list URI or file (default: the manifest's statusEndpoint)")
	credit := fs.String("credit", "", "comma-separated auditor keys you credit")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
	respFile := fs.String("response", "", "local copy of a subject response the status list names")
	fs.Parse(args)
	if err := need(fs, "manifest", "attestation", "target"); err != nil {
		return err
	}
	now := time.Now()
	in := audit.Input{Now: now, State: &audit.StatusState{}, Responses: map[string][]byte{}, Trust: audit.Trust{Credited: map[sig.Key]bool{}}}
	var err error
	if in.Manifest, err = fetch(*manifest, 256<<10); err != nil {
		return err
	}
	if in.Attestation, err = fetch(*att, 256<<10); err != nil {
		return err
	}
	if *targetCommit != "" {
		if err := urirule.Check(*target); err != nil {
			return err
		}
		in.Target = audit.Target{Kind: audit.KindSource, Source: *target, Revision: *targetCommit}
		return verifyWith(in, *statusRef, *credit, *respFile, *asJSON, now)
	}
	src := *target
	if *targetFile != "" {
		if err := urirule.Check(*target); err != nil {
			return err
		}
		src = *targetFile
	}
	tb, err := fetch(src, 256<<10)
	if err != nil {
		return err
	}
	var pb []byte
	if *pinned != "" {
		if pb, err = fetch(*pinned, 4<<20); err != nil {
			return err
		}
	}
	in.Target = audit.DeploymentTarget(*target, tb, pb)
	return verifyWith(in, *statusRef, *credit, *respFile, *asJSON, now)
}

func verifyWith(in audit.Input, statusRef, credit, respFile string, asJSON bool, now time.Time) error {
	for _, k := range strings.Split(credit, ",") {
		if k != "" {
			in.Trust.Credited[sig.Key(strings.TrimSpace(k))] = true
		}
	}
	m, err := audit.ParseManifest(in.Manifest, now)
	if err != nil {
		return err
	}
	sref := statusRef
	if sref == "" {
		sref = m.StatusEndpoint
	}
	if st, err := fetch(sref, 4<<20); err == nil {
		in.Status = st
		// Follow the entry's revocation and responses so the decision is complete.
		if l, _ := audit.ParseStatus(st, m, nil, now); l != nil {
			if a, err := audit.ParseAttestation(in.Attestation); err == nil {
				if e := l.Entry(a.AttestationID); e != nil {
					if e.Revocation != nil {
						in.Revocation, _ = fetch(e.Revocation.URI, 64<<10)
					}
					for _, r := range e.Responses {
						if b, err := fetch(r.URI, audit.MaxResponseText*2); err == nil {
							in.Responses[sig.Digest(b)] = b
						}
					}
				}
			}
		}
	}
	if respFile != "" {
		b, err := os.ReadFile(respFile)
		if err != nil {
			return err
		}
		in.Responses[sig.Digest(b)] = b
	}
	d := audit.Verify(in)
	if asJSON {
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("display: %s\n", d.Display)
	if d.Error != "" {
		fmt.Printf("error:   %s\n", d.Error)
	}
	fmt.Printf("high-stakes reliance: %v\n\n%s\n", d.HighStakesOK, d.Summary(now))
	for _, n := range d.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	return nil
}

func respond(args []string) error {
	fs := flag.NewFlagSet("respond", flag.ExitOnError)
	att := fs.String("attestation", "", "attestation URI or file")
	key := fs.String("key", "", "subject operator key")
	id := fs.String("id", "", "response id (16–128 of A-Za-z0-9_-)")
	text := fs.String("text", "", "reply text")
	out := fs.String("out", "", "output")
	fs.Parse(args)
	if err := need(fs, "attestation", "key", "id", "text", "out"); err != nil {
		return err
	}
	raw, err := fetch(*att, 256<<10)
	if err != nil {
		return err
	}
	a, err := audit.ParseAttestation(raw)
	if err != nil {
		return err
	}
	k, err := site.LoadKey(*key)
	if err != nil {
		return err
	}
	r := audit.SubjectResponse{ResponseVersion: 1, ResponseID: *id, AttestationID: a.AttestationID, Attestation: sig.Digest(raw), Subject: a.Subject, Respondent: site.KeyOf(k), IssuedAt: sig.FormatTime(time.Now()), Text: *text}
	b, err := audit.SignDoc(r, k)
	if err != nil {
		return err
	}
	if _, err := audit.ParseResponse(b, a, sig.Digest(raw)); err != nil {
		return err
	}
	return site.WriteAtomic(*out, b)
}

func fixtures(args []string) error {
	fs := flag.NewFlagSet("fixtures", flag.ExitOnError)
	dir := fs.String("dir", "fixtures", "fixture directory")
	fs.Parse(args)
	b, err := os.ReadFile(filepath.Join(*dir, "cases.json"))
	if err != nil {
		return err
	}
	var set struct {
		Cases   []audit.FixtureCase    `json:"cases"`
		Invalid []audit.FixtureInvalid `json:"invalid"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return err
	}
	files := map[string][]byte{}
	entries, _ := os.ReadDir(*dir)
	for _, e := range entries {
		if files[e.Name()], err = os.ReadFile(filepath.Join(*dir, e.Name())); err != nil {
			return err
		}
	}
	failed := 0
	for _, c := range set.Cases {
		d, err := audit.RunFixtureCase(files, c)
		ok := err == nil && d.Display == c.ExpectDisplay && d.Error == c.ExpectError && d.HighStakesOK == c.ExpectHighOK
		if !ok {
			failed++
		}
		fmt.Printf("%-5s %-36s %s\n", map[bool]string{true: "pass", false: "FAIL"}[ok], c.Name, c.Covers)
	}
	for _, c := range set.Invalid {
		err := audit.RunFixtureInvalid(files, c)
		ok := (err == nil) == c.ExpectOK
		if !ok {
			failed++
		}
		fmt.Printf("%-5s %-36s %s\n", map[bool]string{true: "pass", false: "FAIL"}[ok], c.Name, c.Covers)
	}
	if failed > 0 {
		return fmt.Errorf("%d fixture(s) failed", failed)
	}
	fmt.Printf("\nall %d fixtures pass\n", len(set.Cases)+len(set.Invalid))
	return nil
}

func conformanceDiscovery(args []string) error {
	fs := flag.NewFlagSet("conformance-discovery", flag.ExitOnError)
	manifest := fs.String("manifest", "", "provider manifest URL")
	out := fs.String("out", "", "write the canonical report here")
	scopeDoc := fs.Bool("scope-doc", false, "print the scope document and exit")
	fs.Parse(args)
	if *scopeDoc {
		fmt.Print(discovery.ScopeMarkdown())
		return nil
	}
	if err := need(fs, "manifest"); err != nil {
		return err
	}
	rep := discovery.Run(context.Background(), discovery.NewHTTPFetcher(), *manifest, time.Now())
	for _, c := range rep.Checks {
		if c.Outcome != discovery.Pass {
			fmt.Printf("%-14s %-6s %-36s %s\n", c.Outcome, c.Level, c.ID, c.Detail)
		}
	}
	fmt.Printf("\n%d checks, %d documents fetched: result %s\n", len(rep.Checks), len(rep.Documents), strings.ToUpper(rep.Result))
	if *out != "" {
		b, err := rep.Canonical()
		if err != nil {
			return err
		}
		return site.WriteAtomic(*out, b)
	}
	return nil
}

// Observation is an auditor finding outside the suite (methodology:
// severity "informational" unless it rests on a clause the suite omits).
type Observation struct {
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
	Evidence []audit.DocRef `json:"evidence"`
}

func draftConformance(args []string) error {
	fs := flag.NewFlagSet("draft-conformance", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	reportPath := fs.String("report", "", "canonical suite report")
	obsPath := fs.String("observations", "", "JSON array of observations outside the suite")
	id := fs.String("id", "", "attestation id")
	contact := fs.String("contact", "", "subject contact the findings were sent to (mailto:… or https://…)")
	notified := fs.String("notified-at", "", "when the subject was notified (RFC 3339 UTC)")
	rel := fs.String("relationships", "", "declared relationships with the subject")
	out := fs.String("out", "", "draft to write")
	fs.Parse(args)
	if err := need(fs, "root", "config", "report", "id", "contact", "notified-at", "relationships", "out"); err != nil {
		return err
	}
	c, _, err := loadAll(*root, *config, "")
	if err != nil {
		return err
	}
	reportRaw, err := os.ReadFile(*reportPath)
	if err != nil {
		return err
	}
	var rep struct {
		ManifestURI string `json:"manifestUri"`
		Result      string `json:"result"`
		RunAt       string `json:"runAt"`
		Checks      []struct{ ID, Level, Outcome string }
		Documents   []struct{ URI, Digest, Role string }
	}
	if err := json.Unmarshal(reportRaw, &rep); err != nil {
		return err
	}
	suiteObj, err := canon.Parse(reportRaw)
	if err != nil {
		return err
	}
	var obs []Observation
	if *obsPath != "" {
		b, err := os.ReadFile(*obsPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &obs); err != nil {
			return err
		}
	}
	var manDigest, snapDigest string
	snaps := 0
	for _, d := range rep.Documents {
		switch d.Role {
		case "provider-manifest":
			manDigest = d.Digest
		case "catalog-snapshot":
			snapDigest = d.Digest
			snaps++
		}
	}
	if manDigest == "" {
		return errors.New("report has no provider manifest: nothing to bind")
	}
	// The manifest must still be the bytes the run examined.
	manRaw, err := fetch(rep.ManifestURI, 64<<10)
	if err != nil {
		return err
	}
	if sig.Digest(manRaw) != manDigest {
		return errors.New("the provider manifest changed since the run: run the suite again")
	}
	var man struct {
		ProviderID string  `json:"providerId"`
		Operator   sig.Key `json:"operator"`
	}
	if err := json.Unmarshal(manRaw, &man); err != nil {
		return err
	}
	summary := map[string]int{}
	for _, ch := range rep.Checks {
		if ch.Outcome == "fail" {
			if ch.Level == "MUST" {
				summary["high"]++
			} else {
				summary["low"]++
			}
		}
	}
	result := rep.Result
	for _, o := range obs {
		if !oneOfStr(o.Severity, audit.SeverityLevels...) {
			return fmt.Errorf("observation severity %q", o.Severity)
		}
		summary[o.Severity]++
		if result == audit.Clear && o.Severity != "informational" {
			result = audit.FindingsNoted
		}
	}
	// The findings report: the suite's own canonical output plus the
	// auditor's observations, content-addressed.
	obsVals := []any{}
	for _, o := range obs {
		ov, err := audit.CanonicalOf(o)
		if err != nil {
			return err
		}
		po, _ := canon.Parse(ov)
		obsVals = append(obsVals, po)
	}
	findings, err := canon.Encode(canon.Object{"findingsVersion": canon.Number("1"), "suiteReport": suiteObj, "observations": obsVals})
	if err != nil {
		return err
	}
	fd := sig.Digest(findings)
	rpath := "reports/" + strings.TrimPrefix(fd, "sha256:") + ".json"
	if err := site.WriteAtomic(filepath.Join(*root, rpath), findings); err != nil {
		return err
	}
	ref := func(p string) (audit.DocRef, error) { return site.Ref(*root, c, p) }
	meth, err := ref("methodology/conformance-run.md")
	if err != nil {
		return err
	}
	scope, err := ref("scopes/discovery-static-ed25519-provider.md")
	if err != nil {
		return err
	}
	scale, err := ref(site.SeverityPath)
	if err != nil {
		return err
	}
	unsol, err := ref(site.UnsolicitedPath)
	if err != nil {
		return err
	}
	auditorKey, err := manifestOperator(*root)
	if err != nil {
		return err
	}
	now := time.Now()
	a := audit.Attestation{
		AttestationVersion: 1, AttestationID: *id,
		Subject: "onym:component:" + strings.TrimPrefix(man.ProviderID, "onym:component:"), SubjectOperator: man.Operator,
		Artifact:         audit.Artifact{Kind: audit.KindDeployment, Source: rep.ManifestURI, Revision: manDigest},
		MethodologyClass: audit.ConformanceRun, Methodology: meth, Scope: scope,
		ScopeSummary: fmt.Sprintf("%s %s: Discovery-Static-Ed25519 provider obligations and client acceptance of the deployment as served at %s", discovery.SuiteID, discovery.SuiteVersion, rep.RunAt),
		Exclusions: []string{
			"client behaviour",
			"availability, honesty, or security of the listed instances beyond their signed manifests' digests, fields, and signatures",
			"host security and key custody",
			"destination manifests' conformance to their own seat contracts",
			"any state of the deployment other than the one served at run time",
		},
		Result: result, SeverityScale: &scale, SeverityFloor: strPtr("low"),
		FindingsReport:  &audit.DocRef{URI: c.BaseURI + rpath, Digest: fd},
		FindingsSummary: summary, Engagement: "unsolicited",
		Sponsor: auditorKey, SponsorName: c.DisplayName + " (self-funded)", Relationships: *rel,
		Unsolicited: &audit.UnsolicitedDisclosure{Policy: unsol.Digest, SubjectContact: *contact, SubjectNotifiedAt: *notified},
		IssuedAt:    sig.FormatTime(now), ExpiresAt: strPtr(sig.FormatTime(now.Add(30 * 24 * time.Hour))),
	}
	if snaps == 1 {
		// The pinned snapshot must also still be what is served.
		for _, d := range rep.Documents {
			if d.Role != "catalog-snapshot" {
				continue
			}
			cur, err := fetch(d.URI, 1<<20)
			if err != nil {
				return err
			}
			if sig.Digest(cur) != snapDigest {
				return errors.New("the catalog snapshot changed since the run: run the suite again")
			}
		}
		a.Artifact.ArtifactHash = &snapDigest
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("findings report %s%s\nresult %s, summary %v\n", c.BaseURI, rpath, result, summary)
	return site.WriteAtomic(*out, append(b, '\n'))
}

func manifestOperator(root string) (sig.Key, error) {
	b, err := os.ReadFile(filepath.Join(root, site.ManifestPath))
	if err != nil {
		return "", err
	}
	var m struct {
		Operator sig.Key `json:"operator"`
	}
	return m.Operator, json.Unmarshal(b, &m)
}

func strPtr(s string) *string { return &s }

func oneOfStr(v string, set ...string) bool {
	for _, x := range set {
		if v == x {
			return true
		}
	}
	return false
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// checkout fetches exactly one commit into dir and proves HEAD is it.
func checkout(repo, commit, dir string) error {
	if err := urirule.Check(repo); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return errors.New("-commit must be a full 40-character commit id")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", repo}, {"fetch", "-q", "--depth", "1", "origin", commit}, {"checkout", "-q", "--detach", "FETCH_HEAD"}} {
		if _, err := git(dir, args...); err != nil {
			return err
		}
	}
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if head != commit {
		return fmt.Errorf("checked out %s, not %s", head, commit)
	}
	return nil
}

// AgentReport is the findings document of one LLM-assisted review.
type AgentReport struct {
	FindingsVersion int             `json:"findingsVersion"`
	Methodology     string          `json:"methodology"`
	Engine          map[string]any  `json:"engine"`
	Artifact        audit.Artifact  `json:"artifact"`
	Scope           string          `json:"scope"`
	Coverage        agent.Coverage  `json:"coverage"`
	Findings        []agent.Finding `json:"findings"`
	Rejected        []agent.Finding `json:"rejectedByEvidenceCheck"`
	AuditorReview   map[string]any  `json:"auditorReview"`
	StopReason      string          `json:"stopReason"`
	Iterations      int             `json:"iterations"`
	Transcript      audit.DocRef    `json:"transcript"`
}

func agentReview(args []string) error {
	fs := flag.NewFlagSet("agent-review", flag.ExitOnError)
	repo := fs.String("repo", "", "repository HTTPS URL")
	commit := fs.String("commit", "", "full commit id to examine")
	scope := fs.String("scope", "", "what is in scope, in plain words")
	scopeFile := fs.String("scope-file", "", "file holding the scope")
	out := fs.String("out", "", "output directory")
	provider := fs.String("provider", agent.ProviderOpenRouter, "openrouter (OPENROUTER_API_KEY) or anthropic (ANTHROPIC_API_KEY)")
	model := fs.String("model", "", "Claude model (default anthropic/claude-opus-5 via OpenRouter, claude-opus-5 direct)")
	effort := fs.String("effort", agent.DefaultEffort, "effort: low|medium|high|xhigh|max")
	maxIter := fs.Int("max-iterations", agent.DefaultMaxIterations, "cap on model turns")
	fs.Parse(args)
	if err := need(fs, "repo", "commit", "out"); err != nil {
		return err
	}
	if *scopeFile != "" {
		b, err := os.ReadFile(*scopeFile)
		if err != nil {
			return err
		}
		*scope = string(b)
	}
	if strings.TrimSpace(*scope) == "" {
		return errors.New("state the scope with -scope or -scope-file")
	}
	client, err := agent.NewClient(*provider)
	if err != nil {
		return fmt.Errorf("%w (never paste a key into a chat or a file in this repository)", err)
	}
	if *model == "" {
		*model = agent.DefaultModel
		if *provider == agent.ProviderOpenRouter {
			*model = agent.DefaultOpenRouterModel
		}
	}
	work := filepath.Join(*out, "workspace")
	if err := checkout(*repo, *commit, work); err != nil {
		return err
	}
	fmt.Printf("examining %s at %s with %s via %s (effort %s)…\n", *repo, *commit, *model, *provider, *effort)
	res, err := agent.Review(context.Background(), client, agent.Config{
		Provider: *provider, Model: *model, Effort: *effort, MaxIterations: *maxIter,
		RepoDir: work, Source: *repo, Revision: *commit, Scope: *scope,
	})
	if err != nil {
		return err
	}
	tpath := filepath.Join(*out, "transcript.json")
	if err := site.WriteAtomic(tpath, res.Transcript); err != nil {
		return err
	}
	rep := AgentReport{
		FindingsVersion: 1, Methodology: agent.Version,
		Engine:   map[string]any{"model": *model, "effort": *effort, "maxIterations": *maxIter, "systemPrompt": agent.PromptDigest(), "tools": []string{"list_files", "read_file", "search", "report_finding", "finish"}},
		Artifact: audit.Artifact{Kind: audit.KindSource, Source: *repo, Revision: *commit},
		Scope:    *scope, Coverage: res.Coverage, Findings: res.Findings, Rejected: res.Rejected,
		AuditorReview: map[string]any{"state": "pending"},
		StopReason:    res.StopReason, Iterations: res.Iterations,
		Transcript: audit.DocRef{URI: "https://transcript.invalid/pending-publication", Digest: sig.Digest(res.Transcript)},
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := site.WriteAtomic(filepath.Join(*out, "findings.json"), append(b, '\n')); err != nil {
		return err
	}
	var sum strings.Builder
	fmt.Fprintf(&sum, "# Agent review — for the auditor\n\n%s at `%s`\n\nProposed result: **%s** · stop: %s · turns: %d\n\n", *repo, *commit, res.ResultClass(), res.StopReason, res.Iterations)
	fmt.Fprintf(&sum, "Coverage (%s): %s\n\n- examined: %s\n- not examined: %s\n\n", map[bool]string{true: "complete", false: "partial"}[res.Coverage.Complete], res.Coverage.Summary, strings.Join(res.Coverage.Examined, ", "), strings.Join(res.Coverage.NotExamined, "; "))
	for _, f := range res.Findings {
		fmt.Fprintf(&sum, "## %s · %s · %s\n\n`%s:%d-%d` · confidence %s\n\n```\n%s\n```\n\n%s\n\nFix: %s\n\n", f.ID, strings.ToUpper(f.Severity), f.Title, f.Path, f.LineStart, f.LineEnd, f.Confidence, f.Quote, f.Description, f.Recommendation)
	}
	if len(res.Rejected) > 0 {
		fmt.Fprintf(&sum, "## Rejected by the evidence check (%d)\n\n", len(res.Rejected))
		for _, f := range res.Rejected {
			fmt.Fprintf(&sum, "- %s — %s\n", f.Title, f.Rejection)
		}
	}
	sum.WriteString("\n## Before you sign\n\n1. Open every finding at its cited lines in the workspace and decide whether you stand behind it.\n2. Drop what you do not, with a reason: each `draft-review -drop F2:reason` is recorded in the published report.\n3. Notify the subject through its published security contact; record where and when.\n4. Run `draft-review`, read the draft, then `attest`.\n")
	if err := site.WriteAtomic(filepath.Join(*out, "summary.md"), []byte(sum.String())); err != nil {
		return err
	}
	fmt.Printf("\n%d verified finding(s), %d rejected; proposed result %s\nread %s before anything else\n", len(res.Findings), len(res.Rejected), res.ResultClass(), filepath.Join(*out, "summary.md"))
	return nil
}

func draftReview(args []string) error {
	fs := flag.NewFlagSet("draft-review", flag.ExitOnError)
	root := fs.String("root", "", "site root")
	config := fs.String("config", "", "auditor config")
	findingsPath := fs.String("findings", "", "findings.json written by agent-review")
	id := fs.String("id", "", "attestation id")
	rel := fs.String("relationships", "", "declared relationships with the subject")
	contact := fs.String("contact", "", "subject contact the findings were sent to")
	notified := fs.String("notified-at", "", "when the subject was notified (RFC 3339 UTC)")
	subject := fs.String("subject", "", "subject component id (onym:component:...)")
	subjectOp := fs.String("subject-operator", "", "subject operator key (onym:key:...), whose signed reply will be accepted")
	var drops multiFlag
	fs.Var(&drops, "drop", "ID:reason for a finding the auditor does not stand behind (repeatable)")
	out := fs.String("out", "", "draft to write")
	fs.Parse(args)
	if err := need(fs, "root", "config", "findings", "id", "relationships", "contact", "notified-at", "subject", "subject-operator", "out"); err != nil {
		return err
	}
	c, _, err := loadAll(*root, *config, "")
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*findingsPath)
	if err != nil {
		return err
	}
	var rep AgentReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return err
	}
	tb, err := os.ReadFile(filepath.Join(filepath.Dir(*findingsPath), "transcript.json"))
	if err != nil {
		return err
	}
	if sig.Digest(tb) != rep.Transcript.Digest {
		return errors.New("transcript.json does not match the digest in findings.json")
	}
	// The auditor's overrides are recorded, never silent.
	dropped := []map[string]string{}
	reasons := map[string]string{}
	for _, d := range drops {
		k, why, ok := strings.Cut(d, ":")
		if !ok || strings.TrimSpace(why) == "" {
			return fmt.Errorf("-drop %q: give a reason as ID:reason", d)
		}
		reasons[k] = strings.TrimSpace(why)
	}
	kept := []agent.Finding{}
	for _, f := range rep.Findings {
		if why, ok := reasons[f.ID]; ok {
			dropped = append(dropped, map[string]string{"id": f.ID, "title": f.Title, "reason": why})
			delete(reasons, f.ID)
			continue
		}
		kept = append(kept, f)
	}
	for k := range reasons {
		return fmt.Errorf("-drop names %s, which is not a finding", k)
	}
	rep.Findings = kept
	rep.AuditorReview = map[string]any{"state": "reviewed", "reviewedBy": c.DisplayName, "dropped": dropped}
	// Publish the transcript and the report, content-addressed.
	thex := strings.TrimPrefix(sig.Digest(tb), "sha256:")
	tpath := "reports/" + thex + "-transcript.json"
	if err := site.WriteAtomic(filepath.Join(*root, tpath), tb); err != nil {
		return err
	}
	rep.Transcript = audit.DocRef{URI: c.BaseURI + tpath, Digest: sig.Digest(tb)}
	rb, err := audit.CanonicalOf(rep)
	if err != nil {
		return err
	}
	rhex := strings.TrimPrefix(sig.Digest(rb), "sha256:")
	rpath := "reports/" + rhex + ".json"
	if err := site.WriteAtomic(filepath.Join(*root, rpath), rb); err != nil {
		return err
	}
	scopeDoc := fmt.Sprintf("# Scope: security-review of %s at %s\n\nMethodology `security-review-llm-v1`.\n\n%s\n", rep.Artifact.Source, rep.Artifact.Revision, rep.Scope)
	spath := "scopes/security-review-" + rep.Artifact.Revision[:12] + ".md"
	if err := site.WriteAtomic(filepath.Join(*root, spath), []byte(scopeDoc)); err != nil {
		return err
	}
	ref := func(p string) (audit.DocRef, error) { return site.Ref(*root, c, p) }
	meth, err := ref("methodology/security-review-llm.md")
	if err != nil {
		return err
	}
	scopeRef, err := ref(spath)
	if err != nil {
		return err
	}
	scale, err := ref(site.SeverityPath)
	if err != nil {
		return err
	}
	unsol, err := ref(site.UnsolicitedPath)
	if err != nil {
		return err
	}
	auditorKey, err := manifestOperator(*root)
	if err != nil {
		return err
	}
	// The result follows the reviewed findings, not the agent's proposal.
	class := (&agent.Result{Findings: kept, Coverage: rep.Coverage, StopReason: rep.StopReason}).ResultClass()
	summary := map[string]int{}
	for _, f := range kept {
		summary[f.Severity]++
	}
	excl := append([]string{
		"anything outside the stated scope",
		"runtime behaviour: the review reads source at one commit and executes nothing",
		"dependencies not vendored in the repository",
		"defects the examination did not find: an LLM-assisted review can miss issues",
	}, rep.Coverage.NotExamined...)
	now := time.Now()
	a := audit.Attestation{
		AttestationVersion: 1, AttestationID: *id,
		Subject: *subject, SubjectOperator: sig.Key(*subjectOp),
		Artifact:         rep.Artifact,
		MethodologyClass: audit.SecurityReview, Methodology: meth, Scope: scopeRef,
		ScopeSummary: "LLM-assisted security review (" + rep.Engine["model"].(string) + ", human-reviewed): " + firstLine(rep.Scope),
		Exclusions:   excl, Result: class, SeverityScale: &scale, SeverityFloor: strPtr("low"),
		FindingsReport: &audit.DocRef{URI: c.BaseURI + rpath, Digest: sig.Digest(rb)}, FindingsSummary: summary,
		Engagement: "unsolicited", Sponsor: auditorKey, SponsorName: c.DisplayName + " (self-funded)", Relationships: *rel,
		Unsolicited: &audit.UnsolicitedDisclosure{Policy: unsol.Digest, SubjectContact: *contact, SubjectNotifiedAt: *notified},
		IssuedAt:    sig.FormatTime(now), ExpiresAt: strPtr(sig.FormatTime(now.Add(180 * 24 * time.Hour))),
	}
	db, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("report %s%s\nresult %s, %v, %d dropped by the auditor\n", c.BaseURI, rpath, class, summary, len(dropped))
	return site.WriteAtomic(*out, append(db, '\n'))
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, "; ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runConsole(args []string) error {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	root := fs.String("root", "public", "site root")
	config := fs.String("config", "config.json", "auditor config")
	key := fs.String("key", "keys/auditor.key", "auditor key")
	statusKey := fs.String("status-key", "keys/status.key", "status key")
	reviews := fs.String("reviews", "reviews", "review directories")
	inbox := fs.String("inbox", "inbox", "orders pulled from the server")
	host := fs.String("deploy-host", "root@69.62.114.87", "server holding the order inbox")
	provider := fs.String("provider", agent.ProviderOpenRouter, "engine provider: openrouter or anthropic")
	listen := fs.String("listen", "127.0.0.1:8790", "loopback address")
	fs.Parse(args)
	h, _, err := net.SplitHostPort(*listen)
	if err != nil || (h != "127.0.0.1" && h != "localhost") {
		return errors.New("the console holds the auditor key: listen on 127.0.0.1 only")
	}
	c, k, err := loadAll(*root, *config, *key)
	if err != nil {
		return err
	}
	sk, err := site.LoadKey(*statusKey)
	if err != nil {
		return err
	}
	for _, d := range []string{*reviews, *inbox} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	wd, _ := os.Getwd()
	con := &console.Console{PublicRoot: *root, Config: c, AuditorKey: k, StatusKey: sk, Reviews: *reviews, Inbox: *inbox, RepoRoot: wd, DeployHost: *host, Provider: *provider}
	srv := &http.Server{Addr: *listen, Handler: con.Handler(*listen), ReadHeaderTimeout: 10 * time.Second}
	fmt.Printf("auditor console: http://%s/\n(loopback only; the auditor key never leaves this machine)\n", *listen)
	return srv.ListenAndServe()
}

func hubDisable(args []string) error {
	fs := flag.NewFlagSet("hub-disable", flag.ExitOnError)
	root := fs.String("hub-root", "/var/lib/onym-audit/hub", "hub directory")
	slug := fs.String("slug", "", "auditor name")
	reason := fs.String("reason", "", "why (kept with the tree)")
	fs.Parse(args)
	if err := need(fs, "slug", "reason"); err != nil {
		return err
	}
	h, err := hub.New(*root, "", "")
	if err != nil {
		return err
	}
	return h.Disable(*slug, *reason)
}
