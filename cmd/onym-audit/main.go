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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"onym-audit/audit"
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
  revoke      -root DIR -config FILE -key FILE -id ID -reason REASON [-detail-uri U -detail FILE]
  countersign -in ORDER.json -key FILE -out FILE     accept a reviewed order (auditor role)

Online (holds only the delegated status key):
  status      -root DIR -config FILE -status-key FILE    re-sign status.json now
  serve       -root DIR -config FILE -status-key FILE -inbox DIR [-listen ADDR]

Anyone:
  verify      -manifest URI|FILE -attestation URI|FILE -target URI [-status URI|FILE] [-credit onym:key:..]
  respond     -attestation URI|FILE -key FILE -id ID -text TEXT -out FILE   (subject's signed reply)
  sign-order  -in ORDER.json -role subject|sponsor -key FILE -out FILE
  fixtures    -dir DIR                               run the published fixture cases
`

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"keygen": keygen, "publish": publish, "attest": attest, "revoke": revoke,
		"countersign": countersign, "status": status, "serve": serve, "verify": verify,
		"respond": respond, "sign-order": signOrder, "fixtures": fixtures,
		"conformance-discovery": conformanceDiscovery,
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
	pinned := fs.String("target-document", "", "URI or file of the further served document you are about to use (e.g. the current catalog snapshot), when the attestation pins one")
	statusRef := fs.String("status", "", "status list URI or file (default: the manifest's statusEndpoint)")
	credit := fs.String("credit", "", "comma-separated auditor keys you credit")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
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
	tb, err := fetch(*target, 256<<10)
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
	for _, k := range strings.Split(*credit, ",") {
		if k != "" {
			in.Trust.Credited[sig.Key(strings.TrimSpace(k))] = true
		}
	}
	m, err := audit.ParseManifest(in.Manifest, now)
	if err != nil {
		return err
	}
	sref := *statusRef
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
	d := audit.Verify(in)
	if *asJSON {
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

// conformanceDiscovery is wired in once the suite package lands.
var conformanceDiscovery = func(args []string) error {
	return errors.New("the Discovery conformance suite is not built into this binary")
}
