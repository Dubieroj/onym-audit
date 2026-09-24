package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"onym-audit/audit"
)

// resign returns m with mut applied, signed again by Alice.
func resign(t *testing.T, m json.RawMessage, mut func(*audit.AuditorManifest)) json.RawMessage {
	t.Helper()
	var am audit.AuditorManifest
	if err := json.Unmarshal(m, &am); err != nil {
		t.Fatal(err)
	}
	am.Signature = ""
	mut(&am)
	raw, err := audit.SignDoc(am, key("alice"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Manifests are public: resending one must not carry other files into the
// auditor's tree, nor roll the auditor back to an older manifest. The
// contact is free text: pages show it as text and link only mailto:/https:.
func TestRegisterWritesOnlyWhatTheManifestReferences(t *testing.T) {
	h, srv := testHub(t)
	alice := key("alice")
	_, c := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": "alice"})
	statusKey := c["statusKey"].(string)
	m, docs := manifest(t, "alice", statusKey, alice)
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 201 {
		t.Fatalf("register %d %v", code, out)
	}
	att, adocs := attestation(t, "alice", "alice-att-0000000001", alice)
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": adocs}); code != 201 {
		t.Fatalf("publish %d %v", code, out)
	}
	scope := filepath.Join(h.tenantDir("alice"), "scopes", "alice-att-0000000001.md")
	before, _ := os.ReadFile(scope)

	for _, extra := range []map[string]string{
		{"scopes/alice-att-0000000001.md": "attacker text"},
		{"notes/spam.md": "spam"},
		{"reports/x.json": `{"x":1}`},
	} {
		d := map[string]string{}
		for k, v := range docs {
			d[k] = v
		}
		for k, v := range extra {
			d[k] = v
		}
		if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": d}); code != 422 {
			t.Errorf("replayed manifest carried %v: %d", extra, code)
		}
	}
	if after, _ := os.ReadFile(scope); string(after) != string(before) {
		t.Fatal("an attestation's scope was overwritten")
	}
	if _, err := os.Stat(filepath.Join(h.tenantDir("alice"), "notes", "spam.md")); err == nil {
		t.Error("an unreferenced file was written")
	}
	// Resending the current manifest with its own documents changes nothing.
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 201 {
		t.Errorf("identical re-register %d %v", code, out)
	}
	// A newer manifest is accepted; replaying the older one afterwards is not.
	newer := resign(t, m, func(a *audit.AuditorManifest) { a.ValidUntil = "2027-12-24T00:00:00Z" })
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": newer, "docs": map[string]string{}}); code != 201 {
		t.Fatalf("newer manifest %d %v", code, out)
	}
	if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": map[string]string{}}); code != 409 {
		t.Errorf("older manifest replayed: %d", code)
	}
	// Contacts: any text up to MaxContact bytes; no control characters.
	for i, c := range []struct {
		contact string
		want    int
	}{
		{"line\nbreak", 422},
		{strings.Repeat("a", MaxContact+1), 422},
		{"@alice in Telegram", 201},
		{"javascript:alert(document.domain)//a@example.org", 201},
		{"https://example.org/security", 201},
		{"mailto:security@example.org", 201},
	} {
		v := fmt.Sprintf("2028-0%d-01T00:00:00Z", i+1)
		mm := resign(t, m, func(a *audit.AuditorManifest) { a.Contact, a.ValidUntil = c.contact, v })
		if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": mm, "docs": map[string]string{}}); code != c.want {
			t.Errorf("contact %q: %d %v", c.contact, code, out)
		}
	}
}
