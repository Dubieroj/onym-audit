package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"onym-audit/audit"
	"onym-audit/onymid"
	"onym-audit/sig"
)

func linkReq(t *testing.T, k ed25519.PrivateKey, action, account string, at time.Time) map[string]any {
	req := struct {
		Action   string `json:"action"`
		Auditor  string `json:"auditor"`
		Account  string `json:"account"`
		IssuedAt string `json:"issuedAt"`
	}{action, "onym:component:alice", account, sig.FormatTime(at)}
	raw, err := audit.SignDoc(req, k)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"request": json.RawMessage(raw)}
}

// The link is published only when the account carries the auditor's key and
// the auditor key's proof for that very account.
func TestStellarLink(t *testing.T) {
	h, srv, alice := orderingHub(t)
	holder := key("holder")
	account := onymid.AccountID(holder.Public().(ed25519.PublicKey))
	other := onymid.AccountID(key("other").Public().(ed25519.PublicKey))
	entries := map[string]map[string]string{}
	h.Horizon = func(_ context.Context, a string) (map[string]string, error) {
		if d, ok := entries[a]; ok {
			return d, nil
		}
		return nil, errors.New("this account does not exist on the Stellar public network")
	}
	b64 := base64.StdEncoding.EncodeToString
	pub := alice.Public().(ed25519.PublicKey)
	path := "/hub/api/a/alice/stellar-link"
	file := filepath.Join(h.tenantDir("alice"), LinkFile)

	for name, c := range map[string]struct {
		data map[string]string
		want int
	}{
		"no account":                {nil, 422},
		"no entries":                {map[string]string{}, 422},
		"another auditor's key":     {map[string]string{LinkDataKey: b64(key("mallory").Public().(ed25519.PublicKey)), LinkDataProof: b64(ed25519.Sign(alice, LinkMessage(account)))}, 422},
		"proof for another account": {map[string]string{LinkDataKey: b64(pub), LinkDataProof: b64(ed25519.Sign(alice, LinkMessage(other)))}, 422},
	} {
		delete(entries, account)
		if c.data != nil {
			entries[account] = c.data
		}
		if code, out := call(srv, "POST", path, linkReq(t, alice, "stellar-link", account, h.Now())); code != c.want {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a failed link was published")
	}

	entries[account] = map[string]string{LinkDataKey: b64(pub), LinkDataProof: b64(ed25519.Sign(alice, LinkMessage(account)))}
	if code, _ := call(srv, "POST", path, linkReq(t, key("mallory"), "stellar-link", account, h.Now())); code != 403 {
		t.Errorf("a link set by another key: %d", code)
	}
	if code, _ := call(srv, "POST", path, linkReq(t, alice, "stellar-link", account, h.Now().Add(-time.Hour))); code != 403 {
		t.Errorf("a stale link request accepted: %d", code)
	}
	if code, out := call(srv, "POST", path, linkReq(t, alice, "stellar-link", account, h.Now())); code != 201 || out["account"] != account {
		t.Fatalf("link: %d %v", code, out)
	}
	// The published file is the auditor's signed request, served in its tree.
	raw, err := os.ReadFile(file)
	if err != nil || sig.Verify(raw, "signature", sig.KeyOf(pub)) != nil {
		t.Fatalf("stellar-link.json is not the auditor's signed request: %v", err)
	}
	if code, _ := call(srv, "GET", "/a/alice/"+LinkFile, nil); code != 200 {
		t.Errorf("stellar-link.json not served: %d", code)
	}
	if code, _ := call(srv, "POST", path, linkReq(t, alice, "stellar-unlink", "", h.Now())); code != 200 {
		t.Errorf("unlink: %d", code)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("unlink left the file")
	}
}
