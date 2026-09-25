package hub

// Linking a hosted auditor to an account it already has on the Stellar
// public network. The account's holder writes two data entries on that
// account, in one transaction signed in their own wallet:
//
//	onym-audit-auditor  the auditor's Ed25519 key (32 bytes)
//	onym-audit-proof    the auditor key's signature over LinkMessage(account) (64 bytes)
//
// Both sides consent on the network itself: the account by signing the
// transaction, the auditor key by the proof. No contract and no funds of the
// auditor's own are needed. The hub checks the entries and publishes the
// auditor's signed request as stellar-link.json, which anyone can check the
// same way against a public Horizon node.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"onym-audit/onymid"
	"onym-audit/sig"
)

const (
	LinkDataKey   = "onym-audit-auditor"
	LinkDataProof = "onym-audit-proof"
	PublicNetwork = "Public Global Stellar Network ; September 2015"
	PublicHorizon = "https://horizon.stellar.org"
	LinkFile      = "stellar-link.json"
)

// LinkMessage is what the auditor key signs for the link to account.
func LinkMessage(account string) []byte {
	return []byte("onym-audit-link-v1\n" + PublicNetwork + "\n" + account)
}

// accountData returns the data entries of a public-network account, base64
// values as Horizon serves them.
func (h *Hub) accountData(ctx context.Context, account string) (map[string]string, error) {
	if h.Horizon != nil {
		return h.Horizon(ctx, account)
	}
	resp, b, err := h.get(ctx, PublicHorizon+"/accounts/"+account, MaxFetchBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("this account does not exist on the Stellar public network")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Horizon: HTTP %d", resp.StatusCode)
	}
	var a struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	return a.Data, nil
}

// checkLink verifies the two entries on account against the auditor key.
func (h *Hub) checkLink(ctx context.Context, account string, operator sig.Key) error {
	pub, err := operator.Public()
	if err != nil {
		return err
	}
	data, err := h.accountData(ctx, account)
	if err != nil {
		return err
	}
	key, _ := base64.StdEncoding.DecodeString(data[LinkDataKey])
	proof, _ := base64.StdEncoding.DecodeString(data[LinkDataProof])
	switch {
	case len(key) == 0 || len(proof) == 0:
		return fmt.Errorf("the account has no %s and %s entries yet", LinkDataKey, LinkDataProof)
	case string(key) != string(pub):
		return fmt.Errorf("%s on the account is another auditor's key", LinkDataKey)
	case len(proof) != ed25519.SignatureSize || !ed25519.Verify(pub, LinkMessage(account), proof):
		return fmt.Errorf("%s on the account is not this auditor key's signature for this account", LinkDataProof)
	}
	return nil
}

// stellarLink publishes, or removes, the auditor's link to a public-network
// account. The request is signed by the auditor's own key.
func (h *Hub) stellarLink(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var in struct {
		Request json.RawMessage `json:"request"`
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
	var q struct {
		Action    string `json:"action"`
		Auditor   string `json:"auditor"`
		Account   string `json:"account"`
		IssuedAt  string `json:"issuedAt"`
		Signature string `json:"signature"`
	}
	if err := h.signedRequest(in.Request, &q, func() sig.Key { return m.Operator }, func() string { return q.IssuedAt }); err != nil || q.Auditor != m.ComponentID || (q.Action != "stellar-link" && q.Action != "stellar-unlink") {
		fail(w, 403, errors.New("a link is set only by a fresh request signed by this auditor's key"))
		return
	}
	path := filepath.Join(h.tenantDir(slug), LinkFile)
	if q.Action == "stellar-unlink" {
		os.Remove(path)
		reply(w, 200, map[string]bool{"unlinked": true})
		return
	}
	if _, err := onymid.ParseAccountID(q.Account); err != nil {
		fail(w, 422, errors.New("account must be a Stellar account ID (G…)"))
		return
	}
	if err := h.checkLink(r.Context(), q.Account, m.Operator); err != nil {
		fail(w, 422, err)
		return
	}
	raw, _ := canonical(in.Request)
	if err := h.write(slug, map[string][]byte{LinkFile: raw}); err != nil {
		fail(w, 507, err)
		return
	}
	reply(w, 201, map[string]string{"account": q.Account, "uri": h.base(slug) + LinkFile})
}
