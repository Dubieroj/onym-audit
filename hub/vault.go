package hub

// Vaults let one identity find its orders and requests on any device. The
// app keeps its list encrypted (AES-256-GCM, a key derived from the phrase)
// under a signing key derived from the same phrase for this purpose alone:
// the hub stores ciphertext it cannot read, under a key that appears in no
// order, request, or manifest — so it links nothing it did not already see.
// Only that key's fresh signature reads or replaces the vault.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"onym-audit/sig"
)

const (
	MaxVaultBytes = 256 << 10
	MaxVaults     = 20000
)

func (h *Hub) vaultPath(k sig.Key) string {
	return filepath.Join(h.Root, "vaults", strings.TrimPrefix(string(k), "onym:key:")+".json")
}

type vaultFile struct {
	Data      string `json:"data"`
	UpdatedAt string `json:"updatedAt"`
}

func (h *Hub) vault(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Request json.RawMessage `json:"request"`
	}
	if !h.body(w, r, 2, &in) {
		return
	}
	var q struct {
		Action    string  `json:"action"`
		Key       sig.Key `json:"key"`
		Data      *string `json:"data"`
		IssuedAt  string  `json:"issuedAt"`
		Signature string  `json:"signature"`
	}
	if err := h.signedRequest(in.Request, &q, func() sig.Key { return q.Key }, func() string { return q.IssuedAt }); err != nil || !keyRE.MatchString(string(q.Key)) {
		fail(w, 403, errors.New("a vault opens only to its own key's fresh signature"))
		return
	}
	l := h.lock("vault:" + string(q.Key))
	l.Lock()
	defer l.Unlock()
	switch q.Action {
	case "get":
		var v vaultFile
		if b, err := os.ReadFile(h.vaultPath(q.Key)); err == nil && json.Unmarshal(b, &v) == nil {
			reply(w, 200, v)
			return
		}
		reply(w, 200, map[string]any{"data": nil})
	case "put":
		if q.Data == nil || len(*q.Data) > MaxVaultBytes {
			fail(w, 413, errors.New("a vault holds at most 256 KiB"))
			return
		}
		if _, err := base64.StdEncoding.DecodeString(*q.Data); err != nil {
			fail(w, 422, errors.New("vault data is base64 ciphertext"))
			return
		}
		if _, err := os.Stat(h.vaultPath(q.Key)); err != nil {
			if n, _ := filepath.Glob(filepath.Join(h.Root, "vaults", "*.json")); len(n) >= MaxVaults {
				fail(w, 507, errors.New("the hub holds too many vaults"))
				return
			}
		}
		b, _ := json.Marshal(vaultFile{Data: *q.Data, UpdatedAt: sig.FormatTime(h.Now())})
		if err := writeFile(h.vaultPath(q.Key), b); err != nil {
			fail(w, 500, errors.New("could not store the vault"))
			return
		}
		reply(w, 200, map[string]string{"updatedAt": sig.FormatTime(h.Now())})
	default:
		fail(w, 422, errors.New("action is get or put"))
	}
}
