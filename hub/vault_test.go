package hub

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestVault(t *testing.T) {
	h, srv := testHub(t)
	v := key("vault")
	data := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	put := map[string]any{"action": "put", "key": string(pub(v)), "data": data}
	if code, out := call(srv, "POST", "/hub/api/vault", signedAsk(t, h, v, put)); code != 200 {
		t.Fatalf("put %d %v", code, out)
	}
	code, out := call(srv, "POST", "/hub/api/vault", signedAsk(t, h, v, map[string]any{"action": "get", "key": string(pub(v)), "data": nil}))
	if code != 200 || out["data"] != data {
		t.Fatalf("get %d %v", code, out)
	}
	// Another key can neither read nor replace it.
	mallory := key("mallory")
	if code, _ := call(srv, "POST", "/hub/api/vault", signedAsk(t, h, mallory, map[string]any{"action": "get", "key": string(pub(v)), "data": nil})); code != 403 {
		t.Errorf("read by another key: %d", code)
	}
	if code, _ := call(srv, "POST", "/hub/api/vault", signedAsk(t, h, mallory, map[string]any{"action": "put", "key": string(pub(v)), "data": data})); code != 403 {
		t.Errorf("replaced by another key: %d", code)
	}
	// A captured request goes stale.
	old := signedAsk(t, h, v, map[string]any{"action": "get", "key": string(pub(v)), "data": nil})
	h.Now = func() time.Time { return time.Date(2026, 9, 24, 13, 0, 0, 0, time.UTC) }
	if code, _ := call(srv, "POST", "/hub/api/vault", old); code != 403 {
		t.Errorf("stale request accepted: %d", code)
	}
	big := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", MaxVaultBytes)))
	if code, _ := call(srv, "POST", "/hub/api/vault", signedAsk(t, h, v, map[string]any{"action": "put", "key": string(pub(v)), "data": big})); code != 413 {
		t.Errorf("oversized vault accepted: %d", code)
	}
}
