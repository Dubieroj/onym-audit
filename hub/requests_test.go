package hub

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"onym-audit/audit"
	"onym-audit/sig"
)

func signedJSON(t *testing.T, v any, k ed25519.PrivateKey) json.RawMessage {
	raw, err := audit.SignDoc(v, k)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rfp(t *testing.T, h *Hub, id string, to *sig.Key, requester ed25519.PrivateKey) map[string]any {
	q := Request{
		RequestVersion: 1, RequestID: id, To: to, Subject: "onym:component:example", MethodologyCls: audit.SecurityReview,
		Artifact:  audit.Artifact{Kind: audit.KindSource, Source: "https://github.com/example/repo", Revision: strings.Repeat("e", 40)},
		ScopeText: "src/\n", Requester: pub(requester), IssuedAt: sig.FormatTime(h.Now()), ExpiresAt: sig.FormatTime(h.Now().Add(14 * 24 * 3600e9)),
	}
	return map[string]any{"request": signedJSON(t, q, requester)}
}

func responseOffer(t *testing.T, slug, requestID string, k ed25519.PrivateKey) json.RawMessage {
	of := audit.Offer{
		OfferVersion: 1, OfferID: ResponseOfferID(requestID), Auditor: "onym:component:" + slug, AuditorKey: pub(k),
		MethodologyClass: audit.SecurityReview, Scope: shared("methodology/security-review-manual.md", "manual"),
		Fee: audit.OfferFee{Model: "pro-bono"}, TimelineDays: 10, Disclosure: disc, ValidUntil: "2027-09-24T00:00:00Z",
	}
	return signedJSON(t, of, k)
}

func signedAsk(t *testing.T, h *Hub, k ed25519.PrivateKey, fields map[string]any) map[string]any {
	fields["issuedAt"] = sig.FormatTime(h.Now())
	return map[string]any{"request": signedJSON(t, fields, k)}
}

func TestRequestsForProposals(t *testing.T) {
	h, srv, alice := orderingHub(t)
	dave := key("dave")
	pubID, dirID := "req-aaaaaaaaaaaaaaaaaaaa", "req-bbbbbbbbbbbbbbbbbbbb"
	if code, out := call(srv, "POST", "/hub/api/requests", rfp(t, h, pubID, nil, dave)); code != 201 {
		t.Fatalf("public request %d %v", code, out)
	}
	carol := pub(key("carol"))
	if code, out := call(srv, "POST", "/hub/api/requests", rfp(t, h, dirID, &carol, dave)); code != 201 {
		t.Fatalf("directed request %d %v", code, out)
	}
	forged := rfp(t, h, "req-cccccccccccccccccccc", nil, dave)
	var fq map[string]any
	json.Unmarshal(forged["request"].(json.RawMessage), &fq)
	fq["requester"] = string(pub(key("mallory")))
	if code, _ := call(srv, "POST", "/hub/api/requests", map[string]any{"request": fq}); code != 422 {
		t.Errorf("request with a forged requester: %d", code)
	}

	// The public list shows the public request only; the directed one opens
	// to its addressee's signature.
	var list []map[string]any
	code, _ := call(srv, "GET", "/hub/api/requests", nil)
	rec := callRaw(srv, "GET", "/hub/api/requests", nil)
	json.Unmarshal(rec, &list)
	if code != 200 || len(list) != 1 || list[0]["requestId"] != pubID {
		t.Fatalf("public list %v", list)
	}
	rec = callRaw(srv, "POST", "/hub/api/requests/for", signedAsk(t, h, key("carol"), map[string]any{"action": "requests-for", "key": string(carol)}))
	json.Unmarshal(rec, &list)
	if len(list) != 1 || list[0]["requestId"] != dirID {
		t.Errorf("addressee's list %s", rec)
	}
	if code, _ := call(srv, "POST", "/hub/api/requests/for", signedAsk(t, h, key("mallory"), map[string]any{"action": "requests-for", "key": string(carol)})); code != 403 {
		t.Errorf("someone else opened carol's list: %d", code)
	}

	// Alice answers the public request; the directed one is not hers.
	if code, out := call(srv, "POST", "/hub/api/requests/"+pubID+"/responses", map[string]any{"slug": "alice", "offer": responseOffer(t, "alice", pubID, alice)}); code != 201 {
		t.Fatalf("respond %d %v", code, out)
	}
	if code, _ := call(srv, "POST", "/hub/api/requests/"+dirID+"/responses", map[string]any{"slug": "alice", "offer": responseOffer(t, "alice", dirID, alice)}); code != 422 {
		t.Errorf("answered a request addressed to another key: %d", code)
	}
	// Responses open to the requester's key only.
	if code, _ := call(srv, "POST", "/hub/api/requests/"+pubID+"/mine", signedAsk(t, h, key("mallory"), map[string]any{"action": "responses", "requestId": pubID})); code != 403 {
		t.Errorf("someone else read the responses: %d", code)
	}
	code, out := call(srv, "POST", "/hub/api/requests/"+pubID+"/mine", signedAsk(t, h, dave, map[string]any{"action": "responses", "requestId": pubID}))
	if rs, _ := out["responses"].([]any); code != 200 || len(rs) != 1 {
		t.Fatalf("responses %d %v", code, out)
	}

	// Dave orders under Alice's response; the order closes the request.
	scope := "src/\n"
	o := order(t, "ord-0000000000000041", scope, func(o *audit.AuditOrder) { o.Fee.OfferID = ResponseOfferID(pubID) })
	if code, out := call(srv, "POST", "/a/alice/orders", map[string]any{"order": o, "scopeText": scope, "contact": "mailto:dave@example.org"}); code != 202 {
		t.Fatalf("order under a response %d %v", code, out)
	}
	rec = callRaw(srv, "GET", "/hub/api/requests", nil)
	json.Unmarshal(rec, &list)
	if len(list) != 0 {
		t.Errorf("answered request still open: %s", rec)
	}
	o2 := order(t, "ord-0000000000000042", scope, func(o *audit.AuditOrder) { o.Fee.OfferID = ResponseOfferID(pubID) })
	if code, _ := call(srv, "POST", "/a/alice/orders", map[string]any{"order": o2, "scopeText": scope, "contact": "mailto:dave@example.org"}); code != 422 {
		t.Errorf("a second order under a closed request: %d", code)
	}
}
