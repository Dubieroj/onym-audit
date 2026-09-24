// Package stellar anchors an auditor's register on the Stellar test network,
// byte-compatible with the app's public/stellar.js: the anchor is a hash of
// the auditor's own acts in its status list, written as the data entry
// "onym-audit-status" of the auditor's Stellar account (the auditor key).
// Re-signing for freshness does not change it; issuing or revoking does.
package stellar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"onym-audit/audit"
	"onym-audit/canon"
)

const (
	Passphrase = "Test SDF Network ; September 2015"
	Horizon    = "https://horizon-testnet.stellar.org"
	Friendbot  = "https://friendbot.stellar.org"
	DataName   = "onym-audit-status"
)

// Digest hashes the auditor's acts in a status list: canonical JSON of
// {anchorVersion, auditor, entries sorted by attestationId}; subjects'
// responses are not the auditor's acts and are left out.
func Digest(statusRaw []byte) ([32]byte, error) {
	var st audit.StatusList
	if err := json.Unmarshal(statusRaw, &st); err != nil {
		return [32]byte{}, err
	}
	type entry struct {
		AttestationID string  `json:"attestationId"`
		Attestation   string  `json:"attestation"`
		State         string  `json:"state"`
		SupersededBy  *string `json:"supersededBy"`
		Revocation    *string `json:"revocation"`
	}
	es := []entry{}
	for _, e := range st.Entries {
		x := entry{AttestationID: e.AttestationID, Attestation: e.Attestation.Digest, State: e.State, SupersededBy: e.SupersededBy}
		if e.Revocation != nil {
			d := e.Revocation.Digest
			x.Revocation = &d
		}
		es = append(es, x)
	}
	sort.Slice(es, func(i, j int) bool { return es[i].AttestationID < es[j].AttestationID })
	raw, err := json.Marshal(map[string]any{"anchorVersion": 1, "auditor": st.Auditor, "entries": es})
	if err != nil {
		return [32]byte{}, err
	}
	obj, err := canon.Parse(raw)
	if err != nil {
		return [32]byte{}, err
	}
	c, err := canon.Encode(obj)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(c), nil
}

type xdr struct{ bytes.Buffer }

func (x *xdr) u32(n uint32) { binary.Write(&x.Buffer, binary.BigEndian, n) }
func (x *xdr) u64(n uint64) { binary.Write(&x.Buffer, binary.BigEndian, n) }
func (x *xdr) opaque(b []byte) {
	x.u32(uint32(len(b)))
	x.Write(b)
	for x.Len()%4 != 0 {
		x.WriteByte(0)
	}
}

// Transaction encodes one ManageData transaction: source account, fee 100,
// sequence number, time bounds, no memo, no extension.
func Transaction(pub ed25519.PublicKey, seq int64, maxTime uint64, name string, value []byte) []byte {
	var x xdr
	x.u32(0)
	x.Write(pub)
	x.u32(100)
	x.u64(uint64(seq))
	x.u32(1)
	x.u64(0)
	x.u64(maxTime)
	x.u32(0)
	x.u32(1)
	x.u32(0)
	x.u32(10)
	x.opaque([]byte(name))
	x.u32(1)
	x.opaque(value)
	x.u32(0)
	return x.Bytes()
}

// SignaturePayload is the hash a Stellar signature covers.
func SignaturePayload(tx []byte) [32]byte {
	var x xdr
	id := sha256.Sum256([]byte(Passphrase))
	x.Write(id[:])
	x.u32(2)
	x.Write(tx)
	return sha256.Sum256(x.Bytes())
}

func envelope(tx []byte, pub ed25519.PublicKey, sig []byte) []byte {
	var x xdr
	x.u32(2)
	x.Write(tx)
	x.u32(1)
	x.Write(pub[28:])
	x.opaque(sig)
	return x.Bytes()
}

type account struct {
	Sequence         string            `json:"sequence"`
	Data             map[string]string `json:"data"`
	LastModifiedTime string            `json:"last_modified_time"`
}

var client = &http.Client{Timeout: 30 * time.Second}

func getAccount(id string) (*account, error) {
	r, err := client.Get(Horizon + "/accounts/" + id)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode == 404 {
		return nil, nil
	}
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("stellar: HTTP %d", r.StatusCode)
	}
	var a account
	return &a, json.NewDecoder(r.Body).Decode(&a)
}

// Anchor writes digest to the account of key (funding it from the test
// network's Friendbot if it does not exist) and returns the transaction hash.
func Anchor(key ed25519.PrivateKey, accountID string, digest [32]byte) (string, error) {
	a, err := getAccount(accountID)
	if err != nil {
		return "", err
	}
	if a == nil {
		if r, err := client.Get(Friendbot + "/?addr=" + accountID); err == nil {
			r.Body.Close()
		}
		if a, err = getAccount(accountID); err != nil || a == nil {
			return "", errors.New("stellar: the test account could not be funded")
		}
	}
	seq, err := strconv.ParseInt(a.Sequence, 10, 64)
	if err != nil {
		return "", err
	}
	pub := key.Public().(ed25519.PublicKey)
	tx := Transaction(pub, seq+1, uint64(time.Now().Unix()+300), DataName, digest[:])
	h := SignaturePayload(tx)
	env := envelope(tx, pub, ed25519.Sign(key, h[:]))
	r, err := client.Post(Horizon+"/transactions", "application/x-www-form-urlencoded", strings.NewReader("tx="+url.QueryEscape(base64.StdEncoding.EncodeToString(env))))
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	var res struct {
		Hash   string `json:"hash"`
		Title  string `json:"title"`
		Extras struct {
			ResultCodes json.RawMessage `json:"result_codes"`
		} `json:"extras"`
	}
	json.Unmarshal(body, &res)
	if r.StatusCode != 200 {
		return "", fmt.Errorf("stellar: %s %s", res.Title, res.Extras.ResultCodes)
	}
	return res.Hash, nil
}

// State compares a status list with the anchor on the network: "match",
// "stale", or "none", with the time of the account's last change.
func State(accountID string, statusRaw []byte) (string, string, error) {
	a, err := getAccount(accountID)
	if err != nil {
		return "", "", err
	}
	if a == nil || a.Data[DataName] == "" {
		return "none", "", nil
	}
	v, err := base64.StdEncoding.DecodeString(a.Data[DataName])
	if err != nil {
		return "", "", err
	}
	d, err := Digest(statusRaw)
	if err != nil {
		return "", "", err
	}
	if hex.EncodeToString(v) == hex.EncodeToString(d[:]) {
		return "match", a.LastModifiedTime, nil
	}
	return "stale", a.LastModifiedTime, nil
}
