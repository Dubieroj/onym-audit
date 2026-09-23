// Package site lays out and maintains an auditor's published tree: the
// static files a relying client fetches byte-for-byte (profile §5).
package site

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"onym-audit/audit"
	"onym-audit/sig"
)

// Config is the auditor's unsigned input to manifest generation. Paths are
// relative to the site root; URIs are BaseURI + path.
type Config struct {
	BaseURI       string   `json:"baseUri"`
	ComponentID   string   `json:"componentId"`
	DisplayName   string   `json:"displayName"`
	Contact       string   `json:"contact"`
	ValidUntil    string   `json:"validUntil"`
	Offers        []string `json:"offers"`
	Methodologies []struct {
		Class         string   `json:"class"`
		Specification string   `json:"specification"`
		ScopesOffered []string `json:"scopesOffered"`
	} `json:"methodologies"`
}

// Fixed paths inside the site tree.
const (
	ManifestPath     = "manifest.json"
	ProfilePath      = "profile.json"
	ProfileSpecPath  = "profile/Audit-Static-Ed25519.md"
	StatusPath       = "status.json"
	IndependencePath = "policies/independence.md"
	UnsolicitedPath  = "policies/unsolicited.md"
	LiabilityPath    = "policies/liability.md"
	SeverityPath     = "severity-v1.json"
	PrivacyPath      = "privacy.md"
)

// LoadConfig reads and sanity-checks a config file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if !strings.HasSuffix(c.BaseURI, "/") {
		return nil, errors.New("baseUri must end with /")
	}
	return &c, nil
}

// Ref pins a site file by URI and exact-bytes digest.
func Ref(root string, c *Config, path string) (audit.DocRef, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return audit.DocRef{}, err
	}
	return audit.DocRef{URI: c.BaseURI + path, Digest: sig.Digest(b)}, nil
}

// LoadKey reads a 32-byte Ed25519 seed stored as hex.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a hex Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// KeyOf returns the onym:key of a private key.
func KeyOf(p ed25519.PrivateKey) sig.Key { return sig.KeyOf(p.Public().(ed25519.PublicKey)) }

// WriteAtomic replaces path's content in one rename, so a reader never sees
// a half-written signed file.
func WriteAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteSigned writes a signed document and its detached `.sig` sibling
// (standard padded base64 plus one newline, profile §3).
func WriteSigned(path string, raw []byte) error {
	var doc struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Signature == "" {
		return fmt.Errorf("%s: no signature to detach", path)
	}
	if err := WriteAtomic(path, raw); err != nil {
		return err
	}
	return WriteAtomic(path+".sig", []byte(doc.Signature+"\n"))
}

// BuildProfile signs the AuditProfile (Audit.md §5.1) naming the profile
// specification in the site tree.
func BuildProfile(root string, c *Config, publisher ed25519.PrivateKey) ([]byte, error) {
	spec, err := Ref(root, c, ProfileSpecPath)
	if err != nil {
		return nil, err
	}
	return audit.SignDoc(audit.AuditProfile{
		ProfileVersion: 1, ProfileID: audit.ProfileID, Interface: audit.Interface,
		Operations: audit.Operations, MethodologyClasses: audit.MethodologyClasses,
		AttestationSchema: audit.AttestationSchema, ResultClasses: audit.ResultClasses,
		Freshness: audit.Freshness, ErrorSchema: audit.ErrorSchema,
		Specification: spec, Publisher: KeyOf(publisher),
	}, publisher)
}

// BuildManifest signs the auditor manifest from the config and the current
// bytes of every document it pins.
func BuildManifest(root string, c *Config, auditor ed25519.PrivateKey, statusKey sig.Key) ([]byte, error) {
	refs := map[string]audit.DocRef{}
	for _, p := range []string{ProfilePath, IndependencePath, UnsolicitedPath, LiabilityPath, SeverityPath, PrivacyPath} {
		r, err := Ref(root, c, p)
		if err != nil {
			return nil, err
		}
		refs[p] = r
	}
	var ms []audit.Methodology
	for _, m := range c.Methodologies {
		r, err := Ref(root, c, m.Specification)
		if err != nil {
			return nil, err
		}
		ms = append(ms, audit.Methodology{Class: m.Class, Specification: r, ScopesOffered: m.ScopesOffered})
	}
	offers := c.Offers
	if offers == nil {
		offers = []string{}
	}
	return audit.SignDoc(audit.AuditorManifest{
		Version: 1, ComponentID: c.ComponentID, Seat: "audit", Operator: KeyOf(auditor),
		DisplayName: c.DisplayName, Contact: c.Contact,
		AuditProfileID: audit.ProfileID, AuditProfile: refs[ProfilePath], Methodologies: ms,
		IndependencePolicy: refs[IndependencePath], UnsolicitedPolicy: refs[UnsolicitedPath],
		Liability: refs[LiabilityPath], SeverityScale: refs[SeverityPath], PrivacyProfile: refs[PrivacyPath],
		StatusEndpoint: c.BaseURI + StatusPath, StatusKey: statusKey,
		Offers: offers, ValidUntil: c.ValidUntil,
	}, auditor)
}

// Collect reads every attestation, revocation, and subject response in the
// tree and verifies each against the manifest before it can enter a status
// list: the online status key must never vouch for a document the offline
// auditor key did not sign.
func Collect(root string, c *Config, m *audit.AuditorManifest) ([]audit.Published, int64, error) {
	files, _ := filepath.Glob(filepath.Join(root, "attestations", "*.json"))
	sort.Strings(files)
	var pubs []audit.Published
	var minEpoch int64
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, 0, err
		}
		a, err := audit.ParseAttestation(raw)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f, err)
		}
		if a.AuditorKey != m.Operator || a.Auditor != m.ComponentID {
			return nil, 0, fmt.Errorf("%s: not issued by this auditor", f)
		}
		if filepath.Base(f) != a.AttestationID+".json" {
			return nil, 0, fmt.Errorf("%s: file name must be <attestationId>.json", f)
		}
		p := audit.Published{Attestation: a, Ref: audit.DocRef{URI: c.BaseURI + "attestations/" + filepath.Base(f), Digest: sig.Digest(raw)}, Responses: []audit.DocRef{}}
		if rraw, err := os.ReadFile(filepath.Join(root, "revocations", a.AttestationID+".json")); err == nil {
			rv, err := audit.ParseRevocation(rraw)
			if err != nil || rv.AttestationID != a.AttestationID || rv.AuditorKey != m.Operator {
				return nil, 0, fmt.Errorf("revocation for %s is invalid: %v", a.AttestationID, err)
			}
			from, _ := sig.ParseTime(rv.EffectiveFrom)
			p.Revocation, p.RevokedFrom = &audit.DocRef{URI: c.BaseURI + "revocations/" + a.AttestationID + ".json", Digest: sig.Digest(rraw)}, from
			if rv.StatusEpoch > minEpoch {
				minEpoch = rv.StatusEpoch
			}
		}
		resps, _ := filepath.Glob(filepath.Join(root, "responses", a.AttestationID, "*.json"))
		sort.Strings(resps)
		for _, rf := range resps {
			rraw, err := os.ReadFile(rf)
			if err != nil {
				return nil, 0, err
			}
			if _, err := audit.ParseResponse(rraw, a, sig.Digest(raw)); err != nil {
				return nil, 0, fmt.Errorf("%s: %w", rf, err)
			}
			p.Responses = append(p.Responses, audit.DocRef{URI: c.BaseURI + "responses/" + a.AttestationID + "/" + filepath.Base(rf), Digest: sig.Digest(rraw)})
		}
		pubs = append(pubs, p)
	}
	return pubs, minEpoch, nil
}

// ResignStatus rebuilds status.json from the tree at now.
func ResignStatus(root string, c *Config, statusPriv ed25519.PrivateKey, now time.Time) error {
	raw, err := os.ReadFile(filepath.Join(root, ManifestPath))
	if err != nil {
		return err
	}
	m, err := audit.ParseManifest(raw, now)
	if err != nil {
		return err
	}
	pubs, minEpoch, err := Collect(root, c, m)
	if err != nil {
		return err
	}
	// Never sign below an epoch already published, even if the clock steps back.
	if prev, err := os.ReadFile(filepath.Join(root, StatusPath)); err == nil {
		var p struct {
			StatusEpoch int64 `json:"statusEpoch"`
		}
		if json.Unmarshal(prev, &p) == nil && p.StatusEpoch > minEpoch {
			minEpoch = p.StatusEpoch
		}
	}
	st, err := audit.BuildStatus(m, pubs, now, minEpoch, statusPriv)
	if err != nil {
		return err
	}
	return WriteSigned(filepath.Join(root, StatusPath), st)
}
