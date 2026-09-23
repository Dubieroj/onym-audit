package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"onym-audit/urirule"
)

// Fetcher retrieves one document. Implementations must not follow
// redirects outside the Discovery-Static-Ed25519 §7 bounds and should read
// at most LimitFrom(ctx)+1 body bytes, setting Truncated when more exist.
type Fetcher interface {
	Get(ctx context.Context, uri string) (*Response, error)
}

// Response is one HTTP exchange as the suite sees it.
type Response struct {
	URI       string      // final URI after redirects
	Status    int         // HTTP status code
	Header    http.Header // response headers of the final hop
	Body      []byte      // at most limit+1 bytes
	Truncated bool        // the body was longer than the per-call limit
	Redirects []string    // each redirect target followed, in order
}

type limitKey struct{}

// DefaultLimit bounds a fetch whose context carries no limit.
const DefaultLimit = 1 << 20

// WithLimit attaches the per-call body limit (bytes) the suite derives from
// the §7 bounds table for the document being fetched.
func WithLimit(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, limitKey{}, limit)
}

// LimitFrom returns the per-call body limit, or DefaultLimit.
func LimitFrom(ctx context.Context) int64 {
	if v, ok := ctx.Value(limitKey{}).(int64); ok && v >= 0 {
		return v
	}
	return DefaultLimit
}

// §7 fetch bounds.
const (
	maxRedirects = 3
	fetchTimeout = 60 * time.Second
	userAgent    = "onym-audit-conformance/1.0"
)

// RedirectError reports a redirect the fetcher refused to follow.
// SectionSeven is true when the refusal is required by the §7 redirect
// rule itself (more than 3 hops, a non-HTTPS target, an IP-literal host, or
// an explicit port); false when the target only fails the stricter URI
// policy this auditor applies to every URI it follows (query, fragment,
// userinfo).
type RedirectError struct {
	From, To     string
	Reason       string
	SectionSeven bool
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("redirect from %q to %q refused: %s", e.From, e.To, e.Reason)
}

type httpFetcher struct {
	transport http.RoundTripper
}

// ErrIPDial reports a connection refused because the host the transport was
// about to dial is an IP literal: a host that passed the URI rules
// syntactically but normalizes to an address (IDNA maps full-width digits,
// e.g. "１２７.０.０.１", to 127.0.0.1).
var ErrIPDial = errors.New("refusing to dial an IP-literal host")

// NewHTTPFetcher returns the production fetcher: HTTPS only, at most 3
// HTTPS→HTTPS redirects whose targets pass urirule.Check (no IP literals,
// no port), a 60 s timeout, no cookie jar, no compression negotiation, a
// plain User-Agent, and bodies read to at most limit+1 bytes. It connects
// directly (no environment proxy), and as defense in depth never dials a
// host that reaches the dialer as an IP literal.
func NewHTTPFetcher() Fetcher {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DisableCompression = true
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) != nil {
			return nil, fmt.Errorf("%w: %s", ErrIPDial, host)
		}
		return d.DialContext(ctx, network, addr)
	}
	return &httpFetcher{transport: t}
}

func (f *httpFetcher) Get(ctx context.Context, uri string) (*Response, error) {
	if err := urirule.Check(uri); err != nil {
		return nil, err
	}
	var hops []string
	client := &http.Client{
		Transport: f.transport,
		Timeout:   fetchTimeout,
		Jar:       nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			from := via[len(via)-1].URL.String()
			to := redirectTarget(req)
			if len(via) > maxRedirects {
				return &RedirectError{From: from, To: to, Reason: "more than 3 redirects (§7)", SectionSeven: true}
			}
			if err := urirule.Check(to); err != nil {
				return &RedirectError{From: from, To: to, Reason: err.Error(), SectionSeven: sectionSevenRedirect(req.URL)}
			}
			hops = append(hops, to)
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		var re *RedirectError
		if errors.As(err, &re) {
			return nil, re
		}
		return nil, err
	}
	defer resp.Body.Close()
	limit := LimitFrom(ctx)
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading body of %s: %w", uri, err)
	}
	out := &Response{
		URI:       resp.Request.URL.String(),
		Status:    resp.StatusCode,
		Header:    resp.Header,
		Body:      body,
		Redirects: hops,
	}
	if int64(len(body)) > limit {
		out.Truncated = true
	}
	return out, nil
}

// redirectTarget is the raw Location value when it is absolute (so a
// redundant ":443" is judged before URL normalization), else the resolved
// URL.
func redirectTarget(req *http.Request) string {
	if req.Response != nil {
		loc := req.Response.Header.Get("Location")
		if u, err := url.Parse(loc); err == nil {
			if u.IsAbs() {
				return loc
			}
			if u.Host != "" { // scheme-relative
				return req.URL.Scheme + ":" + loc
			}
		}
	}
	return req.URL.String()
}

// sectionSevenRedirect reports whether a refused target violates the §7
// redirect rule proper: judged on scheme and authority (host and port)
// only, so a query, fragment or userinfo does not count.
func sectionSevenRedirect(u *url.URL) bool {
	if u.Scheme != "https" {
		return true
	}
	return urirule.Check("https://"+u.Host+"/") != nil
}
