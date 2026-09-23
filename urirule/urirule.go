// Package urirule enforces the URI rules of Discovery-Static-Ed25519 §7,
// which this audit profile adopts for every URI it publishes or follows.
package urirule

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var ErrURI = errors.New("URI rule violation")

// numericHost catches IPv4 forms net.ParseIP misses but resolvers accept:
// integer (3232235777), hex (0xc0a80101), octal, and shortened dotted forms.
var numericHost = regexp.MustCompile(`^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}$`)

// Check reports whether raw is an acceptable URI: https only, a DNS host
// (no IP literal in any form), no userinfo, query, fragment, or port — the
// port check runs on the raw string, because URL libraries normalize a
// redundant ":443" away before a parsed-port check is reachable.
func Check(raw string) error {
	const scheme = "https://"
	if !strings.HasPrefix(raw, scheme) {
		return fmt.Errorf("%w: %q is not https", ErrURI, raw)
	}
	rest := raw[len(scheme):]
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	if strings.Contains(authority, "@") {
		return fmt.Errorf("%w: %q carries userinfo", ErrURI, raw)
	}
	if strings.HasPrefix(authority, "[") {
		return fmt.Errorf("%w: %q has an IP literal host", ErrURI, raw)
	}
	if strings.Contains(authority, ":") {
		return fmt.Errorf("%w: %q has an explicit port", ErrURI, raw)
	}
	if strings.ContainsAny(rest, "?#") {
		return fmt.Errorf("%w: %q has a query or fragment", ErrURI, raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: %q does not parse", ErrURI, raw)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if net.ParseIP(host) != nil || numericHost.MatchString(host) {
		return fmt.Errorf("%w: %q has an IP literal host", ErrURI, raw)
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf("%w: %q is not a DNS name", ErrURI, raw)
	}
	return nil
}
