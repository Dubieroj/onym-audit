package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPublic(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "224.0.0.1"} {
		if Public(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	for _, s := range []string{"69.62.114.87", "1.1.1.1", "2606:4700:4700::1111"} {
		if !Public(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as non-public", s)
		}
	}
}

// A DNS name that resolves to loopback is refused at connect time.
func TestDialRefusesNamesThatResolveInside(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := net.Dialer{Timeout: 2 * time.Second, Control: Control}
	_, err = d.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if !errors.Is(err, ErrNonPublic) {
		t.Fatalf("dialing localhost: %v", err)
	}
}
