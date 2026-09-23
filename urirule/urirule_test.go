package urirule

import "testing"

func TestCheck(t *testing.T) {
	for _, ok := range []string{
		"https://discovery.onym.app/manifest.json",
		"https://foldy.io/audit/status.json",
		"https://example.org",
		"HTTPS://example.org/x",
		"https://xn--e1afmkfd.xn--p1ai/x",
	} {
		if err := Check(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://example.org/x",
		"https://example.org:443/x",
		"https://example.org:/x",
		"https://user@example.org/x",
		"https://example.org/x?q=1",
		"https://example.org/x#f",
		"https://192.168.1.1/x",
		"https://[::1]/x",
		"https://3232235777/x",
		"https://0xc0a80101/x",
		"https://127.1/x",
		"https://localhost/x",
		"ftp://example.org/x",
		"https://１２７.０.０.１/x",
		"https://пример.рф/x",
		"https://foo.123/x",
		"https://1.2.3.4.5/x",
		"https://foo.0x1f/x",
	} {
		if err := Check(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
