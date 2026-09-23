package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"onym-audit/urirule"
)

// testFetcher points the production fetcher at a local TLS server for every
// DNS name, so redirect policy is exercised on real HTTP semantics.
func testFetcher(t *testing.T, h http.Handler) Fetcher {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	tr := NewHTTPFetcher().(*httpFetcher).transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // the test server's certificate is for example.com
	return &httpFetcher{transport: tr}
}

func TestHTTPFetcher(t *testing.T) {
	var mu sync.Mutex
	var agents, cookies []string
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents = append(agents, r.UserAgent())
		cookies = append(cookies, r.Header.Get("Cookie"))
		mu.Unlock()
		w.Write([]byte("hello"))
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 100))) })
	redirect := func(path, to string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1"})
			w.Header().Set("Location", to)
			w.WriteHeader(http.StatusFound)
		})
	}
	redirect("/hop1", "/hop2")
	redirect("/hop2", "https://provider.test/hop3")
	redirect("/hop3", "/ok")
	redirect("/hop0", "/hop1")
	redirect("/to-ip", "https://127.0.0.1/ok")
	redirect("/to-int-ip", "https://2130706433/ok")
	redirect("/to-port", "https://provider.test:443/ok")
	redirect("/to-http", "http://provider.test/ok")
	redirect("/to-query", "https://provider.test/ok?x=1")
	f := testFetcher(t, mux)
	ctx := context.Background()

	t.Run("three redirects are followed, without cookies", func(t *testing.T) {
		r, err := f.Get(ctx, "https://provider.test/hop1")
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != 200 || string(r.Body) != "hello" || len(r.Redirects) != 3 {
			t.Fatalf("status %d body %q redirects %v", r.Status, r.Body, r.Redirects)
		}
		mu.Lock()
		defer mu.Unlock()
		if agents[len(agents)-1] != userAgent || cookies[len(cookies)-1] != "" {
			t.Fatalf("user agent %q, cookie %q", agents[len(agents)-1], cookies[len(cookies)-1])
		}
	})
	t.Run("a fourth redirect is refused", func(t *testing.T) {
		_, err := f.Get(ctx, "https://provider.test/hop0")
		var re *RedirectError
		if !errors.As(err, &re) || !re.SectionSeven {
			t.Fatalf("got %v", err)
		}
	})
	for _, p := range []string{"/to-ip", "/to-int-ip", "/to-port", "/to-http"} {
		t.Run("refuses "+p, func(t *testing.T) {
			_, err := f.Get(ctx, "https://provider.test"+p)
			var re *RedirectError
			if !errors.As(err, &re) || !re.SectionSeven {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("a query-bearing target is refused but not as a §7 violation", func(t *testing.T) {
		_, err := f.Get(ctx, "https://provider.test/to-query")
		var re *RedirectError
		if !errors.As(err, &re) || re.SectionSeven {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("reads at most limit+1 bytes", func(t *testing.T) {
		r, err := f.Get(WithLimit(ctx, 10), "https://provider.test/big")
		if err != nil {
			t.Fatal(err)
		}
		if !r.Truncated || len(r.Body) != 11 {
			t.Fatalf("truncated %v, %d bytes", r.Truncated, len(r.Body))
		}
	})
	t.Run("never dials a host that normalizes to an IP literal", func(t *testing.T) {
		// Full-width digits pass a syntactic IP-literal check but IDNA
		// maps them to 127.0.0.1 before dialing.
		_, err := NewHTTPFetcher().Get(ctx, "https://１２７.０.０.１/manifest.json")
		if !errors.Is(err, ErrIPDial) && !errors.Is(err, urirule.ErrURI) {
			t.Fatalf("got %v", err)
		}
		dial := NewHTTPFetcher().(*httpFetcher).transport.(*http.Transport).DialContext
		if _, err := dial(ctx, "tcp", "127.0.0.1:443"); !errors.Is(err, ErrIPDial) {
			t.Fatalf("dial guard: %v", err)
		}
	})
	t.Run("refuses non-https and IP-literal URLs outright", func(t *testing.T) {
		for _, u := range []string{"http://provider.test/ok", "https://127.0.0.1/ok", "https://provider.test:8443/ok"} {
			if _, err := f.Get(ctx, u); err == nil {
				t.Errorf("%s fetched", u)
			}
		}
	})
}
