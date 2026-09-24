package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

type counting struct{ n int }

func (c *counting) Get(_ context.Context, uri string) (*Response, error) {
	c.n++
	return &Response{URI: uri, Status: 200, Header: http.Header{}, Body: make([]byte, 1024)}, nil
}

// A provider decides how many documents a run fetches; the run's budget
// bounds it, and what is left is reported as not fetched.
func TestRunBudget(t *testing.T) {
	f := &counting{}
	r := &run{ctx: context.Background(), f: f, now: time.Now(), findings: map[string][]finding{}, cache: map[string]*fetched{}}
	var skipped int
	for i := 0; i < MaxRunFetches+1000; i++ {
		if x := r.get(fmt.Sprintf("https://dest%d.example.org/manifest.json", i), 1<<20, "destination", false); errors.Is(x.err, ErrBudget) {
			skipped++
		}
	}
	if f.n != MaxRunFetches || skipped != 1000 {
		t.Errorf("fetched %d (cap %d), skipped %d", f.n, MaxRunFetches, skipped)
	}
}
