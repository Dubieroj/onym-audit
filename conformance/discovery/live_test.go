package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLiveRun runs the suite once against the live Onym provider and saves
// the canonical report. It performs read-only HTTPS GETs and is skipped
// unless ONYM_LIVE=1.
func TestLiveRun(t *testing.T) {
	if os.Getenv("ONYM_LIVE") != "1" {
		t.Skip("set ONYM_LIVE=1 to run against https://discovery.onym.app/manifest.json")
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	rep := Run(ctx, NewHTTPFetcher(), "https://discovery.onym.app/manifest.json", now)
	b, err := rep.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "testdata", "live-run-"+now.Format("2006-01-02")+".json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("result %s, %d documents, saved %s", rep.Result, len(rep.Documents), path)
	for _, c := range rep.Checks {
		if c.Outcome != Pass {
			t.Logf("%s %s %s: %s", c.Level, c.ID, c.Outcome, c.Detail)
		}
	}
}
