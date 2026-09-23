package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// The schemas sent to the model carry every description whole.
func TestToolSchemas(t *testing.T) {
	s := &state{}
	tools, err := s.tools()
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools {
		b, _ := json.Marshal(tl.InputSchema())
		if strings.Contains(string(b), `"description":""`) {
			t.Errorf("%s: empty description in %s", tl.Name(), b)
		}
		if tl.Name() == "report_finding" && !strings.Contains(string(b), "and how it is reached") {
			t.Errorf("report_finding description truncated: %s", b)
		}
		if tl.Name() == "report_finding" && !strings.Contains(string(b), `"required"`) {
			t.Errorf("report_finding has no required fields: %s", b)
		}
	}
}
