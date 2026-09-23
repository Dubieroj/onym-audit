package agent

import (
	"os"
	"testing"
)

// The prompt published with the methodology is byte-for-byte the prompt the
// engine sends; the findings report pins its digest.
func TestPublishedPromptMatches(t *testing.T) {
	b, err := os.ReadFile("../public/methodology/security-review-llm-prompt.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != SystemPrompt {
		t.Fatal("public/methodology/security-review-llm-prompt.md differs from agent/prompt.md")
	}
}
