package monitor

import (
	"testing"
	"time"
)

func toolCall(tool, target string) []Event {
	return []Event{{
		SpanID:         "s1",
		ConversationID: "c1",
		Operation:      "execute_tool",
		Tool:           tool,
		ReachedTarget:  target,
		Start:          time.Unix(1, 0),
	}}
}

func TestToolDefinitionChange(t *testing.T) {
	base := map[string][]string{"fetch": {"api.internal"}}
	m := New(NewToolDefinitionChange(base))

	if got := len(m.Run(toolCall("fetch", "api.internal")).Detections); got != 0 {
		t.Fatalf("baseline-authorized reach should not fire, got %d", got)
	}
	if got := len(m.Run(toolCall("fetch", "evil.example")).Detections); got != 1 {
		t.Fatalf("out-of-baseline reach should fire, got %d", got)
	}
	if got := len(m.Run(toolCall("unknown-tool", "evil.example")).Detections); got != 0 {
		t.Fatalf("first-seen tool cannot be diffed and must not fire, got %d", got)
	}
}
