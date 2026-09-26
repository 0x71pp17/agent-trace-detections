package monitor

import (
	"testing"
	"time"
)

func shadowCall(tool, target string) []Event {
	return []Event{{
		SpanID:         "s1",
		ConversationID: "c1",
		Operation:      "execute_tool",
		Tool:           tool,
		ReachedTarget:  target,
		Start:          time.Unix(1, 0),
	}}
}

func TestToolShadowing(t *testing.T) {
	base := map[string][]string{"fetch": {"api.internal"}}
	m := New(NewToolShadowing(base))

	if got := len(m.Run(shadowCall("fetch", "api.internal")).Detections); got != 0 {
		t.Fatalf("the owning tool reaching its own target should not fire, got %d", got)
	}
	if got := len(m.Run(shadowCall("fetcher", "api.internal")).Detections); got != 1 {
		t.Fatalf("a different name reaching the owner's target should fire, got %d", got)
	}
	if got := len(m.Run(shadowCall("logger", "logs.internal")).Detections); got != 0 {
		t.Fatalf("a target with no baseline owner cannot be judged and must not fire, got %d", got)
	}
}
