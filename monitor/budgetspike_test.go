package monitor

import (
	"testing"
	"time"
)

func calls(agent string, n int) []Event {
	evs := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		evs = append(evs, Event{
			SpanID:         agent + "-" + time.Duration(i).String(),
			ConversationID: "c-" + agent,
			AgentID:        agent,
			Operation:      "execute_tool",
			Sink:           SinkNetOut,
			ReachedTarget:  "api.example",
			Start:          time.Unix(int64(i), 0),
		})
	}
	return evs
}

func TestBudgetSpike(t *testing.T) {
	m := New(NewBudgetSpike(5, nil))

	if got := len(m.Run(calls("under", 5)).Detections); got != 0 {
		t.Fatalf("5 calls at budget 5 should not fire, got %d", got)
	}
	if got := len(m.Run(calls("over", 8)).Detections); got != 1 {
		t.Fatalf("8 calls at budget 5 should fire once, got %d", got)
	}
}

func TestBudgetSpikePerAgentOverride(t *testing.T) {
	m := New(NewBudgetSpike(5, map[string]int{"trusted": 100}))
	if got := len(m.Run(calls("trusted", 40)).Detections); got != 0 {
		t.Fatalf("agent with a raised budget should not fire, got %d", got)
	}
}
