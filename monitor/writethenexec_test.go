package monitor

import (
	"testing"
	"time"
)

func ev(id string, sink Sink, target string, t int) Event {
	return Event{
		SpanID:         id,
		ConversationID: "c1",
		AgentID:        "a1",
		Operation:      "execute_tool",
		Sink:           sink,
		ReachedTarget:  target,
		Start:          time.Unix(int64(t), 0),
	}
}

func TestWriteThenExec(t *testing.T) {
	cases := []struct {
		name    string
		events  []Event
		wantHit bool
	}{
		{
			name: "attack: write payload then exec it",
			events: []Event{
				ev("s1", SinkFileWrite, "/tmp/payload.sh", 1),
				ev("s2", SinkShellExec, "/tmp/payload.sh", 2),
			},
			wantHit: true,
		},
		{
			name: "benign twin: exec a binary not written this conversation",
			events: []Event{
				ev("s1", SinkFileWrite, "/tmp/report.txt", 1),
				ev("s2", SinkShellExec, "/usr/bin/deploy", 2),
			},
			wantHit: false,
		},
		{
			name: "ordering: exec before the write does not compose",
			events: []Event{
				ev("s1", SinkShellExec, "/tmp/payload.sh", 1),
				ev("s2", SinkFileWrite, "/tmp/payload.sh", 2),
			},
			wantHit: false,
		},
		{
			name: "unclassified: a missing sink is not a hit",
			events: []Event{
				ev("s1", "", "/tmp/payload.sh", 1),
				ev("s2", SinkShellExec, "/tmp/payload.sh", 2),
			},
			wantHit: false,
		},
		{
			name: "cross-conversation: a write in another conversation does not compose",
			events: []Event{
				{SpanID: "s1", ConversationID: "cA", Sink: SinkFileWrite, ReachedTarget: "/tmp/payload.sh", Start: time.Unix(1, 0)},
				{SpanID: "s2", ConversationID: "cB", Sink: SinkShellExec, ReachedTarget: "/tmp/payload.sh", Start: time.Unix(2, 0)},
			},
			wantHit: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := New(NewWriteThenExec).Run(tc.events)
			got := len(res.Detections) > 0
			if got != tc.wantHit {
				t.Fatalf("want hit=%v, got %d detections", tc.wantHit, len(res.Detections))
			}
		})
	}
}

func TestUnclassifiedCounted(t *testing.T) {
	res := New(NewWriteThenExec).Run([]Event{ev("s1", "", "/x", 1)})
	if res.UnclassifiedSpans != 1 {
		t.Fatalf("want 1 unclassified span, got %d", res.UnclassifiedSpans)
	}
}

func TestDetectionCarriesSpansAndTwin(t *testing.T) {
	res := New(NewWriteThenExec).Run([]Event{
		ev("w", SinkFileWrite, "/tmp/x.sh", 1),
		ev("x", SinkShellExec, "/tmp/x.sh", 2),
	})
	if len(res.Detections) != 1 {
		t.Fatalf("want 1 detection, got %d", len(res.Detections))
	}
	d := res.Detections[0]
	if len(d.Spans) != 2 || d.Spans[0] != "w" || d.Spans[1] != "x" {
		t.Fatalf("want correlated spans [w x], got %v", d.Spans)
	}
	if d.Twin == "" {
		t.Fatalf("detection must carry its benign twin")
	}
	if d.Category != CategoryCrossCall {
		t.Fatalf("want cross-call category, got %s", d.Category)
	}
}
