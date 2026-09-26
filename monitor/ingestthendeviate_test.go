package monitor

import (
	"testing"
	"time"
)

func req(id string, values ...string) Event {
	return Event{SpanID: id, ConversationID: "c1", AgentID: "a1", Operation: "chat", Writer: WriterUser, SurfacedValues: values, Start: time.Unix(1, 0)}
}

func ingest(id string) Event {
	return Event{SpanID: id, ConversationID: "c1", AgentID: "a1", Operation: "retrieval", ArgTaints: []Taint{TaintUntrustedWeb}, ReachedTarget: "webpage", Start: time.Unix(2, 0)}
}

func act(id, target string) Event {
	return Event{SpanID: id, ConversationID: "c1", AgentID: "a1", Operation: "execute_tool", Sink: SinkNetOut, ReachedTarget: target, Tool: "send_email", Start: time.Unix(3, 0)}
}

func TestIngestThenDeviate(t *testing.T) {
	m := New(NewIngestThenDeviate)

	// attack: untrusted content ingested, then an action to a target the user never named
	if got := len(m.Run([]Event{req("u", "summarize-inbox"), ingest("i"), act("a", "attacker@evil.example")}).Detections); got != 1 {
		t.Fatalf("ingest then non-user-named action should fire, got %d", got)
	}

	// benign, entailed: the user named the action's target
	if got := len(m.Run([]Event{req("u", "vendor@corp.internal"), ingest("i"), act("a", "vendor@corp.internal")}).Detections); got != 0 {
		t.Fatalf("action to a user-named target should not fire, got %d", got)
	}

	// benign, broad authorization: the honest false positive; the user authorized
	// broadly but named no target, so the action reads as a deviation.
	if got := len(m.Run([]Event{req("u", "research-and-act"), ingest("i"), act("a", "partner@corp.internal")}).Detections); got != 1 {
		t.Fatalf("broad-authorization action is the documented FP and should fire, got %d", got)
	}

	// no ingestion: a non-user-named action without prior untrusted content
	if got := len(m.Run([]Event{req("u", "task"), act("a", "somewhere@corp.internal")}).Detections); got != 0 {
		t.Fatalf("action without prior ingestion should not fire, got %d", got)
	}

	// ordering: the action must follow the ingestion in time
	ordering := m.Run([]Event{
		{SpanID: "a", ConversationID: "c1", Operation: "execute_tool", Sink: SinkNetOut, ReachedTarget: "x@evil.example", Start: time.Unix(1, 0)},
		{SpanID: "i", ConversationID: "c1", Operation: "retrieval", ArgTaints: []Taint{TaintUntrustedWeb}, Start: time.Unix(2, 0)},
	})
	if len(ordering.Detections) != 0 {
		t.Fatalf("action before ingestion should not fire, got %d", len(ordering.Detections))
	}
}
