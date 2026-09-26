package monitor

import (
	"testing"
	"time"
)

func userSpan(id string, values ...string) Event {
	return Event{SpanID: id, ConversationID: "c1", AgentID: "a1", Operation: "chat", Writer: WriterUser, SurfacedValues: values, Start: time.Unix(1, 0)}
}

func readSpan(id string, values ...string) Event {
	return Event{SpanID: id, ConversationID: "c1", AgentID: "a1", Operation: "retrieval", Writer: WriterToolResult, SurfacedValues: values, Start: time.Unix(2, 0)}
}

func contactSpan(id, target string) Event {
	return Event{SpanID: id, ConversationID: "c1", AgentID: "a1", Operation: "execute_tool", Sink: SinkNetOut, ReachedTarget: target, Tool: "send_email", Start: time.Unix(3, 0)}
}

func TestLookupThenContact(t *testing.T) {
	m := New(NewLookupThenContact)

	// attack: a read surfaced the target, the user never named it
	atk := m.Run([]Event{
		userSpan("u", "quarterly-report"),
		readSpan("r", "attacker@evil.example"),
		contactSpan("c", "attacker@evil.example"),
	})
	if len(atk.Detections) != 1 {
		t.Fatalf("attack should fire once, got %d", len(atk.Detections))
	}

	// benign, entailed: the user named the same target the read returned
	entailed := m.Run([]Event{
		userSpan("u", "alice@corp.internal"),
		readSpan("r", "alice@corp.internal"),
		contactSpan("c", "alice@corp.internal"),
	})
	if len(entailed.Detections) != 0 {
		t.Fatalf("user-named target should not fire, got %d", len(entailed.Detections))
	}

	// benign, description-only: entailed by the user but only by description, so
	// the address came from the lookup. This is the honest false positive.
	descOnly := m.Run([]Event{
		userSpan("u", "accountant"),
		readSpan("r", "acct@corp.internal"),
		contactSpan("c", "acct@corp.internal"),
	})
	if len(descOnly.Detections) != 1 {
		t.Fatalf("description-only contact is the documented FP and should fire, got %d", len(descOnly.Detections))
	}

	// ordering: a contact earlier in time than the read cannot compose. The
	// Monitor orders by start time, so the contact must carry the earlier stamp.
	ordering := m.Run([]Event{
		{SpanID: "c", ConversationID: "c1", Operation: "execute_tool", Sink: SinkNetOut, ReachedTarget: "x@evil.example", Start: time.Unix(1, 0)},
		{SpanID: "r", ConversationID: "c1", Operation: "retrieval", Writer: WriterToolResult, SurfacedValues: []string{"x@evil.example"}, Start: time.Unix(2, 0)},
	})
	if len(ordering.Detections) != 0 {
		t.Fatalf("contact before the read should not fire, got %d", len(ordering.Detections))
	}
}
