package monitor

import (
	"testing"
	"time"
)

func memWrite(id, conv, value string, w Writer, tsec int) Event {
	return Event{SpanID: id, ConversationID: conv, Operation: "memory_write", Writer: w, SurfacedValues: []string{value}, Start: time.Unix(int64(tsec), 0)}
}

func activate(id, conv, target string, tsec int) Event {
	return Event{SpanID: id, ConversationID: conv, Operation: "execute_tool", Sink: SinkNetOut, ReachedTarget: target, Tool: "send_email", Start: time.Unix(int64(tsec), 0)}
}

func TestMemoryPersistThenActivate(t *testing.T) {
	m := func() *Monitor { return New().WithCrossSession(NewMemoryPersistThenActivate) }

	// attack: a tool-result write in one conversation, activated in another
	atk := m().Run([]Event{
		memWrite("w", "convA", "evil@x.example", WriterToolResult, 1),
		activate("a", "convB", "evil@x.example", 2),
	})
	if len(atk.Detections) != 1 {
		t.Fatalf("non-operator persist then cross-conversation activation should fire, got %d", len(atk.Detections))
	}

	// benign: the user wrote the value to memory
	userWrote := m().Run([]Event{
		memWrite("w", "convA", "addr@corp.internal", WriterUser, 1),
		activate("a", "convB", "addr@corp.internal", 2),
	})
	if len(userWrote.Detections) != 0 {
		t.Fatalf("user-written memory should not fire, got %d", len(userWrote.Detections))
	}

	// benign: persisted but never activated
	dormant := m().Run([]Event{
		memWrite("w", "convA", "v@x.example", WriterToolResult, 1),
		activate("a", "convB", "other@x.example", 2),
	})
	if len(dormant.Detections) != 0 {
		t.Fatalf("a persisted value that is never activated should not fire, got %d", len(dormant.Detections))
	}

	// same conversation is not cross-session
	sameConv := m().Run([]Event{
		memWrite("w", "convA", "v@x.example", WriterToolResult, 1),
		activate("a", "convA", "v@x.example", 2),
	})
	if len(sameConv.Detections) != 0 {
		t.Fatalf("activation in the same conversation is not cross-session and should not fire, got %d", len(sameConv.Detections))
	}
}
