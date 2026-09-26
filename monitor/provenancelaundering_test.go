package monitor

import (
	"testing"
	"time"
)

func emit(id, value string) Event {
	return Event{SpanID: id, ConversationID: "c1", Operation: "retrieval", Writer: WriterToolResult, SurfacedValues: []string{value}, Start: time.Unix(1, 0)}
}

func reuse(id, target string, taints ...Taint) Event {
	return Event{SpanID: id, ConversationID: "c1", Operation: "execute_tool", Sink: SinkFileWrite, ReachedTarget: target, Tool: "write_config", ArgTaints: taints, Start: time.Unix(2, 0)}
}

func TestProvenanceLaundering(t *testing.T) {
	m := New(NewProvenanceLaundering)

	// attack: a tool-result value reused as a trusted argument
	if got := len(m.Run([]Event{emit("e", "evil@x.example"), reuse("r", "evil@x.example", TaintTrusted)}).Detections); got != 1 {
		t.Fatalf("a tool-result value reused as trusted should fire, got %d", got)
	}

	// benign: the value is reused but its untrusted taint is preserved
	if got := len(m.Run([]Event{emit("e", "v@x.example"), reuse("r", "v@x.example", TaintUntrustedWeb)}).Detections); got != 0 {
		t.Fatalf("reuse with preserved untrusted taint should not fire, got %d", got)
	}

	// benign: never reused
	if got := len(m.Run([]Event{emit("e", "v@x.example")}).Detections); got != 0 {
		t.Fatalf("a value never reused should not fire, got %d", got)
	}

	// a value not from a tool result, used as trusted, is not laundering
	if got := len(m.Run([]Event{reuse("r", "clean@x.example", TaintTrusted)}).Detections); got != 0 {
		t.Fatalf("a value with no tool-result origin should not fire, got %d", got)
	}
}
