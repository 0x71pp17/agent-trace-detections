package monitor

import (
	"testing"
	"time"
)

func peerMsg(id, claim, origin string, tsec int) Event {
	return Event{
		SpanID:         id,
		ConversationID: "c1",
		AgentID:        "a1",
		Operation:      "receive_message",
		Writer:         WriterPeerAgent,
		SurfacedValues: []string{claim},
		PeerOrigin:     origin,
		Start:          time.Unix(int64(tsec), 0),
	}
}

func TestManufacturedConsensus(t *testing.T) {
	mk := func() *Monitor { return New(NewManufacturedConsensus(3, 10*time.Second)) }

	// attack: three messages, one claim, one origin, inside the window
	atk := mk().Run([]Event{
		peerMsg("m1", "shared-claim", "botnet", 1),
		peerMsg("m2", "shared-claim", "botnet", 2),
		peerMsg("m3", "shared-claim", "botnet", 3),
	})
	if len(atk.Detections) != 1 {
		t.Fatalf("three from one origin should fire, got %d", len(atk.Detections))
	}
	if len(atk.Detections[0].Spans) != 3 {
		t.Fatalf("detection should carry the three cluster spans, got %v", atk.Detections[0].Spans)
	}

	// benign: three messages, one claim, three distinct origins
	distinct := mk().Run([]Event{
		peerMsg("m1", "shared-claim", "src-a", 1),
		peerMsg("m2", "shared-claim", "src-b", 2),
		peerMsg("m3", "shared-claim", "src-c", 3),
	})
	if len(distinct.Detections) != 0 {
		t.Fatalf("distinct origins should not fire, got %d", len(distinct.Detections))
	}

	// below threshold: two from one origin
	two := mk().Run([]Event{
		peerMsg("m1", "shared-claim", "botnet", 1),
		peerMsg("m2", "shared-claim", "botnet", 2),
	})
	if len(two.Detections) != 0 {
		t.Fatalf("two messages should not reach the cluster size, got %d", len(two.Detections))
	}

	// window: three from one origin but spread beyond the window
	spread := mk().Run([]Event{
		peerMsg("m1", "shared-claim", "botnet", 1),
		peerMsg("m2", "shared-claim", "botnet", 100),
		peerMsg("m3", "shared-claim", "botnet", 200),
	})
	if len(spread.Detections) != 0 {
		t.Fatalf("messages spread beyond the window should not cluster, got %d", len(spread.Detections))
	}
}
