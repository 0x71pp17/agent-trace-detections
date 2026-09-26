package monitor

import (
	"strconv"
	"time"
)

// ManufacturedConsensus fires when one agent receives several inbound peer
// messages asserting the same claim within a short window, and those messages
// cluster to a single origin. It is the shape of sockpuppet corroboration: a
// receiving agent treats cross-referencing senders as independent evidence when
// they in fact share a source. A per-call decision evaluates each message alone
// and cannot cross-reference the senders.
//
// The origin is a supplied enrichment. MCP carries no peer identity, so origin
// clustering is heuristic: it also flags a single legitimate source that sends
// several messages about the same claim, which is a real false positive and the
// reason this is a layered signal rather than a verdict.
type ManufacturedConsensus struct {
	minCluster int
	window     time.Duration
	seen       map[string]map[string][]consensusMsg // claim -> origin -> messages
	fired      map[string]bool
}

type consensusMsg struct {
	span string
	at   time.Time
}

// NewManufacturedConsensus returns a constructor for the signature with the
// minimum cluster size and the time window that define a manufactured cluster.
func NewManufacturedConsensus(minCluster int, window time.Duration) func() Signature {
	return func() Signature {
		return &ManufacturedConsensus{
			minCluster: minCluster,
			window:     window,
			seen:       map[string]map[string][]consensusMsg{},
			fired:      map[string]bool{},
		}
	}
}

// Name returns the signature identifier.
func (m *ManufacturedConsensus) Name() string { return "manufactured-consensus" }

// Category returns the per-call-monitor residual this signature covers.
func (m *ManufacturedConsensus) Category() Category { return CategoryCrossCall }

// Twin returns the benign sequence with the same shape.
func (m *ManufacturedConsensus) Twin() string {
	return "genuine corroboration of a claim from independent sources (distinct origins)"
}

// Observe clusters inbound peer messages by claim and origin, and fires when a
// single origin asserts the same claim minCluster times within the window.
func (m *ManufacturedConsensus) Observe(e Event) []Detection {
	if e.Writer != WriterPeerAgent || e.PeerOrigin == "" || len(e.SurfacedValues) == 0 {
		return nil
	}
	var out []Detection
	for _, claim := range e.SurfacedValues {
		if claim == "" {
			continue
		}
		if m.seen[claim] == nil {
			m.seen[claim] = map[string][]consensusMsg{}
		}
		m.seen[claim][e.PeerOrigin] = append(m.seen[claim][e.PeerOrigin], consensusMsg{span: e.SpanID, at: e.Start})
		key := claim + "\x00" + e.PeerOrigin
		if m.fired[key] {
			continue
		}
		cutoff := e.Start.Add(-m.window)
		spans := make([]string, 0, len(m.seen[claim][e.PeerOrigin]))
		for _, msg := range m.seen[claim][e.PeerOrigin] {
			if !msg.at.Before(cutoff) {
				spans = append(spans, msg.span)
			}
		}
		if len(spans) >= m.minCluster {
			m.fired[key] = true
			out = append(out, Detection{
				Signature: m.Name(),
				Category:  m.Category(),
				Spans:     spans,
				Rationale: "claim " + claim + " was asserted by " + strconv.Itoa(len(spans)) +
					" messages from one origin within the window; a shared origin presenting as " +
					"independent corroboration, which a per-call decision cannot cross-reference",
				Twin: m.Twin(),
			})
		}
	}
	return out
}
