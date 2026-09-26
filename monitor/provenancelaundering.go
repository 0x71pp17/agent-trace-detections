package monitor

// ProvenanceLaundering fires when a value a tool result surfaced (an untrusted
// origin) later reappears as a trusted argument on a call the per-call monitor
// would approve. The value's untrusted provenance is dropped across the call
// boundary: the per-call taint does not propagate, so the reused value carries a
// trusted taint the monitor accepts. It bridges the cross-call classes (the reuse
// spans two calls) and the permitted-flow classes (the laundered value rides an
// approved flow).
//
// Reusing a tool-result value as a later argument is common, so the discriminator
// is narrow: the taint changed from untrusted origin to trusted on reuse. A
// legitimately validated tool-result value that is genuinely trusted on reuse
// reads as a false positive.
type ProvenanceLaundering struct {
	toolResult map[string]string // value -> span id of the tool result that surfaced it
	fired      map[string]bool
}

// NewProvenanceLaundering constructs the signature with empty per-conversation state.
func NewProvenanceLaundering() Signature {
	return &ProvenanceLaundering{toolResult: map[string]string{}, fired: map[string]bool{}}
}

// Name returns the signature identifier.
func (p *ProvenanceLaundering) Name() string { return "provenance-laundering" }

// Category returns the per-call-monitor residual this signature covers.
func (p *ProvenanceLaundering) Category() Category { return CategoryBridge }

// Twin returns the benign sequence with the same shape.
func (p *ProvenanceLaundering) Twin() string {
	return "legitimate reuse of a tool-result value that is genuinely trusted on reuse"
}

// Observe records tool-result-surfaced values and fires when one reappears as a
// trusted argument on a later call.
func (p *ProvenanceLaundering) Observe(e Event) []Detection {
	if e.Writer == WriterToolResult {
		for _, v := range e.SurfacedValues {
			if v == "" {
				continue
			}
			if _, seen := p.toolResult[v]; !seen {
				p.toolResult[v] = e.SpanID
			}
		}
	}
	if e.Operation == "execute_tool" && e.ReachedTarget != "" && hasTaint(e.ArgTaints, TaintTrusted) {
		if src, ok := p.toolResult[e.ReachedTarget]; ok && !p.fired[e.ReachedTarget] {
			p.fired[e.ReachedTarget] = true
			return []Detection{{
				Signature: p.Name(),
				Category:  p.Category(),
				Spans:     []string{src, e.SpanID},
				Rationale: "value " + e.ReachedTarget + " was surfaced by a tool result (an untrusted " +
					"origin) and later used as a trusted argument; the per-call taint did not carry its " +
					"provenance across the call boundary",
				Twin: p.Twin(),
			}}
		}
	}
	return nil
}

func hasTaint(taints []Taint, want Taint) bool {
	for _, t := range taints {
		if t == want {
			return true
		}
	}
	return false
}
