package monitor

// LookupThenContact fires when an agent contacts (net.out) a target that an
// earlier read surfaced into the conversation and that the user did not name in
// the request. Both calls are individually permissible; the read-to-contact
// correlation is the finding, and a per-call decision does not carry it.
//
// The user-named versus looked-up distinction approximates user entailment: it
// clears a contact whose target the user supplied, but it cannot clear a contact
// the user requested only by description (the address came from the lookup, not
// the request). So this signature keeps a real false-positive rate against
// benign lookups and is a layered signal, not a standalone verdict.
type LookupThenContact struct {
	lookedUp  map[string]string // surfaced value -> span id of the read that surfaced it
	userNamed map[string]bool   // values the user supplied in the request
	fired     map[string]bool
}

// NewLookupThenContact constructs the signature with empty per-conversation state.
func NewLookupThenContact() Signature {
	return &LookupThenContact{
		lookedUp:  map[string]string{},
		userNamed: map[string]bool{},
		fired:     map[string]bool{},
	}
}

// Name returns the signature identifier.
func (l *LookupThenContact) Name() string { return "lookup-then-contact" }

// Category returns the per-call-monitor residual this signature covers.
func (l *LookupThenContact) Category() Category { return CategoryCrossCall }

// Twin returns the benign sequence with the same shape.
func (l *LookupThenContact) Twin() string {
	return "a lookup followed by a contact the user named in the request"
}

// Observe records the provenance of surfaced values and fires when a net.out
// call reaches a looked-up, non-user-named target.
func (l *LookupThenContact) Observe(e Event) []Detection {
	for _, v := range e.SurfacedValues {
		if v == "" {
			continue
		}
		switch e.Writer {
		case WriterUser:
			l.userNamed[v] = true
		case WriterToolResult:
			if _, seen := l.lookedUp[v]; !seen {
				l.lookedUp[v] = e.SpanID
			}
		}
	}
	if e.Operation == "execute_tool" && e.Sink == SinkNetOut && e.ReachedTarget != "" {
		readSpan, lookedUp := l.lookedUp[e.ReachedTarget]
		if lookedUp && !l.userNamed[e.ReachedTarget] && !l.fired[e.ReachedTarget] {
			l.fired[e.ReachedTarget] = true
			return []Detection{{
				Signature: l.Name(),
				Category:  l.Category(),
				Spans:     []string{readSpan, e.SpanID},
				Rationale: "net.out reached " + e.ReachedTarget +
					", a value an earlier read surfaced and the user did not name; " +
					"a per-call decision does not carry the read-to-contact link",
				Twin: l.Twin(),
			}}
		}
	}
	return nil
}
