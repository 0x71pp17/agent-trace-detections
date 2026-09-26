package monitor

// MemoryPersistThenActivate fires when durable memory is written by a
// non-operator source (a tool result or a peer agent) and a later action in a
// different conversation reaches the persisted value. It is the cross-session
// persistence primitive: content that entered memory outside the user's or
// operator's control later drives an action, across the conversation boundary a
// per-conversation decision never sees.
//
// This is a cross-session signature; the Monitor runs it over all events in a
// batch, not per conversation. The writer of the durable-memory span is the
// strong observable signal. Linking a later action to a specific memory without
// content is best-effort, so a non-operator source that legitimately caches a
// value and reuses it later reads as a false positive.
type MemoryPersistThenActivate struct {
	persisted map[string]persistInfo // persisted value -> where and by whom
	fired     map[string]bool
}

type persistInfo struct {
	span   string
	conv   string
	writer Writer
}

// NewMemoryPersistThenActivate constructs the signature. Register it with the
// Monitor's WithCrossSession so it gets a single instance per batch.
func NewMemoryPersistThenActivate() Signature {
	return &MemoryPersistThenActivate{persisted: map[string]persistInfo{}, fired: map[string]bool{}}
}

// Name returns the signature identifier.
func (p *MemoryPersistThenActivate) Name() string { return "memory-persist-then-activate" }

// Category returns the per-call-monitor residual this signature covers.
func (p *MemoryPersistThenActivate) Category() Category { return CategoryCrossCall }

// Twin returns the benign sequence with the same shape.
func (p *MemoryPersistThenActivate) Twin() string {
	return "a value the user or operator wrote to memory, later used as intended"
}

// Observe records durable-memory writes and fires when a non-benign action in a
// different conversation reaches a value a non-operator source persisted.
func (p *MemoryPersistThenActivate) Observe(e Event) []Detection {
	if e.Operation == "memory_write" {
		for _, v := range e.SurfacedValues {
			if v == "" {
				continue
			}
			if _, seen := p.persisted[v]; !seen {
				p.persisted[v] = persistInfo{span: e.SpanID, conv: e.ConversationID, writer: e.Writer}
			}
		}
		return nil
	}
	if e.Operation == "execute_tool" && e.Sink != "" && e.Sink != SinkBenign && e.ReachedTarget != "" {
		info, ok := p.persisted[e.ReachedTarget]
		nonOperator := info.writer == WriterToolResult || info.writer == WriterPeerAgent
		if ok && nonOperator && info.conv != e.ConversationID && !p.fired[e.ReachedTarget] {
			p.fired[e.ReachedTarget] = true
			return []Detection{{
				Signature: p.Name(),
				Category:  p.Category(),
				Spans:     []string{info.span, e.SpanID},
				Rationale: "value " + e.ReachedTarget + " was written to durable memory by a " +
					string(info.writer) + " source in an earlier conversation and drove an action here; " +
					"a per-conversation decision does not carry memory across the session boundary",
				Twin: p.Twin(),
			}}
		}
	}
	return nil
}
