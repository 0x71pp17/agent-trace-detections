package monitor

// WriteThenExec detects a file.write to a location followed by a shell.exec
// whose target is that same location, within one conversation. Both calls are
// individually permissible, so a per-call decision admits each one; the
// composition is the finding. This signature carries no entailment heuristic,
// which is why its only false-positive source is legitimate build and deploy
// behaviour, measured against its benign twin.
type WriteThenExec struct {
	written map[string]string // reached_target -> span id of the write
}

// NewWriteThenExec constructs the signature with empty per-conversation state.
func NewWriteThenExec() Signature {
	return &WriteThenExec{written: map[string]string{}}
}

// Name returns the signature identifier.
func (w *WriteThenExec) Name() string { return "write-then-exec" }

// Category returns the per-call-monitor residual this signature covers.
func (w *WriteThenExec) Category() Category { return CategoryCrossCall }

// Twin returns the benign sequence with the same shape, used to measure the
// false-positive rate.
func (w *WriteThenExec) Twin() string {
	return "a deploy agent writing a script then running it under a user instruction"
}

// Observe records file.write targets and fires when a shell.exec reaches a
// target an earlier file.write in the same conversation produced.
func (w *WriteThenExec) Observe(e Event) []Detection {
	switch e.Sink {
	case SinkFileWrite:
		if e.ReachedTarget != "" {
			w.written[e.ReachedTarget] = e.SpanID
		}
	case SinkShellExec:
		if e.ReachedTarget == "" {
			return nil
		}
		if writeSpan, ok := w.written[e.ReachedTarget]; ok {
			return []Detection{{
				Signature: w.Name(),
				Category:  w.Category(),
				Spans:     []string{writeSpan, e.SpanID},
				Rationale: "shell.exec target " + e.ReachedTarget +
					" was produced by an earlier file.write in the same conversation; " +
					"a per-call decision sees two individually-permitted calls",
				Twin: w.Twin(),
			}}
		}
	}
	return nil
}
