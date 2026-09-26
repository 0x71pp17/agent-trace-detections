package monitor

// ToolDefinitionChange fires when a known tool reaches a target outside its
// trusted baseline reach. It detects the observable component of a rug-pull: the
// tool now reaches somewhere its baseline did not authorize. Diffing the full
// definition (description and schema) requires those fields on the span; this
// signature uses the reach the trace already carries. It needs a trusted
// baseline map (the boundary-map spec), so a first-seen tool cannot be diffed.
type ToolDefinitionChange struct {
	baseline map[string]map[string]bool
	flagged  map[string]bool
}

// NewToolDefinitionChange returns a constructor for the signature with a trusted
// baseline of allowed reached targets per tool.
func NewToolDefinitionChange(baseline map[string][]string) func() Signature {
	b := map[string]map[string]bool{}
	for tool, targets := range baseline {
		set := map[string]bool{}
		for _, t := range targets {
			set[t] = true
		}
		b[tool] = set
	}
	return func() Signature {
		return &ToolDefinitionChange{baseline: b, flagged: map[string]bool{}}
	}
}

// Name returns the signature identifier.
func (t *ToolDefinitionChange) Name() string { return "tool-definition-change" }

// Category returns the per-call-monitor residual this signature covers.
func (t *ToolDefinitionChange) Category() Category { return CategoryToolIntegrity }

// Twin returns the benign sequence with the same shape.
func (t *ToolDefinitionChange) Twin() string {
	return "a known tool reaching a target already in its authorized baseline"
}

// Observe compares a known tool's reach against its baseline and fires on a
// target the baseline does not authorize.
func (t *ToolDefinitionChange) Observe(e Event) []Detection {
	if e.Operation != "execute_tool" || e.Tool == "" || e.ReachedTarget == "" {
		return nil
	}
	allowed, known := t.baseline[e.Tool]
	if !known {
		return nil // first-seen tool: cannot diff against a baseline
	}
	key := e.Tool + "\x00" + e.ReachedTarget
	if !allowed[e.ReachedTarget] && !t.flagged[key] {
		t.flagged[key] = true
		return []Detection{{
			Signature: t.Name(),
			Category:  t.Category(),
			Spans:     []string{e.SpanID},
			Rationale: "tool " + e.Tool + " reached " + e.ReachedTarget +
				", outside its trusted baseline reach; the map a per-call decision trusts is stale",
			Twin: t.Twin(),
		}}
	}
	return nil
}
