package monitor

import (
	"sort"
	"strings"
)

// ToolShadowing fires when a tool reaches a target that the trusted baseline
// attributes to a different tool. It detects a name squatting on another tool's
// established reach: a shadow or lookalike whose name does not own the target it
// resolves to. It reads the same trusted baseline as tool-definition-change
// (tool -> its authorized targets), inverted to target -> owning tools, so a
// first-seen target with no known owner cannot be judged and does not fire.
//
// This is the complement of tool-definition-change: that signature catches a
// known tool reaching a new target; this one catches a different name reaching a
// known tool's target.
type ToolShadowing struct {
	owners  map[string]map[string]bool // reached_target -> set of tools that own it
	flagged map[string]bool
}

// NewToolShadowing returns a constructor for the signature with a trusted
// baseline of authorized reached targets per tool.
func NewToolShadowing(baseline map[string][]string) func() Signature {
	owners := map[string]map[string]bool{}
	for tool, targets := range baseline {
		for _, target := range targets {
			if owners[target] == nil {
				owners[target] = map[string]bool{}
			}
			owners[target][tool] = true
		}
	}
	return func() Signature {
		return &ToolShadowing{owners: owners, flagged: map[string]bool{}}
	}
}

// Name returns the signature identifier.
func (s *ToolShadowing) Name() string { return "tool-shadowing" }

// Category returns the per-call-monitor residual this signature covers.
func (s *ToolShadowing) Category() Category { return CategoryToolIntegrity }

// Twin returns the benign sequence with the same shape.
func (s *ToolShadowing) Twin() string {
	return "an intentional alias listed in the baseline as owning the target"
}

// Observe fires when a tool reaches a target owned by a different tool.
func (s *ToolShadowing) Observe(e Event) []Detection {
	if e.Operation != "execute_tool" || e.Tool == "" || e.ReachedTarget == "" {
		return nil
	}
	owners, known := s.owners[e.ReachedTarget]
	if !known || owners[e.Tool] {
		return nil // no baseline owner, or this tool legitimately owns the target
	}
	key := e.Tool + "\x00" + e.ReachedTarget
	if s.flagged[key] {
		return nil
	}
	s.flagged[key] = true
	names := make([]string, 0, len(owners))
	for o := range owners {
		names = append(names, o)
	}
	sort.Strings(names)
	return []Detection{{
		Signature: s.Name(),
		Category:  s.Category(),
		Spans:     []string{e.SpanID},
		Rationale: "tool " + e.Tool + " reached " + e.ReachedTarget +
			", a target the baseline attributes to " + strings.Join(names, ", ") +
			"; a different name resolving to another tool's reach is a shadow",
		Twin: s.Twin(),
	}}
}
