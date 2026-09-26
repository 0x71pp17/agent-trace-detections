package monitor

// BudgetSpike fires when an agent makes more tool or model calls in one
// conversation than its baseline allows. No single call is anomalous; the
// accumulation is, and a per-call decision holds no session count. The baseline
// is supplied (learned offline from benign traffic), not rolled at runtime, so a
// wrong baseline moves the result.
type BudgetSpike struct {
	max      int
	perAgent map[string]int
	counts   map[string]int
	fired    map[string]bool
}

// NewBudgetSpike returns a constructor for the signature with a default
// per-conversation call budget and optional per-agent overrides.
func NewBudgetSpike(max int, perAgent map[string]int) func() Signature {
	return func() Signature {
		return &BudgetSpike{
			max:      max,
			perAgent: perAgent,
			counts:   map[string]int{},
			fired:    map[string]bool{},
		}
	}
}

// Name returns the signature identifier.
func (b *BudgetSpike) Name() string { return "budget-spike" }

// Category returns the per-call-monitor residual this signature covers.
func (b *BudgetSpike) Category() Category { return CategoryCrossCall }

// Twin returns the benign sequence with the same shape.
func (b *BudgetSpike) Twin() string {
	return "a long, user-initiated task that makes many legitimate calls"
}

// Observe counts tool and model calls per agent and fires once when the count
// first exceeds the agent's budget.
func (b *BudgetSpike) Observe(e Event) []Detection {
	if e.Operation != "execute_tool" && e.Operation != "chat" {
		return nil
	}
	b.counts[e.AgentID]++
	limit := b.max
	if v, ok := b.perAgent[e.AgentID]; ok {
		limit = v
	}
	if b.counts[e.AgentID] > limit && !b.fired[e.AgentID] {
		b.fired[e.AgentID] = true
		return []Detection{{
			Signature: b.Name(),
			Category:  b.Category(),
			Spans:     []string{e.SpanID},
			Rationale: "agent call count in this conversation exceeded its baseline; " +
				"a per-call decision holds no session count",
			Twin: b.Twin(),
		}}
	}
	return nil
}
