package monitor

import "sort"

// Signature observes ordered events within one conversation and reports
// detections. A fresh instance is created per conversation, so an
// implementation keeps its per-conversation state on the value its constructor
// returns.
type Signature interface {
	Name() string
	Category() Category
	Twin() string
	Observe(Event) []Detection
}

// Monitor runs a set of signatures over a batch of events.
type Monitor struct {
	constructors []func() Signature
	// sessionCtors are cross-session signatures: the Monitor gives each a single
	// instance per batch and feeds it every event in global time order, so it can
	// correlate across the conversation boundary a per-conversation signature never
	// sees.
	sessionCtors []func() Signature
}

// New returns a Monitor that runs the given signature constructors.
func New(constructors ...func() Signature) *Monitor {
	return &Monitor{constructors: constructors}
}

// WithCrossSession registers cross-session signatures, which the Monitor runs
// over all events in a batch (one instance, global time order) rather than fresh
// per conversation. Returns the Monitor for chaining.
func (m *Monitor) WithCrossSession(constructors ...func() Signature) *Monitor {
	m.sessionCtors = append(m.sessionCtors, constructors...)
	return m
}

// Result is the outcome of a run.
type Result struct {
	Detections []Detection `json:"detections"`
	// UnclassifiedSpans counts spans with no Sink enrichment. They are reported
	// as uncovered rather than passed silently, so coverage stays honest.
	UnclassifiedSpans int `json:"unclassified_spans"`
}

// Run groups events by conversation, orders each group by start time, and feeds
// them to a fresh set of signatures per conversation.
func (m *Monitor) Run(events []Event) Result {
	byConv := map[string][]Event{}
	order := []string{}
	res := Result{}
	for _, e := range events {
		if _, ok := byConv[e.ConversationID]; !ok {
			order = append(order, e.ConversationID)
		}
		byConv[e.ConversationID] = append(byConv[e.ConversationID], e)
		if e.Sink == "" {
			res.UnclassifiedSpans++
		}
	}
	for _, conv := range order {
		evs := byConv[conv]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Start.Before(evs[j].Start) })
		sigs := make([]Signature, 0, len(m.constructors))
		for _, c := range m.constructors {
			sigs = append(sigs, c())
		}
		for _, e := range evs {
			for _, s := range sigs {
				res.Detections = append(res.Detections, s.Observe(e)...)
			}
		}
	}
	if len(m.sessionCtors) > 0 {
		all := make([]Event, len(events))
		copy(all, events)
		sort.SliceStable(all, func(i, j int) bool { return all[i].Start.Before(all[j].Start) })
		sigs := make([]Signature, 0, len(m.sessionCtors))
		for _, c := range m.sessionCtors {
			sigs = append(sigs, c())
		}
		for _, e := range all {
			for _, s := range sigs {
				res.Detections = append(res.Detections, s.Observe(e)...)
			}
		}
	}
	return res
}
