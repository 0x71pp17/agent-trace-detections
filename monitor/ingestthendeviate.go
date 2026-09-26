package monitor

// IngestThenDeviate fires when a conversation ingests untrusted external content
// (a read carrying an untrusted.web taint) and the agent then takes a non-benign
// action whose target the user did not name. It is the behavioral shadow of an
// indirect prompt injection: the engine cannot read the injected instruction, so
// it keys on the deviation (an action not entailed by the user request) after
// untrusted content entered the context.
//
// Entailment is approximated by the user-named target set, the same machinery as
// lookup-then-contact, so this signature carries the highest false-positive rate
// of the set. An agent legitimately acts on targets the user did not literally
// name whenever the request was broad. It is a layered signal, not a verdict; its
// residual is where a content classifier reads the injection itself.
type IngestThenDeviate struct {
	ingested  bool
	userNamed map[string]bool
	fired     map[string]bool
}

// NewIngestThenDeviate constructs the signature with empty per-conversation state.
func NewIngestThenDeviate() Signature {
	return &IngestThenDeviate{userNamed: map[string]bool{}, fired: map[string]bool{}}
}

// Name returns the signature identifier.
func (d *IngestThenDeviate) Name() string { return "ingest-then-deviate" }

// Category returns the per-call-monitor residual this signature covers.
func (d *IngestThenDeviate) Category() Category { return CategoryPermittedFlow }

// Twin returns the benign sequence with the same shape.
func (d *IngestThenDeviate) Twin() string {
	return "external content that legitimately prompts a user-requested action"
}

// Observe records user-named targets and untrusted ingestion, and fires on a
// non-benign action to a non-user-named target once untrusted content is in
// context.
func (d *IngestThenDeviate) Observe(e Event) []Detection {
	if e.Writer == WriterUser {
		for _, v := range e.SurfacedValues {
			if v != "" {
				d.userNamed[v] = true
			}
		}
	}
	for _, taint := range e.ArgTaints {
		if taint == TaintUntrustedWeb {
			d.ingested = true
		}
	}
	if d.ingested && e.Operation == "execute_tool" && e.Sink != "" && e.Sink != SinkBenign && e.ReachedTarget != "" {
		if !d.userNamed[e.ReachedTarget] && !d.fired[e.ReachedTarget] {
			d.fired[e.ReachedTarget] = true
			return []Detection{{
				Signature: d.Name(),
				Category:  d.Category(),
				Spans:     []string{e.SpanID},
				Rationale: "after untrusted external content was ingested, the agent reached " +
					e.ReachedTarget + ", a target the user did not name; a deviation the per-call " +
					"monitor's flow check and a content classifier resolve",
				Twin: d.Twin(),
			}}
		}
	}
	return nil
}
