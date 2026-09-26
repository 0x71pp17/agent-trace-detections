// Package monitor detects cross-call and sequence-level attacks in agent
// execution traces (OpenTelemetry GenAI spans) that a per-call reference
// monitor does not observe. Each call in these attacks is individually
// permissible; the attack lives in the correlation across calls that a
// stateless per-call decision discards.
package monitor

import "time"

// Sink classifies the effect a tool call reaches. The vocabulary is shared as a
// spec with the sibling broker project, not as a code dependency.
type Sink string

const (
	SinkShellExec  Sink = "shell.exec"
	SinkNetOut     Sink = "net.out"
	SinkFileWrite  Sink = "file.write"
	SinkSecretRead Sink = "secret.read"
	SinkBenign     Sink = "benign"
)

// Taint describes where an argument value came from.
type Taint string

const (
	TaintTrusted       Taint = "trusted"
	TaintUntrustedWeb  Taint = "untrusted.web"
	TaintTenantPrivate Taint = "tenant.private"
	TaintUnknown       Taint = "unknown"
)

// Writer identifies who wrote a durable state span.
type Writer string

const (
	WriterOperator   Writer = "operator"
	WriterUser       Writer = "user"
	WriterToolResult Writer = "tool.result"
	WriterPeerAgent  Writer = "peer.agent"
)

// Category groups a signature by which per-call-monitor residual it covers.
type Category string

const (
	CategoryCrossCall     Category = "cross-call"
	CategoryPermittedFlow Category = "permitted-flow"
	CategoryToolIntegrity Category = "tool-integrity"
)

// Event is one normalized span from an agent execution trace.
type Event struct {
	TraceID        string    `json:"trace_id"`
	SpanID         string    `json:"span_id"`
	ParentSpanID   string    `json:"parent_span_id"`
	ConversationID string    `json:"conversation_id"` // gen_ai.conversation.id
	AgentID        string    `json:"agent_id"`        // gen_ai.agent.name / .id
	Operation      string    `json:"operation"`       // gen_ai.operation.name
	Tool           string    `json:"tool"`            // gen_ai.tool.name
	CallID         string    `json:"call_id"`         // gen_ai.tool.call.id
	Sink           Sink      `json:"sink"`            // enrichment (broker vocabulary)
	ReachedTarget  string    `json:"reached_target"`  // enrichment: normalized destination touched
	ArgTaints      []Taint   `json:"arg_taints"`      // enrichment (broker vocabulary), per argument
	Writer         Writer    `json:"writer"`          // enrichment: on a state write
	InputTokens    int       `json:"input_tokens"`    // gen_ai.usage.input_tokens
	OutputTokens   int       `json:"output_tokens"`   // gen_ai.usage.output_tokens
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
}

// Detection is one flagged signature instance.
type Detection struct {
	Signature string   `json:"signature"`
	Category  Category `json:"category"`
	Spans     []string `json:"spans"`     // correlated span ids composing the finding
	Rationale string   `json:"rationale"` // the cross-call state a per-call monitor could not see
	Twin      string   `json:"twin"`      // the benign twin this signature is measured against
}
