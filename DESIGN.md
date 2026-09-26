# agent-trace-detections: design

Detects cross-call and sequence-level attacks in agent execution traces (OpenTelemetry GenAI spans)
that a per-call reference monitor does not observe. Each individual call in these attacks is
individually permissible; the attack lives in the correlation across calls that a stateless per-call
decision discards. The engine reconstructs that correlation, applies a fixed rule set, and reports each
finding with the correlated spans and a measured false-positive rate.

## 1. Trace input schema

The engine consumes a stream (or batch) of normalized events, one per span, ordered by start time and
grouped by conversation. Fields come from three sources: the OpenTelemetry GenAI conventions, an
enrichment layer the instrumentation must supply, and state the engine derives across spans.

### 1a. Standard OTel GenAI fields (read directly)

The GenAI conventions are Development status and drift across SDKs, so the engine pins a convention
version and normalizes attribute aliases at ingest (see Limitations). Fields consumed:

| Field | Attribute | Use |
|---|---|---|
| Operation | `gen_ai.operation.name` | discriminator: chat, execute_tool, retrieval, invoke_agent, memory ops |
| Tool | `gen_ai.tool.name` | which tool/function/MCP tool ran |
| Call id | `gen_ai.tool.call.id` | correlates a call to its result |
| Agent | `gen_ai.agent.name` / `gen_ai.agent.id` | initiating agent identity |
| Conversation | `gen_ai.conversation.id` | groups a multi-turn session (the primary window key) |
| Input tokens | `gen_ai.usage.input_tokens` | budget accumulation |
| Output tokens | `gen_ai.usage.output_tokens` | budget accumulation |
| Finish reason | `gen_ai.response.finish_reasons` | behavior-shift signal (rise in tool_calls) |
| Trace / span / parent | core OTel span fields | tree reconstruction and ordering |

### 1b. Enrichment attributes (not in the standard; instrumentation must supply)

The reached-target and provenance of a call are not standardized. The engine requires them, and it
adopts the same vocabulary the broker already defines, so the two projects share a documented spec
rather than a code dependency:

| Field | Values | Source of the vocabulary |
|---|---|---|
| `sink` | shell.exec, net.out, file.write, secret.read, benign | broker Sink model |
| `reached_target` | normalized destination actually touched (host, path, object) | this repo's spec |
| `arg_taint` | trusted, untrusted.web, tenant.private, unknown (per argument) | broker Taint model |
| `writer` | operator, user, tool.result, peer.agent (on a state write) | this repo's spec |
| `surfaced_values` | normalized values a span brought into context; `writer` marks their provenance | this repo's spec |
| `peer_origin` | the origin an inbound peer message clusters to | this repo's spec |

An event missing a required enrichment field for a given signature is reported as uncovered for that
signature rather than silently passed, so coverage is honest.

### 1c. Derived state (what the per-call monitor drops, and this engine holds)

Per conversation, the engine maintains: values surfaced by read/retrieval spans (to match against later
reached targets), write-reach locations in the current turn, a per-agent rolling budget baseline,
durable-memory writes keyed by writer, and inbound peer-message clusters. This derived state is exactly
the cross-call and session context a stateless per-call decision has no access to.

### Go shape

```go
// Event is one normalized span from an agent execution trace.
type Event struct {
    TraceID, SpanID, ParentSpanID string
    ConversationID string     // gen_ai.conversation.id
    AgentID        string      // gen_ai.agent.name / .id
    Operation      string      // gen_ai.operation.name
    Tool           string      // gen_ai.tool.name
    CallID         string      // gen_ai.tool.call.id
    Sink           Sink        // enrichment (broker vocabulary)
    ReachedTarget  string      // enrichment: normalized destination touched
    ArgTaints      []Taint     // enrichment (broker vocabulary), per argument
    Writer         Writer      // enrichment: on a state write
    InputTokens    int         // gen_ai.usage.input_tokens
    OutputTokens   int         // gen_ai.usage.output_tokens
    Start, End     time.Time
}

// Detection is one flagged signature instance.
type Detection struct {
    Signature string    // e.g. "lookup-then-contact"
    Category  Category  // CrossCall | PermittedFlow | ToolIntegrity
    Spans     []string  // the correlated span ids that compose the finding
    Rationale string    // the cross-call state the per-call monitor could not see
    Twin      string    // the benign twin this signature is measured against
}
```

## 2. Position in the defense stack

Three independent layers, each with a documented residual that is the next layer's mandate. A
permitted-flow injection has to defeat all three.

| Layer | Decides on | Documented residual it passes on |
|---|---|---|
| Per-call reference monitor (broker) | one call: capability and information flow | injection on a permitted flow; no cross-call or session state |
| This engine | correlation across calls and sessions | content it cannot read; entailment it can only approximate |
| Content classifier (defense-eval) | the text of a call | its own measured miss rate |

This engine is the temporal complement to the per-call monitor. It does not read content and does not
replace the classifier; it recovers the cross-call and session correlation the per-call monitor drops
by construction.

## 3. Detection categories and rule spec

Rules are expressed over the schema fields. Window is the correlation scope. Twin is the benign
sequence with the same shape, used to measure the false-positive rate.

### Category 1: cross-call sequence (the flagship; the per-call monitor's stateless miss)

Every rule here is a correlation of individually-permissible calls.

**lookup-then-contact**
- Window: one conversation.
- Trigger: a read/retrieval span surfaces value V in its result or reached set; a later
  `execute_tool` span with `sink=net.out` has `reached_target` equal to (or containing) V, same agent,
  within N calls or T seconds.
- Derived state: values surfaced by reads, matched against later contact targets (the cross-call taint
  the per-call monitor does not propagate).
- Bound: a benign lookup then a user-requested contact has the same shape. The discriminator is user
  entailment, which this layer only approximates; measure the false-positive rate.
- Twin: the same sequence where the contact target was named in the user request.

**write-then-exec**
- Window: one turn.
- Trigger: `execute_tool sink=file.write` to location L, then `execute_tool sink=shell.exec` whose
  input references L, L written before the exec.
- Derived state: write-reach locations for the current turn.
- Bound: requires more than one tool call per turn to observe. Build and deploy agents legitimately
  write then execute.
- Twin: a deploy agent writing a script then running it under a user instruction.

**budget-spike**
- Window: one `invoke_agent` run or conversation.
- Trigger: count of chat/execute_tool spans, or summed usage tokens, exceeds the per-agent rolling
  baseline by factor K.
- Derived state: per-agent baseline (requires history).
- Bound: the baseline must be per-agent; a genuinely long task spikes too.
- Twin: a long, user-initiated task.

**memory-persist-then-activate** (cross-session)
- Window: across conversations in a batch. This is the only cross-session signature; the Monitor runs it
  over all events in a batch (one instance, global time order) rather than fresh per conversation.
- Trigger: a `memory_write` span with `writer in {tool.result, peer.agent}` persists a value
  (`surfaced_values`), then a non-benign `execute_tool` in a *different* conversation reaches that value.
- Derived state: persisted values keyed by value, carrying the writer and the conversation of the write.
- Bound: linking an action to a specific memory without content is best-effort; the strong observable
  signal is the non-operator writer. A non-operator source that legitimately caches a value and reuses it
  later reads as a false positive (0.25 on the fixture corpus).
- Twin: a value the user or operator wrote to memory, later used as intended.

**manufactured-consensus**
- Window: a tight time window (seconds) within a conversation.
- Trigger: minCluster or more inbound peer-message spans (`writer=peer.agent`) assert the same claim
  (`surfaced_values`) with the same `peer_origin`, within the window. Consumes the `peer_origin`
  enrichment.
- Derived state: inbound peer-message clusters keyed by claim and origin.
- Bound: MCP carries no peer identity, so origin clustering is heuristic; it also flags one legitimate
  source that sends several messages about the same claim (FP 0.25 on the fixture corpus).
- Twin: genuine corroboration from independent sources (distinct origins).

### Category 2: permitted-flow deviation (the per-call monitor's content miss, partially covered)

**ingest-then-deviate**
- Window: one conversation.
- Trigger: a read span carries external content (`arg_taint=untrusted.web`), then an `execute_tool` with
  a non-benign `sink` reaches a target the user did not name (`writer=user` `surfaced_values`), after the
  ingestion. First signature to consume `arg_taint`; reuses the user-named machinery of
  lookup-then-contact.
- Derived state: an ingestion flag, and the user-named target set for the conversation.
- Bound: behavioral shadow only. The engine cannot read the injection; entailment is heuristic, so this
  is the highest-false-positive signature (0.75 on the fixture corpus). Its residual is where a content
  classifier takes over.
- Twin: external content that legitimately prompts a user-requested action.

### Bridge: provenance laundering (content-origin problem via a cross-call mechanism)

**provenance-laundering** (bridge: cross-call and permitted-flow)
- Window: one conversation.
- Trigger: a value V is surfaced by a `writer=tool.result` span (an untrusted origin), then V reappears
  as the `reached_target` of a later `execute_tool` whose `arg_taints` include `trusted`. The taint
  changed from untrusted origin to trusted on reuse.
- Derived state: values emitted by tool results, matched against later trusted arguments.
- Bound: reusing a tool-result value as a later argument is common, so the discriminator is narrow (the
  taint crossing). A legitimately validated tool-result value that is genuinely trusted on reuse reads
  as a false positive (0.25 on the fixture corpus).
- Twin: legitimate reuse of a tool-result value that is genuinely trusted on reuse.

### Category 3: tool-surface integrity (not a flow miss; the monitor's Policy inputs going stale)

These do not decide a flow; they detect when the map the per-call monitor trusts no longer holds.

**tool-definition-change (rug-pull)**
- Window: baseline versus current.
- Trigger: a hash of (tool name, description, schema, reached_target) for a tool or server differs from
  a known-good baseline.
- Derived state: a trusted baseline map of tool definitions (the boundary-map spec).
- Bound: requires a trusted baseline; a first-seen tool cannot be diffed.
- Twin: a legitimate tool version update.

**tool-shadowing**
- Window: current graph.
- Trigger: a tool reaches a `reached_target` the trusted baseline attributes to a different tool (a name
  squatting on another tool's reach). Reads the same baseline as tool-definition-change, inverted to
  target -> owning tools. Complement of tool-definition-change: that flags a known tool reaching a new
  target, this flags a different name reaching a known tool's target.
- Bound: needs the trusted baseline; a first-seen target with no known owner cannot be judged.
- Twin: an intentional alias listed in the baseline as owning the target.

## 4. False-positive discipline

Every Category 1 and the bridge signature has a legitimate twin, and a sequence detector with no
measured false-positive rate is not credible. The engine reports a per-signature false-positive rate
measured against its twin, using the benign-twin attribution method the defense-eval harness already
applies. A signature ships only with its twin and its measured rate stated.

## 5. Validation corpora

A signature counts as covered only when it has fired on a replayed attack trace and been measured
against its benign twin; intended-but-unfired rules are reported as gaps. The shipped harness
(`cmd/replay`, the `corpus` package) scores signatures against a self-authored fixture corpus and
pins the
resulting recall and false-positive numbers in a test, so a regression fails CI. The fixtures are not an
independent benchmark; production false-positive rates require production traces. The next corpora are
the ones already available as sibling projects: the multi-tenant agentic RAG lab (measured attacks
across retrieval-authorization flaws) and the AgentDojo-derived corpora used by the defense-eval
harness. That integration is planned, not done.

## 6. Relationship to sibling repositories

This repository is standalone and imports none of the siblings as packages. It shares one thing with
the broker: a documented vocabulary (Sink, Taint, and the boundary-map format), published as a spec
that each project implements independently. The broker enforces per call against that vocabulary; this
engine detects across calls against it; the control-plane scanner can populate part of the boundary
map; the defense-eval harness supplies corpora and the twin-attribution method. None of these is a
build dependency.

## 7. Limitations

- Content-blind by design: structural signatures catch composition and propagation, not the semantics
  of a single action. This engine pairs with a content classifier; it does not replace one.
- The GenAI conventions are Development status and disagree across SDKs; the engine pins a version and
  normalizes aliases at ingest, and a convention change can still require a normalization update.
- Deferred egress from an agent-authored artifact (an action that fires when a human opens the artifact
  later) usually occurs outside the agent trace; the artifact-write span is observable, the egress is
  not, so this class needs a signal from a second system and is not claimed as covered by the trace
  alone.
- Entailment (whether an action followed from the user request) is heuristic; ingest-then-deviate and
  lookup-then-contact inherit that as their dominant false-positive source, which is why each ships
  with a measured rate.
- Tool-integrity signatures require a trusted baseline map; a first-seen tool or server cannot be
  diffed.
- budget-spike uses a supplied baseline (learned offline from benign traffic), not a baseline rolled at
  runtime; a wrong baseline moves the result, and the baseline must be per-agent.
- tool-definition-change diffs the reach the trace carries, not the full tool definition; detecting a
  changed description or schema requires those fields on the span as enrichment.
