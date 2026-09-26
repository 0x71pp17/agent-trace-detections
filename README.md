# agent-trace-detections

[![ci](https://github.com/0x71pp17/agent-trace-detections/actions/workflows/ci.yml/badge.svg)](https://github.com/0x71pp17/agent-trace-detections/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.23-00ADD8.svg?logo=go&logoColor=white)](go.mod)

Detects cross-call and sequence-level attacks in agent execution traces. Each call in these attacks is
individually permissible; the attack lives in the correlation across calls that a per-call reference
monitor discards. This engine reconstructs that correlation from OpenTelemetry GenAI spans, applies a
fixed rule set, and reports each finding with its correlated spans and a false-positive rate measured
against a benign twin.

It is the temporal complement to a per-call monitor: it does not read content and does not replace a
content classifier. It recovers the cross-call and session state a stateless per-call decision drops by
construction.

## Status

Eight signatures are implemented and measured against their twins on a self-authored fixture corpus,
spanning all three categories (cross-call, permitted-flow, and tool-integrity). The remaining signatures in `DESIGN.md` are specified and not yet
implemented. Corpus validation currently runs on the fixture set below; running it on the
AgentDojo-derived corpora is the next step, not a completed claim.

| Signature | Category | Implemented |
|---|---|---|
| write-then-exec | cross-call | yes |
| budget-spike | cross-call (session-state) | yes |
| lookup-then-contact | cross-call | yes |
| tool-definition-change | tool-integrity | yes |
| tool-shadowing | tool-integrity | yes |
| ingest-then-deviate | permitted-flow | yes |
| manufactured-consensus | cross-call | yes |
| memory-persist-then-activate | cross-call (cross-session) | yes |
| provenance-laundering | bridge | specified |

## Measured results

Recall on attacks and false-positive rate against benign twins, measured by `cmd/replay` on the
self-authored fixture corpus in `corpus/testdata/fixtures.json`. The `corpus` test pins these numbers,
so CI fails if they drift. These are fixtures, not an independent benchmark; production false-positive
rates require production traces.

| Signature | Recall | FP rate | Attacks / Benign |
|---|---|---|---|
| budget-spike | 1.00 | 0.00 | 3 / 3 |
| ingest-then-deviate | 1.00 | 0.75 | 3 / 4 |
| lookup-then-contact | 1.00 | 0.33 | 3 / 3 |
| manufactured-consensus | 1.00 | 0.25 | 3 / 4 |
| memory-persist-then-activate | 1.00 | 0.25 | 3 / 4 |
| tool-definition-change | 1.00 | 0.00 | 3 / 3 |
| tool-shadowing | 1.00 | 0.00 | 3 / 3 |
| write-then-exec | 1.00 | 0.50 | 3 / 6 |

The write-then-exec false-positive rate is the point, not a defect. Half its benign cases are deploy
scripts that write a file and then execute it, which is structurally identical to the attack. This
signature cannot separate them, so it is a detection signal for a layered decision, not a standalone
verdict; the content and entailment its structure cannot see are what the per-call monitor's flow check
and a content classifier resolve. lookup-then-contact carries a smaller but real false-positive rate for
the same reason: it clears a contact whose target the user named, but it fires on a contact the user
requested only by description, since the address then came from the lookup rather than the request.
ingest-then-deviate carries the highest false-positive rate, 0.75 on these fixtures, and by design: it
fires whenever untrusted content was ingested and the agent then acted on a target the user did not
name, which happens legitimately whenever the user's request was broad. It is the clearest layered
signal in the set; its residual is exactly what a content classifier reads. manufactured-consensus keeps a
smaller real false-positive rate for a related reason: origin clustering cannot separate a sockpuppet
cluster from one legitimate source that sends several messages about the same claim.
memory-persist-then-activate carries the same 0.25 for the same shape of reason: a non-operator source
that legitimately caches a value and reuses it in a later conversation is indistinguishable from one
that plants a value for later activation. It is the only cross-session signature; the engine runs it
over a whole batch of events rather than per conversation. budget-spike,
tool-definition-change, and tool-shadowing separate cleanly on these fixtures because their attacks
cross a supplied baseline the benign cases stay within.

## Input

A stream or batch of OpenTelemetry GenAI spans, grouped by `gen_ai.conversation.id`, plus six
enrichment attributes the instrumentation supplies (`sink`, `reached_target`, `arg_taint`, `writer`,
`surfaced_values`, `peer_origin`; `writer` also marks the provenance of `surfaced_values`).
The enrichment vocabulary is shared as a spec with the sibling broker and boundary-map projects, not as
a code dependency. A span missing a required enrichment field is reported as `unclassified_spans`
rather than passed silently.

## Use

```bash
# score the signatures against a labeled corpus
go run ./cmd/replay -corpus corpus/testdata/fixtures.json

# run the engine over a trace and emit detections (exit 1 when any fire)
go run ./cmd/seqmon -in trace.json
```

## Example

Input trace, two individually-permitted calls:

```json
[
  {"span_id":"s1","conversation_id":"c1","operation":"execute_tool","tool":"fs_write","sink":"file.write","reached_target":"/tmp/payload.sh","start":"2026-09-26T10:00:01Z"},
  {"span_id":"s2","conversation_id":"c1","operation":"execute_tool","tool":"shell","sink":"shell.exec","reached_target":"/tmp/payload.sh","start":"2026-09-26T10:00:02Z"}
]
```

`go run ./cmd/seqmon -in trace.json` reports the composition and exits 1:

```json
{
  "detections": [
    {
      "signature": "write-then-exec",
      "category": "cross-call",
      "spans": [
        "s1",
        "s2"
      ],
      "rationale": "shell.exec target /tmp/payload.sh was produced by an earlier file.write in the same conversation; a per-call decision sees two individually-permitted calls",
      "twin": "a deploy agent writing a script then running it under a user instruction"
    }
  ],
  "unclassified_spans": 0
}
```

## Output

One `Detection` per finding: the signature, its category, the correlated span ids, the cross-call state
the per-call monitor could not see, and the benign twin the signature is measured against.

## Assurance

Each implemented signature ships with its benign twin and a false-positive rate measured against that
twin on the fixture corpus. The corpus test pins the numbers so a regression fails CI. A signature that
has not been measured this way is not shipped as covered; it stays in the specified list above.

## Scope

Structural detection only; see `DESIGN.md` for the full limitations, including content-blindness, the
Development-status instability of the GenAI conventions, the supplied-baseline dependency of
budget-spike, the reach-only slice of tool-definition-change (a full definition hash needs
description and schema on the span), deferred-egress traces that fall outside the agent's own spans, the
heuristic nature of user-request entailment, and the trusted-baseline dependency of the tool-integrity
signatures.

## License

MIT.
