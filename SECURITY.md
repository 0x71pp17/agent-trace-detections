# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private vulnerability
reporting on this repository (Security tab, "Report a vulnerability"). Please do
not open a public issue for a security report.

Include a description of the issue, the affected file or signature, and a minimal
trace or test case that reproduces it. A runnable reproduction is the fastest path
to a fix, and this project's test layout makes one straightforward to attach.

## Scope

This project analyzes trace data and produces detections. Reports of interest
include: a signature that can be made to miss an attack it claims to cover, a
signature whose false-positive behaviour differs from its documented bound, an
input that crashes or hangs the engine, and any handling of a supplied corpus or
trace file that reaches beyond reading and scoring it.

Out of scope: the known, documented limitations in `DESIGN.md` (content-blindness,
the entailment approximation, the supplied-baseline dependency, and the
reach-only slice of tool-definition-change). Those are stated bounds, not defects.

## Supported versions

The `main` branch is the supported version.
