# WADE Repository Audit Notes

## Purpose
This document defines the expectations for a holistic audit of the WADE repository.
The goal is to improve code hygiene, reduce redundancy, tighten error handling, and
simplify end-to-end processing flows without changing intended behavior.

## Scope
Review the full pipeline end-to-end, including:
- Staging and file discovery
- Classification / routing
- Queueing and worker dispatch
- Per-tool worker implementations
- Output normalization (JSON/CSV) and downstream ingestion assumptions (e.g., Splunk)

## What “Good” Looks Like
- One clear way to run commands and capture output/results
- Consistent logging (structured + file path context)
- Predictable error handling and return codes
- Minimal duplicated helpers / wrappers
- Idempotent behavior where expected
- Small, safe refactors that can be merged in steps

## Audit Checklist

### 1) End-to-end flow (front to back)
- Map the full flow from input image/file to final outputs
- Identify handoff points that are brittle or inconsistent
- Flag “hidden coupling” (implicit assumptions between components)
- Recommend simplified control flow / orchestration patterns

### 2) Redundancy and helper consolidation
Find duplicated patterns and propose consolidations:
- subprocess wrappers (run/capture/check)
- JSON writing / event envelope building
- hashing / file identity
- path construction and naming normalization
- retry/backoff, timeouts, resource checks
Deliverable: a list of duplicates with file paths and a consolidation plan.

### 3) Syntax, style, and hygiene
- Identify dead code, unused imports, unreachable branches
- Normalize naming and module layout
- Tighten typing where it improves clarity (not bureaucracy)
- Call out “clever” code that should be simpler

### 4) Error handling and reliability
- Verify errors are surfaced consistently and are actionable
- Identify swallowed exceptions and ambiguous return states
- Recommend a uniform pattern for:
  - exit codes
  - partial success reporting
  - retries/timeouts
  - corrupt/unsupported input handling

### 5) Security and secrets/logging
- Locate any plaintext secret handling (env, config, logs)
- Identify sensitive data that should never be printed
- Recommend a single safe pattern for secret usage and redaction

### 6) Testing and validation
- Identify high-value tests (unit/integration) for critical flows
- Recommend smoke tests for pipeline stages
- Suggest linters/static checks appropriate to WADE

## Deliverables
Return:
1) A prioritized checklist of improvements with file paths
2) A refactor plan split into 3–5 small PRs (scope + payoff)
3) Specific proposals for helper consolidation (what, where, why)
