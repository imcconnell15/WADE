# WADE Continuity & Pipeline Integrity Audit Notes

## Purpose

This document defines the expectations for a continuity-focused audit of the WADE repository.

Primary objective: ensure **end-to-end correctness** across scripts/modules by validating that **variables, schemas, mappings, matrices, and handoffs** align consistently from ingestion through worker execution and output generation.

Secondary objective: improve hygiene, reduce redundancy, tighten error handling, and strengthen logging—without changing intended behavior unless clearly incorrect.

---

## Scope

Review the full pipeline end-to-end, including:

- Staging and file discovery
- Classification / routing logic
- Ticket/schema generation and metadata propagation
- Queueing and worker dispatch
- Worker execution and output path correctness
- Output normalization (JSON/CSV/JSONL) and Splunk ingestion assumptions
- Splunk app alignment (props/transforms/sourcetypes/indexes/dashboards)
- Logging and troubleshooting visibility across all steps

---

## Continuity Goals

### What “Good” Looks Like

- A single **source of truth** for key values (hostname, location, artifact type, image id, tool/module names)
- Consistent **ticket schema** and metadata fields across all scripts
- All mapping/matrix logic is explicit, validated, and tested (no “magic strings” spread everywhere)
- Classifier decisions are explainable, logged, and stable
- Worker outputs land in the correct, predictable locations every time
- Splunk app reflects reality: current indexes, sourcetypes, and event shapes match generated artifacts
- Logs are structured, correlated, and sufficient to debug failures quickly

---

## Audit Checklist

## 1) End-to-end pipeline continuity (front to back)

Validate the full chain:

- Input arrives → staging assigns identifiers → classifier decides routes → ticket built → worker runs → output written → Splunk expects and parses it

Checks:

- Map the entire flow and identify every **handoff point**
- Confirm “same concept” is represented with **one canonical field name** across components
  - Example: hostname, case name, image source path, image type, location, artifact category, tool, module
- Identify missing or ambiguous intersections:
  - “Classifier says X but ticket schema expects Y”
  - “Worker writes output but Splunk expects different sourcetype/index/event keys”
- Require **explicit mapping layers** (no silent assumptions)

Deliverable:
- A diagram-like narrative describing the pipeline, with “handoff contracts” per step (inputs/outputs/required fields)

---

## 2) Variable, mapping, matrix, and intersection correctness

Treat all routing/decision logic as **data contracts**.

Checks:

- Identify the “routing matrix” (artifact → tool/worker/module → output paths → Splunk sourcetype/index)
- Verify all keys are consistent:
  - Names match module filenames
  - Worker identifiers match CLI flags and dispatch logic
  - Tool names match run_tool wrappers and logging
- Ensure there is a centralized mapping definition (or propose one) for:
  - artifact categories
  - worker registry
  - expected output file names/extensions
  - sourcetypes/indexes

Deliverable:
- A prioritized list of mismatched keys/fields with file paths and recommended normalization strategy

---

## 3) Classifier logic correctness and soundness

Validate that classification is:

- correct for common cases
- stable across runs
- explainable (logged)
- safe (doesn’t misroute into destructive or expensive paths)

Checks:

- Enumerate all supported artifact types and what “evidence” triggers each classification
- Confirm precedence rules (when multiple types match) are deterministic
- Validate that negative cases don’t misclassify (e.g., “random binary” ≠ memory dump)
- Confirm classifier outputs produce consistent tickets and correct worker routing

Deliverable:
- A test matrix of sample inputs → expected classification → expected worker routes
- Recommendations for tightening signals and ordering rules

---

## 4) Worker output pathing and correctness

Every worker must write outputs to the correct location, and the location must be derived consistently.

Checks:

- Inventory how output paths are computed across workers
- Ensure all workers use the same path resolver function(s), not ad-hoc joins
- Validate that derived values exist and are consistent:
  - hostname
  - location
  - artifact subtype
  - tool/module name
  - timestamp / run id (if used)
- Confirm outputs include required sidecars:
  - manifest metadata
  - error logs / stderr
  - counts / summaries (if expected)

Deliverable:
- A “path contract” for each worker: inputs → computed output root → expected output filenames
- A list of workers deviating from the standard pathing approach + exact patch suggestions

---

## 5) Splunk app alignment with current artifact disposition

Ensure Splunk content matches what WADE produces now (not what it used to produce).

Checks:

- Inventory generated artifact streams:
  - indexes
  - sourcetypes
  - event formats (JSON/JSONL/CSV)
- Validate props/transforms against actual output
- Confirm field extractions and timestamps work
- Identify deprecated stanzas/dashboards/searches that no longer match reality
- Propose a clean mapping table:
  - artifact → index → sourcetype → expected fields → dashboard panels

Deliverable:
- A refactor plan for the Splunk app (stanzas to add/update/remove), based on real current outputs

---

## 6) Logging robustness for development and troubleshooting

During development, logging should be “excessively helpful,” not minimal.

Checks:

- Ensure every stage logs:
  - start/end markers
  - input identifiers and resolved paths
  - classification outcomes + why
  - ticket contents (redacted) or at least required fields
  - command executed (safely)
  - return codes, durations, counts, output paths, and errors
- Enforce correlation:
  - a single run id / image id / ticket id carried through all logs
- Confirm log sinks:
  - JSON logs for Splunk ingestion
  - human-readable logs for console/journalctl during debugging

Deliverable:
- A “logging minimum viable contract” for all scripts/workers
- A list of missing log points and what to add (file path + specific event type)

---

## Deliverables

Return:

1) A prioritized checklist of improvements with specific file paths
2) A continuity-focused mapping table:
   - artifact type → classification evidence → worker/tool/module → output path pattern → Splunk index/sourcetype
3) A refactor plan split into 3–5 small PRs (scope + payoff estimates)
4) Concrete proposals for:
   - consolidating mapping/matrix definitions
   - standardizing output path resolution
   - making classifier decisions testable and logged
   - updating Splunk app to match current outputs
   - strengthening logging for development

---
