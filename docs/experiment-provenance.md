# AgentDojo experiment provenance

This release consolidates all paper-facing AgentDojo work from the private
research workspace into one self-contained repository. The source workspace
contained several generations of runners and many provider-specific rerun
scripts. They are represented here by their final maintained entrypoints and
reproduction documentation, rather than copied verbatim.

## Source families

| Workspace source | Purpose | Release representation |
|---|---|---|
| `agentdojo/` | Early provider-specific benchmark runners and environment notes | Superseded by `scripts/run_agentdojo_stepwise.py` and `.env.example` |
| `openclaw_stepwise/` | Early stepwise mutation implementation and AgentDojo/OpenClaw adaptation work | Consolidated into `iterinject/`; OpenClaw-only scenarios are outside this release |
| `agentvigil/` | AgentVigil baseline implementation and rerun helpers | Consolidated into `agentvigil/` |
| `runs/` | Development runs, smoke tests, failed runs, and final per-case outputs | Not included; generated locally and ignored |
| `release/iterinject/` | Staging tree used during the paper experiments | Cleaned into this repository |

## What is published

- The final IterInject AgentDojo implementation and CLI.
- The AgentVigil baseline implementation used for comparison.
- The defense replay and aggregate-result scripts.
- The result aggregation and defense replay scripts, without their generated
  outputs.
- A machine-readable experiment matrix in `experiments/manifest.json`.

## What is intentionally excluded

- `.env` files and provider credentials.
- Provider-specific shell scripts that embed credentials, private endpoints,
  machine paths, or ad hoc retry lists.
- Aggregate result tables, successful payload cases, raw API transcripts, full
  model responses, and development logs. These are experiment outputs and may
  contain provider metadata.
- Smoke tests, failed attempts, caches, virtual environments, and temporary
  archives.
- OpenClaw-only experiments, which evaluate a different runtime rather than
  AgentDojo.

The excluded material is not required to run the released code. The
aggregation script documents its fixed suite denominators and failure-filling
behavior when run locally.

## Result derivation

`scripts/summarize_agentdojo_runs.py` reads local per-case outputs from
`runs/qwen3_attack_<model>/`. The Benchmark row uses the first evaluated
payload. The IterInject row uses the best observed outcome across the initial
payload and the final selected mutation. JSR remains a per-attempt conjunction
of attack success and user-task utility.

No result files are checked in. Per-case raw runs and generated tables remain
local because they are large, contain full model transcripts, and are not part
of the source release.

## Historical parameter discrepancy

Some staging documentation and provider-specific scripts used victim
temperature `0.7` during development. The finalized paper-facing experiment
configuration uses victim temperature `0.0`, as recorded in
`experiments/manifest.json` and the repository README. The mutation model
temperature remains `0.7`.
