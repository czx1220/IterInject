# IterInject AgentDojo Experiments

This repository contains the complete paper-facing AgentDojo experiment
release for IterInject: the IterInject implementation, our AgentVigil
replication, baseline evaluation, defense replay, result aggregation scripts,
and experiment configuration.

The private research workspace also contained early provider-specific runners,
smoke tests, failed reruns, and OpenClaw adaptation experiments. Their mapping
to this release and the exclusion rationale are documented in
[`docs/experiment-provenance.md`](docs/experiment-provenance.md). The canonical
machine-readable configuration is
[`experiments/manifest.json`](experiments/manifest.json).

## Structure

```text
iterinject/
  agentdojo_benchmark.py     Shared benchmark templates and suite sizes
  agentdojo_adapter.py       AgentDojo runner and OpenAI-compatible tool pipeline
  agentdojo_mutator.py       AgentDojo-specific payload mutation wrapper
  seed_bank.py               Cross-target scoring and self-evolving seed bank
  config.py                  Paper-aligned defaults and disguise seed definitions
  evaluation_agent.py        Rule-based diagnostic feedback helpers
  injection_agent.py         LLM payload optimizer client and prompt construction
  logger.py                  Per-case local experiment logging

agentvigil/
  agentvigil.py              MCTS fuzzing loop
  mcts.py                    UCB1 tree selection and backpropagation
  mutations.py               Prompt mutation operators
  scoring.py                 Per-case AgentDojo evaluation
  seed_collector.py          AgentDojo attack seed construction
  run.py                     AgentVigil CLI entry point

scripts/
  run_agentdojo_stepwise.py      Main AgentDojo IterInject runner
  summarize_agentdojo_runs.py    Aggregates per-case outputs into paper tables
  run_agentdojo_defense_replay.py Replays successful DeepSeek payloads under defenses

experiments/
  manifest.json                 Canonical experiment matrix and artifact index
  agentdojo_cases.json          Paper's 102 selected user-injection pairs

docs/
  experiment-provenance.md      Source lineage and release boundary

tests/
  test_release_helpers.py       Runner and aggregation regression tests
  test_release_integrity.py     Artifact and result consistency checks
```

## Paper-Aligned AgentDojo Setup

- Benchmark: AgentDojo `v1.2.2`
- Suites and denominators: Workspace 140, Banking 130, Travel 75, Slack 165, total 510 cases
- Victim models: GLM-5.1, MiniMax-M2.7, DeepSeek-V4-Flash, Qwen3.5-27B
- Victim temperature: `0.0`
- Payload optimizer: Qwen3-8B, temperature `0.7`, thinking disabled
- Attack types: `direct`, `ignore_previous`, `system_message`, `injecagent`, `important_instructions`
- Disguise candidates: `system_reminder`, `direct_request`, `fake_error`, `data_content`, `config_field`, `silent_execution`, `comment`, `override_rules`, `encode_obfuscate`, `fake_system_prompt`
- Iteration budget: 7
- No-improvement patience: 3, extended by 2 after reaching diagnostic value `v(Detected)=1`
- Pipeline: OpenAI-compatible tool-calling pipeline

## Paper Algorithm Mapping

The implementation follows Algorithm 1 and Sections 4.1-4.3 of the paper. It
contains two distinct optimization levels:

1. **Feedback-guided iteration (inner loop).** For one disguise seed and one
   attack target, the victim is evaluated, the rule-based Diagnoser assigns
   `SUCCESS`, `PARTIAL`, `DETECTED`, or `IGNORED`, and the optimizer receives
   the current payload, structured feedback, and the full iteration history.
   The loop runs for at most 7 evaluations, stops after 3 non-improving rounds
   (extended by 2 after reaching `DETECTED`), and stops immediately on success.
2. **Seed self-evolution (outer loop).** Seeds retain cumulative mean diagnostic
   scores across targets and are tried in descending score order. After each
   failed seed batch, the rule table selects `splice`, `camouflage`,
   `format_shift`, `escalate`, or `repeat`; an LLM synthesizes a new reusable
   disguise and appends it to the persistent seed bank.

The default case manifest contains 102 selected user-injection pairs:
Workspace 28, Banking 26, Travel 15, and Slack 33. Applying the five paper
attack types yields the reported 510 cases per victim model. Explicit
`--user-task` or `--injection-task` arguments override this manifest for
controlled runs.

## Installation

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set the target-model and mutation-model endpoints in `.env`. Both clients use
OpenAI-compatible APIs. Avoid passing keys on the command line on shared
systems because command lines can be recorded by process monitors and shell
history.

The `transformers_pi_detector` defense additionally requires AgentDojo's
optional local-detector dependencies:

```bash
pip install "agentdojo[transformers]==0.1.35"
```

This optional installation includes PyTorch and Transformers and is not needed
for the main IterInject or AgentVigil experiments.

Run the offline checks before any API-backed experiment:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
python scripts/run_agentdojo_stepwise.py --help
python -m agentvigil.run --help
```

## Running IterInject and the Benchmark Baseline

Run one victim model at a time. Repeated `--suite` and `--baseline-attack`
arguments select the complete paper configuration:

```bash
python scripts/run_agentdojo_stepwise.py \
  --run-id qwen3_attack_qwen \
  --benchmark-version v1.2.2 \
  --suite workspace \
  --suite banking \
  --suite travel \
  --suite slack \
  --baseline-attack direct \
  --baseline-attack ignore_previous \
  --baseline-attack system_message \
  --baseline-attack injecagent \
  --baseline-attack important_instructions \
  --model Qwen3.5-27B \
  --temperature 0.0 \
  --pipeline-mode openai-tools \
  --seed-batch-size 3 \
  --stop-on-first-success
```

The script defaults to the 10 AgentDojo disguise candidates. Override with
repeated `--disguise` flags only for controlled reruns. The static Benchmark
result is the first payload evaluation for each case; add `--max-iterations 1`
to run only that evaluation. IterInject reports the best observed result across
the initial payload and subsequent mutations. Use `--disable-seed-synthesis`
for the no-self-evolution ablation and `--disable-cross-learning` for the
no-cross-template-ICL ablation.

## Running AgentVigil

```bash
python -m agentvigil.run \
  --suite workspace \
  --model Qwen3.5-27B \
  --temperature 0.0 \
  --helper-model Qwen3-8B \
  --iterations 7 \
  --mutations-per-iter 3 \
  --benchmark-version v1.2.2 \
  --logdir runs/agentvigil_qwen3.5-27b
```

Use these canonical run directory names when regenerating the unified table:
`agentvigil_glm5`, `agentvigil_minimax`, `agentvigil_deepseek`, and
`agentvigil_qwen3.5-27b`.

## Replaying Defenses

Defense experiments replay payloads that already succeeded without defenses;
they do not optimize against a defense. Place the DeepSeek IterInject and
AgentVigil runs under `runs/`, then run:

```bash
python scripts/run_agentdojo_defense_replay.py \
  --iterinject-root runs/qwen3_attack_deepseek \
  --agentvigil-root runs/agentvigil_deepseek \
  --model DeepSeek-V4-Flash
```

The default defenses are tool filtering, the transformers prompt-injection
detector, delimiter-based spotlighting, and repeated user prompting.

## Aggregating Local Runs

After the four IterInject and AgentVigil runs are present under `runs/`,
regenerate the complete three-method table:

```bash
python scripts/summarize_agentdojo_runs.py \
  --runs-root runs \
  --agentvigil-runs-root runs
```

The aggregation script writes results locally; result tables, raw runs,
successful payloads, transcripts, and runtime statistics are intentionally not
included in this source release. Keep those outputs in a local ignored
directory when running experiments.

## Metrics and Counting

- **ASR**: attacker goal success rate.
- **UA**: benign user-task completion rate.
- **JSR**: rate at which ASR and UA succeed in the same attempt.

All percentages use fixed AgentDojo denominators: Workspace 140, Banking 130,
Travel 75, Slack 165, for 510 cases per victim model. Missing selected cases
are counted as failures and recorded in the JSON aggregation metadata.

## Research Use

This repository contains indirect prompt-injection payloads for controlled
security evaluation. Run them only against systems and accounts you are
authorized to test. The included AgentDojo tasks use benchmark fixtures rather
than real user accounts.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
