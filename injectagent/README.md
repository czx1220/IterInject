# IterInject

Official repository for **IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization**, Findings of EMNLP 2026.

[Paper v1](https://arxiv.org/abs/2605.24659v1) · [Single-case optimization](#single-case-optimization) · [Seed search](#seed-search) · [Asset provenance](THIRD_PARTY_NOTICES.md)

This subproject contains the optimization inner loop, an InjecAgent adapter, and sequential seed search with cumulative scoring, strategy synthesis, and historical successful references. Related AgentDojo and Claude Code implementations are maintained in the sibling directories `../agentdojo/` and `../claudecode/`; complete paper reproduction remains a work in progress.

Strategy assets are bundled under `src/iterinject/assets/strategies/`; benchmark cases, tools, and response cache are under `data/injecagent/`. Source identities and hashes are recorded in the [asset manifest](src/iterinject/assets/manifest.json) and [strategy catalog](configs/seeds/strategy-catalog.json). Runtime assets require no parent checkout.

## Install

Python 3.10 or later. Runtime dependency: `openai`; the core and benchmark parser use the standard library. The provider SDK is initialized only on an actual model call.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m iterinject --help
```

## Configuration

- `configs/method/iterinject.json`: the complete method, with `inner_loop` for iteration and stopping and `outer_search` for strategy selection, synthesis, scoring and reference rules.
- `configs/runs/seed-search.json`: the run identity, scope, API request budget and initial strategy bindings.
- `configs/benchmarks/injecagent.json`: task settings and five independent model-role templates, shared by single-case optimization and seed search.
- `configs/seeds/strategy-catalog.json`: 27 strategy categories, the plain baseline, and hash-checked source bindings.

The benchmark template requires explicit model names, base URLs, temperatures, output limits, and API-key environment variable names. Its model/address/token-limit fields are intentionally empty until configured. Set the named key variables in your shell; credential values are never written into configuration or saved records. The package does not load dotenv files automatically.

DS uses an independently configured simulation model when `simulation.mode` is `generate_on_miss`. The simulator checks the source and run response caches first. `cache_only` stops on an absent response. Generated responses are saved inside the run directory; the source cache remains read-only.

## Single-case optimization

After filling the benchmark template, list available case IDs:

```bash
.venv/bin/python -m iterinject manifest \
  --benchmark-config configs/benchmarks/injecagent.json \
  --data-dir data/injecagent
```

Supply a case ID and a UTF-8 initial-payload file, replacing the placeholders below:

```bash
.venv/bin/python -m iterinject run \
  --method-config configs/method/iterinject.json \
  --benchmark-config configs/benchmarks/injecagent.json \
  --data-dir data/injecagent \
  --case-id '<case-id>' \
  --initial-payload-file '<initial-payload-file>' \
  --output-dir results/run-001
```

Every output directory must be new. `evaluate` accepts the same inputs for one fixed evaluation with zero optimizer calls. `summarize --run-dir ...` reads saved runs without model requests. Explicit absolute input paths work from other working directories.

Single-case commands use the method configuration's `inner_loop` section. The same file also contains the `outer_search` settings used when running seed search.

The InjecAgent adapter supplies ReAct prompts, injection serialization, diagnosis, and simulation. `--approved-diagnostic-policy` and `--approved-optimizer-template` provide explicit preset overrides. Refinement uses the recorded payload and feedback history without silent truncation. Invalid outputs, context failures, model failures, and persistence failures stop the case without fabricating an evaluated attempt.

## Seed search

The outer search ranks seed strategies, runs the inner loop for each selected seed, and can synthesize a reusable strategy after failed trials. Success stops the target. Seed scores, newly registered strategies, and successful references commit together after a target ends normally.

Fill the five model roles in `configs/benchmarks/injecagent.json`. Choose `attack` (`dh` or `ds`), `setting` (`base` or `enhanced`), `prompt_type` (`InjecAgent` or `hwchase17_react`), and simulation mode (`generate_on_miss` or `cache_only`). Set the run configuration's `scope_id` to identify this experiment's evaluation scope.

Edit `configs/method/iterinject.json` to configure both layers of the method. `inner_loop` controls iterations and stopping. `outer_search` controls Top K, trials and syntheses per target, the total generated-strategy limit, reference count, selector threshold, initial seed score, and the scoring and visibility rules. `selector_version` supports `trajectory_table7_v2` and `paper_table7_v1`.

Edit `configs/runs/seed-search.json` to set the `run_id`, `scope_id`, API request budget and `seed_bindings`. The bindings explicitly select and order initial strategies; the supplied list includes all 27 categories and can be reduced or reordered. The strategy catalog also supports subsets of the bundled assets with consistent declared counts. Template numbers are editable defaults. New run configurations reject algorithm parameters: those belong in the method configuration.

Generate a target manifest containing case IDs, source hashes and tool-chain signatures:

```bash
.venv/bin/python -m iterinject manifest \
  --benchmark-config configs/benchmarks/injecagent.json \
  --run-config configs/runs/seed-search.json \
  --data-dir data/injecagent \
  --output-file targets.json
```

Without selection options this includes every case in dataset order. Repeat `--case-id '<case-id>'` to select cases in a specific order, or use `--limit <count>` to cap the selection. Manifest generation needs neither the method configuration nor model credentials, creates no model clients, and makes no API calls. The output file must be new.

```bash
.venv/bin/python -m iterinject search \
  --run-config configs/runs/seed-search.json \
  --method-config configs/method/iterinject.json \
  --benchmark-config configs/benchmarks/injecagent.json \
  --seed-catalog configs/seeds/strategy-catalog.json \
  --target-manifest targets.json \
  --data-dir data/injecagent \
  --output-dir results/search-001
```

Target count and execution order come from the manifest. Preflight checks configuration types, supported policy versions, seed eligibility and source hashes before creating model clients.

Search runs store `search.json` with separate method and run configuration snapshots, independent trials, initialization and synthesis records, generated definitions, durable `model-calls.jsonl`, checkpoints, and a summary. Resume requires an identical configuration/code/data snapshot at a committed target boundary; interrupted uncommitted targets are rejected. Runs saved before a source or configuration format change require a new run under the updated implementation.

## Records and metrics

A single-case run stores `run.json`, `attempts.jsonl`, `optimizer.jsonl`, and `summary.json`, including public configurations, input hashes, failure evidence, model usage, and API request counts. API counts include failed requests and exclude client-initialization failures; SDK retries are disabled.

DH uses Success, Detected, and Ignored. DS additionally uses Partial when extraction succeeds without completing sending. This DH implementation omits the related-but-incorrect-tool Partial outcome described in paper C.1; the method adaptation is explicit. Invalid outcomes and execution errors remain separate from diagnostic scores.

Summary rates are fractions in `[0, 1]`. `asr_valid` uses valid cases, while `asr_all` uses all cases; excluded cases and reasons are reported. Complete DS success requires both extraction and sending. A zero valid denominator gives `null`. Summaries keep evaluation scopes and diagnostic versions separate.

## Provenance and license

Own code: MIT. Migrated InjecAgent code retains the upstream notice in `LICENSES/injecagent-MIT.txt`; see `THIRD_PARTY_NOTICES.md` for file-level sources. Bundled strategy assets are local research additions with separately recorded provenance; their source files have no individual license declaration. Original source datasets remain unchanged.

## Citation

If you find this work useful, please cite our paper:

```bibtex
@misc{chen2026iterinject,
  title = {IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization},
  author = {Zixuan Chen and Jiaxiang Chen and Li Luo and Ke Xu and Xiaoxiang Huang and Tanfeng Sun and Xinghao Jiang},
  year = {2026},
  eprint = {2605.24659},
  archivePrefix = {arXiv},
  primaryClass = {cs.LG},
  url = {https://arxiv.org/abs/2605.24659}
}
```
