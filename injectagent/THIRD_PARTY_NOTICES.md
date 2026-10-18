# Third-party notices

IterInject's own code is licensed under the MIT License in `LICENSE`, as selected by the repository owner on 2026-10-09.

## InjecAgent

The original InjecAgent benchmark is referenced by the parent README at <https://github.com/uiuc-kang-lab/InjecAgent>. Migrated code in this repository comes from the local InjecAgent checkout at parent revision `d6b9245`, which includes local optimization additions. The original MIT notice, copyright (c) 2023 Qiusi Zhan, is preserved byte for byte in `LICENSES/injecagent-MIT.txt`.

| Migrated location | Source in parent InjecAgent checkout | Change |
| --- | --- | --- |
| `src/iterinject/adapters/injecagent/parser.py` | `src/output_parsing.py` | Standard-library n-grams; explicit errors; actual injected payload used for echo checking. Original parser validity/success criteria retained. |
| `src/iterinject/adapters/injecagent/agent_prompts.py` | `src/prompts/agent_prompts.py`; `src/evaluate_prompted_agent.py:26-37` | Original ReAct prompts and input assembly moved into adapter; DS stage 2 requires the parsed thought and parameters. |
| `src/iterinject/adapters/injecagent/dataset.py` | `src/optimization/optimize.py:124-170`; `src/utils.py:117-130` | Explicit read-only paths, stable identity, strict single placeholder; user-approved JSON string serialization after dynamic substitution. |
| `src/iterinject/adapters/injecagent/optimizer.py`, `optimizer.txt` | `src/optimization/mutation_engine.py:32-90,118-177` | InjecAgent context and prompt structure retained; full per-case history/latest records, four-level feedback, explicit references, no silent truncation. |
| `src/iterinject/adapters/injecagent/diagnostic-policy.json` | `src/optimization/evaluation_bridge.py:21-36` | Legacy detection/refusal vocabulary plus `sorry` from paper C.1; lowercase substring matching. Version 2 records the user's approved method adaptation: Partial is DS-only; DH uses Success/Detected/Ignored. |
| `src/iterinject/adapters/injecagent/simulated_responses.py` | Upstream commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`: `src/utils.py:137-165`; `src/prompts/generation_prompts.py` | Exact legacy cache key and original generation prompt/first-fence extraction; source cache remains read-only, generated entries use a separate run cache and explicit simulation model configuration. |
| `src/iterinject/adapters/injecagent/metrics.py` | `src/utils.py:43-69` | Case-level full DS success separated from conditional stage 2 success and invalid exclusions. |
| `src/iterinject/adapters/injecagent/initializers.py`, `configs/seeds/strategy-catalog.json`, `src/iterinject/assets/strategies/` | Local `src/optimization/disguise_adapter.py`, `agent_safe_clean/config.py`, `agent_safe_clean/initial_payloads_generated.py` at `8d7e09a16471ffef74aece2bffe255a496fefef1` (JacksonChen) | Selected AST nodes are bundled with exact syntax-tree fidelity: 16 native functions + registry, 27 Claude definitions + Enum, and 270 explicit target-bound compatibility payloads. These are local research additions, not identified as verbatim upstream benchmark assets. None of the three source files has a separate license declaration; original path/hash/commit/author are recorded in the asset manifest. |

The core optimizer and model client are newly implemented. The source-based InjecAgent preset is user-approved, with baseline hashes in `src/iterinject/adapters/injecagent/preset.json`. It is not asserted to be a recovered verbatim publication asset. The generic opt-in reconstruction text in `prompts/optimizer.txt` is retained as an earlier asset; the InjecAgent CLI uses the adapter preset.

The owner authorized repository-local runtime assets. `data/injecagent/` now includes six byte-identical benchmark JSON files. Tools and four case sets match Qiusi Zhan's initial `623f1bf3ad8ed35abe71f9f9d8fd9d99ad65aeea` snapshot. The response cache additionally contains local changes at `d6b9245e8d88bebbe4fab964cafad8135f9854c4` (JacksonChen). Neither local source tree inspected for these assets contains a separate data license declaration; the upstream MIT notice is retained without treating it as new evidence of individual asset licensing. Benchmark input hashes are recorded by the `manifest` command and in saved run manifests. Old experiment logs and unrelated projects are not included.
