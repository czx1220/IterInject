# Paper-to-code alignment

This repository implements the AgentDojo portion of *IterInject: Indirect
Prompt Injection Against LLM Agents via Feedback-Guided Iterative
Optimization* (arXiv:2605.24659). It does not claim to release the InjectAgent,
Claude Code, or mechanistic-analysis pipelines described elsewhere in the
paper.

| Paper component | Implementation |
|---|---|
| Disguise seed bank `D` | `iterinject/seed_bank.py::SeedBank` |
| Initial 10 AgentDojo seeds | `iterinject/config.py::DISGUISE_TEMPLATES` |
| Inner inject-diagnose-refine loop | `scripts/run_agentdojo_stepwise.py::run_experiment` |
| Four diagnostic labels and values | `iterinject/seed_bank.py::DIAGNOSTIC_VALUES` |
| Full-history optimizer context | `iterinject/injection_agent.py::_format_history_section` |
| Patience `P=3`, relaxed by 2 at `v*=1` | `run_experiment` stopping logic |
| Cross-target cumulative score `S(d)` | `SeedBank.complete_target` |
| Descending-score batch selection | `SeedBank.top_k` |
| Rule-based synthesis strategy | `select_synthesis_strategy` |
| LLM Disguise Synthesizer | `AgentDojoMutator.synthesize_seed` |
| Persistent self-evolving state | `agentdojo_stepwise_resume_state.json` |
| Fixed 510-case selection | `experiments/agentdojo_cases.json` |

## Terminology

**Iteration** is the inner-loop update of a payload for a fixed target and
seed. The optimizer observes the victim output and structured diagnosis, then
produces the next payload conditioned on all earlier attempts.

**Self-evolution** is the outer-loop change to the strategy space itself. The
system scores seeds across targets, changes their future priority, synthesizes
new seeds from batch-level failure patterns, and persists those seeds for later
targets. Rewording one payload repeatedly is iterative optimization, but is not
by itself seed-bank self-evolution.

## AgentDojo settings

- AgentDojo v1.2.2 (`agentdojo==0.1.35`).
- Victim temperature 0.0.
- GLM-5.1, DeepSeek-V4-Flash, and Qwen3.5-27B use non-thinking mode;
  MiniMax-M2.7 retains the server default thinking mode.
- Qwen3-8B optimizer, temperature 0.7, thinking disabled.
- Maximum 7 inner-loop evaluations, patience 3, extended by 2 after reaching
  diagnostic value 1.
- AgentVigil uses 7 iterations, 3 mutations per iteration, UCB1 constant
  1.414, and the five mutation operators named in Appendix B.1.
