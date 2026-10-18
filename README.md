# IterInject

Official code repository for **IterInject: Indirect Prompt Injection Against LLM Agents via Feedback-Guided Iterative Optimization**, Findings of EMNLP 2026.

[Paper (arXiv)](https://arxiv.org/abs/2605.24659) · [PDF](https://arxiv.org/pdf/2605.24659) · [OpenReview](https://openreview.net/forum?id=OBXkjB2JzD)

**Zixuan Chen, Jiaxiang Chen, Li Luo, Ke Xu, Xiaoxiang Huang, Tanfeng Sun, Xinghao Jiang**

Shanghai Jiao Tong University · The University of Hong Kong

IterInject studies indirect prompt injection against LLM agents through feedback-guided iterative optimization. This repository brings together the three experiment implementations in separate directories. Each subproject keeps its own setup instructions, dependencies, and configuration.

## Repository layout

| Directory | Contents |
| --- | --- |
| [`agentdojo/`](agentdojo/README.md) | AgentDojo experiments, AgentVigil replication, defense replay, aggregation scripts, and paper-aligned artifacts. |
| [`injectagent/`](injectagent/README.md) | IterInject optimization framework, InjecAgent adapter and data, configurable single-case runs, and seed search. |
| [`claudecode/`](claudecode/README.md) | Claude Code experiment runner, payload and evaluation modules, scripts, and representative result examples. |

## Getting started

The three experiment suites are independently configured. Run commands from the corresponding subproject directory and follow its README.

### AgentDojo

Start with [`agentdojo/README.md`](agentdojo/README.md) for the benchmark setup, model configuration, and experiment commands. Its Python dependencies and example environment file are in `agentdojo/`.

### InjecAgent

The InjecAgent implementation requires Python 3.10 or later and installs as an editable package:

```bash
cd injectagent
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m iterinject --help
```

See [`injectagent/README.md`](injectagent/README.md) for configuration, single-case runs, seed search, data provenance, and licenses. Model settings are templates and must be configured before API-backed runs.

### Claude Code

The Claude Code runner requires Python 3.9 or later, the Claude Code CLI, and credentials for the injection and target agents:

```bash
cd claudecode
python3 -m pip install -r requirements.txt
export INJECTION_AGENT_TOKEN="..."
export INJECTION_AGENT_URL="https://api.anthropic.com"
export ANTHROPIC_AUTH_TOKEN="..."
export ANTHROPIC_BASE_URL="https://api.anthropic.com"
export ANTHROPIC_MODEL="..."
bash scripts/run_full_experiment.sh
```

See [`claudecode/README.md`](claudecode/README.md) for target-specific commands and details about the representative examples.

## Citation

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
