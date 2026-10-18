# Claude Code Experiments

Claude Code experiment implementation for IterInject, organized as a standalone subproject within the unified repository.

## Contents

- Experiment orchestration, payload templates, target execution, evaluation, logging, and shell runners are in this directory.
- `examples/`: representative summaries and iteration traces for the `echo`, `read_file`, and `bash_cmd` targets.

## Setup

Requires Python 3.9 or newer, the Claude Code CLI, and credentials for the injection and target agents.

```bash
python3 -m pip install -r requirements.txt
```

Set the injection agent credentials and target agent settings in the environment. The target runner reads `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, and `ANTHROPIC_MODEL`; the injection agent reads `INJECTION_AGENT_TOKEN` and `INJECTION_AGENT_URL`.

```bash
export INJECTION_AGENT_TOKEN="..."
export INJECTION_AGENT_URL="https://api.anthropic.com"
export ANTHROPIC_AUTH_TOKEN="..."
export ANTHROPIC_BASE_URL="https://api.anthropic.com"
export ANTHROPIC_MODEL="..."
```

Run from the experiment directory:

```bash
cd claudecode
bash scripts/run_full_experiment.sh
```

To run one target instead:

```bash
bash scripts/run_target.sh echo
```

Generated logs and experiment outputs are written under `experiments/` and are ignored by Git. The checked-in examples are a small representative subset, not the full run dataset.
