#!/bin/bash
# Full experiment: 27 general + 12 CC-specific disguises x 9 targets
# Usage: bash scripts/run_full_experiment.sh [model_name]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

MODEL="${1:-minimax-m2.1}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="experiments/${MODEL}"
mkdir -p "$LOG_DIR"

echo "========================================"
echo "Full Experiment Suite"
echo "Model: $MODEL"
echo "Time: $(date)"
echo "Strategies: 27 general + 12 CC = 39 total"
echo "Targets: 9"
echo "========================================"

echo ""
echo "========================================"
echo "Running all targets (39 seeds x 9 targets)"
echo "========================================"
python3 -u main.py all 2>&1 | tee "${LOG_DIR}/run_all_${TIMESTAMP}.log"

echo ""
echo "========================================"
echo "Generating Reports"
echo "========================================"
python3 -u report_generator.py --paper-format
python3 -u report_generator.py

echo ""
echo "========================================"
echo "Full experiment completed at $(date)"
echo "Results in: ${LOG_DIR}/"
echo "========================================"
