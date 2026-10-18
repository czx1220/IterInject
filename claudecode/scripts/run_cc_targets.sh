#!/bin/bash
# CC-Aware strategy experiment
# Usage: bash scripts/run_cc_targets.sh [target_name]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

TARGET="${1:-env_leak}"

LOG_DIR="experiments/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/run_cc_${TARGET}_${TIMESTAMP}.log"

echo "========================================" | tee "$LOG_FILE"
echo "CC-Aware Experiment: $TARGET at $(date)" | tee -a "$LOG_FILE"
echo "Strategies: 12 CC-Aware (CC01-CC12)" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

python3 -u main.py target "$TARGET" 2>&1 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "CC-Aware experiment completed at $(date)" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
