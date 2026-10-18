#!/bin/bash
# Run all strategies (27 general + 12 CC) for a single target
# Usage: bash scripts/run_target.sh <target_name>
# Example: bash scripts/run_target.sh echo
#          bash scripts/run_target.sh env_leak
#          bash scripts/run_target.sh create_file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

TARGET="$1"
if [ -z "$TARGET" ]; then
    echo "Usage: bash scripts/run_target.sh <target>"
    echo "Targets: echo, read_file, env_leak, bash_cmd, write_file, call_skill, network, create_file, modify_memory"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="experiments/logs"
mkdir -p "$LOG_DIR"

LOG_FILE="${LOG_DIR}/run_${TARGET}_${TIMESTAMP}.log"

echo "========================================" | tee "$LOG_FILE"
echo "Target: $TARGET" | tee -a "$LOG_FILE"
echo "Start: $(date)" | tee -a "$LOG_FILE"
echo "Strategies: 27 general + 12 CC = 39 total" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

python3 -u main.py target "$TARGET" 2>&1 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Target $TARGET completed at $(date)" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
