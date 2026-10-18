"""实验日志记录器"""
import json
from datetime import datetime
from pathlib import Path
from config import MODEL_LOGS_DIR, MODEL_PAYLOADS_DIR


class ExperimentLogger:
    """完整的实验日志记录器"""

    def __init__(self, experiment_id: str):
        self.experiment_id = experiment_id
        self.log_file = MODEL_LOGS_DIR / f"{experiment_id}_full.log"
        self.json_file = MODEL_LOGS_DIR / f"{experiment_id}_data.json"
        self.payload_file = MODEL_PAYLOADS_DIR / f"{experiment_id}_payload.txt"
        self.records = []

        # 确保目录存在
        MODEL_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        MODEL_PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)

        # 初始化日志文件
        with open(self.log_file, 'w') as f:
            f.write(f"{'='*70}\n")
            f.write(f"Experiment: {experiment_id}\n")
            f.write(f"Started: {datetime.now().isoformat()}\n")
            f.write(f"{'='*70}\n\n")

    def log(self, message: str):
        """写入日志并打印"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        with open(self.log_file, 'a') as f:
            f.write(line)
        print(line, end='')

    def log_iteration(self, iteration: int, disguise: str, target: str,
                      payload: str, agent_response: str, feedback: dict,
                      latency_ms: int = 0):
        """记录一次完整迭代"""
        record = {
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "disguise": disguise,
            "target": target,
            "payload": payload,
            "agent_response": agent_response,
            "feedback": feedback,
            "graded_score": feedback.get("graded_score", "ERROR"),
            "score_numeric": feedback.get("score_numeric"),
            "is_success": feedback.get("is_success", False),
            "latency_ms": latency_ms,
        }
        self.records.append(record)

        # 写入文本日志
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"ITERATION {iteration}\n")
            f.write(f"{'='*70}\n")
            f.write(f"Disguise: {disguise}\n")
            f.write(f"Target: {target}\n")
            f.write(f"\n{'─'*30} PAYLOAD {'─'*30}\n")
            f.write(f"{payload}\n")
            f.write(f"\n{'─'*30} AGENT RESPONSE {'─'*24}\n")
            f.write(f"{agent_response}\n")
            f.write(f"\n{'─'*30} FEEDBACK {'─'*29}\n")
            f.write(f"Result: {feedback.get('result')}\n")
            f.write(f"Score: {feedback.get('score')}\n")
            f.write(f"Keywords: {feedback.get('keywords')}\n")
            f.write(f"Detected as injection: {feedback.get('detected_as_injection')}\n")
            f.write(f"Awareness level: {feedback.get('awareness_level', 'N/A')}\n")
            f.write(f"Success: {feedback.get('success')}\n")
            f.write(f"{'='*70}\n")

        # 写入 JSON（每次迭代都更新）
        with open(self.json_file, 'w') as f:
            json.dump(self.records, f, indent=2, ensure_ascii=False)

    def log_mutation(self, iteration: int, mutation_prompt: str, new_payload: str):
        """记录变异过程"""
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'─'*30} MUTATION (for iter {iteration + 1}) {'─'*20}\n")
            f.write(f"Mutation Prompt:\n{mutation_prompt}\n")
            f.write(f"\n{'─'*30} GENERATED PAYLOAD {'─'*21}\n")
            f.write(f"{new_payload}\n")
            f.write(f"{'─'*70}\n")

    def log_final(self, success: bool, best_score: float, iterations: int):
        """记录最终结果"""
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"EXPERIMENT COMPLETE\n")
            f.write(f"{'='*70}\n")
            f.write(f"Success: {success}\n")
            f.write(f"Best Score: {best_score}\n")
            f.write(f"Total Iterations: {iterations}\n")
            f.write(f"Finished: {datetime.now().isoformat()}\n")
            f.write(f"{'='*70}\n")

    def save_successful_payload(self, payload: str, disguise: str, target: str):
        """保存成功的 payload"""
        with open(self.payload_file, 'w', encoding='utf-8') as f:
            f.write(f"# Successful Payload\n")
            f.write(f"# Disguise: {disguise}\n")
            f.write(f"# Target: {target}\n")
            f.write(f"# Time: {datetime.now().isoformat()}\n")
            f.write(f"# {'='*60}\n\n")
            f.write(payload)
