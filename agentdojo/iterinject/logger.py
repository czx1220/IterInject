"""实验日志记录器"""
import json
from datetime import datetime

try:
    from .config import MODEL_LOGS_DIR, MODEL_PAYLOADS_DIR
except ImportError:  # pragma: no cover - supports direct script execution
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
                      latency_seconds: float = 0.0,
                      mutation_latency_seconds: float = 0.0,
                      prompt_tokens: int = 0,
                      completion_tokens: int = 0,
                      total_tokens: int = 0,
                      estimated_cost_usd: float = 0.0,
                      mutation_prompt: str = None,
                      mutation_prompt_tokens: int = 0,
                      mutation_completion_tokens: int = 0,
                      mutation_cost_usd: float = 0.0):
        """记录一次完整迭代"""
        record = {
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "disguise": disguise,
            "target": target,
            "payload": payload,
            "agent_response": agent_response,
            "feedback": feedback,
            "latency_seconds": latency_seconds,
            "mutation_latency_seconds": mutation_latency_seconds,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": estimated_cost_usd,
            "mutation_prompt": mutation_prompt,
            "mutation_prompt_tokens": mutation_prompt_tokens,
            "mutation_completion_tokens": mutation_completion_tokens,
            "mutation_cost_usd": mutation_cost_usd,
        }
        self.records.append(record)

        # 写入文本日志
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"ITERATION {iteration}\n")
            f.write(f"{'='*70}\n")
            f.write(f"Disguise: {disguise}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Latency: {latency_seconds}s")
            if mutation_latency_seconds > 0:
                f.write(f" | Mutation: {mutation_latency_seconds}s")
            f.write(f"\nTokens: prompt={prompt_tokens}, completion={completion_tokens}, total={total_tokens}\n")
            f.write(f"Cost: ${estimated_cost_usd:.6f}\n")
            f.write(f"\n{'─'*30} PAYLOAD {'─'*30}\n")
            f.write(f"{payload}\n")
            f.write(f"\n{'─'*30} AGENT RESPONSE {'─'*24}\n")
            f.write(f"{agent_response}\n")
            f.write(f"\n{'─'*30} FEEDBACK {'─'*29}\n")
            f.write(f"Result: {feedback.get('result')}\n")
            f.write(f"Score: {feedback.get('score')}\n")
            f.write(f"Keywords: {feedback.get('keywords')}\n")
            f.write(f"Detected as injection: {feedback.get('detected_as_injection')}\n")
            f.write(f"Success: {feedback.get('success')}\n")
            f.write(f"{'='*70}\n")

        # 写入 JSON（每次迭代都更新）
        with open(self.json_file, 'w') as f:
            json.dump(self.records, f, indent=2, ensure_ascii=False)

    def log_mutation(self, iteration: int, mutation_prompt: str, new_payload: str,
                     mutation_prompt_tokens: int = 0,
                     mutation_completion_tokens: int = 0,
                     mutation_cost_usd: float = 0.0):
        """记录变异过程"""
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'─'*30} MUTATION (for iter {iteration + 1}) {'─'*20}\n")
            f.write(f"Mutation Prompt:\n{mutation_prompt}\n")
            f.write(f"\n{'─'*30} GENERATED PAYLOAD {'─'*21}\n")
            f.write(f"{new_payload}\n")
            f.write(f"Tokens: prompt={mutation_prompt_tokens}, completion={mutation_completion_tokens}\n")
            f.write(f"Cost: ${mutation_cost_usd:.6f}\n")
            f.write(f"{'─'*70}\n")

        # 更新上一个 record 的 mutation 信息
        if self.records:
            self.records[-1]["mutation_prompt"] = mutation_prompt
            self.records[-1]["mutation_generated_payload"] = new_payload
            self.records[-1]["mutation_prompt_tokens"] = mutation_prompt_tokens
            self.records[-1]["mutation_completion_tokens"] = mutation_completion_tokens
            self.records[-1]["mutation_cost_usd"] = mutation_cost_usd
            # 重写 JSON 文件
            with open(self.json_file, 'w') as f:
                json.dump(self.records, f, indent=2, ensure_ascii=False)

    def log_final(self, success: bool, best_score: float, iterations: int,
                  total_experiment_latency: float = 0.0):
        """记录最终结果"""
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'='*70}\n")
            f.write("EXPERIMENT COMPLETE\n")
            f.write(f"{'='*70}\n")
            f.write(f"Success: {success}\n")
            f.write(f"Best Score: {best_score}\n")
            f.write(f"Total Iterations: {iterations}\n")
            f.write(f"Total Experiment Latency: {total_experiment_latency}s\n")
            f.write(f"Finished: {datetime.now().isoformat()}\n")
            f.write(f"{'='*70}\n")

    def save_successful_payload(self, payload: str, disguise: str, target: str):
        """保存成功的 payload"""
        with open(self.payload_file, 'w', encoding='utf-8') as f:
            f.write("# Successful Payload\n")
            f.write(f"# Disguise: {disguise}\n")
            f.write(f"# Target: {target}\n")
            f.write(f"# Time: {datetime.now().isoformat()}\n")
            f.write(f"# {'='*60}\n\n")
            f.write(payload)
