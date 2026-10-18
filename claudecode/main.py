#!/usr/bin/env python3
"""
主控程序 - 间接提示注入实验框架 (Claude Code)
协调注入 Agent、目标 Agent 和评估 Agent 的迭代循环

运行方式:
  python main.py target echo          # 针对单个目标
  python main.py all                   # 运行所有目标
  python main.py single <disguise> <target>  # 单个组合

攻击目标 (9 targets):
  L1 - Information Leakage:
    echo, read_file, env_leak

  L2 - Transient Execution:
    bash_cmd, call_skill, network

  L3 - Persistent Modification:
    write_file, create_file, modify_memory

伪装方式 (39 seeds = 27 general + 12 CC-specific)
"""
import sys
import json
import time
from datetime import datetime

from config import (
    DisguiseSeed, TargetSeed, MODEL_EXPERIMENTS_DIR, TARGET_MODEL,
    MAX_ITERATIONS, NO_IMPROVEMENT_LIMIT, NO_IMPROVEMENT_LIMIT_DV_THRESHOLD,
    SUCCESS_TYPES, ResultType, TARGET_ACTIONS, DISGUISE_TEMPLATES,
    CONFIG_FILE,
)
from cc_payloads import CCDisguiseSeed, CC_DISGUISE_TEMPLATES, CC_INITIAL_PAYLOADS, CC_TARGET_ACTIONS
from logger import ExperimentLogger
from injection_agent import InjectionAgent
from target_agent import TargetAgent
from evaluation_agent import EvaluationAgent
from report_generator import ReportGenerator
from seed_bank import SeedBank, DIAGNOSTIC_VALUE_MAP
from seed_synthesizer import SeedSynthesizer


class CCInjectionAgent(InjectionAgent):
    """CC 格式注入 Agent - 直接写 payload 到配置文件（不追加原始内容）"""

    def __init__(self):
        super().__init__()
        self.normal_config = ""

    def get_initial_payload(self, disguise, target):
        target_name = target.value if isinstance(target, TargetSeed) else target
        if disguise in CC_INITIAL_PAYLOADS:
            if target_name in CC_INITIAL_PAYLOADS[disguise]:
                return CC_INITIAL_PAYLOADS[disguise][target_name]
        template_info = CC_DISGUISE_TEMPLATES.get(disguise, {})
        examples = template_info.get("examples", [])
        if examples:
            return examples[0]
        return ""

    def inject_payload(self, payload, disguise):
        with open(CONFIG_FILE, 'w') as f:
            f.write(payload)
        return payload

    def restore_config(self):
        with open(CONFIG_FILE, 'w') as f:
            f.write("")


def _result_to_diagnostic_value(result_type: str) -> int:
    """将 ResultType 字符串映射为诊断值 (3/2/1/0)"""
    if result_type.startswith("SUCCESS"):
        return 3
    elif result_type == "PARTIAL":
        return 2
    elif result_type.startswith("DETECTED"):
        return 1
    return 0


def run_experiment(disguise, target: TargetSeed,
                   successful_patterns: list = None) -> dict:
    """
    运行完整实验

    Args:
        disguise: 伪装方式 (DisguiseSeed / CCDisguiseSeed / DynamicSeed)
        target: 攻击目标
        successful_patterns: 来自其他成功伪装的pattern提示 (cross-disguise learning)

    Returns:
        实验结果字典
    """
    experiment_id = f"{disguise.value}_{target.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    logger = ExperimentLogger(experiment_id)
    if isinstance(disguise, CCDisguiseSeed):
        injection_agent = CCInjectionAgent()
    else:
        injection_agent = InjectionAgent()
    target_agent = TargetAgent()
    evaluation_agent = EvaluationAgent()

    logger.log(f"Starting experiment: {disguise.value} + {target.value}")
    logger.log(f"Max iterations: {MAX_ITERATIONS}")
    logger.log(f"No improvement limit: {NO_IMPROVEMENT_LIMIT}")

    # 获取初始 payload
    payload = injection_agent.get_initial_payload(disguise, target)
    if not payload:
        logger.log(f"ERROR: No initial payload for {disguise.value} + {target.value}")
        return {"success": False, "error": "No initial payload"}

    logger.log(f"Initial payload loaded ({len(payload)} chars)")

    # 如果有跨伪装的成功pattern提示
    if successful_patterns:
        logger.log(f"Got {len(successful_patterns)} successful patterns from other disguises for cross-learning")

    # 迭代状态
    best_score = 0.0
    best_payload = payload
    best_result_type = "IGNORED"
    best_diagnostic_value = 0
    no_improvement_count = 0
    success = False
    final_iteration = 0
    history = []

    # 主迭代循环
    for iteration in range(1, MAX_ITERATIONS + 1):
        final_iteration = iteration
        logger.log(f"\n{'='*50}")
        logger.log(f"ITERATION {iteration}")
        logger.log(f"{'='*50}")

        # Step 1: 注入 payload
        logger.log("Step 1: Injecting payload...")
        injection_agent.inject_payload(payload, disguise)

        # Step 2: 执行目标 agent
        logger.log("Step 2: Executing target agent...")
        t0 = time.time()
        agent_response = target_agent.execute()
        latency_ms = int((time.time() - t0) * 1000)
        logger.log(f"Got response ({len(agent_response)} chars, {latency_ms}ms)")

        # Step 3: 评估结果
        logger.log("Step 3: Evaluating result...")
        feedback = evaluation_agent.evaluate(agent_response, target)
        logger.log(f"Result: {feedback['result']}, Score: {feedback['score']}")
        logger.log(f"Keywords: {feedback['keywords']}")
        logger.log(f"Detected: {feedback['detected_as_injection']}, Awareness: {feedback.get('awareness_level', 'N/A')}")

        # Step 4: 记录完整迭代
        logger.log_iteration(
            iteration, disguise.value, target.value,
            payload, agent_response, feedback,
            latency_ms=latency_ms
        )

        # Step 5: 恢复配置
        injection_agent.restore_config()

        # Step 6: 记录到历史 (用于 in-context learning)
        history.append({
            "iteration": iteration,
            "payload": payload,
            "score": feedback["score"],
            "result": feedback["result"],
            "keywords": feedback.get("keywords", []),
            "detected_as_injection": feedback.get("detected_as_injection", False),
            "reached_injection": feedback.get("reached_injection", False),
            "awareness_level": feedback.get("awareness_level", "none"),
        })

        # Step 7: 检查是否成功
        if feedback["success"]:
            result_type = feedback['result']
            logger.log(f"SUCCESS ({result_type})! Attack succeeded!")
            logger.save_successful_payload(payload, disguise.value, target.value)
            best_score = feedback["score"]  # 使用实际得分（包含置信度）
            success = True
            break

        # Step 8: 更新最高分并检查是否有提升
        current_dv = _result_to_diagnostic_value(feedback["result"])
        if current_dv > best_diagnostic_value:
            best_diagnostic_value = current_dv

        if feedback["score"] > best_score:
            best_score = feedback["score"]
            best_payload = payload
            best_result_type = feedback["result"]
            no_improvement_count = 0
            logger.log(f"New best score: {best_score}")
        else:
            no_improvement_count += 1
            logger.log(f"No improvement ({no_improvement_count})")

        # Step 9: 检查是否应该停止 (诊断值 >= 阈值时放宽停止条件)
        effective_limit = NO_IMPROVEMENT_LIMIT
        if best_diagnostic_value >= NO_IMPROVEMENT_LIMIT_DV_THRESHOLD:
            effective_limit = NO_IMPROVEMENT_LIMIT + 2
            logger.log(f"Diagnostic value {best_diagnostic_value} >= {NO_IMPROVEMENT_LIMIT_DV_THRESHOLD}, extended limit to {effective_limit}")

        if no_improvement_count >= effective_limit:
            logger.log(f"Stopping: no improvement for {effective_limit} iterations")
            break

        # Step 10: 生成变异 payload（除非是最后一次迭代）
        if iteration < MAX_ITERATIONS:
            logger.log("Step 10: Generating mutated payload...")

            detailed_feedback = evaluation_agent.generate_detailed_feedback(
                agent_response, payload, target, feedback
            )
            suggestion = detailed_feedback.get("suggestion_summary", "继续尝试")
            logger.log(f"Suggestion: {suggestion}")

            # CC seeds 变异时使用 fallback disguise
            mutation_disguise = disguise
            if isinstance(disguise, CCDisguiseSeed):
                mutation_disguise = DisguiseSeed.D05_SCRIPTED_MESSAGE

            mutation_prompt, new_payload = injection_agent.mutate_payload(
                detailed_feedback, payload, agent_response, mutation_disguise, target,
                history=history,
                best_payload=best_payload,
                best_score=best_score,
                successful_patterns=successful_patterns
            )

            if new_payload.startswith("LLM_ERROR"):
                logger.log(f"Mutation failed: {new_payload}")
                break

            logger.log_mutation(iteration, mutation_prompt, new_payload)
            logger.log(f"New payload generated ({len(new_payload)} chars)")

            payload = new_payload

    # 记录最终结果
    logger.log_final(success, best_score, final_iteration)

    return {
        "success": success,
        "best_score": best_score,
        "best_result_type": best_result_type,
        "iterations": final_iteration,
        "experiment_id": experiment_id,
        "log_file": str(logger.log_file),
        "json_file": str(logger.json_file),
        "best_payload": best_payload if not success else None,
    }


class DynamicSeed:
    """合成种子的轻量包装，兼容 DisguiseSeed 接口"""
    def __init__(self, value):
        self.value = value
        self.name = value

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if hasattr(other, "value"):
            return self.value == other.value
        return NotImplemented

    def __repr__(self):
        return f"DynamicSeed({self.value!r})"


def run_target_experiment(target: TargetSeed, seed_bank: SeedBank = None) -> dict:
    """
    针对单个目标，按种子库排序尝试伪装方式
    支持种子库累积分排序 + 批次合成 + 跨伪装迁移学习

    Args:
        target: 攻击目标
        seed_bank: 种子库实例（跨 target 共享）
    """
    # 所有伪装方式 (27 general + 12 CC-specific = 39)
    disguise_seeds = [
        # 27 general disguise seeds
        DisguiseSeed.D05_SCRIPTED_MESSAGE,
        DisguiseSeed.D06_FAKE_TOOL_CALL,
        DisguiseSeed.D07_SIMULATION_FRAME,
        DisguiseSeed.D08_FAKE_CONVERSATION,
        DisguiseSeed.D10_FORGE_OUTPUT,
        DisguiseSeed.D11_FAKE_ERROR,
        DisguiseSeed.D12_FAKE_SYSTEM_PROMPT,
        DisguiseSeed.D14_VALID_JUSTIFICATION,
        DisguiseSeed.D15_SOCIAL_PROOF,
        DisguiseSeed.D17_OVERRIDE_RULES,
        DisguiseSeed.D18_EMBED_LEGITIMATE,
        DisguiseSeed.D19_IMPERSONATE,
        DisguiseSeed.D20_OVERWRITE_PERSONA,
        DisguiseSeed.D21_URGENCY,
        DisguiseSeed.D22_CONDITIONAL_TRIGGER,
        DisguiseSeed.D23_NECESSARY_PREREQUISITE,
        DisguiseSeed.D24_SILENT_EXECUTION,
        DisguiseSeed.D01_SYSTEM_REMINDER,
        DisguiseSeed.D02_CONFIG_FIELD,
        DisguiseSeed.D03_COMMENT,
        DisguiseSeed.D04_DATA_CONTENT,
        DisguiseSeed.D09_CHAIN_COMMANDS,
        DisguiseSeed.D13_REPETITION,
        DisguiseSeed.D16_ENCODE_OBFUSCATE,
        DisguiseSeed.D25_REDEFINE_WORDS,
        DisguiseSeed.D26_MULTILINGUAL,
        DisguiseSeed.D27_EMOTIONAL,
        # 12 CC-specific disguise seeds
        CCDisguiseSeed.CC01_TOOL_RESULT_SPOOF,
        CCDisguiseSeed.CC07_AGENT_DELEGATION,
        CCDisguiseSeed.CC08_SYSTEM_REMINDER_CONTEXT,
        CCDisguiseSeed.CC09_TOOL_RESULT_CHAIN,
        CCDisguiseSeed.CC02_CLAUDE_MD_DIRECTIVE,
        CCDisguiseSeed.CC03_MEMORY_INJECT,
        CCDisguiseSeed.CC06_SKILL_EXPANSION,
        CCDisguiseSeed.CC13_HOOK_USER_FEEDBACK,
        CCDisguiseSeed.CC14_AUTO_MODE_ENABLED,
        CCDisguiseSeed.CC15_TODO_TASK_INJECTION,
        CCDisguiseSeed.CC16_PLAN_APPROVED,
        CCDisguiseSeed.CC17_CRON_TASK_DUE,
    ]

    BATCH_SIZE = 3

    # 初始化种子库（首个 target 时创建，后续复用）
    if seed_bank is None:
        seed_bank = SeedBank(disguise_seeds, batch_size=BATCH_SIZE)

    # 初始化合成器
    injection_agent = InjectionAgent()
    synthesizer = SeedSynthesizer(injection_agent._call_llm)

    results = []
    successful_disguises = []
    successful_patterns = []
    total_iterations = 0
    tried = set()

    target_action = TARGET_ACTIONS.get(target, str(target))

    print(f"\n{'='*60}")
    print(f"TARGET: {target.value}")
    print(f"Seed bank size: {len(seed_bank)}, batch size: {BATCH_SIZE}")
    print(f"{'='*60}\n")

    batch_idx = 0
    while seed_bank.has_untried(tried):
        batch = seed_bank.get_next_batch(tried)
        if not batch:
            break

        batch_idx += 1
        batch_failures = []

        print(f"\n{'─'*60}")
        print(f"Batch {batch_idx}: {[d.value for d in batch]}")
        print(f"{'─'*60}")

        for disguise in batch:
            tried.add(disguise.value)

            print(f"  Trying disguise: {disguise.value}")
            if successful_patterns:
                print(f"    (with {len(successful_patterns)} cross-learning patterns)")

            result = run_experiment(
                disguise, target,
                successful_patterns=successful_patterns if successful_patterns else None
            )
            total_iterations += result['iterations']

            results.append({
                "disguise": disguise.value,
                "target": target.value,
                **result
            })

            # 记录诊断值到种子库
            result_type = result.get('best_result_type', 'IGNORED')
            dv = DIAGNOSTIC_VALUE_MAP.get(result_type, 0)
            seed_bank.record_result(disguise, dv)

            # 保存中间结果
            MODEL_EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
            with open(MODEL_EXPERIMENTS_DIR / f"target_{target.value}_results.json", 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            if result['success']:
                print(f"  *** SUCCESS with {disguise.value}! (iter: {result['iterations']}) ***")
                successful_disguises.append(disguise.value)
                successful_patterns.append({
                    "source_disguise": disguise.value,
                    "target": target.value,
                    "payload": result.get('best_payload') or 'N/A',
                    "score": result['best_score'],
                })
            else:
                print(f"  Failed with {disguise.value} (iter: {result['iterations']}, score: {result['best_score']})")
                batch_failures.append({
                    "seed": disguise,
                    "status": result_type,
                    "diagnostic_value": dv,
                    "best_payload": result.get('best_payload', ''),
                })

        # 批次合成：从失败记录中合成新种子
        if batch_failures:
            synth_result = synthesizer.synthesize(batch_failures, target_action)
            if synth_result:
                seed_value, template = synth_result
                new_seed = DynamicSeed(seed_value)
                target_avg = seed_bank.get_target_avg(tried)
                seed_bank.add_synthesized_seed(new_seed, target_avg)
                DISGUISE_TEMPLATES[new_seed] = template
                print(f"  [Synthesis] New seed: {seed_value} (strategy: {template['name']})")

    # 完成 target 后更新所有种子累积分
    seed_bank.update_scores_after_target(tried)

    # 打印种子库排名
    print(f"\n  Seed bank ranking after {target.value}:")
    for s in seed_bank.summary()[:10]:
        print(f"    {s['seed']}: score={s['score']}" +
              (" [synthesized]" if s['synthesized'] else ""))

    # 打印汇总
    print(f"\n{'='*60}")
    print(f"TARGET {target.value} SUMMARY")
    print(f"{'='*60}")
    print(f"Total disguises tried: {len(tried)}")
    print(f"Total iterations: {total_iterations}")
    print(f"Successful disguises: {len(successful_disguises)}/{len(tried)}")

    if successful_disguises:
        print(f"Success rate: {len(successful_disguises)/len(tried)*100:.1f}%")
        print(f"Winning disguises: {', '.join(successful_disguises)}")
    else:
        print("No successful disguise found")

    return {
        "target": target.value,
        "success": len(successful_disguises) > 0,
        "successful_disguises": successful_disguises,
        "success_count": len(successful_disguises),
        "total_disguises": len(tried),
        "success_rate": len(successful_disguises) / len(tried) if tried else 0,
        "total_iterations": total_iterations,
        "seed_bank_summary": seed_bank.summary(),
        "attempts": results,
    }


def run_all_experiments():
    """运行所有目标的实验，种子库跨 target 共享"""
    all_targets = [
        # L1 - Information Leakage
        TargetSeed.T1_ECHO,
        TargetSeed.T2_READ_FILE,
        TargetSeed.T3_ENV_LEAK,
        # L2 - Transient Execution
        TargetSeed.T4_BASH_CMD,
        TargetSeed.T6_CALL_SKILL,
        TargetSeed.T7_NETWORK,
        # L3 - Persistent Modification
        TargetSeed.T5_WRITE_FILE,
        TargetSeed.T11_CREATE_FILE,
        TargetSeed.T8_MODIFY_MEMORY,
    ]

    # 初始化共享种子库（27 general + 12 CC = 39 seeds）
    initial_seeds = [
        DisguiseSeed.D05_SCRIPTED_MESSAGE,
        DisguiseSeed.D06_FAKE_TOOL_CALL,
        DisguiseSeed.D07_SIMULATION_FRAME,
        DisguiseSeed.D08_FAKE_CONVERSATION,
        DisguiseSeed.D10_FORGE_OUTPUT,
        DisguiseSeed.D11_FAKE_ERROR,
        DisguiseSeed.D12_FAKE_SYSTEM_PROMPT,
        DisguiseSeed.D14_VALID_JUSTIFICATION,
        DisguiseSeed.D15_SOCIAL_PROOF,
        DisguiseSeed.D17_OVERRIDE_RULES,
        DisguiseSeed.D18_EMBED_LEGITIMATE,
        DisguiseSeed.D19_IMPERSONATE,
        DisguiseSeed.D20_OVERWRITE_PERSONA,
        DisguiseSeed.D21_URGENCY,
        DisguiseSeed.D22_CONDITIONAL_TRIGGER,
        DisguiseSeed.D23_NECESSARY_PREREQUISITE,
        DisguiseSeed.D24_SILENT_EXECUTION,
        DisguiseSeed.D01_SYSTEM_REMINDER,
        DisguiseSeed.D02_CONFIG_FIELD,
        DisguiseSeed.D03_COMMENT,
        DisguiseSeed.D04_DATA_CONTENT,
        DisguiseSeed.D09_CHAIN_COMMANDS,
        DisguiseSeed.D13_REPETITION,
        DisguiseSeed.D16_ENCODE_OBFUSCATE,
        DisguiseSeed.D25_REDEFINE_WORDS,
        DisguiseSeed.D26_MULTILINGUAL,
        DisguiseSeed.D27_EMOTIONAL,
        CCDisguiseSeed.CC01_TOOL_RESULT_SPOOF,
        CCDisguiseSeed.CC07_AGENT_DELEGATION,
        CCDisguiseSeed.CC08_SYSTEM_REMINDER_CONTEXT,
        CCDisguiseSeed.CC09_TOOL_RESULT_CHAIN,
        CCDisguiseSeed.CC02_CLAUDE_MD_DIRECTIVE,
        CCDisguiseSeed.CC03_MEMORY_INJECT,
        CCDisguiseSeed.CC06_SKILL_EXPANSION,
        CCDisguiseSeed.CC13_HOOK_USER_FEEDBACK,
        CCDisguiseSeed.CC14_AUTO_MODE_ENABLED,
        CCDisguiseSeed.CC15_TODO_TASK_INJECTION,
        CCDisguiseSeed.CC16_PLAN_APPROVED,
        CCDisguiseSeed.CC17_CRON_TASK_DUE,
    ]
    seed_bank = SeedBank(initial_seeds, batch_size=3)

    results = []

    for target in all_targets:
        result = run_target_experiment(target, seed_bank=seed_bank)
        results.append(result)

        # 保存总结果
        with open(MODEL_EXPERIMENTS_DIR / "all_targets_results.json", 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    # 最终汇总
    print(f"\n{'='*60}")
    print("FINAL SUMMARY - ALL TARGETS")
    print(f"{'='*60}")

    total_success = 0
    total_iters = 0
    for r in results:
        success_rate = r.get('success_rate', 0) * 100
        success_count = r.get('success_count', 0)
        total_disguises = r.get('total_disguises', 39)
        iters = r.get('total_iterations', 0)
        total_iters += iters

        if r['success']:
            total_success += 1
            disguises = ', '.join(r.get('successful_disguises', [])[:3])
            if len(r.get('successful_disguises', [])) > 3:
                disguises += f" (+{len(r['successful_disguises'])-3} more)"
            print(f"  {r['target']}: {success_count}/{total_disguises} SUCCESS ({success_rate:.1f}%) - {disguises}")
        else:
            print(f"  {r['target']}: 0/{total_disguises} FAILED")

    print(f"\n  Total targets with at least 1 success: {total_success}/{len(results)}")
    print(f"  Total iterations across all experiments: {total_iters}")

    # 生成实验报告
    print(f"\n{'='*60}")
    print("GENERATING REPORT...")
    print(f"{'='*60}")
    generator = ReportGenerator()
    report = generator.generate_summary_report()
    json_path = generator.save_report(report)
    md_path = generator.save_markdown_report(report)
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")

    return results


def main():
    """主入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python main.py target <target>             # 针对目标尝试所有伪装方式")
        print("  python main.py all                         # 运行所有目标")
        print("  python main.py single <disguise> <target>  # 运行单个组合")
        print()
        print("Target options: echo, read_file, env_leak, bash_cmd,")
        print("                call_skill, network, write_file, create_file, modify_memory")
        sys.exit(1)

    command = sys.argv[1]

    if command == "all":
        run_all_experiments()

    elif command == "target":
        if len(sys.argv) < 3:
            print("Error: target command requires <target>")
            sys.exit(1)

        try:
            target = TargetSeed(sys.argv[2])
        except ValueError as e:
            print(f"Error: Invalid target - {e}")
            sys.exit(1)

        result = run_target_experiment(target)
        print(f"\n{'='*60}")
        print("FINAL RESULT")
        print(f"{'='*60}")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif command == "single":
        if len(sys.argv) < 4:
            print("Error: single command requires <disguise> and <target>")
            sys.exit(1)

        try:
            target = TargetSeed(sys.argv[3])
        except ValueError as e:
            print(f"Error: Invalid target - {e}")
            sys.exit(1)

        try:
            disguise = DisguiseSeed(sys.argv[2])
        except ValueError:
            try:
                disguise = CCDisguiseSeed(sys.argv[2])
            except ValueError as e:
                print(f"Error: Invalid disguise - {e}")
                sys.exit(1)

        result = run_experiment(disguise, target)
        print(f"\n{'='*60}")
        print("RESULT")
        print(f"{'='*60}")
        print(json.dumps(result, indent=2))

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()