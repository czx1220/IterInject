"""AgentVigil reproduction: MCTS-based fuzzing loop for indirect prompt injection.

Per-task evaluation: each seed/mutation is evaluated on a specific (user_task, injection_task) pair.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

from openai import OpenAI

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.task_suite.task_suite import TaskSuite

from .mcts import MCTSNode, MCTSTree
from .mutations import mutate
from .scoring import evaluate_seed
from .seed_collector import collect_seeds

logger = logging.getLogger(__name__)


@dataclass
class FuzzConfig:
    n_iterations: int = 7
    n_mutations_per_iter: int = 3
    exploration_constant: float = 1.414
    helper_model: str = "Qwen3-8B"
    temperature: float = 0.7
    logdir: Path | None = None
    helper_extra_body: dict | None = None


@dataclass
class FuzzResult:
    best_prompt: str
    best_score: float
    best_asr: float
    iteration_logs: list[dict] = field(default_factory=list)
    final_asr: float = 0.0
    final_ua: bool = False
    final_error: str | None = None


def run_fuzzing(
    suite: TaskSuite,
    user_task_id: str,
    injection_task_id: str,
    agent_pipeline: BasePipelineElement,
    helper_client: OpenAI,
    config: FuzzConfig | None = None,
    verbose: bool = False,
    attack_name: str | None = None,
) -> FuzzResult:
    """Run AgentVigil fuzzing on a specific (user_task, injection_task) pair."""
    config = config or FuzzConfig()

    # 1. Collect seeds for this injection_task and attack
    logger.info("Collecting seed prompts from AgentDojo templates...")
    seeds = collect_seeds(suite, attack_name=attack_name)
    seeds = [s for s in seeds if s["injection_task_id"] == injection_task_id]
    logger.info(f"Collected {len(seeds)} seed prompts for {injection_task_id} ({attack_name}).")

    if not seeds:
        logger.warning(f"No seeds found for {injection_task_id}")
        return FuzzResult(best_prompt="", best_score=0.0, best_asr=0.0)

    # 2. Initialize MCTS tree
    tree = MCTSTree.from_seeds(seeds)

    # 3. Initial evaluation of all seeds on the specific pair
    logger.info(f"Evaluating initial seed prompts on {user_task_id} x {injection_task_id}...")
    for node in tree.get_all_prompts():
        result = evaluate_seed(
            seed_prompt=node.prompt,
            suite=suite,
            agent_pipeline=agent_pipeline,
            user_task_id=user_task_id,
            injection_task_id=injection_task_id,
            verbose=verbose,
        )
        score = 1.0 if result["success"] else 0.0
        node.score = score
        tree.backpropagate(node, score)
        logger.info(f"  Seed [{node.metadata.get('template_name', '?')}] success={result['success']}")
        if result["success"]:
            logger.info("  Early stop: seed succeeded")

    iteration_logs = []
    found_success = any(n.score > 0 for n in tree.get_all_prompts())

    # 4. Main fuzzing loop
    for iteration in range(config.n_iterations):
        if found_success:
            break
        iter_start = time.time()
        logger.info(f"\n--- Iteration {iteration + 1}/{config.n_iterations} ---")

        # Select node to expand
        selected = tree.select(config.exploration_constant)
        logger.info(f"Selected seed (score={selected.score:.2f}, visits={selected.visits})")

        # Get crossover partner
        partner_node = tree.random_prompt(exclude=selected)
        partner_prompt = partner_node.prompt if partner_node else None

        # Generate mutations
        try:
            mutations = mutate(
                prompt=selected.prompt,
                helper_client=helper_client,
                helper_model=config.helper_model,
                crossover_partner=partner_prompt,
                n_mutations=config.n_mutations_per_iter,
                temperature=config.temperature,
                extra_body=config.helper_extra_body,
            )
        except Exception as e:
            logger.warning(f"Mutation failed: {e}")
            continue

        # Evaluate each mutation on the specific pair
        for mut_info in mutations:
            mut_prompt = mut_info["prompt"]
            mut_name = mut_info["mutation"]

            result = evaluate_seed(
                seed_prompt=mut_prompt,
                suite=suite,
                agent_pipeline=agent_pipeline,
                user_task_id=user_task_id,
                injection_task_id=injection_task_id,
                verbose=verbose,
            )
            score = 1.0 if result["success"] else 0.0

            child = selected.add_child(
                prompt=mut_prompt,
                score=score,
                metadata={
                    "mutation": mut_name,
                    "injection_task_id": injection_task_id,
                    "parent_template": selected.metadata.get("template_name", ""),
                },
            )
            tree.all_nodes.append(child)
            tree.backpropagate(child, score)

            logger.info(f"  [{mut_name}] success={result['success']}")
            if result["success"]:
                found_success = True
                break

        iter_duration = time.time() - iter_start
        best_so_far = tree.best_seed()
        iter_log = {
            "iteration": iteration + 1,
            "duration_s": round(iter_duration, 1),
            "selected_score": selected.score,
            "best_score": best_so_far.score,
            "n_mutations": len(mutations),
        }
        iteration_logs.append(iter_log)
        logger.info(f"  Iteration done in {iter_duration:.1f}s | Best score: {best_so_far.score:.2f}")

    # 5. Final evaluation of best prompt on the specific pair
    best_node = tree.best_seed()
    final_result = evaluate_seed(
        seed_prompt=best_node.prompt,
        suite=suite,
        agent_pipeline=agent_pipeline,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        verbose=verbose,
    )
    final_asr = 1.0 if final_result["success"] else 0.0
    logger.info(f"\nFinal result: success={final_result['success']} utility={final_result['utility']}")

    result = FuzzResult(
        best_prompt=best_node.prompt,
        best_score=best_node.score,
        best_asr=final_asr,
        iteration_logs=iteration_logs,
        final_asr=final_asr,
        final_ua=final_result["utility"],
        final_error=final_result.get("error"),
    )

    # Save results
    if config.logdir:
        _save_results(config.logdir, suite.name, user_task_id, injection_task_id, result, best_node, attack_name)

    return result


def _save_results(logdir: Path, suite_name: str, user_task_id: str, injection_task_id: str,
                  result: FuzzResult, best_node: MCTSNode, attack_name: str | None = None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if attack_name:
        out_dir = logdir / suite_name / user_task_id / attack_name / injection_task_id / timestamp
    else:
        out_dir = logdir / suite_name / user_task_id / injection_task_id / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "suite": suite_name,
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "best_prompt": result.best_prompt,
        "best_score": result.best_score,
        "best_asr": result.best_asr,
        "final_asr": result.final_asr,
        "final_ua": result.final_ua,
        "final_error": result.final_error,
        "best_metadata": best_node.metadata,
        "iterations": result.iteration_logs,
    }

    with open(out_dir / "result.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    with open(out_dir / "best_prompt.txt", "w") as f:
        f.write(result.best_prompt)

    logger.info(f"Results saved to {out_dir}")
