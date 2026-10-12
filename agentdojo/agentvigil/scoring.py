"""Scoring: per-task ASR evaluation for AgentVigil."""

from __future__ import annotations

import json
import logging

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.task_suite import TaskSuite
from agentdojo.types import get_text_content_as_str

logger = logging.getLogger(__name__)

# Cache: (suite_name, user_task_id) -> list of visible injection vector IDs
_vector_cache: dict[tuple[str, str], list[str]] = {}


def _find_injection_vectors(suite: TaskSuite, user_task_id: str) -> list[str]:
    """Find injection vectors visible to the agent for a given user_task.

    Uses the same canary mechanism as BaseAttack.get_injection_candidates:
    inject canary strings into all vectors, run the user_task's ground truth,
    and check which canaries appear in tool responses.
    """
    cache_key = (suite.name, user_task_id)
    if cache_key in _vector_cache:
        return _vector_cache[cache_key]

    injection_defaults = suite.get_injection_vector_defaults()
    canary_injections = {inj: f"<CANARY---{inj}--->" for inj in injection_defaults}

    user_task = suite.get_user_task_by_id(user_task_id)
    gt_pipeline = GroundTruthPipeline(user_task)
    runtime = FunctionsRuntime(suite.tools)
    environment = suite.load_and_inject_default_environment(canary_injections)
    _, _, _, responses, _ = gt_pipeline.query(user_task.PROMPT, runtime, environment)

    candidates = []
    for inj in canary_injections:
        for response in responses:
            if response["content"] is not None and canary_injections[inj] in get_text_content_as_str(
                response["content"]
            ):
                candidates.append(inj)
                break

    if not candidates:
        candidates = list(injection_defaults.keys())[:1]

    _vector_cache[cache_key] = candidates
    return candidates


def evaluate_seed(
    seed_prompt: str,
    suite: TaskSuite,
    agent_pipeline: BasePipelineElement,
    user_task_id: str,
    injection_task_id: str,
    verbose: bool = False,
) -> dict:
    """Evaluate a seed prompt on a specific (user_task, injection_task) pair.

    Returns dict with: success, utility, error
    """
    user_task = suite.get_user_task_by_id(user_task_id)
    injection_task = suite.get_injection_task_by_id(injection_task_id)

    target_vectors = _find_injection_vectors(suite, user_task_id)

    # Escape for YAML double-quoted scalars (same as baseline)
    safe_prompt = json.dumps(seed_prompt, ensure_ascii=False)[1:-1]
    injections = {v: safe_prompt for v in target_vectors}

    try:
        utility, security = suite.run_task_with_pipeline(
            agent_pipeline, user_task, injection_task, injections, verbose=verbose
        )
        # security=True means injection succeeded (attack succeeded)
        success = security
        return {
            "success": success,
            "utility": utility,
            "error": None,
        }
    except Exception as e:
        if verbose:
            logger.warning(f"Task {user_task_id} failed: {e}")
        return {
            "success": False,
            "utility": False,
            "error": str(e),
        }
