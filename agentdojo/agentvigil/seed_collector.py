"""Collect seed prompts from AgentDojo's built-in attack templates."""

from __future__ import annotations

from agentdojo.task_suite.task_suite import TaskSuite

from iterinject.agentdojo_benchmark import STANDARD_INJECTION_TEMPLATES

# Attack template strings. Each uses {goal} as placeholder for the injection task goal.
ATTACK_TEMPLATES = STANDARD_INJECTION_TEMPLATES

def collect_seeds(
    suite: TaskSuite,
    attack_name: str | None = None,
    user_name: str = "Emma Johnson",
    model_name: str = "Qwen",
) -> list[dict]:
    """Generate the handcrafted benchmark prompt used to initialize AgentVigil."""
    seeds = []
    for inj_task_id, inj_task in suite.injection_tasks.items():
        goal = inj_task.GOAL
        fmt = dict(goal=goal, user=user_name, model=model_name)

        if attack_name and attack_name in ATTACK_TEMPLATES:
            # Attack-specific template
            prompt = ATTACK_TEMPLATES[attack_name].format(**fmt)
            seeds.append({
                "prompt": prompt,
                "template_name": attack_name,
                "injection_task_id": inj_task_id,
                "goal": goal,
            })
        elif attack_name is None:
            # All attacks (fallback)
            for atk_name, atk_tpl in ATTACK_TEMPLATES.items():
                prompt = atk_tpl.format(**fmt)
                seeds.append({
                    "prompt": prompt,
                    "template_name": atk_name,
                    "injection_task_id": inj_task_id,
                    "goal": goal,
                })
    return seeds
