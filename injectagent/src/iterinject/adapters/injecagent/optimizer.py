"""InjecAgent optimizer preset, adapted from the local mutation engine.

Benchmark tool/context fields stay here; the generic renderer only handles
the complete payload/feedback records and explicit seed/reference inputs.
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from ...core.types import Attempt, ExecutionFailure, SeedContext, TargetSpec
from ...models import ModelCallError
from ...prompts.render import PromptOptimizer, render_optimizer_prompt
from .dataset import INJECTION_PROTOCOL, InjecAgentCase


class InjecAgentPromptOptimizer(PromptOptimizer):
    def __init__(self, client: Any, case: InjecAgentCase,
                 tools: dict[str, dict[str, Any]], template_path: str | Path | None = None):
        package = files(__package__)
        super().__init__(client, template_path=template_path if template_path is not None else
                         package.joinpath("optimizer.txt"))
        self.case = case
        # Freeze the benchmark context independently of subsequent caller changes.
        self.context = json.dumps({
            "attack": case.attack,
            "user_tool": case.raw["User Tool"],
            "attacker_tools": [tools[name] for name in case.raw["Attacker Tools"]],
            "tool_response_template": case.raw["Tool Response Template"],
            "injection_protocol": INJECTION_PROTOCOL,
        }, ensure_ascii=False)
        self.template_info["adapter"] = "injecagent"
        self.template_info["context"] = json.loads(self.context)
        if template_path is None:
            self.template_info.update(json.loads(package.joinpath("preset.json").read_text(encoding="utf-8")))

    def refine(self, target: TargetSpec, seed: SeedContext, latest: Attempt,
               history: tuple[Attempt, ...], reference_successes: tuple[str, ...]) -> str:
        if target.target_id != self.case.case_id or target.objective != self.case.objective:
            raise ValueError("optimizer target must match its InjecAgent case")
        body = render_optimizer_prompt(self.template, target, seed, latest, history,
                                       reference_successes)
        prompt = f"[InjecAgent Context]\n{self.context}\n\n{body}"
        output = self.client.complete([{"role": "user", "content": prompt}])
        if not isinstance(output, str) or not output.strip():
            raise ModelCallError(ExecutionFailure(
                "empty_model_response", "Optimizer returned no payload text."))
        # No quote/fence stripping or 500-character truncation.
        return output
