"""Render complete optimizer evidence; bundled content is an opt-in draft."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from pathlib import Path
from string import Formatter
from typing import Any

from iterinject.core.types import Attempt, ExecutionFailure, SeedContext, TargetSpec
from iterinject.models import ModelCallError


_REQUIRED_FIELDS = frozenset({"seed_name", "seed_description", "objective", "history",
                              "latest", "reference_successes"})
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {"target_id", "seed_id"}


def _attempt_data(attempt: Attempt) -> dict[str, Any]:
    feedback = attempt.result.feedback
    if feedback is None:
        raise ValueError("optimizer input requires evaluated feedback, not execution failure")
    return {
        "attempt_index": attempt.attempt_index, "payload": attempt.payload,
        "status": feedback.status.value, "value": feedback.value, "reason": feedback.reason,
        "evidence": feedback.evidence, "response_text": feedback.response_text,
    }


def _validate_template(template: str) -> None:
    seen: set[str] = set()
    try:
        for _, field, spec, conversion in Formatter().parse(template):
            if field is None:
                continue
            if field not in _ALLOWED_FIELDS or spec or conversion:
                raise ValueError("optimizer template contains an unsupported field or format operation")
            seen.add(field)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid optimizer template fields") from error
    if not _REQUIRED_FIELDS <= seen:
        missing = ", ".join(sorted(_REQUIRED_FIELDS - seen))
        raise ValueError(f"optimizer template is missing required fields: {missing}")


def render_optimizer_prompt(template: str, target: TargetSpec, seed: SeedContext,
                            latest: Attempt, history: tuple[Attempt, ...],
                            reference_successes: tuple[str, ...]) -> str:
    _validate_template(template)
    if any(previous.attempt_index >= latest.attempt_index for previous in history):
        raise ValueError("history must contain only attempts before latest")
    values = {
        "target_id": target.target_id, "objective": target.objective,
        "seed_id": seed.seed_id, "seed_name": seed.name, "seed_description": seed.description,
        "history": json.dumps([_attempt_data(previous) for previous in history], ensure_ascii=False),
        "latest": json.dumps(_attempt_data(latest), ensure_ascii=False),
        "reference_successes": json.dumps(list(reference_successes), ensure_ascii=False),
    }
    # One formatting pass operates only on the trusted template; braces in values stay literal.
    return template.format_map(values)


class PromptOptimizer:
    """PayloadOptimizer implementation; explicit path does not claim paper provenance."""

    def __init__(self, client: Any, template_path: str | Path | None = None,
                 allow_draft: bool = False):
        self.client = client
        if template_path is not None:
            path = Path(template_path).expanduser().resolve()
            content = path.read_bytes()
            status = "explicit_unverified"
            source_path = str(path)
        elif allow_draft:
            resource = files("iterinject.prompts").joinpath("optimizer.txt")
            content = resource.read_bytes()
            status = "reconstruction_draft"
            source_path = str(resource)
        else:
            raise ValueError("Provide an explicit template_path or opt in with allow_draft=True.")
        self.template = content.decode("utf-8")
        _validate_template(self.template)
        self.template_info = {
            "status": status, "path": source_path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "source": "caller supplied" if template_path is not None else
                      "benchmark-independent draft extracted from the bundled InjecAgent optimizer template",
        }

    def refine(self, target: TargetSpec, seed: SeedContext, latest: Attempt,
               history: tuple[Attempt, ...], reference_successes: tuple[str, ...]) -> str:
        prompt = render_optimizer_prompt(self.template, target, seed, latest, history,
                                         reference_successes)
        output = self.client.complete([{"role": "user", "content": prompt}])
        if not isinstance(output, str) or not output.strip():
            raise ModelCallError(ExecutionFailure(
                "empty_model_response", "Optimizer returned no payload text."))
        return output
