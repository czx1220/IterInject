"""Durable, complete single-run artifacts without model initialization."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
from typing import Any

from .types import Attempt, Feedback, FeedbackStatus, OptimizationResult


SCHEMA_VERSION = "1.0"


def serialize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        result = {f.name: serialize(getattr(value, f.name)) for f in fields(value)}
        if isinstance(value, Feedback):
            result["value"] = value.value
        return result
    if isinstance(value, dict):
        return {str(k): serialize(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [serialize(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _check_public_metadata(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {"api_key", "authorization", ".env", "env_contents",
                              "access_token", "secret", "password", "headers"}:
                raise ValueError(f"credential field is forbidden in run metadata: {key}")
            _check_public_metadata(item)
    elif isinstance(value, list):
        for item in value:
            _check_public_metadata(item)


def _json(value: Any) -> str:
    return json.dumps(serialize(value), ensure_ascii=False, allow_nan=False)


def _write_new(path: Path, value: Any) -> None:
    encoded = _json(value)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(encoded + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _append_record(path: Path, value: Any) -> None:
    encoded = _json(value)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(encoded + "\n")
        stream.flush()
        os.fsync(stream.fileno())


class RunLogger:
    def __init__(self, run_dir: str | Path, metadata: dict[str, Any]):
        public = serialize(metadata)
        _check_public_metadata(public)
        # Validate the whole snapshot before creating even an empty run directory.
        run = {**public, "schema_version": SCHEMA_VERSION,
               "created_at": datetime.now(timezone.utc).isoformat()}
        _json(run)
        self.run_dir = Path(run_dir).expanduser().resolve()
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.attempts_path = self.run_dir / "attempts.jsonl"
        _write_new(self.run_dir / "run.json", run)
        self.attempts_path.touch(exist_ok=False)
        (self.run_dir / "optimizer.jsonl").touch(exist_ok=False)

    def _append(self, attempt: Attempt) -> None:
        _append_record(self.attempts_path, attempt)

    def record_attempt(self, attempt: Attempt) -> None:
        self._append(attempt)

    def record_optimizer(self, record: dict[str, Any]) -> None:
        _check_public_metadata(serialize(record))
        _append_record(self.run_dir / "optimizer.jsonl", record)

    def finish(self, result: OptimizationResult, case_outcome: dict[str, Any], *,
               model_call_counts: dict[str, int] | None = None,
               model_interface_counts: dict[str, int] | None = None) -> None:
        first_success = next((a.attempt_index for a in result.attempts
                              if a.result.feedback is not None and
                              a.result.feedback.status is FeedbackStatus.SUCCESS), None)
        summary = {
            "schema_version": SCHEMA_VERSION,
            "stop_reason": result.stop_reason,
            "attempt_count": len(result.attempts),
            "best_attempt_index": result.best_attempt.attempt_index if result.best_attempt else None,
            "first_success_index": first_success,
            "optimizer_calls": result.optimizer_calls,
            "victim_calls": result.victim_calls,
            "model_call_counts": model_call_counts,
            "model_interface_counts": model_interface_counts,
            "failure": result.failure,
            "case_outcome": case_outcome,
        }
        _write_new(self.run_dir / "summary.json", summary)
