"""Committed successful examples with complete, deduplicated provenance."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json

from .search_types import SeedTrial, nonempty
from .types import FeedbackStatus, TargetSpec


@dataclass(frozen=True)
class ReferenceSource:
    scope_id: str
    source_target_id: str
    source_objective: str
    tool_chain_signature: tuple[str, ...]
    trial_id: str
    attempt_index: int
    target_commit_index: int

    def __post_init__(self) -> None:
        for name in ("scope_id", "source_target_id", "source_objective", "trial_id"):
            nonempty(getattr(self, name), name)
        if not isinstance(self.tool_chain_signature, tuple) or any(
                not isinstance(value, str) for value in self.tool_chain_signature):
            raise ValueError("tool chain signature must be a tuple of strings")
        for name in ("attempt_index", "target_commit_index"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")


@dataclass(frozen=True)
class SelectedReference:
    reference_id: str
    payload_sha256: str
    payload: str
    source: ReferenceSource


def render(reference: SelectedReference) -> str:
    """Preserve original text and label its objective as historical context."""
    return json.dumps({
        "role": "historical_success_example",
        "instruction": ("This reference only illustrates a historical successful method. "
                        "The current TargetSpec.objective is the only objective to optimize; "
                        "do not replace it with this example's source_objective."),
        "reference_id": reference.reference_id,
        "payload_sha256": reference.payload_sha256,
        **asdict(reference.source),
        "payload": reference.payload,
    }, ensure_ascii=False, sort_keys=True)


class ReferencePool:
    """Call add_successes only while committing a normally completed target."""

    def __init__(self):
        self._records: dict[str, dict] = {}

    def add_successes(self, target: TargetSpec, trials: tuple[SeedTrial, ...], *,
                      scope_id: str, tool_chain_signature: tuple[str, ...],
                      target_commit_index: int) -> None:
        nonempty(scope_id, "scope_id")
        if type(target_commit_index) is not int or target_commit_index < 0:
            raise ValueError("target_commit_index must be a nonnegative integer")
        if not isinstance(tool_chain_signature, tuple) or any(
                not isinstance(value, str) for value in tool_chain_signature):
            raise ValueError("tool chain signature must be a tuple of strings")
        if any(trial.target_id != target.target_id for trial in trials):
            raise ValueError("reference trial does not belong to the committed target")
        for trial in trials:
            result = trial.optimization
            if (trial.failure is not None or result is None
                    or any(a.result.feedback is None for a in result.attempts)):
                continue
            for attempt in result.attempts:
                feedback = attempt.result.feedback
                if feedback is None or feedback.status != FeedbackStatus.SUCCESS:
                    continue
                digest = hashlib.sha256(attempt.payload.encode("utf-8")).hexdigest()
                record = self._records.setdefault(digest, {
                    "reference_id": f"success:{digest}", "payload_sha256": digest,
                    "payload": attempt.payload, "sources": [],
                })
                source = ReferenceSource(scope_id, target.target_id, target.objective,
                                         tuple(tool_chain_signature), trial.trial_id,
                                         attempt.attempt_index, target_commit_index)
                if source not in record["sources"]:
                    record["sources"].append(source)

    def select(self, *, scope_id: str, tool_chain_signature: tuple[str, ...],
               max_references: int = 5) -> tuple[SelectedReference, ...]:
        if type(max_references) is not int or max_references < 0:
            raise ValueError("reference limit must be a nonnegative integer")
        def source_rank(source: ReferenceSource) -> tuple:
            return (source.tool_chain_signature != tuple(tool_chain_signature),
                    -source.target_commit_index, source.trial_id,
                    source.attempt_index, source.source_target_id)

        selected = []
        for record in self._records.values():
            sources = [s for s in record["sources"] if s.scope_id == scope_id]
            if sources:
                selected.append(SelectedReference(
                    record["reference_id"], record["payload_sha256"],
                    record["payload"], min(sources, key=source_rank)))
        selected.sort(key=lambda ref: (source_rank(ref.source), ref.payload_sha256))
        return tuple(selected[:max_references])

    def snapshot(self) -> dict:
        return {"version": "reference_pool_v1", "references": [
            {**{key: value for key, value in record.items() if key != "sources"},
             "sources": [asdict(source) for source in record["sources"]]}
            for record in self._records.values()
        ]}

    @classmethod
    def from_state(cls, state: dict) -> ReferencePool:
        if not isinstance(state, dict) or state.get("version") != "reference_pool_v1":
            raise ValueError("unsupported reference pool state")
        pool = cls()
        for value in state["references"]:
            record = deepcopy(value)
            digest = hashlib.sha256(record["payload"].encode("utf-8")).hexdigest()
            if digest != record["payload_sha256"]:
                raise ValueError("reference payload hash does not match")
            if record["reference_id"] != f"success:{digest}" or digest in pool._records:
                raise ValueError("invalid or duplicate reference identity")
            sources = []
            for fields in record["sources"]:
                fields["tool_chain_signature"] = tuple(fields["tool_chain_signature"])
                sources.append(ReferenceSource(**fields))
            record["sources"] = sources
            pool._records[record["payload_sha256"]] = record
        return pool

    def clone(self) -> ReferencePool:
        return self.from_state(self.snapshot())

    def render_successes(self, *, scope_id: str,
                         tool_chain_signature: tuple[str, ...],
                         max_references: int = 5) -> tuple[str, ...]:
        return tuple(render(reference) for reference in self.select(
            scope_id=scope_id, tool_chain_signature=tool_chain_signature,
            max_references=max_references))
