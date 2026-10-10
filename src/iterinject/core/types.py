"""Generic contracts; no benchmark or model SDK imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class FeedbackStatus(str, Enum):
    SUCCESS = "Success"
    PARTIAL = "Partial"
    DETECTED = "Detected"
    IGNORED = "Ignored"


class StopReason(str, Enum):
    SUCCESS = "success"
    PATIENCE = "patience"
    ITERATION_LIMIT = "iteration_limit"
    EXECUTION_FAILURE = "execution_failure"


def _nonempty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonempty text")


@dataclass(frozen=True)
class TargetSpec:
    target_id: str
    objective: str

    def __post_init__(self) -> None:
        _nonempty(self.target_id, "target_id")
        _nonempty(self.objective, "objective")


@dataclass(frozen=True)
class SeedContext:
    seed_id: str
    name: str
    description: str


@dataclass(frozen=True)
class Feedback:
    status: FeedbackStatus
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    response_text: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, FeedbackStatus):
            raise ValueError("status must be a FeedbackStatus")
        _nonempty(self.reason, "reason")

    @property
    def value(self) -> int:
        return {FeedbackStatus.SUCCESS: 3, FeedbackStatus.PARTIAL: 2,
                FeedbackStatus.DETECTED: 1, FeedbackStatus.IGNORED: 0}[self.status]


@dataclass(frozen=True)
class ExecutionFailure:
    kind: str
    message: str


@dataclass(frozen=True)
class Trace:
    """Opaque serializable evidence and attempted client invocations by role.

    Actual API request counts are recorded separately by model clients: a
    fixture invocation or client initialization error need not send a request.
    """

    data: dict[str, Any] = field(default_factory=dict)
    calls: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if any(type(n) is not int or n < 0 for n in self.calls.values()):
            raise ValueError("call counts must be nonnegative integers")


@dataclass(frozen=True)
class AttemptResult:
    feedback: Feedback | None = None
    failure: ExecutionFailure | None = None
    trace: Trace = field(default_factory=Trace)

    def __post_init__(self) -> None:
        if (self.feedback is None) == (self.failure is None):
            raise ValueError("exactly one of feedback/failure is required")


@dataclass(frozen=True)
class Attempt:
    attempt_index: int
    payload: str
    result: AttemptResult


@dataclass(frozen=True)
class InnerLoopConfiguration:
    max_iterations: int
    patience: int
    relax_at_value: int = 1
    patience_extension: int = 0

    def __post_init__(self) -> None:
        for name in ("max_iterations", "patience"):
            n = getattr(self, name)
            if type(n) is not int or n < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.relax_at_value) is not int or not 0 <= self.relax_at_value <= 3:
            raise ValueError("relax_at_value must be in [0, 3]")
        if type(self.patience_extension) is not int or self.patience_extension < 0:
            raise ValueError("patience_extension must be a nonnegative integer")


@dataclass(frozen=True)
class OptimizationResult:
    attempts: tuple[Attempt, ...]
    best_attempt: Attempt | None
    stop_reason: StopReason
    optimizer_calls: int
    failure: ExecutionFailure | None = None

    @property
    def victim_calls(self) -> int:
        return sum(a.result.trace.calls.get("victim", 0) for a in self.attempts)


class Evaluator(Protocol):
    def evaluate(self, payload: str) -> AttemptResult: ...


class PayloadOptimizer(Protocol):
    def refine(self, target: TargetSpec, seed: SeedContext, latest: Attempt,
               history: tuple[Attempt, ...], reference_successes: tuple[str, ...]) -> str: ...
