"""Single-case inner loop (paper §4.2, Algorithm 1; plan §4.2)."""

from __future__ import annotations

from collections.abc import Callable

from .types import (
    Attempt, AttemptResult, Evaluator, ExecutionFailure, FeedbackStatus,
    InnerLoopConfiguration, OptimizationResult, PayloadOptimizer, SeedContext,
    StopReason, TargetSpec, Trace,
)


def _failure(exc: Exception, kind: str) -> ExecutionFailure:
    reported = getattr(exc, "failure", None)
    if isinstance(reported, ExecutionFailure):
        return reported
    # Raw third-party exceptions may contain credentials/headers. Detailed model
    # errors belong in the client's sanitized call record, not this generic layer.
    return ExecutionFailure(kind, f"{type(exc).__name__} during {kind}")


def run_optimizer(
    target: TargetSpec,
    seed: SeedContext,
    initial_payload: str,
    evaluator: Evaluator,
    optimizer: PayloadOptimizer,
    config: InnerLoopConfiguration,
    reference_successes: tuple[str, ...] = (),
    *,
    on_attempt: Callable[[Attempt], None] | None = None,
) -> OptimizationResult:
    if not isinstance(initial_payload, str) or not initial_payload.strip():
        raise ValueError("initial_payload must be nonempty text")
    attempts: list[Attempt] = []
    best: Attempt | None = None
    best_value = 0
    stale = 0
    optimizer_calls = 0
    payload = initial_payload

    def finish(reason: StopReason, failure: ExecutionFailure | None = None) -> OptimizationResult:
        return OptimizationResult(tuple(attempts), best, reason, optimizer_calls, failure)

    for index in range(config.max_iterations):
        try:
            evaluated = evaluator.evaluate(payload)
            if not isinstance(evaluated, AttemptResult):
                raise TypeError("Evaluator must return AttemptResult")
        except Exception as exc:
            evaluated = AttemptResult(failure=_failure(exc, "evaluator_error"),
                                      trace=Trace(data={"exception_type": type(exc).__name__}))
        current = Attempt(index, payload, evaluated)
        attempts.append(current)
        # A failed write propagates immediately; further work without a durable
        # attempt record would violate the run's audit contract.
        if on_attempt is not None:
            on_attempt(current)
        if evaluated.failure is not None:
            return finish(StopReason.EXECUTION_FAILURE, evaluated.failure)

        feedback = evaluated.feedback
        assert feedback is not None  # AttemptResult guarantees exclusivity.
        if feedback.status is FeedbackStatus.SUCCESS:
            best = current
            return finish(StopReason.SUCCESS)
        if best is None:
            best = current
        if feedback.value > best_value:
            best_value = feedback.value
            best = current
            stale = 0
        else:
            stale += 1
        effective_patience = config.patience + (
            config.patience_extension if best_value >= config.relax_at_value else 0)
        if stale >= effective_patience:
            return finish(StopReason.PATIENCE)
        if index + 1 == config.max_iterations:
            return finish(StopReason.ITERATION_LIMIT)

        optimizer_calls += 1
        try:
            next_payload = optimizer.refine(target, seed, current,
                                            tuple(attempts[:-1]), reference_successes)
            if not isinstance(next_payload, str) or not next_payload.strip():
                return finish(StopReason.EXECUTION_FAILURE,
                              ExecutionFailure("optimizer_empty_output", "Optimizer returned no payload"))
            payload = next_payload
        except Exception as exc:
            return finish(StopReason.EXECUTION_FAILURE, _failure(exc, "optimizer_error"))

    raise AssertionError("positive iteration budget must produce an attempt")
