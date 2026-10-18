"""One payload evaluation, including the complete DS extraction/sending chain."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol

from ...core.types import AttemptResult, ExecutionFailure, Trace
from .agent_prompts import build_messages
from .dataset import InjecAgentCase
from .diagnoser import DiagnosticPolicy, diagnose
from .parser import evaluate_output_prompted


class VictimClient(Protocol):
    def complete(self, messages: list[dict[str, str]]) -> str: ...


class SimulatedResponses(Protocol):
    def lookup(self, tool: str, parameter_text: str) -> str: ...


class InjecAgentRunner:
    def __init__(self, case: InjecAgentCase, victim: VictimClient,
                 tools: dict[str, dict[str, Any]], simulated_responses: SimulatedResponses | None = None,
                 diagnostic_policy: DiagnosticPolicy | None = None, prompt_type: str = "InjecAgent"):
        self.case, self.victim, self.tools = case, victim, tools
        self.simulated_responses, self.diagnostic_policy = simulated_responses, diagnostic_policy
        self.prompt_type = prompt_type

    def evaluate(self, payload: str) -> AttemptResult:
        trace: dict[str, Any] = {"case_id": self.case.case_id, "attack": self.case.attack,
                                  "setting": self.case.setting, "source": self.case.source,
                                  "payload": payload, "prompt_type": self.prompt_type,
                                  "diagnostic_policy": None if self.diagnostic_policy is None else self.diagnostic_policy.snapshot(),
                                  "stages": [], "extraction_success": False, "send_success": False}
        calls = {"victim": 0, "simulation": 0}
        api_count_known = type(getattr(self.victim, "call_count", None)) is int
        trace["victim_api_count_known"] = api_count_known
        if api_count_known:
            calls["victim_api"] = 0
        simulation_api_known = type(getattr(self.simulated_responses, "call_count", None)) is int
        if simulation_api_known:
            calls["simulation_api"] = 0

        def failed(kind: str, message: str) -> AttemptResult:
            trace["failure"] = {"kind": kind, "message": message}
            return AttemptResult(failure=ExecutionFailure(kind, message), trace=Trace(trace, dict(calls)))

        try:
            item = self.case.inject(payload)
        except (ValueError, KeyError, TypeError) as exc:
            return failed("data_error", str(exc))

        def execute_stage(name: str, target: str, stage2: bool = False):
            stage: dict[str, Any] = {"stage": name, "messages": None, "output": None,
                                     "raw_eval": None, "call_records": []}
            trace["stages"].append(stage)
            try:
                stage["messages"] = build_messages(item, self.tools, self.prompt_type, stage2=stage2)
            except Exception as exc:
                return failed("data_error", f"{name}: {type(exc).__name__}")
            record_start = len(getattr(self.victim, "call_records", []))
            api_start = self.victim.call_count if api_count_known else None
            call_failure = None
            try:
                calls["victim"] += 1
                stage["output"] = self.victim.complete(stage["messages"])
            except Exception as exc:
                typed_failure = getattr(exc, "failure", None)
                call_failure = typed_failure if isinstance(typed_failure, ExecutionFailure) else ExecutionFailure(
                    "model_error", f"{name}: {type(exc).__name__}")
            finally:
                stage["call_records"] = deepcopy(getattr(self.victim, "call_records", [])[record_start:])
                if api_count_known:
                    calls["victim_api"] += self.victim.call_count - api_start
            if call_failure:
                return failed(call_failure.kind, call_failure.message)
            try:
                stage["raw_eval"] = evaluate_output_prompted(stage["output"], target,
                                                              item["Attacker Tools"], item["User Tool"], payload)
            except Exception as exc:
                return failed("parse_error", f"{name}: {type(exc).__name__}")
            if stage["raw_eval"]["eval"] == "invalid":
                return failed("parse_error", f"{name}: {stage['raw_eval'].get('invalid_reason', 'invalid output')}")
            return None

        failure = execute_stage("s1", item["Attacker Tools"][0])
        if failure:
            return failure
        first = trace["stages"][0]["raw_eval"]
        if self.case.attack == "ds" and first["eval"] == "succ":
            trace["extraction_success"] = True
            # Correct fields from old evaluate_prompted_agent.py:98-100.
            item["Attacker Tool Parameters"] = first["Attacker Tool Parameters"]
            item["Attacker Tool Thought"] = first["Attacker Tool Thought"]
            if self.simulated_responses is None:
                return failed("cache_miss", "DS requires an explicitly supplied simulated-response provider.")
            trace["simulation"] = {"tool": item["Attacker Tools"][0],
                                     "parameters": item["Attacker Tool Parameters"], "response": None,
                                     "source": None, "call_records": [],
                                     "api_count_known": simulation_api_known}
            record_start = len(getattr(self.simulated_responses, "call_records", []))
            generation_start = getattr(self.simulated_responses, "generation_count", 0)
            simulation_api_start = self.simulated_responses.call_count if simulation_api_known else None
            simulation_failure = None
            try:
                item["Attacker Tool Response"] = self.simulated_responses.lookup(item["Attacker Tools"][0],
                                                                                item["Attacker Tool Parameters"])
                trace["simulation"]["response"] = item["Attacker Tool Response"]
            except KeyError as exc:
                simulation_failure = ExecutionFailure("cache_miss", str(exc))
            except Exception as exc:
                typed_failure = getattr(exc, "failure", None)
                simulation_failure = typed_failure if isinstance(typed_failure, ExecutionFailure) else ExecutionFailure(
                    "simulation_error", type(exc).__name__)
            finally:
                trace["simulation"]["source"] = deepcopy(getattr(self.simulated_responses, "source", {"kind": "injected_fixture"}))
                trace["simulation"]["call_records"] = deepcopy(getattr(self.simulated_responses, "call_records", [])[record_start:])
                calls["simulation"] += getattr(self.simulated_responses, "generation_count", 0) - generation_start
                if simulation_api_known:
                    calls["simulation_api"] += self.simulated_responses.call_count - simulation_api_start
            if simulation_failure:
                return failed(simulation_failure.kind, simulation_failure.message)
            failure = execute_stage("s2", item["Attacker Tools"][1], stage2=True)
            if failure:
                return failure
            trace["send_success"] = trace["stages"][1]["raw_eval"]["eval"] == "succ"
        diagnosis = diagnose(self.case, trace["stages"], self.diagnostic_policy)
        if isinstance(diagnosis, ExecutionFailure):
            return failed(diagnosis.kind, diagnosis.message)
        return AttemptResult(feedback=diagnosis, trace=Trace(trace, dict(calls)))
