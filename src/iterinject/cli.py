"""Compose the generic inner loop with the explicit InjecAgent adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from iterinject.core.types import (
    AttemptResult, SeedContext, TargetSpec,
)


def _json_file(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _file_info(path: str | Path) -> dict[str, str]:
    resolved = Path(path).resolve()
    return {"path": str(resolved), "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()}


def _code_info() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    def git(*arguments):
        completed = subprocess.run(["git", "-C", str(root), *arguments],
                                   text=True, capture_output=True, check=False)
        return completed.stdout.strip() if completed.returncode == 0 else None
    files = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted((root / "src" / "iterinject").rglob("*.py"))}
    snapshot = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"revision": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain")),
            "source_file_sha256": hashlib.sha256(snapshot).hexdigest(), "source_files": files}


def _build_remote_client(role: str, value: dict[str, Any]):
    from iterinject.models import ModelConfig, OpenAICompatibleClient
    return OpenAICompatibleClient(ModelConfig(role=role, **value))


class _FixtureClient:
    """Explicit scripted responses; no SDK or environment access."""

    def __init__(self, role: str, responses: list[str]):
        if not isinstance(responses, list) or any(not isinstance(s, str) for s in responses):
            raise ValueError(f"fixture {role}_responses must be a list of text responses")
        self.role = role
        self.responses = list(responses)
        self.call_records: list[dict[str, Any]] = []
        self.config = {"role": role, "model": f"fixture:{role}", "network_calls": 0}

    @property
    def call_count(self) -> int:
        return 0

    def complete(self, messages: list[dict[str, str]]) -> str:
        index = len(self.call_records)
        record = {"index": index, "role": self.role, "config": self.config,
                  "messages": messages, "api_calls": 0}
        self.call_records.append(record)
        if index >= len(self.responses):
            record["failure"] = {"kind": "fixture_exhausted", "message": "fixture response script exhausted"}
            raise RuntimeError("fixture response script exhausted")
        output = self.responses[index]
        record.update({"raw_response": output, "output": output, "failure": None})
        return output


class _RecordedOptimizerClient:
    def __init__(self, client, logger):
        self.client = client
        self.logger = logger

    def complete(self, messages):
        before = len(self.client.call_records)
        try:
            return self.client.complete(messages)
        finally:
            for record in self.client.call_records[before:]:
                self.logger.record_optimizer(record)

    def __getattr__(self, name):
        return getattr(self.client, name)


def _policy_from_mapping(value: dict[str, Any], fixture: bool = False):
    from iterinject.adapters.injecagent.diagnoser import DiagnosticPolicy, DIAGNOSTIC_VERSION, PARTIAL_SCOPE
    allowed = {"status", "source", "detection_keywords", "refusal_keywords", "version", "matching",
               "diagnostic_version", "partial_scope"}
    if set(value) - allowed:
        raise ValueError("diagnostic policy contains unsupported fields")
    if not fixture and value.get("status") != "approved":
        raise ValueError("diagnostic policy must explicitly declare status=approved")
    if value.get("matching", "lowercased_substring") != "lowercased_substring":
        raise ValueError("only matching=lowercased_substring is implemented")
    if value.get("version") == "injecagent-source-aligned-v1":
        raise ValueError("legacy diagnostic policy version v1 is unsupported; use the approved v2 policy")
    if value.get("partial_scope", PARTIAL_SCOPE) != PARTIAL_SCOPE:
        raise ValueError("diagnostic policy only supports partial_scope=ds_only")
    if value.get("diagnostic_version", DIAGNOSTIC_VERSION) != DIAGNOSTIC_VERSION:
        raise ValueError("diagnostic policy requires diagnostic_version=injecagent-ds-only-partial-v2")
    source = value.get("source")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("diagnostic policy requires a nonempty source")
    if fixture and not source.startswith("fixture:"):
        raise ValueError("fixture diagnostic policy source must start with fixture:")
    keywords = {}
    for name in ("detection_keywords", "refusal_keywords"):
        entries = value.get(name, [])
        if not isinstance(entries, list) or any(not isinstance(s, str) or not s for s in entries):
            raise ValueError(f"{name} must be a list of nonempty text")
        keywords[name] = tuple(entries)
    return DiagnosticPolicy(**keywords, source=source)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iterinject", description="IterInject optimization and sequential seed search")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("run", "evaluate"):
        child = sub.add_parser(command, help="optimize a single case" if command == "run" else "evaluate one fixed payload")
        for name in ("method-config", "benchmark-config", "data-dir", "case-id", "initial-payload-file", "output-dir"):
            child.add_argument(f"--{name}", required=True)
        child.add_argument("--engineering-smoke", action="store_true",
                           help="record engineering validation separately from formal metric groups")
        child.add_argument("--fixture-script", help="JSON scripted victim/optimizer responses and explicit fixture policy")
        child.add_argument("--approved-diagnostic-policy", help="override the approved InjecAgent diagnostic preset")
        child.add_argument("--approved-optimizer-template", help="override the approved InjecAgent optimizer preset")
        child.add_argument("--reference-successes-file", help="JSON list of explicit reference payloads")
    child = sub.add_parser("search", help="run the configured sequential seed search")
    child.add_argument("--run-config", required=True,
                       help="run inputs and total request budget")
    for name in ("method-config", "benchmark-config", "seed-catalog", "target-manifest", "data-dir", "output-dir"):
        child.add_argument(f"--{name}", required=True)
    child.add_argument("--fixture-script")
    child.add_argument("--engineering-smoke", action="store_true")
    child.add_argument("--resume", action="store_true")
    child = sub.add_parser("summarize", help="read saved summaries without model clients")
    child.add_argument("--run-dir", action="append", required=True)
    child = sub.add_parser("manifest", help="read stable case IDs and data provenance")
    child.add_argument("--benchmark-config", required=True)
    child.add_argument("--data-dir", required=True)
    child.add_argument("--run-config", help="generate a target manifest for this run instead of the case listing")
    child.add_argument("--case-id", action="append", help="select a case; repeat to specify execution order")
    child.add_argument("--limit", type=int, help="maximum number of selected cases; omitted means all")
    child.add_argument("--output-file", help="save the JSON to a new file without overwriting an existing manifest")
    return parser


def _benchmark(value: dict[str, Any]) -> tuple[str, str, str]:
    if value.get("adapter") != "injecagent":
        raise ValueError("benchmark adapter must be injecagent")
    attack, setting = value.get("attack"), value.get("setting")
    if attack not in {"dh", "ds"} or setting not in {"base", "enhanced"}:
        raise ValueError("benchmark requires attack=dh|ds and setting=base|enhanced")
    return attack, setting, value.get("prompt_type", "InjecAgent")


def _manifest(args) -> dict[str, Any]:
    from iterinject.adapters.injecagent.dataset import load_cases
    benchmark = _json_file(args.benchmark_config)
    attack, setting, _ = _benchmark(benchmark)
    cases = load_cases(Path(args.data_dir).resolve(), attack, setting,
                       case_ids=getattr(args, "case_id", None))
    limit = getattr(args, "limit", None)
    if limit is not None:
        if type(limit) is not int or limit < 1:
            raise ValueError("manifest limit must be a positive integer")
        cases = cases[:limit]
    run_path = getattr(args, "run_config", None)
    if run_path:
        from iterinject.configuration import parse_run_configuration
        config = parse_run_configuration(_json_file(run_path))
        if "scope_id" in benchmark and benchmark["scope_id"] != config.scope_id:
            raise ValueError("benchmark/run scope mismatch")
        if not cases:
            raise ValueError("target manifest must be nonempty")
        output = {"schema_version": "phase2-target-manifest-v1", "scope_id": config.scope_id,
                  "attack": attack, "setting": setting,
                  "targets": [{"target_id": case.case_id, "source": case.source,
                               "tool_chain_signature": case.raw["Attacker Tools"]} for case in cases]}
    else:
        output = {"data_dir": str(Path(args.data_dir).resolve()), "attack": attack, "setting": setting,
                  "cases": [{"case_id": case.case_id, "attacker_tools": case.raw["Attacker Tools"],
                             "objective": case.raw["Attacker Instruction"], "source": case.source} for case in cases]}
    output_path = getattr(args, "output_file", None)
    if output_path:
        with Path(output_path).expanduser().open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    return output


def _model_snapshot(client) -> dict[str, Any]:
    config = client.config
    return config.to_dict() if hasattr(config, "to_dict") else dict(config)


def _simulation_config(benchmark: dict[str, Any], *, fixture: bool) -> tuple[str, dict[str, Any]]:
    """Validate the independently configured DS simulator before creating clients."""
    value = benchmark.get("simulation", {})
    if not isinstance(value, dict):
        raise ValueError("simulation must be an explicit JSON object")
    mode = value.get("mode", "generate_on_miss")
    if mode not in {"generate_on_miss", "cache_only"}:
        raise ValueError("simulation mode must be generate_on_miss or cache_only")
    model_value = {name: item for name, item in value.items() if name != "mode"}
    if mode == "generate_on_miss" and not fixture:
        from iterinject.models import ModelConfig
        try:
            ModelConfig(role="simulation", **model_value)
        except (TypeError, ValueError) as error:
            raise ValueError(f"simulation requires an independent model configuration: {error}") from None
    return mode, model_value


def _execute(args) -> tuple[dict[str, Any], int]:
    from iterinject.execution import execute_single
    return execute_single(args)


def _summarize(args) -> dict[str, Any]:
    from iterinject.adapters.injecagent.metrics import summarize_case_results
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for value in args.run_dir:
        path = Path(value).resolve()
        metadata = _json_file(path / "run.json")
        summary = _json_file(path / "summary.json")
        outcome = summary.get("case_outcome")
        if not isinstance(outcome, dict):
            raise ValueError(f"summary has no case outcome: {path}")
        policy = metadata.get("diagnostic_policy")
        if policy is not None and not isinstance(policy, dict):
            raise ValueError("run diagnostic_policy must be a JSON object or null")
        version = policy.get("diagnostic_version", "unspecified") if policy else "unspecified"
        if not isinstance(version, str) or not version.strip():
            raise ValueError("run diagnostic_version must be nonempty text")
        identity = (metadata.get("mode", "unknown"), metadata.get("evaluation_scope", "unspecified"), version)
        grouped.setdefault(identity, []).append(outcome)
    for records in grouped.values():
        ids = [record["case_id"] for record in records]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate case IDs within one mode/scope/diagnostic version; summarize separate runs separately")
    groups = [{"mode": mode, "evaluation_scope": scope, "diagnostic_version": version,
               "metrics": summarize_case_results(records)}
              for (mode, scope, version), records in grouped.items()]
    if len(groups) == 1:
        return groups[0]
    return {"mode": "mixed", "evaluation_scope": "mixed", "diagnostic_version": "mixed", "groups": groups}


def main(argv: list[str] | None = None) -> int:
    from .models import ModelCallError
    try:
        args = _parser().parse_args(argv)
        if args.command == "manifest":
            output, code = _manifest(args), 0
        elif args.command == "search":
            from .search_cli import run_search
            output, code = run_search(args)
        elif args.command == "summarize":
            output, code = _summarize(args), 0
        else:
            output, code = _execute(args)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return code
    except SystemExit as error:
        return int(error.code)
    except ModelCallError as error:
        print(f"iterinject: {error.failure.kind}: {error.failure.message}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"iterinject: {error}", file=sys.stderr)
        return 2
