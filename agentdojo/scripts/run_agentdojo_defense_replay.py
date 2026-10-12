"""Replay successful DeepSeek AgentDojo attacks under AgentDojo defenses.

This script is for defense robustness experiments. It takes payloads that
already succeeded without defenses and re-evaluates them under each optional
AgentDojo defense, without re-optimizing the payload against the defense.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


SCRIPT_DIR = Path(__file__).parent
RELEASE_ROOT = SCRIPT_DIR.parent
RUNS_ROOT = RELEASE_ROOT / "runs"

load_dotenv(RELEASE_ROOT / ".env")

sys.path.insert(0, str(RELEASE_ROOT))

from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from iterinject.agentdojo_adapter import (  # noqa: E402
    FixedPayloadAttack,
    make_openai_compatible_pipeline,
    run_injected_task,
)


from iterinject.agentdojo_benchmark import format_standard_injection  # noqa: E402

DEFAULT_DEFENSES = [
    "tool_filter",
    "transformers_pi_detector",
    "spotlighting_with_delimiting",
    "repeat_user_prompt",
]


@dataclass(frozen=True)
class ReplayCase:
    method: str
    suite_name: str
    user_task_id: str
    attack_type: str
    injection_task_id: str
    payload: str
    source_path: str
    source_methods: tuple[str, ...] = ()
    source_paths: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.method,
            self.suite_name,
            self.user_task_id,
            self.attack_type,
            self.injection_task_id,
        )

    @property
    def payload_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.suite_name,
            self.user_task_id,
            self.attack_type,
            self.injection_task_id,
            self.payload,
        )

    @property
    def methods(self) -> tuple[str, ...]:
        return self.source_methods or (self.method,)

    @property
    def paths(self) -> tuple[str, ...]:
        return self.source_paths or (self.source_path,)


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "success"}
    return False


def first_iteration_success(payload: dict[str, Any]) -> bool:
    history = payload.get("iteration_history") or []
    if history:
        first = history[0]
        return bool_value(first.get("attack_success")) or first.get("result") == "SUCCESS"
    if int(payload.get("iterations") or 0) == 1:
        return bool_value(payload.get("attack_success"))
    return False


def latest_agentvigil_results(root: Path) -> dict[tuple[str, str, str, str], Path]:
    latest: dict[tuple[str, str, str, str], tuple[str, Path]] = {}
    for path in root.rglob("result.json"):
        rel = path.relative_to(root).parts
        if len(rel) < 6:
            continue
        key = rel[:-2]
        timestamp = rel[-2]
        if key not in latest or timestamp > latest[key][0]:
            latest[key] = (timestamp, path)
    return {key: path for key, (_, path) in latest.items()}


def standard_payload(benchmark_version: str, suite_name: str, attack_type: str, injection_task_id: str) -> str:
    suite = get_suite(benchmark_version, suite_name)
    goal = suite.get_injection_task_by_id(injection_task_id).GOAL
    return format_standard_injection(attack_type, goal)


def collect_handcraft_cases(iterinject_root: Path, benchmark_version: str) -> list[ReplayCase]:
    cases = []
    for path in sorted(iterinject_root.glob("*/*/*/*.json")):
        payload = json.loads(path.read_text())
        if not first_iteration_success(payload):
            continue
        suite_name = payload.get("suite_name") or path.parts[-5]
        attack_type = payload.get("baseline_attack") or payload.get("attack_type") or path.parts[-2]
        injection_task_id = payload.get("injection_task_id") or path.stem
        cases.append(
            ReplayCase(
                method="handcraft",
                suite_name=suite_name,
                user_task_id=payload.get("user_task_id") or path.parts[-3],
                attack_type=attack_type,
                injection_task_id=injection_task_id,
                payload=standard_payload(benchmark_version, suite_name, attack_type, injection_task_id),
                source_path=str(path),
            )
        )
    return cases


def collect_iterinject_cases(iterinject_root: Path) -> list[ReplayCase]:
    cases = []
    for path in sorted(iterinject_root.glob("*/*/*/*.json")):
        payload = json.loads(path.read_text())
        if not bool_value(payload.get("attack_success")):
            continue
        cases.append(
            ReplayCase(
                method="iterinject",
                suite_name=payload.get("suite_name") or path.parts[-5],
                user_task_id=payload.get("user_task_id") or path.parts[-3],
                attack_type=payload.get("baseline_attack") or payload.get("attack_type") or path.parts[-2],
                injection_task_id=payload.get("injection_task_id") or path.stem,
                payload=payload.get("best_payload") or "",
                source_path=str(path),
            )
        )
    return [case for case in cases if case.payload]


def collect_agentvigil_cases(agentvigil_root: Path) -> list[ReplayCase]:
    cases = []
    for key, path in sorted(latest_agentvigil_results(agentvigil_root).items()):
        suite_name, user_task_id, attack_type, injection_task_id = key
        payload = json.loads(path.read_text())
        attack_success = bool_value(
            payload.get("best_asr")
            if "best_asr" in payload
            else payload.get("final_asr")
        )
        if not attack_success:
            continue
        best_prompt = payload.get("best_prompt") or ""
        if not best_prompt:
            continue
        cases.append(
            ReplayCase(
                method="agentvigil",
                suite_name=suite_name,
                user_task_id=user_task_id,
                attack_type=attack_type,
                injection_task_id=injection_task_id,
                payload=best_prompt,
                source_path=str(path),
            )
        )
    return cases


def collapse_duplicate_payloads(cases: list[ReplayCase]) -> list[ReplayCase]:
    """Run each distinct successful payload once, while preserving method labels."""
    grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for case in cases:
        entry = grouped.setdefault(
            case.payload_key,
            {
                "case": case,
                "methods": set(),
                "paths": [],
            },
        )
        if case.source_methods:
            entry["methods"].update(case.source_methods)
        else:
            entry["methods"].add(case.method)
        entry["paths"].append(case.source_path)

    deduped = []
    for entry in grouped.values():
        case = entry["case"]
        methods = tuple(sorted(entry["methods"]))
        paths = tuple(dict.fromkeys(entry["paths"]))
        deduped.append(
            ReplayCase(
                method="unique_payload",
                suite_name=case.suite_name,
                user_task_id=case.user_task_id,
                attack_type=case.attack_type,
                injection_task_id=case.injection_task_id,
                payload=case.payload,
                source_path=paths[0] if paths else case.source_path,
                source_methods=methods,
                source_paths=paths,
            )
        )
    return sorted(deduped, key=lambda item: (item.suite_name, item.user_task_id, item.attack_type, item.injection_task_id, item.payload))


def build_case_manifest_entries(cases: list[ReplayCase]) -> list[dict[str, Any]]:
    """Group successful source payloads by AgentDojo case.

    A case is identified by (suite, user task, attack type, injection task).
    If the handcrafted benchmark prompt succeeds, later methods inherit that
    payload because the sequential evaluation stops before mutation/fuzzing.
    """
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for case in cases:
        key = (case.suite_name, case.user_task_id, case.attack_type, case.injection_task_id)
        entry = grouped.setdefault(
            key,
            {
                "suite_name": case.suite_name,
                "user_task_id": case.user_task_id,
                "attack_type": case.attack_type,
                "injection_task_id": case.injection_task_id,
                "successful_methods": [],
                "method_payloads": {},
            },
        )
        if case.method not in entry["successful_methods"]:
            entry["successful_methods"].append(case.method)
        entry["method_payloads"][case.method] = {
            "payload": case.payload,
            "source_path": case.source_path,
        }

    entries = []
    for entry in grouped.values():
        entry["successful_methods"] = sorted(entry["successful_methods"])
        handcraft_payload = entry["method_payloads"].get("handcraft")
        if handcraft_payload:
            for method in entry["successful_methods"]:
                if method == "handcraft":
                    continue
                entry["method_payloads"][method] = {
                    "payload": handcraft_payload["payload"],
                    "source_path": handcraft_payload["source_path"],
                    "inherited_from": "handcraft",
                }
        entries.append(entry)
    return sorted(
        entries,
        key=lambda item: (
            item["suite_name"],
            item["user_task_id"],
            item["attack_type"],
            item["injection_task_id"],
        ),
    )


def build_method_replay_cases(case_entries: list[dict[str, Any]]) -> list[ReplayCase]:
    replay_cases = []
    for entry in case_entries:
        for method in entry["successful_methods"]:
            method_payload = entry["method_payloads"][method]
            replay_cases.append(
                ReplayCase(
                    method=method,
                    suite_name=entry["suite_name"],
                    user_task_id=entry["user_task_id"],
                    attack_type=entry["attack_type"],
                    injection_task_id=entry["injection_task_id"],
                    payload=method_payload["payload"],
                    source_path=method_payload["source_path"],
                )
            )
    return replay_cases


def output_path_for(output_root: Path, run_id: str, defense: str, case: ReplayCase) -> Path:
    return (
        output_root
        / run_id
        / defense
        / case.method
        / case.suite_name
        / case.user_task_id
        / case.attack_type
        / f"{case.injection_task_id}.json"
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temp_path.replace(path)


def evaluate_case(case: ReplayCase, *, suite, pipeline, attack) -> dict[str, Any]:
    user_task = suite.get_user_task_by_id(case.user_task_id)
    injection_task = suite.get_injection_task_by_id(case.injection_task_id)
    attack.set_payload(case.payload)
    start = time.time()
    result = run_injected_task(
        suite=suite,
        pipeline=pipeline,
        user_task=user_task,
        injection_task=injection_task,
        attack=attack,
    )
    return {
        "suite_name": case.suite_name,
        "user_task_id": case.user_task_id,
        "injection_task_id": case.injection_task_id,
        "attack_type": case.attack_type,
        "baseline_attack": case.attack_type,
        "method": case.method,
        "source_methods": list(case.methods),
        "source_paths": list(case.paths),
        "source_path": case.source_path,
        "payload": case.payload,
        "injections": result.injections,
        "messages": result.messages,
        "utility": result.utility,
        "security": result.injection_success,
        "attack_success": result.injection_success,
        "response_text": result.response_text,
        "tool_traces": [str(call) for call in result.tool_traces],
        "duration": round(time.time() - start, 2),
        "latency_seconds": result.latency_seconds,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "total_tokens": result.total_tokens,
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for item in results:
        method = item["method"]
        key = (item["defense"], method)
        row = summary.setdefault(
            ":".join(key),
            {"defense": item["defense"], "method": method, "total": 0, "success": 0, "utility": 0, "jsr": 0, "errors": 0},
        )
        row["total"] += 1
        if item.get("error"):
            row["errors"] += 1
        row["success"] += int(bool_value(item.get("attack_success")))
        row["utility"] += int(bool_value(item.get("utility")))
        row["jsr"] += int(bool_value(item.get("attack_success")) and bool_value(item.get("utility")))
    for row in summary.values():
        denom = row["total"] or 1
        row["asr"] = row["success"] / denom
        row["ua"] = row["utility"] / denom
        row["jsr_rate"] = row["jsr"] / denom
    return {"rows": list(summary.values())}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="deepseek_defense_replay")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--base-url-env", default="OPENAI_BASE_URL")
    parser.add_argument("--iterinject-root", type=Path, default=RELEASE_ROOT / "runs" / "qwen3_attack_deepseek")
    parser.add_argument("--agentvigil-root", type=Path, default=RUNS_ROOT / "agentvigil_deepseek")
    parser.add_argument("--output-root", type=Path, default=RUNS_ROOT)
    parser.add_argument("--defense", action="append", dest="defenses", default=[])
    parser.add_argument("--method", action="append", dest="methods", default=[])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--case-manifest",
        type=Path,
        default=RELEASE_ROOT / "runs" / "deepseek_defense_source_cases.json",
        help="Where to write the collected successful source cases.",
    )
    parser.add_argument(
        "--write-cases-only",
        action="store_true",
        help="Only collect successful source cases and write the manifest; do not run defenses.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    defenses = args.defenses or DEFAULT_DEFENSES
    methods = set(args.methods or ["handcraft", "agentvigil", "iterinject"])

    raw_cases: list[ReplayCase] = []
    if "handcraft" in methods:
        raw_cases.extend(collect_handcraft_cases(args.iterinject_root, args.benchmark_version))
    if "agentvigil" in methods:
        raw_cases.extend(collect_agentvigil_cases(args.agentvigil_root))
    if "iterinject" in methods:
        raw_cases.extend(collect_iterinject_cases(args.iterinject_root))

    seen = set()
    method_cases = []
    for case in raw_cases:
        if case.key in seen:
            continue
        seen.add(case.key)
        method_cases.append(case)
    case_entries = build_case_manifest_entries(method_cases)
    method_replay_cases = build_method_replay_cases(case_entries)
    payload_replay_cases = collapse_duplicate_payloads(method_replay_cases)
    cases = method_replay_cases
    if args.limit is not None:
        cases = cases[: args.limit]

    raw_counts = {
        method: sum(1 for case in method_cases if case.method == method)
        for method in sorted({case.method for case in method_cases})
    }
    dedup_counts = {
        method: sum(1 for case in method_replay_cases if case.method == method)
        for method in sorted({case.method for case in method_replay_cases})
    }
    payload_overlap_counts = Counter("+".join(case.methods) for case in payload_replay_cases)
    case_methods = defaultdict(set)
    for case in method_cases:
        case_methods[
            (case.suite_name, case.user_task_id, case.attack_type, case.injection_task_id)
        ].add(case.method)
    case_overlap_counts = Counter("+".join(sorted(methods)) for methods in case_methods.values())
    print(
        f"Loaded {len(method_cases)} method-labeled successful cases; "
        f"{len(case_entries)} unique successful AgentDojo cases; "
        f"{len(payload_replay_cases)} distinct payload replays after exact-payload deduplication."
    )
    manifest_payload = {
        "generated_at": datetime.now().isoformat(),
        "benchmark_version": args.benchmark_version,
        "iterinject_root": str(args.iterinject_root),
        "agentvigil_root": str(args.agentvigil_root),
        "raw_method_counts": raw_counts,
        "dedup_method_counts": dedup_counts,
        "unique_successful_cases": len(case_entries),
        "method_replay_records": len(method_replay_cases),
        "unique_payload_replays": len(payload_replay_cases),
        "payload_overlap_counts": dict(sorted(payload_overlap_counts.items())),
        "case_overlap_counts": dict(sorted(case_overlap_counts.items())),
        "case_entries": case_entries,
        "payload_replays": [
            {
                "source_methods": list(case.methods),
                "suite_name": case.suite_name,
                "user_task_id": case.user_task_id,
                "attack_type": case.attack_type,
                "injection_task_id": case.injection_task_id,
                "payload": case.payload,
                "source_paths": list(case.paths),
            }
            for case in payload_replay_cases
        ],
    }
    write_json(args.case_manifest, manifest_payload)
    if args.write_cases_only:
        print(f"Wrote case manifest: {args.case_manifest}")
        return 0

    run_root = args.output_root / args.run_id
    run_root.mkdir(parents=True, exist_ok=True)

    all_results = []
    suite_cache = {}
    for defense in defenses:
        print(f"\n=== Defense: {defense} ===")
        try:
            pipeline = make_openai_compatible_pipeline(
                model=args.model,
                api_key=args.api_key,
                base_url=args.base_url or os.getenv(args.base_url_env),
                api_key_env=args.api_key_env,
                base_url_env=args.base_url_env,
                defense=defense,
                pipeline_name=f"defense-replay/{args.model}/{defense}",
                pipeline_mode="openai-tools",
                temperature=args.temperature,
            )
        except Exception as exc:
            print(f"[defense-init-error] {defense}: {exc}")
            for case in cases:
                out = output_path_for(args.output_root, args.run_id, defense, case)
                item = {
                    "defense": defense,
                    "method": case.method,
                    "suite_name": case.suite_name,
                    "user_task_id": case.user_task_id,
                    "attack_type": case.attack_type,
                    "injection_task_id": case.injection_task_id,
                    "attack_success": False,
                    "utility": False,
                    "error": f"defense init failed: {exc}",
                    "source_paths": list(case.paths),
                    "source_path": case.source_path,
                    "generated_at": datetime.now().isoformat(),
                }
                if args.overwrite or not out.exists():
                    write_json(out, item)
                all_results.append(item)
            continue

        attack_cache = {}
        payload_eval_cache: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for idx, case in enumerate(cases, 1):
            out = output_path_for(args.output_root, args.run_id, defense, case)
            if out.exists() and not args.overwrite:
                try:
                    item = json.loads(out.read_text())
                    all_results.append(item)
                    print(f"[{idx}/{len(cases)}] skip {defense}/{case.method}/{case.suite_name}/{case.user_task_id}/{case.attack_type}/{case.injection_task_id}")
                    continue
                except json.JSONDecodeError:
                    pass

            if case.payload_key in payload_eval_cache:
                cached = dict(payload_eval_cache[case.payload_key])
                item = {
                    **cached,
                    "method": case.method,
                    "source_path": case.source_path,
                    "cache_reused": True,
                }
                print(f"[{idx}/{len(cases)}] reuse {defense}/{case.method}/{case.suite_name}/{case.user_task_id}/{case.attack_type}/{case.injection_task_id}")
                write_json(out, item)
                all_results.append(item)
                write_json(run_root / "summary.json", {"run_id": args.run_id, "results": all_results, **summarize(all_results)})
                continue

            suite = suite_cache.get(case.suite_name)
            if suite is None:
                suite = get_suite(args.benchmark_version, case.suite_name)
                suite_cache[case.suite_name] = suite
            attack = attack_cache.get(case.suite_name)
            if attack is None:
                attack = FixedPayloadAttack(suite, pipeline)
                attack_cache[case.suite_name] = attack

            print(f"[{idx}/{len(cases)}] run {defense}/{case.method}/{case.suite_name}/{case.user_task_id}/{case.attack_type}/{case.injection_task_id}")
            try:
                item = evaluate_case(case, suite=suite, pipeline=pipeline, attack=attack)
                item["error"] = None
                item["cache_reused"] = False
            except Exception as exc:
                item = {
                    "suite_name": case.suite_name,
                    "user_task_id": case.user_task_id,
                    "injection_task_id": case.injection_task_id,
                    "attack_type": case.attack_type,
                    "baseline_attack": case.attack_type,
                    "method": case.method,
                    "source_methods": list(case.methods),
                    "source_paths": list(case.paths),
                    "source_path": case.source_path,
                    "payload": case.payload,
                    "utility": False,
                    "security": False,
                    "attack_success": False,
                    "error": str(exc),
                }
            item.update(
                {
                    "defense": defense,
                    "model": args.model,
                    "temperature": args.temperature,
                    "disable_thinking": os.environ.get("DISABLE_THINKING", "1"),
                    "benchmark_version": args.benchmark_version,
                    "evaluation_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "agentdojo_package_version": importlib.metadata.version("agentdojo"),
                }
            )
            write_json(out, item)
            payload_eval_cache[case.payload_key] = dict(item)
            all_results.append(item)
            write_json(run_root / "summary.json", {"run_id": args.run_id, "results": all_results, **summarize(all_results)})

    write_json(run_root / "summary.json", {"run_id": args.run_id, "results": all_results, **summarize(all_results)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
