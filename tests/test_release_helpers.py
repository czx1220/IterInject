from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agentvigil.run import (
    _load_pairs_from_case_dir,
    _load_pairs_from_manifest,
    _should_skip_case,
)
from iterinject.agentdojo_adapter import should_disable_thinking
from agentvigil.seed_collector import collect_seeds
from scripts.run_agentdojo_defense_replay import (
    ReplayCase,
    collapse_duplicate_payloads,
    first_iteration_success,
    summarize,
)
from scripts.summarize_agentdojo_runs import agentvigil_outcomes, collect_run
from scripts.run_agentdojo_stepwise import (
    AGENTDOJO_SUITE_CASES,
    load_paper_case_pairs,
    resolve_baseline_attacks,
    resolve_suites,
)


class StepwiseHelpersTest(unittest.TestCase):
    def test_agentvigil_supports_direct_script_help(self) -> None:
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, str(root / "agentvigil" / "run.py"), "--help"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--case-manifest", completed.stdout)

    def test_paper_thinking_modes_keep_minimax_default(self) -> None:
        self.assertFalse(should_disable_thinking("MiniMax-M2.7"))
        self.assertTrue(should_disable_thinking("GLM-5.1"))
        self.assertTrue(should_disable_thinking("DeepSeek-V4-Flash"))
        self.assertTrue(should_disable_thinking("Qwen3.5-27B"))

    def test_default_suite_and_attack_order_is_stable(self) -> None:
        self.assertEqual(resolve_suites([]), list(AGENTDOJO_SUITE_CASES))
        self.assertEqual(
            resolve_baseline_attacks([]),
            [
                "direct",
                "ignore_previous",
                "system_message",
                "injecagent",
                "important_instructions",
            ],
        )

    def test_paper_case_manifest_reconstructs_510_cases(self) -> None:
        manifest = Path(__file__).resolve().parents[1] / "experiments" / "agentdojo_cases.json"
        expected_pairs = {"workspace": 28, "banking": 26, "travel": 15, "slack": 33}
        for suite, pair_count in expected_pairs.items():
            with self.subTest(suite=suite):
                self.assertEqual(len(load_paper_case_pairs(manifest, suite)), pair_count)
        self.assertEqual(sum(expected_pairs.values()) * 5, 510)

    def test_explicit_values_preserve_input_order(self) -> None:
        self.assertEqual(
            resolve_suites(["slack", "workspace", "slack"]),
            ["slack", "workspace", "slack"],
        )
        self.assertEqual(
            resolve_baseline_attacks(["direct", "injecagent", "direct"]),
            ["direct", "injecagent", "direct"],
        )


class DefenseReplayHelpersTest(unittest.TestCase):
    def test_first_iteration_success_prefers_iteration_history(self) -> None:
        self.assertTrue(
            first_iteration_success(
                {
                    "iterations": 4,
                    "attack_success": False,
                    "iteration_history": [{"result": "SUCCESS"}],
                }
            )
        )
        self.assertFalse(
            first_iteration_success(
                {"iterations": 2, "attack_success": True, "iteration_history": []}
            )
        )

    def test_duplicate_payloads_preserve_all_source_methods(self) -> None:
        common = {
            "suite_name": "workspace",
            "user_task_id": "user_task_0",
            "attack_type": "direct",
            "injection_task_id": "injection_task_0",
            "payload": "same payload",
        }
        cases = [
            ReplayCase(method="handcraft", source_path="first.json", **common),
            ReplayCase(method="iterinject", source_path="second.json", **common),
        ]

        deduped = collapse_duplicate_payloads(cases)

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].methods, ("handcraft", "iterinject"))
        self.assertEqual(deduped[0].paths, ("first.json", "second.json"))

    def test_summary_counts_joint_success_per_record(self) -> None:
        summary = summarize(
            [
                {
                    "defense": "tool_filter",
                    "method": "iterinject",
                    "attack_success": True,
                    "utility": True,
                },
                {
                    "defense": "tool_filter",
                    "method": "iterinject",
                    "attack_success": True,
                    "utility": False,
                    "error": "failed utility check",
                },
            ]
        )["rows"][0]

        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["success"], 2)
        self.assertEqual(summary["utility"], 1)
        self.assertEqual(summary["jsr"], 1)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["asr"], 1.0)
        self.assertEqual(summary["ua"], 0.5)
        self.assertEqual(summary["jsr_rate"], 0.5)


class AgentVigilResumeHelpersTest(unittest.TestCase):
    def test_agentvigil_starts_from_one_handcrafted_seed(self) -> None:
        suite = SimpleNamespace(
            injection_tasks={"injection_task_0": SimpleNamespace(GOAL="send the email")}
        )
        seeds = collect_seeds(suite, attack_name="direct")
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["template_name"], "direct")

    def test_latest_agentvigil_outcome_uses_final_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = (
                Path(tmp)
                / "workspace"
                / "user_task_0"
                / "direct"
                / "injection_task_0"
                / "20260101-000000"
                / "result.json"
            )
            result.parent.mkdir(parents=True)
            result.write_text(json.dumps({"final_asr": 1, "final_ua": False}))

            outcomes = agentvigil_outcomes(Path(tmp))

            self.assertEqual(
                outcomes[("workspace", "user_task_0", "direct", "injection_task_0")],
                (True, False),
            )

    def test_case_directory_pairs_are_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            for attack in ("direct", "injecagent"):
                path = (
                    case_dir
                    / "workspace"
                    / "user_task_0"
                    / attack
                    / "injection_task_1.json"
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}")

            self.assertEqual(
                _load_pairs_from_case_dir(case_dir, "workspace"),
                [("user_task_0", "injection_task_1")],
            )

    def test_agentvigil_uses_the_same_paper_case_manifest(self) -> None:
        manifest = Path(__file__).resolve().parents[1] / "experiments" / "agentdojo_cases.json"
        self.assertEqual(len(_load_pairs_from_manifest(manifest, "workspace")), 28)

    def test_rerun_errors_only_skips_a_case_with_a_successful_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            error_result = case_dir / "first" / "result.json"
            error_result.parent.mkdir(parents=True)
            error_result.write_text(json.dumps({"final_error": "timeout"}))
            self.assertFalse(_should_skip_case(case_dir, rerun_errors=True))

            ok_result = case_dir / "second" / "result.json"
            ok_result.parent.mkdir(parents=True)
            ok_result.write_text(json.dumps({"final_error": None}))
            self.assertTrue(_should_skip_case(case_dir, rerun_errors=True))


class AggregationHelpersTest(unittest.TestCase):
    def test_incomplete_runs_report_missing_without_inflating_observed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = collect_run("Test", root / "iterinject", root / "agentvigil")

        for method in ("Benchmark", "AgentVigil", "IterInject"):
            overall = summary["rows"][method]["overall"]
            self.assertEqual(overall["observed"], 0)
            self.assertEqual(overall["missing"], 510)


if __name__ == "__main__":
    unittest.main()
