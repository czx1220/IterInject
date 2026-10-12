"""AgentVigil CLI entry point.

Usage:
    python -m agentvigil.run --suite workspace

    python -m agentvigil.run --suite workspace --model Qwen3.5-27B \
        --helper-model Qwen3-8B

    python -m agentvigil.run --suite workspace --iterations 7 --mutations-per-iter 3
"""

from __future__ import annotations

import glob
import json
import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if __package__ in {None, ""}:
    # Make the package importable when this file is invoked as a script.
    sys.path.insert(0, str(ROOT))

import click  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from openai import OpenAI  # noqa: E402

from agentdojo.task_suite.load_suites import get_suite, get_suites  # noqa: E402

from agentvigil.agentvigil import FuzzConfig, run_fuzzing  # noqa: E402
from iterinject.agentdojo_adapter import (  # noqa: E402
    make_openai_compatible_pipeline,
)

load_dotenv(ROOT / ".env")

ATTACK_NAMES = ["direct", "ignore_previous", "system_message", "injecagent", "important_instructions"]


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def make_target_pipeline(
    model: str,
    base_url: str | None = None,
    api_key: str | None = None,
    temperature: float = 0.0,
):
    return make_openai_compatible_pipeline(
        model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
    )


@click.command()
@click.option("-s", "--suite", "suite_names", multiple=True, help="Suite(s) to run (workspace, banking, slack, travel)")
@click.option("--model", default="Qwen3.5-27B", help="Target LLM model name")
@click.option("--model-base-url", default=None, help="Target LLM API base URL (for non-OpenAI)")
@click.option("--model-api-key", default=None, help="Target LLM API key")
@click.option("--temperature", default=0.0, type=float, help="Target LLM temperature")
@click.option("--helper-model", default="Qwen3-8B", help="Helper model for mutations")
@click.option("--helper-base-url", default=None, help="Helper model API base URL")
@click.option("--helper-api-key", default=None, help="Helper model API key")
@click.option("--iterations", default=7, type=int, help="Number of fuzzing iterations")
@click.option("--mutations-per-iter", default=3, type=int, help="Mutations per iteration")
@click.option("--exploration-constant", default=1.414, type=float, help="UCB1 exploration constant (C)")
@click.option("--benchmark-version", default="v1.2.2", help="AgentDojo benchmark version")
@click.option("--logdir", default="./runs", type=click.Path(), help="Directory to save results")
@click.option("--case-dir", default=None, type=click.Path(exists=True), help="Directory with iterinject case structure to filter pairs")
@click.option(
    "--case-manifest",
    default=str(ROOT / "experiments" / "agentdojo_cases.json"),
    type=click.Path(exists=True),
    help="Paper case-selection manifest used unless --case-dir is supplied",
)
@click.option("--rerun-errors", is_flag=True, help="Rerun cases whose existing results all have final_error set")
def main(
    suite_names,
    model,
    model_base_url,
    model_api_key,
    temperature,
    helper_model,
    helper_base_url,
    helper_api_key,
    iterations,
    mutations_per_iter,
    exploration_constant,
    benchmark_version,
    logdir,
    case_dir,
    case_manifest,
    rerun_errors,
):
    logger.info(f"AgentVigil Fuzzing | Target: {model} | Helper: {helper_model}")

    # Setup target pipeline
    pipeline = make_target_pipeline(model, model_base_url, model_api_key, temperature)

    # Setup helper client
    helper_client = OpenAI(
        api_key=helper_api_key or os.getenv("MUTATION_API_KEY") or os.getenv("OPENAI_API_KEY"),
        base_url=helper_base_url or os.getenv("MUTATION_BASE_URL") or os.getenv("OPENAI_BASE_URL"),
    )

    # Get suites
    if suite_names:
        suites = [get_suite(benchmark_version, name) for name in suite_names]
    else:
        suites = list(get_suites(benchmark_version).values())

    logdir_path = Path(logdir)
    logdir_path.mkdir(parents=True, exist_ok=True)

    for suite in suites:
        logger.info(f"\n{'='*60}")
        logger.info(f"Suite: {suite.name}")
        logger.info(f"User tasks: {len(suite.user_tasks)} | Injection tasks: {len(suite.injection_tasks)}")
        logger.info(f"{'='*60}")

        # Build list of (user_task, injection_task) pairs
        if case_dir:
            pairs = _load_pairs_from_case_dir(Path(case_dir), suite.name)
            logger.info(f"Loaded {len(pairs)} pairs from case-dir")
        elif case_manifest:
            pairs = _load_pairs_from_manifest(Path(case_manifest), suite.name)
            logger.info(f"Loaded {len(pairs)} pairs from paper case manifest")
        else:
            pairs = [(ut, inj) for ut in suite.user_tasks for inj in suite.injection_tasks]

        completed = 0
        skipped = 0

        for ut_id, inj_id in pairs:
            for attack in ATTACK_NAMES:
                # Check if already done (resume)
                suite_result_dir = logdir_path / suite.name / ut_id / attack / inj_id
                if _should_skip_case(suite_result_dir, rerun_errors):
                    skipped += 1
                    continue

                completed += 1
                logger.info(f"\n--- [{completed}] {suite.name}:{ut_id}:{inj_id}:{attack} ---")

                config = FuzzConfig(
                    n_iterations=iterations,
                    n_mutations_per_iter=mutations_per_iter,
                    exploration_constant=exploration_constant,
                    helper_model=helper_model,
                    logdir=logdir_path,
                    helper_extra_body={"enable_thinking": False},
                )

                try:
                    result = run_fuzzing(
                        suite=suite,
                        user_task_id=ut_id,
                        injection_task_id=inj_id,
                        agent_pipeline=pipeline,
                        helper_client=helper_client,
                        config=config,
                        attack_name=attack,
                    )
                    logger.info(f"  ASR: {result.final_asr:.2%} | UA: {result.final_ua} | Score: {result.best_score:.2f}")
                except Exception as e:
                    logger.error(f"  Failed: {e}")

        logger.info(f"\nSuite {suite.name} done. Completed: {completed}, Skipped: {skipped}")


def _load_pairs_from_case_dir(case_dir: Path, suite_name: str) -> list[tuple[str, str]]:
    """Load (user_task, injection_task) pairs from iterinject case directory structure."""
    suite_dir = case_dir / suite_name
    pairs = []
    for ut_dir in sorted(glob.glob(str(suite_dir / "user_task_*"))):
        ut = os.path.basename(ut_dir)
        for attack_dir in sorted(glob.glob(f"{ut_dir}/*")):
            for inj_file in sorted(glob.glob(f"{attack_dir}/*.json")):
                inj = os.path.basename(inj_file).replace(".json", "")
                pairs.append((ut, inj))
    # Deduplicate (same pair may appear under multiple attack dirs)
    return list(dict.fromkeys(pairs))


def _load_pairs_from_manifest(
    case_manifest: Path, suite_name: str
) -> list[tuple[str, str]]:
    payload = json.loads(case_manifest.read_text())
    return [
        (case["user_task_id"], case["injection_task_id"])
        for case in payload["suites"][suite_name]
    ]


def _should_skip_case(case_dir: Path, rerun_errors: bool) -> bool:
    result_files = list(case_dir.glob("*/result.json")) if case_dir.exists() else []
    if not result_files:
        return False
    if not rerun_errors:
        return True

    for result_file in result_files:
        try:
            with open(result_file, "r") as f:
                data = json.load(f)
        except Exception:
            continue
        if data.get("final_error") in (None, ""):
            return True
    return False


if __name__ == "__main__":
    main()
