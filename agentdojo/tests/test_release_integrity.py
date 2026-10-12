from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseIntegrityTest(unittest.TestCase):
    def test_manifest_paths_exist(self) -> None:
        manifest = json.loads((ROOT / "experiments" / "manifest.json").read_text())
        artifacts = manifest["release_contents"]
        paths = [
            *artifacts["source_entrypoints"],
            *artifacts["configuration"],
            *artifacts["tests"],
        ]
        for relative_path in paths:
            with self.subTest(path=relative_path):
                self.assertTrue((ROOT / relative_path).exists())

    def test_results_and_cases_are_not_published(self) -> None:
        manifest = json.loads((ROOT / "experiments" / "manifest.json").read_text())
        self.assertNotIn("aggregate_results", manifest["release_contents"])
        self.assertFalse((ROOT / "results").exists())
        self.assertFalse((ROOT / "cases").exists())

    def test_example_environment_contains_no_live_credentials(self) -> None:
        env_example = (ROOT / ".env.example").read_text()
        self.assertIn("replace-with-your-target-api-key", env_example)
        self.assertIn("replace-with-your-mutation-api-key", env_example)


if __name__ == "__main__":
    unittest.main()
