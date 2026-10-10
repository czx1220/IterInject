"""Explicit-path, read-only benchmark inputs with stable case provenance.

Data field sources: old optimization/optimize.py:124-170 and
evaluate_prompted_agent.py:26-37. Original benchmark inputs are never overwritten.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PLACEHOLDER = "<Attacker Instruction>"
INJECTION_PROTOCOL = "explicit_template_json_string_v2"
IDENTITY_FIELDS = ("User Instruction", "User Tool", "Tool Parameters", "Attacker Tools",
                   "Attacker Instruction", "Tool Response Template")
REQUIRED_FIELDS = IDENTITY_FIELDS + ("Thought", "Tool Response")


@dataclass(frozen=True)
class InjecAgentCase:
    case_id: str
    attack: str
    setting: str
    raw: dict[str, Any]
    source: dict[str, Any]

    @property
    def objective(self) -> str:
        return self.raw["Attacker Instruction"]

    def inject(self, payload: str) -> dict[str, Any]:
        """Replace the declared slot, then serialize the response text once.

        This is the explicit-payload template path from old optimize.py:161-170,
        with missing/multiple placeholders rejected instead of silently replaced.
        JSON string serialization is the user-approved InjecAgent correction.
        It normalizes quoting/escaping independently of malformed stored responses.
        The enhanced prefix is not implicitly added to the supplied payload.
        """
        if not isinstance(payload, str) or not payload.strip():
            raise ValueError("payload must be nonempty text")
        template = self.raw["Tool Response Template"]
        if not isinstance(template, str) or template.count(PLACEHOLDER) != 1:
            raise ValueError("Tool Response Template must contain exactly one <Attacker Instruction>")
        item = copy.deepcopy(self.raw)
        response_text = template.replace(PLACEHOLDER, payload, 1)
        item["Tool Response"] = json.dumps(response_text)
        return item


def load_cases(data_dir: str | Path, attack: str, setting: str,
               case_ids: Iterable[str] | None = None) -> tuple[InjecAgentCase, ...]:
    if attack not in ("dh", "ds"):
        raise ValueError("attack must be dh or ds")
    if setting not in ("base", "enhanced"):
        raise ValueError("setting must be base or enhanced")
    directory = Path(data_dir).expanduser().resolve(strict=True)
    filename = f"test_cases_{attack}_{setting}.json"
    content = (directory / filename).read_bytes()
    rows = json.loads(content)
    if not isinstance(rows, list):
        raise ValueError("benchmark data must be a list of cases")
    digest = hashlib.sha256(content).hexdigest()
    cases = []
    seen = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or any(field not in row for field in REQUIRED_FIELDS):
            raise ValueError(f"invalid case data at {filename}:{index}")
        tools = row["Attacker Tools"]
        if not isinstance(tools, list) or len(tools) != (1 if attack == "dh" else 2):
            raise ValueError(f"invalid attacker tool chain at {filename}:{index}")
        identity = {"attack": attack, "setting": setting,
                    "fields": {field: row[field] for field in IDENTITY_FIELDS}}
        encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        case_id = f"{attack}:{setting}:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"
        if case_id in seen:
            raise ValueError(f"duplicate case identity at {filename}:{index}")
        seen.add(case_id)
        source = {"filename": filename, "index": index, "setting": setting,
                  "file_sha256": digest, "identity_fields": list(IDENTITY_FIELDS),
                  "injection_protocol": INJECTION_PROTOCOL,
                  "legacy_tool_response_preserved": True,
                  "tool_response_serialization": "json_string",
                  "legacy_envelope_reused": False,
                  "enhanced_prefix_added": False}
        cases.append(InjecAgentCase(case_id, attack, setting, copy.deepcopy(row), source))
    if case_ids is not None:
        selected = tuple(case_ids)
        if len(set(selected)) != len(selected):
            raise ValueError("case selection contains duplicate ids")
        by_id = {case.case_id: case for case in cases}
        missing = set(selected) - by_id.keys()
        if missing:
            raise ValueError(f"case selection ids not found: {sorted(missing)}")
        return tuple(by_id[case_id] for case_id in selected)
    return tuple(cases)


def load_case(data_dir: str | Path, case_id: str, attack: str, setting: str) -> InjecAgentCase:
    return load_cases(data_dir, attack, setting, case_ids=(case_id,))[0]


def load_tools(data_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Flatten toolkit + tool name as in old utils.py:117-130, without mutation."""
    toolkits = json.loads((Path(data_dir).expanduser().resolve(strict=True) / "tools.json").read_bytes())
    result = {}
    for toolkit in toolkits:
        for original in toolkit["tools"]:
            tool = copy.deepcopy(original)
            name = toolkit["toolkit"] + tool["name"]
            if name in result:
                raise ValueError(f"duplicate tool definition: {name}")
            tool["name"] = name
            result[name] = tool
    return result
