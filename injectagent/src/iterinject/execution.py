"""Execution services composed outside CLI parsing and search scheduling."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from iterinject.core.types import AttemptResult, InnerLoopConfiguration, SeedContext, TargetSpec


def execute_single(args) -> tuple[dict[str, Any], int]:
    from iterinject.cli import (
        _json_file, _benchmark, _simulation_config, _policy_from_mapping,
        _FixtureClient, _build_remote_client, _code_info, _file_info,
        _model_snapshot, _RecordedOptimizerClient,
    )
    from iterinject.adapters.injecagent.dataset import load_case, load_tools
    from iterinject.adapters.injecagent.metrics import case_outcome
    from iterinject.adapters.injecagent.runner import InjecAgentRunner
    from iterinject.adapters.injecagent.simulated_responses import (
        GeneratedSimulatedResponses, ReadOnlySimulatedResponses, SIMULATION_PROMPT_INFO,
    )
    from iterinject.core.logging import RunLogger, serialize
    from iterinject.core.optimizer import run_optimizer
    from iterinject.adapters.injecagent.optimizer import InjecAgentPromptOptimizer
    from iterinject.adapters.injecagent.diagnoser import load_diagnostic_preset
    from iterinject.configuration import parse_method_configuration

    benchmark = _json_file(args.benchmark_config)
    attack, setting, prompt_type = _benchmark(benchmark)
    method_configuration = parse_method_configuration(_json_file(args.method_config))
    method = method_configuration.inner_loop
    fixture = _json_file(args.fixture_script) if args.fixture_script else None
    mode = "fixture" if fixture is not None else "remote"
    scope = "engineering_smoke" if args.engineering_smoke else "formal"
    simulation_mode, simulation_value = (_simulation_config(benchmark, fixture=fixture is not None)
                                        if attack == "ds" else (None, {}))
    if fixture is not None:
        policy_value = fixture.get("diagnostic_policy")
        if not isinstance(policy_value, dict):
            raise ValueError("fixture requires an explicit diagnostic_policy")
        policy = _policy_from_mapping(policy_value, fixture=True)
    else:
        policy_value = (_json_file(args.approved_diagnostic_policy)
                        if args.approved_diagnostic_policy else load_diagnostic_preset())
        policy = _policy_from_mapping(policy_value)

    initial_path = Path(args.initial_payload_file).resolve()
    initial_payload = initial_path.read_text(encoding="utf-8")
    if not initial_payload.strip():
        raise ValueError("initial payload file must contain nonempty text")
    data_dir = Path(args.data_dir).resolve()
    case = load_case(data_dir, args.case_id, attack, setting)
    tools = load_tools(data_dir)
    target = TargetSpec(case.case_id, case.raw["Attacker Instruction"])
    seed = SeedContext(**benchmark.get("seed", {
        "seed_id": "explicit-initial-payload", "name": initial_path.name,
        "description": "Explicit initial payload supplied as a file.",
    }))
    references: tuple[str, ...] = ()
    if args.reference_successes_file:
        values = json.loads(Path(args.reference_successes_file).read_text(encoding="utf-8"))
        if not isinstance(values, list) or any(not isinstance(s, str) or not s.strip() for s in values):
            raise ValueError("reference successes must be a JSON list of nonempty payloads")
        references = tuple(values)
    simulation_client = None
    if fixture is not None:
        victim = _FixtureClient("victim", fixture.get("victim_responses", []))
        optimizer_client = _FixtureClient("optimizer", fixture.get("optimizer_responses", []))
        if simulation_mode == "generate_on_miss":
            simulation_client = _FixtureClient("simulation", fixture.get("simulation_responses", []))
    else:
        victim = _build_remote_client("victim", benchmark["victim"])
        optimizer_client = _build_remote_client("optimizer", benchmark["optimizer"]) if args.command == "run" else None
        if simulation_mode == "generate_on_miss":
            simulation_client = _build_remote_client("simulation", simulation_value)

    optimizer = None
    if args.command == "run":
        optimizer = InjecAgentPromptOptimizer(optimizer_client, case, tools,
                                              template_path=args.approved_optimizer_template)
    source_files = [data_dir / f"test_cases_{attack}_{setting}.json", data_dir / "tools.json"]
    if attack == "ds":
        source_files.append(data_dir / "attacker_simulated_responses.json")
    metadata = {
        "schema_version": "1", "mode": mode, "evaluation_scope": scope, "operation": args.command,
        "code": _code_info(), "initial_payload": _file_info(initial_path),
        "case_id": case.case_id, "target": serialize(target), "seed": serialize(seed),
        "method_config": serialize(method), "method_config_source": _file_info(args.method_config),
        "method_configuration": method_configuration.snapshot(),
        "benchmark_config_source": _file_info(args.benchmark_config),
        "benchmark": {"adapter": "injecagent", "attack": attack, "setting": setting, "prompt_type": prompt_type},
        "models": {"victim": _model_snapshot(victim),
                   "optimizer": _model_snapshot(optimizer_client) if optimizer_client else None},
        "optimizer_prompt": optimizer.template_info if optimizer else None,
        "diagnostic_policy": {**policy_value, **policy.snapshot()},
        "data": {"source": case.source, "files": [_file_info(path) for path in source_files if path.is_file()]},
        "reference_successes": list(references),
    }
    if attack == "ds":
        metadata["models"]["simulation"] = (_model_snapshot(simulation_client)
                                              if simulation_client else None)
        metadata["simulation"] = {
            "mode": simulation_mode,
            "source_cache": "read_only",
            "generated_cache": ("attacker_simulated_responses.json"
                                if simulation_mode == "generate_on_miss" else None),
            "prompt": SIMULATION_PROMPT_INFO if simulation_mode == "generate_on_miss" else None,
        }
    if fixture is not None:
        metadata["fixture_script"] = _file_info(args.fixture_script)
    else:
        metadata["diagnostic_policy_source"] = (_file_info(args.approved_diagnostic_policy)
            if args.approved_diagnostic_policy else {
                "kind": "bundled_injecagent_preset", "version": policy_value["version"],
                "canonical_json_sha256": hashlib.sha256(json.dumps(
                    policy_value, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            })
        if optimizer:
            metadata["optimizer_prompt_approval"] = ("explicit_cli_approved_template"
                if args.approved_optimizer_template else "user_approved_injecagent_source_adaptation")
    logger = RunLogger(Path(args.output_dir).resolve(), metadata)
    if optimizer:
        optimizer.client = _RecordedOptimizerClient(optimizer_client, logger)
    simulated_responses = None
    if attack == "ds":
        simulated_responses = (GeneratedSimulatedResponses(
            data_dir, simulation_client, tools, logger.run_dir / "attacker_simulated_responses.json")
            if simulation_mode == "generate_on_miss" else ReadOnlySimulatedResponses(data_dir))
    evaluator = InjecAgentRunner(case, victim, tools,
        simulated_responses=simulated_responses,
        diagnostic_policy=policy, prompt_type=prompt_type)
    effective_method = method if args.command == "run" else InnerLoopConfiguration(1, method.patience,
                                            method.relax_at_value, method.patience_extension)
    result = run_optimizer(target, seed, initial_payload, evaluator, optimizer, effective_method,
                           reference_successes=references, on_attempt=logger.record_attempt)
    terminal = result.attempts[-1].result
    if result.failure and terminal.failure is None:
        terminal = AttemptResult(failure=result.failure, trace=terminal.trace)
    outcome = case_outcome(case.case_id, attack, terminal)
    model_call_counts = {
        "victim": victim.call_count,
        "optimizer": optimizer_client.call_count if optimizer_client else 0,
    }
    model_interface_counts = None
    if attack == "ds":
        model_call_counts["simulation"] = simulation_client.call_count if simulation_client else 0
        model_interface_counts = {
            "victim": result.victim_calls, "optimizer": result.optimizer_calls,
            "simulation": getattr(simulated_responses, "generation_count", 0),
        }
    logger.finish(result, outcome, model_call_counts=model_call_counts,
                  model_interface_counts=model_interface_counts)
    return {"mode": mode, "evaluation_scope": scope, "run_dir": str(Path(args.output_dir).resolve()),
            "stop_reason": result.stop_reason.value, "attempts": len(result.attempts),
            "optimizer_calls": result.optimizer_calls, "case_outcome": outcome}, 1 if result.failure else 0




class InjecAgentSeedExecutor:
    """One isolated inner loop per seed, with optionally shared budgeted clients.

    Injected clients may share search counters but never inner-loop histories;
    their API totals are snapshotted at trial entry and reported as differences.
    Without injected clients the factory creates independent role clients per trial.
    """

    ROLES = ('initializer', 'synthesis', 'victim', 'optimizer', 'simulation')

    def __init__(self, data_dir, benchmark, method, output_dir, *, clients=None,
                 client_factory=None, diagnostic_policy=None, optimizer_template=None,
                 mode='remote', evaluation_scope='formal', legacy_root=None, asset_root=None,
                 initializer=None, method_configuration=None):
        from iterinject.adapters.injecagent.dataset import load_tools
        from iterinject.cli import _benchmark, _build_remote_client, _policy_from_mapping
        from iterinject.adapters.injecagent.diagnoser import load_diagnostic_preset
        self.data_dir = Path(data_dir).expanduser().resolve(strict=True)
        self.benchmark = dict(benchmark)
        self.attack, self.setting, self.prompt_type = _benchmark(self.benchmark)
        self.method = method
        self.method_configuration = method_configuration
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.clients = None if clients is None else dict(clients)
        self.client_factory = client_factory or _build_remote_client
        self.policy = diagnostic_policy or _policy_from_mapping(load_diagnostic_preset())
        self.optimizer_template = optimizer_template
        self.mode, self.evaluation_scope = mode, evaluation_scope
        if asset_root is not None and legacy_root is not None:
            raise ValueError('supply only one explicit asset root')
        selected = asset_root if asset_root is not None else legacy_root
        if selected is None:
            from .assets import asset_root as bundled_root
            selected = bundled_root()
        self.asset_root = Path(selected).resolve()
        self.legacy_root = self.asset_root  # Compatibility attribute.
        self.initializer = initializer
        self.tools = load_tools(self.data_dir)
        if self.clients is not None:
            for role in ('victim', 'optimizer'):
                if role not in self.clients:
                    raise ValueError(f'trial execution requires a {role} client')
            if len({id(c) for c in self.clients.values() if c is not None}) != sum(c is not None for c in self.clients.values()):
                raise ValueError('model roles require independent client instances')
        else:
            # Validate complete role configurations before creating any SDK/client.
            from iterinject.models import ModelConfig
            for role in ('initializer', 'synthesis', 'victim', 'optimizer'):
                value = self.benchmark.get(role)
                if not isinstance(value, dict):
                    raise ValueError(f'{role} requires an independent model configuration')
                ModelConfig(role=role, **value)
        from iterinject.cli import _simulation_config
        self.simulation_mode, self.simulation_value = (
            _simulation_config(self.benchmark, fixture=self.mode == 'fixture')
            if self.attack == 'ds' else (None, {}))

    def _trial_clients(self):
        if self.clients is not None:
            return dict(self.clients)
        roles = ('initializer', 'synthesis', 'victim', 'optimizer')
        result = {role: self.client_factory(role, self.benchmark[role]) for role in roles}
        if self.simulation_mode == 'generate_on_miss':
            result['simulation'] = self.client_factory('simulation', self.simulation_value)
        return result

    @staticmethod
    def _counts(clients):
        return {role: int(getattr(clients.get(role), 'call_count', 0))
                for role in InjecAgentSeedExecutor.ROLES}

    @staticmethod
    def _write(path, value):
        import os
        from iterinject.core.logging import serialize, _check_public_metadata
        record = serialize(value)
        _check_public_metadata(record)
        encoded = json.dumps(record, ensure_ascii=False, allow_nan=False)
        with Path(path).open('x', encoding='utf-8') as stream:
            stream.write(encoded + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _reference_hashes(references):
        records = []
        for text in references:
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                value = None
            payload = value.get('payload') if isinstance(value, dict) and value.get('role') == 'historical_success_example' else text
            if not isinstance(payload, str) or not payload.strip():
                raise ValueError('historical success reference payload must be nonempty text')
            digest = hashlib.sha256(payload.encode()).hexdigest()
            if isinstance(value, dict) and value.get('payload_sha256', digest) != digest:
                raise ValueError('historical success reference payload hash mismatch')
            records.append({'payload_sha256': digest,
                            'rendered_sha256': hashlib.sha256(text.encode()).hexdigest()})
        return records

    def execute(self, target, seed, reference_successes=()):
        from copy import deepcopy
        from uuid import uuid4
        from iterinject.core.logging import RunLogger, serialize
        from iterinject.core.search_types import SeedTrial
        from iterinject.core.types import ExecutionFailure
        from iterinject.adapters.injecagent.dataset import load_case
        from iterinject.adapters.injecagent.initializers import InjecAgentInitializer
        from iterinject.cli import _model_snapshot, _file_info, _code_info
        from iterinject.adapters.injecagent.optimizer import InjecAgentPromptOptimizer
        from iterinject.adapters.injecagent.simulated_responses import SIMULATION_PROMPT_INFO
        case = load_case(self.data_dir, target.target_id, self.attack, self.setting)
        if target.objective != case.objective:
            raise ValueError('trial target objective must match its InjecAgent case')
        if not isinstance(reference_successes, tuple) or any(not isinstance(s, str) or not s.strip() for s in reference_successes):
            raise ValueError('reference_successes must be a tuple of nonempty text')
        reference_hashes = self._reference_hashes(reference_successes)
        clients = self._trial_clients()
        before_counts = self._counts(clients)
        record_starts = {role: len(getattr(clients.get(role), 'call_records', [])) for role in self.ROLES}
        trial_id = 'trial-' + uuid4().hex
        optimizer = InjecAgentPromptOptimizer(clients['optimizer'], case, self.tools, template_path=self.optimizer_template)
        source_files = [self.data_dir / f'test_cases_{self.attack}_{self.setting}.json', self.data_dir / 'tools.json']
        if self.attack == 'ds':
            source_files.append(self.data_dir / 'attacker_simulated_responses.json')
        metadata = {
            'mode': self.mode, 'evaluation_scope': self.evaluation_scope, 'operation': 'seed_trial',
            'trial_id': trial_id, 'case_id': case.case_id, 'target': serialize(target),
            'search_seed': serialize(seed), 'method_config': serialize(self.method),
            'method_configuration': (self.method_configuration if self.method_configuration is not None
                                     else {'inner_loop': serialize(self.method)}),
            'benchmark': {'adapter': 'injecagent', 'attack': self.attack, 'setting': self.setting, 'prompt_type': self.prompt_type},
            'models': {role: _model_snapshot(clients[role]) if clients.get(role) is not None else None for role in self.ROLES},
            'diagnostic_policy': self.policy.snapshot(),
            'code': _code_info(), 'optimizer_prompt': optimizer.template_info,
            'optimizer_prompt_approval': 'explicit_approved_template' if self.optimizer_template else 'user_approved_injecagent_source_adaptation',
            'data': {'source': case.source, 'files': [_file_info(path) for path in source_files if path.is_file()]},
            'reference_successes': list(reference_successes),
            'reference_hashes': reference_hashes,
        }
        if self.attack == 'ds':
            metadata['simulation'] = {'mode': self.simulation_mode, 'source_cache': 'read_only',
                'generated_cache': 'attacker_simulated_responses.json' if self.simulation_mode == 'generate_on_miss' else None,
                'prompt': SIMULATION_PROMPT_INFO if self.simulation_mode == 'generate_on_miss' else None}
        logger = RunLogger(self.output_dir / trial_id, metadata)
        initializer = self.initializer or InjecAgentInitializer(clients.get('initializer'), asset_root=self.asset_root)
        interface_start = getattr(initializer, 'interface_calls', 0)
        initialization, failure = None, None
        try:
            initialization = initializer.initialize(target, seed, case, self.tools)
        except Exception as exc:
            reported = getattr(exc, 'failure', None)
            failure = reported if isinstance(reported, ExecutionFailure) else ExecutionFailure(
                'initializer_error', f'{type(exc).__name__} during initialization')
        init_calls = getattr(initializer, 'interface_calls', 0) - interface_start
        provenance = initialization.provenance if initialization is not None else {
            'initializer_kind': seed.initializer_kind, 'seed_id': seed.seed_id,
            'definition_sha256': seed.definition_sha256,
        }
        self._write(logger.run_dir / 'initializer.json', {
            'provenance': provenance, 'payload': initialization.payload if initialization is not None else None,
            'failure': failure, 'call_records': deepcopy(getattr(clients.get('initializer'), 'call_records', [])[record_starts['initializer']:]),
            'interface_calls': init_calls,
            'api_calls': self._counts(clients)['initializer'] - before_counts['initializer'],
            'trial_id': trial_id, 'target_id': target.target_id, 'seed_id': seed.seed_id,
        })
        if failure is not None:
            after_counts = self._counts(clients)
            counts = {role: after_counts[role] - before_counts[role] for role in self.ROLES}
            interfaces = {role: 0 for role in self.ROLES}
            interfaces['initializer'] = init_calls
            self._write(logger.run_dir / 'summary.json', {
                'schema_version': '1.0', 'stop_reason': 'initialization_failure',
                'attempt_count': 0, 'failure': failure, 'initialization_failure': failure,
                'model_call_counts': counts, 'model_interface_counts': interfaces,
            })
            return SeedTrial(trial_id, target.target_id, seed.seed_id, None,
                str(logger.run_dir), counts, provenance, failure, interfaces)
        from iterinject.adapters.injecagent.optimizer import InjecAgentPromptOptimizer
        from iterinject.adapters.injecagent.runner import InjecAgentRunner
        from iterinject.adapters.injecagent.metrics import case_outcome
        from iterinject.adapters.injecagent.simulated_responses import GeneratedSimulatedResponses, ReadOnlySimulatedResponses
        from iterinject.core.optimizer import run_optimizer
        from iterinject.cli import _RecordedOptimizerClient
        simulated_responses = None
        if self.attack == 'ds':
            simulated_responses = (GeneratedSimulatedResponses(self.data_dir, clients.get('simulation'),
                self.tools, logger.run_dir / 'attacker_simulated_responses.json')
                if self.simulation_mode == 'generate_on_miss' else ReadOnlySimulatedResponses(self.data_dir))
        optimizer.client = _RecordedOptimizerClient(clients['optimizer'], logger)
        evaluator = InjecAgentRunner(case, clients['victim'], self.tools,
            simulated_responses=simulated_responses, diagnostic_policy=self.policy,
            prompt_type=self.prompt_type)
        result = run_optimizer(target, SeedContext(seed.seed_id, seed.strategy_id, seed.variant_id),
            initialization.payload, evaluator, optimizer, self.method,
            reference_successes=reference_successes, on_attempt=logger.record_attempt)
        terminal = result.attempts[-1].result
        if result.failure and terminal.failure is None:
            terminal = AttemptResult(failure=result.failure, trace=terminal.trace)
        outcome = case_outcome(case.case_id, self.attack, terminal)
        after_counts = self._counts(clients)
        counts = {role: after_counts[role] - before_counts[role] for role in self.ROLES}
        interfaces = {role: 0 for role in self.ROLES}
        interfaces.update(initializer=init_calls, victim=result.victim_calls,
                          optimizer=result.optimizer_calls,
                          simulation=getattr(simulated_responses, 'generation_count', 0))
        logger.finish(result, outcome, model_call_counts=counts, model_interface_counts=interfaces)
        return SeedTrial(trial_id, target.target_id, seed.seed_id, result,
                         str(logger.run_dir), counts, provenance, interface_calls=interfaces)
