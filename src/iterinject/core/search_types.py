"""Benchmark-independent identities, search rules, and execution inputs."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, field, asdict
import math
import re
from typing import Protocol
from .types import ExecutionFailure, OptimizationResult, TargetSpec


OUTER_SEARCH_FIELDS = (
    'top_k', 'max_seed_trials_per_target', 'max_syntheses_per_target',
    'max_generated_seeds', 'max_references', 'selector_version',
    'selector_threshold', 'initial_seed_score', 'score_update_mode',
    'invalid_target_policy', 'reference_order', 'reference_semantics',
    'new_seed_visibility', 'new_seed_trial_policy',
)


def _from_mapping(cls, value, name):
    if not isinstance(value, dict):
        raise ValueError(f'{name} must be an object')
    try:
        return cls(**deepcopy(value))
    except TypeError as exc:
        raise ValueError(f'invalid {name} fields: {exc}') from None


def nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{name} must be nonempty text')


def validate_search_policy(value):
    """Validate the outer algorithm independently of run identity and assets."""
    for name in ('top_k', 'max_seed_trials_per_target', 'max_syntheses_per_target',
                 'max_generated_seeds', 'max_references'):
        n = value[name]
        if type(n) is not int or n < (1 if name == 'top_k' else 0):
            raise ValueError(f'{name} has an invalid bound')
    for name in ('initial_seed_score', 'selector_threshold'):
        n = value[name]
        try:
            finite = not isinstance(n, bool) and isinstance(n, (int, float)) and math.isfinite(n)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError(f'{name} must be finite')
    policies = {
        'score_update_mode': ('target_atomic_inherit_once_v1',),
        'invalid_target_policy': ('fail_target_no_score_method_failure_in_observed_asr_v1',),
        'reference_order': ('same_tool_chain_then_recent_v1',),
        'reference_semantics': ('labeled_historical_examples_v1',),
        'new_seed_visibility': ('current_target',),
        'new_seed_trial_policy': ('generated_next_once_v1',),
        'selector_version': ('trajectory_table7_v2', 'paper_table7_v1'),
    }
    for name, allowed in policies.items():
        if value[name] not in allowed:
            raise ValueError(f'unsupported {name}')


def validate_search_run(value):
    """Validate run inputs without assuming a particular outer algorithm."""
    for name in ('run_id', 'scope_id'):
        nonempty(value[name], name)
    for name in ('approval_source', 'approved_at'):
        if value.get(name) is not None:
            nonempty(value[name], name)
    if value['status'] not in ('configured', 'approved', 'fixture'):
        raise ValueError('run status must be configured, approved, or fixture')
    n = value['max_api_requests']
    if type(n) is not int or n < 0:
        raise ValueError('max_api_requests has an invalid bound')
    if value['status'] != 'fixture' and value['scope_id'].startswith('fixture:'):
        raise ValueError('formal run cannot use fixture scope')
    bindings = value['seed_bindings']
    if not isinstance(bindings, (list, tuple)) or not bindings:
        raise ValueError('seed_bindings must be a nonempty explicit list')
    ids = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) - {
                'seed_id', 'variant_id', 'initializer_kind', 'target_binding',
                'definition', 'definition_sha256', 'target_mapping'}:
            raise ValueError('invalid seed binding fields')
        for name in ('seed_id', 'variant_id', 'initializer_kind'):
            nonempty(binding.get(name), f'seed binding {name}')
        if value['status'] != 'fixture' and (
                binding['variant_id'].startswith('fixture:') or binding['initializer_kind'] == 'fixture'):
            raise ValueError('formal run cannot use fixture seeds')
        ids.append(binding['seed_id'])
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate seed bindings')


@dataclass(frozen=True)
class SearchSeed:
    seed_id: str
    strategy_id: str
    variant_id: str
    definition_sha256: str
    initializer_kind: str
    source_ref: dict
    parent_seed_ids: tuple[str, ...] = ()
    target_binding: str | None = None
    registered_index: int = 0

    def __post_init__(self):
        for name in ('seed_id', 'strategy_id', 'variant_id', 'initializer_kind'):
            nonempty(getattr(self, name), name)
        if re.fullmatch(r'[0-9a-f]{64}', self.definition_sha256) is None:
            raise ValueError('definition_sha256 must be a SHA256 hex digest')
        if type(self.registered_index) is not int or self.registered_index < 0:
            raise ValueError('registered_index must be nonnegative')
        if not isinstance(self.source_ref, dict):
            raise ValueError('source_ref must be an object')
        if self.target_binding is not None:
            nonempty(self.target_binding, 'target_binding')
        if len(set(self.parent_seed_ids)) != len(self.parent_seed_ids):
            raise ValueError('duplicate parent seed identity')


@dataclass(frozen=True)
class SeedTrial:
    trial_id: str
    target_id: str
    seed_id: str
    optimization: OptimizationResult | None
    run_dir: str
    api_calls: dict[str, int]
    initializer_provenance: dict
    initialization_failure: ExecutionFailure | None = None
    interface_calls: dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        if (self.optimization is None) == (self.initialization_failure is None):
            raise ValueError('trial needs an optimization result or initialization failure')
        for name in ('trial_id', 'target_id', 'seed_id', 'run_dir'):
            nonempty(getattr(self, name), name)
        if any(type(n) is not int or n < 0 for n in self.api_calls.values()):
            raise ValueError('API call counts must be nonnegative integers')

    @property
    def failure(self):
        return self.initialization_failure or (self.optimization.failure if self.optimization else None)


class SeedExecutor(Protocol):
    def execute(self, target: TargetSpec, seed: SearchSeed,
                reference_successes: tuple[str, ...]) -> SeedTrial: ...


class SeedSynthesizer(Protocol):
    def synthesize(self, target: TargetSpec, failed_trials: tuple[SeedTrial, ...],
                   operation: str, parent_seed_ids: tuple[str, ...]) -> SearchSeed: ...


class SearchRecorder(Protocol):
    def event(self, kind: str, fields: dict) -> None: ...
    def commit_target(self, target_result: dict, state: dict) -> None: ...


@dataclass(frozen=True)
class OuterSearchConfiguration:
    """Search algorithm rules owned by the method configuration."""

    top_k: int
    max_seed_trials_per_target: int
    max_syntheses_per_target: int
    max_generated_seeds: int
    max_references: int
    selector_version: str
    selector_threshold: float
    initial_seed_score: float
    score_update_mode: str
    invalid_target_policy: str
    reference_order: str
    reference_semantics: str
    new_seed_visibility: str
    new_seed_trial_policy: str

    def __post_init__(self):
        validate_search_policy(asdict(self))

    @classmethod
    def from_mapping(cls, value):
        return _from_mapping(cls, value, 'outer_search configuration')

    def snapshot(self):
        return asdict(self)


@dataclass(frozen=True)
class RunConfiguration:
    """Identity, request allowance, and explicit assets for one execution."""

    run_id: str
    status: str
    scope_id: str
    max_api_requests: int
    seed_bindings: tuple[dict, ...]
    approval_source: str | None = None
    approved_at: str | None = None

    def __post_init__(self):
        validate_search_run(asdict(self))
        # A caller may retain and mutate the source mapping after construction.
        object.__setattr__(self, 'seed_bindings', tuple(deepcopy(self.seed_bindings)))

    @classmethod
    def from_mapping(cls, value):
        return _from_mapping(cls, value, 'run configuration')

    def snapshot(self):
        value = asdict(self)
        value['seed_bindings'] = list(value['seed_bindings'])
        return {name: item for name, item in value.items()
                if name not in ('approval_source', 'approved_at') or item is not None}


@dataclass(frozen=True)
class SearchConfiguration:
    """Explicit composition of method rules and run inputs for the scheduler."""

    outer_search: OuterSearchConfiguration
    run: RunConfiguration

    def __post_init__(self):
        if not isinstance(self.outer_search, OuterSearchConfiguration):
            raise ValueError('outer_search must be an OuterSearchConfiguration')
        if not isinstance(self.run, RunConfiguration):
            raise ValueError('run must be a RunConfiguration')

    @classmethod
    def from_mapping(cls, value):
        if not isinstance(value, dict):
            raise ValueError('search configuration must be an object')
        if set(value) != {'outer_search', 'run'}:
            raise ValueError('search configuration must contain exactly outer_search and run')
        return cls(OuterSearchConfiguration.from_mapping(value['outer_search']),
                   RunConfiguration.from_mapping(value['run']))

    def snapshot(self):
        return {'outer_search': self.outer_search.snapshot(), 'run': self.run.snapshot()}
