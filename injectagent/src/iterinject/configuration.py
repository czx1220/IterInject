"""Pure validation and composition of method rules and search-run inputs."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass

from .core.search_types import (
    OUTER_SEARCH_FIELDS, OuterSearchConfiguration, RunConfiguration,
    SearchConfiguration,
)
from .core.types import InnerLoopConfiguration


def _from_mapping(cls, value, name):
    if not isinstance(value, dict):
        raise ValueError(f'{name} must be an object')
    try:
        return cls(**value)
    except TypeError as exc:
        raise ValueError(f'invalid {name} fields: {exc}') from None


@dataclass(frozen=True)
class MethodConfiguration:
    inner_loop: InnerLoopConfiguration
    outer_search: OuterSearchConfiguration

    def snapshot(self):
        return {'inner_loop': asdict(self.inner_loop),
                'outer_search': self.outer_search.snapshot()}


def parse_method_configuration(value):
    """Validate both algorithm layers from the complete method document."""
    if not isinstance(value, dict):
        raise ValueError('method configuration must be an object')
    if set(value) != {'inner_loop', 'outer_search'}:
        raise ValueError('method configuration must contain exactly inner_loop and outer_search')
    value = deepcopy(value)
    inner = _from_mapping(InnerLoopConfiguration, value['inner_loop'],
                          'inner_loop configuration')
    outer = _from_mapping(OuterSearchConfiguration, value['outer_search'],
                          'outer_search configuration')
    return MethodConfiguration(inner, outer)


def parse_run_configuration(value):
    """Validate run identity, scope, budget, and selected seed bindings."""
    if not isinstance(value, dict):
        raise ValueError('run configuration must be an object')
    algorithm_fields = set(value) & set(OUTER_SEARCH_FIELDS)
    if algorithm_fields:
        raise ValueError('outer_search parameters belong in method configuration: ' +
                         ', '.join(sorted(algorithm_fields)))
    return RunConfiguration.from_mapping(deepcopy(value))


def compose_search_configuration(method_value, run_value):
    """Keep method rules and execution inputs separate in the scheduler."""
    method = parse_method_configuration(method_value)
    run = parse_run_configuration(run_value)
    return method, run, SearchConfiguration(method.outer_search, run)
