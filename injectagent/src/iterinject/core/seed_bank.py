"""Deterministic seed ranking and atomic contributions from complete targets."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import math

from .search_types import SearchSeed, SeedTrial
from .types import TargetSpec


def _finite_score(value: float) -> None:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value)):
        raise ValueError("score must be finite")


def trial_mean(trial: SeedTrial) -> float | None:
    """A trial contributes only when every attempt has valid feedback."""
    if trial.initialization_failure is not None or trial.optimization is None:
        return None
    result = trial.optimization
    if result.failure is not None:
        return None
    values = [a.result.feedback.value for a in result.attempts
              if a.result.feedback is not None]
    if len(values) != len(result.attempts) or not values:
        return None
    return sum(values) / len(values)


def target_deltas(eligible_seed_ids_at_commit: tuple[str, ...],
                  tried_means: dict[str, float]) -> dict[str, float]:
    if not tried_means:
        raise ValueError("target has no completed scored trial")
    if not set(tried_means).issubset(eligible_seed_ids_at_commit):
        raise ValueError("scored trial seed is not eligible for this target")
    if len(set(eligible_seed_ids_at_commit)) != len(eligible_seed_ids_at_commit):
        raise ValueError("duplicate eligible seed identity")
    for score in tried_means.values():
        _finite_score(score)
        if not 0 <= score <= 3:
            raise ValueError("trial mean must be in [0, 3]")
    propagated = sum(tried_means.values()) / len(tried_means)
    return {seed_id: tried_means.get(seed_id, propagated)
            for seed_id in eligible_seed_ids_at_commit}


class SeedBank:
    def __init__(self, seeds: tuple[SearchSeed, ...], initial_score: float):
        _finite_score(initial_score)
        self._seeds: dict[str, SearchSeed] = {}
        self._scores: dict[str, float] = {}
        self._pending_seed_ids: set[str] = set()
        self._birth_scores: dict[str, dict[str, float | None]] = {}
        for seed in seeds:
            self.register(seed, initial_score)
        self._pending_seed_ids.clear()
        self._birth_scores.clear()

    @property
    def scores(self) -> dict[str, float]:
        return dict(self._scores)

    def get(self, seed_id: str) -> SearchSeed:
        return self._seeds[seed_id]

    def eligible(self, target: TargetSpec) -> tuple[SearchSeed, ...]:
        return tuple(seed for seed in self._seeds.values()
                     if seed.initializer_kind != "unsupported"
                     and seed.target_binding in (None, target.target_id))

    def rank_untried(self, target: TargetSpec, tried: set[str],
                     k: int) -> tuple[SearchSeed, ...]:
        if type(k) is not int or k < 0:
            raise ValueError("rank limit must be a nonnegative integer")
        candidates = (s for s in self.eligible(target) if s.seed_id not in tried)
        return tuple(sorted(candidates,
                            key=lambda s: (-self._scores[s.seed_id],
                                           s.registered_index))[:k])

    def register(self, seed: SearchSeed, initial_score: float) -> None:
        _finite_score(initial_score)
        if seed.seed_id in self._seeds:
            raise ValueError("duplicate seed identity")
        self._seeds[seed.seed_id] = replace(deepcopy(seed), registered_index=len(self._seeds))
        self._scores[seed.seed_id] = initial_score
        self._pending_seed_ids.add(seed.seed_id)
        self._birth_scores[seed.seed_id] = {
            "provisional_registration_score": initial_score,
            "birth_target_final_score": None,
        }

    def snapshot(self) -> dict:
        return {"version": "seed_bank_v1",
                "seeds": [asdict(seed) for seed in self._seeds.values()],
                "scores": dict(self._scores),
                "pending_seed_ids": [s for s in self._seeds if s in self._pending_seed_ids],
                "birth_scores": deepcopy(self._birth_scores)}

    @classmethod
    def from_state(cls, state: dict) -> SeedBank:
        if not isinstance(state, dict) or state.get("version") != "seed_bank_v1":
            raise ValueError("unsupported seed bank state")
        if set(state) != {"version", "seeds", "scores", "pending_seed_ids", "birth_scores"}:
            raise ValueError("invalid seed bank state fields")
        seeds = []
        for index, value in enumerate(state["seeds"]):
            fields = deepcopy(value)
            if fields.get("registered_index") != index:
                raise ValueError("seed registration order does not match state")
            fields["parent_seed_ids"] = tuple(fields.get("parent_seed_ids", ()))
            seeds.append(SearchSeed(**fields))
        bank = cls(tuple(seeds), initial_score=0.0)
        if set(state["scores"]) != set(bank._seeds):
            raise ValueError("seed state scores do not match identities")
        for score in state["scores"].values():
            _finite_score(score)
        bank._scores = dict(state["scores"])
        bank._pending_seed_ids = set(state["pending_seed_ids"])
        bank._birth_scores = deepcopy(state["birth_scores"])
        if not bank._pending_seed_ids.issubset(bank._seeds):
            raise ValueError("unknown pending seed identity")
        if (not set(bank._birth_scores).issubset(bank._seeds)
                or not bank._pending_seed_ids.issubset(bank._birth_scores)):
            raise ValueError("invalid birth score identity")
        for seed_id, provenance in bank._birth_scores.items():
            if set(provenance) != {"provisional_registration_score", "birth_target_final_score"}:
                raise ValueError("invalid birth score provenance fields")
            _finite_score(provenance["provisional_registration_score"])
            final = provenance["birth_target_final_score"]
            if seed_id in bank._pending_seed_ids:
                if final is not None or bank._scores[seed_id] != provenance["provisional_registration_score"]:
                    raise ValueError("pending seed has inconsistent birth score")
            else:
                _finite_score(final)
                if not 0 <= final <= 3:
                    raise ValueError("birth target final score must be in [0, 3]")
        return bank

    def clone(self) -> SeedBank:
        return self.from_state(self.snapshot())

    def apply_target(self, eligible_seed_ids_at_commit: tuple[str, ...],
                     tried_means: dict[str, float],
                     new_seed_ids_on_target: tuple[str, ...]) -> None:
        deltas = target_deltas(eligible_seed_ids_at_commit, tried_means)
        if not set(deltas).issubset(self._seeds):
            raise ValueError("unknown eligible seed identity")
        new_ids = set(new_seed_ids_on_target)
        if not new_ids.issubset(eligible_seed_ids_at_commit):
            raise ValueError("new seed is not eligible on its birth target")
        if not new_ids.issubset(self._pending_seed_ids):
            raise ValueError("birth target seed was already committed")
        if self._pending_seed_ids.intersection(deltas) != new_ids:
            raise ValueError("pending birth target seed must be declared")
        result = dict(self._scores)
        for seed_id, delta in deltas.items():
            result[seed_id] = (delta if seed_id in new_ids
                               else self._scores[seed_id] + delta)
        self._scores = result
        for seed_id in new_ids:
            self._birth_scores[seed_id]["birth_target_final_score"] = deltas[seed_id]
        self._pending_seed_ids.difference_update(new_ids)
