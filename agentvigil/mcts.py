"""MCTS tree with UCB1 selection for AgentVigil fuzzing."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


@dataclass
class MCTSNode:
    prompt: str
    parent: MCTSNode | None = None
    children: list[MCTSNode] = field(default_factory=list)
    visits: int = 0
    total_reward: float = 0.0
    score: float = 0.0
    metadata: dict = field(default_factory=dict)

    @property
    def q_value(self) -> float:
        if self.visits == 0:
            return 0.0
        return self.total_reward / self.visits

    def ucb(self, exploration_constant: float = 1.414) -> float:
        if self.parent is None:
            return self.q_value
        if self.visits == 0:
            return float("inf")
        return self.q_value + exploration_constant * math.sqrt(
            2.0 * math.log(self.parent.visits + 1) / (self.visits + 1e-8)
        )

    def select_child(self, exploration_constant: float = 1.414) -> MCTSNode:
        return max(self.children, key=lambda c: c.ucb(exploration_constant))

    def add_child(self, prompt: str, score: float, metadata: dict | None = None) -> MCTSNode:
        child = MCTSNode(
            prompt=prompt,
            parent=self,
            score=score,
            metadata=metadata or {},
        )
        self.children.append(child)
        return child


@dataclass
class MCTSTree:
    root: MCTSNode
    all_nodes: list[MCTSNode] = field(default_factory=list)

    def __post_init__(self):
        self.all_nodes.append(self.root)

    @classmethod
    def from_seeds(cls, seeds: list[dict]) -> MCTSTree:
        root = MCTSNode(prompt="__root__")
        tree = cls(root=root)
        for seed in seeds:
            child = MCTSNode(
                prompt=seed["prompt"],
                parent=root,
                metadata={
                    "template_name": seed.get("template_name", ""),
                    "injection_task_id": seed.get("injection_task_id", ""),
                    "goal": seed.get("goal", ""),
                },
            )
            root.children.append(child)
            tree.all_nodes.append(child)
        return tree

    def select(self, exploration_constant: float = 1.414) -> MCTSNode:
        node = self.root
        while node.children:
            node = node.select_child(exploration_constant)
        return node

    def backpropagate(self, node: MCTSNode, reward: float) -> None:
        current = node
        while current is not None:
            current.visits += 1
            current.total_reward += reward
            current = current.parent

    def best_seed(self) -> MCTSNode:
        return max(self.all_nodes, key=lambda n: n.score)

    def get_all_prompts(self) -> list[MCTSNode]:
        return [n for n in self.all_nodes if n.prompt != "__root__"]

    def random_prompt(self, exclude: MCTSNode | None = None) -> MCTSNode | None:
        candidates = [
            n for n in self.all_nodes
            if n.prompt != "__root__" and n is not exclude
        ]
        if not candidates:
            return None
        return random.choice(candidates)
