"""
Reinforcement-learning helper for adapting IDS parameters on the fly.

This module does not plug directly into the realtime detection loop yet, but it
provides a concrete policy optimizer we can call whenever we observe new attack
patterns (for example, after labeling traffic).  It keeps a lightweight
Q-learning table on disk so future training sessions can carry over accumulated
experience.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np

from app.config import settings


@dataclass(frozen=True)
class RLState:
    """State representation for the policy: binned attack + false-positive rates."""

    attack_rate_bin: int
    false_positive_bin: int

    @staticmethod
    def from_metrics(attack_rate: float, false_positive_rate: float) -> "RLState":
        """Quantize raw metrics into coarse bins to keep the Q-table small."""
        attack_bin = min(4, int(attack_rate * 5))
        fp_bin = min(4, int(false_positive_rate * 5))
        return RLState(attack_bin, fp_bin)


class RLOptimizer:
    """
    Simple tabular Q-learning implementation.

    - States encode observed attack/false positive rates.
    - Actions map to detector sensitivity adjustments.
    - Rewards favor high detection with low false positives.
    """

    ACTIONS: Tuple[str, ...] = ("decrease_sensitivity", "hold", "increase_sensitivity")

    def __init__(
        self,
        alpha: float = 0.2,
        gamma: float = 0.9,
        epsilon: float = 0.1,
        model_path: str | None = None,
    ):
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.model_path = model_path or os.path.join("models", "rl_optimizer.json")
        self.q_table: Dict[str, Dict[str, float]] = {}
        self._load()

    # --------------------------------------------------------------------- util
    def _serialize_state(self, state: RLState) -> str:
        return f"{state.attack_rate_bin}:{state.false_positive_bin}"

    def _load(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "r", encoding="utf-8") as handle:
                    self.q_table = json.load(handle)
            except json.JSONDecodeError:
                self.q_table = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "w", encoding="utf-8") as handle:
            json.dump(self.q_table, handle, indent=2)

    # -------------------------------------------------------------------- policy
    def choose_action(self, state: RLState) -> str:
        """ε-greedy action selection."""
        state_key = self._serialize_state(state)
        self.q_table.setdefault(state_key, {action: 0.0 for action in self.ACTIONS})

        if np.random.rand() < self.epsilon:
            return np.random.choice(self.ACTIONS)
        return max(self.q_table[state_key], key=self.q_table[state_key].get)

    def update_policy(
        self,
        state: RLState,
        action: str,
        reward: float,
        next_state: RLState,
    ):
        """Standard Q-learning update."""
        state_key = self._serialize_state(state)
        next_key = self._serialize_state(next_state)

        self.q_table.setdefault(state_key, {a: 0.0 for a in self.ACTIONS})
        self.q_table.setdefault(next_key, {a: 0.0 for a in self.ACTIONS})

        best_future = max(self.q_table[next_key].values())
        td_target = reward + self.gamma * best_future
        td_error = td_target - self.q_table[state_key][action]

        self.q_table[state_key][action] += self.alpha * td_error
        self._save()

    # ------------------------------------------------------------------- rewards
    @staticmethod
    def compute_reward(detection_rate: float, false_positive_rate: float) -> float:
        """
        Favor high detection and penalize false positives.

        Reward = detection_rate - penalty(false_positive_rate)
        """
        penalty = math.pow(false_positive_rate, 2)  # quadratic penalty
        return detection_rate - penalty

    # ------------------------------------------------------------ public facade
    def recommend_threshold_adjustment(
        self,
        attack_rate: float,
        false_positive_rate: float,
    ) -> str:
        """Convenience helper to go from raw metrics to an action."""
        state = RLState.from_metrics(attack_rate, false_positive_rate)
        return self.choose_action(state)


# Global singleton (mirrors other backend helpers)
rl_optimizer = RLOptimizer(
    alpha=0.3,
    gamma=0.85,
    epsilon=float(settings.CONFIDENCE_THRESHOLD) * 0.1,
)
