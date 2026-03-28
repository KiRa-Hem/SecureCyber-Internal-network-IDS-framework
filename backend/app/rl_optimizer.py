"""
Reinforcement-learning optimizer for autonomous IDS threshold tuning.

Plugs into the live detection loop via `evaluate_and_adjust()`.  After every
N alerts (configured by RL_EVAL_INTERVAL), the optimizer observes current
attack / false-positive rates, selects a Q-learning action, and optionally
applies the resulting threshold adjustment to the detection pipeline.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import numpy as np

from app.config import settings

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ state

@dataclass(frozen=True)
class RLState:
    """State representation: binned attack + false-positive rates."""

    attack_rate_bin: int
    false_positive_bin: int

    @staticmethod
    def from_metrics(attack_rate: float, false_positive_rate: float) -> "RLState":
        attack_bin = min(4, int(attack_rate * 5))
        fp_bin = min(4, int(false_positive_rate * 5))
        return RLState(attack_bin, fp_bin)


# --------------------------------------------------------------- optimizer

class RLOptimizer:
    """
    Tabular Q-learning for autonomous threshold tuning.

    Actions:
      - decrease_sensitivity → raise confidence threshold (fewer alerts)
      - hold                 → keep current thresholds
      - increase_sensitivity → lower confidence threshold (more alerts)
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

        # Live-loop tracking
        self._alert_counter: int = 0
        self._total_alerts: int = 0
        self._true_positives: int = 0
        self._false_positives: int = 0
        self._total_evaluations: int = 0
        self._total_adjustments: int = 0
        self._last_action: Optional[str] = None
        self._last_eval_ts: Optional[float] = None
        # Start at the XGBoost safety-floor threshold so the RL agent
        # begins at a sensible detection sensitivity.
        self._current_threshold: float = max(
            float(getattr(settings, "XGBOOST_MIN_RUNTIME_THRESHOLD", 0.5)),
            float(settings.RL_THRESHOLD_MIN),
        )
        self._history: list[dict] = []

    # ---------------------------------------------------------------- persistence
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

    # ---------------------------------------------------------------- policy
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

    # ---------------------------------------------------------------- rewards
    @staticmethod
    def compute_reward(detection_rate: float, false_positive_rate: float) -> float:
        penalty = math.pow(false_positive_rate, 2)
        return detection_rate - penalty

    # ---------------------------------------------------------- live loop API

    def record_alert(self, is_true_positive: bool = True) -> Optional[Dict]:
        """
        Called after every alert.  Increments counters and triggers
        an RL evaluation when the interval is reached.
        """
        if not settings.RL_ENABLED:
            return None

        self._alert_counter += 1
        self._total_alerts += 1
        if is_true_positive:
            self._true_positives += 1
        else:
            self._false_positives += 1

        if self._alert_counter >= settings.RL_EVAL_INTERVAL:
            return self.evaluate_and_adjust()
        return None

    def evaluate_and_adjust(self) -> Dict:
        """
        Core live-loop method.  Computes current attack / FP rates,
        chooses an RL action, updates the Q-table, and optionally
        applies the threshold adjustment.
        """
        total = max(self._total_alerts, 1)
        attack_rate = self._true_positives / total
        fp_rate = self._false_positives / total

        state = RLState.from_metrics(attack_rate, fp_rate)
        action = self.choose_action(state)
        reward = self.compute_reward(attack_rate, fp_rate)

        # Apply threshold adjustment
        adjusted = False
        old_threshold = self._current_threshold
        step = settings.RL_THRESHOLD_STEP

        if settings.RL_AUTO_APPLY:
            if action == "increase_sensitivity":
                self._current_threshold = max(
                    settings.RL_THRESHOLD_MIN, self._current_threshold - step
                )
                adjusted = True
            elif action == "decrease_sensitivity":
                self._current_threshold = min(
                    settings.RL_THRESHOLD_MAX, self._current_threshold + step
                )
                adjusted = True

        # Q-learning update with next state from adjusted thresholds
        next_state = RLState.from_metrics(attack_rate, fp_rate)
        self.update_policy(state, action, reward, next_state)

        self._total_evaluations += 1
        if adjusted:
            self._total_adjustments += 1
        self._last_action = action
        self._last_eval_ts = time.time()
        self._alert_counter = 0  # reset interval counter

        result = {
            "evaluation": self._total_evaluations,
            "action": action,
            "reward": round(reward, 4),
            "attack_rate": round(attack_rate, 4),
            "fp_rate": round(fp_rate, 4),
            "old_threshold": round(old_threshold, 4),
            "new_threshold": round(self._current_threshold, 4),
            "adjusted": adjusted,
        }
        self._history.append(result)
        if len(self._history) > 50:
            self._history = self._history[-50:]

        logger.info(
            "RL eval #%d: action=%s reward=%.3f threshold=%.4f→%.4f",
            self._total_evaluations, action, reward,
            old_threshold, self._current_threshold,
        )
        return result

    @property
    def current_threshold(self) -> float:
        """The RL-adjusted confidence threshold for the detection pipeline."""
        return self._current_threshold

    def get_status(self) -> Dict:
        """Return current RL optimizer status for the API."""
        return {
            "enabled": settings.RL_ENABLED,
            "auto_apply": settings.RL_AUTO_APPLY,
            "eval_interval": settings.RL_EVAL_INTERVAL,
            "total_alerts_seen": self._total_alerts,
            "alerts_until_next_eval": max(0, settings.RL_EVAL_INTERVAL - self._alert_counter),
            "total_evaluations": self._total_evaluations,
            "total_adjustments": self._total_adjustments,
            "current_threshold": round(self._current_threshold, 4),
            "last_action": self._last_action,
            "last_eval_timestamp": self._last_eval_ts,
            "q_table_states": len(self.q_table),
            "recent_history": self._history[-10:],
        }

    def recommend_threshold_adjustment(
        self, attack_rate: float, false_positive_rate: float
    ) -> str:
        """Convenience helper to go from raw metrics to an action."""
        state = RLState.from_metrics(attack_rate, false_positive_rate)
        return self.choose_action(state)


# Global singleton
rl_optimizer = RLOptimizer(
    alpha=0.3,
    gamma=0.85,
    epsilon=0.1,
)
