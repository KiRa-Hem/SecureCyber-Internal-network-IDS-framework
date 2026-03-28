"""
Autonomous Model Updating Pipeline.

Monitors drift alerts and triggers model retraining when thresholds are
exceeded.  Provides shadow-model A/B comparison using holdout data and
model health status.

Phase 4: Real retraining via retrain_on_drift.py subprocess + holdout eval.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Paths
_BASE_DIR = Path(__file__).resolve().parents[2]
_MODEL_DIR = _BASE_DIR / "models" / "cicids2018_packet"
_RETRAIN_SCRIPT = _BASE_DIR / "models" / "training_scripts" / "retrain_on_drift.py"
_HOLDOUT_EVAL_PATH = _MODEL_DIR / "holdout_eval.json"


class ModelUpdater:
    """Tracks model health, drift events, and manages autonomous retraining."""

    HEALTH_GREEN = "green"
    HEALTH_YELLOW = "yellow"
    HEALTH_RED = "red"

    def __init__(self):
        self.model_version: str = "1.0.0"
        self.last_retrain_ts: Optional[float] = None
        self.drift_events: deque = deque(maxlen=100)
        self.retrain_history: List[Dict[str, Any]] = []
        self.retrain_queued: bool = False
        self.shadow_model_active: bool = False
        self.shadow_eval_count: int = 0
        self.shadow_correct: int = 0
        self.active_correct: int = 0
        self._startup_ts = time.time()

        # Phase 4: subprocess tracking
        self._retrain_process: Optional[subprocess.Popen] = None
        self._retrain_thread: Optional[threading.Thread] = None
        self._retrain_status: str = "idle"  # idle | running | success | failed
        self._retrain_error: Optional[str] = None
        self._baseline_metrics: Optional[Dict[str, Any]] = None

        # Load baseline holdout metrics on startup
        self._load_baseline_metrics()

    # ------------------------------------------------------------ baseline

    def _load_baseline_metrics(self) -> None:
        """Load the current model's holdout evaluation as baseline for comparison."""
        try:
            if _HOLDOUT_EVAL_PATH.exists():
                with open(_HOLDOUT_EVAL_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._baseline_metrics = data.get("metrics", {})
                logger.info(
                    "Baseline holdout metrics loaded: F1=%.4f, AUC=%.4f",
                    self._baseline_metrics.get("f1", 0),
                    self._baseline_metrics.get("roc_auc", 0),
                )
            else:
                logger.info("No holdout_eval.json found — shadow comparison will use accuracy only.")
        except Exception as exc:
            logger.warning("Failed to load baseline metrics: %s", exc)

    # ---------------------------------------------------------------- drift

    def record_drift(self, drift_alert: Dict[str, Any]) -> None:
        """Record a drift event and check if retraining should be queued."""
        if not settings.AUTO_RETRAIN_ENABLED:
            return

        self.drift_events.append({
            "timestamp": int(time.time()),
            "features": drift_alert.get("drift_features", []),
            "confidence": drift_alert.get("confidence", 0.6),
        })

        recent = self._recent_drift_count(window_seconds=3600)
        if recent >= settings.AUTO_RETRAIN_DRIFT_THRESHOLD and not self.retrain_queued:
            self._queue_retrain(reason=f"{recent} drift alerts in the last hour")

    def _recent_drift_count(self, window_seconds: int = 3600) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for d in self.drift_events if d["timestamp"] > cutoff)

    # --------------------------------------------------------------- retrain

    def _queue_retrain(self, reason: str = "") -> None:
        """Queue a real retraining job via retrain_on_drift.py subprocess."""
        self.retrain_queued = True
        self.shadow_model_active = True
        self.shadow_eval_count = 0
        self.shadow_correct = 0
        self.active_correct = 0

        entry = {
            "version": self._next_version(),
            "queued_at": int(time.time()),
            "reason": reason,
            "status": "retrain_running",
        }
        self.retrain_history.append(entry)
        logger.info("Retraining queued → shadow model v%s (%s)", entry["version"], reason)

        # Phase 4: Backup current model, then launch subprocess
        self._backup_model()
        self._launch_retrain_subprocess()

    def _backup_model(self) -> None:
        """Backup the current XGBoost model before retraining."""
        model_file = _MODEL_DIR / "attack_classifier_xgb.json"
        backup_file = _MODEL_DIR / "attack_classifier_xgb.backup.json"
        try:
            if model_file.exists():
                shutil.copy2(str(model_file), str(backup_file))
                logger.info("Model backed up to %s", backup_file)
        except Exception as exc:
            logger.warning("Model backup failed: %s", exc)

    def _launch_retrain_subprocess(self) -> None:
        """Launch retrain_on_drift.py as a non-blocking subprocess in a thread."""
        self._retrain_status = "running"
        self._retrain_error = None

        def _run():
            try:
                cmd = [
                    sys.executable,
                    str(_RETRAIN_SCRIPT),
                    "--force",
                    "--model-dir", str(_MODEL_DIR),
                ]

                # Add MongoDB URI if available
                try:
                    mongo_uri = settings.MONGO_URI_COMPUTED
                    if mongo_uri:
                        cmd.extend(["--mongo-uri", mongo_uri])
                except Exception:
                    pass

                logger.info("Retrain subprocess starting: %s", " ".join(cmd))
                self._retrain_process = subprocess.Popen(
                    cmd,
                    cwd=str(_BASE_DIR),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                stdout, stderr = self._retrain_process.communicate(timeout=1800)
                exit_code = self._retrain_process.returncode

                if exit_code == 0:
                    self._retrain_status = "success"
                    logger.info("Retrain subprocess completed successfully")
                    if stdout:
                        logger.debug("Retrain stdout: %s", stdout[-500:])

                    # Reload holdout metrics for shadow comparison
                    self._load_baseline_metrics()

                    # Compare new model against baseline using holdout data
                    self._compare_shadow_model()
                else:
                    self._retrain_status = "failed"
                    self._retrain_error = stderr[-500:] if stderr else f"Exit code {exit_code}"
                    logger.error("Retrain subprocess failed (exit=%d): %s", exit_code, self._retrain_error)
                    self._rollback_model()

            except subprocess.TimeoutExpired:
                self._retrain_status = "failed"
                self._retrain_error = "Retrain process timed out (30 min)"
                logger.error("Retrain subprocess timed out")
                if self._retrain_process:
                    self._retrain_process.kill()
                self._rollback_model()

            except Exception as exc:
                self._retrain_status = "failed"
                self._retrain_error = str(exc)
                logger.error("Retrain subprocess error: %s", exc)
                self._rollback_model()

            finally:
                self._retrain_process = None
                # Update history entry
                if self.retrain_history:
                    self.retrain_history[-1]["status"] = self._retrain_status
                    self.retrain_history[-1]["completed_at"] = int(time.time())
                    if self._retrain_error:
                        self.retrain_history[-1]["error"] = self._retrain_error

        self._retrain_thread = threading.Thread(target=_run, daemon=True, name="retrain")
        self._retrain_thread.start()

    def _rollback_model(self) -> None:
        """Restore the backed-up model on retrain failure."""
        backup_file = _MODEL_DIR / "attack_classifier_xgb.backup.json"
        model_file = _MODEL_DIR / "attack_classifier_xgb.json"
        try:
            if backup_file.exists():
                shutil.copy2(str(backup_file), str(model_file))
                logger.info("Model rolled back from backup")
        except Exception as exc:
            logger.error("Model rollback failed: %s", exc)

        self.shadow_model_active = False
        self.retrain_queued = False

    def _compare_shadow_model(self) -> None:
        """Compare the newly trained model against baseline using holdout eval."""
        try:
            # Load the new holdout eval (retrain_on_drift.py writes this)
            if not _HOLDOUT_EVAL_PATH.exists():
                logger.warning("No holdout_eval.json after retrain — skipping comparison")
                self._finalize_shadow_via_holdout(None)
                return

            with open(_HOLDOUT_EVAL_PATH, "r", encoding="utf-8") as f:
                new_eval = json.load(f)

            new_metrics = new_eval.get("metrics", {})
            self._finalize_shadow_via_holdout(new_metrics)

        except Exception as exc:
            logger.error("Shadow model comparison failed: %s", exc)
            self._finalize_shadow_via_holdout(None)

    def _finalize_shadow_via_holdout(self, new_metrics: Optional[Dict[str, Any]]) -> None:
        """Decide whether to keep the new model or rollback based on holdout metrics."""
        baseline = self._baseline_metrics or {}
        baseline_f1 = float(baseline.get("f1", 0))
        baseline_auc = float(baseline.get("roc_auc", 0))

        if new_metrics is None:
            # No metrics available — keep new model (trust the retrain pipeline)
            decision = "swap"
            shadow_f1 = 0.0
            shadow_auc = 0.0
            logger.info("No holdout comparison available — accepting new model on faith")
        else:
            shadow_f1 = float(new_metrics.get("f1", 0))
            shadow_auc = float(new_metrics.get("roc_auc", 0))

            # Compare: new model must not be significantly worse
            # Allow swap if F1 improved OR AUC improved and F1 didn't drop > 5%
            f1_improved = shadow_f1 >= baseline_f1
            auc_improved = shadow_auc >= baseline_auc
            f1_acceptable = shadow_f1 >= baseline_f1 * 0.95  # max 5% F1 drop

            if f1_improved or (auc_improved and f1_acceptable):
                decision = "swap"
                logger.info(
                    "Shadow model PROMOTED (F1: %.4f→%.4f, AUC: %.4f→%.4f)",
                    baseline_f1, shadow_f1, baseline_auc, shadow_auc,
                )
            else:
                decision = "keep"
                logger.info(
                    "Shadow model REJECTED (F1: %.4f→%.4f, AUC: %.4f→%.4f)",
                    baseline_f1, shadow_f1, baseline_auc, shadow_auc,
                )
                self._rollback_model()

        # Update model version and history
        if decision == "swap":
            self.model_version = self._next_version()
            self.last_retrain_ts = time.time()

        if self.retrain_history:
            self.retrain_history[-1]["status"] = decision
            self.retrain_history[-1]["completed_at"] = int(time.time())
            self.retrain_history[-1]["shadow_f1"] = round(shadow_f1, 4)
            self.retrain_history[-1]["shadow_auc"] = round(shadow_auc, 4)
            self.retrain_history[-1]["baseline_f1"] = round(baseline_f1, 4)
            self.retrain_history[-1]["baseline_auc"] = round(baseline_auc, 4)

        self.shadow_model_active = False
        self.retrain_queued = False

    def _next_version(self) -> str:
        parts = self.model_version.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
        except ValueError:
            parts.append("1")
        return ".".join(parts)

    # ----------------------------------------------------------- shadow eval (live packets)

    def shadow_evaluate(self, active_correct: bool, shadow_correct: bool) -> Optional[str]:
        """
        Feed one comparison result between the active and shadow models.
        Returns 'swap' if the shadow model should replace the active one.
        """
        if not self.shadow_model_active:
            return None

        self.shadow_eval_count += 1
        if shadow_correct:
            self.shadow_correct += 1
        if active_correct:
            self.active_correct += 1

        if self.shadow_eval_count >= settings.SHADOW_MODEL_EVAL_PACKETS:
            return self._finalize_shadow_live()
        return None

    def _finalize_shadow_live(self) -> str:
        """Finalize shadow eval based on live packet comparison."""
        shadow_acc = self.shadow_correct / max(self.shadow_eval_count, 1)
        active_acc = self.active_correct / max(self.shadow_eval_count, 1)

        if shadow_acc >= active_acc:
            self.model_version = self._next_version()
            self.last_retrain_ts = time.time()
            decision = "swap"
            logger.info(
                "Shadow model promoted via live eval to v%s (shadow=%.2f%%, active=%.2f%%)",
                self.model_version, shadow_acc * 100, active_acc * 100,
            )
        else:
            decision = "keep"
            logger.info(
                "Shadow model discarded via live eval (shadow=%.2f%%, active=%.2f%%)",
                shadow_acc * 100, active_acc * 100,
            )

        if self.retrain_history:
            self.retrain_history[-1]["status"] = decision
            self.retrain_history[-1]["completed_at"] = int(time.time())
            self.retrain_history[-1]["shadow_accuracy"] = round(shadow_acc, 4)
            self.retrain_history[-1]["active_accuracy"] = round(active_acc, 4)

        self.shadow_model_active = False
        self.retrain_queued = False
        return decision

    # ---------------------------------------------------------------- status

    @property
    def health(self) -> str:
        recent = self._recent_drift_count(window_seconds=3600)
        if recent >= settings.AUTO_RETRAIN_DRIFT_THRESHOLD:
            return self.HEALTH_RED
        if recent >= max(1, settings.AUTO_RETRAIN_DRIFT_THRESHOLD // 2):
            return self.HEALTH_YELLOW
        return self.HEALTH_GREEN

    def get_status(self) -> Dict[str, Any]:
        return {
            "model_version": self.model_version,
            "health": self.health,
            "last_retrain": self.last_retrain_ts,
            "drift_events_1h": self._recent_drift_count(3600),
            "drift_threshold": settings.AUTO_RETRAIN_DRIFT_THRESHOLD,
            "retrain_queued": self.retrain_queued,
            "retrain_status": self._retrain_status,
            "retrain_error": self._retrain_error,
            "shadow_active": self.shadow_model_active,
            "shadow_progress": (
                f"{self.shadow_eval_count}/{settings.SHADOW_MODEL_EVAL_PACKETS}"
                if self.shadow_model_active else None
            ),
            "baseline_metrics": self._baseline_metrics,
            "retrain_history": self.retrain_history[-5:],
            "uptime_seconds": int(time.time() - self._startup_ts),
        }


# Global instance
model_updater = ModelUpdater()

