"""
engine.py – Loads rules.yaml and runs 4 detection checks per event.

Rules (all thresholds from YAML):
  1. Baseline Deviation  – z-score on calls-per-minute and token_cost
  2. Scope Violation     – tool not in agent's allowed_tools
  3. Missing Approval    – high-risk tool + approval_status != approved
  4. Origin Mismatch     – memory_write from external_untrusted
"""
from __future__ import annotations

import math
import os
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from batr.schema import Event, Flag

_RULES_PATH = Path(__file__).parent / "rules.yaml"


def _load_rules(path: Path = _RULES_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Per-agent baseline state ─────────────────────────────────────────────────

class _AgentBaseline:
    """Tracks call-rate and token_cost statistics for one agent."""

    def __init__(self, window: int, z_threshold: float):
        self.window = window          # number of events to learn from
        self.z_threshold = z_threshold
        self._costs: List[float] = []
        self._timestamps: deque[datetime] = deque()
        self._seen_tools: set[str] = set()
        self._trained = False

        # learned stats
        self._cost_mean: float = 0.0
        self._cost_std: float = 1.0
        self._rate_mean: float = 0.0
        self._rate_std: float = 1.0

    # --- internal helpers ---

    def _calls_per_minute(self) -> float:
        if len(self._timestamps) < 2:
            return 0.0
        span = (self._timestamps[-1] - self._timestamps[0]).total_seconds()
        if span == 0:
            return float(len(self._timestamps))
        return len(self._timestamps) / (span / 60.0)

    @staticmethod
    def _std(values: List[float]) -> float:
        n = len(values)
        if n < 2:
            return 1.0
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
        return math.sqrt(variance) or 1.0

    def _train(self) -> None:
        self._cost_mean = sum(self._costs) / len(self._costs)
        self._cost_std = self._std(self._costs)

        # compute per-event rates over rolling windows of 10 events
        rates: List[float] = []
        ts_list = list(self._timestamps)
        for i in range(10, len(ts_list)):
            span = (ts_list[i] - ts_list[i - 10]).total_seconds()
            if span > 0:
                rates.append(10 / (span / 60.0))
        if rates:
            self._rate_mean = sum(rates) / len(rates)
            self._rate_std = self._std(rates)
        else:
            self._rate_mean = 0.0
            self._rate_std = 1.0

        self._trained = True

    def update(self, event: Event) -> None:
        """Add a benign training event."""
        self._costs.append(float(event.token_cost))
        self._timestamps.append(event.timestamp)
        self._seen_tools.add(event.tool_name)
        if len(self._costs) >= self.window and not self._trained:
            self._train()

    def check(self, event: Event) -> Tuple[bool, str]:
        """
        Returns (flagged, evidence).
        Only checks after training is complete.
        """
        if not self._trained:
            return False, ""

        reasons: List[str] = []

        # Unseen tool
        if event.tool_name not in self._seen_tools:
            reasons.append(f"tool '{event.tool_name}' never seen in baseline")

        # Token cost z-score
        cost_z = (event.token_cost - self._cost_mean) / self._cost_std
        if abs(cost_z) > self.z_threshold:
            reasons.append(f"token_cost z={cost_z:.1f} (mean={self._cost_mean:.0f})")

        # Call-rate: compute current rate using last 10 timestamps + this event
        recent = list(self._timestamps)[-9:] + [event.timestamp]
        if len(recent) == 10:
            span = (recent[-1] - recent[0]).total_seconds()
            if span > 0:
                current_rate = 10 / (span / 60.0)
                if self._rate_std > 0:
                    rate_z = (current_rate - self._rate_mean) / self._rate_std
                    if abs(rate_z) > self.z_threshold:
                        reasons.append(f"call-rate z={rate_z:.1f} (rate={current_rate:.1f}/min)")

        if reasons:
            return True, "; ".join(reasons)
        return False, ""


# ── Engine ───────────────────────────────────────────────────────────────────

class Engine:
    def __init__(self, rules_path: Path = _RULES_PATH):
        self.rules = _load_rules(rules_path)
        self._baselines: Dict[str, _AgentBaseline] = defaultdict(
            lambda: _AgentBaseline(
                window=self.rules["baseline"]["baseline_window_events"],
                z_threshold=self.rules["baseline"]["z_threshold"],
            )
        )
        self._event_counts: Dict[str, int] = defaultdict(int)

    # ── individual rule checks ───────────────────────────────────────────────

    def _check_scope(self, event: Event) -> Flag | None:
        allowed = self.rules["agents"].get(event.agent_id, {}).get("allowed_tools", [])
        if event.tool_name not in allowed:
            return Flag(
                rule_name="scope_violation",
                event_id=event.event_id,
                agent_id=event.agent_id,
                timestamp=event.timestamp,
                evidence=(
                    f"tool '{event.tool_name}' not in allowed_tools "
                    f"({', '.join(allowed) or 'none'})"
                ),
            )
        return None

    def _check_approval(self, event: Event) -> Flag | None:
        high_risk = self.rules["tool_risk"]["high_risk"]
        if event.tool_name in high_risk and event.approval_status != "approved":
            return Flag(
                rule_name="missing_approval",
                event_id=event.event_id,
                agent_id=event.agent_id,
                timestamp=event.timestamp,
                evidence=(
                    f"high-risk tool '{event.tool_name}' called with "
                    f"approval_status='{event.approval_status}'"
                ),
            )
        return None

    def _check_origin(self, event: Event) -> Flag | None:
        if event.event_type == "memory_write" and event.data_origin == "external_untrusted":
            return Flag(
                rule_name="origin_mismatch",
                event_id=event.event_id,
                agent_id=event.agent_id,
                timestamp=event.timestamp,
                evidence=(
                    f"memory_write from data_origin='{event.data_origin}'"
                ),
            )
        return None

    def _check_baseline(self, event: Event) -> Flag | None:
        flagged, evidence = self._baselines[event.agent_id].check(event)
        if flagged:
            return Flag(
                rule_name="baseline_deviation",
                event_id=event.event_id,
                agent_id=event.agent_id,
                timestamp=event.timestamp,
                evidence=f"baseline anomaly: {evidence}",
            )
        return None

    # ── public API ───────────────────────────────────────────────────────────

    def process(self, event: Event) -> List[Flag]:
        """Run all 4 checks on one event. Returns (possibly empty) list of Flags."""
        flags: List[Flag] = []

        n = self._event_counts[event.agent_id]

        # Always train baseline during warmup window (use all events as proxy for
        # benign; the baseline is learned from the first N events of each agent)
        window = self.rules["baseline"]["baseline_window_events"]
        if n < window:
            self._baselines[event.agent_id].update(event)
            self._event_counts[event.agent_id] += 1
            # Still run the other 3 deterministic rules during warmup
            for check in (self._check_scope, self._check_approval, self._check_origin):
                f = check(event)
                if f:
                    flags.append(f)
            return flags

        self._event_counts[event.agent_id] += 1

        for check in (
            self._check_baseline,
            self._check_scope,
            self._check_approval,
            self._check_origin,
        ):
            f = check(event)
            if f:
                flags.append(f)

        # Keep baseline updated with post-warmup events too (sliding)
        self._baselines[event.agent_id].update(event)
        return flags

    def run(self, events: List[Event]) -> List[Flag]:
        """Process all events and return every flag produced."""
        all_flags: List[Flag] = []
        for event in events:
            all_flags.extend(self.process(event))
        return all_flags
