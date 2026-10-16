"""
correlator.py – Merges flags into Incidents by agent and time window.

Algorithm:
  - Sort flags by (agent_id, timestamp)
  - Merge consecutive flags from the same agent where the gap between
    the current flag and the incident's end_time <= window_seconds
  - Compute severity score = sum of per-rule weights
  - Map total score to severity level (LOW / MEDIUM / HIGH / CRITICAL)
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Dict, List

import yaml

from batr.schema import Flag, Incident

_RULES_PATH = Path(__file__).parent / "rules.yaml"


def _load_rules(path: Path = _RULES_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _score_to_level(score: int, levels: dict) -> str:
    for level_name, bounds in levels.items():
        if bounds["min"] <= score <= bounds["max"]:
            return level_name
    return "CRITICAL"


def correlate(flags: List[Flag], rules_path: Path = _RULES_PATH) -> List[Incident]:
    rules = _load_rules(rules_path)
    window_seconds: int = rules["correlation"]["window_seconds"]
    weights: Dict[str, int] = rules["severity_weights"]
    levels: dict = rules["severity_levels"]

    if not flags:
        return []

    # Sort by agent then timestamp
    sorted_flags = sorted(flags, key=lambda f: (f.agent_id, f.timestamp))

    incidents: List[Incident] = []
    # Working incident buffer
    current_agent: str = sorted_flags[0].agent_id
    bucket: List[Flag] = [sorted_flags[0]]

    def _flush(bucket: List[Flag]) -> Incident:
        score = sum(weights.get(f.rule_name, 0) for f in bucket)
        return Incident(
            incident_id=str(uuid.uuid4()),
            agent_id=bucket[0].agent_id,
            flags=list(bucket),
            start_time=bucket[0].timestamp,
            end_time=bucket[-1].timestamp,
            severity_score=score,
            severity_level=_score_to_level(score, levels),
        )

    for flag in sorted_flags[1:]:
        gap = (flag.timestamp - bucket[-1].timestamp).total_seconds()
        if flag.agent_id == current_agent and gap <= window_seconds:
            bucket.append(flag)
        else:
            incidents.append(_flush(bucket))
            current_agent = flag.agent_id
            bucket = [flag]

    incidents.append(_flush(bucket))
    return incidents
