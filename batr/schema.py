"""
schema.py – Pydantic models for BATR events, flags, and incidents.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Event(BaseModel):
    event_id: str
    timestamp: datetime
    agent_id: str
    agent_role: Literal["finance", "support", "data_retrieval"]
    event_type: Literal["tool_call", "memory_write"]
    tool_name: str
    approval_status: Literal["approved", "not_required", "missing"]
    data_origin: Literal["internal", "user", "external_untrusted"]
    token_cost: int
    # label is ONLY for evaluation – never read by the engine
    label: str = "benign"


class Flag(BaseModel):
    rule_name: str
    event_id: str
    agent_id: str
    timestamp: datetime
    evidence: str


class Incident(BaseModel):
    incident_id: str
    agent_id: str
    flags: List[Flag]
    start_time: datetime
    end_time: datetime
    severity_score: int
    severity_level: str  # LOW / MEDIUM / HIGH / CRITICAL
