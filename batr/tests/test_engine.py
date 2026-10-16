"""
tests/test_engine.py – pytest tests: one per rule + one correlation test.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from batr.engine import Engine
from batr.correlator import correlate
from batr.schema import Event, Flag


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event(**kwargs) -> Event:
    defaults = dict(
        event_id="evt-001",
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
        agent_id="finance_agent_1",
        agent_role="finance",
        event_type="tool_call",
        tool_name="query_balance",
        approval_status="not_required",
        data_origin="internal",
        token_cost=50,
        label="benign",
    )
    defaults.update(kwargs)
    return Event(**defaults)


def _warmed_engine(agent_id: str = "finance_agent_1") -> Engine:
    """Return an Engine whose baseline for agent_id is fully trained."""
    engine = Engine()
    base_ts = datetime(2024, 1, 1, 8, 0, 0)
    for i in range(55):  # > baseline_window_events (50)
        e = _event(
            event_id=f"warm-{i}",
            timestamp=base_ts + timedelta(seconds=i * 60),
            agent_id=agent_id,
            tool_name="query_balance",
            token_cost=50,
        )
        engine.process(e)
    return engine


# ── Rule 1: Scope Violation ────────────────────────────────────────────────────

def test_scope_violation_flagged():
    engine = Engine()
    e = _event(tool_name="delete_record")  # not in finance allowed_tools
    flags = engine.process(e)
    assert any(f.rule_name == "scope_violation" for f in flags), (
        "Expected scope_violation flag for disallowed tool"
    )


def test_scope_violation_not_flagged_for_allowed_tool():
    engine = Engine()
    e = _event(tool_name="query_balance")  # allowed for finance_agent_1
    flags = engine.process(e)
    assert not any(f.rule_name == "scope_violation" for f in flags), (
        "Should not flag allowed tool as scope_violation"
    )


# ── Rule 2: Missing Approval ───────────────────────────────────────────────────

def test_missing_approval_flagged():
    engine = Engine()
    e = _event(tool_name="transfer_funds", approval_status="missing")
    flags = engine.process(e)
    assert any(f.rule_name == "missing_approval" for f in flags)


def test_missing_approval_approved_ok():
    engine = Engine()
    e = _event(tool_name="transfer_funds", approval_status="approved")
    flags = engine.process(e)
    assert not any(f.rule_name == "missing_approval" for f in flags)


def test_missing_approval_low_risk_tool_not_flagged():
    engine = Engine()
    e = _event(tool_name="query_balance", approval_status="missing")
    flags = engine.process(e)
    assert not any(f.rule_name == "missing_approval" for f in flags), (
        "Low-risk tool should not trigger missing_approval"
    )


# ── Rule 3: Origin Mismatch ────────────────────────────────────────────────────

def test_origin_mismatch_flagged():
    engine = Engine()
    e = _event(event_type="memory_write", data_origin="external_untrusted")
    flags = engine.process(e)
    assert any(f.rule_name == "origin_mismatch" for f in flags)


def test_origin_mismatch_internal_ok():
    engine = Engine()
    e = _event(event_type="memory_write", data_origin="internal")
    flags = engine.process(e)
    assert not any(f.rule_name == "origin_mismatch" for f in flags)


def test_origin_mismatch_tool_call_not_flagged():
    """event_type=tool_call with external_untrusted should NOT trigger origin_mismatch."""
    engine = Engine()
    e = _event(event_type="tool_call", data_origin="external_untrusted")
    flags = engine.process(e)
    assert not any(f.rule_name == "origin_mismatch" for f in flags)


# ── Rule 4: Baseline Deviation ────────────────────────────────────────────────

def test_baseline_deviation_unseen_tool():
    engine = _warmed_engine()
    e = _event(
        event_id="atk-unseen",
        timestamp=datetime(2024, 1, 2, 0, 0, 0),
        tool_name="never_seen_tool",
    )
    flags = engine.process(e)
    assert any(f.rule_name == "baseline_deviation" for f in flags), (
        "Unseen tool should trigger baseline_deviation"
    )


def test_baseline_deviation_token_spike():
    engine = _warmed_engine()
    # Inject an event with extremely high token_cost (z >> 3)
    e = _event(
        event_id="atk-token",
        timestamp=datetime(2024, 1, 2, 0, 0, 0),
        token_cost=99999,
    )
    flags = engine.process(e)
    assert any(f.rule_name == "baseline_deviation" for f in flags), (
        "Extreme token_cost z-score should trigger baseline_deviation"
    )


def test_baseline_deviation_not_flagged_during_warmup():
    """Events during warmup window (first 50) should not produce baseline_deviation."""
    engine = Engine()
    flags = engine.process(_event(event_id="w-001", token_cost=50))
    assert not any(f.rule_name == "baseline_deviation" for f in flags)


# ── Correlation test ───────────────────────────────────────────────────────────

def test_correlate_merges_flags_within_window():
    """Two flags from the same agent within 300 s → one incident."""
    base = datetime(2024, 1, 1, 12, 0, 0)
    flags = [
        Flag(
            rule_name="scope_violation",
            event_id="e1",
            agent_id="finance_agent_1",
            timestamp=base,
            evidence="test",
        ),
        Flag(
            rule_name="missing_approval",
            event_id="e2",
            agent_id="finance_agent_1",
            timestamp=base + timedelta(seconds=100),
            evidence="test2",
        ),
    ]
    incidents = correlate(flags)
    assert len(incidents) == 1, "Flags within window should merge into one incident"
    assert incidents[0].severity_score == 8  # 4 + 4


def test_correlate_splits_flags_outside_window():
    """Two flags from same agent but gap > 300 s → two incidents."""
    base = datetime(2024, 1, 1, 12, 0, 0)
    flags = [
        Flag(
            rule_name="scope_violation",
            event_id="e1",
            agent_id="finance_agent_1",
            timestamp=base,
            evidence="test",
        ),
        Flag(
            rule_name="missing_approval",
            event_id="e2",
            agent_id="finance_agent_1",
            timestamp=base + timedelta(seconds=400),
            evidence="test2",
        ),
    ]
    incidents = correlate(flags)
    assert len(incidents) == 2, "Flags outside window should be separate incidents"


def test_correlate_severity_level_critical():
    """Score >= 8 should map to CRITICAL."""
    base = datetime(2024, 1, 1, 12, 0, 0)
    flags = [
        Flag(rule_name="scope_violation", event_id="e1", agent_id="finance_agent_1",
             timestamp=base, evidence="a"),
        Flag(rule_name="missing_approval", event_id="e2", agent_id="finance_agent_1",
             timestamp=base + timedelta(seconds=10), evidence="b"),
        Flag(rule_name="origin_mismatch", event_id="e3", agent_id="finance_agent_1",
             timestamp=base + timedelta(seconds=20), evidence="c"),
    ]
    incidents = correlate(flags)
    assert incidents[0].severity_level == "CRITICAL"
    assert incidents[0].severity_score == 12  # 4+4+4


def test_correlate_different_agents_separate_incidents():
    """Same-time flags from different agents → different incidents."""
    base = datetime(2024, 1, 1, 12, 0, 0)
    flags = [
        Flag(rule_name="scope_violation", event_id="e1", agent_id="finance_agent_1",
             timestamp=base, evidence="x"),
        Flag(rule_name="scope_violation", event_id="e2", agent_id="support_agent_1",
             timestamp=base + timedelta(seconds=5), evidence="y"),
    ]
    incidents = correlate(flags)
    assert len(incidents) == 2
    agents = {i.agent_id for i in incidents}
    assert agents == {"finance_agent_1", "support_agent_1"}
