"""
generator.py – Seeded synthetic log generator (seed=42).

3 agents per role, benign sequences from role-specific tool distributions,
then injected attacks:
  - scope_violation
  - missing_approval
  - origin_mismatch
  - combined (unauthorized transfer_funds, no approval, same agent, same window)
  - call_rate_spike
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import List

from batr.schema import Event

# Role → benign tool distributions
ROLE_TOOLS = {
    "finance": ["query_balance", "generate_report", "read_transaction_history", "validate_payment"],
    "support": ["lookup_customer", "update_ticket", "send_notification", "read_knowledge_base"],
    "data_retrieval": ["fetch_data", "run_query", "export_csv", "read_schema"],
}

AGENTS = {
    "finance_agent_1": "finance",
    "finance_agent_2": "finance",
    "finance_agent_3": "finance",
    "support_agent_1": "support",
    "support_agent_2": "support",
    "support_agent_3": "support",
    "data_agent_1": "data_retrieval",
    "data_agent_2": "data_retrieval",
    "data_agent_3": "data_retrieval",
}


def _make_event(
    rng: random.Random,
    agent_id: str,
    ts: datetime,
    tool_name: str,
    approval_status: str = "not_required",
    data_origin: str = "internal",
    event_type: str = "tool_call",
    token_cost: int | None = None,
    label: str = "benign",
) -> Event:
    role = AGENTS[agent_id]
    if token_cost is None:
        token_cost = rng.randint(10, 200)
    return Event(
        event_id=str(uuid.UUID(int=rng.getrandbits(128))),
        timestamp=ts,
        agent_id=agent_id,
        agent_role=role,
        event_type=event_type,
        tool_name=tool_name,
        approval_status=approval_status,
        data_origin=data_origin,
        token_cost=token_cost,
        label=label,
    )


def generate_logs(seed: int = 42, n_benign_per_agent: int = 60) -> List[Event]:
    rng = random.Random(seed)
    events: List[Event] = []

    # ── Benign baseline ──────────────────────────────────────────────────────
    base_ts = datetime(2024, 1, 1, 8, 0, 0)
    agent_ts: dict[str, datetime] = {a: base_ts for a in AGENTS}

    for _ in range(n_benign_per_agent):
        for agent_id, role in AGENTS.items():
            tool = rng.choice(ROLE_TOOLS[role])
            agent_ts[agent_id] += timedelta(seconds=rng.randint(20, 90))
            events.append(
                _make_event(rng, agent_id, agent_ts[agent_id], tool)
            )

    # ── Attack injections ────────────────────────────────────────────────────
    # Pick timestamps well after baseline (>= 1 hour after last benign event)
    atk_base = max(e.timestamp for e in events) + timedelta(hours=1)

    # 1. Scope violation – finance_agent_1 uses delete_record (not in allowed list)
    t1 = atk_base + timedelta(seconds=10)
    events.append(
        _make_event(rng, "finance_agent_1", t1, "delete_record", label="scope_violation")
    )

    # 2. Missing approval – support_agent_2 calls send_external_email without approval
    t2 = atk_base + timedelta(seconds=30)
    events.append(
        _make_event(
            rng, "support_agent_2", t2, "send_external_email",
            approval_status="missing", label="missing_approval"
        )
    )

    # 3. Origin mismatch – data_agent_3 memory_write from external_untrusted
    t3 = atk_base + timedelta(seconds=60)
    events.append(
        _make_event(
            rng, "data_agent_3", t3, "fetch_data",
            event_type="memory_write", data_origin="external_untrusted",
            label="origin_mismatch"
        )
    )

    # 4. Combined attack – finance_agent_2: scope + missing_approval, within window
    t4a = atk_base + timedelta(seconds=80)
    events.append(
        _make_event(
            rng, "finance_agent_2", t4a, "transfer_funds",
            approval_status="missing", label="combined_attack"
        )
    )
    t4b = atk_base + timedelta(seconds=120)
    events.append(
        _make_event(
            rng, "finance_agent_2", t4b, "transfer_funds",
            approval_status="missing", data_origin="external_untrusted",
            event_type="memory_write", label="combined_attack"
        )
    )

    # 5. Call-rate spike – data_agent_1 fires 20 rapid calls in <30 s
    spike_start = atk_base + timedelta(seconds=200)
    for i in range(20):
        t_spike = spike_start + timedelta(seconds=i * 1.2)
        events.append(
            _make_event(
                rng, "data_agent_1", t_spike, "run_query",
                token_cost=rng.randint(300, 600),
                label="call_rate_spike"
            )
        )

    # Sort by timestamp
    events.sort(key=lambda e: e.timestamp)
    return events
