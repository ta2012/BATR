"""
app.py – BATR Streamlit Dashboard
"""
from __future__ import annotations

import os
import sys

# Ensure the repo root is on sys.path so `batr.*` imports resolve on
# Streamlit Cloud (which adds the file's directory, not the repo root).
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from typing import Dict, List

import pandas as pd
import streamlit as st

from batr.correlator import correlate
from batr.engine import Engine
from batr.generator import generate_logs
from batr.schema import Event, Flag, Incident
from batr.summarizer import summarize

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="BATR – Behavior-Aware Threat Reasoning",
    layout="wide",
)

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

.stApp { background: #0d1117; color: #c9d1d9; }

section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #21262d;
}

/* Metrics */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 14px 18px;
}
[data-testid="stMetric"] label {
    color: #6e7681 !important;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    font-weight: 500;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #e6edf3 !important;
    font-size: 1.6rem;
    font-weight: 600;
}

/* Severity labels */
.sev {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-family: 'Inter', monospace;
}
.sev-LOW      { background: #0d1f16; color: #3fb950; border: 1px solid #238636; }
.sev-MEDIUM   { background: #1f1800; color: #d29922; border: 1px solid #9e6a03; }
.sev-HIGH     { background: #1f0d0d; color: #f85149; border: 1px solid #da3633; }
.sev-CRITICAL { background: #1a0d26; color: #d2a8ff; border: 1px solid #8957e5; }
.sev-BLOCKED  { background: #1f0d0d; color: #f85149; border: 1px solid #da3633; }
.sev-OK       { background: transparent; color: #6e7681; border: 1px solid #21262d; }

/* Incident card */
.inc-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 12px;
}
.inc-meta {
    color: #6e7681;
    font-size: 0.78rem;
    font-family: 'Inter', monospace;
    margin-top: 4px;
}
.inc-summary {
    color: #c9d1d9;
    font-size: 0.88rem;
    margin-top: 10px;
    line-height: 1.5;
}

/* Rule pills */
.rpill {
    display: inline-block;
    margin: 2px 3px;
    padding: 1px 8px;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
    font-family: 'Inter', monospace;
    background: #161b22;
    color: #79c0ff;
    border: 1px solid #1f6feb;
    letter-spacing: 0.03em;
}

/* Quarantine label */
.quarantine-label {
    display: inline-block;
    padding: 4px 10px;
    border: 1px solid #da3633;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    color: #f85149;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

/* Tabs */
button[data-baseweb="tab"] {
    font-size: 0.85rem !important;
    font-weight: 500 !important;
    color: #6e7681 !important;
    letter-spacing: 0.02em;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #e6edf3 !important;
    border-bottom: 2px solid #388bfd !important;
}

/* Divider */
hr { border-color: #21262d !important; }

/* Sidebar headings */
.sidebar-heading {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #6e7681;
    margin: 16px 0 6px 0;
}
</style>
""",
    unsafe_allow_html=True,
)

# ── Session state ─────────────────────────────────────────────────────────────

if "events" not in st.session_state:
    st.session_state.events: List[Event] = []
    st.session_state.flags: List[Flag] = []
    st.session_state.incidents: List[Incident] = []
    st.session_state.summaries: Dict[str, dict] = {}
    st.session_state.agent_registry: Dict[str, str] = {}
    st.session_state.generated = False

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<p class="sidebar-heading">Configuration</p>', unsafe_allow_html=True)
    seed = st.number_input("Seed", value=42, min_value=0, step=1)
    window_sec = st.slider("Correlation window (s)", min_value=60, max_value=600, value=300, step=30)
    n_benign = st.slider("Benign events per agent", min_value=20, max_value=100, value=60, step=10)

    st.markdown("")
    if st.button("Run analysis", use_container_width=True, type="primary"):
        with st.spinner("Generating logs"):
            events = generate_logs(seed=seed, n_benign_per_agent=n_benign)

        with st.spinner("Running detection engine"):
            engine = Engine()
            flags = engine.run(events)

        with st.spinner("Correlating incidents"):
            import pathlib, uuid as _uuid, yaml
            _rules_path = pathlib.Path(__file__).parent / "rules.yaml"
            _rules = yaml.safe_load(_rules_path.read_text())
            _rules["correlation"]["window_seconds"] = window_sec

            def _correlate_patched(flags, rules):
                from batr.correlator import _score_to_level
                from batr.schema import Incident as _Inc
                weights = rules["severity_weights"]
                levels = rules["severity_levels"]
                ws = rules["correlation"]["window_seconds"]
                if not flags:
                    return []
                sorted_flags = sorted(flags, key=lambda f: (f.agent_id, f.timestamp))
                incidents = []
                bucket = [sorted_flags[0]]
                cur_agent = sorted_flags[0].agent_id

                def _flush(b):
                    score = sum(weights.get(f.rule_name, 0) for f in b)
                    return _Inc(
                        incident_id=str(_uuid.uuid4()),
                        agent_id=b[0].agent_id,
                        flags=list(b),
                        start_time=b[0].timestamp,
                        end_time=b[-1].timestamp,
                        severity_score=score,
                        severity_level=_score_to_level(score, levels),
                    )

                for flag in sorted_flags[1:]:
                    gap = (flag.timestamp - bucket[-1].timestamp).total_seconds()
                    if flag.agent_id == cur_agent and gap <= ws:
                        bucket.append(flag)
                    else:
                        incidents.append(_flush(bucket))
                        cur_agent = flag.agent_id
                        bucket = [flag]
                incidents.append(_flush(bucket))
                return incidents

            incidents = _correlate_patched(flags, _rules)

        with st.spinner("Building summaries"):
            summaries = {inc.incident_id: summarize(inc) for inc in incidents}

        st.session_state.events = events
        st.session_state.flags = flags
        st.session_state.incidents = incidents
        st.session_state.summaries = summaries
        st.session_state.agent_registry = {
            a: "active" for a in {e.agent_id for e in events}
        }
        st.session_state.generated = True

    if st.session_state.generated:
        st.markdown("")
        st.markdown('<p class="sidebar-heading">Agent Registry</p>', unsafe_allow_html=True)
        for agent_id, status in sorted(st.session_state.agent_registry.items()):
            col_a, col_b = st.columns([3, 2])
            col_a.markdown(f"`{agent_id}`")
            if status == "quarantined":
                col_b.markdown(
                    '<span class="sev sev-BLOCKED">quarantined</span>',
                    unsafe_allow_html=True,
                )
            else:
                col_b.markdown(
                    '<span class="sev sev-OK">active</span>',
                    unsafe_allow_html=True,
                )

# ── Page header ───────────────────────────────────────────────────────────────

st.markdown(
    """
<div style="padding: 20px 0 4px 0;">
  <h1 style="font-size: 1.5rem; font-weight: 600; margin: 0; color: #e6edf3; letter-spacing: -0.01em;">
    Behavior-Aware Threat Reasoning
  </h1>
  <p style="color: #6e7681; margin: 4px 0 0 0; font-size: 0.85rem;">
    AI agent activity monitor
  </p>
</div>
""",
    unsafe_allow_html=True,
)

# ── Metrics ───────────────────────────────────────────────────────────────────

if st.session_state.generated:
    total_events = len(st.session_state.events)
    total_flags = len(st.session_state.flags)
    total_incidents = len(st.session_state.incidents)
    alert_reduction = round(total_flags / max(total_incidents, 1), 1)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events", total_events)
    c2.metric("Flags", total_flags)
    c3.metric("Incidents", total_incidents)
    c4.metric("Alert reduction", f"{alert_reduction}x", help="Flags / Incidents")
    st.markdown("")

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs(["Live Feed", "Log Detail", "Incidents", "Evaluation"])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 – Live Feed
# ─────────────────────────────────────────────────────────────────────────────

with tab1:
    if not st.session_state.generated:
        st.info("Run analysis from the sidebar.")
    else:
        flagged_event_ids = {f.event_id for f in st.session_state.flags}
        quarantined = {
            a for a, s in st.session_state.agent_registry.items() if s == "quarantined"
        }

        STATUS_BLOCKED = "BLOCKED"
        STATUS_FLAGGED = "FLAGGED"
        STATUS_OK = "OK"

        rows = []
        for e in st.session_state.events:
            is_blocked = e.agent_id in quarantined
            is_flagged = e.event_id in flagged_event_ids
            rows.append(
                {
                    "Status": STATUS_BLOCKED if is_blocked else (STATUS_FLAGGED if is_flagged else STATUS_OK),
                    "Time": e.timestamp.strftime("%H:%M:%S"),
                    "Agent": e.agent_id,
                    "Role": e.agent_role,
                    "Type": e.event_type,
                    "Tool": e.tool_name,
                    "Approval": e.approval_status,
                    "Origin": e.data_origin,
                    "Tokens": e.token_cost,
                    "Label": e.label,
                }
            )

        df = pd.DataFrame(rows)

        fc1, fc2, fc3 = st.columns(3)
        status_filter = fc1.multiselect(
            "Status",
            [STATUS_OK, STATUS_FLAGGED, STATUS_BLOCKED],
            default=[STATUS_OK, STATUS_FLAGGED, STATUS_BLOCKED],
        )
        agent_filter = fc2.multiselect(
            "Agent", sorted(df["Agent"].unique()), default=list(df["Agent"].unique())
        )
        role_filter = fc3.multiselect(
            "Role", sorted(df["Role"].unique()), default=list(df["Role"].unique())
        )

        mask = (
            df["Status"].isin(status_filter)
            & df["Agent"].isin(agent_filter)
            & df["Role"].isin(role_filter)
        )
        filtered_df = df[mask]

        st.caption(f"{len(filtered_df)} events shown")

        def _row_color(row):
            if row["Status"] == STATUS_BLOCKED:
                return ["background-color: rgba(218, 54, 51, 0.12)"] * len(row)
            if row["Status"] == STATUS_FLAGGED:
                return ["background-color: rgba(248, 81, 73, 0.06)"] * len(row)
            return [""] * len(row)

        st.dataframe(
            filtered_df.style.apply(_row_color, axis=1),
            width="stretch",
            height=520,
        )

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 – Log Detail
# ─────────────────────────────────────────────────────────────────────────────

with tab2:
    if not st.session_state.generated:
        st.info("Run analysis from the sidebar.")
    else:
        event_options = {
            f"{e.timestamp.strftime('%H:%M:%S')}  {e.agent_id}  {e.tool_name}  [{e.event_id[:8]}]": e
            for e in st.session_state.events
        }
        selection = st.selectbox("Select event", list(event_options.keys()))
        selected_event = event_options[selection]

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("**Raw event**")
            raw = selected_event.model_dump()
            raw["timestamp"] = raw["timestamp"].isoformat()
            st.json(raw)

        with col_right:
            st.markdown("**Rules fired**")
            fired_flags = [
                f for f in st.session_state.flags if f.event_id == selected_event.event_id
            ]
            if not fired_flags:
                st.caption("No rules fired.")
            else:
                level_map = {
                    "scope_violation": "HIGH",
                    "missing_approval": "HIGH",
                    "origin_mismatch": "HIGH",
                    "baseline_deviation": "MEDIUM",
                }
                for flag in fired_flags:
                    lvl = level_map.get(flag.rule_name, "MEDIUM")
                    st.markdown(
                        f'<span class="sev sev-{lvl}">{flag.rule_name}</span>',
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"**Evidence:** {flag.evidence}")
                    st.markdown("---")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 3 – Incidents
# ─────────────────────────────────────────────────────────────────────────────

with tab3:
    if not st.session_state.generated:
        st.info("Run analysis from the sidebar.")
    elif not st.session_state.incidents:
        st.info("No incidents found.")
    else:
        for inc in st.session_state.incidents:
            summary_data = st.session_state.summaries.get(inc.incident_id, {})
            agent_status = st.session_state.agent_registry.get(inc.agent_id, "active")
            lvl = inc.severity_level

            with st.container():
                st.markdown(
                    f"""
<div class="inc-card">
  <div style="display:flex; align-items:center; gap:10px;">
    <span class="sev sev-{lvl}">{lvl}</span>
    <span style="font-weight:600; color:#e6edf3; font-size:0.95rem;">{inc.agent_id}</span>
  </div>
  <div class="inc-meta">
    {inc.start_time.strftime("%H:%M:%S")} &rarr; {inc.end_time.strftime("%H:%M:%S")}
    &nbsp;&middot;&nbsp; score {inc.severity_score}
    &nbsp;&middot;&nbsp; {len(inc.flags)} flag(s)
  </div>
  <div class="inc-summary">{summary_data.get("summary", "")}</div>
</div>
""",
                    unsafe_allow_html=True,
                )

                col_ev, col_act, col_btn = st.columns([3, 4, 2])

                with col_ev:
                    st.caption("Rules")
                    for rule in summary_data.get("evidence", []):
                        st.markdown(
                            f'<span class="rpill">{rule}</span>',
                            unsafe_allow_html=True,
                        )

                with col_act:
                    st.caption("Recommended action")
                    st.markdown(
                        f'<span style="font-size:0.85rem; color:#c9d1d9;">'
                        f'{summary_data.get("recommended_action", "")}</span>',
                        unsafe_allow_html=True,
                    )

                with col_btn:
                    st.caption("Agent control")
                    if agent_status == "quarantined":
                        st.markdown(
                            '<span class="quarantine-label">quarantined</span>',
                            unsafe_allow_html=True,
                        )
                    else:
                        if st.button(
                            f"Isolate {inc.agent_id}",
                            key=f"isolate_{inc.incident_id}",
                        ):
                            st.session_state.agent_registry[inc.agent_id] = "quarantined"
                            st.rerun()

                if not summary_data.get("summary_reliable", True):
                    st.warning(
                        "LLM evidence did not match actual flags. Summary may be unreliable."
                    )

                with st.expander("Raw flags"):
                    for flag in inc.flags:
                        st.markdown(
                            f"- `[{flag.rule_name}]` `{flag.event_id[:8]}` — {flag.evidence}"
                        )

                st.markdown("---")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4 – Evaluation
# ─────────────────────────────────────────────────────────────────────────────

with tab4:
    if not st.session_state.generated:
        st.info("Run analysis from the sidebar.")
    else:
        st.caption("Labels are only used here. The engine never reads them.")
        st.markdown("")

        events = st.session_state.events
        flags = st.session_state.flags
        incidents = st.session_state.incidents

        flagged_ids = {f.event_id for f in flags}
        attack_ids = {e.event_id for e in events if e.label != "benign"}
        benign_ids = {e.event_id for e in events if e.label == "benign"}

        tp = len(flagged_ids & attack_ids)
        fp = len(flagged_ids & benign_ids)
        fn = len(attack_ids - flagged_ids)
        tn = len(benign_ids - flagged_ids)

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)

        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Precision", f"{precision:.2%}")
        mc2.metric("Recall", f"{recall:.2%}")
        mc3.metric("False-positive rate", f"{fpr:.2%}")
        mc4.metric("F1", f"{f1:.2%}")

        st.markdown("")
        st.markdown("**Counts**")

        # Split into two tables to keep Arrow types consistent
        count_num_df = pd.DataFrame(
            {
                "Metric": [
                    "Total events",
                    "Attack events (ground truth)",
                    "Benign events (ground truth)",
                    "True positives",
                    "False positives",
                    "False negatives",
                    "True negatives",
                    "Raw flags",
                    "Incidents",
                ],
                "Value": [
                    len(events),
                    len(attack_ids),
                    len(benign_ids),
                    tp,
                    fp,
                    fn,
                    tn,
                    len(flags),
                    len(incidents),
                ],
            }
        )
        st.table(count_num_df)
        st.caption(
            f"Alert reduction: {len(flags) / max(len(incidents), 1):.1f}x  "
            f"(flags / incidents)"
        )

        st.markdown("")
        st.markdown("**Per-label breakdown**")
        label_rows = []
        for label in sorted({e.label for e in events}):
            label_events = [e for e in events if e.label == label]
            label_ids = {e.event_id for e in label_events}
            detected = len(flagged_ids & label_ids)
            label_rows.append(
                {
                    "Label": label,
                    "Count": len(label_events),
                    "Detected": detected,
                    "Missed": len(label_ids) - detected,
                    "Detection rate": f"{detected / max(len(label_events), 1):.0%}",
                }
            )
        st.dataframe(pd.DataFrame(label_rows), width="stretch")
