"""
summarizer.py – Generates incident summaries.

Priority:
  1. GROQ_API_KEY present → Groq Llama 3 (JSON mode)
  2. Any error / no key   → deterministic template fallback

Safety guarantee: the LLM may raise severity but never lower it below
the rule-based severity_level.

Output dict keys: summary, severity, evidence, recommended_action, summary_reliable
"""
from __future__ import annotations

import json
import os
from typing import Dict, Any

from batr.schema import Incident

_ACTIONS: Dict[str, str] = {
    "scope_violation": "Restrict agent tool permissions immediately and audit recent activity.",
    "missing_approval": "Require mandatory approval workflow for high-risk tool calls.",
    "origin_mismatch": "Block external-untrusted data writes and review memory state.",
    "baseline_deviation": "Investigate call-rate spike; consider rate-limiting the agent.",
}

_LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _higher_level(a: str, b: str) -> str:
    ai = _LEVEL_ORDER.index(a) if a in _LEVEL_ORDER else 0
    bi = _LEVEL_ORDER.index(b) if b in _LEVEL_ORDER else 0
    return _LEVEL_ORDER[max(ai, bi)]


def _template_summary(incident: Incident) -> Dict[str, Any]:
    rule_names = list({f.rule_name for f in incident.flags})
    actions = "; ".join(
        _ACTIONS.get(r, "Review agent activity and apply least-privilege policies.")
        for r in rule_names
    )
    evidences = [f.evidence for f in incident.flags]
    summary = (
        f"Agent '{incident.agent_id}' triggered {len(incident.flags)} flag(s) "
        f"({', '.join(rule_names)}) between "
        f"{incident.start_time.strftime('%H:%M:%S')} and "
        f"{incident.end_time.strftime('%H:%M:%S')}. "
        f"Severity: {incident.severity_level} (score {incident.severity_score})."
    )
    return {
        "summary": summary,
        "severity": incident.severity_level,
        "evidence": rule_names,
        "recommended_action": actions,
        "summary_reliable": True,
    }


def _groq_summary(incident: Incident) -> Dict[str, Any]:
    """Call Groq Llama-3.3-70B. Returns dict or raises on failure."""
    from groq import Groq  # type: ignore

    client = Groq(api_key=os.environ["GROQ_API_KEY"])

    flag_lines = "\n".join(
        f"  - [{f.rule_name}] {f.evidence}" for f in incident.flags
    )
    prompt = (
        "You are a security analyst. Analyse this AI agent incident and respond ONLY "
        "with a JSON object (no markdown fences) with keys: "
        "summary (string), severity (one of LOW/MEDIUM/HIGH/CRITICAL), "
        "evidence (list of rule name strings), recommended_action (string).\n\n"
        f"Agent: {incident.agent_id}\n"
        f"Severity (rule-based): {incident.severity_level} (score {incident.severity_score})\n"
        f"Flags:\n{flag_lines}"
    )

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=512,
    )
    raw = response.choices[0].message.content.strip()

    # Strip optional markdown code fences
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    parsed: Dict[str, Any] = json.loads(raw)

    # Safety: never lower severity below rule-based level
    llm_level = parsed.get("severity", incident.severity_level)
    parsed["severity"] = _higher_level(incident.severity_level, llm_level)

    # Verify evidence matches actual flag rule names
    actual_rules = {f.rule_name for f in incident.flags}
    reported_rules = set(parsed.get("evidence", []))
    parsed["summary_reliable"] = actual_rules == reported_rules

    return parsed


def summarize(incident: Incident) -> Dict[str, Any]:
    """Return summary dict for an incident."""
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if api_key:
        try:
            return _groq_summary(incident)
        except Exception as exc:
            # Fallback silently, tag as not from LLM
            result = _template_summary(incident)
            result["summary"] = f"[LLM error: {exc}] " + result["summary"]
            return result
    return _template_summary(incident)
