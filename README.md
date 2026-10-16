# BATR – Behavior-Aware Threat Reasoning

Monitors AI agent activity logs, flags risky behavior with YAML-defined rules, merges flags into incidents, and surfaces them in a Streamlit dashboard.

## Requirements

Python 3.10+

## Setup

```
pip install -r requirements.txt
```

## Run the dashboard

From the project root (`batr/`):

```
streamlit run batr/app.py
```

Then open `http://localhost:8501`, adjust the controls in the sidebar, and click **Run analysis**.

Optional: set `GROQ_API_KEY` in your environment to use Groq Llama-3 for incident summaries. Without it the fallback template is used automatically.

## Run tests

```
pytest batr/tests/test_engine.py -v
```

## File layout

```
batr/
  rules.yaml            rule config (agent tools, thresholds, weights)
  schema.py             Pydantic Event / Flag / Incident models
  generator.py          seeded synthetic log generator
  engine.py             loads rules.yaml, runs 4 checks per event
  correlator.py         merges flags into incidents, computes severity
  summarizer.py         Groq Llama-3 summary with template fallback
  app.py                Streamlit dashboard
  tests/
    test_engine.py      15 pytest tests (rules + correlation)
requirements.txt
README.md
```
