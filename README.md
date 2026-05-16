\# Secure Agentic Tool-Use Loop



A production-patterned Claude API agent built as part of CCA-F (Claude Certified Architect – Foundations) exam preparation.



\## What It Demonstrates



\- Full stop\_reason agentic loop (tool\_use → end\_turn)

\- Parallel tool execution

\- Path traversal prevention and sandbox file access

\- Tool exception isolation and structured error handling

\- Exponential backoff on transient API errors

\- Tool failure escalation with human handoff

\- Human confirmation gate on write operations

\- Structured audit logging on every tool call



\## Security Principles Applied



\- API credentials loaded from environment only (.env) — never hardcoded

\- Allowlist-based file sandbox — agent cannot access files outside permitted directory

\- Canonical path resolution blocks path traversal attacks

\- Consequential actions (file writes) require explicit human YES before executing

\- Hard iteration cap prevents runaway agent loops



\## Setup



1\. Clone the repo

2\. Copy `.env.example` to `.env` and add your Anthropic API key

3\. `pip install -r requirements.txt`

4\. `python hr\_kb\_agent.py`



\## Stack



\- Python 3.12

\- Anthropic SDK

\- python-dotenv

