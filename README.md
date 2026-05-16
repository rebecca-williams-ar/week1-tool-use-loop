# Secure Agentic Tool-Use Loop

A production-patterned Claude API agent built as part of CCA-F (Claude Certified Architect – Foundations) exam preparation.

## What It Demonstrates

- Full stop_reason agentic loop (tool_use → end_turn)
- Parallel tool execution
- Path traversal prevention and sandbox file access
- Tool exception isolation and structured error handling
- Exponential backoff on transient API errors
- Tool failure escalation with human handoff
- Human confirmation gate on write operations (consequential action pattern)
- Structured audit logging on every tool call

## Security Principles Applied

- API credentials loaded from environment only — never hardcoded
- All secret access centralized in `secrets.py` — swap to a real secrets manager by changing one file
- Allowlist-based file sandbox — agent cannot access files outside permitted directory
- Canonical path resolution blocks path traversal attacks
- Consequential actions (file writes) require explicit human YES before executing
- Hard iteration cap prevents runaway agent loops
- Unknown tool names rejected and logged as security violations

> Credentials are managed via `.env` locally (excluded from version control).
> Production deployments should use GCP Secret Manager or equivalent.
> See `.env.example` for required variables.

## Setup

1. Clone the repo
2. Copy `.env.example` to `.env` and add your Anthropic API key
3. `pip install -r requirements.txt`
4. `python hr_kb_agent.py`

## Stack

- Python 3.12
- Anthropic SDK
- python-dotenv
