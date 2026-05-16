"""
Week 1 CCA-F Exercise: Secure Agentic Tool-Use Loop
====================================================
Demonstrates the core Claude stop_reason loop with enterprise security:
  - Credentials from environment only (never hardcoded)
  - All tool inputs validated and path-traversal-hardened before execution
  - Allowlist-based file access (agent cannot escape the sandbox)
  - Structured audit log for every tool call
  - Hard iteration cap to prevent runaway agent loops
  - Tool exception isolation — failures return structured errors, never crash the loop
  - API retry with exponential backoff for transient errors
  - Tool failure escalation — repeated failures trigger human handoff
  - Human confirmation gate on all write operations (consequential action pattern)
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from secrets import get_secret

# ---------------------------------------------------------------------------
# SECURITY: Load .env first, then retrieve credentials through secrets.py.
# All secret access is centralized there — to migrate to a real secrets
# manager (GCP, AWS, Vault), only secrets.py needs to change.
# ---------------------------------------------------------------------------
load_dotenv()
API_KEY = get_secret("ANTHROPIC_API_KEY")

# ---------------------------------------------------------------------------
# SECURITY: Define the sandbox. The agent may only read files inside this
# directory. resolve() gives us the absolute, canonical path — no symlink tricks.
# ---------------------------------------------------------------------------
SANDBOX_DIR = (Path(__file__).parent / "allowed_files").resolve()

# Hard cap on agentic loop iterations. Prevents infinite loops if the model
# keeps requesting tools without reaching end_turn.
MAX_ITERATIONS = 10

# If this many tool calls fail in a single agent run, stop and escalate to a human.
# Repeated failures signal something is wrong that the agent cannot self-correct.
MAX_TOOL_FAILURES = 3

# API retry settings for transient errors (rate limits, network blips).
API_MAX_RETRIES = 3
API_BACKOFF_BASE = 2  # seconds — doubles each retry: 2s, 4s, 8s

# SECURITY: Write operations are restricted to these extensions.
# The agent cannot create scripts, config files, or executables.
ALLOWED_WRITE_EXTENSIONS = {".txt"}

# SECURITY: Maximum content size for a write operation.
# Prevents the agent from writing arbitrarily large files.
MAX_WRITE_BYTES = 10_000

# ---------------------------------------------------------------------------
# AUDIT LOGGING
# Every tool call is logged with timestamp, tool name, inputs, and result.
# In production this would go to a SIEM or centralized log store.
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s UTC | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("agent_audit")


def audit(event: str, detail: dict) -> None:
    logger.info("%s | %s", event, json.dumps(detail))


# ---------------------------------------------------------------------------
# TOOL DEFINITIONS
# These tell Claude what tools exist and what inputs they expect.
# Descriptions matter — Claude uses them to decide when and how to call tools.
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "list_files",
        "description": (
            "List all files available in the knowledge base. "
            "Call this first when you need to find relevant information."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "read_file",
        "description": (
            "Read the full contents of a file from the knowledge base. "
            "Use list_files first to see what files are available."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "The exact filename to read (e.g. 'security_policy.txt').",
                }
            },
            "required": ["filename"],
        },
    },
    {
        "name": "search_file",
        "description": (
            "Search for a keyword within a specific file. "
            "Returns all lines containing the keyword (case-insensitive)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "The exact filename to search.",
                },
                "keyword": {
                    "type": "string",
                    "description": "The keyword or phrase to search for.",
                },
            },
            "required": ["filename", "keyword"],
        },
    },
    {
        "name": "write_file",
        "description": (
            "Write a new file to the knowledge base. "
            "IMPORTANT: Only call this tool after you have shown the user exactly what "
            "you plan to write and they have explicitly asked you to proceed. "
            "Never call this tool speculatively or before confirming with the user. "
            "Will fail if the file already exists."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "The filename to create (e.g. 'summary.txt'). Must end in .txt.",
                },
                "content": {
                    "type": "string",
                    "description": "The full text content to write to the file.",
                },
            },
            "required": ["filename", "content"],
        },
    },
]


# ---------------------------------------------------------------------------
# TOOL IMPLEMENTATIONS
# Each function validates its inputs before doing anything.
# ---------------------------------------------------------------------------

def _resolve_safe_path(filename: str) -> Path | None:
    """
    SECURITY: Resolve a filename to an absolute path and verify it sits
    inside SANDBOX_DIR. Blocks path traversal attacks like '../../../etc/passwd'.
    Returns None if the path escapes the sandbox.
    """
    # Strip any directory components the model might have added
    safe_name = Path(filename).name
    candidate = (SANDBOX_DIR / safe_name).resolve()

    # The canonical path must start with the sandbox — no escape allowed
    if not str(candidate).startswith(str(SANDBOX_DIR)):
        audit("SECURITY_VIOLATION", {"attempted_path": filename, "resolved": str(candidate)})
        return None
    return candidate


def tool_list_files() -> str:
    files = [f.name for f in SANDBOX_DIR.iterdir() if f.is_file()]
    audit("TOOL_CALL", {"tool": "list_files", "result_count": len(files)})
    if not files:
        return "No files are available in the knowledge base."
    return "Available files:\n" + "\n".join(f"- {f}" for f in sorted(files))


def tool_read_file(filename: str) -> str:
    # SECURITY: Validate input type before using it
    if not isinstance(filename, str) or not filename.strip():
        return "Error: filename must be a non-empty string."

    path = _resolve_safe_path(filename)
    if path is None:
        return "Error: access denied — file is outside the permitted directory."
    if not path.exists():
        return f"Error: '{filename}' not found in the knowledge base."
    if not path.is_file():
        return "Error: that path is not a file."

    content = path.read_text(encoding="utf-8")
    audit("TOOL_CALL", {"tool": "read_file", "filename": filename, "bytes_read": len(content)})
    return content


def tool_search_file(filename: str, keyword: str) -> str:
    if not isinstance(filename, str) or not filename.strip():
        return "Error: filename must be a non-empty string."
    if not isinstance(keyword, str) or not keyword.strip():
        return "Error: keyword must be a non-empty string."

    # SECURITY: Limit keyword length to prevent regex-style abuse
    if len(keyword) > 200:
        return "Error: keyword too long (max 200 characters)."

    path = _resolve_safe_path(filename)
    if path is None:
        return "Error: access denied — file is outside the permitted directory."
    if not path.exists():
        return f"Error: '{filename}' not found in the knowledge base."

    lines = path.read_text(encoding="utf-8").splitlines()
    matches = [
        f"Line {i+1}: {line}"
        for i, line in enumerate(lines)
        if keyword.lower() in line.lower()
    ]

    audit("TOOL_CALL", {"tool": "search_file", "filename": filename, "keyword": keyword, "matches": len(matches)})

    if not matches:
        return f"No matches found for '{keyword}' in {filename}."
    return f"Found {len(matches)} match(es) for '{keyword}' in {filename}:\n\n" + "\n".join(matches)


def tool_write_file(filename: str, content: str) -> str:
    """
    CONSEQUENTIAL ACTION: Write a new file to the sandbox.

    This function is a pure validated write — it does NOT ask for confirmation.
    The confirmation gate lives in the orchestrator (run_agent), which intercepts
    write_file tool calls before dispatching them. Tools should be pure functions;
    orchestrators decide what to call and when.

    Security layers:
      1. Extension allowlist — only .txt files permitted
      2. Path traversal check — cannot escape SANDBOX_DIR
      3. No-overwrite rule — cannot silently replace existing files
      4. Content size cap — prevents runaway writes
    """
    if not isinstance(filename, str) or not filename.strip():
        return "Error: filename must be a non-empty string."
    if not isinstance(content, str) or not content.strip():
        return "Error: content must be non-empty."

    # SECURITY: Extension allowlist — reject anything that isn't .txt
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_WRITE_EXTENSIONS:
        audit("SECURITY_VIOLATION", {"reason": "disallowed_extension", "filename": filename, "suffix": suffix})
        return f"Error: only {ALLOWED_WRITE_EXTENSIONS} files may be written. Got '{suffix}'."

    # SECURITY: Content size cap
    if len(content.encode("utf-8")) > MAX_WRITE_BYTES:
        return f"Error: content exceeds maximum allowed size ({MAX_WRITE_BYTES} bytes)."

    # SECURITY: Path traversal check
    path = _resolve_safe_path(filename)
    if path is None:
        return "Error: access denied — file is outside the permitted directory."

    # SECURITY: No silent overwrites
    if path.exists():
        return (
            f"Error: '{filename}' already exists. "
            "Delete it manually before writing a new version."
        )

    path.write_text(content, encoding="utf-8")
    audit("WRITE_CONFIRMED", {"filename": filename, "bytes_written": len(content.encode("utf-8"))})
    return f"File '{filename}' created successfully ({len(content.encode('utf-8'))} bytes)."


def dispatch_tool(name: str, inputs: dict) -> str:
    """Route a tool call from Claude to the correct implementation."""
    if name == "list_files":
        return tool_list_files()
    elif name == "read_file":
        return tool_read_file(inputs.get("filename", ""))
    elif name == "search_file":
        return tool_search_file(inputs.get("filename", ""), inputs.get("keyword", ""))
    elif name == "write_file":
        return tool_write_file(inputs.get("filename", ""), inputs.get("content", ""))
    else:
        # SECURITY: Unknown tool names are rejected, not silently ignored
        audit("SECURITY_VIOLATION", {"unknown_tool": name, "inputs": inputs})
        return f"Error: unknown tool '{name}'."


def safe_dispatch_tool(name: str, inputs: dict, failure_counter: list) -> str:
    """
    RELIABILITY: Wraps dispatch_tool so that any unexpected exception is caught,
    logged, and returned to Claude as a structured error string rather than
    crashing the entire agent loop.

    Claude receives the error and can decide to retry with different parameters,
    try a different tool, or inform the user — rather than the loop dying silently.

    failure_counter is a one-element list used as a mutable int across loop iterations.
    """
    try:
        return dispatch_tool(name, inputs)
    except Exception as exc:
        failure_counter[0] += 1
        audit("TOOL_EXCEPTION", {
            "tool": name,
            "inputs": inputs,
            "error": str(exc),
            "failure_count": failure_counter[0],
        })
        return (
            f"Error: tool '{name}' raised an unexpected exception: {exc}. "
            "Please try a different approach or a different tool."
        )


def call_api_with_retry(client: anthropic.Anthropic, **kwargs) -> anthropic.types.Message:
    """
    RELIABILITY: Wraps client.messages.create with exponential backoff for
    transient errors (rate limits, network blips). Permanent errors (auth
    failures, invalid requests) are re-raised immediately — retrying those
    would just burn quota and delay the failure signal.

    Backoff schedule: 2s → 4s → 8s, then re-raise.
    """
    for attempt in range(1, API_MAX_RETRIES + 1):
        try:
            return client.messages.create(**kwargs)
        except anthropic.RateLimitError as exc:
            if attempt == API_MAX_RETRIES:
                audit("API_ERROR", {"type": "rate_limit", "attempts": attempt, "final": True})
                raise
            wait = API_BACKOFF_BASE ** attempt
            audit("API_RETRY", {"type": "rate_limit", "attempt": attempt, "wait_seconds": wait})
            print(f"  [Rate limited] Waiting {wait}s before retry {attempt}/{API_MAX_RETRIES}...")
            time.sleep(wait)
        except anthropic.APIConnectionError as exc:
            if attempt == API_MAX_RETRIES:
                audit("API_ERROR", {"type": "connection_error", "attempts": attempt, "final": True})
                raise
            wait = API_BACKOFF_BASE ** attempt
            audit("API_RETRY", {"type": "connection_error", "attempt": attempt, "wait_seconds": wait})
            print(f"  [Connection error] Waiting {wait}s before retry {attempt}/{API_MAX_RETRIES}...")
            time.sleep(wait)
        # anthropic.AuthenticationError, BadRequestError, etc. are NOT caught —
        # they indicate a code or config problem that retrying won't fix.


# ---------------------------------------------------------------------------
# THE AGENTIC LOOP
# This is the core CCA-F pattern: send → inspect stop_reason → execute tools
# → return results → repeat until end_turn or iteration cap hit.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a helpful HR and Security assistant for ACME Corp. "
    "You have access to the company knowledge base via tools. "
    "Always use list_files first, then read or search the relevant file. "
    "Answer only from the knowledge base — do not use outside knowledge. "
    "If the answer is not in the files, say so clearly. "
    "IMPORTANT: Before calling write_file, always read the source material first, "
    "then show the user a summary of what you plan to write and ask them to confirm. "
    "Only call write_file after the user has explicitly said yes."
)


def _confirm_write(filename: str, content: str) -> bool:
    """
    HUMAN CONFIRMATION GATE — lives in the orchestrator, not the tool.

    Tools are pure functions. The orchestrator decides what to call and when.
    This intercepts write_file calls before dispatch and requires explicit
    human approval. The agent loop pauses here until the operator responds.
    """
    print("\n" + "!" * 60)
    print("  WRITE OPERATION — HUMAN APPROVAL REQUIRED")
    print("!" * 60)
    print(f"  File : {filename}")
    print(f"  Size : {len(content.encode('utf-8'))} bytes")
    print(f"  Preview:")
    for line in content.splitlines()[:10]:
        print(f"    {line}")
    if len(content.splitlines()) > 10:
        print(f"    ... ({len(content.splitlines()) - 10} more lines)")
    print()
    audit("WRITE_PENDING_APPROVAL", {"filename": filename, "bytes": len(content.encode("utf-8"))})
    response = input("  Type YES (exact, all caps) to authorize, or anything else to cancel: ").strip()
    approved = response == "YES"
    if not approved:
        audit("WRITE_CANCELLED", {"filename": filename, "operator_response": response})
    return approved


def run_agent(messages: list, tool_failure_count: list) -> tuple[str, bool]:
    """
    Run one turn of the agentic loop against an existing message history.

    Returns (answer_text, needs_continuation) where needs_continuation is
    True when Claude asked a follow-up question and is waiting for user input.
    """
    client = anthropic.Anthropic(api_key=API_KEY)

    for iteration in range(1, MAX_ITERATIONS + 1):
        if tool_failure_count[0] >= MAX_TOOL_FAILURES:
            audit("AGENT_ESCALATION", {
                "reason": "max_tool_failures_reached",
                "failures": tool_failure_count[0],
                "iteration": iteration,
            })
            return (
                f"[ESCALATION REQUIRED] {tool_failure_count[0]} tool errors occurred. "
                "A human agent should review audit.log and handle this manually.",
                False,
            )

        print(f"\n[Iteration {iteration}] Calling Claude API...")

        response = call_api_with_retry(
            client,
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        print(f"  stop_reason: {response.stop_reason}")

        if response.stop_reason == "end_turn":
            final_text = next(
                (block.text for block in response.content if hasattr(block, "text")),
                "(no text response)"
            )
            # Add Claude's answer to history so the conversation can continue
            messages.append({"role": "assistant", "content": response.content})
            audit("AGENT_END", {"iterations": iteration, "tool_failures": tool_failure_count[0]})
            return final_text, True  # True = conversation can continue

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue

                print(f"  Tool requested: {block.name}({json.dumps(block.input)})")

                # ----------------------------------------------------------
                # CONFIRMATION GATE — intercept write_file before dispatch.
                # The orchestrator authorizes; the tool only executes.
                # ----------------------------------------------------------
                if block.name == "write_file":
                    filename = block.input.get("filename", "")
                    content = block.input.get("content", "")
                    if not _confirm_write(filename, content):
                        result = f"Write cancelled by operator. '{filename}' was not created."
                        print(f"  Write cancelled.")
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })
                        continue

                result = safe_dispatch_tool(block.name, block.input, tool_failure_count)
                print(f"  Tool result preview: {result[:120]}{'...' if len(result) > 120 else ''}")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })

            messages.append({"role": "user", "content": tool_results})
            continue

        audit("AGENT_ERROR", {"unexpected_stop_reason": response.stop_reason, "iteration": iteration})
        return f"Agent stopped unexpectedly: stop_reason='{response.stop_reason}'", False

    audit("AGENT_ERROR", {"reason": "max_iterations_reached", "cap": MAX_ITERATIONS})
    return f"Agent halted: reached maximum iteration limit ({MAX_ITERATIONS}).", False


# ---------------------------------------------------------------------------
# ENTRY POINT — test with three questions that exercise all three tools
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("ACME Corp HR & Security Assistant")
    print("Type your question, or 'quit' to exit.\n")

    # Message history persists for the entire session — Claude remembers context
    messages: list = []
    tool_failure_count = [0]

    while True:
        user_input = input("You: ").strip()
        if not user_input:
            continue
        if user_input.lower() in {"quit", "exit", "q"}:
            print("Session ended.")
            break

        print(f"\n{'='*60}")
        print(f"Question: {user_input}")
        print(f"{'='*60}")

        messages.append({"role": "user", "content": user_input})
        audit("AGENT_START", {"question": user_input})

        answer, can_continue = run_agent(messages, tool_failure_count)

        print(f"\nAssistant: {answer}\n")
        print("-" * 60)
