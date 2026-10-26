"""Monitor reviewer, Claude Code backend (default): runs on a Claude Pro / Max plan.

Each review is one headless `claude -p` call whose only tools are the monitor's MCP
tools (mcp_server.py): every built-in tool (Bash, files, web) is disabled, and
permissions are "dontAsk" with only `mcp__aab` allowed. The login is the one made
once over SSH in the monitor container (`claude` then `/login`), or
CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`; it is stored in the
monitor's home volume.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from tools import SYSTEM

MODEL = os.environ.get("MONITOR_MODEL", "sonnet")
TIMEOUT_S = int(os.environ.get("MONITOR_CC_TIMEOUT_S", "900"))
MAX_TURNS = os.environ.get("MONITOR_MAX_TOOL_TURNS", "24")
HERE = Path(__file__).resolve().parent
NOT_LOGGED_IN = ("not logged in", "please run /login", "invalid api key", "oauth token",
                 "authentication_error", "/login")


def command(mcp_config: str) -> list[str]:
    return ["claude", "-p", "--output-format", "json", "--model", MODEL,
            "--system-prompt", SYSTEM,
            "--mcp-config", mcp_config, "--strict-mcp-config",
            "--tools", "", "--allowedTools", "mcp__aab", "--permission-mode", "dontAsk",
            "--max-turns", str(MAX_TURNS), "--no-session-persistence"]


def mcp_config() -> dict:
    env = {k: os.environ[k] for k in ("MONITOR_DB_DSN", "MONITOR_AUTO_KILL") if os.environ.get(k)}
    return {"mcpServers": {"aab": {"type": "stdio", "command": "python3",
                                   "args": [str(HERE / "mcp_server.py")], "env": env}}}


def parse_result(stdout: str, stderr: str, returncode: int) -> dict:
    """{stopped, summary, error, not_logged_in} from `claude -p --output-format json`."""
    try:
        out = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
    except ValueError:
        out = {}
    text = str(out.get("result") or "")
    failed = returncode != 0 or out.get("is_error") or not out
    err = None
    if failed:
        err = (text or stderr or stdout or f"claude exited with {returncode}").strip()[-2000:]
    low = (err or "").lower()
    return {"stopped": out.get("subtype") or ("error" if failed else None),
            "summary": text if not failed else None, "error": err,
            "not_logged_in": bool(err) and any(s in low for s in NOT_LOGGED_IN),
            "cost_usd": out.get("total_cost_usd")}


def claude_env() -> dict:
    env = {**os.environ}
    env.pop("ANTHROPIC_API_KEY", None)  # use the plan login, never a stray API key
    if os.environ.get("MONITOR_CC_API_KEY"):  # explicit opt-in to bill an API key instead
        env["ANTHROPIC_API_KEY"] = os.environ["MONITOR_CC_API_KEY"]
    return env


def logged_in() -> bool | None:
    """Whether Claude Code has credentials (local check, no model call); None if unknown."""
    try:
        p = subprocess.run(["claude", "auth", "status", "--json"], capture_output=True, text=True,
                           env=claude_env(), timeout=30)
        return bool(json.loads(p.stdout).get("loggedIn"))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def review(briefing: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="aab-review-") as tmp:
        cfg = Path(tmp) / "mcp.json"
        cfg.write_text(json.dumps(mcp_config()))
        env = claude_env()
        try:
            p = subprocess.run(command(str(cfg)), input=briefing, capture_output=True, text=True,
                               cwd=tmp, env=env, timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return {"stopped": "timeout", "summary": None, "not_logged_in": False,
                    "error": f"claude -p did not finish in {TIMEOUT_S}s"}
        except FileNotFoundError:
            return {"stopped": "error", "summary": None, "not_logged_in": False,
                    "error": "claude CLI not found"}
    return parse_result(p.stdout, p.stderr, p.returncode)
