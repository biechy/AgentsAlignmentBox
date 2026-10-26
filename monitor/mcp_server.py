"""Minimal MCP server (stdio, JSON-RPC 2.0) exposing the monitor's tools to Claude Code.

The Claude Code backend (cc_backend.py) starts `claude -p` with this server as its
only tool source, so a Claude Pro / Max plan can drive the reviewer. It is also
available in the monitor's SSH console: run `claude` there and ask about the log.

Tools: list_agents, agent_detail, tool_calls, sql (one read-only SELECT), raise_flag.
No dependency beyond psycopg; one JSON message per line on stdin / stdout.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db  # noqa: E402
from tools import TOOLS, call_tool  # noqa: E402

SERVER_INFO = {"name": "aab-monitor", "version": "1.0.0"}
DEFAULT_PROTOCOL = "2025-06-18"


class Server:
    def __init__(self, conn_factory=db.connect):
        self._conn_factory = conn_factory
        self._conn = None

    @property
    def conn(self):
        if self._conn is None or self._conn.closed:
            self._conn = self._conn_factory()
        return self._conn

    def handle(self, msg: dict) -> dict | None:
        """The response to one JSON-RPC message (None for notifications)."""
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:  # notification (initialized, cancelled...)
            return None
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion") or DEFAULT_PROTOCOL,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": SERVER_INFO}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [{"name": t["name"], "description": t["description"],
                                     "inputSchema": t["input_schema"]} for t in TOOLS]}
            elif method == "tools/call":
                result = self._call(params.get("name"), params.get("arguments") or {})
            else:
                return {"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32601, "message": f"method not found: {method}"}}
        except Exception as e:  # noqa: BLE001
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _call(self, name: str, args: dict) -> dict:
        try:
            out = call_tool(self.conn, name, args)
            return {"content": [{"type": "text", "text": json.dumps(out, default=str)[:60000]}],
                    "isError": False}
        except Exception as e:  # tool errors go back to the model
            if self._conn is not None and getattr(self._conn, "broken", False):
                self._conn = None
            return {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                    "isError": True}


def main() -> None:
    server = Server()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        resp = server.handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
