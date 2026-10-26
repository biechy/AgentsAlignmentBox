"""Kill switch: agents the operator stopped, and the replies the proxy sends them.

The web dashboard (or the monitor, with auto-kill on) inserts a row into
`agent_controls`. The proxy reloads that table every second; from then on every
model call of the agent gets a short final answer telling it that it was stopped
(so Claude Code / Codex end the turn cleanly and a parent agent receives that
answer as the sub-agent's result), and every request of its tool calls is refused.
Deleting the row revives the agent.
"""
from __future__ import annotations

import json
import sys
import threading
import time

BLOCK_REASON = "agent stopped by the operator (kill switch)"
STOP_TEXT = ("[AgentsAlignmentBox] This agent was stopped by the operator. "
             "Do not continue the task and do not start other agents. End your turn now.")


class KillSwitch:
    def __init__(self, dsn: str | None = None, interval_s: float = 1.0):
        self.killed: frozenset[str] = frozenset()
        self.dsn = dsn
        self.interval_s = interval_s
        if dsn:
            threading.Thread(target=self._run, name="obs-killswitch", daemon=True).start()

    def is_killed(self, agent_id: str | None) -> bool:
        return bool(agent_id) and agent_id in self.killed

    def _run(self) -> None:
        import psycopg
        conn = None
        while True:
            try:
                if conn is None or conn.closed:
                    conn = psycopg.connect(self.dsn, autocommit=True)
                rows = conn.execute("SELECT agent_id FROM obs.agent_controls"
                                    " WHERE action = 'kill'").fetchall()
                self.killed = frozenset(r[0] for r in rows)
            except Exception as e:  # noqa: BLE001  keep the last known list
                print(f"[obs-killswitch] {e.__class__.__name__}: {e}", file=sys.stderr, flush=True)
                try:
                    conn and conn.close()
                except Exception:  # noqa: BLE001
                    pass
                conn = None
            time.sleep(self.interval_s)


def anthropic_reply(stream: bool, model: str | None) -> tuple[bytes, str]:
    """(body, content-type) of a Messages API answer that ends the agent's turn."""
    msg = {"id": "msg_aab_stopped", "type": "message", "role": "assistant",
           "model": model or "aab-stopped", "content": [], "stop_reason": None,
           "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}
    if not stream:
        body = {**msg, "content": [{"type": "text", "text": STOP_TEXT}], "stop_reason": "end_turn"}
        return json.dumps(body).encode(), "application/json"
    ev = [
        {"type": "message_start", "message": msg},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": STOP_TEXT}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
         "usage": {"output_tokens": 0}},
        {"type": "message_stop"},
    ]
    return _sse(ev), "text/event-stream"


def openai_reply(stream: bool, model: str | None) -> tuple[bytes, str]:
    """(body, content-type) of a Responses API answer that ends the agent's turn."""
    item = {"type": "message", "id": "msg_aab_stopped", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": STOP_TEXT, "annotations": []}]}
    usage = {"input_tokens": 0, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 0,
             "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 0}
    resp = {"id": "resp_aab_stopped", "object": "response", "created_at": int(time.time()),
            "model": model or "aab-stopped", "status": "completed", "output": [item], "usage": usage}
    if not stream:
        return json.dumps(resp).encode(), "application/json"
    ev = [
        {"type": "response.created", "response": {**resp, "status": "in_progress", "output": []}},
        {"type": "response.output_item.added", "output_index": 0, "item": {**item, "status": "in_progress"}},
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0,
         "item_id": item["id"], "delta": STOP_TEXT},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": resp},
    ]
    return _sse(ev), "text/event-stream"


def _sse(events: list[dict]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()
