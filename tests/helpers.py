"""Builders for fake Anthropic API traffic (requests and streamed responses)."""
from __future__ import annotations

import itertools
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

_ids = itertools.count(1)

TOOLS = [{"name": n, "input_schema": {"type": "object"}} for n in ("Bash", "WebFetch", "Agent")]
SESSION = "11111111-2222-3333-4444-555555555555"


def tool_use(name: str, inp: dict) -> dict:
    return {"type": "tool_use", "id": f"toolu_{next(_ids):04d}", "name": name, "input": inp}


def request_body(messages: list[dict], tools=TOOLS, model="claude-sonnet-5-5") -> bytes:
    return json.dumps({
        "model": model, "max_tokens": 1000, "stream": True,
        "system": [{"type": "text", "text": "You are Claude Code."}],
        "tools": tools, "messages": messages,
        "metadata": {"user_id": f"user_abc_account__session_{SESSION}"},
    }).encode()


def sse(blocks: list[dict], stop_reason="tool_use", model="claude-sonnet-5-5") -> bytes:
    """Stream `blocks` the way the Messages API does (text and tool_use deltas)."""
    ev = [{"type": "message_start", "message": {
        "id": f"msg_{next(_ids):04d}", "model": model, "role": "assistant", "content": [],
        "usage": {"input_tokens": 100, "output_tokens": 1, "cache_read_input_tokens": 50}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            ev.append({"type": "content_block_start", "index": i,
                       "content_block": {"type": "text", "text": ""}})
            t = b["text"]
            for chunk in (t[: len(t) // 2], t[len(t) // 2:]):
                ev.append({"type": "content_block_delta", "index": i,
                           "delta": {"type": "text_delta", "text": chunk}})
        elif b["type"] == "thinking":
            ev.append({"type": "content_block_start", "index": i,
                       "content_block": {"type": "thinking", "thinking": ""}})
            ev.append({"type": "content_block_delta", "index": i,
                       "delta": {"type": "thinking_delta", "thinking": b["thinking"]}})
        else:  # tool_use / server_tool_use
            ev.append({"type": "content_block_start", "index": i, "content_block": {
                "type": b["type"], "id": b["id"], "name": b["name"], "input": {}}})
            s = json.dumps(b["input"])
            for chunk in (s[:5], s[5:]):
                ev.append({"type": "content_block_delta", "index": i,
                           "delta": {"type": "input_json_delta", "partial_json": chunk}})
        ev.append({"type": "content_block_stop", "index": i})
    ev.append({"type": "message_delta", "delta": {"stop_reason": stop_reason},
               "usage": {"output_tokens": 42}})
    ev.append({"type": "message_stop"})
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in ev).encode()


def assistant(blocks: list[dict]) -> dict:
    return {"role": "assistant", "content": blocks}


def results(*pairs: tuple[dict, str]) -> dict:
    return {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": tu["id"], "content": out} for tu, out in pairs]}


# -- OpenAI Responses API (Codex) ---------------------------------------------
CODEX_THREAD = "0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000"


def codex_body(items: list[dict], thread: str = CODEX_THREAD, model="gpt-5.5-codex") -> bytes:
    return json.dumps({
        "model": model, "instructions": "You are Codex, a coding agent.", "stream": True,
        "store": False, "prompt_cache_key": thread,
        "tools": [{"type": "function", "name": "shell", "parameters": {"type": "object"}},
                  {"type": "web_search"}],
        "input": items,
    }).encode()


def codex_user(text: str) -> dict:
    return {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}


def codex_env() -> dict:
    return codex_user("<environment_context>\n  <cwd>/workspace</cwd>\n</environment_context>")


def codex_call(command: list[str]) -> dict:
    return {"type": "function_call", "name": "shell", "call_id": f"call_{next(_ids):04d}",
            "arguments": json.dumps({"command": command})}


def codex_output(call: dict, out: str) -> dict:
    return {"type": "function_call_output", "call_id": call["call_id"], "output": out}


def codex_sse(items: list[dict], model="gpt-5.5-codex") -> bytes:
    rid = f"resp_{next(_ids):04d}"
    ev = [{"type": "response.created", "response": {"id": rid, "model": model, "status": "in_progress"}}]
    for i, it in enumerate(items):
        ev.append({"type": "response.output_item.added", "output_index": i, "item": it})
        ev.append({"type": "response.output_item.done", "output_index": i, "item": it})
    ev.append({"type": "response.completed", "response": {
        "id": rid, "model": model, "status": "completed",
        "usage": {"input_tokens": 300, "input_tokens_details": {"cached_tokens": 200},
                  "output_tokens": 30}}})
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in ev).encode()


def codex_text(text: str) -> dict:
    return {"type": "message", "role": "assistant", "id": f"msg_{next(_ids):04d}",
            "content": [{"type": "output_text", "text": text}]}
