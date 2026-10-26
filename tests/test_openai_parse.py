"""Codex traffic (OpenAI Responses API) normalised to the Anthropic shape."""
import json

from helpers import (CODEX_THREAD, codex_body, codex_call, codex_env, codex_output, codex_sse,
                     codex_text, codex_user)

import openai_parse as op


def test_endpoints():
    assert op.is_responses_call("POST", "api.openai.com", "/v1/responses")
    assert op.is_responses_call("POST", "chatgpt.com", "/backend-api/codex/responses")
    assert not op.is_responses_call("GET", "chatgpt.com", "/backend-api/codex/responses")
    assert not op.is_responses_call("POST", "api.openai.com", "/v1/responses/compact")
    assert not op.is_responses_call("POST", "evil.com", "/v1/responses")


def test_request_to_messages():
    call = codex_call(["bash", "-lc", "ls"])
    body = json.loads(codex_body([codex_env(), codex_user("List the files"), call,
                                  codex_output(call, "a.txt"), codex_text("One file.")]))
    msgs = op.to_messages(body)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user", "assistant"]
    assert msgs[1]["content"][0] == {"type": "tool_use", "id": call["call_id"], "name": "shell",
                                     "input": {"command": ["bash", "-lc", "ls"]}}
    assert msgs[2]["content"][0]["tool_use_id"] == call["call_id"]
    assert op.task_text(msgs) == "List the files"          # Codex wrapper skipped
    assert op.session_id_from(body, {}) == CODEX_THREAD
    assert op.session_id_from({}, {"session_id": "s1"}) == "s1"
    assert op.system_text(body).startswith("You are Codex")
    assert op.tool_names(body) == ["shell", "web_search"]
    assert op.parent_session_from({"X-Codex-Parent-Thread-Id": "p1"}) == "p1"


def test_streamed_response():
    call = codex_call(["curl", "-s", "https://example.com"])
    r = op.parse_response(codex_sse([{"type": "reasoning", "summary": [
        {"type": "summary_text", "text": "Need to fetch."}]}, codex_text("Fetching."), call]),
        "text/event-stream")
    assert r.text == "Fetching." and r.thinking == "Need to fetch."
    assert r.tool_uses() == [{"id": call["call_id"], "name": "shell",
                              "input": {"command": ["curl", "-s", "https://example.com"]},
                              "server": False}]
    assert r.usage == {"input_tokens": 100, "output_tokens": 30, "cache_read_input_tokens": 200}
    assert r.stop_reason == "completed" and r.message_id.startswith("resp_")


def test_server_tool_and_errors():
    ws = {"type": "web_search_call", "id": "ws_1", "status": "completed",
          "action": {"type": "search", "query": "heat pumps"}}
    r = op.parse_response(codex_sse([ws, codex_text("ok")]), "text/event-stream")
    assert r.tool_uses()[0]["server"] and r.tool_uses()[0]["name"] == "web_search"
    err = op.parse_response(b'{"error": {"message": "bad key"}}', "application/json")
    assert "bad key" in err.error
    failed = 'data: {"type":"response.failed","response":{"id":"r","status":"failed","error":{"code":"x"}}}\n\n'
    assert op.parse_response(failed, "text/event-stream").error
