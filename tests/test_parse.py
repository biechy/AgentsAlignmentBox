import json

from helpers import SESSION, results, sse, tool_use

import anthropic_parse as ap


def test_is_messages_call():
    assert ap.is_messages_call("POST", "api.anthropic.com", "/v1/messages")
    assert ap.is_messages_call("POST", "api.anthropic.com", "/v1/messages?beta=true")
    assert not ap.is_messages_call("POST", "api.anthropic.com", "/v1/messages/count_tokens")
    assert not ap.is_messages_call("GET", "api.anthropic.com", "/v1/messages")
    assert not ap.is_messages_call("POST", "evil.com", "/v1/messages")


def test_sse_reassembles_text_thinking_and_tool_input():
    tu = tool_use("Bash", {"command": "ls -la /", "description": "list"})
    raw = sse([{"type": "thinking", "thinking": "let me look"},
               {"type": "text", "text": "Listing the root."}, tu])
    r = ap.parse_response(raw, "text/event-stream; charset=utf-8")
    assert r.text == "Listing the root."
    assert r.thinking == "let me look"
    assert r.stop_reason == "tool_use"
    assert r.usage["input_tokens"] == 100 and r.usage["output_tokens"] == 42
    assert r.tool_uses() == [{"id": tu["id"], "name": "Bash", "input": tu["input"], "server": False}]


def test_json_response_and_server_tools():
    data = {"id": "msg_1", "model": "m", "stop_reason": "end_turn", "usage": {"input_tokens": 3},
            "content": [
                {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search",
                 "input": {"query": "x"}},
                {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
                 "content": [{"type": "web_search_result", "url": "https://a.org"}]},
                {"type": "text", "text": "done"}]}
    r = ap.parse_response(json.dumps(data).encode(), "application/json")
    assert r.tool_uses()[0]["server"] is True
    assert r.server_tool_results()[0]["tool_use_id"] == "srvtoolu_1"
    assert r.text == "done"


def test_error_response():
    r = ap.parse_response(b'{"type":"error","error":{"type":"overloaded_error"}}', "application/json")
    assert "overloaded" in r.error


def test_session_id_variants():
    assert ap.session_id_from({"metadata": {"user_id": f"user_x_account__session_{SESSION}"}}, {}) == SESSION
    assert ap.session_id_from({"metadata": {"user_id": json.dumps({"session_id": "abc"})}}, {}) == "abc"
    assert ap.session_id_from({}, {"X-Claude-Code-Session-Id": "hdr"}) == "hdr"
    assert ap.session_id_from({}, {}) is None


def test_tool_results_and_text():
    tu = tool_use("Bash", {"command": "ls"})
    msgs = [{"role": "user", "content": "go"}, {"role": "assistant", "content": [tu]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tu["id"],
                                          "content": [{"type": "text", "text": "a\nb"}],
                                          "is_error": True}]}]
    assert ap.tool_results(msgs) == [{"tool_use_id": tu["id"], "content": "a\nb", "is_error": True}]
