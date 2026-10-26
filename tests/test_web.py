"""Parent inference, agent rows and sub-trees of the dashboard (web/server.py); no database."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))
import server as api  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def row(agent_id, running=None, last_seen=NOW):
    return {"agent_id": agent_id, "running_tools_at_start": running, "client_host": "agent-1",
            "model": "m", "first_prompt": "task", "tools_offered": ["Bash"],
            "first_seen": NOW, "last_seen": last_seen, "n_llm_calls": 1, "n_tool_calls": 0,
            "n_http": 0, "input_tokens": 10, "output_tokens": 5}


def test_parent_prefers_spawn_tool_over_bash():
    running = [{"agent_id": "a", "tool_use_id": "t_bash"}, {"agent_id": "b", "tool_use_id": "t_agent"}]
    names = {"t_bash": "Bash", "t_agent": "Agent"}
    assert api.infer_parent(running, names) == "b"
    assert api.infer_parent(running[:1], names) == "a"
    assert api.infer_parent([], names) is None
    assert api.infer_parent([{"agent_id": "a", "tool_use_id": "t_read"}], {"t_read": "Read"}) is None


def test_tree_roles_and_status():
    names = {"t1": "Agent", "t2": "Bash"}
    rows = [row("root"), row("w", [{"agent_id": "root", "tool_use_id": "t1"}]),
            row("c", [{"agent_id": "w", "tool_use_id": "t2"}], last_seen=NOW - timedelta(minutes=5)),
            row("orphan", [{"agent_id": "gone", "tool_use_id": "t1"}])]
    out = {a["agent_id"]: a for a in api.build_agents(rows, names, {"w": 1}, NOW)}
    assert (out["root"]["parent_id"], out["root"]["role"], out["root"]["status"]) == (None, "orchestrator", "running")
    assert (out["w"]["parent_id"], out["w"]["role"], out["w"]["status"]) == ("root", "worker", "flagged")
    assert (out["c"]["parent_id"], out["c"]["role"], out["c"]["status"]) == ("w", "child", "done")
    assert out["orphan"]["parent_id"] is None


def test_evidence_flattened():
    ev = {"candidates": ["ag"], "attribution": "tool_tag", "http_request_ids": [3, 4], "tool_use_id": "tu"}
    assert api._evidence_ids(ev) == ["3", "4", "tu"]
    assert api._evidence_ids(None) == []


def test_json_dates_are_iso():
    import json
    assert json.loads(json.dumps({"ts": NOW}, default=api._json_default)) == {"ts": "2026-10-22T12:00:00+00:00"}


def test_task_text_strips_reminders():
    raw = "<system-reminder>\nenv\n</system-reminder>\n<system-reminder>x</system-reminder>\n\nDo the task."
    assert api.task_text(raw) == "Do the task."
    assert api.task_text(None) == ""


def test_web_search_helpers_fold_into_their_caller():
    names = {"t_ws": "WebSearch", "t_agent": "Agent"}
    helper = row("h", [{"agent_id": "w", "tool_use_id": "t_ws"}])
    helper["tools_offered"] = ["web_search"]
    rows = [row("root"), row("w", [{"agent_id": "root", "tool_use_id": "t_agent"}]), helper]
    assert api.helper_owners(rows, names) == {"h": "w"}
    out = {a["agent_id"]: a for a in api.build_agents(rows, names, {}, NOW)}
    assert set(out) == {"root", "w"}
    assert out["w"]["input_tokens"] == 20 and out["w"]["n_llm_calls"] == 2


def test_background_subagent_matched_by_task():
    sub = row("sub")  # started after the Agent call returned: nothing running
    sub["first_prompt"] = "<system-reminder>x</system-reminder>\nResearch   the market"
    spawns = {api.task_key("Research the market"): "root"}
    out = {a["agent_id"]: a for a in api.build_agents([row("root"), sub], {}, {}, NOW, spawns)}
    assert (out["sub"]["parent_id"], out["sub"]["role"]) == ("root", "worker")


def test_killed_status_wins_and_subtree():
    names = {"t1": "Agent", "t2": "Agent"}
    rows = [row("root"), row("w1", [{"agent_id": "root", "tool_use_id": "t1"}]),
            row("w2", [{"agent_id": "w1", "tool_use_id": "t2"}]), row("other")]
    agents = api.build_agents(rows, names, {"w1": 2}, NOW, killed={"w1"})
    out = {a["agent_id"]: a for a in agents}
    assert out["w1"]["status"] == "killed" and out["w1"]["open_flags"] == 2
    assert api.descendants(agents, "root") == ["w1", "w2"]
    assert api.descendants(agents, "w2") == []


def test_codex_subagent_parent_from_thread_header():
    parent = row("p")
    parent.update(session_id="thread-1", provider="openai")
    child = row("c")
    child.update(session_id="thread-2", parent_session_id="thread-1", provider="openai")
    out = {a["agent_id"]: a for a in api.build_agents([parent, child], {}, {}, NOW)}
    assert (out["c"]["parent_id"], out["c"]["role"], out["c"]["provider"]) == ("p", "worker", "openai")


def test_codex_wrappers_stripped():
    raw = "<environment_context>\n<cwd>/w</cwd>\n</environment_context>\nFix the bug"
    assert api.task_text(raw) == "Fix the bug"
