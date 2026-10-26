"""Entry point for the hidden monitor.

    python run.py --once        # one review cycle, then exit
    python run.py --loop 60     # review every 60s
    python run.py --rules-only  # deterministic rules only, no model

Backends for the model reviewer (MONITOR_BACKEND):
    claude-code  (default) headless Claude Code, billed to the Claude plan the monitor
                 container is logged in with (Pro / Max), see cc_backend.py
    api          Anthropic API tool-use loop, billed to MONITOR_ANTHROPIC_API_KEY, see agent.py
    rules-only   no model at all

Each cycle runs the rules on rows newer than the saved watermarks, scores the new tool
calls with the tabular model (tabular.py), then runs the reviewer when there is new
agent activity (MONITOR_TRIGGER=activity, default) or only when a rule fired or the
tabular model found something unusual (MONITOR_TRIGGER=signals). Every cycle is
recorded in `monitor_runs`.
State (watermarks) is kept in MONITOR_STATE_FILE (default ./monitor_state.json).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import db
import rules

STATE_FILE = os.environ.get("MONITOR_STATE_FILE", "monitor_state.json")
BACKEND = os.environ.get("MONITOR_BACKEND", "claude-code").strip().lower()
TRIGGER = os.environ.get("MONITOR_TRIGGER", "activity").strip().lower()
LOGIN_HINT = ("the monitor's Claude Code is not logged in: run "
              f"`ssh -p {os.environ.get('AAB_MONITOR_SSH_PORT', '2223')} monitor@localhost`, "
              "then `claude` and `/login` (or set MONITOR_CLAUDE_CODE_OAUTH_TOKEN in .env)")


def log(msg: str) -> None:
    print(f"[monitor] {msg}", file=sys.stderr, flush=True)


def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def write_rule_flags(conn, signals: list[rules.Signal]) -> int:
    """Insert rule signals as flags, skipping ones already recorded (same fingerprint)."""
    seen = db.recent_flag_fingerprints(conn, "rule:%")
    n = 0
    for s in signals:
        detector = f"rule:{s.rule}"
        fp = db.fingerprint(detector, s.agent_id, s.category, s.evidence)
        if fp in seen:
            continue
        seen.add(fp)
        db.insert_flag(conn, agent_id=s.agent_id, severity=s.severity, category=s.category,
                       summary=s.summary, evidence=s.evidence, detector=detector)
        n += 1
    return n


def model_name(backend: str) -> str | None:
    if backend == "api":
        from agent import MODEL
        return MODEL
    if backend == "claude-code":
        from cc_backend import MODEL
        return MODEL
    return None


def not_logged_in() -> bool:
    import cc_backend
    return cc_backend.logged_in() is False


def review(conn, backend: str, briefing: str) -> dict:
    """Run the model reviewer; returns {n_flags, stopped, summary, error, not_logged_in}."""
    if backend == "api":
        import anthropic

        from agent import MonitorAgent
        key = os.environ.get("MONITOR_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return {"n_flags": 0, "error": "MONITOR_BACKEND=api needs MONITOR_ANTHROPIC_API_KEY"}
        out = MonitorAgent(conn, anthropic.Anthropic(api_key=key)).review(briefing)
        return {"n_flags": len(out["raised"]), "stopped": out.get("stopped"),
                "summary": out.get("summary")}
    import cc_backend
    before = db._rows(conn, "SELECT coalesce(max(id), 0) AS m FROM flags", cap=1)[0]["m"]
    out = cc_backend.review(briefing)
    n = db._rows(conn, "SELECT count(*) AS n FROM flags WHERE id > %s AND detector = %s",
                 (before, "agent:monitor"), cap=1)[0]["n"]
    return {**out, "n_flags": n}


def tabular_pass(conn, backend: str) -> dict:
    """Score new tool calls with the tabular model; with no model reviewer, its alerts
    become low flags (detector tabular:<model>)."""
    try:
        import tabular
        out = tabular.score_pending(conn)
    except Exception as e:  # noqa: BLE001  never let the hint break the cycle
        log(f"tabular: {type(e).__name__}: {e}")
        return {"model": "error", "n_scored": 0, "alerts": []}
    if out["n_scored"]:
        log(f"tabular ({out['model']}): {out['n_scored']} tool calls scored, "
            f"{len(out['alerts'])} above {tabular.THRESHOLD}")
    if backend == "rules-only":
        seen = db.recent_flag_fingerprints(conn, "tabular:%")
        for a in out["alerts"]:
            detector = f"tabular:{out['model']}"
            ev = {"tool_use_id": a["tool_use_id"], "score": a["score"]}
            if db.fingerprint(detector, a["agent_id"], "anomaly", ev) in seen:
                continue
            db.insert_flag(conn, agent_id=a["agent_id"], severity="low", category="anomaly",
                           summary=f"Unusual {a['tool_name']} call (score {a['score']}): "
                                   + ", ".join(a["reasons"] or ["no single feature stands out"]),
                           evidence=ev, detector=detector)
    return out


def cycle(conn, state: dict, backend: str) -> dict:
    run_id = db.start_run(conn, backend, model_name(backend))
    result = {"backend": backend, "n_signals": 0, "n_rule_flags": 0, "n_model_flags": 0,
              "reviewed": False}
    try:
        signals, new_wm = rules.run_rules(conn, state.get("watermarks", {}))
        result["n_signals"] = len(signals)
        result["n_rule_flags"] = write_rule_flags(conn, signals)
        log(f"rules: {len(signals)} signals, {result['n_rule_flags']} new flags")
        tab = tabular_pass(conn, backend)
        result.update(tabular_model=tab["model"], n_scored=tab["n_scored"],
                      n_tabular_alerts=len(tab["alerts"]))

        latest = db.latest_activity(conn)
        since = state.get("reviewed_until")
        new_activity = bool(latest) and latest != since
        wanted = (signals or tab["alerts"] or state.get("force_model")
                  or (TRIGGER == "activity" and new_activity))
        if backend == "claude-code" and not_logged_in():
            result["error"] = LOGIN_HINT   # shown in the dashboard; rules still ran
            log(f"model: skipped, {LOGIN_HINT}")
        elif backend != "rules-only" and wanted:
            from agent import build_briefing
            out = review(conn, backend, build_briefing(conn, signals, since, tab["alerts"]))
            result.update(reviewed=True, n_model_flags=out.get("n_flags", 0),
                          stopped=out.get("stopped"), summary=out.get("summary"),
                          error=LOGIN_HINT if out.get("not_logged_in") else out.get("error"))
            if not out.get("error"):
                state["reviewed_until"] = latest
            log(f"model: {result['n_model_flags']} flags, stopped={result.get('stopped')}"
                + (f", error: {result['error']}" if result.get("error") else ""))
        elif backend != "rules-only":
            log("model: skipped (no new activity)")
        state["watermarks"] = new_wm
        save_state(state)
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        raise
    finally:
        try:
            db.end_run(conn, run_id, **result)
        except Exception as e:  # noqa: BLE001
            log(f"cannot record the cycle: {e}")
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true")
    g.add_argument("--loop", type=float, metavar="SECONDS")
    ap.add_argument("--rules-only", action="store_true",
                    help="run deterministic rules only, no model")
    ap.add_argument("--reset", action="store_true", help="ignore saved watermarks")
    args = ap.parse_args()

    backend = "rules-only" if args.rules_only else BACKEND
    if backend not in ("claude-code", "api", "rules-only"):
        sys.exit(f"unknown MONITOR_BACKEND {backend!r} (claude-code, api or rules-only)")
    state = {} if args.reset else load_state()

    if args.once:
        conn = db.connect()
        print(json.dumps(cycle(conn, state, backend), indent=2, default=str))
        return
    log(f"loop every {args.loop}s (backend={backend}, trigger={TRIGGER}); Ctrl-C to stop")
    conn = None
    while True:
        try:
            if conn is None or conn.closed or conn.broken:
                conn = db.connect()
            cycle(conn, state, backend)
        except Exception as e:  # keep the loop alive across transient errors
            log(f"cycle error: {type(e).__name__}: {e}")
            conn = None
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
