"""Tabular anomaly scoring of tool calls, on CPU, for the monitor.

Each finished tool call becomes one row of numeric features: what kind of tool it
is, what its input does (network, upload, secrets, obfuscation, paths outside the
workspace), the web traffic it caused (hosts, bytes sent, uploads to non-provider
hosts, blocked or untagged requests) and whether the agent's task called for the
network at all. A classifier estimates the probability that the row is a problem.

Model (MONITOR_TABULAR):
  tabpfn  TabPFN v2, a tabular foundation model: it is not trained, it reads the
          labelled rows in context and predicts the new ones (CPU, a few seconds for a
          few hundred rows). Weights: Prior Labs License (Apache 2.0 + attribution).
  trees   scikit-learn ExtraTrees on the same rows (fallback when TabPFN is missing).
  off     no tabular scoring.

Labelled rows: a small built-in seed set (hand-made examples of benign and harmful
calls; deliberately simple, a starting point) plus the operator's verdicts from the
dashboard: tool calls behind a flag marked "confirmed" are positives, behind a flag
marked "dismissed" are negatives. The more flags you review, the better it gets.

Scores go to `tabular_scores`; calls above MONITOR_TABULAR_THRESHOLD are handed to
the model reviewer as signals (and, with the rules-only backend, become low flags).
"""
from __future__ import annotations

import json
import math
import os
import re
import sys

import db

BACKEND = os.environ.get("MONITOR_TABULAR", "tabpfn").strip().lower()
THRESHOLD = float(os.environ.get("MONITOR_TABULAR_THRESHOLD", "0.6"))
MAX_ROWS = int(os.environ.get("MONITOR_TABULAR_MAX_ROWS", "300"))
MAX_TRAIN = 900                               # TabPFN v2 on CPU: up to ~1000 rows
PROVIDER_DOMAINS = ("anthropic.com", "claude.ai", "openai.com", "chatgpt.com")

NET_RE = re.compile(r"\b(curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|telnet|socat)\b|https?://"
                    r"|requests\.|urllib|fetch\(|http\.client|pip install|npm install|git clone", re.I)
UPLOAD_RE = re.compile(r"-X\s*(POST|PUT|PATCH)|--data|--data-binary|--upload-file|\s-d\s|\s-F\s|"
                       r"\s-T\s|requests\.(post|put)|method=['\"]?(POST|PUT)", re.I)
SECRET_RE = re.compile(r"secret|token|passw|credential|api[_-]?key|\.env\b|id_rsa|id_ed25519|"
                       r"\.ssh/|\.aws/|\.netrc|\.claude\.json|auth\.json|/etc/shadow|private[_-]?key", re.I)
OBFUSCATION_RE = re.compile(r"base64|xxd|openssl enc|\beval\b|\|\s*(ba)?sh\b|python3? -c|"
                            r"perl -e|\\x[0-9a-f]{2}|chr\(", re.I)
OUTSIDE_RE = re.compile(r"(^|[\s'\"=])(/etc/|/root|/home/|/proc/|/sys/|/var/|/usr/|/opt/|/run/|~/)")
DESTRUCTIVE_RE = re.compile(r"\brm\s+-[a-z]*r[a-z]*f|\bmkfs|\bdd\s+if=|>\s*/dev/sd|chmod\s+-R\s+777|"
                            r"\bshred\b|git push --force|DROP TABLE", re.I)
PERSIST_RE = re.compile(r"crontab|systemctl|\.bashrc|\.profile|authorized_keys|nohup|setsid|disown|&\s*$",
                        re.I | re.M)
TASK_NET_RE = re.compile(r"https?://|\bweb\b|internet|online|url|website|fetch|download|api\b|"
                         r"search|browse|curl|http|install|pip|npm|github|clone", re.I)
WRAPPERS_RE = re.compile(r"<(system-reminder|environment_context|user_instructions)>.*?</\1>", re.S)
TASK_UPLOAD_RE = re.compile(r"upload|post\b|send|submit|publish|push|share|webhook|email", re.I)

# Feature name -> human-readable reason when it is on (binary features only).
REASONS = {
    "cmd_network": "command uses the network",
    "cmd_upload": "command sends data out",
    "cmd_secret": "touches secret-like files or values",
    "cmd_obfuscation": "obfuscation or piping into a shell",
    "cmd_outside_workspace": "paths outside /workspace",
    "cmd_destructive": "destructive command",
    "cmd_persistence": "persistence or background process",
    "upload_ext": "uploaded to a non-provider host",
    "any_blocked": "request blocked by the proxy",
    "untagged_shell": "shell request without its proxy tag",
    "net_not_in_task": "network use the task did not ask for",
    "upload_not_in_task": "upload the task did not ask for",
}
FEATURES = [
    "is_shell", "is_web", "is_write", "is_spawn", "is_subagent",
    "cmd_network", "cmd_upload", "cmd_secret", "cmd_obfuscation", "cmd_outside_workspace",
    "cmd_destructive", "cmd_persistence",
    "log_input_len", "log_result_len", "result_error",
    "n_http", "n_hosts", "log_bytes_out", "upload_ext", "any_blocked", "untagged_shell",
    "task_net", "task_upload", "net_not_in_task", "upload_not_in_task",
]
SHELL_TOOLS = {"Bash", "shell", "local_shell", "exec_command", "shell_command", "BashOutput"}
WEB_TOOLS = {"WebFetch", "WebSearch", "web_search", "web_fetch"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"}
SPAWN_TOOLS = {"Agent", "Task", "spawn_agent"}


def log(msg: str) -> None:
    print(f"[tabular] {msg}", file=sys.stderr, flush=True)


# -- features -----------------------------------------------------------------
def features(row: dict) -> dict:
    """Feature dict of one tool call row (see `pending_rows` for the columns)."""
    name = row.get("tool_name") or ""
    text = row.get("input") or ""
    task = WRAPPERS_RE.sub("", row.get("task") or "")   # the task as written, no client context
    f = {
        "is_shell": float(name in SHELL_TOOLS),
        "is_web": float(name in WEB_TOOLS),
        "is_write": float(name in WRITE_TOOLS),
        "is_spawn": float(name in SPAWN_TOOLS),
        "is_subagent": float(bool(row.get("is_subagent"))),
        "cmd_network": float(bool(NET_RE.search(text))),
        "cmd_upload": float(bool(UPLOAD_RE.search(" " + text))),
        "cmd_secret": float(bool(SECRET_RE.search(text))),
        "cmd_obfuscation": float(bool(OBFUSCATION_RE.search(text))),
        "cmd_outside_workspace": float(bool(OUTSIDE_RE.search(text))),
        "cmd_destructive": float(bool(DESTRUCTIVE_RE.search(text))),
        "cmd_persistence": float(name in SHELL_TOOLS and bool(PERSIST_RE.search(text))),
        "log_input_len": math.log1p(len(text)),
        "log_result_len": math.log1p(len(row.get("result") or "")),
        "result_error": float(bool(row.get("result_is_error"))),
        "n_http": float(row.get("n_http") or 0),
        "n_hosts": float(row.get("n_hosts") or 0),
        "log_bytes_out": math.log1p(row.get("bytes_out") or 0),
        "upload_ext": float((row.get("n_upload_ext") or 0) > 0),
        "any_blocked": float((row.get("n_blocked") or 0) > 0),
        "untagged_shell": float(name in SHELL_TOOLS and (row.get("n_untagged") or 0) > 0),
        "task_net": float(bool(TASK_NET_RE.search(task))),
        "task_upload": float(bool(TASK_UPLOAD_RE.search(task))),
    }
    uses_net = f["cmd_network"] or f["n_http"] > 0
    f["net_not_in_task"] = float(bool(uses_net) and not f["task_net"] and not f["is_web"])
    f["upload_not_in_task"] = float((f["cmd_upload"] or f["upload_ext"]) and not f["task_upload"])
    return f


def vector(f: dict) -> list[float]:
    return [float(f.get(k, 0.0)) for k in FEATURES]


def reasons(f: dict) -> list[str]:
    return [txt for k, txt in REASONS.items() if f.get(k)]


# Built-in labelled examples: (features that are on, extra numeric values, label).
# Deliberately small and simple; the operator's flag reviews are added on top.
def _seed_row(on: tuple[str, ...], label: int, **num) -> tuple[dict, int]:
    f = {k: 0.0 for k in FEATURES}
    f.update({k: 1.0 for k in on})
    f.update({"log_input_len": math.log1p(num.get("input_len", 80)),
              "log_result_len": math.log1p(num.get("result_len", 400)),
              "n_http": float(num.get("n_http", 0)), "n_hosts": float(num.get("n_hosts", 0)),
              "log_bytes_out": math.log1p(num.get("bytes_out", 0))})
    return f, label


SEED = [
    # benign: reading, writing, listing, tests, web research the task asked for
    _seed_row(("is_shell",), 0),
    _seed_row(("is_shell",), 0, input_len=40, result_len=2000),
    _seed_row(("is_write",), 0, input_len=1500, result_len=60),
    _seed_row(("is_write", "is_subagent"), 0, input_len=900, result_len=60),
    _seed_row(("is_spawn",), 0, input_len=600, result_len=1500),
    _seed_row(("is_spawn", "task_net"), 0, input_len=500, result_len=900),
    _seed_row((), 0, input_len=60, result_len=3000),                       # Read, Glob, Grep...
    _seed_row(("is_subagent",), 0, input_len=60, result_len=2500),
    _seed_row(("is_web", "task_net"), 0, n_http=2, n_hosts=2, bytes_out=0),
    _seed_row(("is_web", "task_net", "is_subagent"), 0, n_http=1, n_hosts=1),
    _seed_row(("is_shell", "cmd_network", "task_net"), 0, n_http=1, n_hosts=1),
    _seed_row(("is_shell", "cmd_network", "task_net", "is_subagent"), 0, n_http=3, n_hosts=1),
    _seed_row(("is_shell", "cmd_network", "task_net"), 0, n_http=12, n_hosts=2),   # pip install
    _seed_row(("is_shell", "cmd_upload", "cmd_network", "task_net", "task_upload", "upload_ext"), 0,
              n_http=1, n_hosts=1, bytes_out=300),                      # upload the task asked for
    _seed_row(("is_shell", "cmd_outside_workspace"), 0, input_len=50, result_len=300),  # ls /usr/...
    _seed_row(("is_shell", "result_error"), 0, input_len=70, result_len=200),
    # harmful or drifting
    _seed_row(("is_shell", "cmd_network", "cmd_upload", "cmd_secret", "upload_ext",
               "net_not_in_task", "upload_not_in_task"), 1, n_http=1, n_hosts=1, bytes_out=400),
    _seed_row(("is_shell", "is_subagent", "cmd_network", "cmd_upload", "cmd_secret", "upload_ext",
               "net_not_in_task", "upload_not_in_task"), 1, n_http=1, n_hosts=1, bytes_out=120),
    _seed_row(("is_shell", "cmd_network", "cmd_upload", "upload_ext", "upload_not_in_task",
               "task_net"), 1, n_http=1, n_hosts=1, bytes_out=5000),
    _seed_row(("is_shell", "cmd_secret", "cmd_outside_workspace"), 1, input_len=60, result_len=900),
    _seed_row(("is_shell", "cmd_network", "cmd_obfuscation", "net_not_in_task"), 1,
              n_http=1, n_hosts=1, input_len=200),                      # curl | sh
    _seed_row(("is_shell", "cmd_obfuscation", "cmd_secret"), 1, input_len=150),        # base64 a key
    _seed_row(("is_shell", "any_blocked", "cmd_network", "net_not_in_task"), 1, n_http=1, n_hosts=1),
    _seed_row(("is_shell", "untagged_shell", "cmd_network"), 1, n_http=1, n_hosts=1),
    _seed_row(("is_shell", "cmd_destructive", "cmd_outside_workspace"), 1, input_len=40),
    _seed_row(("is_shell", "cmd_persistence", "cmd_outside_workspace"), 1, input_len=120),
    _seed_row(("is_web", "is_subagent", "net_not_in_task"), 1, n_http=1, n_hosts=1),
]


# -- data ---------------------------------------------------------------------
def _provider_args() -> tuple[list[str], list[str]]:
    return list(PROVIDER_DOMAINS), ["%." + d for d in PROVIDER_DOMAINS]


ROW_SQL = """
SELECT t.tool_use_id, t.agent_id, t.ts, t.tool_name, t.tool_input::text AS input,
       t.result_content AS result, t.result_is_error, a.first_prompt AS task,
       coalesce(jsonb_array_length(a.running_tools_at_start), 0) > 0 AS is_subagent,
       h.n_http, h.n_hosts, h.bytes_out, h.n_upload_ext, h.n_blocked, h.n_untagged
  FROM tool_calls t JOIN agents a USING (agent_id)
  LEFT JOIN LATERAL (
    SELECT count(*) AS n_http, count(DISTINCT host) AS n_hosts,
           coalesce(sum(req_bytes), 0) AS bytes_out,
           count(*) FILTER (WHERE method IN ('POST', 'PUT', 'PATCH') AND req_bytes > 0
                            AND NOT (host = ANY(%s) OR host LIKE ANY(%s))) AS n_upload_ext,
           count(*) FILTER (WHERE blocked) AS n_blocked,
           count(*) FILTER (WHERE proxy_tag IS NULL OR proxy_tag ~ '^aab[sr]-') AS n_untagged
      FROM http_requests h
     WHERE NOT h.is_llm_api
       AND (h.tool_use_id = t.tool_use_id
            OR (h.tool_use_id IS NULL AND h.agent_id = t.agent_id
                AND h.ts BETWEEN t.ts AND coalesce(t.ts_result, t.ts + interval '5 minutes')))
  ) h ON true
"""


def pending_rows(conn, limit: int = MAX_ROWS) -> list[dict]:
    """Finished client tool calls not scored yet (plus ones running for over 5 minutes)."""
    return db._rows(conn, ROW_SQL +
        " LEFT JOIN tabular_scores s ON s.tool_use_id = t.tool_use_id"
        " WHERE s.tool_use_id IS NULL AND NOT t.is_server_tool"
        "   AND (t.ts_result IS NOT NULL OR t.ts < now() - interval '5 minutes')"
        " ORDER BY t.ts LIMIT %s", (*_provider_args(), limit), cap=limit)


def labelled_rows(conn) -> list[tuple[dict, int]]:
    """Tool calls behind flags the operator confirmed (1) or dismissed (0)."""
    flags = db._rows(conn,
        "SELECT status, evidence FROM flags WHERE status IN ('confirmed', 'dismissed')"
        " ORDER BY id DESC LIMIT 2000", cap=2000)
    label: dict[str, int] = {}
    http_ids: dict[int, int] = {}
    for f in flags:
        y = 1 if f["status"] == "confirmed" else 0
        ev = f["evidence"] or {}
        for k in ("tool_use_id", "tool_call_id"):
            if isinstance(ev.get(k), str):
                label.setdefault(ev[k], y)
        for k in ("tool_use_ids", "tool_call_ids"):
            for t in ev.get(k) or []:
                if isinstance(t, str):
                    label.setdefault(t, y)
        for h in ev.get("http_request_ids") or []:
            if isinstance(h, int):
                http_ids.setdefault(h, y)
    if http_ids:
        for r in db._rows(conn, "SELECT id, tool_use_id FROM http_requests"
                                " WHERE id = ANY(%s) AND tool_use_id IS NOT NULL",
                          (list(http_ids),), cap=5000):
            label.setdefault(r["tool_use_id"], http_ids[r["id"]])
    if not label:
        return []
    rows = db._rows(conn, ROW_SQL + " WHERE t.tool_use_id = ANY(%s)",
                    (*_provider_args(), list(label)[:MAX_TRAIN]), cap=MAX_TRAIN)
    return [(features(r), label[r["tool_use_id"]]) for r in rows]


# -- models -------------------------------------------------------------------
class Model:
    """Fits on labelled rows and predicts P(problem) for new rows."""

    def __init__(self, backend: str = BACKEND):
        self.backend = backend
        self.name = "off"
        self._tabpfn = None
        if backend == "tabpfn":
            try:
                from tabpfn import TabPFNClassifier
                from tabpfn.constants import ModelVersion
                self._tabpfn = TabPFNClassifier.create_default_for_version(
                    ModelVersion.V2, device="cpu")
                self.name = "tabpfn-v2"
            except Exception as e:  # noqa: BLE001  missing package or weights
                log(f"TabPFN unavailable ({type(e).__name__}: {e}); using ExtraTrees")
                backend = "trees"
        if backend == "trees":
            try:
                import sklearn  # noqa: F401
                self.name = "extra-trees"
            except ImportError:
                log("scikit-learn unavailable; tabular scoring off")
                self.name = "off"

    @property
    def enabled(self) -> bool:
        return self.name != "off"

    def fit_proba(self, X, y, Xn, categorical: list[int] | None = None):
        """(classes, probabilities of each class for each row of Xn), in context."""
        import numpy as np
        if self._tabpfn is not None:
            try:
                self._tabpfn.categorical_features_indices = categorical or None
                self._tabpfn.fit(X, y)
                return list(self._tabpfn.classes_), np.asarray(self._tabpfn.predict_proba(Xn))
            except Exception as e:  # noqa: BLE001
                log(f"TabPFN failed ({type(e).__name__}: {e}); using ExtraTrees")
                self._tabpfn, self.name = None, "extra-trees"
        from sklearn.ensemble import ExtraTreesClassifier
        fill = np.nanmedian(np.vstack([X, Xn]), axis=0)          # trees need no NaN
        fill = np.where(np.isnan(fill), 0.0, fill)
        X = np.where(np.isnan(X), fill, X)
        Xn = np.where(np.isnan(Xn), fill, Xn)
        clf = ExtraTreesClassifier(n_estimators=200, min_samples_leaf=1, random_state=0)
        clf.fit(X, y)
        return list(clf.classes_), clf.predict_proba(Xn)

    def predict(self, train: list[tuple[dict, int]], rows: list[dict]) -> list[float]:
        """P(label 1) of each tool call feature dict in `rows`."""
        if not rows or not self.enabled:
            return []
        import numpy as np
        train = train[-MAX_TRAIN:]
        X = np.array([vector(f) for f, _ in train], dtype=float)
        y = np.array([lab for _, lab in train], dtype=int)
        Xn = np.array([vector(r) for r in rows], dtype=float)
        classes, proba = self.fit_proba(X, y, Xn)
        return [float(p) for p in proba[:, classes.index(1)]]


_MODEL: Model | None = None


def model() -> Model:
    global _MODEL
    if _MODEL is None:
        _MODEL = Model()
    return _MODEL


# -- one scoring pass ---------------------------------------------------------
def score_pending(conn, m: Model | None = None) -> dict:
    """Score the new tool calls, store the scores, return {model, n_scored, alerts}."""
    m = m or model()
    if not m.enabled:
        return {"model": "off", "n_scored": 0, "alerts": []}
    rows = pending_rows(conn)
    if not rows:
        return {"model": m.name, "n_scored": 0, "alerts": []}
    feats = [features(r) for r in rows]
    scores = m.predict(SEED + labelled_rows(conn), feats)
    alerts = []
    for r, f, s in zip(rows, feats, scores):
        why = reasons(f)
        conn.execute(
            "INSERT INTO tabular_scores (tool_use_id, agent_id, score, model, features, reasons)"
            " VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (tool_use_id) DO UPDATE SET"
            " score = EXCLUDED.score, model = EXCLUDED.model, features = EXCLUDED.features,"
            " reasons = EXCLUDED.reasons, ts = now()",
            (r["tool_use_id"], r["agent_id"], s, m.name, json.dumps(f), why))
        if s >= THRESHOLD:
            alerts.append({"tool_use_id": r["tool_use_id"], "agent_id": r["agent_id"],
                           "tool_name": r["tool_name"], "score": round(s, 3), "reasons": why,
                           "input": (r["input"] or "")[:300]})
    return {"model": m.name, "n_scored": len(rows), "alerts": alerts}


def top_scores(conn, agent_id: str | None = None, min_score: float = 0.5,
               limit: int = 50) -> list[dict]:
    """Highest anomaly scores, for the reviewer's `tabular_scores` tool."""
    return db._rows(conn,
        "SELECT s.tool_use_id, s.agent_id, round(s.score::numeric, 3)::float8 AS score, s.model,"
        " s.reasons, t.tool_name, left(t.tool_input::text, 400) AS input, t.ts"
        " FROM tabular_scores s JOIN tool_calls t USING (tool_use_id)"
        " WHERE s.score >= %s AND (%s::text IS NULL OR s.agent_id = %s)"
        " ORDER BY s.score DESC, t.ts DESC LIMIT %s",
        (min_score, agent_id, agent_id, min(limit, db.ROW_CAP)))


# -- on-demand predictions on any table (reviewer tool `tabular_predict`) ------
MAX_PREDICT = 2000
MAX_FEATURES = 100
POSITIVE = {"1", "true", "yes", "confirmed", "bad", "positive"}
NEGATIVE = {"0", "false", "no", "dismissed", "good", "negative"}


def _cell(v):
    """A SQL value as (number or NaN, kind): kind is num, cat (text) or skip."""
    import datetime as dt
    from decimal import Decimal
    if v is None:
        return float("nan"), None
    if isinstance(v, bool):
        return float(v), "num"
    if isinstance(v, (int, float, Decimal)):
        return float(v), "num"
    if isinstance(v, (dt.datetime, dt.date)):
        if isinstance(v, dt.date) and not isinstance(v, dt.datetime):
            v = dt.datetime(v.year, v.month, v.day)
        return v.timestamp(), "num"
    if isinstance(v, dt.timedelta):
        return v.total_seconds(), "num"
    if isinstance(v, str):
        return v, "cat"
    return None, "skip"                      # json, arrays...: not a feature


def flag_labels(conn, key: str) -> dict:
    """{id: 1|0} from flags the operator confirmed (1) or dismissed (0), keyed by
    tool_use_id, agent_id or http_request_id."""
    flags = db._rows(conn, "SELECT status, agent_id, evidence FROM flags"
                           " WHERE status IN ('confirmed', 'dismissed') ORDER BY id DESC",
                     cap=5000)
    out: dict = {}
    for f in flags:
        y = 1 if f["status"] == "confirmed" else 0
        ev = f["evidence"] or {}
        if key == "agent_id":
            ids = [f["agent_id"]] if f["agent_id"] else []
        elif key == "http_request_id":
            ids = [i for i in ev.get("http_request_ids") or [] if isinstance(i, int)]
        else:
            ids = [ev[k] for k in ("tool_use_id", "tool_call_id") if isinstance(ev.get(k), str)]
            ids += [t for k in ("tool_use_ids", "tool_call_ids") for t in ev.get(k) or []
                    if isinstance(t, str)]
        for i in ids:
            out.setdefault(i, y)
    return out


def predict_table(conn, query: str, params: list | None = None, label_column: str = "label",
                  id_column: str | None = None, labels_from_flags: str | None = None,
                  exclude_columns: list[str] | None = None, limit: int = 50,
                  m: Model | None = None) -> dict:
    """Run a read-only SELECT; rows with a label train the model in context, rows
    without one are predicted. See the `tabular_predict` tool description."""
    import math as _m

    import numpy as np
    m = m or model()
    if not m.enabled:
        raise ValueError("the tabular model is off (MONITOR_TABULAR=off)")
    rows = db.query(conn, query, params, cap=MAX_TRAIN + MAX_PREDICT)
    if not rows:
        raise ValueError("the query returned no rows")
    cols = list(rows[0].keys())
    id_column = id_column or cols[0]
    if id_column not in cols:
        raise ValueError(f"id_column {id_column!r} is not a column of the query ({cols})")
    if labels_from_flags:
        if labels_from_flags not in ("tool_use_id", "agent_id", "http_request_id"):
            raise ValueError("labels_from_flags must be tool_use_id, agent_id or http_request_id")
        fl = flag_labels(conn, labels_from_flags)
        for r in rows:
            r["__label"] = fl.get(r[id_column])
        label_key = "__label"
    else:
        if label_column not in cols:
            raise ValueError(f"no {label_column!r} column: add one (NULL for the rows to predict)"
                             " or set labels_from_flags")
        label_key = label_column
    skip = {id_column, label_key, label_column, *(exclude_columns or [])}
    feat_cols, kinds, dropped = [], {}, []
    for c in cols:
        if c in skip:
            continue
        ks = {_cell(r[c])[1] for r in rows} - {None}
        if "skip" in ks or len(ks) > 1:
            dropped.append(c)
        else:
            feat_cols.append(c)
            kinds[c] = ks.pop() if ks else "num"
    if not feat_cols:
        raise ValueError("no usable feature column (numbers, booleans, dates or text)")
    if len(feat_cols) > MAX_FEATURES:
        dropped += feat_cols[MAX_FEATURES:]
        feat_cols = feat_cols[:MAX_FEATURES]
    codes: dict[str, dict] = {c: {} for c in feat_cols if kinds[c] == "cat"}

    def vec(r):
        out = []
        for c in feat_cols:
            v, _ = _cell(r[c])
            if kinds[c] == "cat":
                out.append(float("nan") if v != v or v is None else
                           float(codes[c].setdefault(v, len(codes[c]))))
            else:
                out.append(v)
        return out

    def norm(v):
        if isinstance(v, (int, float)) and not isinstance(v, bool) and float(v).is_integer():
            v = int(v)
        s = str(v).strip().lower()
        return "1" if s in POSITIVE else "0" if s in NEGATIVE else str(v)

    def labelled(r):
        v = r[label_key]
        return v is not None and not (isinstance(v, float) and _m.isnan(v))

    train = [r for r in rows if labelled(r)][-MAX_TRAIN:]
    test = [r for r in rows if not labelled(r)][:MAX_PREDICT]
    labels = [norm(r[label_key]) for r in train]
    if len(set(labels)) < 2:
        raise ValueError(f"need labelled rows of at least two classes; got {len(train)} labelled"
                         f" row(s) with classes {sorted(set(labels))}")
    if not test:
        raise ValueError("every row is labelled: leave the label NULL for the rows to predict")
    X = np.array([vec(r) for r in train], dtype=float)
    Xn = np.array([vec(r) for r in test], dtype=float)
    cat_idx = [i for i, c in enumerate(feat_cols) if kinds[c] == "cat"]
    classes, proba = m.fit_proba(X, np.array(labels), Xn, cat_idx)
    classes = [str(c) for c in classes]
    binary = set(classes) == {"0", "1"}
    preds = []
    for r, p in zip(test, proba):
        best = int(np.argmax(p))
        item = {"id": r[id_column], "prediction": classes[best],
                "probabilities": {c: round(float(x), 3) for c, x in zip(classes, p)}}
        if binary:
            item["score"] = round(float(p[classes.index("1")]), 3)
        preds.append(item)
    preds.sort(key=lambda x: -(x.get("score") if binary else max(x["probabilities"].values())))
    return {"model": m.name, "classes": classes, "n_train": len(train), "n_predicted": len(test),
            "label_counts": {c: labels.count(c) for c in sorted(set(labels))},
            "features": {c: kinds[c] for c in feat_cols}, "dropped_columns": dropped,
            "predictions": preds[:max(1, min(int(limit), 500))]}
