"""Asynchronous writer to Postgres.

The proxy must never slow down or break agent traffic, so SQL statements are
queued and executed by one background thread, in order (the order matters:
an agent row is inserted before its llm_calls / tool_calls rows). If the
database is down, statements are kept and retried.
"""
from __future__ import annotations

import queue
import sys
import threading
import time
from typing import Any, Callable

try:
    import psycopg
    from psycopg.types.json import Jsonb
except ImportError:  # unit tests can run with a fake sink
    psycopg = None

    def Jsonb(x):  # type: ignore
        return x


Statement = tuple[str, tuple]


def log(msg: str) -> None:
    print(f"[obs-store] {msg}", file=sys.stderr, flush=True)


class Store:
    def __init__(self, dsn: str | None, sink: Callable[[str, tuple], None] | None = None,
                 maxsize: int = 200_000):
        """`sink` replaces the database (tests). Otherwise statements go to `dsn`."""
        self.dsn = dsn
        self.sink = sink
        self.q: queue.Queue[Statement | None] = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self._thread: threading.Thread | None = None
        if sink is None:
            self._thread = threading.Thread(target=self._run, name="obs-store", daemon=True)
            self._thread.start()

    # -- public -------------------------------------------------------------
    def execute(self, sql: str, params: tuple = ()) -> None:
        params = tuple(clean(p) if isinstance(p, str) else p for p in params)
        if self.sink is not None:
            self.sink(sql, params)
            return
        try:
            self.q.put_nowait((sql, params))
        except queue.Full:
            self.dropped += 1
            if self.dropped % 1000 == 1:
                log(f"queue full, dropped {self.dropped} statements")

    def close(self, timeout: float = 10.0) -> None:
        if self._thread is None:
            return
        self.q.put(None)
        self._thread.join(timeout)

    # -- writer thread ------------------------------------------------------
    def _connect(self):
        delay = 1.0
        while True:
            try:
                conn = psycopg.connect(self.dsn, autocommit=True)
                log("connected to database")
                return conn
            except Exception as e:  # noqa: BLE001
                log(f"cannot connect ({e.__class__.__name__}: {e}); retry in {delay:.0f}s")
                time.sleep(delay)
                delay = min(delay * 2, 30.0)

    def _run(self) -> None:
        conn = self._connect()
        pending: Statement | None = None
        while True:
            item = pending or self.q.get()
            pending = None
            if item is None:
                conn.close()
                return
            sql, params = item
            try:
                conn.execute(sql, params)
            except Exception as e:  # noqa: BLE001
                if conn.closed or conn.broken:
                    log(f"connection lost ({e}); reconnecting")
                    pending = item
                    conn = self._connect()
                else:  # bad row: log and skip, never block the queue
                    log(f"statement failed: {e.__class__.__name__}: {e} | {' '.join(sql.split()[:3])}")


def clean(x: Any) -> Any:
    """Remove NUL characters, which Postgres rejects in TEXT and JSONB."""
    if isinstance(x, str):
        return x.replace("\x00", "") if "\x00" in x else x
    if isinstance(x, dict):
        return {clean(k): clean(v) for k, v in x.items()}
    if isinstance(x, list):
        return [clean(v) for v in x]
    return x


def jsonb(x: Any):
    return None if x is None else Jsonb(clean(x))
