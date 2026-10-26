"""sandbox/bin/aab-status: what is live in the sandbox, from `ps` (faked here)."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PS = """\
  101     1   600 ?        sshd: agent@pts/0
  102   101   598 pts/0    -bash
  103   102   300 pts/0    claude
  110     1    90 ?        sshd: agent@notty
  111   110    89 ?        bash -c /usr/local/bin/aab-launch
  120     1    40 ?        node /usr/local/bin/codex exec --dangerously-bypass-approvals-and-sandbox fix it
  121   120    39 ?        /usr/local/lib/node_modules/@openai/codex/vendor/bin/codex exec fix it
  130     1    20 ?        claude -p --dangerously-skip-permissions summarise
  140   103    10 pts/0    /bin/bash -c sleep 5
"""


def test_status_from_ps(tmp_path):
    fake = tmp_path / "ps"
    fake.write_text(f"#!/bin/sh\ncat <<'X'\n{PS}X\n")
    fake.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    out = json.loads(subprocess.run([sys.executable, str(ROOT / "sandbox/bin/aab-status")],
                                    capture_output=True, text=True, env=env, check=True).stdout)
    assert out["ok"] and out["sessions"] == [{"tty": "pts/0", "since_s": 600}]   # not the dashboard's
    clis = {c["pid"]: c for c in out["clis"]}
    assert set(clis) == {103, 120, 130}                     # codex binary folded into its wrapper
    assert (clis[103]["cli"], clis[103]["headless"], clis[103]["tty"]) == ("claude", False, "pts/0")
    assert (clis[120]["cli"], clis[120]["headless"]) == ("codex", True)
    assert (clis[130]["cli"], clis[130]["headless"]) == ("claude", True)
