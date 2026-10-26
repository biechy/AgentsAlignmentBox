#!/usr/bin/env python3
"""Claude Code PreToolUse hook: name the tool call in the traffic it causes, so the proxy
knows exactly which tool call, hence which agent, sent each request.

- Bash: the command runs with proxy credentials naming its tool call
  (http://<tool_use_id>:x@proxy:8080); every process it starts (curl, pip, git, scripts,
  background jobs) inherits them.
- WebFetch: the request is made by the Claude Code process itself (shared by an
  orchestrator and its sub-agents), so the URL gets a marker instead,
  ?aab_tag=<tool_use_id>, which the proxy reads and removes before forwarding.

Installed as a managed (root-owned) setting: agents cannot edit or disable it.
"""
import json
import os
import re
import sys
from urllib.parse import urlsplit, urlunsplit

URL_TAG = "aab_tag"

data = json.load(sys.stdin)
tool_use_id = data.get("tool_use_id") or ""
tool_input = data.get("tool_input") or {}
if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tool_use_id):
    sys.exit(0)  # nothing to tag: leave the call untouched


def with_marker(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    keep = [p for p in parts.query.split("&") if p and p.partition("=")[0] != URL_TAG]
    keep.append(f"{URL_TAG}={tool_use_id}")
    return urlunsplit(parts._replace(query="&".join(keep)))


command, url = tool_input.get("command"), tool_input.get("url")
if isinstance(command, str):
    proxy = urlsplit(os.environ.get("HTTPS_PROXY") or "http://proxy:8080")
    host = proxy.hostname + (f":{proxy.port}" if proxy.port else "")
    tagged = urlunsplit((proxy.scheme, f"{tool_use_id}:x@{host}", "", "", ""))
    prefix = (f"export HTTP_PROXY={tagged} HTTPS_PROXY={tagged} "
              f"http_proxy={tagged} https_proxy={tagged}\n")
    updated = {**tool_input, "command": prefix + command}
elif data.get("tool_name") == "WebFetch" and isinstance(url, str) and with_marker(url):
    updated = {**tool_input, "url": with_marker(url)}
else:
    sys.exit(0)

out = {"hookEventName": "PreToolUse", "updatedInput": updated}
# The modified input needs a decision. Under bypassPermissions everything is allowed
# anyway; otherwise ask, so a human sees the call that will really run.
out["permissionDecision"] = "allow" if data.get("permission_mode") == "bypassPermissions" else "ask"
print(json.dumps({"hookSpecificOutput": out}))
