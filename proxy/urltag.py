"""WebFetch URL marker and redirects: exact attribution of the Claude Code client's own
web requests. Pure functions, no I/O.

Shell commands carry their tool call in the proxy credentials (tag_tool_call.py). A
WebFetch request is made by the Claude Code process itself, shared by an orchestrator and
its sub-agents, so the same hook adds the tool call to the URL instead:
`https://example.com/page?aab_tag=toolu_...`. The proxy reads the marker, removes it
before forwarding (the site sees the original URL), and attributes the request to that
tool call. When the answer is a redirect, the proxy remembers the target for a minute so
the follow-up request (which no longer carries the marker) is attributed too.
"""
from __future__ import annotations

import time
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

URL_TAG = "aab_tag"
REDIRECT_TTL_S = 60.0
REDIRECT_STATUS = (301, 302, 303, 307, 308)


def strip_url_tag(path: str) -> tuple[str, str | None]:
    """(path without the marker, the marker's value or None). Other query parameters are
    kept byte for byte (signed URLs keep working)."""
    base, sep, query = path.partition("?")
    if not sep:
        return path, None
    keep, tag = [], None
    for part in query.split("&"):
        key, _, value = part.partition("=")
        if key == URL_TAG:
            tag = unquote(value)
        else:
            keep.append(part)
    if tag is None:
        return path, None
    return base + ("?" + "&".join(keep) if keep else ""), tag


def add_url_tag(url: str, tag: str) -> str:
    """The URL with the marker (any marker already there replaced)."""
    parts = urlsplit(url)
    query = strip_url_tag("/?" + parts.query)[0].partition("?")[2] if parts.query else ""
    query = (query + "&" if query else "") + f"{URL_TAG}={tag}"
    return urlunsplit(parts._replace(query=query))


def _key(url: str) -> str:
    parts = urlsplit(url)
    path, _ = strip_url_tag(parts.path + ("?" + parts.query if parts.query else ""))
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))


class Redirects:
    """Redirect targets of tagged requests, per container, for a short time."""

    def __init__(self, ttl_s: float = REDIRECT_TTL_S, clock=time.monotonic, max_size: int = 5000):
        self.ttl_s, self.clock, self.max_size = ttl_s, clock, max_size
        self._map: dict[tuple[str, str], tuple[float, str | None]] = {}

    def remember(self, ip: str | None, request_url: str, location: str, tag: str) -> None:
        key = (ip or "", _key(urljoin(request_url, location)))
        now = self.clock()
        old = self._map.get(key)
        # Two tool calls redirected to the same place at once: nobody gets it.
        if old and now - old[0] < self.ttl_s and old[1] != tag:
            tag = None
        self._map[key] = (now, tag)
        if len(self._map) > self.max_size:
            for k in sorted(self._map, key=lambda k: self._map[k][0])[: self.max_size // 2]:
                del self._map[k]

    def take(self, ip: str | None, url: str) -> str | None:
        hit = self._map.pop((ip or "", _key(url)), None)
        if hit and self.clock() - hit[0] < self.ttl_s:
            return hit[1]
        return None
