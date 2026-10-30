"""Pluggable audit LogStore (NFR-12). Loki ships as v1 default behind this interface.

In-memory dev store is bounded twice: 1-year retention default (FR-9 D6)
plus a hard entry cap, so a busy worker cannot grow it without limit.
All modules share one process-wide store via get_shared_log(), so the
audit trail is complete instead of fragmented per module.
"""

import threading
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

RETENTION_DEFAULT = timedelta(days=365)
CAPACITY_DEFAULT = 10_000


class LogStore(Protocol):
    def append(self, *, action_class: str, decision: str, line: str) -> None: ...
    def query(self, *, action_class: str | None = None) -> list[dict[str, Any]]: ...
    def purge_expired(self) -> int: ...


class InMemoryLogStore:
    """Dev/test default. Keeps low-cardinality labels; run id lives in line content."""

    def __init__(
        self, retention: timedelta = RETENTION_DEFAULT, capacity: int = CAPACITY_DEFAULT
    ) -> None:
        self._rows: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._retention = retention
        self._since_purge = 0
        self._last_purge = datetime.now(UTC)
        # RLock: append() triggers purge_expired() under the same hold.
        # Without this, a purge racing an append silently drops the entry
        # (append lands in the deque object the purge just replaced).
        self._lock = threading.RLock()

    def append(self, *, action_class: str, decision: str, line: str) -> None:
        with self._lock:
            self._rows.append(
                {
                    "action_class": action_class,
                    "decision": decision,
                    "line": line,
                    "ts": datetime.now(UTC).isoformat(),
                }
            )
            self._since_purge += 1
            # Bounded work: purge every 100 appends or hourly, whichever comes
            # first, so low-traffic workers still enforce retention.
            if self._since_purge >= 100 or datetime.now(UTC) - self._last_purge >= timedelta(
                hours=1
            ):
                self.purge_expired()
                self._since_purge = 0

    def query(self, *, action_class: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if action_class is None:
                return list(self._rows)
            return [r for r in self._rows if r["action_class"] == action_class]

    def purge_expired(self) -> int:
        with self._lock:
            cutoff = datetime.now(UTC) - self._retention
            kept = [r for r in self._rows if datetime.fromisoformat(r["ts"]) >= cutoff]
            removed = len(self._rows) - len(kept)
            self._rows = deque(kept, maxlen=self._rows.maxlen)
            self._last_purge = datetime.now(UTC)
            return removed


_shared_lock = threading.Lock()


class LokiLogStore:
    """Durable audit backend (follow-up #2, NFR-12): Loki push/query APIs.

    Labels stay low-cardinality (action_class, decision); the run id and
    detail live in the log line, never in a label. Append never raises on
    the tool/gate hot path: a Loki outage degrades to the bounded
    in-memory fallback and a warning, so auditing cannot break a scan.
    Retention is enforced server-side by Loki, so purge_expired() is a
    no-op returning 0.
    """

    def __init__(
        self,
        base_url: str,
        *,
        tenant: str = "",
        timeout: float = 5.0,
        transport=None,
        fallback: InMemoryLogStore | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._tenant = tenant
        self._timeout = timeout
        self._transport = transport
        self.fallback = fallback if fallback is not None else InMemoryLogStore()

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._tenant:
            headers["X-Scope-OrgID"] = self._tenant
        return headers

    def _client(self):
        import httpx

        return httpx.Client(timeout=self._timeout, transport=self._transport)

    def append(self, *, action_class: str, decision: str, line: str) -> None:
        import logging

        ts_ns = str(int(datetime.now(UTC).timestamp() * 1_000_000_000))
        payload = {
            "streams": [
                {
                    "stream": {"action_class": action_class, "decision": decision},
                    "values": [[ts_ns, line]],
                }
            ]
        }
        try:
            with self._client() as client:
                resp = client.post(
                    f"{self._base}/loki/api/v1/push", json=payload, headers=self._headers()
                )
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - audit must not break the hot path
            logging.getLogger(__name__).warning("Loki audit push failed, buffering: %s", exc)
            self.fallback.append(action_class=action_class, decision=decision, line=line)

    def query(self, *, action_class: str | None = None) -> list[dict[str, Any]]:
        import logging
        import time as _time

        selector = f'{{action_class="{action_class}"}}' if action_class else '{action_class=~".+"}'
        params = {
            "query": selector,
            "start": "0",
            "end": str(int(_time.time() * 1_000_000_000)),
            "direction": "forward",
            "limit": "5000",
        }
        try:
            with self._client() as client:
                resp = client.get(
                    f"{self._base}/loki/api/v1/query_range",
                    params=params,
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001 - degrade to buffered rows
            logging.getLogger(__name__).warning("Loki audit query failed: %s", exc)
            return self.fallback.query(action_class=action_class)
        rows: list[dict[str, Any]] = []
        for stream in (data.get("data") or {}).get("result") or []:
            labels = stream.get("stream") or {}
            for ts_ns, line in stream.get("values") or []:
                try:
                    ts = datetime.fromtimestamp(int(ts_ns) / 1e9, tz=UTC).isoformat()
                except (TypeError, ValueError, OSError):
                    ts = ""
                rows.append(
                    {
                        "action_class": labels.get("action_class", ""),
                        "decision": labels.get("decision", ""),
                        "line": line,
                        "ts": ts,
                        "_ns": int(ts_ns) if str(ts_ns).isdigit() else 0,
                    }
                )
        rows.sort(key=lambda r: r["_ns"])
        for row in rows:
            row.pop("_ns", None)
        buffered = self.fallback.query(action_class=action_class)
        return rows + buffered if buffered else rows

    def purge_expired(self) -> int:
        """Retention is server-side in Loki; nothing to purge locally."""
        return self.fallback.purge_expired()


_shared: LogStore | None = None


def _build_shared_log() -> LogStore:
    from security_agent.config import get_settings

    s = get_settings()
    backend = getattr(s, "audit_backend", "memory")
    backend = backend.strip().lower() if isinstance(backend, str) else "memory"
    if backend == "loki":
        url = getattr(s, "loki_url", "http://loki:3100")
        tenant = getattr(s, "loki_tenant", "")
        timeout = getattr(s, "loki_timeout_seconds", 5.0)
        return LokiLogStore(
            url if isinstance(url, str) and url else "http://loki:3100",
            tenant=tenant if isinstance(tenant, str) else "",
            timeout=timeout if isinstance(timeout, (int, float)) else 5.0,
        )
    return InMemoryLogStore()


def get_shared_log() -> LogStore:
    """Process-wide audit store; every module appends here."""
    global _shared
    if _shared is None:
        with _shared_lock:
            if _shared is None:
                _shared = _build_shared_log()
    return _shared
