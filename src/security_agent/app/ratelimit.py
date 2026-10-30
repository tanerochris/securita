"""Tiny sliding-window rate limiter (per IP + path).

In-memory by design for H1 (single app container). Bounded: the bucket map
is capped with oldest-resident eviction, so rotating source IPs cannot grow
it without limit. All access holds a lock: sync routes run in a threadpool.
"""

import threading
import time
from collections import deque

_buckets: dict[tuple[str, str], deque[float]] = {}
_buckets_lock = threading.Lock()
_BUCKETS_MAX = 4096


def allow(ip: str, path: str, *, limit: int = 10, window: float = 60.0) -> bool:
    now = time.monotonic()
    key = (ip, path)
    with _buckets_lock:
        bucket = _buckets.get(key)
        if bucket is None:
            if len(_buckets) >= _BUCKETS_MAX:
                _buckets.pop(next(iter(_buckets)))
            bucket = _buckets[key] = deque()
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True
