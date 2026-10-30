"""Loki audit backend (follow-up #2): payload, query, fallback, factory."""

import json
from unittest import mock

import httpx

from security_agent.audit import InMemoryLogStore, LokiLogStore, _build_shared_log


def _store(handler):
    return LokiLogStore("http://loki:3100/", tenant="t1", transport=httpx.MockTransport(handler))


def test_loki_push_payload_labels_and_tenant():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["org"] = request.headers.get("x-scope-orgid")
        seen["body"] = json.loads(request.content)
        return httpx.Response(204)

    store = _store(handler)
    store.append(action_class="tool", decision="allow", line="run=1 osv-scanner scan")
    assert seen["url"] == "http://loki:3100/loki/api/v1/push"
    assert seen["org"] == "t1"
    stream = seen["body"]["streams"][0]
    assert stream["stream"] == {"action_class": "tool", "decision": "allow"}
    assert stream["values"][0][1] == "run=1 osv-scanner scan"
    assert store.fallback.query() == []  # nothing buffered on success


def test_loki_query_parses_and_sorts():
    def handler(request):
        assert "query_range" in str(request.url)
        payload = {
            "data": {
                "result": [
                    {
                        "stream": {"action_class": "gate", "decision": "deny"},
                        "values": [["2000000000", "second"], ["1000000000", "first"]],
                    }
                ]
            }
        }
        return httpx.Response(200, json=payload)

    rows = _store(handler).query(action_class="gate")
    assert [r["line"] for r in rows] == ["first", "second"]
    assert rows[0]["action_class"] == "gate" and rows[0]["decision"] == "deny"


def test_loki_outage_falls_back_without_raising():
    def handler(request):
        return httpx.Response(500)

    store = _store(handler)
    store.append(action_class="secret", decision="alert", line="secret=1")
    assert [r["line"] for r in store.query()] == ["secret=1"]
    assert store.purge_expired() == 0


def test_factory_selects_backend():
    mem = mock.Mock(audit_backend="memory")
    with mock.patch("security_agent.config.get_settings", return_value=mem):
        assert isinstance(_build_shared_log(), InMemoryLogStore)
    loki = mock.Mock(
        audit_backend="loki", loki_url="http://loki:3100", loki_tenant="", loki_timeout_seconds=5.0
    )
    with mock.patch("security_agent.config.get_settings", return_value=loki):
        assert isinstance(_build_shared_log(), LokiLogStore)
