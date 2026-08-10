"""Testy CLI/SDK liveapisec (TODO 2.25) — bez sieci (MockTransport / stub)."""

from __future__ import annotations

import json

import httpx
import pytest

from liveapisec.cli import (
    _build_auth,
    _cmd_findings,
    _cmd_push,
    _cmd_scan,
    _print_endpoints,
    _validate_auth,
    _verify_target,
    main,
)
from liveapisec.client import LiveAPISec, LiveAPISecError, severity_rank


def _client(handler) -> LiveAPISec:
    transport = httpx.MockTransport(handler)
    return LiveAPISec(
        api_url="https://liveapisec.test",
        api_key="las_dev_test",
        transport=transport,
    )


# --- severity_rank -----------------------------------------------------------
def test_severity_rank() -> None:
    assert severity_rank("critical") == 0
    assert severity_rank("high") == 1
    assert severity_rank("medium") == 2
    assert severity_rank("low") == 3
    assert severity_rank("info") == 4
    assert severity_rank("bogus") == 5


# --- create_site -------------------------------------------------------------
def test_create_site_posts_payload_and_auth_header() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "site_id": "65f000000000000000000001",
                "name": "my-api",
                "base_url": "https://api.example.com",
                "endpoints_count": 2,
                "auth": "jwt",
            },
        )

    api = _client(handler)
    site = api.create_site(
        name="my-api",
        base_url="https://api.example.com",
        endpoints=[{"method": "GET", "path": "/users"}, {"method": "POST", "path": "/payments"}],
        auth={"type": "jwt", "token": "eyJ.secret"},
    )
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/developers/sites")
    assert captured["auth"] == "Bearer las_dev_test"
    assert captured["body"]["name"] == "my-api"
    assert captured["body"]["auth"]["token"] == "eyJ.secret"
    assert site["site_id"] == "65f000000000000000000001"


def test_create_site_with_existing_id_uses_put() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(200, json={"site_id": "65fabc", "endpoints_count": 1, "auth": "none"})

    api = _client(handler)
    api.create_site(
        name="x",
        base_url="https://x.test",
        endpoints=[{"method": "GET", "path": "/"}],
        site_id="65fabc",
    )
    assert captured["method"] == "PUT"


def test_api_error_raises_liveapisecerror() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Unauthorized", "detail": "invalid API key"})

    api = _client(handler)
    with pytest.raises(LiveAPISecError) as exc:
        api.create_site("x", "https://x.test", endpoints=[{"method": "GET", "path": "/"}])
    assert exc.value.status == 401
    assert "Unauthorized" in str(exc.value)


def test_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("LIVEAPISEC_API_KEY", raising=False)
    api = LiveAPISec(api_url="https://x.test", api_key=None)
    with pytest.raises(LiveAPISecError) as exc:
        api.get_site("65fabc")
    assert "Missing API key" in str(exc.value)


# --- scans -------------------------------------------------------------------
def test_trigger_scan() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"scan_id": "scan123", "status": "queued", "branch": "main", "commit": "abc"},
        )

    api = _client(handler)
    scan = api.trigger_scan("65fabc", branch="main", commit="abc")
    assert scan["scan_id"] == "scan123"
    assert captured["body"] == {"branch": "main", "commit": "abc"}


def test_wait_for_scan_polls_until_completed(monkeypatch) -> None:
    import liveapisec.client as client_mod

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/scans/scan123/findings"):
            return httpx.Response(
                200,
                json=[
                    {"severity": "high", "title": "XSS", "target": "GET /users"},
                    {"severity": "info", "title": "header", "target": "GET /"},
                ],
            )
        calls["n"] += 1
        status = "running" if calls["n"] == 1 else "completed"
        return httpx.Response(
            200,
            json=[
                {
                    "scan_id": "scan123",
                    "status": status,
                    "summary": {
                        "tests_run": 42,
                        "findings": 2,
                        "by_severity": {"high": 1, "info": 1},
                    },
                }
            ],
        )

    api = _client(handler)
    monkeypatch.setattr(
        client_mod,
        "time",
        type("T", (), {"monotonic": lambda self: 0.0, "sleep": lambda self, s: None})(),
    )
    done = api.wait_for_scan("65fabc", "scan123", poll_interval=0.01)
    assert done["status"] == "completed"
    assert len(done["findings"]) == 2


def test_findings_above() -> None:
    findings = [
        {"severity": "critical", "title": "a"},
        {"severity": "high", "title": "b"},
        {"severity": "medium", "title": "c"},
        {"severity": "info", "title": "d"},
    ]
    assert len(LiveAPISec.findings_above(findings, "high")) == 2
    assert len(LiveAPISec.findings_above(findings, "critical")) == 1
    assert LiveAPISec.findings_above(findings, "info") == findings


# --- CLI: push ---------------------------------------------------------------
class _StubClient:
    def __init__(self) -> None:
        self.sites: list[dict] = []

    def create_site(self, **kw):
        self.sites.append(kw)
        return {"site_id": "65faaa", "name": kw["name"], "endpoints_count": 1, "auth": "none"}


def test_cli_push_builds_payload(capsys) -> None:
    stub = _StubClient()

    class Args:
        name = "my-api"
        base_url = "https://api.example.com"
        project = None
        endpoint: list = [{"method": "GET", "path": "/users"}]  # noqa: RUF012 (test stub)
        openapi_url = None
        site = None
        auth_type = "none"
        auth_token = None
        auth_cookie = None
        auth_header = "X-API-Key"
        auth_token_url = None
        auth_client_id = None
        auth_client_secret = None
        verify = False
        json = False

    assert _cmd_push(stub, Args()) == 0
    out = capsys.readouterr().out
    assert "65faaa" in out
    assert "export SITE_ID=65faaa" in out


def test_cli_push_requires_endpoint(capsys) -> None:
    class Args:
        name = "x"
        base_url = "https://x.test"
        project = None
        endpoint: list = []  # noqa: RUF012 (test stub)
        openapi_url = None
        site = None
        verify = False
        json = False

    assert _cmd_push(_StubClient(), Args()) == 2
    assert "error:" in capsys.readouterr().err


# --- performance: 1000+ endpoints --------------------------------------------
def test_cli_push_many_endpoints_sent_and_summarized(capsys) -> None:
    """All 1500 endpoints go in ONE request; output summarizes + shows the cap note."""
    captured: dict = {}

    class Client:
        def create_site(self, **kw):
            captured["endpoints"] = kw["endpoints"]
            return {
                "site_id": "65fbig",
                "name": kw["name"],
                "endpoints_count": len(kw["endpoints"]),
                "auth": "none",
            }

    class Args:
        name = "my-api"
        base_url = "https://api.example.com"
        project = None
        endpoint: list = [  # noqa: RUF012 (test stub)
            {"method": "GET", "path": f"/users/{i}"} for i in range(1500)
        ]
        openapi_url = None
        site = None
        auth_type = "none"
        auth_token = None
        auth_cookie = None
        auth_header = "X-API-Key"
        auth_token_url = None
        auth_client_id = None
        auth_client_secret = None
        verify = False
        json = False

    assert _cmd_push(Client(), Args()) == 0
    # wszystko wysłane w jednym requeście
    assert len(captured["endpoints"]) == 1500
    # output podsumowuje (nie 1500 linii) + notka o limicie skanera
    captured_out = capsys.readouterr()
    assert "1500 endpoints" in captured_out.out
    assert "SCANNER_MAX_TARGETS" in captured_out.err


def test_print_endpoints_summarizes_large_list(capsys) -> None:
    eps = [{"method": "GET", "path": f"/x/{i}"} for i in range(100)]
    _print_endpoints(eps, limit=10)
    out = capsys.readouterr().out
    assert "/x/0" in out
    assert "90 more" in out  # 100 - 10


# --- interactive pickers (project / site) ------------------------------------
def test_pick_project_existing(monkeypatch, capsys) -> None:
    from liveapisec.cli import _pick_project

    monkeypatch.setattr("builtins.input", lambda _p: "1")
    sites = [
        {"site_id": "a", "name": "api-a", "project": "svc"},
        {"site_id": "b", "name": "api-b", "project": "svc"},
        {"site_id": "c", "name": "api-c", "project": "mobile"},
    ]
    assert _pick_project(sites) == "mobile"  # posortowane: mobile, svc → 1 = mobile
    out = capsys.readouterr().out
    assert "Pick a project" in out
    assert "create new project" in out


def test_pick_project_new(monkeypatch, capsys) -> None:
    from liveapisec.cli import _pick_project

    monkeypatch.setattr("builtins.input", lambda _p: "brand-new")
    assert _pick_project([]) == "brand-new"  # brak projektów → typuje nazwę


def test_pick_site_existing(monkeypatch, capsys) -> None:
    from liveapisec.cli import _pick_site

    monkeypatch.setattr("builtins.input", lambda _p: "2")
    sites = [
        {"site_id": "a", "name": "api-a", "project": "svc", "base_url": "https://a"},
        {"site_id": "b", "name": "api-b", "project": "svc", "base_url": "https://b"},
    ]
    picked = _pick_site(sites, "svc")
    assert picked and picked["site_id"] == "b"


def test_pick_site_new(monkeypatch, capsys) -> None:
    from liveapisec.cli import _pick_site

    monkeypatch.setattr("builtins.input", lambda _p: "9")  # spoza listy → nowy
    sites = [{"site_id": "a", "name": "api-a", "project": "svc", "base_url": "https://a"}]
    assert _pick_site(sites, "svc") is None


def test_list_sites_sdk() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json=[{"site_id": "a", "project": "svc"}])

    sites = _client(handler).list_sites()
    assert captured["url"].endswith("/developers/sites")
    assert sites == [{"site_id": "a", "project": "svc"}]


def test_push_interactive_picks_existing_site(monkeypatch, capsys) -> None:
    import sys as _sys

    from liveapisec.cli import _cmd_push

    class FakeTTY:
        def isatty(self):
            return True

    monkeypatch.setattr(_sys, "stdin", FakeTTY())
    monkeypatch.setattr("builtins.input", lambda _p: "1")  # project=1, site=1

    sites = [
        {"site_id": "siteA", "name": "api-a", "project": "svc", "base_url": "https://a.test"},
    ]
    calls: dict = {}

    class Client:
        def list_sites(self):
            return sites

        def create_site(self, **kw):
            calls.update(kw)
            return {
                "site_id": kw.get("site_id") or "new",
                "name": "x",
                "endpoints_count": 1,
                "auth": "none",
                "updated": bool(kw.get("site_id")),
            }

    class Args:
        name = None
        base_url = None
        project = None
        endpoint: list = [{"method": "GET", "path": "/users"}]  # noqa: RUF012
        openapi_url = None
        site = None
        auth_type = "none"
        auth_token = None
        auth_cookie = None
        auth_header = "X-API-Key"
        auth_token_url = None
        auth_client_id = None
        auth_client_secret = None
        verify = False
        json = False

    assert _cmd_push(Client(), Args()) == 0
    # wybrał istniejący site → PUT (site_id), name/base_url z istniejącego
    assert calls["site_id"] == "siteA"
    assert calls["name"] == "api-a"
    assert calls["base_url"] == "https://a.test"


# --- CLI: scan gate ----------------------------------------------------------
class _GateClient:
    def __init__(self, findings) -> None:
        self.findings = findings

    def trigger_scan(self, site_id, branch=None, commit=None):
        return {"scan_id": "s1", "status": "queued"}

    def wait_for_scan(self, site_id, scan_id):
        return {
            "scan_id": "s1",
            "status": "completed",
            "summary": {"tests_run": 5, "findings": len(self.findings)},
            "findings": self.findings,
        }


def test_cli_scan_gate_fails_on_high(capsys) -> None:
    class Args:
        site = "65f"
        branch = None
        commit = None
        wait = True
        fail_on = "high"
        poll_interval = 0.01
        timeout = 5
        json = False

    client = _GateClient([{"severity": "high", "title": "XSS", "target": "GET /users"}])
    assert _cmd_scan(client, Args()) == 1
    assert "gate failed" in capsys.readouterr().err


def test_cli_scan_gate_passes_on_info(capsys) -> None:
    class Args:
        site = "65f"
        branch = None
        commit = None
        wait = True
        fail_on = "high"
        poll_interval = 0.01
        timeout = 5
        json = False

    client = _GateClient([{"severity": "info", "title": "header", "target": "GET /"}])
    assert _cmd_scan(client, Args()) == 0
    assert "no findings at or above high" in capsys.readouterr().out


def test_cli_findings(capsys) -> None:
    class Args:
        site = "65f"
        scan = "s1"
        json = False

    class Client:
        def get_findings(self, site, scan):
            return [{"severity": "medium", "title": "Rate limit", "target": "GET /healthz"}]

    assert _cmd_findings(Client(), Args()) == 0
    assert "[MEDIUM] Rate limit" in capsys.readouterr().out


# --- OAuth2 auth + --verify --------------------------------------------------
def test_build_auth_oauth2() -> None:
    class Args:
        auth_type = "oauth2"
        auth_token = None
        auth_cookie = None
        auth_header = "X-API-Key"
        auth_token_url = "https://idp.example.com/oauth/token"
        auth_client_id = "client-123"
        auth_client_secret = "s3cret"

    auth = _build_auth(Args())
    assert auth == {
        "type": "oauth2",
        "token_url": "https://idp.example.com/oauth/token",
        "client_id": "client-123",
        "client_secret": "s3cret",
    }


def test_validate_auth_oauth2_requires_fields() -> None:
    class Args:
        auth_type = "oauth2"
        auth_token = None
        auth_cookie = None
        auth_header = "X-API-Key"
        auth_token_url = "https://idp.example.com/oauth/token"
        auth_client_id = None
        auth_client_secret = None

    assert _validate_auth(Args(), {"type": "oauth2"}) is not None


def test_validate_auth_bearer_requires_token() -> None:
    class Args:
        auth_type = "bearer"
        auth_token = None
        auth_cookie = None
        auth_header = "X-API-Key"
        auth_token_url = None
        auth_client_id = None
        auth_client_secret = None

    assert _validate_auth(Args(), {"type": "bearer"}) is not None


def test_verify_target_ok(monkeypatch, capsys) -> None:
    def fake_request(method, url, headers=None, timeout=None, follow_redirects=None):
        assert headers["Authorization"] == "Bearer tok"
        return httpx.Response(200)

    monkeypatch.setattr("httpx.request", fake_request)
    auth = {"type": "bearer", "token": "tok"}
    assert (
        _verify_target("https://api.example.com", [{"method": "GET", "path": "/users"}], auth) == 0
    )
    assert "✓" in capsys.readouterr().out


def test_verify_target_auth_failed(monkeypatch, capsys) -> None:
    def fake_request(method, url, headers=None, timeout=None, follow_redirects=None):
        return httpx.Response(401)

    monkeypatch.setattr("httpx.request", fake_request)
    auth = {"type": "bearer", "token": "dead"}
    code = _verify_target("https://api.example.com", [{"method": "GET", "path": "/users"}], auth)
    assert code == 2
    assert "auth failed" in capsys.readouterr().err


def test_verify_target_oauth2_fetches_token(monkeypatch, capsys) -> None:
    import httpx as _httpx

    def fake_request(
        method, url, headers=None, timeout=None, follow_redirects=None, data=None, **kw
    ):
        req = _httpx.Request(method, url)
        # token fetch
        if url == "https://idp.example.com/oauth/token":
            assert data["grant_type"] == "client_credentials"
            return _httpx.Response(200, json={"access_token": "fresh"}, request=req)
        assert headers["Authorization"] == "Bearer fresh"
        return _httpx.Response(200, request=req)

    monkeypatch.setattr("httpx.request", fake_request)
    auth = {
        "type": "oauth2",
        "token_url": "https://idp.example.com/oauth/token",
        "client_id": "c",
        "client_secret": "s",
    }
    assert (
        _verify_target("https://api.example.com", [{"method": "GET", "path": "/users"}], auth) == 0
    )


def test_cli_main_requires_api_key(capsys, monkeypatch) -> None:
    monkeypatch.delenv("LIVEAPISEC_API_KEY", raising=False)
    assert (
        main(
            [
                "--api-key",
                "",
                "push",
                "--name",
                "x",
                "--base-url",
                "https://x.test",
                "--endpoint",
                "GET /",
            ]
        )
        == 2
    )
    assert "Missing API key" in capsys.readouterr().err
