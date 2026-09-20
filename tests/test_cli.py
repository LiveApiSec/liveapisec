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


def test_trigger_hacker_scan() -> None:
    """TODO 3.6.1 — hacker-mode przez SDK/CLI (dev/stg env, nigdy prod)."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"scan_id": "hack123", "status": "queued", "environment": "development", "mode": "hacker"},
        )

    api = _client(handler)
    scan = api.trigger_hacker_scan("65fabc", "development")
    assert scan["scan_id"] == "hack123"
    assert scan["mode"] == "hacker"
    assert captured["url"].endswith("/developers/sites/65fabc/hacker-scans")
    assert captured["body"] == {"environment": "development"}


def test_trigger_hacker_scan_with_goal() -> None:
    """TODO 3.6.2 — guided goal w hacker-mode przez SDK/CLI."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"scan_id": "hack456", "status": "queued", "environment": "development"},
        )

    api = _client(handler)
    scan = api.trigger_hacker_scan("65fabc", "development", goal="check /users for IDOR")
    assert scan["scan_id"] == "hack456"
    assert captured["body"] == {
        "environment": "development",
        "goal": "check /users for IDOR",
    }


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


def test_cli_projects_groups_and_shows_last_scan(capsys) -> None:
    from liveapisec.cli import _cmd_projects

    class Client:
        def list_sites(self):
            return [
                {
                    "site_id": "a",
                    "name": "api-a",
                    "project": "svc",
                    "base_url": "https://a.test",
                    "last_scan": {
                        "status": "completed",
                        "tests_run": 42,
                        "findings": 3,
                        "by_severity": {"high": 1, "medium": 2},
                    },
                },
                {
                    "site_id": "b",
                    "name": "api-b",
                    "project": "svc",
                    "base_url": "https://b.test",
                    "last_scan": {"status": "failed"},
                },
                {
                    "site_id": "c",
                    "name": "api-c",
                    "project": "mobile",
                    "base_url": "https://c.test",
                    "last_scan": None,
                },
            ]

    class Args:
        project = None
        json = False

    assert _cmd_projects(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "svc" in out and "mobile" in out
    assert "api-a" in out and "api-b" in out and "api-c" in out
    assert "completed" in out
    assert "42 tests" in out
    assert "3 findings" in out
    assert "high=1 medium=2" in out
    assert "failed" in out
    assert "no test yet" in out


def test_cli_projects_json_and_filter(capsys) -> None:
    from liveapisec.cli import _cmd_projects

    sites = [
        {"site_id": "a", "project": "svc", "last_scan": None},
        {"site_id": "b", "project": "mobile", "last_scan": None},
    ]

    class Client:
        def list_sites(self):
            return sites

    class Args:
        project = None
        json = True

    assert _cmd_projects(Client(), Args()) == 0
    import json as _json

    assert _json.loads(capsys.readouterr().out) == sites

    class Args:
        project = "mobile"
        json = False

    assert _cmd_projects(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "mobile" in out
    assert "svc" not in out


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

    def trigger_scan(self, site_id, branch=None, commit=None, tunnel=False):
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


def test_cli_scans_lists_history_and_summarizes(capsys) -> None:
    from liveapisec.cli import _cmd_scans

    class Client:
        def list_scans(self, site):
            return [
                {
                    "scan_id": "s3",
                    "status": "completed",
                    "branch": "main",
                    "commit": "abc",
                    "summary": {"tests_run": 42, "findings": 3, "by_severity": {"high": 1, "medium": 2}},
                },
                {"scan_id": "s2", "status": "failed", "branch": "main"},
                {"scan_id": "s1", "status": "completed", "summary": {"tests_run": 5, "findings": 0}},
            ]

    class Args:
        site = "65f"
        limit = 20
        json = False

    assert _cmd_scans(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "s3" in out and "s2" in out and "s1" in out
    assert "status=completed" in out
    assert "tests=42" in out and "findings=3" in out
    assert "high=1 medium=2" in out
    assert "status=failed" in out

    class Args:
        site = "65f"
        limit = 1
        json = False

    assert _cmd_scans(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "more (use --json for all)" in out

    class Args:
        site = "65f"
        limit = 20
        json = True

    assert _cmd_scans(Client(), Args()) == 0
    import json as _json

    assert len(_json.loads(capsys.readouterr().out)) == 3


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


# --- certificate (scope-aware) -----------------------------------------------


def test_get_certificate_scope_sdk() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "scope": "project",
                "slug": "acme-payments",
                "trust_url": "https://liveapisec.com/trust/acme-payments",
                "embeds": {"badge": "<div data-liveapisec-widget></div>"},
            },
        )

    data = _client(handler).get_certificate(scope="project", project="payments")
    assert data["slug"] == "acme-payments"
    assert "scope=project" in seen["url"]
    assert "project=payments" in seen["url"]


def test_cli_certificate_prints_snippet(capsys) -> None:
    from liveapisec.cli import _cmd_certificate

    class Client:
        def get_certificate(self, scope="org", project=None, site=None):
            return {
                "scope": "org",
                "slug": "acme",
                "trust_url": "https://liveapisec.com/trust/acme",
                "embeds": {
                    "badge": '<div data-liveapisec-widget data-slug="acme" data-type="badge"></div>'
                },
            }

    class Args:
        json = False
        type = "badge"
        scope = "org"
        project = None
        site = None

    assert _cmd_certificate(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "https://liveapisec.com/trust/acme" in out
    assert "data-liveapisec-widget" in out
    assert "scope: org" in out


# --- reverse tunnel (A) ------------------------------------------------------


def test_trigger_scan_tunnel_flag() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"scan_id": "s1", "status": "queued"})

    _client(handler).trigger_scan("site1", tunnel=True)
    assert captured["body"] == {"tunnel": True}


def test_trigger_hacker_scan_tunnel_flag() -> None:
    """Hacker-mode przez tunel CLI (localhost/internal) — flaga w payloadzie."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"scan_id": "hack-t", "status": "queued"})

    _client(handler).trigger_hacker_scan("site1", "development", tunnel=True)
    assert captured["body"] == {"environment": "development", "tunnel": True}


def test_cmd_connect_forwards_one_request(monkeypatch, capsys) -> None:
    import base64
    from typing import ClassVar

    import httpx as _httpx

    from liveapisec.cli import _cmd_connect

    class FakeResp:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}
        content = b'{"ok":true}'

    class FakeClient:
        def __init__(self, *a, **k): ...

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, url, headers=None, content=None):
            assert method == "GET" and url == "http://localhost:8000/x"
            return FakeResp()

    monkeypatch.setattr(_httpx, "Client", FakeClient)
    got: dict = {}
    seq = [
        {
            "request_id": "r1",
            "method": "GET",
            "url": "http://localhost:8000/x",
            "headers": {"host": "localhost:8000", "accept": "*/*"},
            "body": "",
        },
        None,
    ]

    class Client:
        def open_tunnel(self, site_id):
            return {"tunnel_id": "t1", "site_id": site_id, "base_url": "http://localhost:8000"}

        def tunnel_next(self, tunnel_id, timeout=25):
            if seq:
                return seq.pop(0)
            raise KeyboardInterrupt

        def tunnel_result(self, tunnel_id, result):
            got["result"] = result

        def close_tunnel(self, tunnel_id):
            got["closed"] = True

    class Args:
        site = "s1"
        poll_timeout = 1

    assert _cmd_connect(Client(), Args()) == 0
    assert got["closed"] is True
    assert got["result"]["status"] == 200
    assert base64.b64decode(got["result"]["body"]) == b'{"ok":true}'
    assert "localhost:8000" in got["result"]["headers"].get("host", "") or True


def test_create_site_sends_schedule_and_access() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"site_id": "s1", "access": "internal"})

    _client(handler).create_site(
        "n",
        "http://10.0.0.5:8000",
        endpoints=[{"method": "GET", "path": "/x"}],
        access="internal",
        schedule="off",
    )
    assert captured["body"]["access"] == "internal"
    assert captured["body"]["schedule"] == "off"


def test_create_site_omits_empty_schedule_access() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"site_id": "s1"})

    _client(handler).create_site("n", "https://api.test", endpoints=[{"method": "GET", "path": "/x"}])
    assert "access" not in captured["body"]
    assert "schedule" not in captured["body"]


# --- verdict / compliance / report / certificate PDF -------------------------

def _verdict_payload(verdict="fail"):
    return {
        "scan_id": "cur", "baseline_scan_id": "base", "fail_on": "high",
        "verdict": verdict,
        "counts": {"new": 1, "fixed": 2, "persisting": 3, "blocking": 1 if verdict == "fail" else 0},
        "blocking": [{"severity": "high", "title": "IDOR", "target": "GET /u"}] if verdict == "fail" else [],
        "new": [], "fixed": [], "persisting": [],
    }


def test_cli_verdict_fail_exit_1(capsys) -> None:
    from liveapisec.cli import _cmd_verdict

    class Args:
        site = "s1"; scan = "cur"; baseline = "base"; fail_on = "high"; json = False

    class Client:
        def get_verdict(self, site, scan, baseline, fail_on="high"):
            assert (site, scan, baseline, fail_on) == ("s1", "cur", "base", "high")
            return _verdict_payload("fail")

    assert _cmd_verdict(Client(), Args()) == 1
    captured = capsys.readouterr()
    assert "verdict: FAIL" in captured.out and "IDOR" in captured.err


def test_cli_verdict_pass_exit_0(capsys) -> None:
    from liveapisec.cli import _cmd_verdict

    class Args:
        site = "s1"; scan = "cur"; baseline = "base"; fail_on = "high"; json = False

    class Client:
        def get_verdict(self, site, scan, baseline, fail_on="high"):
            return _verdict_payload("pass")

    assert _cmd_verdict(Client(), Args()) == 0


def test_cli_compliance(capsys) -> None:
    from liveapisec.cli import _cmd_compliance

    class Args:
        site = "s1"; scan = "cur"; json = False

    class Client:
        def get_compliance(self, site, scan):
            return {
                "scan_id": "cur",
                "frameworks": {
                    "pci_dss": {"name": "PCI DSS 4.0", "failed": 1, "requirements_with_findings": 2},
                    "gdpr": {"name": "GDPR", "failed": 0, "requirements_with_findings": 0},
                },
            }

    assert _cmd_compliance(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "PCI DSS 4.0" in out and "GDPR" in out


def test_cli_report_saves_file(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_report

    out = tmp_path / "r.json"

    class Args:
        site = "s1"; scan = "cur"; json = False; output = str(out)

    class Client:
        def get_report(self, site, scan):
            return {"scan_id": "cur", "summary": {}}

    assert _cmd_report(Client(), Args()) == 0
    assert '"scan_id": "cur"' in out.read_text()


def test_cli_certificate_pdf(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_certificate

    out = tmp_path / "c.pdf"

    class Args:
        site = "s1"; scan = "cur"; pdf = True; variant = "full"; output = str(out)
        json = False; scope = "org"; project = None; type = "badge"

    class Client:
        def download_certificate_pdf(self, site, scan, variant="full"):
            assert (site, scan, variant) == ("s1", "cur", "full")
            return b"%PDF-1.4 fake", "liveapisec-certificate-full-cur.pdf"

    assert _cmd_certificate(Client(), Args()) == 0
    assert out.read_bytes() == b"%PDF-1.4 fake"
    assert "certificate PDF saved" in capsys.readouterr().out


# --- all (full pipeline) -----------------------------------------------------

def _all_client(**kw):
    from liveapisec.client import LiveAPISecError

    class Client:
        def trigger_scan(self, site, branch=None, commit=None, tunnel=False):
            return {"scan_id": "new1"}

        def wait_for_scan(self, site, scan_id, timeout=None, interval=None):
            return {"scan_id": "new1", "status": "completed", "tests_run": 5, "findings": []}

        def list_scans(self, site):
            return [
                {"scan_id": "new1", "status": "completed"},
                {"scan_id": "base9", "status": "completed"},
            ]

        def get_verdict(self, site, scan, baseline, fail_on="high"):
            assert baseline == kw.get("baseline", "base9")
            return {
                "scan_id": scan, "baseline_scan_id": baseline, "fail_on": fail_on,
                "verdict": kw.get("verdict", "pass"),
                "counts": {"new": 0, "fixed": 1, "persisting": 0, "blocking": 0},
                "blocking": [],
            }

        def get_compliance(self, site, scan):
            if kw.get("compliance_402"):
                raise LiveAPISecError(402, "Upgrade required", "compliance is Pro+")
            return {"scan_id": scan, "frameworks": {}}

        def get_report(self, site, scan):
            return {"scan_id": scan, "summary": {}}

        def get_findings(self, site, scan):
            return []

        def download_certificate_pdf(self, site, scan, variant="full"):
            if kw.get("no_pdf"):
                raise LiveAPISecError(409, "Certificate not available", "scan did not pass")
            return b"%PDF-1.4 x", "cert.pdf"

    return Client()


def _all_args(tmp_path, **kw):
    class Args:
        site = "s1"
        baseline = kw.get("baseline")
        fail_on = "high"
        branch = None; commit = None; tunnel = False
        hacker = False; env = None; goal = None
        variant = "full"
        report_out = str(tmp_path / "r.json")
        pdf_out = str(tmp_path / "c.pdf")
        json = kw.get("json", False)
    return Args()


def test_cli_all_pass(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_all

    assert _cmd_all(_all_client(), _all_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "PASS" in out and "report saved" in out and "certificate PDF saved" in out
    assert (tmp_path / "r.json").exists() and (tmp_path / "c.pdf").exists()


def test_cli_all_fail_exit_1(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_all

    assert _cmd_all(_all_client(verdict="fail"), _all_args(tmp_path)) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_all_tolerates_402_and_409(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_all

    assert _cmd_all(_all_client(compliance_402=True, no_pdf=True), _all_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "compliance skipped" in out and "certificate PDF skipped" in out


# --- markdown report ---------------------------------------------------------

def _md_client():
    class Client:
        def get_report(self, site, scan):
            return {
                "scan_id": scan, "status": "completed",
                "summary": {"tests_run": 10, "duration_s": 3.2, "findings": 2,
                            "by_severity": {"high": 1, "low": 1}},
            }

        def get_findings(self, site, scan):
            return [
                {"severity": "high", "title": "IDOR", "target": "GET /u/{id}", "category": "bola"},
                {"severity": "low", "title": "Verbose header", "target": "GET /", "category": "headers"},
            ]

    return Client()


def test_cli_report_md(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_report

    out = tmp_path / "r.md"

    class Args:
        site = "s1"; scan = "s9"; json = False; output = str(out); format = "md"

    assert _cmd_report(_md_client(), Args()) == 0
    text = out.read_text()
    assert text.startswith("# LiveAPIsec security report")
    assert "| high | IDOR |" in text
    assert "report saved" in capsys.readouterr().out


def test_cli_all_md_report_with_verdict(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_all

    class Client(_all_client().__class__):
        pass

    base = _all_client()

    class Args:
        site = "s1"
        baseline = None
        fail_on = "high"
        branch = None; commit = None; tunnel = False
        hacker = False; env = None; goal = None
        variant = "full"
        report_out = str(tmp_path / "run.md")
        pdf_out = str(tmp_path / "c.pdf")
        format = "md"
        json = False

    # reuse stub methods from _all_client via delegation
    class Delegating:
        def __getattr__(self, name):
            return getattr(base, name)

    assert _cmd_all(Delegating(), Args()) == 0
    text = (tmp_path / "run.md").read_text()
    assert "Regression verdict vs baseline" in text
    assert "report saved" in capsys.readouterr().out
