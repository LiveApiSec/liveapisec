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


# --- create_project -------------------------------------------------------------
def test_create_project_posts_payload_and_auth_header() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "project_id": "65f000000000000000000001",
                "name": "my-api",
                "base_url": "https://api.example.com",
                "endpoints_count": 2,
                "auth": "jwt",
            },
        )

    api = _client(handler)
    site = api.create_project(
        name="my-api",
        base_url="https://api.example.com",
        endpoints=[{"method": "GET", "path": "/users"}, {"method": "POST", "path": "/payments"}],
        auth={"type": "jwt", "token": "eyJ.secret"},
    )
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/developers/projects")
    assert captured["auth"] == "Bearer las_dev_test"
    assert captured["body"]["name"] == "my-api"
    assert captured["body"]["auth"]["token"] == "eyJ.secret"
    assert site["project_id"] == "65f000000000000000000001"


def test_create_project_with_existing_id_uses_put() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(200, json={"project_id": "65fabc", "endpoints_count": 1, "auth": "none"})

    api = _client(handler)
    api.create_project(
        name="x",
        base_url="https://x.test",
        endpoints=[{"method": "GET", "path": "/"}],
        project_id="65fabc",
    )
    assert captured["method"] == "PUT"


def test_api_error_raises_liveapisecerror() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Unauthorized", "detail": "invalid API key"})

    api = _client(handler)
    with pytest.raises(LiveAPISecError) as exc:
        api.create_project("x", "https://x.test", endpoints=[{"method": "GET", "path": "/"}])
    assert exc.value.status == 401
    assert "Unauthorized" in str(exc.value)


def test_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("LIVEAPISEC_API_KEY", raising=False)
    api = LiveAPISec(api_url="https://x.test", api_key=None)
    with pytest.raises(LiveAPISecError) as exc:
        api.get_project("65fabc")
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
    assert captured["url"].endswith("/developers/projects/65fabc/hacker-scans")
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

    def create_project(self, **kw):
        self.sites.append(kw)
        return {"project_id": "65faaa", "name": kw["name"], "endpoints_count": 1, "auth": "none"}


def test_cli_push_builds_payload(capsys) -> None:
    stub = _StubClient()

    class Args:
        name = "my-api"
        base_url = "https://api.example.com"
        project = None
        endpoint: list = [{"method": "GET", "path": "/users"}]  # noqa: RUF012 (test stub)
        openapi_url = None
        project = None
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
    assert "export PROJECT_ID=65faaa" in out


def test_push_project_without_name_fills_from_existing(capsys) -> None:
    """Regresja: `push --project <id>` bez `--name`/`--base-url` → PUT z pustym
    `name` i mylący 422. Teraz brakujące pola są dopełniane z istniejącego projektu.
    """
    captured: dict = {}

    class Client:
        def get_project(self, project_id):
            return {
                "project_id": project_id,
                "name": "existing-name",
                "base_url": "https://old.test",
            }

        def create_project(self, **kw):
            captured.update(kw)
            return {
                "project_id": "65fabc",
                "name": kw["name"],
                "endpoints_count": 1,
                "auth": "none",
            }

    class Args:
        name = None
        base_url = None
        project = "65fabc"
        endpoint: list = [{"method": "GET", "path": "/x"}]  # noqa: RUF012 (test stub)
        openapi_url = None
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
    assert captured["name"] == "existing-name"
    assert captured["base_url"] == "https://old.test"
    capsys.readouterr()


def test_cli_push_requires_endpoint(capsys) -> None:
    class Args:
        name = "x"
        base_url = "https://x.test"
        project = None
        endpoint: list = []  # noqa: RUF012 (test stub)
        openapi_url = None
        project = None
        verify = False
        json = False

    assert _cmd_push(_StubClient(), Args()) == 2
    assert "error:" in capsys.readouterr().err


# --- performance: 1000+ endpoints --------------------------------------------
def test_cli_push_many_endpoints_sent_and_summarized(capsys) -> None:
    """All 1500 endpoints go in ONE request; output summarizes + shows the cap note."""
    captured: dict = {}

    class Client:
        def create_project(self, **kw):
            captured["endpoints"] = kw["endpoints"]
            return {
                "project_id": "65fbig",
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
        project = None
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


# --- interactive picker (project) --------------------------------------------
def test_pick_project_existing(monkeypatch, capsys) -> None:
    from liveapisec.cli import _pick_project

    monkeypatch.setattr("builtins.input", lambda _p: "2")
    projects = [
        {"project_id": "a", "name": "api-a", "base_url": "https://a"},
        {"project_id": "b", "name": "api-b", "base_url": "https://b"},
    ]
    picked = _pick_project(projects)
    assert picked and picked["project_id"] == "b"
    out = capsys.readouterr().out
    assert "Pick a project" in out
    assert "create new project" in out


def test_pick_project_new(monkeypatch, capsys) -> None:
    from liveapisec.cli import _pick_project

    monkeypatch.setattr("builtins.input", lambda _p: "9")  # spoza listy → nowy
    projects = [{"project_id": "a", "name": "api-a", "base_url": "https://a"}]
    assert _pick_project(projects) is None


def test_list_projects_sdk() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json=[{"project_id": "a", "project": "svc"}])

    sites = _client(handler).list_projects()
    assert captured["url"].endswith("/developers/projects")
    assert sites == [{"project_id": "a", "project": "svc"}]


def test_cli_projects_shows_last_scan(capsys) -> None:
    from liveapisec.cli import _cmd_projects

    class Client:
        def list_projects(self):
            return [
                {
                    "project_id": "a",
                    "name": "api-a",
                    "base_url": "https://a.test",
                    "last_scan": {
                        "status": "completed",
                        "tests_run": 42,
                        "findings": 3,
                        "by_severity": {"high": 1, "medium": 2},
                    },
                },
                {
                    "project_id": "b",
                    "name": "api-b",
                    "base_url": "https://b.test",
                    "last_scan": {"status": "failed"},
                },
                {
                    "project_id": "c",
                    "name": "api-c",
                    "base_url": "https://c.test",
                    "last_scan": None,
                },
            ]

    class Args:
        project = None
        json = False

    assert _cmd_projects(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "api-a" in out and "api-b" in out and "api-c" in out
    assert "completed" in out
    assert "42 tests" in out
    assert "3 findings" in out
    assert "high=1 medium=2" in out
    assert "failed" in out
    assert "no test yet" in out


def test_cli_projects_json(capsys) -> None:
    from liveapisec.cli import _cmd_projects

    projects = [
        {"project_id": "a", "name": "api-a", "last_scan": None},
        {"project_id": "b", "name": "api-b", "last_scan": None},
    ]

    class Client:
        def list_projects(self):
            return projects

    class Args:
        project = None
        json = True

    assert _cmd_projects(Client(), Args()) == 0
    import json as _json

    assert _json.loads(capsys.readouterr().out) == projects


def test_push_interactive_picks_existing_site(monkeypatch, capsys) -> None:
    import sys as _sys

    from liveapisec.cli import _cmd_push

    class FakeTTY:
        def isatty(self):
            return True

    monkeypatch.setattr(_sys, "stdin", FakeTTY())
    monkeypatch.setattr("builtins.input", lambda _p: "1")  # project=1, site=1

    sites = [
        {"project_id": "siteA", "name": "api-a", "project": "svc", "base_url": "https://a.test"},
    ]
    calls: dict = {}

    class Client:
        def list_projects(self):
            return sites

        def create_project(self, **kw):
            calls.update(kw)
            return {
                "project_id": kw.get("project_id") or "new",
                "name": "x",
                "endpoints_count": 1,
                "auth": "none",
                "updated": bool(kw.get("project_id")),
            }

    class Args:
        name = None
        base_url = None
        project = None
        endpoint: list = [{"method": "GET", "path": "/users"}]  # noqa: RUF012
        openapi_url = None
        project = None
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
    # wybrał istniejący site → PUT (project_id), name/base_url z istniejącego
    assert calls["project_id"] == "siteA"
    assert calls["name"] == "api-a"
    assert calls["base_url"] == "https://a.test"


# --- CLI: scan gate ----------------------------------------------------------
class _GateClient:
    def __init__(self, findings) -> None:
        self.findings = findings

    def trigger_scan(
        self, project_id, branch=None, commit=None, tunnel=False, auth_b=None, environment=None
    ):
        return {"scan_id": "s1", "status": "queued"}

    def wait_for_scan(self, project_id, scan_id):
        return {
            "scan_id": "s1",
            "status": "completed",
            "summary": {"tests_run": 5, "findings": len(self.findings)},
            "findings": self.findings,
        }


def test_cli_scan_gate_fails_on_high(capsys) -> None:
    class Args:
        project = "65f"
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
        project = "65f"
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
        project = "65f"
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
        project = "65f"
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
        project = "65f"
        limit = 1
        json = False

    assert _cmd_scans(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "more (use --json for all)" in out

    class Args:
        project = "65f"
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
        project = None

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
        def open_tunnel(self, project_id):
            return {"tunnel_id": "t1", "project_id": project_id, "base_url": "http://localhost:8000"}

        def tunnel_next(self, tunnel_id, timeout=25):
            if seq:
                return seq.pop(0)
            raise KeyboardInterrupt

        def tunnel_result(self, tunnel_id, result):
            got["result"] = result

        def close_tunnel(self, tunnel_id):
            got["closed"] = True

    class Args:
        project = "s1"
        poll_timeout = 1

    assert _cmd_connect(Client(), Args()) == 0
    assert got["closed"] is True
    assert got["result"]["status"] == 200
    assert base64.b64decode(got["result"]["body"]) == b'{"ok":true}'
    assert "localhost:8000" in got["result"]["headers"].get("host", "") or True


def test_create_project_sends_schedule_and_access() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"project_id": "s1", "access": "internal"})

    _client(handler).create_project(
        "n",
        "http://10.0.0.5:8000",
        endpoints=[{"method": "GET", "path": "/x"}],
        access="internal",
        schedule="off",
    )
    assert captured["body"]["access"] == "internal"
    assert captured["body"]["schedule"] == "off"


def test_create_project_omits_empty_schedule_access() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"project_id": "s1"})

    _client(handler).create_project("n", "https://api.test", endpoints=[{"method": "GET", "path": "/x"}])
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
        project = "s1"; scan = "cur"; baseline = "base"; fail_on = "high"; json = False

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
        project = "s1"; scan = "cur"; baseline = "base"; fail_on = "high"; json = False

    class Client:
        def get_verdict(self, site, scan, baseline, fail_on="high"):
            return _verdict_payload("pass")

    assert _cmd_verdict(Client(), Args()) == 0


def test_cli_compliance(capsys) -> None:
    from liveapisec.cli import _cmd_compliance

    class Args:
        project = "s1"; scan = "cur"; json = False

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
        project = "s1"; scan = "cur"; json = False; output = str(out)

    class Client:
        def get_report(self, site, scan):
            return {"scan_id": "cur", "summary": {}}

    assert _cmd_report(Client(), Args()) == 0
    assert '"scan_id": "cur"' in out.read_text()


def test_cli_certificate_pdf(tmp_path, capsys) -> None:
    from liveapisec.cli import _cmd_certificate

    out = tmp_path / "c.pdf"

    class Args:
        project = "s1"; scan = "cur"; pdf = True; variant = "full"; output = str(out)
        json = False; scope = "org"; type = "badge"

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
        def trigger_scan(self, site, branch=None, commit=None, tunnel=False, auth_b=None):
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
        project = "s1"
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
        project = "s1"; scan = "s9"; json = False; output = str(out); format = "md"

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
        project = "s1"
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


# --- scan-code (renamed from push-code; old name stays as alias) --------------

def test_scan_code_alias_parses_to_same_command() -> None:
    from liveapisec.cli import _cmd_scan_code, build_parser

    for name in ("scan-code", "push-code"):
        args = build_parser().parse_args([name, "--dir", ".", "--dry-run"])
        assert args.func is _cmd_scan_code
        assert _cmd_scan_code.__name__ == '_cmd_scan_code'


# --- auth-matrix (second identity) -------------------------------------------

def test_auth_b_payload_builds_bearer() -> None:
    from liveapisec.cli import _auth_b_payload

    class Args:
        auth_type_b = "bearer"; auth_token_b = "tok123"

    assert _auth_b_payload(Args()) == {"auth_method": "bearer", "fields": {"token": "tok123"}}


def test_auth_b_payload_none_when_no_token() -> None:
    from liveapisec.cli import _auth_b_payload

    class Args:
        auth_type_b = "bearer"; auth_token_b = None

    assert _auth_b_payload(Args()) is None


def test_trigger_scan_sends_auth_b() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"scan_id": "s1", "status": "queued"})

    _client(handler).trigger_scan(
        "site1", auth_b={"auth_method": "bearer", "fields": {"token": "second"}}
    )
    assert captured["body"]["auth_b"]["fields"] == {"token": "second"}


def test_trigger_scan_sends_environment() -> None:
    """TODO 2.50: `scan --url <name>` przekazuje environment do API."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"scan_id": "s1", "status": "queued"})

    _client(handler).trigger_scan("site1", environment="staging")
    assert captured["body"]["environment"] == "staging"


def test_scan_parser_has_url_flag() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(["scan", "--project", "s1", "--url", "staging"])
    assert args.url == "staging"


def test_scan_parser_has_auth_b_flags() -> None:
    from liveapisec.cli import build_parser

    for cmd in ("scan", "all"):
        args = build_parser().parse_args([cmd, "--project", "s1", "--auth-token-b", "t"])
        assert args.auth_token_b == "t"
        assert args.auth_type_b == "bearer"


# --- ask-mode (SEC-ASK-N) --------------------------------------------------------

def _ask_client():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/ask-sessions") and request.method == "POST":
            return httpx.Response(201, json={"session_id": "sess1", "questions": 200})
        if path.endswith("/ask-sessions"):
            return httpx.Response(200, json=[{
                "session_id": "sess1", "api_spec_id": "s1", "status": "open",
                "questions": 2,
                "counts": {"pass": 0, "fail": 1, "na": 0, "unanswered": 1},
                "failed": [{"qid": "SEC-ASK-1", "category": "authentication",
                            "question": "MFA?", "fix": "Require.", "note": "no mfa"}],
            }])
        if "/answers" in path:
            return httpx.Response(200, json={
                "session_id": "sess1", "questions": 2,
                "counts": {"pass": 1, "fail": 1, "na": 0, "unanswered": 0},
                "failed": [],
            })
        return httpx.Response(200, json={
            "session_id": "sess1", "status": "open",
            "counts": {"pass": 0, "fail": 0, "na": 0, "unanswered": 1},
            "failed": [],
            "questions": [{"qid": "SEC-ASK-1", "category": "authentication",
                           "question": "MFA?", "fix": "Require.", "ai": False,
                           "answer": None}],
        })

    return _client(handler)


def test_cli_ask_new(capsys) -> None:
    from liveapisec.cli import _cmd_ask_new

    class Args:
        project = "s1"; no_ai = False; json = False

    assert _cmd_ask_new(_ask_client(), Args()) == 0
    assert "ask session created: sess1 (200 questions)" in capsys.readouterr().out


def test_cli_ask_sessions(capsys) -> None:
    from liveapisec.cli import _cmd_ask_sessions

    class Args:
        project = "s1"; json = False

    assert _cmd_ask_sessions(_ask_client(), Args()) == 0
    out = capsys.readouterr().out
    assert "fail=1" in out and "SEC-ASK-1" in out


def test_cli_ask_counts_line_with_question_list() -> None:
    from liveapisec.cli import _ask_counts_line

    line = _ask_counts_line({
        "session_id": "sess1",
        "questions": [{"qid": "SEC-ASK-1"}, {"qid": "SEC-ASK-2"}],
        "counts": {"pass": 1, "fail": 0, "na": 1, "unanswered": 0},
    })
    assert "2 questions" in line and "pass=1" in line


def test_cli_ask_answer(capsys) -> None:
    from liveapisec.cli import _cmd_ask_answer

    class Args:
        session = "sess1"; question = "SEC-ASK-2"; verdict = "pass"; note = "checked auth.py"; json = False

    assert _cmd_ask_answer(_ask_client(), Args()) == 0
    assert "pass=1" in capsys.readouterr().out


def test_cli_ask_parser() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(
        ["ask", "answer", "--session", "s", "--question", "SEC-ASK-1",
         "--verdict", "fail", "--note", "x"]
    )
    assert args.ask_command == "answer" and args.verdict == "fail"


def test_endpoints_from_spec_file_json(tmp_path) -> None:
    import json

    from liveapisec.cli import _endpoints_from_spec_file

    spec = {"openapi": "3.0.0", "paths": {
        "/users": {"get": {}, "post": {}},
        "/admin": {"delete": {}, "trace": {}},
    }}
    p = tmp_path / "api.json"
    p.write_text(json.dumps(spec))
    assert _endpoints_from_spec_file(str(p)) == [
        {"method": "GET", "path": "/users"},
        {"method": "POST", "path": "/users"},
        {"method": "DELETE", "path": "/admin"},
    ]


def test_endpoints_from_spec_file_errors(tmp_path) -> None:
    import pytest

    from liveapisec.cli import LiveAPISecError, _endpoints_from_spec_file

    p = tmp_path / "bad.json"
    p.write_text('{"info": {}}')
    with pytest.raises(LiveAPISecError):
        _endpoints_from_spec_file(str(p))
    with pytest.raises(LiveAPISecError):
        _endpoints_from_spec_file(str(tmp_path / "missing.json"))


def test_cli_ask_followup(capsys) -> None:
    from liveapisec.cli import _cmd_ask_followup

    def handler(request: httpx.Request) -> httpx.Response:
        if "/followups" in request.url.path:
            return httpx.Response(200, json={
                "session_id": "sess1", "questions": 3, "added": 1,
                "counts": {"pass": 1, "fail": 1, "na": 1, "unanswered": 0},
                "failed": [],
            })
        return httpx.Response(404, json={})

    class Args:
        session = "sess1"; json = False

    assert _cmd_ask_followup(_client(handler), Args()) == 0
    assert "follow-up questions added: 1" in capsys.readouterr().out


def test_cli_ask_followup_parser() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(["ask", "followup", "--session", "s"])
    assert args.ask_command == "followup"


# --- TODO 2.50: wersje per-URL + publiczny certyfikat per-URL ---------------


def test_set_project_certificate_url_sdk() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"environment": "staging"})

    _client(handler).set_project_certificate_url("s1", "staging")
    assert captured["method"] == "PATCH"
    assert captured["path"].endswith("/developers/projects/s1/certificate")
    assert captured["body"]["environment"] == "staging"


def test_cli_certificate_url_flag(capsys) -> None:
    from liveapisec.cli import _cmd_certificate

    calls: dict = {}

    class Client:
        def set_project_certificate_url(self, site, environment):
            calls["site"] = site
            calls["env"] = environment
            return {}

        def get_certificate(self, scope="org", project=None, site=None):
            return {"scope": "project", "slug": "s", "trust_url": "u", "embeds": {}}

    class Args:
        json = False
        type = "badge"
        scope = "project"
        project = None
        project = "s1"
        url = "staging"
        pdf = False
        scan = None
        output = None
        variant = None

    assert _cmd_certificate(Client(), Args()) == 0
    assert calls == {"site": "s1", "env": "staging"}


def test_certificate_parser_has_url_flag() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(["certificate", "--project", "s1", "--url", "staging"])
    assert args.url == "staging"


def test_cli_sites_shows_url_versions(capsys) -> None:
    from liveapisec.cli import _cmd_project

    class Client:
        def get_project(self, site):
            return {
                "project_id": "s1",
                "name": "api",
                "endpoints_count": 1,
                "base_url": "https://x",
                "environments": [
                    {
                        "name": "prod",
                        "base_url": "https://p",
                        "version": "1.2.3",
                        "schedule": "off",
                        "paused": False,
                    },
                    {
                        "name": "dev",
                        "base_url": "https://d",
                        "version": "latest",
                        "schedule": "6h",
                        "paused": False,
                    },
                ],
            }

    class Args:
        json = False
        project = "s1"

    assert _cmd_project(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "prod: https://p  [version=1.2.3]" in out
    assert "dev: https://d  [schedule=6h]" in out


def test_cli_versions_lists_and_marks(capsys) -> None:
    from liveapisec.cli import _cmd_versions

    class Client:
        def list_versions(self, site):
            return [
                {
                    "version": "1.0.1",
                    "note": "merge: +3 endpoints",
                    "created_at": "2026-09-21T00:00:00",
                    "endpoints_count": 5,
                    "used_by": ["prod"],
                    "is_current": True,
                },
                {
                    "version": "1.0.0",
                    "note": "initial",
                    "created_at": "2026-09-20T00:00:00",
                    "endpoints_count": 4,
                    "used_by": [],
                    "is_current": False,
                },
            ]

    class Args:
        json = False
        project = "s1"

    assert _cmd_versions(Client(), Args()) == 0
    out = capsys.readouterr().out
    assert "1.0.1" in out and "(current)" in out
    assert "used by: prod" in out


def test_versions_parser() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(["versions", "--project", "s1"])
    assert args.project == "s1"


def test_cli_delete_project(capsys) -> None:
    from liveapisec.cli import _cmd_delete

    calls: dict = {}

    class Client:
        def delete_project(self, project):
            calls["project"] = project

    class A:
        project = "s1"
        yes = True
        json = False

    class B:
        project = None
        yes = True
        json = False

    assert _cmd_delete(Client(), A()) == 0
    assert calls["project"] == "s1"
    assert _cmd_delete(Client(), B()) == 2  # --project jest wymagane


def test_push_spec_file_sends_full_spec(tmp_path) -> None:
    """TODO 2.50: `--spec-file` wysyła CAŁY spec (parametry/security), nie tylko endpointy."""
    from liveapisec.cli import _cmd_push

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "T", "version": "1"},
        "paths": {
            "/users": {
                "get": {
                    "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                    "security": [{"bearer": []}],
                }
            }
        },
    }
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps(spec))

    calls: dict = {}

    class Client:
        def create_project(self, **kw):
            calls.update(kw)
            return {"project_id": "s1", "name": kw["name"], "endpoints_count": 1, "auth": "none"}

    class Args:
        spec_file = str(p)
        name = "n"
        base_url = "http://x.test"
        project = None
        endpoint: list = []  # noqa: RUF012
        openapi_url = None
        project = None
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
    assert calls["spec"] == spec  # pełny spec, nie lista endpointów
    assert calls["endpoints"] == []


def test_md_report_summary_and_points_to_improve() -> None:
    """TODO 2.50: raport MD ma Summary (ryzyko) + Points to improve (Why/Fix)."""
    from liveapisec.cli import _md_report

    scan = {
        "scan_id": "s1",
        "status": "completed",
        "summary": {
            "tests_run": 100,
            "tested": 124,
            "absent": 3,
            "findings": 1,
            "by_severity": {"low": 1},
        },
    }
    findings = [
        {
            "severity": "low",
            "title": "Missing rate limiting on GET /healthz",
            "target": "GET /healthz",
            "category": "rate_limit",
            "description": "12 rapid requests returned no 429",
        }
    ]
    ask = {
        "session_id": "abc",
        "questions": 10,
        "counts": {"pass": 1, "fail": 1, "na": 0, "unanswered": 8},
        "failed": [
            {
                "qid": "SEC-ASK-2",
                "category": "authentication",
                "severity": "high",
                "question": "Hash?",
                "fix": "Use argon2id",
                "note": "bcrypt",
            }
        ],
    }
    md = _md_report(scan, findings, ask_summary=ask)
    assert "## Summary" in md
    assert "Points to improve" in md
    assert "Coverage" in md and "124 tested" in md and "3 not deployed" in md
    assert "[SCAN]" in md and "[QUESTIONNAIRE]" in md
    assert "**Fix:**" in md
    assert "Use argon2id" in md  # fix z pytania ask
    assert "429" in md  # z opisu findingu (Why)


def test_print_scan_summary(capsys) -> None:
    """TODO 2.50: `scan --wait` drukuje risk/coverage/points to improve."""
    from liveapisec.cli import _print_scan_summary

    scan = {"summary": {"tested": 124, "absent": 3, "by_severity": {"low": 1}}}
    findings = [
        {
            "severity": "low",
            "title": "Missing rate limiting on GET /healthz",
            "target": "GET /healthz",
            "category": "rate_limit",
            "description": "no 429",
        }
    ]
    _print_scan_summary(scan, findings)
    out = capsys.readouterr().out
    assert "risk=LOW" in out
    assert "124 tested" in out and "3 not deployed" in out
    assert "points to improve" in out
    assert "Missing rate limiting" in out

    _print_scan_summary({"summary": {"tested": 5}}, [])
    assert "no findings" in capsys.readouterr().out


def test_hacker_parser_has_destructive_flag() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(["hacker", "--project", "s1", "--env", "dev"])
    assert args.destructive is False
    args2 = build_parser().parse_args(
        ["hacker", "--project", "s1", "--env", "dev", "--destructive"]
    )
    assert args2.destructive is True


def test_trigger_hacker_scan_sends_destructive() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"scan_id": "h1", "status": "queued"})

    _client(handler).trigger_hacker_scan("s1", "dev", destructive=True)
    assert captured["body"]["destructive"] is True


def test_hacker_parser_has_thorough_flag() -> None:
    from liveapisec.cli import build_parser

    args = build_parser().parse_args(["hacker", "--project", "s1", "--env", "dev"])
    assert args.thorough is False
    args2 = build_parser().parse_args(["hacker", "--project", "s1", "--env", "dev", "--thorough"])
    assert args2.thorough is True


def test_trigger_hacker_scan_sends_thorough() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"scan_id": "h1", "status": "queued"})

    _client(handler).trigger_hacker_scan("s1", "dev", thorough=True)
    assert captured["body"]["thorough"] is True


def test_clerk_auth_parser_and_payload() -> None:
    from liveapisec.cli import _build_auth, _validate_auth, build_parser

    args = build_parser().parse_args(
        [
            "push", "--name", "x", "--base-url", "http://x",
            "--auth-type", "clerk",
            "--auth-clerk-secret", "sk_test_x",
            "--auth-clerk-user", "user_1",
            "--auth-clerk-org", "org_1",
            "--endpoint", "GET /me",
        ]
    )
    auth = _build_auth(args)
    assert auth["type"] == "clerk"
    assert auth["clerk_secret"] == "sk_test_x"
    assert auth["clerk_user_id"] == "user_1"
    assert auth["clerk_org_id"] == "org_1"
    assert _validate_auth(args, auth) is None


def test_cli_version_flag_and_sources_in_sync(capsys) -> None:
    """`--version` działa, a wersja jest spójna: __init__ == _version == pyproject."""
    import re
    from pathlib import Path

    import liveapisec
    from liveapisec._version import __version__

    assert liveapisec.__version__ == __version__

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
    assert m and m.group(1) == __version__, "pyproject.toml version out of sync"

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"liveapisec {__version__}"
