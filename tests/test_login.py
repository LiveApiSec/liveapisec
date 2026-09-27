"""Testy `liveapisec login` / `logout` / `whoami` (TODO 2.58) — bez sieci."""

from __future__ import annotations

import sys
from argparse import Namespace

import httpx

from liveapisec import cli
from liveapisec.client import LiveAPISec
from liveapisec.config import load_config, save_config

WHOAMI = {
    "organisation_id": "org_123",
    "organisation_name": "acme",
    "prefix": "las_dev_ab12",
    "scopes": ["projects:read", "projects:write", "scans:trigger"],
    "expires_at": "2026-11-01T00:00:00",
    "created_at": "2026-10-02T00:00:00",
    "last_used_at": None,
}


def _client(handler) -> LiveAPISec:
    return LiveAPISec(
        api_url="https://liveapisec.test",
        api_key="las_dev_test",
        transport=httpx.MockTransport(handler),
    )


def _whoami_transport(handler=None):
    def _h(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/developers/whoami":
            return httpx.Response(200, json=WHOAMI)
        return handler(request) if handler else httpx.Response(404)

    return _h


def test_login_with_token_validates_and_saves(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    client = _client(_whoami_transport())
    monkeypatch.setattr(cli, "LiveAPISec", lambda **kw: client)

    rc = cli._cmd_login(client, Namespace(token="las_dev_new", json=False, no_browser=True))
    assert rc == 0
    cfg = load_config()
    assert cfg["api_key"] == "las_dev_new"
    assert cfg["key_prefix"] == "las_dev_ab12"
    assert cfg["org_id"] == "org_123"
    assert cfg["scopes"] == "projects:read,projects:write,scans:trigger"


def test_login_with_bad_token_fails(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Unauthorized", "detail": "invalid"})

    client = _client(handler)
    monkeypatch.setattr(cli, "LiveAPISec", lambda **kw: client)
    rc = cli._cmd_login(client, Namespace(token="bad", json=False, no_browser=True))
    assert rc == 2
    assert load_config() == {}


def test_login_device_flow_polls_then_saves(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys, "stdin", type("S", (), {"isatty": lambda self: True})())
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    calls = {"token": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/developers/cli/device":
            return httpx.Response(
                200,
                json={
                    "device_code": "d" * 32,
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://liveapisec.test/cli/authorize",
                    "verification_uri_complete": "https://liveapisec.test/cli/authorize?code=WDJB-MJHT",
                    "expires_in": 600,
                    "interval": 5,
                },
            )
        if path == "/developers/cli/token":
            calls["token"] += 1
            if calls["token"] == 1:
                return httpx.Response(
                    400, json={"title": "authorization_pending", "detail": "wait"}
                )
            return httpx.Response(
                200,
                json={
                    "api_key": "las_dev_fromlogin",
                    "token_type": "Bearer",
                    "organisation_id": "org_123",
                    "prefix": "las_dev_ab12",
                    "scopes": ["projects:read"],
                    "expires_at": "2026-11-01T00:00:00",
                },
            )
        if path == "/developers/whoami":
            return httpx.Response(200, json=WHOAMI)
        return httpx.Response(404)

    client = _client(handler)
    monkeypatch.setattr(cli, "LiveAPISec", lambda **kw: client)
    rc = cli._cmd_login(client, Namespace(token=None, json=False, no_browser=True))
    assert rc == 0
    assert calls["token"] == 2  # pending → approved
    assert load_config()["api_key"] == "las_dev_fromlogin"


def test_login_refuses_in_ci(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("CI", "true")
    client = _client(_whoami_transport())
    rc = cli._cmd_login(client, Namespace(token=None, json=False, no_browser=True))
    assert rc == 2  # nie startuje device flow
    assert load_config() == {}


def test_logout_keeps_api_url(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    save_config({"api_key": "las_dev_x", "api_url": "https://api.example.com", "org_id": "o"})
    client = _client(_whoami_transport())
    rc = cli._cmd_logout(client, Namespace(json=False))
    assert rc == 0
    cfg = load_config()
    assert "api_key" not in cfg
    assert "org_id" not in cfg
    assert cfg["api_url"] == "https://api.example.com"


def test_whoami_json(monkeypatch, capsys) -> None:
    client = _client(_whoami_transport())
    rc = cli._cmd_whoami(client, Namespace(json=True))
    assert rc == 0
    out = capsys.readouterr().out
    assert '"organisation_name": "acme"' in out
