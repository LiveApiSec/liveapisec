"""Tests for persistent config + first-run API key prompt (TODO 2.25)."""

from __future__ import annotations

import json

import httpx
import pytest

from liveapisec.cli import _cmd_config, _needs_key, _prompt_for_key, main
from liveapisec.client import LiveAPISec, LiveAPISecError
from liveapisec.config import (
    clear_config,
    config_dir,
    config_path,
    load_config,
    save_config,
)


def _client(handler) -> LiveAPISec:
    return LiveAPISec(
        api_url="https://liveapisec.test",
        api_key="las_dev_test",
        transport=httpx.MockTransport(handler),
    )


# ---------------------------------------------------------------- config


def test_config_save_load_roundtrip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    path = save_config({"api_key": "las_dev_abc", "api_url": "https://api.example.com"})
    assert path == config_path()
    assert load_config() == {
        "api_key": "las_dev_abc",
        "api_url": "https://api.example.com",
    }
    # file written with restricted permissions
    mode = __import__("os").stat(path).st_mode & 0o777
    assert mode == 0o600


def test_config_clear(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    save_config({"api_key": "las_dev_abc"})
    clear_config()
    assert load_config() == {}


def test_config_missing_returns_empty(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path / "does-not-exist"))
    assert load_config() == {}


def test_config_ignores_non_string_values(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    import os

    os.makedirs(config_dir(), exist_ok=True)
    with open(config_path(), "w", encoding="utf-8") as fh:
        json.dump({"api_key": "las_dev_abc", "count": 42}, fh)
    assert load_config() == {"api_key": "las_dev_abc"}


# ---------------------------------------------------------------- prompt / config cmd


def test_prompt_for_key_shows_instructions(monkeypatch, capsys) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "las_dev_xyz")
    key = _prompt_for_key()
    out = capsys.readouterr().err
    assert key == "las_dev_xyz"
    assert "Settings → Developer API" in out
    assert "las_dev_..." in out


def test_prompt_for_key_empty_raises(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "   ")
    with pytest.raises(LiveAPISecError) as exc:
        _prompt_for_key()
    assert "Missing API key" in str(exc.value)


def test_needs_key_skips_config_and_dry_run() -> None:
    assert _needs_key(type("A", (), {"command": "config"})()) is False
    assert _needs_key(type("A", (), {"command": "push-code", "dry_run": True})()) is False
    assert _needs_key(type("A", (), {"command": "scan", "dry_run": False})()) is True


def test_config_cmd_shows_status(capsys) -> None:
    args = type("A", (), {"clear": False})()
    assert _cmd_config(_client(lambda r: httpx.Response(200, json={})), args) == 0
    out = capsys.readouterr().out
    assert "config:" in out
    assert "api_key:" in out
    assert "Settings → Developer API" in out


# ---------------------------------------------------------------- first-run via main


def test_main_uses_saved_config(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("LIVEAPISEC_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("LIVEAPISEC_API_KEY", raising=False)
    save_config({"api_key": "las_dev_saved", "api_url": "https://liveapisec.test"})

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"site_id": "65f1", "name": "x", "endpoints_count": 0})

    # patch the client constructor to inject the mock transport
    original = LiveAPISec.__init__

    def patched_init(self, api_url=None, api_key=None, timeout=30.0, transport=None):
        original(
            self,
            api_url=api_url,
            api_key=api_key,
            timeout=timeout,
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(LiveAPISec, "__init__", patched_init)
    code = main(["sites", "--site", "65f1"])
    assert code == 0
    assert captured["auth"] == "Bearer las_dev_saved"


def test_main_noninteractive_missing_key(monkeypatch, capsys) -> None:
    monkeypatch.delenv("LIVEAPISEC_API_KEY", raising=False)
    # stdin is not a TTY in tests, so no prompt — should error cleanly.
    code = main(["push", "--name", "x", "--base-url", "https://e.com", "--endpoint", "GET /x"])
    err = capsys.readouterr().err
    assert code == 2
    assert "Missing API key" in err
