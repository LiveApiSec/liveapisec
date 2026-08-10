"""Persistent CLI config — ~/.config/liveapisec/config.json.

Used to store the API key (and optional API URL) so a developer only has to
paste it once, on first run. The file is written with mode 0600.
"""

from __future__ import annotations

import json
import os

_CONFIG_FILENAME = "config.json"


def config_dir() -> str:
    """Config directory (override with $LIVEAPISEC_CONFIG_DIR or $XDG_CONFIG_HOME)."""
    override = os.environ.get("LIVEAPISEC_CONFIG_DIR")
    if override:
        return override
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "liveapisec")


def config_path() -> str:
    return os.path.join(config_dir(), _CONFIG_FILENAME)


def load_config() -> dict[str, str]:
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return {k: str(v) for k, v in data.items() if isinstance(v, str)}
    except (OSError, ValueError):
        return {}


def save_config(values: dict[str, str]) -> str:
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = load_config()
    data.update({k: v for k, v in values.items() if v})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def clear_config() -> str:
    path = config_path()
    if os.path.exists(path):
        os.remove(path)
    return path
