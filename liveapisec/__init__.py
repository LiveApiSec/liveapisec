"""liveapisec — official LiveAPISec Developer API client.

Install::

    pip install liveapisec

Then in any project/CI::

    export LIVEAPISEC_API_KEY=las_dev_...
    liveapisec push --name my-api --base-url https://api.example.com --endpoint "GET /users"
    liveapisec scan --project PROJECT_ID --wait --fail-on high
"""

from ._version import __version__
from .cli import main
from .client import (
    DEFAULT_API_URL,
    DEFAULT_FRONTEND_URL,
    LiveAPISecError,
    ScanStatus,
    severity_rank,
)
from .codegen import ScanResult, detect_framework, scan_code
from .config import clear_config, config_path, load_config, save_config

__all__ = [
    "DEFAULT_API_URL",
    "DEFAULT_FRONTEND_URL",
    "LiveAPISecError",
    "ScanResult",
    "ScanStatus",
    "__version__",
    "clear_config",
    "config_path",
    "detect_framework",
    "load_config",
    "main",
    "save_config",
    "scan_code",
    "severity_rank",
]
