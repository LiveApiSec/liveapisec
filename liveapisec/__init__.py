"""liveapisec — oficjalny klient LiveAPISec Developer API.

Instalacja::

    pip install git+https://github.com/<owner>/<repo>.git#subdirectory=cli

Potem w dowolnym projekcie/CI::

    export LIVEAPISEC_API_KEY=las_dev_...
    liveapisec push --name my-api --base-url https://api.example.com --endpoint "GET /users"
    liveapisec scan --site SITE_ID --wait --fail-on high
"""

from .cli import main
from .client import (
    DEFAULT_API_URL,
    LiveAPISecError,
    ScanStatus,
    severity_rank,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_API_URL",
    "LiveAPISecError",
    "ScanStatus",
    "__version__",
    "main",
    "severity_rank",
]
