"""Thin HTTP client for the LiveAPISec Developer API (TODO 2.25).

Wraps the /developers/* endpoints so they can be used from the console,
CI/CD and scripts — no curl, no dashboard.

Auth: `Authorization: Bearer <LIVEAPISEC_API_KEY>` (`las_dev_...` key
generated in Settings → Developer API). The developer token (JWT/cookie/API-key)
is sent in the payload and encrypted server-side (AES-256).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

DEFAULT_API_URL = "https://liveapisec.com"
ENV_API_URL = "LIVEAPISEC_API_URL"
ENV_API_KEY = "LIVEAPISEC_API_KEY"

# Severity order (most to least severe) for CI gates.
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def severity_rank(severity: str) -> int:
    """0 = critical (worst) … 4 = info. Unknown → 5 (below info)."""
    try:
        return _SEV_ORDER.index(severity)
    except ValueError:
        return len(_SEV_ORDER)


class LiveAPISecError(RuntimeError):
    """API error: HTTP status + title/detail (RFC 7807)."""

    def __init__(self, status: int | None, title: str, detail: str = "") -> None:
        super().__init__(f"{title}: {detail}".strip(" :"))
        self.status = status
        self.title = title
        self.detail = detail


class ScanStatus:
    """Scan statuses (as in the UI)."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def api_url_from_env() -> str:
    return os.environ.get(ENV_API_URL, DEFAULT_API_URL).rstrip("/")


class LiveAPISec:
    """Developer API client. `api_url`/`api_key` from env (LIVEAPISEC_API_URL/KEY)."""

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_url = (api_url or api_url_from_env()).rstrip("/")
        self.api_key = api_key or os.environ.get(ENV_API_KEY, "")
        self.timeout = timeout
        self._transport = transport

    # -- transport -----------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kw: Any) -> Any:
        if not self.api_key:
            raise LiveAPISecError(
                None,
                "Missing API key",
                f"set {ENV_API_KEY}=las_dev_... (Settings → Developer API) or pass --api-key",
            )
        url = f"{self.api_url}{path}"
        try:
            with httpx.Client(transport=self._transport) as client:
                resp = client.request(
                    method, url, headers=self._headers(), timeout=self.timeout, **kw
                )
        except httpx.HTTPError as exc:
            raise LiveAPISecError(None, "Connection error", str(exc)) from exc
        if resp.status_code >= 400:
            try:
                body = resp.json()
                title = body.get("title", "Error")
                detail = body.get("detail", resp.text[:300])
            except Exception:  # noqa: BLE001
                title, detail = "Error", resp.text[:300]
            raise LiveAPISecError(resp.status_code, title, detail)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    # -- keys / sites ---------------------------------------------------------
    def create_site(
        self,
        name: str,
        base_url: str,
        endpoints: list[dict[str, str]] | None = None,
        openapi_url: str | None = None,
        project: str | None = None,
        auth: dict[str, Any] | None = None,
        site_id: str | None = None,
    ) -> dict[str, Any]:
        """Push a site (idempotent by name+base_url). Without `site_id` → POST (create/update),
        with `site_id` → PUT (explicit update)."""
        payload: dict[str, Any] = {"name": name, "base_url": base_url}
        if endpoints:
            payload["endpoints"] = endpoints
        if openapi_url:
            payload["openapi_url"] = openapi_url
        if project:
            payload["project"] = project
        if auth:
            payload["auth"] = auth
        if site_id:
            return self._request("PUT", f"/developers/sites/{site_id}", json=payload)
        return self._request("POST", "/developers/sites", json=payload)

    def get_site(self, site_id: str) -> dict[str, Any]:
        return self._request("GET", f"/developers/sites/{site_id}")

    def list_sites(self) -> list[dict[str, Any]]:
        """All sites for the API key's org (CLI groups them by project)."""
        return self._request("GET", "/developers/sites")

    # -- scans ----------------------------------------------------------------
    def trigger_scan(
        self, site_id: str, branch: str | None = None, commit: str | None = None
    ) -> dict[str, Any]:
        """Trigger a scan (202). Returns {scan_id, status, branch, commit}."""
        payload: dict[str, Any] = {}
        if branch:
            payload["branch"] = branch
        if commit:
            payload["commit"] = commit
        return self._request("POST", f"/developers/sites/{site_id}/scans", json=payload)

    def list_scans(self, site_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/developers/sites/{site_id}/scans")

    def get_scan(self, site_id: str, scan_id: str) -> dict[str, Any] | None:
        """A single scan (via the list — no dedicated GET scan endpoint)."""
        for s in self.list_scans(site_id):
            if s.get("scan_id") == scan_id:
                return s
        return None

    def get_findings(self, site_id: str, scan_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/developers/sites/{site_id}/scans/{scan_id}/findings")

    # -- CI helpers ------------------------------------------------------------
    def wait_for_scan(
        self,
        site_id: str,
        scan_id: str,
        poll_interval: float = 3.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Poll until the scan finishes (completed/failed). Returns scan + findings."""
        deadline = time.monotonic() + timeout
        while True:
            scan = self.get_scan(site_id, scan_id)
            if scan is None:
                raise LiveAPISecError(None, "Scan not found", f"scan {scan_id} on site {site_id}")
            status = scan.get("status")
            if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                scan["findings"] = self.get_findings(site_id, scan_id)
                return scan
            if time.monotonic() > deadline:
                raise LiveAPISecError(
                    None, "Timeout", f"scan {scan_id} still {status!r} after {timeout:.0f}s"
                )
            time.sleep(poll_interval)

    @staticmethod
    def findings_above(findings: list[dict[str, Any]], min_severity: str) -> list[dict[str, Any]]:
        """Findings o severity >= min_severity (wg ranku: critical < high < ...)."""
        threshold = severity_rank(min_severity)
        return [f for f in findings if severity_rank(f.get("severity", "info")) <= threshold]

    @staticmethod
    def dump(data: Any) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
