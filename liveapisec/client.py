"""Cienki klient HTTP dla LiveAPISec Developer API (TODO 2.25).

Wrapsuje endpointy /developers/* tak, żeby dało się ich używać z konsoli,
CI/CD i skryptów — bez curl i bez dashboardu.

Auth: `Authorization: Bearer <LIVEAPISEC_API_KEY>` (klucz `las_dev_...`
wygenerowany w Settings → Developer API). Token dewelopera (JWT/cookie/API-key)
jest wysyłany w payloadzie i szyfrowany po stronie serwera (AES-256).
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

# Kolejność istotności severity (do gate'ów w CI).
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def severity_rank(severity: str) -> int:
    """0 = critical (najgorzej) … 4 = info. Nieznane → 5 (poniżej info)."""
    try:
        return _SEV_ORDER.index(severity)
    except ValueError:
        return len(_SEV_ORDER)


class LiveAPISecError(RuntimeError):
    """Błąd API: status HTTP + title/detail (RFC 7807)."""

    def __init__(self, status: int | None, title: str, detail: str = "") -> None:
        super().__init__(f"{title}: {detail}".strip(" :"))
        self.status = status
        self.title = title
        self.detail = detail


class ScanStatus:
    """Statusy skanu (jak w UI)."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def api_url_from_env() -> str:
    return os.environ.get(ENV_API_URL, DEFAULT_API_URL).rstrip("/")


class LiveAPISec:
    """Klient Developer API. `api_url`/`api_key` z env (LIVEAPISEC_API_URL/KEY)."""

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_url = (api_url or api_url_from_env()).rstrip("/")
        self.api_key = api_key or os.environ.get(ENV_API_KEY, "")
        if not self.api_key:
            raise LiveAPISecError(
                None,
                "Missing API key",
                f"set {ENV_API_KEY}=las_dev_... (Settings → Developer API) or pass --api-key",
            )
        self.timeout = timeout
        self._transport = transport

    # -- transport -----------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kw: Any) -> Any:
        url = f"{self.api_url}{path}"
        try:
            with httpx.Client(transport=self._transport) as client:
                resp = client.request(method, url, headers=self._headers(), timeout=self.timeout, **kw)
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
        """Push site (idempotentny wg nazwy+base_url). Bez `site_id` → POST (create/update),
        z `site_id` → PUT (explicit update)."""
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

    # -- scans ----------------------------------------------------------------
    def trigger_scan(
        self, site_id: str, branch: str | None = None, commit: str | None = None
    ) -> dict[str, Any]:
        """Odpal skan (202). Zwraca {scan_id, status, branch, commit}."""
        payload: dict[str, Any] = {}
        if branch:
            payload["branch"] = branch
        if commit:
            payload["commit"] = commit
        return self._request("POST", f"/developers/sites/{site_id}/scans", json=payload)

    def list_scans(self, site_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/developers/sites/{site_id}/scans")

    def get_scan(self, site_id: str, scan_id: str) -> dict[str, Any] | None:
        """Pojedynczy skan (przez listę — brak dedykowanego GET scan)."""
        for s in self.list_scans(site_id):
            if s.get("scan_id") == scan_id:
                return s
        return None

    def get_findings(self, site_id: str, scan_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/developers/sites/{site_id}/scans/{scan_id}/findings")

    # -- helpers dla CI --------------------------------------------------------
    def wait_for_scan(
        self,
        site_id: str,
        scan_id: str,
        poll_interval: float = 3.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Polluj aż skan się zakończy (completed/failed). Zwraca skan + findings."""
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
