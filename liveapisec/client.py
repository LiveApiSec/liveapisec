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

DEFAULT_API_URL = "https://api.liveapisec.com"
# Dashboard / docs live on the main domain (Cloudflare Pages SPA). This is NOT the
# API host: POSTing to it returns 405 by design (static site), so never send API
# calls here.
DEFAULT_FRONTEND_URL = "https://liveapisec.com"
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

    def _request(self, method: str, path: str, timeout: float | None = None, **kw: Any) -> Any:
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
                    method,
                    url,
                    headers=self._headers(),
                    timeout=timeout or self.timeout,
                    **kw,
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

    # -- keys / projects (TODO 2.55: projekt = ApiSpec) ----------------------
    def create_project(
        self,
        name: str,
        base_url: str,
        endpoints: list[dict[str, str]] | None = None,
        openapi_url: str | None = None,
        spec: dict[str, Any] | None = None,
        auth: dict[str, Any] | None = None,
        project_id: str | None = None,
        schedule: str | None = None,
        access: str | None = None,
    ) -> dict[str, Any]:
        """Push a project (idempotent by name+base_url). Without `project_id` → POST
        (create/update), with `project_id` → PUT (explicit update).

        `spec` (TODO 2.50) sends the FULL OpenAPI document (parameters, requestBody,
        schemas, security) — used by `--spec-file` for localhost/private URLs.
        """
        payload: dict[str, Any] = {"name": name, "base_url": base_url}
        if spec is not None:
            payload["spec"] = spec
        if endpoints:
            payload["endpoints"] = endpoints
        if openapi_url:
            payload["openapi_url"] = openapi_url
        if auth:
            payload["auth"] = auth
        if schedule:
            payload["schedule"] = schedule
        if access:
            payload["access"] = access
        if project_id:
            return self._request("PUT", f"/developers/projects/{project_id}", json=payload)
        return self._request("POST", "/developers/projects", json=payload)

    def get_project(self, project_id: str) -> dict[str, Any]:
        return self._request("GET", f"/developers/projects/{project_id}")

    def list_projects(self) -> list[dict[str, Any]]:
        """All projects for the API key's org."""
        return self._request("GET", "/developers/projects")

    def get_certificate(self, scope: str = "org", project: str | None = None) -> dict[str, Any]:
        """Certificate / Trust Page in a chosen scope (org | project)."""
        params: dict[str, str] = {"scope": scope}
        if project:
            params["project"] = project
        return self._request("GET", "/developers/certificate", params=params)

    def set_project_certificate_url(
        self, project_id: str, environment: str | None
    ) -> dict[str, Any]:
        """TODO 2.50: choose which URL the PUBLIC project certificate concerns.

        `environment=None` = the project's default base_url. The selected URL is not
        shown on the public certificate/trust page.
        """
        return self._request(
            "PATCH", f"/developers/projects/{project_id}/certificate", json={"environment": environment}
        )

    # -- URLs / environments (TODO 2.50) -------------------------------------
    def list_environments(self, project_id: str) -> list[dict[str, Any]]:
        """All URLs of a project — the same endpoint set is tested against each."""
        return self._request("GET", f"/developers/projects/{project_id}/environments")

    def list_versions(self, project_id: str) -> list[dict[str, Any]]:
        """All spec versions of a project — to pin on a URL (`urls set --version`)."""
        return self._request("GET", f"/developers/projects/{project_id}/versions")

    def add_environment(
        self,
        project_id: str,
        name: str,
        base_url: str,
        version: str = "latest",
        schedule: str | None = None,
    ) -> dict[str, Any]:
        """Add a URL (environment) to a project."""
        payload: dict[str, Any] = {
            "name": name,
            "base_url": base_url,
            "version": version or "latest",
        }
        if schedule:
            payload["schedule"] = schedule
        return self._request("POST", f"/developers/projects/{project_id}/environments", json=payload)

    def update_environment(self, project_id: str, name: str, **fields: Any) -> dict[str, Any]:
        """Update a URL (base_url / version / schedule / paused)."""
        payload = {k: v for k, v in fields.items() if v is not None}
        return self._request(
            "PATCH", f"/developers/projects/{project_id}/environments/{name}", json=payload
        )

    def remove_environment(self, project_id: str, name: str) -> None:
        """Remove a URL from a project."""
        self._request("DELETE", f"/developers/projects/{project_id}/environments/{name}")

    # -- delete project (TODO 2.50/2.55) -------------------------------------
    def delete_project(self, project_id: str) -> None:
        """Delete a project and all its data (scans, findings, URLs, versions, cert)."""
        self._request("DELETE", f"/developers/projects/{project_id}")

    # -- credentials per-prefix (TODO 2.50) ----------------------------------
    def list_credentials(self, project_id: str) -> list[dict[str, Any]]:
        """Masked credentials of a project (slot, path_prefix, auth_method)."""
        return self._request("GET", f"/developers/projects/{project_id}/credentials")

    def set_credential(
        self, project_id: str, slot: str, auth: dict[str, Any], path_prefix: str | None = None
    ) -> dict[str, Any]:
        """Create/update a credential (optionally bound to a path prefix).

        `auth` is the same shape as `push --auth-*` ({"type": ..., ...}).
        """
        payload: dict[str, Any] = {"slot": slot, "auth": auth}
        if path_prefix is not None:
            payload["path_prefix"] = path_prefix
        return self._request(
            "POST", f"/developers/projects/{project_id}/credentials", json=payload
        )

    def remove_credential(self, project_id: str, slot: str) -> dict[str, Any]:
        """Remove a credential by slot (auth.type=none)."""
        return self._request(
            "POST",
            f"/developers/projects/{project_id}/credentials",
            json={"slot": slot, "auth": {"type": "none"}},
        )

    # -- scans ----------------------------------------------------------------
    def trigger_scan(
        self,
        project_id: str,
        branch: str | None = None,
        commit: str | None = None,
        tunnel: bool = False,
        auth_b: dict[str, Any] | None = None,
        environment: str | None = None,
    ) -> dict[str, Any]:
        """Trigger a scan (202). Returns {scan_id, status, branch, commit}.

        `tunnel=True` routes the scan's HTTP requests through a connected CLI
        (reverse tunnel) — for localhost/internal targets.
        `auth_b` is a second identity for the auth-matrix RBAC test, e.g.
        `{"auth_method": "bearer", "fields": {"token": "..."}}` — it is
        encrypted server-side and lives only on this scan's document.
        `environment` (TODO 2.50) is a URL name — the project's endpoint set is
        tested against that URL's base_url (see `environments` on the project).
        """
        payload: dict[str, Any] = {}
        if branch:
            payload["branch"] = branch
        if commit:
            payload["commit"] = commit
        if tunnel:
            payload["tunnel"] = True
        if auth_b:
            payload["auth_b"] = auth_b
        if environment:
            payload["environment"] = environment
        return self._request("POST", f"/developers/projects/{project_id}/scans", json=payload)

    # -- reverse tunnel (A): CLI as a proxy for internal/localhost tests ------
    def open_tunnel(self, project_id: str) -> dict[str, Any]:
        """Register a tunnel for a project (CLI then long-polls for requests)."""
        return self._request("POST", "/developers/tunnels", json={"project_id": project_id})

    def tunnel_next(self, tunnel_id: str, timeout: int = 25) -> dict[str, Any] | None:
        """Long-poll for the next request to execute locally (None = timeout)."""
        return self._request(
            "GET",
            f"/developers/tunnels/{tunnel_id}/next",
            params={"timeout": timeout},
            timeout=timeout + 15,
        )

    def tunnel_result(self, tunnel_id: str, result: dict[str, Any]) -> None:
        """Post the local execution result back to the waiting worker."""
        self._request("POST", f"/developers/tunnels/{tunnel_id}/result", json=result)

    def close_tunnel(self, tunnel_id: str) -> None:
        self._request("DELETE", f"/developers/tunnels/{tunnel_id}")

    # -- hacker mode (TODO 3.6 / 3.6.1) --------------------------------------
    def trigger_hacker_scan(
        self, project_id: str, environment: str, goal: str | None = None,
        tunnel: bool = False, destructive: bool = False,
        auth_b: dict[str, Any] | None = None, thorough: bool = False,
    ) -> dict[str, Any]:
        """Trigger an autonomous AI hacker-mode test (202) on a dev/staging env.

        Requires a verified domain for public targets; localhost / private IPs are
        exempt. Never runs on production. `goal` is an optional guided attack
        objective (TODO 3.6.2). `tunnel=True` routes requests through a connected
        CLI (reverse tunnel) — for localhost/internal targets. `destructive=False`
        (default) = READ-ONLY (only GET/HEAD/OPTIONS); `destructive=True` allows
        state-changing methods (TODO 2.50). Returns {scan_id, status, environment}.
        """
        payload: dict[str, Any] = {"environment": environment}
        if goal:
            payload["goal"] = goal
        if tunnel:
            payload["tunnel"] = True
        if destructive:
            payload["destructive"] = True
        if auth_b:
            payload["auth_b"] = auth_b
        if thorough:
            payload["thorough"] = True
        return self._request(
            "POST",
            f"/developers/projects/{project_id}/hacker-scans",
            json=payload,
        )

    def list_scans(self, project_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/developers/projects/{project_id}/scans")

    def get_scan(self, project_id: str, scan_id: str) -> dict[str, Any] | None:
        """A single scan (via the list — no dedicated GET scan endpoint)."""
        for s in self.list_scans(project_id):
            if s.get("scan_id") == scan_id:
                return s
        return None

    def get_findings(self, project_id: str, scan_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/developers/projects/{project_id}/scans/{scan_id}/findings")

    def get_verdict(
        self, project_id: str, scan_id: str, baseline_scan_id: str, fail_on: str = "high"
    ) -> dict[str, Any]:
        """CI verdict: new/fixed/persisting findings vs baseline + pass/fail."""
        return self._request(
            "GET",
            f"/developers/projects/{project_id}/scans/{scan_id}/verdict",
            params={"baseline_scan_id": baseline_scan_id, "fail_on": fail_on},
        )

    def get_compliance(self, project_id: str, scan_id: str) -> dict[str, Any]:
        """Compliance mapping (PCI DSS / SOC 2 / ISO 27001 / GDPR / NIS2, SaaS+)."""
        return self._request(
            "GET", f"/developers/projects/{project_id}/scans/{scan_id}/compliance"
        )

    def get_report(self, project_id: str, scan_id: str) -> dict[str, Any]:
        """Full saved scan report (raw results + summary)."""
        return self._request(
            "GET", f"/developers/projects/{project_id}/scans/{scan_id}/report"
        )

    def download_certificate_pdf(
        self, project_id: str, scan_id: str, variant: str = "full"
    ) -> tuple[bytes, str]:
        """Certificate PDF (only when the scan passed). Returns (bytes, filename)."""
        import httpx

        url = (
            f"{self.api_url}/developers/projects/{project_id}/scans/{scan_id}/"
            f"certificate.pdf?variant={variant}"
        )
        try:
            with httpx.Client(transport=self._transport) as client:
                resp = client.get(url, headers=self._headers(), timeout=self.timeout)
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
        filename = f"liveapisec-certificate-{variant}-{scan_id}.pdf"
        disp = resp.headers.get("content-disposition", "")
        if 'filename="' in disp:
            filename = disp.split('filename="', 1)[1].split('"', 1)[0] or filename
        return resp.content, filename

    # -- ask-mode (SEC-ASK-N): code-review questionnaire -----------------------
    def create_ask_session(self, project_id: str, include_ai: bool = True) -> dict[str, Any]:
        """New ask session: bank + AI questions tailored to the API.

        The server calls the LLM inline, so allow a long timeout (default 30s
        would abort while the session is still being generated).
        """
        return self._request(
            "POST",
            f"/developers/projects/{project_id}/ask-sessions",
            json={"include_ai": include_ai},
            timeout=240.0,
        )

    def list_ask_sessions(self, project_id: str) -> list[dict[str, Any]]:
        """Ask sessions of a project with answer aggregates."""
        return self._request("GET", f"/developers/projects/{project_id}/ask-sessions")

    def get_ask_session(self, session_id: str) -> dict[str, Any]:
        """Full session: questions with answers."""
        return self._request("GET", f"/developers/ask-sessions/{session_id}")

    def answer_ask_question(
        self, session_id: str, qid: str, verdict: str, note: str = ""
    ) -> dict[str, Any]:
        """Answer one question: verdict = pass | fail | na (+ developer note)."""
        return self._request(
            "POST",
            f"/developers/ask-sessions/{session_id}/answers",
            json={"qid": qid, "verdict": verdict, "note": note},
        )

    def ask_followups(
        self, session_id: str, rounds: int = 1, until_dry: bool = False
    ) -> dict[str, Any]:
        """Ask the LLM for extra questions based on the answers given so far.

        `rounds` = number of passes; `until_dry` = repeat until a pass adds nothing.
        LLM calls happen inline on the server → long timeout (scaled by rounds).
        """
        return self._request(
            "POST",
            f"/developers/ask-sessions/{session_id}/followups",
            params={"rounds": rounds, "until_dry": str(bool(until_dry)).lower()},
            timeout=240.0 * max(1, min(rounds, 5)),
        )

    # -- CI helpers ------------------------------------------------------------
    def wait_for_scan(
        self,
        project_id: str,
        scan_id: str,
        poll_interval: float = 3.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Poll until the scan finishes (completed/failed). Returns scan + findings."""
        deadline = time.monotonic() + timeout
        while True:
            scan = self.get_scan(project_id, scan_id)
            if scan is None:
                raise LiveAPISecError(None, "Scan not found", f"scan {scan_id} on project {project_id}")
            status = scan.get("status")
            if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                scan["findings"] = self.get_findings(project_id, scan_id)
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
