"""liveapisec — CLI commands (TODO 2.25).

Commands:
  push      — create/update a site + endpoints + optional token (idempotent)
  scan-code — scan source code LOCALLY (nothing leaves your machine) and push endpoints
  scan      — run a scan; --wait waits for the result; --fail-on sets the CI gate
  hacker    — run an autonomous AI hacker-mode test (dev/staging only, localhost exempt)
  status    — site status / recent scans
  findings  — list findings (--json)
  sites     — show a site (endpoints, last_scan)
  certificate — certificate URL + embed snippet for your site
  connect   — reverse tunnel: act as a proxy for scans against localhost/internal

CI example (gate)::

    liveapisec push --name my-api --base-url https://api.example.com \\
        --endpoint "GET /users" --endpoint "POST /payments"
    liveapisec scan --site SITE_ID --branch main --commit "$SHA" --wait --fail-on high

Exit codes (for CI):
  0 — ok (no findings >= threshold)     1 — findings >= threshold (gate failed)
  2 — usage / API error
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from .client import (
    DEFAULT_API_URL,
    DEFAULT_FRONTEND_URL,
    ENV_API_KEY,
    ENV_API_URL,
    LiveAPISec,
    LiveAPISecError,
)
from .codegen import scan_code
from .config import clear_config, config_path, load_config, save_config

_SEV = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Terminal UI — Claude Code-style layout. Auto-disabled when stdout is not a
# TTY (CI, pipes) or when $NO_COLOR is set; force with $FORCE_COLOR=1.
# ---------------------------------------------------------------------------
def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(sys.stdout.isatty())


_C = _color_enabled()


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _C else text


def _green(s: str) -> str:
    return _paint("32", s)


def _red(s: str) -> str:
    return _paint("31", s)


def _yellow(s: str) -> str:
    return _paint("33", s)


def _cyan(s: str) -> str:
    return _paint("36", s)


def _magenta(s: str) -> str:
    return _paint("35", s)


def _bold(s: str) -> str:
    return _paint("1", s)


def _dim(s: str) -> str:
    return _paint("2", s)


# Claude Code-style glyphs.
_OK = _green("✓")
_BAD = _red("✗")
_WARN = _yellow("⚠")
_ARROW = _cyan("→")


def _severe(sev: str) -> str:
    colors = {
        "critical": _red,
        "high": _red,
        "medium": _yellow,
        "low": _cyan,
        "info": _dim,
    }
    return colors.get(sev, _dim)(sev.upper())


def _scan_status(status: str) -> str:
    if status == "completed":
        return _green(status)
    if status == "failed":
        return _red(status)
    if status in ("queued", "running"):
        return _yellow(status)
    return _dim(status or "?")


def _print_endpoints(endpoints: list[dict[str, str]], limit: int = 25) -> None:
    """Print endpoints aligned; summarize huge lists (performance / readability)."""
    shown = endpoints[:limit]
    for e in shown:
        print(f"  {_cyan(e['method']):7} {e['path']}")
    if len(endpoints) > limit:
        print(_dim(f"  …and {len(endpoints) - limit} more endpoint(s) (use --json for all)"))


def _scan_targets_note(count: int) -> None:
    """Transparent note when pushing more targets than a single scan will test."""
    if count > 25:
        print(
            _dim(
                "  note: a single scan runs up to 25 targets (server SCANNER_MAX_TARGETS) — "
                "raise it for bigger APIs."
            ),
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Interactive pickers — when --project / --site are not given and stdin is a TTY:
# show the projects/sites available for the API key and let the user pick one
# or create a new one (Claude Code-style menus).
# ---------------------------------------------------------------------------
def _input_line(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _group_projects(sites: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for s in sites:
        groups.setdefault(s.get("project") or "(no project)", []).append(s)
    return sorted(groups.items())


def _pick_project(sites: list[dict[str, Any]]) -> str | None:
    """Interactive menu: pick an existing project or type a new one."""
    groups = _group_projects(sites)
    print(_cyan("No --project given. Pick a project (or create a new one):"))
    for i, (name, items) in enumerate(groups, 1):
        print(f"  {_bold(str(i))}) {name}  {_dim(f'({len(items)} site(s))')}")
    new_idx = len(groups) + 1
    print(f"  {_bold(str(new_idx))}) {_green('create new project')}")
    choice = _input_line("Enter number or project name: ")
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(groups):
            return groups[idx - 1][0]
        if idx == new_idx:
            name = _input_line("New project name: ")
            return name or None
        return None
    if choice:
        return choice
    return None


def _pick_site(sites: list[dict[str, Any]], project: str) -> dict[str, Any] | None:
    """Interactive menu: pick an existing site in the project or add a new URL.
    Returns the chosen site dict, or None = add a new URL."""
    mine = [s for s in sites if (s.get("project") or "(no project)") == project]
    print(_cyan(f"Now pick a site/URL in '{project}' (or add a new one):"))
    for i, s in enumerate(mine, 1):
        print(f"  {_bold(str(i))}) {s.get('name') or '?'}  {_dim(s.get('base_url') or '')}")
    new_idx = len(mine) + 1
    print(f"  {_bold(str(new_idx))}) {_green('add new URL/site')}")
    choice = _input_line("Enter number: ")
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(mine):
            return mine[idx - 1]
    return None


def _parse_endpoint(value: str) -> dict[str, str]:
    """'GET /users' → {"method":"GET","path":"/users"}."""
    parts = value.split(None, 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"expected 'METHOD /path', got {value!r}")
    method, path = parts
    return {"method": method.upper(), "path": path}


def _auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth-type",
        choices=["none", "jwt", "bearer", "cookie", "api_key", "oauth2", "login", "clerk"],
        default="none",
    )
    parser.add_argument("--auth-token", help="token for jwt/bearer/api_key")
    parser.add_argument("--auth-cookie", help="full Cookie header for type=cookie")
    parser.add_argument("--auth-header", default="X-API-Key", help="header name for api_key")
    parser.add_argument(
        "--auth-token-url", help="token endpoint for type=oauth2 (client_credentials)"
    )
    parser.add_argument("--auth-client-id", help="OAuth2 client_id for type=oauth2")
    parser.add_argument("--auth-client-secret", help="OAuth2 client_secret for type=oauth2")
    # TODO 2.50: login username/password → token (krótkotrwałe JWT).
    parser.add_argument("--auth-login-url", help="login endpoint for type=login")
    parser.add_argument("--auth-username", help="username/email for type=login")
    parser.add_argument("--auth-password", help="password for type=login")
    parser.add_argument(
        "--auth-token-field", default=None, help="token path in login response (default access_token)"
    )
    parser.add_argument(
        "--auth-username-field", default=None, help="body field for username (default email)"
    )
    parser.add_argument(
        "--auth-password-field", default=None, help="body field for password (default password)"
    )
    parser.add_argument(
        "--auth-body", choices=["json", "form"], default=None, help="login body format (default json)"
    )
    # TODO 2.50: Clerk (test-instancja) — świeży session-JWT per skan.
    parser.add_argument("--auth-clerk-secret", help="Clerk Backend API secret (sk_test_...) for type=clerk")
    parser.add_argument("--auth-clerk-user", help="Clerk user_id (user_...) for type=clerk")
    parser.add_argument("--auth-clerk-org", help="optional Clerk org_id (active_organization_id) for type=clerk")


def _build_auth(args: argparse.Namespace) -> dict[str, Any] | None:
    if args.auth_type == "none":
        return None
    auth: dict[str, Any] = {"type": args.auth_type}
    if args.auth_type in ("jwt", "bearer", "api_key"):
        auth["token"] = args.auth_token
    if args.auth_type == "cookie":
        auth["cookie"] = args.auth_cookie
    if args.auth_type == "api_key":
        auth["header"] = args.auth_header
    if args.auth_type == "oauth2":
        auth["token_url"] = args.auth_token_url
        auth["client_id"] = args.auth_client_id
        auth["client_secret"] = args.auth_client_secret
    if args.auth_type == "login":
        auth["login_url"] = args.auth_login_url
        auth["username"] = args.auth_username
        auth["password"] = args.auth_password
        for key, val in (
            ("token_field", getattr(args, "auth_token_field", None)),
            ("username_field", getattr(args, "auth_username_field", None)),
            ("password_field", getattr(args, "auth_password_field", None)),
            ("body", getattr(args, "auth_body", None)),
        ):
            if val:
                auth[key] = val
    if args.auth_type == "clerk":
        auth["clerk_secret"] = args.auth_clerk_secret
        auth["clerk_user_id"] = args.auth_clerk_user
        if getattr(args, "auth_clerk_org", None):
            auth["clerk_org_id"] = args.auth_clerk_org
    return auth


def _validate_auth(args: argparse.Namespace, auth: dict[str, Any] | None) -> str | None:
    """Return an error message for an invalid auth config, else None."""
    if not auth:
        return None
    t = args.auth_type
    if t in ("jwt", "bearer", "api_key") and not args.auth_token:
        return f"--auth-token required for auth-type={t}"
    if t == "cookie" and not args.auth_cookie:
        return "--auth-cookie required for auth-type=cookie"
    if t == "oauth2" and not (
        args.auth_token_url and args.auth_client_id and args.auth_client_secret
    ):
        return "--auth-token-url, --auth-client-id and --auth-client-secret required for auth-type=oauth2"
    if t == "login" and not (
        getattr(args, "auth_login_url", None)
        and getattr(args, "auth_username", None)
        and getattr(args, "auth_password", None)
    ):
        return "--auth-login-url, --auth-username and --auth-password required for auth-type=login"
    if t == "clerk" and not (
        getattr(args, "auth_clerk_secret", None) and getattr(args, "auth_clerk_user", None)
    ):
        return "--auth-clerk-secret and --auth-clerk-user required for auth-type=clerk"
    return None


def _fetch_oauth2_token_cli(auth: dict[str, Any]) -> str:
    """Fetch a fresh access_token for OAuth2 client_credentials (CLI-side verify)."""
    import httpx

    resp = httpx.request(
        "POST",
        auth["token_url"],
        data={
            "grant_type": "client_credentials",
            "client_id": auth.get("client_id", ""),
            "client_secret": auth.get("client_secret", ""),
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise RuntimeError("no access_token in response")
    return token


def _verify_target(
    base_url: str, endpoints: list[dict[str, str]], auth: dict[str, Any] | None
) -> int:
    """Pre-flight check of the first endpoint with the pushed auth (--verify).

    Returns exit code: 0 = ok, 2 = auth-level failure (bad token / fetch error).
    Network errors are informational (our scanner may reach APIs the dev box can't).
    """
    import httpx

    if not endpoints:
        print("  verify: no endpoints to probe", file=sys.stderr)
        return 0
    first = endpoints[0]
    url = base_url.rstrip("/") + first["path"]
    headers: dict[str, str] = {}
    at = (auth or {}).get("type")
    try:
        if at == "bearer":
            headers["Authorization"] = f"Bearer {auth.get('token', '')}"
        elif at == "api_key":
            headers[auth.get("header") or "X-API-Key"] = auth.get("token", "")
        elif at == "cookie":
            headers["Cookie"] = auth.get("cookie", "")
        elif at == "oauth2":
            headers["Authorization"] = f"Bearer {_fetch_oauth2_token_cli(auth)}"
    except Exception as exc:  # noqa: BLE001
        print(f"  verify: could not build auth ({at}): {exc}", file=sys.stderr)
        return 2
    try:
        resp = httpx.request(
            first["method"], url, headers=headers, timeout=10.0, follow_redirects=True
        )
    except httpx.HTTPError as exc:
        print(
            f"  verify: cannot reach {url} from here ({exc}) — that's OK if the API is only reachable from our scanner, but check the token/scopes",
            file=sys.stderr,
        )
        return 0
    status = resp.status_code
    if 200 <= status < 400:
        print(f"  verify: {first['method']} {url} → {status} ✓")
        return 0
    if status in (401, 403):
        print(
            f"  verify: {first['method']} {url} → {status} ✗ auth failed — token expired, wrong scope or wrong header",
            file=sys.stderr,
        )
        return 2
    print(
        f"  verify: {first['method']} {url} → {status} (reachable, unexpected status)",
        file=sys.stderr,
    )
    return 0


def _fmt_scan(scan: dict[str, Any]) -> str:
    status = scan.get("status", "?")
    summary = scan.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    parts = [
        f"scan {scan.get('scan_id')}",
        f"status={status}",
    ]
    if scan.get("branch"):
        parts.append(f"branch={scan['branch']}")
    if scan.get("commit"):
        parts.append(f"commit={scan['commit']}")
    if status == "completed":
        sev = " ".join(
            f"{k}={v}"
            for k, v in sorted(
                by_sev.items(), key=lambda kv: _SEV.index(kv[0]) if kv[0] in _SEV else 9
            )
        )
        # TODO 2.50: hacker mode nie ma `tests_run` — pokaż requests/steps/risk.
        if scan.get("mode") == "hacker":
            parts.append(f"requests={summary.get('requests', '?')}")
            parts.append(f"steps={summary.get('steps', '?')}")
            if summary.get("risk_level"):
                parts.append(f"risk={str(summary['risk_level']).upper()}")
        else:
            parts.append(f"tests={summary.get('tests_run', '?')}")
        parts.append(f"findings={summary.get('findings', 0)}" + (f" ({sev})" if sev else ""))
    return " ".join(parts)


def _fmt_finding(f: dict[str, Any]) -> str:
    sev = f.get("severity", "?")
    title = f.get("title") or f.get("category") or "?"
    target = f.get("target") or ""
    line = f"[{_severe(sev)}] {title}"
    if target:
        line += _dim(f"  ({target})")
    return line


def _load_spec_file(path: str) -> dict:
    """Wczytaj lokalny OpenAPI (JSON/YAML) jako PEŁNY dict (TODO 2.50).

    Zachowuje parametry, requestBody, schematy i security. Serwer nic nie
    pobiera (brak SSRF) — wysyłamy cały spec w polu `spec`.
    """
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise LiveAPISecError("Spec file error", f"cannot read {path}: {exc}") from exc
    try:
        spec = json.loads(text)
    except ValueError:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise LiveAPISecError(
                "Spec file error",
                f"{path} is not JSON — install pyyaml for YAML specs",
            ) from exc
        try:
            spec = yaml.safe_load(text)
        except Exception as exc:
            raise LiveAPISecError("Spec file error", f"cannot parse {path}: {exc}") from exc
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise LiveAPISecError("Spec file error", f"{path} has no OpenAPI 'paths' object")
    return spec


def _endpoints_from_spec_file(path: str) -> list[dict[str, str]]:
    """Parsuj lokalny OpenAPI (JSON/YAML) na listę {method, path}.

    (Kompatybilność — `push` wysyła teraz cały spec; to zostaje dla narzędzi,
    które potrzebują tylko listy endpointów.)
    """
    spec = _load_spec_file(path)
    methods = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
    out = []
    for route, ops in spec["paths"].items():
        if not isinstance(ops, dict):
            continue
        for method in ops:
            if str(method).upper() in methods:
                out.append(_parse_endpoint(f"{str(method).upper()} {route}"))
    if not out:
        raise LiveAPISecError("Spec file error", f"no operations found in {path}")
    return out


def _cmd_push(client: LiveAPISec, args: argparse.Namespace) -> int:
    interactive = sys.stdin.isatty() and not args.json and not args.verify
    sites: list[dict[str, Any]] = []
    if interactive and (not args.project or not args.site):
        try:
            sites = client.list_sites()
        except LiveAPISecError:
            sites = []

    # --- project -----------------------------------------------------------
    project = args.project
    if not project and interactive:
        project = _pick_project(sites)
        if not project:
            print("error: no project chosen", file=sys.stderr)
            return 2

    # --- site / URL ----------------------------------------------------------
    site_id = args.site
    site_name = args.name
    site_base = args.base_url
    if not site_id and interactive:
        existing = _pick_site(sites, project) if project else None
        if existing:
            site_id = existing.get("site_id")
            site_name = existing.get("name") or site_name
            site_base = existing.get("base_url") or site_base
            print(_dim(f"→ updating existing site {existing.get('name') or site_id}"))
        else:
            if not site_name:
                site_name = _input_line("Site name: ")
            if not site_base:
                site_base = _input_line("Base URL (https://...): ")

    if not site_name and not site_id:
        print("error: --name is required", file=sys.stderr)
        return 2
    if not site_base and not site_id:
        print("error: --base-url is required", file=sys.stderr)
        return 2
    if getattr(args, "spec_file", None):
        try:
            spec_payload = _load_spec_file(args.spec_file)
        except LiveAPISecError as exc:
            print(f"error: {exc.title}: {exc.detail}", file=sys.stderr)
            return 2
    else:
        spec_payload = None
    if not args.endpoint and not args.openapi_url and spec_payload is None:
        print("error: provide at least one --endpoint, --spec-file or --openapi-url", file=sys.stderr)
        return 2
    auth = _build_auth(args)
    err = _validate_auth(args, auth)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    site = client.create_site(
        name=site_name,
        base_url=site_base,
        endpoints=args.endpoint,
        openapi_url=args.openapi_url,
        spec=spec_payload,
        project=project,
        auth=auth,
        site_id=site_id,
        schedule=getattr(args, "schedule", None),
        access=getattr(args, "access", None),
    )
    if args.json:
        print(LiveAPISec.dump(site))
    else:
        updated = " (updated)" if site.get("updated") else ""
        print(
            _green(
                f"{_OK} site {site['site_id']}{updated}: {site['name']} — {site['endpoints_count']} endpoints, auth={site['auth']}"
            )
        )
        print(_dim(f"  export SITE_ID={site['site_id']}"))
        _scan_targets_note(len(args.endpoint or []))
    if args.verify and not args.json:
        return _verify_target(site_base, args.endpoint or [], auth)
    return 0


def _clone_repo(url: str) -> str:
    """Shallow-clone a git repo (https/ssh/local) into a temp dir and return its path."""
    import shutil
    import subprocess
    import tempfile

    if shutil.which("git") is None:
        raise LiveAPISecError(None, "git is required", "install git to use --repo")
    tmp = tempfile.mkdtemp(prefix="liveapisec-repo-")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, tmp],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise LiveAPISecError(None, "Clone timed out", url) from exc
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise LiveAPISecError(
            None, "Could not clone repository", (proc.stderr or proc.stdout or "").strip()[:300]
        )
    return tmp


def _cmd_scan_code(client: LiveAPISec, args: argparse.Namespace) -> int:
    root = args.dir or "."
    tmp: str | None = None
    if args.repo:
        try:
            tmp = _clone_repo(args.repo)
        except LiveAPISecError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        root = tmp
    try:
        result = scan_code(root, framework=args.framework)
    finally:
        if tmp:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)
    endpoints = result.endpoints
    if not endpoints:
        fw = (
            f" (framework: {result.framework})"
            if result.framework
            else " — could not detect a supported framework (fastapi/flask/django/nextjs/nestjs/express/laravel/php/spring/go/rust)"
        )
        print(f"error: no endpoints found in {root}{fw}", file=sys.stderr)
        return 2

    if args.dry_run:
        if args.json:
            print(
                LiveAPISec.dump(
                    {
                        "framework": result.framework,
                        "files": result.files_scanned,
                        "endpoints": endpoints,
                    }
                )
            )
        else:
            fw = result.framework or "?"
            print(f"{_ARROW} {_bold(fw)} ({_dim(str(result.files_scanned) + ' files scanned')})")
            print(_yellow(f"found {len(endpoints)} endpoints (dry-run — not pushed):"))
            _print_endpoints(endpoints)
        return 0

    if not args.json:
        fw = result.framework or "?"
        print(f"{_ARROW} {_bold(fw)} ({_dim(str(result.files_scanned) + ' files scanned')})")
        print(f"found {len(endpoints)} endpoints:")
        _print_endpoints(endpoints)

    # --- interactive: resolve project + site/URL when flags are missing --------
    interactive = sys.stdin.isatty() and not args.json and not args.verify
    sites: list[dict[str, Any]] = []
    if interactive and (not args.project or not args.site):
        try:
            sites = client.list_sites()
        except LiveAPISecError:
            sites = []

    project = args.project
    if not project and interactive:
        project = _pick_project(sites)
        if not project:
            print("error: no project chosen", file=sys.stderr)
            return 2

    site_id = args.site
    site_name = args.name
    site_base = args.base_url
    if not site_id and interactive:
        existing = _pick_site(sites, project) if project else None
        if existing:
            site_id = existing.get("site_id")
            site_name = existing.get("name") or site_name
            site_base = existing.get("base_url") or site_base
            print(_dim(f"→ updating existing site {existing.get('name') or site_id}"))
        else:
            if not site_name:
                site_name = _input_line("Site name: ")
            if not site_base:
                site_base = _input_line("Base URL (https://...): ")

    if not site_name and not site_id:
        print("error: --name is required", file=sys.stderr)
        return 2
    if not site_base and not site_id:
        print("error: --base-url is required", file=sys.stderr)
        return 2

    auth = _build_auth(args)
    err = _validate_auth(args, auth)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    push_endpoints = [{"method": e["method"], "path": e["path"]} for e in endpoints]
    site = client.create_site(
        name=site_name,
        base_url=site_base,
        endpoints=push_endpoints,
        project=project,
        auth=auth,
        site_id=site_id,
        schedule=getattr(args, "schedule", None),
        access=getattr(args, "access", None),
    )
    if args.json:
        print(LiveAPISec.dump(site))
    else:
        updated = " (updated)" if site.get("updated") else ""
        print(
            _green(
                f"{_OK} site {site['site_id']}{updated}: {site['name']} — {site['endpoints_count']} endpoints, auth={site['auth']}"
            )
        )
        print(_dim(f"  export SITE_ID={site['site_id']}"))
        _scan_targets_note(len(endpoints))
    if args.verify and not args.json:
        return _verify_target(site_base, push_endpoints, auth)
    return 0


# Backwards-compat alias — the command used to be called `push-code`.
_cmd_push_code = _cmd_scan_code


def _auth_b_payload(args: argparse.Namespace) -> dict[str, Any] | None:
    """Second identity for the auth-matrix RBAC test (None = matrix off)."""
    token_b = getattr(args, "auth_token_b", None)
    if not token_b:
        return None
    method_b = (getattr(args, "auth_type_b", None) or "bearer").lower()
    if method_b not in ("bearer", "api_key", "basic", "cookie"):
        print("error: --auth-type-b must be bearer, api_key, basic or cookie", file=sys.stderr)
        raise SystemExit(2)
    if method_b == "api_key":
        fields: dict[str, str] = {"api_key": token_b}
    elif method_b == "basic":
        user, _, pwd = token_b.partition(":")
        fields = {"username": user, "password": pwd}
    elif method_b == "cookie":
        fields = {"cookie": token_b}
    else:
        fields = {"token": token_b}
    return {"auth_method": method_b, "fields": fields}


def _auth_b_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth-type-b",
        choices=["bearer", "api_key", "basic", "cookie"],
        default="bearer",
        help="second identity type for the auth-matrix RBAC test",
    )
    parser.add_argument(
        "--auth-token-b",
        default=None,
        help="second identity secret (e.g. another user's JWT) — enables the auth-matrix RBAC test",
    )


def _print_scan_summary(scan: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Krótkie podsumowanie po skanie (TODO 2.50): ryzyko, pokrycie, punkty do poprawy.

    Drukowane na końcu `scan --wait` (obok pełnego raportu z `report`/`all`).
    """
    summary = scan.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    tested, absent = summary.get("tested"), summary.get("absent")
    bits = [f"risk={_md_risk(by_sev)}"]
    if tested is not None:
        cov = f"coverage={tested} tested"
        if absent:
            cov += f", {absent} not deployed"
        bits.append(cov)
    print(_dim("  " + "  ·  ".join(bits)))
    if not findings:
        print(_green("  no findings — nothing to improve"))
        return
    order = {s: i for i, s in enumerate(_SEV)}
    ordered = sorted(
        findings, key=lambda f: order.get(str(f.get("severity", "info")).lower(), 99)
    )
    print("  points to improve:")
    for f in ordered[:10]:
        sev = str(f.get("severity", "info")).upper()
        target = f.get("target")
        print(f"    - [{sev}] {f.get('title')}" + (f"  ({target})" if target else ""))
        fix = _finding_fix(f)
        if fix:
            print(_dim(f"        fix: {fix[:160]}"))
    if len(ordered) > 10:
        print(_dim(f"    …and {len(ordered) - 10} more — see `liveapisec report`"))


def _cmd_scan(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    scan = client.trigger_scan(
        args.site,
        branch=args.branch,
        commit=args.commit,
        tunnel=getattr(args, "tunnel", False),
        auth_b=_auth_b_payload(args),
        environment=getattr(args, "url", None),
    )
    scan_id = scan["scan_id"]
    if args.json:
        print(LiveAPISec.dump(scan))
    else:
        target = getattr(args, "url", None)
        print(f"scan queued: {scan_id}" + (f" (url={target})" if target else ""))
    if not args.json and getattr(args, "auth_token_b", None):
        print(_dim("auth-matrix RBAC test enabled (second identity)"))
    if not args.wait:
        return 0

    if not args.json:
        print("waiting for scan to finish…", file=sys.stderr)
    done = client.wait_for_scan(args.site, scan_id)
    findings = done.get("findings") or []
    if args.json:
        print(LiveAPISec.dump(done))
    else:
        print(_fmt_scan(done))
        # TODO 2.50: automatyczne, krótkie podsumowanie po zakończonym skanie.
        if done.get("status") == "completed":
            _print_scan_summary(done, findings)

    if done.get("status") != "completed":
        return 2 if args.fail_on else 0

    gate_sev = args.fail_on  # "high" | "critical" | ...
    if gate_sev:
        blocked = LiveAPISec.findings_above(findings, gate_sev)
        if blocked:
            if not args.json:
                print(
                    _red(
                        f"\n{_BAD} {len(blocked)} finding(s) at or above {gate_sev} — gate failed:"
                    ),
                    file=sys.stderr,
                )
                for f in blocked:
                    print("  " + _fmt_finding(f), file=sys.stderr)
            return 1
        if not args.json:
            print(_green(f"{_OK} no findings at or above {gate_sev}"))
    return 0


# Nagłówki hop-by-hop — nie przekazujemy ich do lokalnego requestu.
_HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
}


def _cmd_connect(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Reverse tunnel: CLI wykonuje requesty skanu lokalnie (localhost/wewnętrzne).

    Rejestruje tunel dla site'u i długo-polluje po requesty; każdy wykonuje
    lokalnie (tylko host z base_url) i odsyła wynik. Ctrl+C zamyka tunel.
    W innym terminalu: `liveapisec scan --site <id> --tunnel`.
    """
    import base64

    import httpx

    opening = client.open_tunnel(args.site)
    tunnel_id = opening["tunnel_id"]
    base = opening.get("base_url")
    allowed_host = httpx.URL(base).host if base else None
    print(_green(f"{_OK} tunnel open for site {args.site}") + (f"  → {base}" if base else ""))
    print(_dim(f"  tunnel_id: {tunnel_id}"))
    if allowed_host:
        print(_dim(f"  forwarding only to host: {allowed_host}"))
    print(_dim("waiting for scan requests… (Ctrl+C to stop)"), file=sys.stderr)

    poll = int(getattr(args, "poll_timeout", 25) or 25)
    try:
        with httpx.Client(follow_redirects=False, timeout=30.0) as hc:
            while True:
                req = client.tunnel_next(tunnel_id, timeout=poll)
                if not req:
                    continue
                rid = req.get("request_id")
                url = req.get("url") or ""
                try:
                    hu = httpx.URL(url)
                    if allowed_host and hu.host != allowed_host:
                        raise RuntimeError(f"refusing host {hu.host!r} (only {allowed_host!r})")
                    body = base64.b64decode(req.get("body") or "")
                    headers = {
                        k: v
                        for k, v in (req.get("headers") or {}).items()
                        if k.lower() not in _HOP_HEADERS
                    }
                    resp = hc.request(
                        req.get("method", "GET"), url, headers=headers, content=body
                    )
                    result: dict = {
                        "request_id": rid,
                        "status": resp.status_code,
                        "headers": dict(resp.headers),
                        "body": base64.b64encode(resp.content).decode("ascii"),
                    }
                except Exception as exc:  # noqa: BLE001 — błąd po stronie CLI
                    result = {"request_id": rid, "error": str(exc)}
                client.tunnel_result(tunnel_id, result)
    except KeyboardInterrupt:  # Ctrl+C to oczekiwany sposób zamknięcia tunelu
        pass
    finally:
        try:
            client.close_tunnel(tunnel_id)
        except Exception:  # noqa: BLE001, S110 — sprzątanie nie rwie wyjścia
            pass
        print("\ntunnel closed", file=sys.stderr)
    return 0


def _print_hacker_summary(scan: dict[str, Any]) -> None:
    """Krótkie podsumowanie hacker-mode (TODO 2.50): risk, plan, proces, rekomendacje."""
    sm = scan.get("summary") or {}
    risk = str(sm.get("risk_level") or "?").upper()
    print(
        _dim(
            f"  risk={risk}  ·  requests={sm.get('requests', '?')}  ·  "
            f"steps={sm.get('steps', '?')}"
        )
    )
    plan = sm.get("plan") or []
    if plan:
        print("  attack plan:")
        for i, p in enumerate(plan, 1):
            print(f"    {i}. {p}")
    if len(sm.get("plan_log") or []) > 1:
        print(_dim(f"    (plan revised {len(sm['plan_log']) - 1}×)"))
    process = sm.get("process")
    if process:
        print(f"  process: {str(process)[:400]}")
    recs = sm.get("recommendations") or []
    if recs:
        print("  recommendations:")
        for r in recs[:6]:
            print(f"    - {r}")
    findings = scan.get("findings") or []
    if findings:
        print("  findings:")
        for f in findings[:10]:
            print(f"    - [{str(f.get('severity', '?')).upper()}] {f.get('title')}")
    else:
        print(_green("  no findings — the agent found no exploitable issue within its scope"))


def _cmd_hacker(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Run an autonomous AI hacker-mode test (TODO 3.6.1).

    Destructive authorized test — dev/staging ONLY, never production. Public
    targets need a verified domain; localhost / private IPs are exempt.
    """
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    if not args.env:
        print(
            "error: --env (environment name, e.g. development) is required", file=sys.stderr
        )
        return 2
    scan = client.trigger_hacker_scan(
        args.site, args.env, goal=args.goal, tunnel=getattr(args, "tunnel", False),
        destructive=getattr(args, "destructive", False),
        auth_b=_auth_b_payload(args),
        thorough=getattr(args, "thorough", False),
    )
    scan_id = scan["scan_id"]
    if args.json:
        print(LiveAPISec.dump(scan))
    else:
        print(
            _WARN
            + _yellow(
                " hacker mode is a DESTRUCTIVE authorized AI test — "
                "dev/staging only, never production (it can break/destroy a system)."
            )
        )
        print(f"hacker scan queued: {scan_id} (env={args.env})")
        if args.goal:
            print(f"goal: {args.goal}")
    if not args.wait:
        return 0

    if not args.json:
        print("waiting for the AI agent to finish…", file=sys.stderr)
    done = client.wait_for_scan(args.site, scan_id)
    if args.json:
        print(LiveAPISec.dump(done))
    else:
        print(_fmt_scan(done))
        # TODO 2.50: auto-podsumowanie hacker-mode (plan/risk/rekomendacje).
        if done.get("status") == "completed":
            _print_hacker_summary(done)
    return 0 if done.get("status") == "completed" else 2


def _cmd_status(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    site = client.get_site(args.site)
    scans = client.list_scans(args.site)
    if args.json:
        print(LiveAPISec.dump({"site": site, "scans": scans[:10]}))
        return 0
    print(f"site {site['site_id']}: {site.get('name')} — {site.get('endpoints_count')} endpoints")
    if site.get("base_url"):
        print(f"  base_url: {site['base_url']}")
    if site.get("project"):
        print(f"  project: {site['project']}")
    if site.get("last_scan_at"):
        print(f"  last_scan_at: {site['last_scan_at']}")
    if not scans:
        print("  (no scans yet)")
        return 0
    print("  recent scans:")
    for s in scans[:5]:
        print("   " + _fmt_scan(s))
    return 0


def _cmd_scans(client: LiveAPISec, args: argparse.Namespace) -> int:
    """List scan history for a site — lets a Copilot/agent see every test result."""
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    scans = client.list_scans(args.site)
    if args.json:
        print(LiveAPISec.dump(scans))
        return 0
    if not scans:
        print("no scans yet")
        return 0
    limit = getattr(args, "limit", 20)
    for s in scans[:limit]:
        print("  " + _fmt_scan(s))
    if len(scans) > limit:
        print(_dim(f"  …and {len(scans) - limit} more (use --json for all)"))
    return 0


def _cmd_findings(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site or not args.scan:
        print("error: --site and --scan are required", file=sys.stderr)
        return 2
    findings = client.get_findings(args.site, args.scan)
    if args.json:
        print(LiveAPISec.dump(findings))
        return 0
    if not findings:
        print("no findings")
        return 0
    for f in findings:
        print(_fmt_finding(f))
    return 0


def _cmd_verdict(client: LiveAPISec, args: argparse.Namespace) -> int:
    """CI regression gate: new/fixed/persisting vs baseline (exit 1 on regressions)."""
    if not args.site or not args.scan or not args.baseline:
        print("error: --site, --scan and --baseline are required", file=sys.stderr)
        return 2
    v = client.get_verdict(args.site, args.scan, args.baseline, fail_on=args.fail_on)
    if args.json:
        print(LiveAPISec.dump(v))
        return 0 if v.get("verdict") == "pass" else 1
    counts = v.get("counts") or {}
    print(f"verdict: {v.get('verdict', '?').upper()}")
    print(
        f"  new: {counts.get('new', 0)}  "
        f"fixed: {counts.get('fixed', 0)}  "
        f"persisting: {counts.get('persisting', 0)}  "
        f"blocking (>={v.get('fail_on')}): {counts.get('blocking', 0)}"
    )
    for f in v.get("blocking") or []:
        print("  " + _red(_fmt_finding(f)), file=sys.stderr)
    return 0 if v.get("verdict") == "pass" else 1


def _cmd_compliance(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Compliance mapping (PCI DSS / SOC 2 / ISO 27001 / GDPR / NIS2, Pro+)."""
    if not args.site or not args.scan:
        print("error: --site and --scan are required", file=sys.stderr)
        return 2
    data = client.get_compliance(args.site, args.scan)
    if args.json:
        print(LiveAPISec.dump(data))
        return 0
    print(f"compliance mapping for scan {args.scan} (open findings only):")
    frameworks = data.get("frameworks") or {}
    for key in ("pci_dss", "soc2", "iso27001", "gdpr", "nis2"):
        fw = frameworks.get(key) or {}
        if not fw:
            continue
        failed = fw.get("failed", 0)
        total = fw.get("requirements_with_findings", 0)
        mark = _red(f"{failed} failed") if failed else _green("ok")
        print(f"  {fw.get('name', key)}: {mark}  ({total} requirements with findings)")
    print(_dim("illustrative mapping within the scanner scope — not a certification"))
    return 0


def _cmd_report(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Full saved scan report — print (--json) or save (JSON or Markdown)."""
    if not args.site or not args.scan:
        print("error: --site and --scan are required", file=sys.stderr)
        return 2
    fmt = (getattr(args, "format", None) or "json").lower()
    if fmt not in ("json", "md"):
        print("error: --format must be json or md", file=sys.stderr)
        return 2
    data = client.get_report(args.site, args.scan)
    if args.json:
        print(LiveAPISec.dump(data))
        return 0
    fmt = (getattr(args, "format", None) or "json").lower()
    out = args.output
    if fmt not in ("json", "md"):
        print("error: --format must be json or md", file=sys.stderr)
        return 2
    if out and out.endswith(".md"):
        fmt = "md"
    if fmt == "md":
        findings = client.get_findings(args.site, args.scan)
        text = _md_report(
            {"scan_id": args.scan, **data},
            findings,
            ask_summary=_latest_ask_with_answers(client, args.site),
        )
        out = out or f"liveapisec-report-{args.scan}.md"
    else:
        text = LiveAPISec.dump(data)
        out = out or f"liveapisec-report-{args.scan}.json"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")
    print(f"report saved: {out} (format={fmt})")
    return 0


def _auto_baseline(client: LiveAPISec, site_id: str, scan_id: str) -> dict[str, Any] | None:
    """Previous completed scan of the site (newest first) — default baseline."""
    try:
        scans = client.list_scans(site_id)
    except Exception:  # noqa: BLE001 — brak historii to nie błąd, verdict skip
        return None
    for s in scans:
        if s.get("scan_id") != scan_id and s.get("status") == "completed":
            return s
    return None


def _cmd_all(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Full pipeline: scan --wait → verdict → compliance → report → PDF."""
    from liveapisec.client import LiveAPISecError

    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    fail_on = args.fail_on or "high"
    hacker = bool(getattr(args, "hacker", False))
    if hacker and not args.env:
        print("error: --hacker needs --env (e.g. development)", file=sys.stderr)
        return 2

    # 1. scan (+ wait — `all` zawsze czeka na wynik)
    if hacker:
        print(
            _WARN
            + _yellow(" hacker mode is DESTRUCTIVE — dev/staging only, never production"),
            file=sys.stderr,
        )
        scan = client.trigger_hacker_scan(
            args.site, args.env, goal=args.goal, tunnel=getattr(args, "tunnel", False)
        )
    else:
        scan = client.trigger_scan(
            args.site,
            branch=args.branch,
            commit=args.commit,
            tunnel=getattr(args, "tunnel", False),
            auth_b=_auth_b_payload(args),
        )
    scan_id = scan["scan_id"]
    print(f"scan queued: {scan_id} — waiting…", file=sys.stderr)
    done = client.wait_for_scan(args.site, scan_id)
    if not args.json:
        print(_fmt_scan(done))
    if done.get("status") != "completed":
        print(f"scan did not complete (status={done.get('status')})", file=sys.stderr)
        return 2

    out: dict[str, Any] = {"scan": done}

    # 2. verdict (jawny --baseline albo auto = poprzedni ukończony skan)
    baseline_id = args.baseline
    if not baseline_id:
        prev = _auto_baseline(client, args.site, scan_id)
        baseline_id = prev.get("scan_id") if prev else None
    verdict = None
    if baseline_id:
        verdict = client.get_verdict(args.site, scan_id, baseline_id, fail_on=fail_on)
        out["verdict"] = verdict
        if not args.json:
            counts = verdict.get("counts") or {}
            mark = _green("PASS") if verdict.get("verdict") == "pass" else _red("FAIL")
            print(
                f"verdict vs {baseline_id[:8]}…: {mark}  "
                f"new={counts.get('new', 0)} fixed={counts.get('fixed', 0)} "
                f"persisting={counts.get('persisting', 0)} blocking(>={fail_on})={counts.get('blocking', 0)}"
            )
            for f in verdict.get("blocking") or []:
                print("  " + _red(_fmt_finding(f)), file=sys.stderr)
    elif not args.json:
        print(_dim("no earlier completed scan — verdict skipped (first scan)"))

    # 3. compliance (Pro+; poniżej planu → notka, nie błąd)
    try:
        out["compliance"] = client.get_compliance(args.site, scan_id)
    except LiveAPISecError as exc:
        out["compliance"] = {"error": f"{exc.title}: {exc.detail}"}
        if not args.json:
            print(_dim(f"compliance skipped: {exc.title}"))

    # 4. report → plik (JSON albo Markdown z verdict + compliance w środku)
    report = client.get_report(args.site, scan_id)
    out["report"] = {"scan_id": scan_id}
    fmt = (getattr(args, "format", None) or "json").lower()
    report_path = args.report_out
    if report_path and report_path.endswith(".md"):
        fmt = "md"
    if fmt == "md":
        findings = client.get_findings(args.site, scan_id)
        comp = out.get("compliance")
        md = _md_report(
            {"scan_id": scan_id, **report},
            findings,
            verdict=verdict,
            compliance=comp if isinstance(comp, dict) else None,
            ask_summary=_latest_ask_with_answers(client, args.site),
        )
        report_path = report_path or f"liveapisec-report-{scan_id}.md"
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(md)
    else:
        report_path = report_path or f"liveapisec-report-{scan_id}.json"
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(LiveAPISec.dump(report))
    if not args.json:
        print(f"report saved: {report_path} (format={fmt})")
    # Ask-mode w podsumowaniu (informacyjnie — gate'em jest verdict).
    ask_sum = _latest_ask_with_answers(client, args.site)
    out["ask"] = (
        {"session_id": ask_sum.get("session_id"), "counts": ask_sum.get("counts")}
        if ask_sum
        else None
    )
    if ask_sum and not args.json:
        counts = ask_sum.get("counts") or {}
        fails = counts.get("fail", 0)
        mark = _red(f"fail={fails}") if fails else _green("no failed answers")
        print(f"ask-mode: {mark}  (pass={counts.get('pass', 0)} unanswered={counts.get('unanswered', 0)})")

    # 5. PDF certyfikatu (tylko gdy passed — inaczej 409 → notka)
    variant = args.variant or "full"
    try:
        content, filename = client.download_certificate_pdf(args.site, scan_id, variant)
        pdf_path = args.pdf_out or filename
        with open(pdf_path, "wb") as fh:
            fh.write(content)
        out["certificate_pdf"] = pdf_path
        if not args.json:
            print(f"certificate PDF saved: {pdf_path} (variant={variant})")
    except LiveAPISecError as exc:
        out["certificate_pdf"] = {"error": f"{exc.title}: {exc.detail}"}
        if not args.json:
            print(_dim(f"certificate PDF skipped: {exc.title}"))

    if args.json:
        print(LiveAPISec.dump(out))
    if verdict and verdict.get("verdict") != "pass":
        return 1
    return 0


def _md_cell(text: Any) -> str:
    """One Markdown table cell — no newlines/pipes breaking the table."""
    return str(text or "—").replace("|", "\\|").replace("\n", "<br>")


def _md_ask_section(ask_summary: dict[str, Any] | None) -> list[str]:
    """Ask-mode (SEC-ASK-N) section for Markdown reports."""
    if not ask_summary:
        return []
    counts = ask_summary.get("counts") or {}
    failed = ask_summary.get("failed") or []
    sid = str(ask_summary.get("session_id", ""))[:8]
    lines = [
        "",
        "## Security questionnaire (ask-mode, SEC-ASK-N)",
        "",
        (f"Session `{sid}…`: {ask_summary.get('questions', 0)} questions — "
         f"pass: **{counts.get('pass', 0)}**, fail: **{counts.get('fail', 0)}**, "
         f"na: {counts.get('na', 0)}, unanswered: {counts.get('unanswered', 0)}"),
    ]
    if failed:
        lines += [
            "",
            "| Severity | ID | Category | Question | Developer note |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in failed[:30]:
            lines.append(
                f"| **{(f.get('severity') or 'medium').upper()}** | {f.get('qid')} | "
                f"{_md_cell(f.get('category'))} | {_md_cell(f.get('question'))} | "
                f"{_md_cell(f.get('note'))} |"
            )
        if len(failed) > 30:
            lines.append(f"_…and {len(failed) - 30} more failed questions (see ask session)._")
    else:
        lines.append("No failed answers. 🎉")
    return lines


def _latest_ask_with_answers(client: LiveAPISec, site_id: str) -> dict[str, Any] | None:
    """Latest ask session with at least one answer (None = nothing to report)."""
    try:
        sessions = client.list_ask_sessions(site_id)
    except Exception:  # noqa: BLE001 — ask opcjonalny w raporcie
        return None
    for s in sessions:
        counts = s.get("counts") or {}
        if counts.get("pass", 0) + counts.get("fail", 0) + counts.get("na", 0) > 0:
            return s
    return None


# TODO 2.50: rekomendacje „jak naprawić” per kategoria findings (raport opisowy).
_REMEDIATION: dict[str, str] = {
    "bola": "Wymuś autoryzację na poziomie obiektu: sprawdzaj, że zalogowany podmiot ma dostęp do KONKRETNEGO id (nie tylko że jest zalogowany). Testuj dwoma tenantami — A musi dostać 403/404 na obiektach B.",
    "broken_auth": "Wymagaj uwierzytelnienia na każdym niepublicznym endpoincie (deny by default); upewnij się, że guard jest realnie podpięty, a nie tylko zadeklarowany w specyfikacji.",
    "rbac": "Ujednolic autoryzację między rolami: serwerowa macierz rola→uprawnienie, jednolite allow/deny, domyślnie odmawiaj przy braku reguły.",
    "mass_assignment": "Whitelistuj pola zapisywalne (DTO/allowlist), żeby klient nie ustawił pól wewnętrznych (role, owner, id, created_at). Ignoruj nieznane klucze.",
    "injection": "Używaj zapytań parametryzowanych / escapingu drivera; nigdy nie sklejaj wejścia do SQL/NoSQL/komend. Waliduj i odrzucaj nieoczekiwane wejście na granicy.",
    "rate_limit": "Dodaj limity per-IP (i per-konto dla auth) z 429 + Retry-After; dla wrażliwych endpointów (login, reset, trigger skanu) użyj exponential backoff.",
    "cors": "Nie odbijaj dowolnego Origin z credentials; jawna allowlist zaufanych originów i tylko potrzebne metody/nagłówki.",
    "headers": "Dodaj nagłówki bezpieczeństwa: Strict-Transport-Security, X-Content-Type-Options: nosniff, Content-Security-Policy, X-Frame-Options, Referrer-Policy.",
    "sensitive_params": "Nie umieszczaj sekretów/tokenów/PII w URL (query/path) — wyciekają przez logi, Referer i proxy. Użyj body/nagłówków; jeśli token musi być w URL, zrób go jednorazowym i krótkotrwałym.",
    "shadow_api": "Zinwentaryzuj i usuń/monitoruj nieudokumentowane endpointy; wymagaj auth i limitów na admin/metrics/debug albo zablokuj je na brzegu.",
    "jwt_weakness": "Przypnij algorytm podpisu po stronie serwera (odrzuć none/alg confusion), wymagaj signature+exp+iss, krótkie access-tokeny i walidacja na każdym żądaniu.",
    "method_tampering": "Wymuszaj tę samą autoryzację dla wszystkich metod HTTP na zasobie; nie polegaj na tym, że klient odrzuci metodę.",
    "info_disclosure": "Zwracaj generyczne błędy (bez stack trace/SQL/wersji); diagnostykę/debug ogranicz do sieci wewnętrznej.",
    "tech_fingerprint": "Ogranicz banery wersji (Server, X-Powered-By, nagłówki frameworka) i nie ujawniaj wersji bibliotek.",
    "api_versions": "Wycofaj przestarzałe wersje API lub obejmij je tą samą autoryzacją/limitami; nie eksponuj starych, niełata­nych wersji.",
    "graphql": "Wymuś autoryzację na poziomie pól, wyłącz introspection na produkcji (jeśli zbędna) i dodaj limity głębokości/złożoności zapytań.",
    "oauth": "Waliduj redirect_uri względem dokładnej allowlisty, wymagaj state/PKCE oraz krótkotrwałych, rotowanych tokenów.",
    "ssrf": "Ogranicz pobieranie po stronie serwera do allowlisty hostów/schematów; blokuj prywatne/metadata IP; waliduj i re-resolvuj URL-e.",
    "ai_probe": "Przejrzyj wynik sondy AI i zastosuj właściwą kontrolę dla tego endpointu.",
}


def _finding_fix(finding: dict[str, Any]) -> str:
    """Rekomendacja naprawy dla findings (mapa kategorii, fallback na opis)."""
    cat = str(finding.get("category") or "").lower()
    return (
        _REMEDIATION.get(cat)
        or str(finding.get("description") or "").strip()
        or "Przejrzyj finding i zastosuj właściwą kontrolę."
    )


def _md_risk(by_sev: dict[str, Any]) -> str:
    if by_sev.get("critical") or by_sev.get("high"):
        return "HIGH"
    if by_sev.get("medium"):
        return "MEDIUM"
    if by_sev.get("low"):
        return "LOW"
    if by_sev.get("info"):
        return "INFO"
    return "NONE"


def _md_improvements(
    findings: list[dict[str, Any]], failed_ask: list[dict[str, Any]] | None
) -> list[str]:
    """Sekcja „Points to improve” — opisowo: co, gdzie, dlaczego i jak naprawić."""
    order = {s: i for i, s in enumerate(_SEV)}
    blocks: list[str] = []
    for f in sorted(
        findings, key=lambda x: order.get(str(x.get("severity", "info")).lower(), 99)
    ):
        sev = str(f.get("severity", "info")).upper()
        target = f.get("target")
        meta = []
        if target:
            meta.append(f"**Endpoint:** `{target}`")
        if f.get("category"):
            meta.append(f"**Category:** `{f.get('category')}`")
        blocks += [
            f"### [SCAN] [{sev}] {f.get('title') or 'Finding'}",
        ]
        if meta:
            blocks.append("- " + "  ·  ".join(meta))
        blocks.append(f"- **Why:** {str(f.get('description') or '').strip() or 'See evidence.'}")
        blocks.append(f"- **Fix:** {_finding_fix(f)}")
        blocks.append("")
    for q in (failed_ask or [])[:30]:
        sev = str(q.get("severity") or "medium").upper()
        blocks.append(
            f"### [QUESTIONNAIRE] [{sev}] {q.get('qid')} — {q.get('question')}"
        )
        if q.get("note"):
            blocks.append(f"- **Your note:** {q.get('note')}")
        if q.get("fix"):
            blocks.append(f"- **Fix:** {q.get('fix')}")
        blocks.append("")
    if not blocks:
        return []
    return ["", "## Points to improve", "", *blocks]


def _md_report(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    verdict: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
    ask_summary: dict[str, Any] | None = None,
) -> str:
    """Human-readable Markdown report: scan summary + verdict + findings + compliance."""
    summary = scan.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    lines = [
        f"# LiveAPIsec security report — scan `{scan.get('scan_id') or scan.get('id')}`",
        "",
        f"- Status: **{scan.get('status', '?')}**",
        f"- Tests run: **{summary.get('tests_run', '?')}**"
        + (f" in {summary.get('duration_s')}s" if summary.get("duration_s") else ""),
        f"- Findings: **{summary.get('findings', len(findings))}**"
        + (
            " (" + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())) + ")"
            if by_sev
            else ""
        ),
    ]
    if scan.get("branch") or scan.get("commit"):
        lines.append(f"- Code: branch `{scan.get('branch')}` commit `{scan.get('commit')}`")
    # TODO 2.50: pokrycie (tested/absent) + podsumowanie ryzyka.
    tested = summary.get("tested")
    absent = summary.get("absent")
    if tested is not None:
        cov = f"- Coverage: **{tested} tested**"
        if absent:
            cov += f" / **{absent} not deployed on this URL**"
        total = (tested or 0) + (absent or 0)
        if total:
            cov += f" of {total} endpoints"
        lines.append(cov)
    failed_ask = (ask_summary or {}).get("failed") or []
    n_scan = len(findings)
    lines += [
        "",
        "## Summary",
        "",
        f"- **Risk: {_md_risk(by_sev)}**"
        + (" — no findings. 🎉" if n_scan == 0 and not failed_ask else ""),
        f"- **Points to improve: {n_scan} from the scan**"
        + (f" + **{len(failed_ask)} from the questionnaire**" if failed_ask else ""),
    ]
    lines += _md_improvements(findings, failed_ask)
    if verdict:
        counts = verdict.get("counts") or {}
        mark = "✅ PASS" if verdict.get("verdict") == "pass" else "❌ FAIL"
        base = str(verdict.get("baseline_scan_id", ""))[:8]
        lines += [
            "",
            "## Regression verdict vs baseline",
            "",
            (f"**{mark}** (fail-on: `{verdict.get('fail_on')}`, baseline `{base}…`)"
             f" — new: **{counts.get('new', 0)}**, fixed: **{counts.get('fixed', 0)}**"
             f", persisting: **{counts.get('persisting', 0)}**, "
             f"blocking: **{counts.get('blocking', 0)}**"),
        ]
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings — clean scan. 🎉")
    else:
        ordered = sorted(findings, key=lambda f: _SEV.index(str(f.get("severity", "info")).lower()) if str(f.get("severity", "info")).lower() in _SEV else 99)
        lines += [
            "| Severity | Title | Target | Category |",
            "| --- | --- | --- | --- |",
        ]
        for f in ordered:
            lines.append(
                f"| {_md_cell(f.get('severity'))} | {_md_cell(f.get('title'))} | "
                f"`{_md_cell(f.get('target'))}` | {_md_cell(f.get('category'))} |"
            )
    if compliance and not compliance.get("error"):
        lines += ["", "## Compliance mapping (illustrative, not a certification)", ""]
        frameworks = compliance.get("frameworks") or {}
        for key in ("pci_dss", "soc2", "iso27001", "gdpr", "nis2"):
            fw = frameworks.get(key) or {}
            if not fw:
                continue
            failed = fw.get("failed", 0)
            mark = "❌" if failed else "✅"
            lines.append(
                f"- {mark} **{fw.get('name', key)}**: {failed} failed / "
                f"{fw.get('requirements_with_findings', 0)} requirements with findings"
            )
    lines += [
        "",
        "---",
        ("_Generated by LiveAPIsec automated tests within the scanned scope — "
         "not a full audit, no guarantee of security._"),
    ]
    lines += _md_ask_section(ask_summary)
    return "\n".join(lines) + "\n"


_SEV_ORDER = ("critical", "high", "medium", "low")


def _sev_label(sev: str) -> str:
    """Kolorowa etykieta priorytetu (critical/high/medium/low)."""
    sev = (sev or "medium").lower()
    text = f"[{sev.upper()}]"
    if sev == "critical":
        return _red(text)
    if sev == "high":
        return _yellow(text)
    if sev == "low":
        return _dim(text)
    return text


def _ask_counts_line(summary: dict[str, Any]) -> str:
    counts = summary.get("counts") or {}
    total = summary.get("questions", 0)
    if isinstance(total, list):  # endpoint szczegółów zwraca listę pytań
        total = len(total)
    line = (
        f"session {summary.get('session_id', '')[:8]}…: {total} questions — "
        f"pass={counts.get('pass', 0)} fail={counts.get('fail', 0)} "
        f"na={counts.get('na', 0)} unanswered={counts.get('unanswered', 0)}"
    )
    clar = summary.get("clarifications") or {}
    if clar.get("total"):
        line += f"  (clarifications: {clar.get('answered', 0)}/{clar['total']} answered)"
    by_sev = summary.get("failed_by_severity") or {}
    if by_sev:
        parts = [
            f"{sev}={by_sev[sev]}"
            for sev in ("critical", "high", "medium", "low")
            if by_sev.get(sev)
        ]
        if parts:
            line += f"  (fails: {', '.join(parts)})"
    return line


def _cmd_ask_new(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site:
        print("error: --site is required", file=sys.stderr)
        return 2
    out = client.create_ask_session(args.site, include_ai=not args.no_ai)
    if args.json:
        print(LiveAPISec.dump(out))
        return 0
    print(f"ask session created: {out['session_id']} ({out['questions']} questions)")
    print(_dim("answer with: liveapisec ask answer --session ID --question SEC-ASK-1 --verdict pass|fail --note ..."))
    return 0


def _cmd_ask_sessions(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site:
        print("error: --site is required", file=sys.stderr)
        return 2
    sessions = client.list_ask_sessions(args.site)
    if args.json:
        print(LiveAPISec.dump(sessions))
        return 0
    if not sessions:
        print("no ask sessions yet — create one: liveapisec ask new --site SITE_ID")
        return 0
    for s in sessions:
        print(_ask_counts_line(s))
        for f in (s.get("failed") or [])[:5]:
            sev = _sev_label(f.get("severity") or "medium")
            print(f"  {_red('FAIL')} {sev} {f['qid']} [{f.get('category')}] {f.get('question', '')[:80]}")
    return 0


def _cmd_ask_show(client: LiveAPISec, args: argparse.Namespace) -> int:
    data = client.get_ask_session(args.session)
    if args.json:
        print(LiveAPISec.dump(data))
        return 0
    only = getattr(args, "only", None)
    print(_ask_counts_line(data))
    clar = [q for q in data.get("questions") or [] if q.get("kind") == "clarification"]
    if clar and only != "failed":
        print("\n" + _bold("Clarifications (no priority — answers sharpen the next round):"))
        for q in clar:
            ans = q.get("answer") or {}
            mark = _green("ANSWERED") if (ans.get("note") or ans.get("verdict")) else _dim("OPEN")
            print(f"\n{mark} {q['qid']}")
            print(f"  Q: {q.get('question')}")
            if q.get("fix"):
                print(f"  Why: {_dim(q['fix'])}")
            if ans.get("note"):
                print(f"  Answer: {ans['note']}")
    for q in data.get("questions") or []:
        if q.get("kind") == "clarification":
            continue  # już pokazane wyżej
        ans = q.get("answer") or {}
        verdict = ans.get("verdict", "unanswered")
        if only == "failed" and verdict != "fail":
            continue
        if only == "unanswered" and verdict != "unanswered":
            continue
        mark = {"pass": _green("PASS"), "fail": _red("FAIL")}.get(verdict, _dim(verdict.upper()))
        sev = q.get("severity") or "medium"
        print(
            f"\n{mark} {q['qid']} [{q.get('category')}] {_sev_label(sev)}"
            + (" (AI)" if q.get("ai") else "")
        )
        print(f"  Q: {q.get('question')}")
        print(f"  Fix: {_dim(q.get('fix', ''))}")
        if ans.get("note"):
            print(f"  Note: {ans['note']}")
    return 0


def _cmd_ask_answer(client: LiveAPISec, args: argparse.Namespace) -> int:
    out = client.answer_ask_question(args.session, args.question, args.verdict, args.note or "")
    if args.json:
        print(LiveAPISec.dump(out))
        return 0
    print(_ask_counts_line(out))
    return 0


def _cmd_ask_followup(client: LiveAPISec, args: argparse.Namespace) -> int:
    out = client.ask_followups(
        args.session,
        rounds=getattr(args, "rounds", 1) or 1,
        until_dry=bool(getattr(args, "until_dry", False)),
    )
    if args.json:
        print(LiveAPISec.dump(out))
        return 0
    added = out.get("added", 0)
    per_round = out.get("added_per_round") or []
    rounds = out.get("rounds", len(per_round) or 1)
    print(f"follow-up questions added: {added} (rounds: {rounds}, per round: {per_round})")
    print(_ask_counts_line(out))
    if added:
        print(_dim("answer them with: liveapisec ask run --session " + args.session))
    return 0


def _cmd_ask_run(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Interactive ask-mode: walk unanswered questions, record pass/fail/na."""
    data = client.get_ask_session(args.session)
    todo = [q for q in data.get("questions") or [] if not (q.get("answer") or {}).get("verdict")]
    if not todo:
        print("all questions answered 🎉")
        print(_ask_counts_line(data))
        return 0
    print(f"{len(todo)} unanswered — verdicts: pass | fail | na (+ optional note). Empty = skip.")
    done = 0
    try:
        for q in todo:
            print(f"\n{q['qid']} [{q.get('category')}]" + (" (AI)" if q.get("ai") else ""))
            print(f"  Q: {q.get('question')}")
            print(f"  Fix: {_dim(q.get('fix', ''))}")
            verdict = input("  verdict [pass/fail/na/skip]: ").strip().lower()
            if verdict in ("", "skip", "s"):
                continue
            if verdict not in ("pass", "fail", "na"):
                print("  skipped (unknown verdict)")
                continue
            note = input("  note (file/function checked, optional): ").strip()
            out = client.answer_ask_question(args.session, q["qid"], verdict, note)
            done += 1
            counts = out.get("counts") or {}
            print(f"  saved ✓  (fail={counts.get('fail', 0)})")
    except (KeyboardInterrupt, EOFError):
        print("\ninterrupted.")
    print(f"\nanswered {done} this run.")
    return 0


def _cmd_certificate(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Certyfikat / Trust Page w wybranym zakresie: publiczny URL + snippet."""
    # TODO 2.50 (opcja 3): wybór URL-a, którego dotyczy PUBLICZNY certyfikat.
    cert_url = getattr(args, "url", None)
    if cert_url is not None and not args.site:
        print("error: --url needs --site", file=sys.stderr)
        return 2
    if args.site and cert_url is not None:
        try:
            client.set_site_certificate_url(args.site, cert_url or None)
            print(
                _green(
                    f"{_OK} public certificate now concerns URL: "
                    f"{cert_url or 'default base_url'}"
                )
            )
        except Exception as exc:  # noqa: BLE001 — zły URL/uprawnienia
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if getattr(args, "pdf", False):
        # PDF z konkretnego skanu (tylko gdy passed) — zapis do pliku.
        if not args.site or not args.scan:
            print("error: --pdf needs --site and --scan", file=sys.stderr)
            return 2
        variant = getattr(args, "variant", None) or "full"
        content, filename = client.download_certificate_pdf(args.site, args.scan, variant)
        out = args.output or filename
        with open(out, "wb") as fh:
            fh.write(content)
        print(f"certificate PDF saved: {out} ({len(content)} bytes, variant={variant})")
        return 0
    data = client.get_certificate(
        scope=getattr(args, "scope", "org") or "org",
        project=getattr(args, "project", None),
        site=getattr(args, "site", None),
    )
    if args.json:
        print(LiveAPISec.dump(data))
        return 0
    if data.get("trust_url"):
        print(f"certificate: {data['trust_url']}")
    else:
        print("certificate: (no public trust page/slug for this site yet)")
    extra = f"  scope: {data.get('scope')}"
    if data.get("slug"):
        extra += f"  slug: {data['slug']}"
    print(_dim(extra))
    wtype = getattr(args, "type", "badge") or "badge"
    embeds = data.get("embeds") or {}
    snippet = embeds.get(wtype) or embeds.get("badge") or ""
    print()
    print(f"Embed ({wtype}) — install the widget in 3 steps:")
    print("  1. Paste the snippet into your site (footer/docs/trust page):")
    print(snippet)
    print("  2. The badge appears automatically once the site passes its tests")
    print("     (failed/no_data shows nothing — by design).")
    print(f"  3. Verify: open {data.get('trust_url') or 'the trust URL above'}")
    print()
    print(_dim("Other types: " + ", ".join(embeds.keys())))
    return 0


def _cmd_projects(client: LiveAPISec, args: argparse.Namespace) -> int:
    """List projects + sites + last scan status — results straight in the terminal."""
    sites = client.list_sites()
    if args.json:
        print(LiveAPISec.dump(sites))
        return 0
    if not sites:
        print(_yellow("no projects yet — push a site first"))
        return 0

    def _last_line(s: dict[str, Any]) -> str:
        name = s.get("name") or "?"
        url = s.get("base_url") or ""
        last = s.get("last_scan")
        if not last or not last.get("status"):
            return f"  {name}  {_dim(url)}  {_dim('no test yet')}"
        status = last.get("status") or "?"
        parts = [f"last test: {_scan_status(status)}"]
        if last.get("tests_run") is not None:
            parts.append(f"{last['tests_run']} tests")
        if last.get("findings"):
            sev = last.get("by_severity") or {}
            sev_str = " ".join(
                f"{k}={v}"
                for k, v in sorted(
                    sev.items(), key=lambda kv: _SEV.index(kv[0]) if kv[0] in _SEV else 9
                )
            )
            parts.append(f"{last['findings']} findings" + (f" ({sev_str})" if sev_str else ""))
        return f"  {name}  {_dim(url)}  {_dim(' · '.join(parts))}"

    if args.project:
        groups: dict[str, list[dict[str, Any]]] = {args.project: []}
        for s in sites:
            if (s.get("project") or "(no project)") == args.project:
                groups[args.project].append(s)
    else:
        groups: dict[str, list[dict[str, Any]]] = {}
        for s in sites:
            groups.setdefault(s.get("project") or "(no project)", []).append(s)

    for project in sorted(groups):
        print(_bold(project))
        for s in groups[project]:
            print(_last_line(s))
        print()
    return 0


def _cmd_sites(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    site = client.get_site(args.site)
    if args.json:
        print(LiveAPISec.dump(site))
        return 0
    print(f"site {site['site_id']}: {site.get('name')} — {site.get('endpoints_count')} endpoints")
    if site.get("base_url"):
        print(f"  base_url: {site['base_url']}")
    if site.get("project"):
        print(f"  project: {site['project']}")
    print(f"  source: {site.get('source')}  last_scan_at: {site.get('last_scan_at')}")
    print(
        f"  access: {site.get('access') or 'external'}  "
        f"schedule: {site.get('schedule') or 'off'}"
    )
    # TODO 2.50: URL-e — ten sam zestaw endpointów testowany przeciw każdemu.
    envs = site.get("environments") or []
    if envs:
        print("  urls (same endpoints tested against each):")
        for e in envs:
            flags = []
            ver = e.get("version") or "latest"
            if ver and ver != "latest":
                flags.append(f"version={ver}")
            if e.get("schedule") and e.get("schedule") != "off":
                flags.append(f"schedule={e['schedule']}")
            if e.get("paused"):
                flags.append("paused")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            print(f"    - {e.get('name')}: {e.get('base_url')}{suffix}")
        print(f"    run one: liveapisec scan --site {args.site} --url <name>")
    # TODO 2.50: profil auth wykryty ze skanu (schemes + grupy wymagające auth).
    ap = site.get("auth_profile") or {}
    if ap:
        schemes = ap.get("schemes") or []
        if schemes:
            desc = ", ".join(
                f"{s.get('name')}({s.get('type') or s.get('scheme') or '?'})" for s in schemes
            )
            print(f"  auth schemes (from spec): {desc}")
        groups = ap.get("groups") or []
        if groups:
            print("  auth requirements (from last scan):")
            for g in groups:
                state = "requires auth" if g.get("auth_required") else "public"
                extra = f", {g['unknown']} write(unknown)" if g.get("unknown") else ""
                scheme = f"  [{', '.join(g['schemes'])}]" if g.get("schemes") else ""
                print(
                    f"    - {g.get('prefix')}: {state} "
                    f"({g.get('auth_required', 0)} auth / {g.get('public', 0)} public"
                    f"{extra} of {g.get('total', 0)}){scheme}"
                )
        if ap.get("credentials"):
            print(f"  credentials configured: {', '.join(ap['credentials'])}")
    return 0


def _cmd_urls(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Zarządzanie URL-ami site'u (TODO 2.50): list / add / set / rm.

    Jeden zestaw endpointów, wiele adresów. Każdy URL ma własną wersję spec
    (`latest` albo snapshot), harmonogram i stan `paused`.
    """
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    action = getattr(args, "action", "list") or "list"

    if action == "list":
        envs = client.list_environments(args.site)
        if args.json:
            print(LiveAPISec.dump(envs))
            return 0
        if not envs:
            print(_dim("no URLs yet — add one: liveapisec urls add --site ID --name dev --url URL"))
            return 0
        for e in envs:
            flags = []
            ver = e.get("version") or "latest"
            flags.append(f"version={ver}")
            if e.get("schedule") and e.get("schedule") != "off":
                flags.append(f"schedule={e['schedule']}")
            if e.get("paused"):
                flags.append("paused")
            print(f"  - {e.get('name')}: {e.get('base_url')}  [{', '.join(flags)}]")
        return 0

    if action == "add":
        if not args.name or not args.base_url:
            print("error: urls add needs --name and --url", file=sys.stderr)
            return 2
        try:
            env = client.add_environment(
                args.site,
                args.name,
                args.base_url,
                version=args.version or "latest",
                schedule=args.schedule,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(_green(f"{_OK} added URL '{env.get('name')}' → {env.get('base_url')}"))
        return 0

    if action == "set":
        if not args.name:
            print("error: urls set needs --name", file=sys.stderr)
            return 2
        fields = {
            "base_url": args.base_url,
            "version": args.version,
            "schedule": args.schedule,
            "paused": True if args.paused else None,
        }
        if all(v is None for v in fields.values()):
            print(
                "error: urls set needs at least one of --url / --version / --schedule / --paused",
                file=sys.stderr,
            )
            return 2
        try:
            env = client.update_environment(args.site, args.name, **fields)
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(_green(f"{_OK} updated URL '{args.name}'"))
        if args.json:
            print(LiveAPISec.dump(env))
        return 0

    if action == "rm":
        if not args.name:
            print("error: urls rm needs --name", file=sys.stderr)
            return 2
        try:
            client.remove_environment(args.site, args.name)
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(_green(f"{_OK} removed URL '{args.name}'"))
        return 0

    print(f"error: unknown urls action '{action}'", file=sys.stderr)
    return 2


def _cmd_versions(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Lista wersji specyfikacji site'u — do przypinania na URL-ach (TODO 2.50)."""
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    versions = client.list_versions(args.site)
    if args.json:
        print(LiveAPISec.dump(versions))
        return 0
    if not versions:
        print(_dim("no versions yet — push a spec first"))
        return 0
    print(_dim(f"versions of site {args.site} (newest first):"))
    for v in versions:
        mark = _green(" (current)") if v.get("is_current") else ""
        note = f"  {_dim(v['note'])}" if v.get("note") else ""
        used = f"  {_dim('used by: ' + ', '.join(v['used_by']))}" if v.get("used_by") else ""
        created = str(v.get("created_at") or "")[:10]
        print(
            f"  {v.get('version')}{mark}  {v.get('endpoints_count', '?')} endpoints"
            f"  {created}{note}{used}"
        )
    print(_dim(f"pin one: liveapisec urls set --site {args.site} --name <url> --version <version>"))
    return 0


def _cmd_delete(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Usuń site albo cały projekt (i wszystkie dane) — TODO 2.50."""
    site = getattr(args, "site", None)
    project = getattr(args, "project", None)
    if bool(site) == bool(project):
        print("error: pass exactly one of --site or --project", file=sys.stderr)
        return 2
    target = f"site {site}" if site else f"project '{project}'"
    if not getattr(args, "yes", False):
        try:
            answer = input(f"Delete {target} and ALL its data? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            print("aborted", file=sys.stderr)
            return 1
    try:
        if site:
            client.delete_site(site)
        else:
            client.delete_project(project)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_green(f"{_OK} deleted {target}"))
    return 0


def _cmd_credentials(client: LiveAPISec, args: argparse.Namespace) -> int:
    """Zarządzanie credentialami site'u per-prefix (TODO 2.50): list/set/rm.

    Pozwala przypiąć różne zestawy auth do różnych tras, np. dev-key na
    `/developers`, a Clerk na resztę — jeden skan dobiera właściwy per ścieżka.
    """
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    action = getattr(args, "action", "list") or "list"
    if action == "list":
        creds = client.list_credentials(args.site)
        if args.json:
            print(LiveAPISec.dump(creds))
            return 0
        if not creds:
            print(_dim("no credentials — set one: liveapisec credentials set --site ID --slot a --auth-type bearer --auth-token …"))
            return 0
        for c in creds:
            pref = c.get("path_prefix") or "(default)"
            print(f"  - slot={c.get('slot')}  {c.get('auth_method')}  prefix={pref}")
        return 0
    if action == "set":
        if not getattr(args, "slot", None):
            print("error: credentials set needs --slot", file=sys.stderr)
            return 2
        auth = _build_auth(args)
        if auth is None:
            print("error: provide --auth-type (and its fields)", file=sys.stderr)
            return 2
        err = _validate_auth(args, auth)
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        try:
            out = client.set_credential(
                args.site, args.slot, auth, path_prefix=getattr(args, "path", None)
            )
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 1
        pref = out.get("path_prefix") or "(default)"
        print(_green(f"{_OK} credential slot={out.get('slot')} {out.get('auth_method')} prefix={pref}"))
        return 0
    if action == "rm":
        if not getattr(args, "slot", None):
            print("error: credentials rm needs --slot", file=sys.stderr)
            return 2
        try:
            client.remove_credential(args.site, args.slot)
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(_green(f"{_OK} removed credential slot={args.slot}"))
        return 0
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="liveapisec",
        description="LiveAPISec Developer API — push API specs, run security scans, gate your CI/CD.",
    )
    parser.add_argument(
        "--api-url", help=f"API base URL (default: $LIVEAPISEC_API_URL or {DEFAULT_API_URL})"
    )
    parser.add_argument("--api-key", help="dev API key las_dev_... (default: $LIVEAPISEC_API_KEY)")
    parser.add_argument("--json", action="store_true", help="print raw JSON output")
    sub = parser.add_subparsers(dest="command", required=True)

    def _json_flag(p: argparse.ArgumentParser) -> None:
        # --json also works after the subcommand name (e.g. `findings ... --json`)
        p.add_argument(
            "--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS
        )

    p_push = sub.add_parser("push", help="create/update a site (idempotent)")
    p_push.add_argument("--name", help="site name (interactive pick if omitted)")
    p_push.add_argument("--base-url")
    p_push.add_argument("--project")
    p_push.add_argument(
        "--schedule",
        choices=["off", "6h", "12h", "24h", "weekly"],
        help="auto-test frequency (respects your plan's max; default off)",
    )
    p_push.add_argument(
        "--access",
        choices=["external", "internal"],
        help="external = scheduler may auto-test; internal = on-demand only via CLI",
    )
    p_push.add_argument(
        "--endpoint", action="append", type=_parse_endpoint, help="'METHOD /path' (repeatable)"
    )
    p_push.add_argument("--openapi-url", help="URL to OpenAPI spec instead of --endpoint")
    p_push.add_argument(
        "--spec-file",
        help="local OpenAPI file (JSON/YAML) — parsed locally, server fetches nothing (no SSRF block)",
    )
    p_push.add_argument("--site", help="existing site_id to update (PUT)")
    p_push.add_argument(
        "--verify",
        action="store_true",
        help="probe the first endpoint with the pushed auth (catch bad tokens early)",
    )
    _auth_args(p_push)
    _json_flag(p_push)
    p_push.set_defaults(func=_cmd_push)

    p_code = sub.add_parser(
        "scan-code",
        aliases=["push-code"],
        help="scan source code LOCALLY for endpoints and push them (code never leaves your machine)",
    )
    p_code.add_argument("--dir", default=".", help="project directory or file to scan (default: .)")
    p_code.add_argument(
        "--repo",
        help="git URL (https/ssh/local) to shallow-clone and scan instead of --dir",
    )
    p_code.add_argument(
        "--framework",
        choices=[
            "fastapi",
            "flask",
            "django",
            "nextjs",
            "nestjs",
            "express",
            "laravel",
            "php",
            "spring",
            "go",
            "rust",
        ],
        help="force framework (default: auto-detect)",
    )
    p_code.add_argument("--name", help="site name (interactive pick if omitted)")
    p_code.add_argument("--base-url", help="base URL (interactive pick if omitted)")
    p_code.add_argument("--project")
    p_code.add_argument(
        "--schedule",
        choices=["off", "6h", "12h", "24h", "weekly"],
        help="auto-test frequency (respects your plan's max; default off)",
    )
    p_code.add_argument(
        "--access",
        choices=["external", "internal"],
        help="external = scheduler may auto-test; internal = on-demand only via CLI",
    )
    p_code.add_argument("--site", help="existing site_id to update (PUT)")
    p_code.add_argument("--dry-run", action="store_true", help="scan locally + list endpoints, do not push (no key needed)")
    p_code.add_argument(
        "--verify",
        action="store_true",
        help="probe the first endpoint with the pushed auth (catch bad tokens early)",
    )
    _auth_args(p_code)
    _json_flag(p_code)
    p_code.set_defaults(func=_cmd_scan_code)

    p_scan = sub.add_parser("scan", help="run a security scan (optionally wait + gate)")
    p_scan.add_argument("--site", required=True)
    p_scan.add_argument("--branch")
    p_scan.add_argument("--commit")
    p_scan.add_argument("--wait", action="store_true", help="poll until finished")
    p_scan.add_argument(
        "--url",
        default=None,
        help="URL/environment name to test the site's endpoints against "
        "(see `liveapisec sites --site <id>`); default: site base_url",
    )
    p_scan.add_argument(
        "--tunnel",
        action="store_true",
        help="run through a connected CLI tunnel (localhost/internal targets)",
    )
    p_scan.add_argument(
        "--fail-on", choices=_SEV, help="exit 1 if findings at/above this severity (default: high)"
    )
    _auth_b_args(p_scan)
    p_scan.add_argument("--poll-interval", type=float, default=3.0)
    p_scan.add_argument("--timeout", type=float, default=600.0)
    _json_flag(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    p_hacker = sub.add_parser(
        "hacker",
        help="run an autonomous AI hacker-mode test (dev/staging only; localhost exempt)",
    )
    p_hacker.add_argument("--site", required=True)
    p_hacker.add_argument(
        "--env", required=True, help="environment name, e.g. development or staging"
    )
    p_hacker.add_argument(
        "--goal",
        default=None,
        help="optional guided attack objective, e.g. \"check /users for IDOR\" "
        "(TODO 3.6.2)",
    )
    # TODO 2.50 — druga tożsamość do testów różnicowych IDOR/RBAC w hacker-mode.
    _auth_b_args(p_hacker)
    p_hacker.add_argument("--wait", action="store_true", help="poll until the agent finishes")
    p_hacker.add_argument(
        "--destructive",
        action="store_true",
        help="allow state-changing methods (POST/PUT/PATCH/DELETE); default is READ-ONLY "
        "(GET/HEAD/OPTIONS only)",
    )
    p_hacker.add_argument(
        "--thorough",
        action="store_true",
        help="'real hacker' mode: no step/request limits, full endpoint coverage, "
        "deterministic A/B/anon differential (auto-IDOR). Ignores AI cost budget.",
    )
    p_hacker.add_argument(
        "--tunnel",
        action="store_true",
        help="run through a connected CLI tunnel (localhost/internal targets)",
    )
    p_hacker.add_argument("--poll-interval", type=float, default=3.0)
    p_hacker.add_argument("--timeout", type=float, default=600.0)
    _json_flag(p_hacker)
    p_hacker.set_defaults(func=_cmd_hacker)

    p_status = sub.add_parser("status", help="site status + recent scans")
    p_status.add_argument("--site", required=True)
    _json_flag(p_status)
    p_status.set_defaults(func=_cmd_status)

    p_scans = sub.add_parser("scans", help="list security test (scan) history for a site")
    p_scans.add_argument("--site", required=True)
    p_scans.add_argument("--limit", type=int, default=20, help="max rows to show (default: 20)")
    _json_flag(p_scans)
    p_scans.set_defaults(func=_cmd_scans)

    p_find = sub.add_parser("findings", help="list findings for a scan")
    p_find.add_argument("--site", required=True)
    p_find.add_argument("--scan", required=True)
    _json_flag(p_find)
    p_find.set_defaults(func=_cmd_findings)

    p_verdict = sub.add_parser(
        "verdict", help="CI regression gate: new/fixed vs baseline (exit 1 on regressions)"
    )
    p_verdict.add_argument("--site", required=True)
    p_verdict.add_argument("--scan", required=True, help="current scan id")
    p_verdict.add_argument("--baseline", required=True, help="baseline scan id")
    p_verdict.add_argument(
        "--fail-on",
        choices=_SEV,
        default="high",
        help="fail when NEW findings reach this severity (default: high)",
    )
    _json_flag(p_verdict)
    p_verdict.set_defaults(func=_cmd_verdict)

    p_compliance = sub.add_parser(
        "compliance", help="compliance mapping: PCI DSS / SOC 2 / ISO 27001 / GDPR / NIS2 (Pro+)"
    )
    p_compliance.add_argument("--site", required=True)
    p_compliance.add_argument("--scan", required=True)
    _json_flag(p_compliance)
    p_compliance.set_defaults(func=_cmd_compliance)

    p_report = sub.add_parser("report", help="full saved scan report (print or save)")
    p_report.add_argument("--site", required=True)
    p_report.add_argument("--scan", required=True)
    p_report.add_argument(
        "-o", "--output", default=None, help="save to file (default: liveapisec-report-<scan>.json|.md)"
    )
    p_report.add_argument(
        "--format", choices=["json", "md"], default="json", help="report format (or use -o file.md)"
    )
    _json_flag(p_report)
    p_report.set_defaults(func=_cmd_report)

    p_all = sub.add_parser(
        "all", help="full pipeline: scan → verdict → compliance → report → certificate PDF"
    )
    p_all.add_argument("--site", required=True)
    p_all.add_argument("--baseline", default=None, help="baseline scan id (default: previous completed scan)")
    p_all.add_argument("--fail-on", choices=_SEV, default="high")
    p_all.add_argument("--branch", default=None)
    p_all.add_argument("--commit", default=None)
    p_all.add_argument("--tunnel", action="store_true", help="route scan traffic via `connect` tunnel")
    p_all.add_argument("--hacker", action="store_true", help="hacker-mode AI test instead of a standard scan (destructive — dev/staging only)")
    p_all.add_argument("--env", default=None, help="environment name (required with --hacker)")
    p_all.add_argument("--goal", default=None, help="guided goal (with --hacker)")
    p_all.add_argument("--variant", choices=["full", "client"], default="full", help="certificate PDF variant")
    p_all.add_argument("--report-out", default=None, help="report file (.json or .md)")
    p_all.add_argument(
        "--format", choices=["json", "md"], default="md",
        help="report format for --report-out (default: md — full run report)",
    )
    p_all.add_argument("--pdf-out", default=None, help="certificate PDF file")
    _auth_b_args(p_all)
    _json_flag(p_all)
    p_all.set_defaults(func=_cmd_all)

    p_ask = sub.add_parser(
        "ask", help="ask-mode: answer SEC-ASK-N security questions about your code"
    )
    ask_sub = p_ask.add_subparsers(dest="ask_command", required=True)

    p_ask_new = ask_sub.add_parser("new", help="new question session for a site (bank 270 + AI)")
    p_ask_new.add_argument("--site", required=True)
    p_ask_new.add_argument("--no-ai", action="store_true", help="bank only, no AI questions")
    _json_flag(p_ask_new)
    p_ask_new.set_defaults(func=_cmd_ask_new)

    p_ask_ls = ask_sub.add_parser("sessions", help="list question sessions of a site")
    p_ask_ls.add_argument("--site", required=True)
    _json_flag(p_ask_ls)
    p_ask_ls.set_defaults(func=_cmd_ask_sessions)

    p_ask_show = ask_sub.add_parser("show", help="show a session (questions + answers)")
    p_ask_show.add_argument("--session", required=True)
    p_ask_show.add_argument("--only", choices=["unanswered", "failed"], default=None)
    _json_flag(p_ask_show)
    p_ask_show.set_defaults(func=_cmd_ask_show)

    p_ask_ans = ask_sub.add_parser("answer", help="answer one question: pass | fail | na")
    p_ask_ans.add_argument("--session", required=True)
    p_ask_ans.add_argument("--question", required=True, help="e.g. SEC-ASK-5")
    p_ask_ans.add_argument(
        "--verdict",
        required=True,
        choices=["pass", "fail", "na", "info"],
        help="info = answer to a clarification question (free text in --note)",
    )
    p_ask_ans.add_argument("--note", default="", help="evidence: file/function checked")
    _json_flag(p_ask_ans)
    p_ask_ans.set_defaults(func=_cmd_ask_answer)

    p_ask_run = ask_sub.add_parser("run", help="interactive: walk unanswered questions")
    p_ask_run.add_argument("--session", required=True)
    p_ask_run.set_defaults(func=_cmd_ask_run)

    p_ask_fu = ask_sub.add_parser(
        "followup", help="AI adds questions based on the answers you gave"
    )
    p_ask_fu.add_argument("--session", required=True)
    p_ask_fu.add_argument(
        "--rounds", type=int, default=1, help="how many AI passes (default 1)"
    )
    p_ask_fu.add_argument(
        "--until-dry",
        action="store_true",
        help="keep asking until a pass adds no new questions (cap 5)",
    )
    _json_flag(p_ask_fu)
    p_ask_fu.set_defaults(func=_cmd_ask_followup)

    p_sites = sub.add_parser("sites", help="show a site")
    p_sites.add_argument("--site", required=True)
    _json_flag(p_sites)
    p_sites.set_defaults(func=_cmd_sites)

    p_urls = sub.add_parser(
        "urls",
        help="list/add/update/remove URLs (environments) — same endpoints, many addresses",
    )
    p_urls.add_argument(
        "action", nargs="?", choices=["list", "add", "set", "rm"], default="list"
    )
    p_urls.add_argument("--site", required=True)
    p_urls.add_argument("--name", help="URL/environment name (add/set/rm)")
    p_urls.add_argument("--url", dest="base_url", help="target address (add/set)")
    p_urls.add_argument(
        "--version", default=None, help="'latest' or a spec version from /versions (add/set)"
    )
    p_urls.add_argument(
        "--schedule", choices=["off", "6h", "12h", "24h", "weekly"], default=None
    )
    p_urls.add_argument("--paused", action="store_true", help="pause scheduled scans (set)")
    _json_flag(p_urls)
    p_urls.set_defaults(func=_cmd_urls)

    p_versions = sub.add_parser(
        "versions", help="list spec versions of a site (to pin on a URL)"
    )
    p_versions.add_argument("--site", required=True)
    _json_flag(p_versions)
    p_versions.set_defaults(func=_cmd_versions)

    p_delete = sub.add_parser(
        "delete", help="delete a site or a whole project (and all its data)"
    )
    p_delete.add_argument("--site", help="site id to delete")
    p_delete.add_argument("--project", help="project name to delete (all its sites)")
    p_delete.add_argument("--yes", action="store_true", help="skip confirmation prompt")
    p_delete.set_defaults(func=_cmd_delete)

    p_creds = sub.add_parser(
        "credentials", help="manage site credentials per-prefix (different auth per route group)"
    )
    p_creds.add_argument("action", nargs="?", choices=["list", "set", "rm"], default="list")
    p_creds.add_argument("--site", required=True)
    p_creds.add_argument("--slot", help="credential slot, e.g. a / b / devkey")
    p_creds.add_argument(
        "--path", help="path prefix this credential applies to, e.g. /developers (default: all)"
    )
    _auth_args(p_creds)
    _json_flag(p_creds)
    p_creds.set_defaults(func=_cmd_credentials)

    p_projects = sub.add_parser(
        "projects",
        help="list projects with sites and the last test status — results straight in the terminal",
    )
    p_projects.add_argument("--project", help="only show this project")
    _json_flag(p_projects)
    p_projects.set_defaults(func=_cmd_projects)

    p_config = sub.add_parser("config", help="show / manage saved config (API key)")
    p_config.add_argument("--clear", action="store_true", help="remove the saved config file")
    p_config.set_defaults(func=_cmd_config)

    p_connect = sub.add_parser(
        "connect", help="reverse tunnel — act as a proxy for scans against localhost/internal"
    )
    p_connect.add_argument("--site", required=True, help="site id (from `liveapisec sites`)")
    p_connect.add_argument(
        "--poll-timeout", type=int, default=25, help="long-poll window in seconds (default 25)"
    )
    p_connect.set_defaults(func=_cmd_connect)

    p_cert = sub.add_parser(
        "certificate", help="certificate / Trust Page: public URL + embed snippet"
    )
    p_cert.add_argument(
        "--type", choices=["badge", "banner", "card", "iframe"], default="badge"
    )
    p_cert.add_argument(
        "--scope",
        choices=["org", "project", "site"],
        default="org",
        help="what the certificate covers (default: org)",
    )
    p_cert.add_argument("--project", help="project name (scope=project)")
    p_cert.add_argument("--site", help="site id (scope=site)")
    p_cert.add_argument(
        "--url",
        default=None,
        help="environment/URL name the PUBLIC certificate concerns (with --site); "
        "pass an empty string to use the default base_url. The URL is not shown publicly.",
    )
    p_cert.add_argument(
        "--pdf",
        action="store_true",
        help="download the certificate PDF for --scan (only when the scan passed)",
    )
    p_cert.add_argument(
        "--variant", choices=["full", "client"], default="full", help="PDF variant"
    )
    p_cert.add_argument("--scan", help="scan id (with --pdf)")
    p_cert.add_argument(
        "-o", "--output", default=None, help="output file (with --pdf/--report)"
    )
    _json_flag(p_cert)
    p_cert.set_defaults(func=_cmd_certificate)

    return parser


def _needs_key(args: argparse.Namespace) -> bool:
    if args.command == "config":
        return False
    return not (args.command in ("scan-code", "push-code") and getattr(args, "dry_run", False))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.json = bool(getattr(args, "json", False))

    cfg = load_config()
    api_key = args.api_key or os.environ.get(ENV_API_KEY) or cfg.get("api_key") or ""
    api_url = args.api_url or os.environ.get(ENV_API_URL) or cfg.get("api_url") or None

    if not api_key and _needs_key(args) and sys.stdin.isatty() and not args.json:
        api_key = _prompt_for_key()
        saved = save_config({"api_key": api_key, "api_url": api_url or ""})
        print(f"✓ API key saved to {saved}", file=sys.stderr)

    try:
        client = LiveAPISec(api_url=api_url, api_key=api_key)
        return int(args.func(client, args))
    except LiveAPISecError as exc:
        if _is_missing_key(exc) and sys.stdin.isatty() and not args.json and not api_key:
            api_key = _prompt_for_key()
            saved = save_config({"api_key": api_key, "api_url": api_url or ""})
            print(f"✓ API key saved to {saved}", file=sys.stderr)
            try:
                client = LiveAPISec(api_url=api_url, api_key=api_key)
                return int(args.func(client, args))
            except LiveAPISecError as exc2:
                print(f"error: {exc2}", file=sys.stderr)
                return 2
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _is_missing_key(exc: LiveAPISecError) -> bool:
    return exc.title == "Missing API key"


def _prompt_for_key() -> str:
    """Interactive first-run: explain where to find the key and read it."""
    print("No LiveAPISec API key found.", file=sys.stderr)
    print(
        "Generate one in the dashboard:  Settings → Developer API → Create API key", file=sys.stderr
    )
    print(f"  {DEFAULT_FRONTEND_URL}/settings", file=sys.stderr)
    print("The key looks like:  las_dev_...", file=sys.stderr)
    print("Tip: no key = only public endpoints can be tested.", file=sys.stderr)
    try:
        value = input("Paste your API key: ").strip()
    except (EOFError, KeyboardInterrupt):
        raise LiveAPISecError(None, "Missing API key", "no key provided") from None
    if not value:
        raise LiveAPISecError(None, "Missing API key", "no key provided")
    return value


def _cmd_config(client: LiveAPISec, args: argparse.Namespace) -> int:
    path = config_path()
    cfg = load_config()
    if args.clear:
        clear_config()
        print(f"removed config: {path}")
        return 0
    print(f"config: {path}")
    print(f"api_key: {'set' if cfg.get('api_key') else 'not set'}")
    print(f"api_url: {cfg.get('api_url') or '(default ' + DEFAULT_API_URL + ')'}")
    print()
    print("Where to find your key:  Settings → Developer API → Create API key")
    print(f"  {DEFAULT_FRONTEND_URL}/settings")
    print("You can also set the environment variables LIVEAPISEC_API_KEY / LIVEAPISEC_API_URL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
