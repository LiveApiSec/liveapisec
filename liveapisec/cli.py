"""liveapisec — CLI commands (TODO 2.25).

Commands:
  push      — create/update a site + endpoints + optional token (idempotent)
  push-code — scan source code (fastapi/flask/nextjs/laravel/php) and push endpoints
  scan      — run a scan; --wait waits for the result; --fail-on sets the CI gate
  status    — site status / recent scans
  findings  — list findings (--json)
  sites     — show a site (endpoints, last_scan)

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
        choices=["none", "jwt", "bearer", "cookie", "api_key", "oauth2"],
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
    if not args.endpoint and not args.openapi_url:
        print("error: provide at least one --endpoint or --openapi-url", file=sys.stderr)
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
        project=project,
        auth=auth,
        site_id=site_id,
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


def _cmd_push_code(client: LiveAPISec, args: argparse.Namespace) -> int:
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


def _cmd_scan(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.site:
        print("error: --site (site_id) is required", file=sys.stderr)
        return 2
    scan = client.trigger_scan(args.site, branch=args.branch, commit=args.commit)
    scan_id = scan["scan_id"]
    if args.json:
        print(LiveAPISec.dump(scan))
    else:
        print(f"scan queued: {scan_id}")
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
    return 0


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
        "--endpoint", action="append", type=_parse_endpoint, help="'METHOD /path' (repeatable)"
    )
    p_push.add_argument("--openapi-url", help="URL to OpenAPI spec instead of --endpoint")
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
        "push-code",
        help="scan source code for endpoints and push them (fastapi/flask/django/nextjs/nestjs/express/laravel/php/spring/go/rust)",
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
    p_code.add_argument("--site", help="existing site_id to update (PUT)")
    p_code.add_argument("--dry-run", action="store_true", help="scan + list endpoints, do not push")
    p_code.add_argument(
        "--verify",
        action="store_true",
        help="probe the first endpoint with the pushed auth (catch bad tokens early)",
    )
    _auth_args(p_code)
    _json_flag(p_code)
    p_code.set_defaults(func=_cmd_push_code)

    p_scan = sub.add_parser("scan", help="run a security scan (optionally wait + gate)")
    p_scan.add_argument("--site", required=True)
    p_scan.add_argument("--branch")
    p_scan.add_argument("--commit")
    p_scan.add_argument("--wait", action="store_true", help="poll until finished")
    p_scan.add_argument(
        "--fail-on", choices=_SEV, help="exit 1 if findings at/above this severity (default: high)"
    )
    p_scan.add_argument("--poll-interval", type=float, default=3.0)
    p_scan.add_argument("--timeout", type=float, default=600.0)
    _json_flag(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    p_status = sub.add_parser("status", help="site status + recent scans")
    p_status.add_argument("--site", required=True)
    _json_flag(p_status)
    p_status.set_defaults(func=_cmd_status)

    p_find = sub.add_parser("findings", help="list findings for a scan")
    p_find.add_argument("--site", required=True)
    p_find.add_argument("--scan", required=True)
    _json_flag(p_find)
    p_find.set_defaults(func=_cmd_findings)

    p_sites = sub.add_parser("sites", help="show a site")
    p_sites.add_argument("--site", required=True)
    _json_flag(p_sites)
    p_sites.set_defaults(func=_cmd_sites)

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

    return parser


def _needs_key(args: argparse.Namespace) -> bool:
    if args.command == "config":
        return False
    return not (args.command == "push-code" and getattr(args, "dry_run", False))


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
    print(f"  {DEFAULT_API_URL}/settings", file=sys.stderr)
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
    print(f"  {DEFAULT_API_URL}/settings")
    print("You can also set the environment variables LIVEAPISEC_API_KEY / LIVEAPISEC_API_URL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
