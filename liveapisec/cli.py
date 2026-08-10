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


def _parse_endpoint(value: str) -> dict[str, str]:
    """'GET /users' → {"method":"GET","path":"/users"}."""
    parts = value.split(None, 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"expected 'METHOD /path', got {value!r}")
    method, path = parts
    return {"method": method.upper(), "path": path}


def _auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth-type", choices=["none", "jwt", "bearer", "cookie", "api_key"], default="none"
    )
    parser.add_argument("--auth-token", help="token for jwt/bearer/api_key")
    parser.add_argument("--auth-cookie", help="full Cookie header for type=cookie")
    parser.add_argument("--auth-header", default="X-API-Key", help="header name for api_key")


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
    return auth


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
    line = f"[{sev}] {title}"
    if target:
        line += f"  ({target})"
    return line


def _cmd_push(client: LiveAPISec, args: argparse.Namespace) -> int:
    if not args.name:
        print("error: --name is required", file=sys.stderr)
        return 2
    if not args.base_url and not args.site:
        print("error: --base-url is required", file=sys.stderr)
        return 2
    if not args.endpoint and not args.openapi_url:
        print("error: provide at least one --endpoint or --openapi-url", file=sys.stderr)
        return 2
    auth = _build_auth(args)
    if auth and args.auth_type in ("jwt", "bearer", "api_key") and not args.auth_token:
        print(f"error: --auth-token required for auth-type={args.auth_type}", file=sys.stderr)
        return 2
    if auth and args.auth_type == "cookie" and not args.auth_cookie:
        print("error: --auth-cookie required for auth-type=cookie", file=sys.stderr)
        return 2

    site = client.create_site(
        name=args.name,
        base_url=args.base_url,
        endpoints=args.endpoint,
        openapi_url=args.openapi_url,
        project=args.project,
        auth=auth,
        site_id=args.site,
    )
    if args.json:
        print(LiveAPISec.dump(site))
    else:
        updated = " (updated)" if site.get("updated") else ""
        print(
            f"site {site['site_id']}{updated}: {site['name']} — {site['endpoints_count']} endpoints, auth={site['auth']}"
        )
        print(f"export SITE_ID={site['site_id']}")
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
    if not args.name:
        print("error: --name is required", file=sys.stderr)
        return 2
    if not args.base_url:
        print("error: --base-url is required", file=sys.stderr)
        return 2
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
            else " — could not detect a supported framework (fastapi/flask/django/nextjs/nestjs/express/laravel/php/spring)"
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
            print(f"framework: {fw} ({result.files_scanned} files scanned)")
            print(f"found {len(endpoints)} endpoints (dry-run — not pushed):")
            for e in endpoints:
                print(f"  {e['method']:7} {e['path']}")
        return 0

    if not args.json:
        fw = result.framework or "?"
        print(f"framework: {fw} ({result.files_scanned} files scanned)")
        print(f"found {len(endpoints)} endpoints:")
        for e in endpoints:
            print(f"  {e['method']:7} {e['path']}")

    auth = _build_auth(args)
    push_endpoints = [{"method": e["method"], "path": e["path"]} for e in endpoints]
    site = client.create_site(
        name=args.name,
        base_url=args.base_url,
        endpoints=push_endpoints,
        project=args.project,
        auth=auth,
        site_id=args.site,
    )
    if args.json:
        print(LiveAPISec.dump(site))
    else:
        updated = " (updated)" if site.get("updated") else ""
        print(
            f"site {site['site_id']}{updated}: {site['name']} — {site['endpoints_count']} endpoints, auth={site['auth']}"
        )
        print(f"export SITE_ID={site['site_id']}")
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
                    f"\n❌ {len(blocked)} finding(s) at or above {gate_sev} — gate failed:",
                    file=sys.stderr,
                )
                for f in blocked:
                    print("  " + _fmt_finding(f), file=sys.stderr)
            return 1
        if not args.json:
            print(f"✅ no findings at or above {gate_sev}")
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
    p_push.add_argument("--name", required=True)
    p_push.add_argument("--base-url")
    p_push.add_argument("--project")
    p_push.add_argument(
        "--endpoint", action="append", type=_parse_endpoint, help="'METHOD /path' (repeatable)"
    )
    p_push.add_argument("--openapi-url", help="URL to OpenAPI spec instead of --endpoint")
    p_push.add_argument("--site", help="existing site_id to update (PUT)")
    _auth_args(p_push)
    _json_flag(p_push)
    p_push.set_defaults(func=_cmd_push)

    p_code = sub.add_parser(
        "push-code",
        help="scan source code for endpoints and push them (fastapi/flask/django/nextjs/nestjs/express/laravel/php/spring)",
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
        ],
        help="force framework (default: auto-detect)",
    )
    p_code.add_argument("--name", required=True)
    p_code.add_argument("--base-url", required=True)
    p_code.add_argument("--project")
    p_code.add_argument("--site", help="existing site_id to update (PUT)")
    p_code.add_argument("--dry-run", action="store_true", help="scan + list endpoints, do not push")
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
