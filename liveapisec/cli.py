"""liveapisec — CLI commands (TODO 2.25).

Commands:
  push      — create/update a site + endpoints + optional token (idempotent)
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
import sys
from typing import Any

from .client import DEFAULT_API_URL, LiveAPISec, LiveAPISecError

_SEV = ["critical", "high", "medium", "low", "info"]


def _parse_endpoint(value: str) -> dict[str, str]:
    """'GET /users' → {"method":"GET","path":"/users"}."""
    parts = value.split(None, 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"expected 'METHOD /path', got {value!r}")
    method, path = parts
    return {"method": method.upper(), "path": path}


def _auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth-type", choices=["none", "jwt", "bearer", "cookie", "api_key"], default="none")
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
        sev = " ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda kv: _SEV.index(kv[0]) if kv[0] in _SEV else 9))
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
        print(f"site {site['site_id']}{updated}: {site['name']} — {site['endpoints_count']} endpoints, auth={site['auth']}")
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
                print(f"\n❌ {len(blocked)} finding(s) at or above {gate_sev} — gate failed:", file=sys.stderr)
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
    parser.add_argument("--api-url", help=f"API base URL (default: $LIVEAPISEC_API_URL or {DEFAULT_API_URL})")
    parser.add_argument("--api-key", help="dev API key las_dev_... (default: $LIVEAPISEC_API_KEY)")
    parser.add_argument("--json", action="store_true", help="print raw JSON output")
    sub = parser.add_subparsers(dest="command", required=True)

    def _json_flag(p: argparse.ArgumentParser) -> None:
        # --json also works after the subcommand name (e.g. `findings ... --json`)
        p.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    p_push = sub.add_parser("push", help="create/update a site (idempotent)")
    p_push.add_argument("--name", required=True)
    p_push.add_argument("--base-url")
    p_push.add_argument("--project")
    p_push.add_argument("--endpoint", action="append", type=_parse_endpoint, help="'METHOD /path' (repeatable)")
    p_push.add_argument("--openapi-url", help="URL to OpenAPI spec instead of --endpoint")
    p_push.add_argument("--site", help="existing site_id to update (PUT)")
    _auth_args(p_push)
    _json_flag(p_push)
    p_push.set_defaults(func=_cmd_push)

    p_scan = sub.add_parser("scan", help="run a security scan (optionally wait + gate)")
    p_scan.add_argument("--site", required=True)
    p_scan.add_argument("--branch")
    p_scan.add_argument("--commit")
    p_scan.add_argument("--wait", action="store_true", help="poll until finished")
    p_scan.add_argument("--fail-on", choices=_SEV, help="exit 1 if findings at/above this severity (default: high)")
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.json = bool(getattr(args, "json", False))
    try:
        client = LiveAPISec(api_url=args.api_url, api_key=args.api_key)
    except LiveAPISecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        return int(args.func(client, args))
    except LiveAPISecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
