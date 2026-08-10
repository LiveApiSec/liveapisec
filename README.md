# liveapisec — CLI/SDK for the LiveAPISec Developer API

Official, thin client for the **LiveAPISec Developer API**. Install it once,
use it in any project, script and CI/CD pipeline — no dashboard, no curl.

> **When to use this?** Instead of walking through the wizard in the dashboard,
> a developer pushes endpoints + an optional token from **their own**
> environment (CI/CD, agent, script). The token is generated on your side and
> encrypted server-side (AES-256).
> **Tip: no token = we only test what's public.**

---

## Installation

### One command (Linux / macOS) — recommended

```bash
curl -fsSL https://raw.githubusercontent.com/LiveApiSec/liveapisec/main/install.sh | bash
```

The installer uses `pipx` when available, otherwise it creates an isolated
virtualenv and symlinks the command into `~/.local/bin` — no `sudo`, and it
works on PEP 668 systems (Ubuntu 24.04+) where a plain `pip install` is
blocked. After installing, open a new terminal and run `liveapisec --help`.

### From PyPI (recommended for developers with pipx/venv)

```bash
pipx install liveapisec     # or: pip install liveapisec (inside a venv)
```

### From GitHub (if you prefer building from the repository)

```bash
pip install "liveapisec @ git+https://github.com/LiveApiSec/liveapisec.git"
```

Verify:

```bash
liveapisec --help
```

Install once (e.g. in a CI image, on a dev machine, in GitHub Actions) and the
`liveapisec` command is available **in every project** on that machine.

---

## Configuration

Generate an API key once in the dashboard: **Settings → Developer API → Create API key**
(the `las_dev_...` key is shown only once — store it as a secret).

### First run (interactive)

The first time you run a command that needs the API (e.g. `push`, `scan`), the CLI
asks for your key, shows you exactly where to find it, and **saves it** to
`~/.config/liveapisec/config.json` (mode `0600`). Next runs pick it up automatically:

```
$ liveapisec push --name my-api --base-url https://api.example.com ...
No LiveAPISec API key found.
Generate one in the dashboard:  Settings → Developer API → Create API key
  https://liveapisec.com/settings
The key looks like:  las_dev_...
Tip: no key = only public endpoints can be tested.
Paste your API key: las_dev_...
✓ API key saved to /home/you/.config/liveapisec/config.json
```

### Environment variables (recommended for CI)

```bash
export LIVEAPISEC_API_KEY=las_dev_...          # required
export LIVEAPISEC_API_URL=https://liveapisec.com   # optional (default)
```

Precedence: `--api-key` / `--api-url` flags → environment variables →
saved config file.

### Manage the saved key

```bash
liveapisec config        # show where the key is stored
liveapisec config --clear  # remove the saved config file
```

---

## Commands

### 1. `push` — push your API (idempotent, safe in CI)

```bash
liveapisec push \
  --name my-api \
  --base-url https://api.example.com \
  --endpoint "GET /users" \
  --endpoint "POST /payments"
```

- The same `name` + `base_url` = **the same site** (update, not a duplicate) —
  you can call push in every build.
- Instead of a list of endpoints you can provide an OpenAPI spec: `--openapi-url https://api.example.com/openapi.json`.
- Optional token: `--auth-type jwt --auth-token <TOKEN>` (or `bearer`,
  `cookie --auth-cookie "session=..."`, `api_key --auth-header X-API-Key`).

Output:

```
site 65f...abc: my-api — 2 endpoints, auth=none
export SITE_ID=65f...abc
```

### 2. `push-code` — scan your source code and push the endpoints

Point the CLI at a repo/folder and it detects the framework, extracts the API
endpoints from the code and pushes them — no running site or OpenAPI spec needed.

```bash
cd my-project
liveapisec push-code --dir . --name my-api --base-url https://api.example.com
```

- Auto-detected frameworks: **FastAPI**, **Flask**, **Django**, **Next.js**
  (`app/api` + `pages/api`), **NestJS** (`@Controller`/`@Get`), **Express**
  (`app.get`), **Laravel**, generic **PHP** (`$app->get`, Slim, Lumen),
  **Spring** (`@GetMapping`, Java), **Go** (Gin, Echo, Fiber, Chi, gorilla/mux,
  `net/http`) and **Rust** (axum, actix-web, rocket, warp).
- Scan a git repository straight from a URL (https / ssh / local path) —
  it is shallow-cloned to a temp dir and cleaned up afterwards:

```bash
liveapisec push-code --repo git@github.com:acme/my-api.git \
  --name my-api --base-url https://api.example.com
```

- Preview before pushing (no API key needed):

```bash
liveapisec push-code --dir . --name my-api --base-url https://api.example.com --dry-run
liveapisec push-code --dir . --name my-api --base-url https://api.example.com --dry-run --json
```

- Force a framework if auto-detection misses it: `--framework nextjs`.

Output:

```
framework: fastapi (42 files scanned)
found 58 endpoints:
  GET     /users
  POST    /payments
site 65f...abc: my-api — 58 endpoints, auth=none
export SITE_ID=65f...abc
```

> **Note on methods**: FastAPI/Flask/Express/NestJS/Spring/Laravel/Go/Rust carry
> the HTTP method in the code. Django `urlpatterns` and Go `net/http` handlers
> do not — those routes are assumed to be `GET`.

### 3. `scan` — run a security test

```bash
# fire and forget (202, does not wait)
liveapisec scan --site SITE_ID --branch main --commit "$GITHUB_SHA"

# wait for the result and fail the build on high (CI gate)
liveapisec scan --site SITE_ID --branch main --commit "$SHA" \
  --wait --fail-on high
```

- `--wait` — polls until the scan finishes (default timeout 600 s,
  interval 3 s; change with `--timeout` / `--poll-interval`).
- `--fail-on high` — **exit code 1** when a finding of severity `high`/`critical`
  is found; `--fail-on critical` only for criticals; omit it → always exit 0
  (except errors).

### 4. `status` — site status + recent scans

```bash
liveapisec status --site SITE_ID
```

### 5. `findings` — scan results

```bash
liveapisec findings --site SITE_ID --scan SCAN_ID
liveapisec findings --site SITE_ID --scan SCAN_ID --json   # raw data (for agents/AI)
```

### 6. `sites` — site details

```bash
liveapisec sites --site SITE_ID
```

---

## GitHub Actions — full example (gate on push)

```yaml
name: liveapisec
on: push
jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - name: Install CLI
        run: pip install "liveapisec @ git+https://github.com/LiveApiSec/liveapisec.git"
      - name: Push API + run security test (gate on high)
        env:
          LIVEAPISEC_API_KEY: ${{ secrets.LIVEAPISEC_KEY }}
        run: |
          liveapisec push --name my-api --base-url "$BASE_URL" \
            --endpoint "GET /users" --endpoint "POST /payments"
          liveapisec scan --site "$SITE_ID" \
            --branch "${GITHUB_REF#refs/heads/}" --commit "$GITHUB_SHA" \
            --wait --fail-on high
```

> **Why is push safe?** Push is idempotent (name+base_url → the same site), so
> the next build does not create junk — it updates endpoints and the token, and
> the next `scan` tests the latest state.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | OK (no findings at/above the threshold, or no `--fail-on`) |
| 1    | Gate failed — findings found at/above `--fail-on` |
| 2    | Usage error / API error / missing key |

---

## Development / tests

```bash
pip install -e ./cli[dev]
cd cli && python -m pytest tests/ -q
```

## SDK (API)

Besides the CLI, the package also exports a client for scripts:

```python
from liveapisec import LiveAPISec

api = LiveAPISec()  # LIVEAPISEC_API_KEY from env
site = api.create_site("my-api", "https://api.example.com",
                       endpoints=[{"method": "GET", "path": "/users"}])
scan = api.trigger_scan(site["site_id"], branch="main", commit="abc")
done = api.wait_for_scan(site["site_id"], scan["scan_id"])
blocked = LiveAPISec.findings_above(done["findings"], "high")
```

---

## Instructions for AI coding assistants (Copilot, Cursor, etc.)

Copy-paste the block below into your AI assistant (GitHub Copilot, Cursor,
Windsurf…) to let it use the LiveAPISec CLI on your behalf.

````markdown
You can use the `liveapisec` CLI (https://pypi.org/project/liveapisec/) to
push API specifications and run security scans against the LiveAPISec platform.

Environment:
- `LIVEAPISEC_API_KEY` — dev API key (las_dev_...), usually already set.
- `LIVEAPISEC_API_URL` — API base URL (default: https://liveapisec.com).
- `SITE_ID` — the site id returned by `liveapisec push` / `liveapisec sites`.

Workflow:
1. Push the API under test (idempotent — safe to repeat):
   `liveapisec push --name <name> --base-url <url> --endpoint "METHOD /path" [--endpoint ...] [--openapi-url <url>] [--auth-type jwt|bearer|cookie|api_key --auth-token <token>]`
2. Read the site id from the output (or `liveapisec sites --site <id>`).
3. Run a security scan and wait for the result:
   `liveapisec scan --site <site_id> --branch <branch> --commit <sha> --wait`
4. Read findings:
   `liveapisec findings --site <site_id> --scan <scan_id>` (add `--json` for raw JSON).
5. Check site status: `liveapisec status --site <site_id>`.

Rules:
- Never print or commit the API key; use the environment variable.
- If a scan fails, read `liveapisec findings --site <id> --scan <scan_id> --json`
  and summarize each finding (severity, title, target).
- Push is idempotent, so re-running it is always safe.
- Exit code 1 from `scan --wait --fail-on <sev>` means the gate failed
  (findings at/above that severity); exit 2 means usage/API error.
````
