# liveapisec — CLI/SDK do LiveAPISec Developer API

Oficjalny, cienki klient do **LiveAPISec Developer API**. Instalujesz raz,
używasz w dowolnym projekcie, skrypcie i pipeline CI/CD — bez dashboardu i bez curl.

> **Kiedy to jest?** Zamiast ręcznie przechodzić kreatora w panelu, developer
> pushuje endpointy + opcjonalny token z **swojego** środowiska (CI/CD, agent,
> skrypt). Token jest generowany u Ciebie i szyfrowany po stronie serwera (AES-256).
> **Tip: brak tokena = testujemy tylko to, co publiczne.**

---

## Instalacja

Z GitHub (rekomendowane, zanim trafimy na PyPI):

```bash
pip install "liveapisec @ git+https://github.com/LiveApiSec/liveapisec.git"
```

Po publikacji na PyPI:

```bash
pip install liveapisec
```

Sprawdź:

```bash
liveapisec --help
```

Kiedy zainstalujesz raz (np. w obrazie CI, na maszynie dev, w GitHub Actions) —
komenda `liveapisec` jest dostępna **w każdym projekcie** w tej maszynie.

---

## Konfiguracja

Klucz API generujesz raz w panelu: **Settings → Developer API → Create API key**
(klucz `las_dev_...` pokazywany jest tylko raz — trzymaj go jako secret).

```bash
export LIVEAPISEC_API_KEY=las_dev_...          # wymagane
export LIVEAPISEC_API_URL=https://liveapisec.com   # opcjonalne (domyślne)
```

Można też podać per-komenda: `--api-key` / `--api-url`.

---

## Komendy

### 1. `push` — wyślij API (idempotentne, bezpieczne w CI)

```bash
liveapisec push \
  --name my-api \
  --base-url https://api.example.com \
  --endpoint "GET /users" \
  --endpoint "POST /payments"
```

- Ten sam `name` + `base_url` = **ten sam site** (aktualizacja, nie duplikat) —
  możesz wołać push w każdym buildzie.
- Zamiast listy endpointów możesz podać OpenAPI: `--openapi-url https://api.example.com/openapi.json`.
- Opcjonalny token: `--auth-type jwt --auth-token <TOKEN>` (albo `bearer`,
  `cookie --auth-cookie "session=..."`, `api_key --auth-header X-API-Key`).

Wynik:

```
site 65f...abc: my-api — 2 endpoints, auth=none
export SITE_ID=65f...abc
```

### 2. `scan` — odpal test bezpieczeństwa

```bash
# zwykłe odpalanie (202, nie czeka)
liveapisec scan --site SITE_ID --branch main --commit "$GITHUB_SHA"

# czekaj na wynik i próg błędu dla CI (gate)
liveapisec scan --site SITE_ID --branch main --commit "$SHA" \
  --wait --fail-on high
```

- `--wait` — polluje aż skan się zakończy (domyślnie timeout 600 s,
  interwał 3 s; zmiana przez `--timeout` / `--poll-interval`).
- `--fail-on high` — **exit code 1** gdy znajdzie finding severity `high`/`critical`;
  `--fail-on critical` tylko przy krytycznych; pomiń → zawsze exit 0 (poza błędami).

### 3. `status` — stan site'a i ostatnich skanów

```bash
liveapisec status --site SITE_ID
```

### 4. `findings` — wyniki skanu

```bash
liveapisec findings --site SITE_ID --scan SCAN_ID
liveapisec findings --site SITE_ID --scan SCAN_ID --json   # surowe dane (dla agenta/AI)
```

### 5. `sites` — szczegóły site'a

```bash
liveapisec sites --site SITE_ID
```

---

## GitHub Actions — pełny przykład (gate na push)

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

> **Dlaczego push jest bezpieczny?** Push jest idempotentny (name+base_url →
> ten sam site), więc kolejny build nie tworzy śmieci — aktualizuje endpointy
> i token, a następny `scan` testuje najnowszy stan.

---

## Exit codes

| Code | Znaczenie |
|------|-----------|
| 0    | OK (brak findings ≥ progu, lub bez `--fail-on`) |
| 1    | Gate failed — znaleziono findings ≥ `--fail-on` |
| 2    | Błąd użycia / błąd API / brak klucza |

---

## Rozwój / testy

```bash
pip install -e ./cli[dev]
cd cli && python -m pytest tests/ -q
```

## API (SDK)

Poza CLI pakiet eksportuje też klienta do skryptów:

```python
from liveapisec import LiveAPISec

api = LiveAPISec()  # LIVEAPISEC_API_KEY z env
site = api.create_site("my-api", "https://api.example.com",
                       endpoints=[{"method": "GET", "path": "/users"}])
scan = api.trigger_scan(site["site_id"], branch="main", commit="abc")
done = api.wait_for_scan(site["site_id"], scan["scan_id"])
blocked = LiveAPISec.findings_above(done["findings"], "high")
```
