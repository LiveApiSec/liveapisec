"""Static code scanning — discover API endpoints from source code.

Supports FastAPI, Flask, Django, Next.js, NestJS, Express, Laravel, generic PHP
routers and Spring (Java). Used by the `liveapisec push-code` command so a
developer can point at a repo/folder and get a list of endpoints pushed to
LiveAPISec without a running site or OpenAPI spec.

Endpoints are returned as ``{"method": "GET", "path": "/users", "source": "..."}``.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field

_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_METHOD_ORDER = {m: i for i, m in enumerate(_HTTP_METHODS)}

# Directories always skipped while walking the tree.
_SKIP_DIRS = {
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "vendor",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "target",
    "coverage",
    ".idea",
    ".vscode",
    ".ruff_cache",
    "htmlcov",
    ".gradle",
}

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_PHP_SUFFIXES = (".php",)
_JAVA_SUFFIXES = (".java",)

_MAX_FILES = 5000


@dataclass
class ScanResult:
    """Outcome of a code scan."""

    framework: str | None
    endpoints: list[dict[str, str]]
    files_scanned: int
    markers: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- helpers


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _is_skip_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.startswith(".")


def _iter_files(root: str) -> list[str]:
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _is_skip_dir(d)]
        for fn in filenames:
            files.append(os.path.join(dirpath, fn))
        if len(files) >= _MAX_FILES:
            break
    return files


def _collect(root: str) -> list[str]:
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        return []
    return _iter_files(root)


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _norm_path(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    p = re.sub(r"/{2,}", "/", p)
    return p.rstrip("/") or "/"


def _dedupe(eps: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for e in eps:
        key = (e["method"], e["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    out.sort(key=lambda e: (e["path"], _METHOD_ORDER.get(e["method"], 99)))
    return out


# ---------------------------------------------------------------- detection


def detect_framework(root: str, files: list[str]) -> str | None:
    """Best-effort framework detection.

    Order: fastapi > flask > django > nextjs > nestjs > express > laravel > php > spring.
    """
    py = [f for f in files if f.endswith(_PY_SUFFIXES)]
    ts = [f for f in files if f.endswith(_TS_SUFFIXES)]
    php = [f for f in files if f.endswith(_PHP_SUFFIXES)]
    java = [f for f in files if f.endswith(_JAVA_SUFFIXES)]

    for f in py:
        text = _read(f)
        if re.search(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b", text):
            return "fastapi"
        if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b", text):
            return "flask"
        if re.search(r"\bfrom\s+django\b|\bimport\s+django\b|django\.urls|django\.conf", text):
            return "django"

    rel = [os.path.relpath(f, root).replace("\\", "/") for f in files]
    if any(re.search(r"(^|/)app/api/", r) or re.search(r"(^|/)pages/api/", r) for r in rel):
        return "nextjs"
    for f in ts:
        text = _read(f)
        if re.search(r"\bfrom\s+['\"]next/", text):
            return "nextjs"
    if any(
        os.path.basename(f) in ("next.config.js", "next.config.mjs", "next.config.ts")
        for f in files
    ):
        return "nextjs"

    for f in ts:
        text = _read(f)
        if re.search(r"@nestjs|from\s+['\"]@nestjs/", text):
            return "nestjs"
        if re.search(r"require\s*\(\s*['\"]express|from\s+['\"]express", text):
            return "express"

    if any(os.path.basename(f) == "artisan" for f in files):
        return "laravel"
    for f in php:
        text = _read(f)
        if re.search(r"\buse\s+Illuminate\\", text) or re.search(
            r"\bRoute::(get|post|put|patch|delete)\b", text
        ):
            return "laravel"
    if any(re.search(r"(^|/)routes/(web|api)\.php$", r) for r in rel):
        return "laravel"

    for f in java:
        text = _read(f)
        if re.search(
            r"org\.springframework\.web\.bind\.annotation|@(Get|Post|Put|Patch|Delete|Request)Mapping",
            text,
        ):
            return "spring"

    if php:
        return "php"
    if py:
        # Python project but no FastAPI/Flask/Django marker — maybe still a frameworkless API.
        return None
    return None


# ---------------------------------------------------------------- FastAPI/Flask


def _methods_kwarg(dec: ast.Call) -> list[str]:
    for kw in dec.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            return [
                e.value.upper()
                for e in kw.value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
    return []


def _routes_from_decorator(dec: ast.expr) -> list[dict[str, str]]:
    """Map ``@app.get('/x')`` / ``@app.route('/x', methods=[...])`` to endpoint(s)."""
    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
        return []
    attr = dec.func.attr
    methods: list[str] = []
    if attr in ("get", "post", "put", "patch", "delete", "head", "options"):
        methods = [attr.upper()]
    elif attr in ("route", "api_route", "add_api_route", "add_route"):
        methods = _methods_kwarg(dec) or ["GET"]
    else:
        return []
    if not dec.args:
        return []
    first = dec.args[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return []
    path = _norm_path(first.value)
    return [{"method": m, "path": path} for m in methods]


def _parse_python(text: str, rel_path: str) -> list[dict[str, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[dict[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            for info in _routes_from_decorator(dec):
                info["source"] = f"{rel_path}:{node.lineno}"
                out.append(info)
    return out


# ---------------------------------------------------------------- Django


_DJANGO_URL_RE = re.compile(
    r"""\b(?:path|re_path|url)\s*\(\s*(?:r)?(['"])(?P<path>.*?)\1(?P<tail>[^)]*?)\)""", re.DOTALL
)


def _django_path(p: str) -> str:
    # path('users/<int:pk>/') and re_path(r'(?P<pk>\d+)/') -> /users/{pk}
    p = re.sub(r"^[^^]*?\^", "", p)  # strip leading ^ (if present)
    p = re.sub(r"\$$", "", p)  # strip trailing $ (if present)
    p = re.sub(r"<[^:>]+:(?P<n>[^>]+)>", r"{\g<n>}", p)
    p = re.sub(r"\(\?P<(?P<n>[^>]+)>[^)]*\)", r"{\g<n>}", p)
    return _norm_path(p)


def _parse_django(text: str, rel_path: str) -> list[dict[str, str]]:
    # Only files that declare urlpatterns (or import django.urls) are routes.
    if "urlpatterns" not in text and "django.urls" not in text:
        return []
    out: list[dict[str, str]] = []
    for match in _DJANGO_URL_RE.finditer(text):
        raw = match.group("path").strip()
        tail = match.group("tail")
        if not raw or "include(" in tail:
            continue
        # Django urlpatterns don't carry the HTTP method — assume GET.
        out.append({"method": "GET", "path": _django_path(raw), "source": rel_path})
    return out


# ---------------------------------------------------------------- Next.js


def _next_path_from_rel(rel: str) -> str | None:
    rel = rel.replace("\\", "/")
    if "/app/" in rel:
        rest = rel.split("/app/", 1)[1]
        parts = rest.split("/")
        if not parts or not parts[-1].startswith("route."):
            return None
        parts = parts[:-1]
        if not parts:
            seg = "/"
        else:
            seg = "/" + "/".join(parts)
    elif rel.startswith("app/"):
        rest = rel[len("app/") :]
        parts = rest.split("/")
        if not parts or not parts[-1].startswith("route."):
            return None
        parts = parts[:-1]
        seg = "/" + "/".join(parts) if parts else "/"
    elif "/pages/api/" in rel:
        rest = rel.split("/pages/api/", 1)[1]
        parts = rest.split("/")
        last = re.sub(r"\.[^.]+$", "", parts[-1])
        if last == "index":
            parts = parts[:-1]
        else:
            parts[-1] = last
        seg = "/api" + (("/" + "/".join(parts)) if parts else "")
    elif rel.startswith("pages/api/"):
        rest = rel[len("pages/api/") :]
        parts = rest.split("/")
        last = re.sub(r"\.[^.]+$", "", parts[-1])
        if last == "index":
            parts = parts[:-1]
        else:
            parts[-1] = last
        seg = "/api" + (("/" + "/".join(parts)) if parts else "")
    else:
        return None
    seg = re.sub(r"\[\.\.\.([^\]]+)\]", r"{...\1}", seg)
    seg = re.sub(r"\[([^\]]+)\]", r"{\1}", seg)
    return _norm_path(seg)


_METHOD_EXPORT_FN_RE = re.compile(
    r"\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.IGNORECASE
)
_METHOD_EXPORT_CONST_RE = re.compile(
    r"\bexport\s+(?:const|let|var)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=", re.IGNORECASE
)


def _next_methods(text: str) -> list[str]:
    methods = set(_METHOD_EXPORT_FN_RE.findall(text))
    methods |= set(_METHOD_EXPORT_CONST_RE.findall(text))
    if methods:
        return sorted(m.upper() for m in methods)
    return ["GET"]  # default handler


def _parse_nextjs(files: list[str], root: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for f in files:
        if not f.endswith(_TS_SUFFIXES):
            continue
        rel = os.path.relpath(f, root).replace("\\", "/")
        path = _next_path_from_rel(rel)
        if path is None:
            continue
        text = _read(f)
        for method in _next_methods(text):
            out.append({"method": method, "path": path, "source": rel})
    return out


# ---------------------------------------------------------------- NestJS


_NEST_CONTROLLER_RE = re.compile(r"""@Controller\s*\(\s*(['"])(?P<prefix>.*?)\1\s*\)""")
_NEST_METHOD_RE = re.compile(
    r"""@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*(?:(['"])(?P<path>.*?)\2)?\s*\)""",
    re.IGNORECASE,
)


def _js_path(p: str) -> str:
    # Express/NestJS :param and * -> {param}
    p = re.sub(r":([A-Za-z_][\w]*)", r"{\1}", p)
    p = re.sub(r"\*", "{param}", p)
    return _norm_path(p)


def _parse_nestjs(text: str, rel_path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    prefix = ""
    for line in text.splitlines():
        m = _NEST_CONTROLLER_RE.search(line)
        if m:
            prefix = m.group("prefix").strip()
            continue
        m = _NEST_METHOD_RE.search(line)
        if m:
            method = m.group(1).upper()
            p = (m.group("path") or "").strip()
            if method == "ALL":
                method = "GET"
            full = (prefix + "/" + p) if (prefix and p) else (prefix or p)
            out.append({"method": method, "path": _js_path(full), "source": rel_path})
    return out


# ---------------------------------------------------------------- Express


_EXPRESS_PATTERNS: list[tuple[re.Pattern, int, int]] = [
    # app.get('/path', ...) / router.post('/path', ...) / api.put(...)
    (
        re.compile(
            r"""\b(?:app|router|route|api|server|express)\.(get|post|put|patch|delete|head|options|all)\s*\(\s*(['"])(.*?)\2""",
            re.IGNORECASE,
        ),
        1,
        3,
    ),
]


def _parse_express(text: str, rel_path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for pattern, m_group, p_group in _EXPRESS_PATTERNS:
        for match in pattern.finditer(text):
            method = match.group(m_group).lower()
            if method == "all":
                method = "get"
            raw = match.group(p_group)
            # Skip mount points like app.use('/api', router) — no method matched anyway.
            path = _js_path(raw)
            out.append({"method": method.upper(), "path": path, "source": rel_path})
    return out


# ---------------------------------------------------------------- Laravel / PHP


_PHP_PATTERNS: list[tuple[re.Pattern, int, int]] = [
    # Route::get('path', ...)  (Laravel)
    (
        re.compile(
            r"""Route::(get|post|put|patch|delete|options|any)\s*\(\s*(['"])(.*?)\2""",
            re.IGNORECASE,
        ),
        1,
        3,
    ),
    # $app->get('path', ...) / $router->post('path', ...)  (Slim / Lumen)
    (
        re.compile(
            r"""\$(?:app|router|route)->(get|post|put|patch|delete|options)\s*\(\s*(['"])(.*?)\2""",
            re.IGNORECASE,
        ),
        1,
        3,
    ),
    # ->addRoute('GET', 'path', ...)
    (
        re.compile(
            r"""->(?:addRoute|map)\s*\(\s*(['"])(get|post|put|patch|delete|options|any)\1\s*,\s*(['"])(.*?)\3""",
            re.IGNORECASE,
        ),
        2,
        4,
    ),
]


def _norm_php_path(p: str) -> str:
    p = re.sub(r"\{([^}:?]+)(?:\?|:[^}]*)?\}", r"{\1}", p)
    return _norm_path(p)


def _parse_php(text: str, rel_path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for pattern, m_group, p_group in _PHP_PATTERNS:
        for match in pattern.finditer(text):
            method = match.group(m_group).lower()
            if method == "any":
                method = "get"
            path = _norm_php_path(match.group(p_group))
            out.append({"method": method.upper(), "path": path, "source": rel_path})
    return out


# ---------------------------------------------------------------- Spring (Java)


_SPRING_SIMPLE_RE = re.compile(
    r"""@(?P<method>Get|Post|Put|Patch|Delete|Head|Options)Mapping\s*\(\s*(['"])(?P<path>.*?)\2""",
    re.IGNORECASE,
)
_SPRING_REQUEST_RE = re.compile(
    r"""@RequestMapping\s*\(\s*(?:value\s*=\s*)?(['"])(?P<path>.*?)\1(?P<rest>.*?)\)""",
    re.IGNORECASE | re.DOTALL,
)
_SPRING_METHOD_KW_RE = re.compile(
    r"""method\s*=\s*(?:RequestMethod\.)?(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)""",
    re.IGNORECASE,
)


def _parse_spring(text: str, rel_path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in _SPRING_SIMPLE_RE.finditer(text):
        method = match.group("method").upper()
        path = _norm_path(match.group("path"))
        out.append({"method": method, "path": path, "source": rel_path})
    for match in _SPRING_REQUEST_RE.finditer(text):
        raw_path = match.group("path").strip()
        rest = match.group("rest")
        m = _SPRING_METHOD_KW_RE.search(rest)
        method = m.group("method").upper() if m else "GET"
        if raw_path:
            out.append({"method": method, "path": _norm_path(raw_path), "source": rel_path})
    return out


# ---------------------------------------------------------------- main API


def scan_code(root: str, framework: str | None = None) -> ScanResult:
    """Discover endpoints under ``root`` (a directory or a single file)."""
    files = _collect(root)
    detected = framework or detect_framework(root, files)

    endpoints: list[dict[str, str]] = []
    if detected in ("fastapi", "flask"):
        for f in files:
            if f.endswith(_PY_SUFFIXES):
                endpoints.extend(_parse_python(_read(f), _rel(root, f)))
    elif detected == "django":
        for f in files:
            if f.endswith(_PY_SUFFIXES):
                endpoints.extend(_parse_django(_read(f), _rel(root, f)))
    elif detected == "nextjs":
        endpoints = _parse_nextjs(files, root)
    elif detected == "nestjs":
        for f in files:
            if f.endswith(_TS_SUFFIXES):
                endpoints.extend(_parse_nestjs(_read(f), _rel(root, f)))
    elif detected == "express":
        for f in files:
            if f.endswith(_TS_SUFFIXES):
                endpoints.extend(_parse_express(_read(f), _rel(root, f)))
    elif detected in ("laravel", "php"):
        for f in files:
            if f.endswith(_PHP_SUFFIXES):
                endpoints.extend(_parse_php(_read(f), _rel(root, f)))
    elif detected == "spring":
        for f in files:
            if f.endswith(_JAVA_SUFFIXES):
                endpoints.extend(_parse_spring(_read(f), _rel(root, f)))

    return ScanResult(
        framework=detected,
        endpoints=_dedupe(endpoints),
        files_scanned=len(files),
    )
