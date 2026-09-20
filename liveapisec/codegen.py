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
_GO_SUFFIXES = (".go",)
_RS_SUFFIXES = (".rs",)

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

    go = [f for f in files if f.endswith(_GO_SUFFIXES)]
    for f in go:
        text = _read(f)
        if re.search(
            r"gin-gonic|labstack/echo|gofiber|go-chi|gorilla/mux|http\.HandleFunc|http\.Handle\(",
            text,
        ):
            return "go"

    rs = [f for f in files if f.endswith(_RS_SUFFIXES)]
    for f in files:
        if os.path.basename(f) == "Cargo.toml":
            text = _read(f)
            if re.search(r"\b(axum|actix-web|rocket|warp)\b", text):
                return "rust"
    for f in rs:
        text = _read(f)
        if re.search(
            r"use\s+axum|use\s+actix_web|use\s+rocket|use\s+warp|#\[(get|post|put|patch|delete)\(",
            text,
            re.IGNORECASE,
        ):
            return "rust"

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


# ------------------------------------------------- FastAPI prefix resolution
#
# FastAPI builds URLs from several pieces: the route decorator path, the
# `APIRouter(prefix=...)` and every `app.include_router(router, prefix=...)`.
# The old parser only read decorators, so it emitted "/accept-consent" instead
# of "/auth/accept-consent". This resolver walks the whole project (resolving
# imports across files) and reconstructs the full prefix chain.

_FASTAPI_ROUTER_CTORS = {"APIRouter", "FastAPI", "Blueprint"}


def _module_name(rel_path: str) -> str:
    p = rel_path.replace("\\", "/")
    p = p.removesuffix(".py")
    parts = [x for x in p.split("/") if x]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _str_kw(call: ast.Call, name: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _ctor_name(call: ast.Call) -> str | None:
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def _parse_fastapi(files: list[str], root: str) -> list[dict[str, str]]:
    """FastAPI parser resolving ``APIRouter(prefix=…)`` + ``include_router(…, prefix=…)``."""
    entries: dict[str, tuple[ast.Module, str, bool]] = {}
    for f in files:
        if not f.endswith(_PY_SUFFIXES):
            continue
        rel = _rel(root, f).replace("\\", "/")
        mod = _module_name(rel)
        if not mod:
            continue
        try:
            tree = ast.parse(_read(f))
        except SyntaxError:
            continue
        entries[mod] = (tree, rel, os.path.basename(f) == "__init__.py")

    own_prefix: dict[str, str] = {}
    local_module: dict[tuple[str, str], str] = {}
    local_symbol: dict[tuple[str, str], tuple[str, str]] = {}

    # Pass A — router definitions + imports (needed to resolve across files).
    for mod, (tree, _rel_path, is_pkg) in entries.items():
        package = mod if is_pkg else (mod.rsplit(".", 1)[0] if "." in mod else "")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if not isinstance(value, ast.Call):
                    continue
                if _ctor_name(value) not in _FASTAPI_ROUTER_CTORS:
                    continue
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        own_prefix[f"{mod}:{tgt.id}"] = _str_kw(value, "prefix") or ""
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    base = ""
                else:
                    base = package
                    for _ in range(node.level - 1):
                        base = base.rsplit(".", 1)[0] if "." in base else ""
                target = ".".join(x for x in (base, node.module or "") if x)
                for alias in node.names:
                    local = alias.asname or alias.name
                    full = f"{target}.{alias.name}" if target else alias.name
                    if full in entries:
                        local_module[(mod, local)] = full
                    else:
                        local_symbol[(mod, local)] = (target, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    local_module[(mod, local)] = alias.name if alias.asname else alias.name.split(".")[0]

    def _unique_var(name: str) -> str | None:
        hits = [k for k in own_prefix if k.endswith(f":{name}")]
        return hits[0] if len(hits) == 1 else None

    def resolve_key(mod: str, node: ast.AST) -> str | None:
        """Resolve a decorator/include_router target to a ``module:var`` key."""
        if isinstance(node, ast.Name):
            name = node.id
            if f"{mod}:{name}" in own_prefix:
                return f"{mod}:{name}"
            if (mod, name) in local_symbol:
                tmod, orig = local_symbol[(mod, name)]
                return f"{tmod}:{orig}"
            if (mod, name) in local_module:
                return f"{local_module[(mod, name)]}:"
            return _unique_var(name) or f"{mod}:{name}"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base = node.value.id
            if (mod, base) in local_module:
                return f"{local_module[(mod, base)]}:{node.attr}"
            if (mod, base) in local_symbol:
                tmod, orig = local_symbol[(mod, base)]
                if orig == base:
                    return f"{tmod}:{node.attr}"
            return _unique_var(node.attr)
        return None

    incoming: dict[str, list[tuple[str, str]]] = {}
    routes: list[tuple[str | None, list[dict[str, str]], str]] = []

    # Pass B — include_router edges + route decorators.
    for mod, (tree, rel, _is_pkg) in entries.items():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "include_router"
                and node.args
            ):
                parent = resolve_key(mod, node.func.value) or f"{mod}:__root__"
                child = resolve_key(mod, node.args[0])
                if child:
                    incoming.setdefault(child, []).append(
                        (parent, _str_kw(node, "prefix") or "")
                    )
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                infos = _routes_from_decorator(dec)
                if not infos:
                    continue
                ref = None
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    ref = resolve_key(mod, dec.func.value)
                routes.append((ref, infos, f"{rel}:{node.lineno}"))

    memo: dict[str, list[str]] = {}

    def prefix_at(key: str, stack: frozenset[str]) -> list[str]:
        if not stack and key in memo:
            return memo[key]
        base = own_prefix.get(key, "")
        edges = incoming.get(key, [])
        if not edges:
            res = [base]
        else:
            mounts: list[str] = []
            for parent, p in edges:
                if parent in stack:
                    continue
                for pre in prefix_at(parent, stack | {key}):
                    mounts.append(pre + p)
            res = [m + base for m in mounts] if mounts else [base]
        if not stack:
            memo[key] = res
        return res

    out: list[dict[str, str]] = []
    for ref, infos, source in routes:
        prefixes = prefix_at(ref, frozenset()) if ref else [""]
        for info in infos:
            for pre in prefixes:
                out.append(
                    {
                        "method": info["method"],
                        "path": _norm_path((pre or "") + info["path"]),
                        "source": source,
                    }
                )
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


# ---------------------------------------------------------------- Go


# Gin/Echo/Fiber/Chi: r.GET("/x"), e.POST("/x/:id"), app.Put(...)
_GO_METHOD_RE = re.compile(
    r"""\.(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*(['"])(?P<path>/.*?)\2""",
    re.IGNORECASE,
)
# stdlib net/http
_GO_HANDLE_RE = re.compile(
    r"""http\.(?:HandleFunc|Handle)\s*\(\s*(['"])(?P<path>/.*?)\1""",
)


def _parse_go(text: str, rel_path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in _GO_METHOD_RE.finditer(text):
        method = match.group("method").upper()
        if method == "ANY":
            method = "GET"
        out.append({"method": method, "path": _js_path(match.group("path")), "source": rel_path})
    for match in _GO_HANDLE_RE.finditer(text):
        # net/http handlers don't carry the HTTP method — assume GET.
        out.append({"method": "GET", "path": _js_path(match.group("path")), "source": rel_path})
    return out


# ---------------------------------------------------------------- Rust


# actix-web / rocket attribute macros: #[get("/x")], #[post("/x/{id}")], #[rocket::get("/x")]
_RUST_ATTR_RE = re.compile(
    r"""#\[(?:\w+::)?(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*(['"])(?P<path>.*?)\2""",
    re.IGNORECASE,
)
# axum: .route("/x", get(handler)) / post(...)
_RUST_AXUM_RE = re.compile(
    r"""\.route\s*\(\s*(['"])(?P<path>.*?)\1\s*,\s*(?P<method>get|post|put|patch|delete|head|options|any)\s*\(""",
    re.IGNORECASE,
)


def _parse_rust(text: str, rel_path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in _RUST_ATTR_RE.finditer(text):
        method = match.group("method").upper()
        out.append({"method": method, "path": _js_path(match.group("path")), "source": rel_path})
    for match in _RUST_AXUM_RE.finditer(text):
        method = match.group("method").upper()
        if method == "ANY":
            method = "GET"
        out.append({"method": method, "path": _js_path(match.group("path")), "source": rel_path})
    return out


# ---------------------------------------------------------------- main API


def scan_code(root: str, framework: str | None = None) -> ScanResult:
    """Discover endpoints under ``root`` (a directory or a single file)."""
    files = _collect(root)
    detected = framework or detect_framework(root, files)

    endpoints: list[dict[str, str]] = []
    if detected == "fastapi":
        endpoints.extend(_parse_fastapi(files, root))
    elif detected == "flask":
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
    elif detected == "go":
        for f in files:
            if f.endswith(_GO_SUFFIXES):
                endpoints.extend(_parse_go(_read(f), _rel(root, f)))
    elif detected == "rust":
        for f in files:
            if f.endswith(_RS_SUFFIXES):
                endpoints.extend(_parse_rust(_read(f), _rel(root, f)))

    return ScanResult(
        framework=detected,
        endpoints=_dedupe(endpoints),
        files_scanned=len(files),
    )
