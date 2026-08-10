"""Tests for static code scanning + `push-code` command (TODO 2.25)."""

from __future__ import annotations

import json

import httpx
import pytest

from liveapisec.cli import _cmd_push_code, main
from liveapisec.client import LiveAPISec
from liveapisec.codegen import detect_framework, scan_code


def _client(handler) -> LiveAPISec:
    return LiveAPISec(
        api_url="https://liveapisec.test",
        api_key="las_dev_test",
        transport=httpx.MockTransport(handler),
    )


def _write(tmp_path, rel: str, content: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------- FastAPI


def test_scan_fastapi(tmp_path) -> None:
    _write(
        tmp_path,
        "app/main.py",
        """from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
def list_users(): ...

@app.post("/payments/{id}")
def pay(id: str): ...

@app.api_route("/health", methods=["GET", "POST"])
def health(): ...

@app.on_event("startup")
def noop(): ...
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "fastapi"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/payments/{id}") in eps
    assert ("GET", "/health") in eps
    assert ("POST", "/health") in eps
    # @app.on_event is not a route
    assert all(not e["path"].startswith("/startup") for e in result.endpoints)


# ---------------------------------------------------------------- Flask


def test_scan_flask(tmp_path) -> None:
    _write(
        tmp_path,
        "app.py",
        """from flask import Flask
app = Flask(__name__)

@app.route("/users", methods=["POST"])
def create_user(): ...

@app.get("/health")
def health(): ...

@app.route("/plain")
def plain(): ...
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "flask"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("POST", "/users") in eps
    assert ("GET", "/health") in eps
    assert ("GET", "/plain") in eps


# ---------------------------------------------------------------- Next.js


def test_scan_nextjs(tmp_path) -> None:
    _write(
        tmp_path,
        "app/api/users/route.ts",
        """import { NextResponse } from 'next/server'
export async function GET() { return NextResponse.json([]) }
export async function POST(req) { return NextResponse.json({}) }
""",
    )
    _write(
        tmp_path,
        "app/api/users/[id]/route.ts",
        """export async function GET(_: any, { params }: any) {
  return Response.json({ id: params.id })
}
""",
    )
    _write(
        tmp_path,
        "pages/api/login.ts",
        """export default function handler(req, res) { res.status(200).end() }
""",
    )
    _write(tmp_path, "components/Card.tsx", "export default function Card() { return null }")
    result = scan_code(str(tmp_path))
    assert result.framework == "nextjs"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/api/users") in eps
    assert ("POST", "/api/users") in eps
    assert ("GET", "/api/users/{id}") in eps
    assert ("GET", "/api/login") in eps
    # components/Card.tsx is not an API route
    assert ("GET", "/Card") not in eps


# ---------------------------------------------------------------- Laravel / PHP


def test_scan_laravel(tmp_path) -> None:
    _write(
        tmp_path,
        "routes/api.php",
        """<?php
use Illuminate\\Support\\Facades\\Route;
Route::get('/users', 'UserController@index');
Route::post('/users/{id}', 'UserController@update');
Route::get('/items/{id?}', 'ItemController@show');
Route::any('/catchall', 'CatchController@index');
""",
    )
    _write(tmp_path, "artisan", "#!/usr/bin/env php\n")
    result = scan_code(str(tmp_path))
    assert result.framework == "laravel"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/users/{id}") in eps
    assert ("GET", "/items/{id}") in eps  # {id?} -> {id}
    assert ("GET", "/catchall") in eps  # any -> get


def test_scan_php_slim(tmp_path) -> None:
    _write(
        tmp_path,
        "index.php",
        """<?php
$app->get('/status', function ($req, $res) { return $res; });
$router->post('/hooks', 'HookController@store');
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "php"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/status") in eps
    assert ("POST", "/hooks") in eps


# ---------------------------------------------------------------- Django


def test_scan_django(tmp_path) -> None:
    _write(
        tmp_path,
        "myapp/urls.py",
        """from django.urls import path
from . import views
urlpatterns = [
    path('users/', views.list_users),
    path('users/<int:pk>/', views.user_detail),
    re_path(r'^items/(?P<slug>[-\\w]+)/$', views.item),
    path('admin/', include('admin.urls')),
]
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "django"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("GET", "/users/{pk}") in eps
    assert ("GET", "/items/{slug}") in eps
    # include()/admin not an endpoint
    assert ("GET", "/admin") not in eps


# ---------------------------------------------------------------- NestJS


def test_scan_nestjs(tmp_path) -> None:
    _write(
        tmp_path,
        "src/users.controller.ts",
        """import { Controller, Get, Post } from '@nestjs/common';
@Controller('users')
export class UsersController {
  @Get()
  list() {}
  @Get(':id')
  detail() {}
  @Post()
  create() {}
}
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "nestjs"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("GET", "/users/{id}") in eps
    assert ("POST", "/users") in eps


# ---------------------------------------------------------------- Express


def test_scan_express(tmp_path) -> None:
    _write(
        tmp_path,
        "app.js",
        """const express = require('express');
const app = express();
app.get('/users', (req, res) => {});
app.post('/users/:id', (req, res) => {});
router.put('/health', handler);
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "express"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/users/{id}") in eps
    assert ("PUT", "/health") in eps


# ---------------------------------------------------------------- Spring


def test_scan_spring(tmp_path) -> None:
    _write(
        tmp_path,
        "UserController.java",
        """package com.example.api;
import org.springframework.web.bind.annotation.*;
@RestController
public class UserController {
  @GetMapping("/users")
  public String list() { return "ok"; }
  @PostMapping("/users/{id}")
  public String update(@PathVariable String id) { return id; }
  @RequestMapping(value = "/health", method = RequestMethod.GET)
  public String health() { return "ok"; }
}
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "spring"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/users/{id}") in eps
    assert ("GET", "/health") in eps


# ---------------------------------------------------------------- Go


def test_scan_go_gin(tmp_path) -> None:
    _write(
        tmp_path,
        "main.go",
        """package main

import (
    "github.com/gin-gonic/gin"
    "net/http"
)

func main() {
    r := gin.Default()
    r.GET("/users", listUsers)
    r.POST("/users/:id", updateUser)
    r.PUT("/health", health)
    http.HandleFunc("/legacy", legacy)
}
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "go"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/users/{id}") in eps
    assert ("PUT", "/health") in eps
    assert ("GET", "/legacy") in eps


def test_scan_go_echo(tmp_path) -> None:
    _write(
        tmp_path,
        "server.go",
        """package main
import "github.com/labstack/echo/v4"
func main() {
    e := echo.New()
    e.GET("/api/v1/items", listItems)
    e.DELETE("/api/v1/items/:id", deleteItem)
}
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "go"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/api/v1/items") in eps
    assert ("DELETE", "/api/v1/items/{id}") in eps


# ---------------------------------------------------------------- Rust


def test_scan_rust_axum(tmp_path) -> None:
    _write(
        tmp_path,
        "Cargo.toml",
        '[dependencies]\naxum = "0.7"\n',
    )
    _write(
        tmp_path,
        "src/main.rs",
        """use axum::routing::{get, post};
use axum::Router;

async fn main() {
    let app = Router::new()
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user));
}
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "rust"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/users") in eps
    assert ("GET", "/users/{id}") in eps


def test_scan_rust_actix_rocket(tmp_path) -> None:
    _write(
        tmp_path,
        "src/main.rs",
        """use actix_web::{get, post, App};

#[get("/users")]
async fn list() {}

#[post("/users/{id}")]
async fn update() {}

#[rocket::get("/health")]
async fn health() {}
""",
    )
    result = scan_code(str(tmp_path))
    assert result.framework == "rust"
    eps = {(e["method"], e["path"]) for e in result.endpoints}
    assert ("GET", "/users") in eps
    assert ("POST", "/users/{id}") in eps
    assert ("GET", "/health") in eps


# ---------------------------------------------------------------- detection


def test_detect_framework_none(tmp_path) -> None:
    _write(tmp_path, "random.txt", "hello world")
    assert detect_framework(str(tmp_path), [str(tmp_path / "random.txt")]) is None


def test_force_framework(tmp_path) -> None:
    _write(
        tmp_path,
        "app.py",
        """@app.get("/users")
def list_users(): ...
""",
    )
    # No framework marker — forcing a framework still parses python routes.
    result = scan_code(str(tmp_path), framework="fastapi")
    assert result.framework == "fastapi"
    assert ("GET", "/users") in {(e["method"], e["path"]) for e in result.endpoints}


# ---------------------------------------------------------------- push-code


def test_push_code_dry_run_lists_endpoints(tmp_path, capsys) -> None:
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/x')\ndef x(): ...\n",
    )
    code = main(
        [
            "push-code",
            "--dir",
            str(tmp_path),
            "--name",
            "my-api",
            "--base-url",
            "https://api.example.com",
            "--dry-run",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "framework: fastapi" in out
    assert "GET" in out and "/x" in out
    assert "dry-run" in out


def test_push_code_json(tmp_path, capsys) -> None:
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/x')\ndef x(): ...\n",
    )
    code = main(
        [
            "push-code",
            "--dir",
            str(tmp_path),
            "--name",
            "my-api",
            "--base-url",
            "https://api.example.com",
            "--dry-run",
            "--json",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert data["framework"] == "fastapi"
    assert data["endpoints"][0]["path"] == "/x"


def test_push_code_pushes_site(tmp_path, capsys) -> None:
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/x')\ndef x(): ...\n",
    )
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "site_id": "65f000000000000000000001",
                "name": "my-api",
                "base_url": "https://api.example.com",
                "endpoints_count": 1,
                "auth": "none",
            },
        )

    args = {
        "dir": str(tmp_path),
        "repo": None,
        "framework": None,
        "name": "my-api",
        "base_url": "https://api.example.com",
        "project": None,
        "site": None,
        "dry_run": False,
        "verify": False,
        "json": False,
        "auth_type": "none",
        "auth_token": None,
        "auth_cookie": None,
        "auth_header": "X-API-Key",
        "auth_token_url": None,
        "auth_client_id": None,
        "auth_client_secret": None,
    }
    code = _cmd_push_code(_client(handler), type("Args", (), args)())
    out = capsys.readouterr().out
    assert code == 0
    assert "developers/sites" in captured["url"]
    assert captured["body"]["endpoints"] == [{"method": "GET", "path": "/x"}]
    assert "export SITE_ID=65f000000000000000000001" in out


def test_push_code_requires_name_and_base_url(tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["push-code", "--dir", str(tmp_path)])
    assert exc.value.code == 2


def test_push_code_no_endpoints(tmp_path, capsys) -> None:
    _write(tmp_path, "readme.txt", "nothing to see")
    code = main(
        ["push-code", "--dir", str(tmp_path), "--name", "x", "--base-url", "https://example.com"]
    )
    err = capsys.readouterr().err
    assert code == 2
    assert "no endpoints found" in err


# ---------------------------------------------------------------- --repo


def test_clone_repo_and_scan(tmp_path, capsys) -> None:
    import shutil
    import subprocess

    if shutil.which("git") is None:
        pytest.skip("git not available")

    # Build a local git repo with a FastAPI file.
    repo = tmp_path / "src"
    _write(
        repo,
        "main.py",
        "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/repo')\ndef r(): ...\n",
    )
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "init",
        ],
        check=True,
    )

    code = main(
        [
            "push-code",
            "--repo",
            str(repo),
            "--name",
            "my-api",
            "--base-url",
            "https://api.example.com",
            "--dry-run",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "framework: fastapi" in out
    assert "/repo" in out
