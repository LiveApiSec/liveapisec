#!/usr/bin/env bash
#
# liveapisec — one-command installer (Linux / macOS).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/LiveApiSec/liveapisec/main/install.sh | bash
#
# Strategy (no sudo needed):
#   1. Use pipx if available (isolated env, command on PATH).
#   2. Otherwise create a private venv under ~/.local/share/liveapisec-venv
#      and symlink the binary into ~/.local/bin — this works even on
#      PEP 668 "externally-managed-environment" systems (Ubuntu 24.04+).
#
set -euo pipefail

PKG="liveapisec"
CMD="liveapisec"
VENV_DIR="${VENV_DIR:-$HOME/.local/share/liveapisec-venv}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

say()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 is required (https://www.python.org/downloads/)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "python3.9+ is required (found: $(python3 --version 2>&1))"

# --- 1) pipx (preferred) ----------------------------------------------------
if command -v pipx >/dev/null 2>&1; then
  say "Installing ${PKG} via pipx…"
  pipx install "$PKG"
  if ! command -v "$CMD" >/dev/null 2>&1; then
    pipx ensurepath >/dev/null 2>&1 || true
    warn "The '${CMD}' command was installed but is not on your PATH yet."
    warn "Open a new terminal, or run:  pipx ensurepath"
  fi
  say "Done! Run:  ${CMD} --help"
  exit 0
fi

# --- 2) fallback: private venv + symlink (no sudo, PEP 668 safe) ------------
if command -v "$CMD" >/dev/null 2>&1; then
  say "${CMD} is already installed ($(command -v "$CMD")). Run:  ${CMD} --help"
  exit 0
fi

say "pipx not found — installing into an isolated venv (${VENV_DIR})"
mkdir -p "$BIN_DIR" "$VENV_DIR"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
fi

say "Installing ${PKG} from PyPI…"
"$VENV_DIR/bin/pip" install --quiet --upgrade "$PKG"

ln -sf "$VENV_DIR/bin/$CMD" "$BIN_DIR/$CMD"

if ! command -v "$CMD" >/dev/null 2>&1; then
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
      warn "Add ${BIN_DIR} to your PATH, then run:  ${CMD} --help"
      warn "  export PATH=\"$BIN_DIR:\$PATH\"   # add to ~/.bashrc / ~/.zshrc"
      ;;
  esac
fi

say "Done! Run:  ${CMD} --help"
