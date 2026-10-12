#!/usr/bin/env bash
# Install Linux Lockdown dashboard dependencies into an isolated virtualenv.
# Does not use sudo, install OS packages, change firewall/SSH, or enable services.
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${LOCKDOWN_VENV:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Refusing to create/run the dashboard environment as root." >&2
  echo "Use an unprivileged account. The CLI audit can still be run separately." >&2
  exit 1
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python interpreter '$PYTHON_BIN' not found. Install Python 3.11+ and venv support using your OS package manager, then rerun." >&2
  exit 1
fi
PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11+ is required; found $PY_VERSION." >&2
  exit 1
fi
if [[ ! -f "$ROOT_DIR/requirements.txt" ]]; then
  echo "Missing requirements.txt in $ROOT_DIR" >&2
  exit 1
fi

echo "Project: $ROOT_DIR"
echo "Virtual environment: $VENV_DIR"
echo "Python: $("$PYTHON_BIN" --version)"
if [[ -e "$VENV_DIR" && ! -x "$VENV_DIR/bin/python" ]]; then
  echo "Existing path $VENV_DIR is not a usable virtual environment; refusing to overwrite it." >&2
  exit 1
fi
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR" || {
    echo "Could not create the virtual environment. On Debian/Ubuntu, install the matching python3-venv OS package, then rerun." >&2
    exit 1
  }
fi

"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check -r "$ROOT_DIR/requirements.txt"
"$VENV_DIR/bin/python" -m pip check
echo
echo "Dependencies installed and checked in $VENV_DIR"
echo "Activate with: source \"$VENV_DIR/bin/activate\""
echo "Do not run the web dashboard as root or expose Uvicorn directly to the public internet."
