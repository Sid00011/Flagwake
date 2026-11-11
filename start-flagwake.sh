#!/bin/sh
# Start the Flagwake page (macOS and Linux): set up a private Python environment the first time,
# then run "flagwake ui", which opens the page in your browser. Run: sh start-flagwake.sh
cd "$(dirname "$0")" || exit 1
VENV=.flagwake-venv
CHECK="import sys, pathlib, importlib.metadata as m, tomllib; src = sys.argv[1]; v = pathlib.Path(src).name.split('-')[1] if src.endswith('.whl') else tomllib.load(open('pyproject.toml', 'rb'))['project']['version']; sys.exit(0 if m.version('flagwake') == v else 1)"

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 &&
     "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PY=$c
    break
  fi
done
if [ -z "$PY" ]; then
  echo "Flagwake needs Python 3.11 or newer, and it was not found on this computer."
  echo "Install it from https://www.python.org/downloads/ (or with your system's package manager),"
  echo "then run this file again."
  exit 1
fi

# From a copy of the source, install it; from a folder with the package file, install that.
if [ -f pyproject.toml ]; then SRC=.; else SRC=$(ls dist/flagwake-*.whl 2>/dev/null | head -n 1); fi
if [ -z "$SRC" ]; then
  echo "No Flagwake package was found next to this file."
  exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
  echo "Setting up Flagwake the first time, about a minute..."
  if ! "$PY" -m venv "$VENV"; then
    echo "Could not create $VENV. On Debian or Ubuntu, install python3-venv first."
    exit 1
  fi
fi
if ! "$VENV/bin/python" -c "$CHECK" "$SRC" >/dev/null 2>&1; then
  echo "Installing Flagwake..."
  if ! "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check "$SRC"; then
    echo "The setup did not finish. Setting up from the source needs an internet connection once,"
    echo "to fetch the build tool. If it keeps failing, delete the folder $VENV and try again."
    exit 1
  fi
fi
exec "$VENV/bin/flagwake" ui "$@"
