#!/usr/bin/env bash
# "No secrets, no payments" scan: api_key, sk-, password, stripe and paypal.
# Case-insensitive. Used by CI (.github/workflows/ci.yml, job "quick").
# Exit 0: clean. Exit 1: a suspicious string was found, or grep itself failed (exit >= 2),
# so an unreadable tree can never pass silently. Optional argument: directory to scan.
# "sk-" is matched as a word start followed by a key character, so "task-" or "risk-" do not
# match. This file is not scanned (*.sh is not an included type), so its own pattern is safe.
# One third-party file is skipped by name: the vendored axe-core, tests/e2e/vendor/axe.min.js
# (test-only, never shipped; its accessibility rules contain the word "password"). Its SHA-256 is
# pinned by a test against tests/e2e/vendor/README.md, and a file of that name anywhere else fails
# this scan.
set -u
root="${1:-.}"
others=$(find "$root" -name axe.min.js -not -path '*/.git/*' -not -path '*/.venv/*' \
  | grep -v '/tests/e2e/vendor/axe\.min\.js$')
if [ -n "$others" ]; then
  echo "hygiene: axe.min.js is only allowed in tests/e2e/vendor/: $others"
  exit 1
fi
# Also the token prefixes of the model providers the model runs may use (nvapi-, AIza, gsk_).
pattern='(api[_-]?key|\bsk-[A-Za-z0-9]|\bnvapi-[A-Za-z0-9_-]{8}|\bAIza[0-9A-Za-z_-]{20}|\bgsk_[A-Za-z0-9]{8}|password|stripe|paypal)'
hits=$(grep -RInEi "$pattern" \
  --include='*.py' --include='*.js' --include='*.html' --include='*.yml' --include='*.yaml' \
  --include='*.toml' --include='*.cfg' --include='*.ini' --include='*.json' \
  --exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules --exclude=axe.min.js \
  "$root")
rc=$?
if [ "$rc" -ge 2 ]; then
  echo "hygiene: grep failed with exit code $rc"
  exit 1
fi
# A line where the word is the point (the masked key field of the page, a field name the registry
# refuses, a fake key in a test) carries "hygiene-ok: <reason>" on that same line, so the reason
# stays next to it for review. A marker without a reason does not count.
left=$(printf '%s\n' "$hits" | grep -vE 'hygiene-ok: [A-Za-z]' | grep -v '^$')
if [ -z "$left" ]; then
  echo "hygiene: clean"
  exit 0
fi
printf '%s\n' "$left"
echo "hygiene: suspicious string found (lines above)"
exit 1
