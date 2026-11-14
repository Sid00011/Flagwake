"""The defender registry: ``flagwake.yaml`` and the drivers it describes.

A registry lists the defenders a folder knows about. Each entry says what kind of program it is
and how to start it; ``flagwake run`` turns an entry into a driver and runs it over a pack. The
file is a strict subset of YAML read by the small parser below (the package has no dependencies):
block mappings, block lists, plain or quoted scalars and JSON-style ``{...}`` / ``[...]`` values.
References (& and *), tags, block scalars, several documents, tabs, duplicate keys and every field
the schema does not name are rejected with the line number.

What an entry can make the harness do is fixed by its kind. Only ``command`` and ``mcp`` entries
start a program, and only from their own ``command`` string: it is split into words and started
without a shell, in the folder that holds ``flagwake.yaml``, in the user's own process with the
user's permissions (it is not sandboxed). No other field is ever placed on a command line: a
model endpoint's URL, model id, key variable name and extra request body reach the reference
program through environment variables, and its caps as integers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REGISTRY_FILE = "flagwake.yaml"
RUNS_DIR = "flagwake-runs"
REGISTRY_VERSION = 1
KINDS = ("command", "http", "mcp", "model-endpoint", "baseline")
ROLE = "defender"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
TEXT_MAX = 200

# Per kind: the fields an entry must have and the further fields it may have.
COMMON = ("name", "kind", "role", "caps", "meta", "world", "mode")
# mode native: the defender speaks the text protocol (through its kind's adapter). mode tools:
# the company is served as tools (MCP and a local REST API) and the defender runs its own loop;
# the harness starts a command defender with the addresses in its environment, or drives a
# shipped program through the same tool layer.
MODES = ("native", "tools")
TOOLS_KINDS = ("command", "baseline")
KIND_FIELDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "command": (("command",), ()),
    "http": (("url",), ()),
    "mcp": (("command",), ("tool",)),
    "model-endpoint": (("base_url", "model"), ("key_env", "extra_body")),
    "baseline": (("baseline",), ()),
}
# Caps: (lowest, highest) allowed. max_commands, step_timeout and incident_timeout are enforced
# by the harness; max_calls, token_budget and max_tokens are passed to the reference program for
# a model endpoint and, for every other kind, checked against the defender's self-reported usage.
# requests_per_minute only paces the reference program (a defender of another kind paces itself).
CAPS: dict[str, tuple[float, float]] = {
    "max_commands": (1, 60),
    "step_timeout": (1, 3600),
    "incident_timeout": (1, 86400),
    "max_calls": (1, 10000),
    "token_budget": (1, 100_000_000),
    "max_tokens": (1, 100_000),
    "requests_per_minute": (1, 100_000),
}
META = ("model_label", "version", "description")
RESERVED_BODY = ("model", "messages", "temperature", "max_tokens")
SECRET_HINT = (
    "key",
    "api_key",  # hygiene-ok: a field name the registry refuses
    "token",
    "password",  # hygiene-ok: a field name the registry refuses
    "secret",
    "authorization",
)


class RegistryError(ValueError):
    """The registry file or an entry is not valid; the message says where and why."""


# --------------------------------------------------------------------------- strict YAML subset


def parse_yaml(text: str) -> Any:
    """Parse the strict YAML subset of ``flagwake.yaml``; raise :class:`RegistryError`."""
    lines: list[tuple[int, int, str]] = []  # (line number, indent, content)
    for no, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise RegistryError(f"line {no}: indent with spaces, not tabs")
        body = _strip_comment(raw).rstrip()
        if not body.strip():
            continue
        if body.strip() in ("---", "..."):
            raise RegistryError(f"line {no}: one document only")
        lines.append((no, len(body) - len(body.lstrip(" ")), body.strip()))
    if not lines:
        return {}
    value, pos = _block(lines, 0, lines[0][1])
    if pos != len(lines):
        raise RegistryError(f"line {lines[pos][0]}: unexpected indentation")
    return value


def _strip_comment(raw: str) -> str:
    quote, escaped = "", False
    for i, ch in enumerate(raw):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or raw[i - 1] in " \t"):
            return raw[:i]
    return raw


def _block(lines: list[tuple[int, int, str]], pos: int, indent: int) -> tuple[Any, int]:
    if lines[pos][2].startswith("- ") or lines[pos][2] == "-":
        return _seq(lines, pos, indent)
    return _map(lines, pos, indent)


def _map(lines: list[tuple[int, int, str]], pos: int, indent: int) -> tuple[dict, int]:
    out: dict[str, Any] = {}
    while pos < len(lines) and lines[pos][1] == indent:
        no, _ind, text = lines[pos]
        if text.startswith("-"):
            raise RegistryError(f"line {no}: a list item where a key was expected")
        key, rest = _split_key(text, no)
        if key in out:
            raise RegistryError(f"line {no}: duplicate key {key!r}")
        pos += 1
        if rest == "":
            if pos < len(lines) and lines[pos][1] > indent:
                out[key], pos = _block(lines, pos, lines[pos][1])
            elif pos < len(lines) and lines[pos][1] == indent and lines[pos][2].startswith("- "):
                out[key], pos = _seq(lines, pos, indent)
            else:
                out[key] = None
        else:
            out[key] = _scalar(rest, no)
    if pos < len(lines) and lines[pos][1] > indent:
        raise RegistryError(f"line {lines[pos][0]}: unexpected indentation")
    return out, pos


def _seq(lines: list[tuple[int, int, str]], pos: int, indent: int) -> tuple[list, int]:
    out: list[Any] = []
    while pos < len(lines) and lines[pos][1] == indent and lines[pos][2].startswith("-"):
        no, _ind, text = lines[pos]
        if text != "-" and not text.startswith("- "):
            raise RegistryError(f"line {no}: write '- ' before a list item")
        item = text[1:].strip()
        if not item:
            pos += 1
            if pos < len(lines) and lines[pos][1] > indent:
                value, pos = _block(lines, pos, lines[pos][1])
                out.append(value)
            else:
                out.append(None)
            continue
        if _is_key(item):
            # "- key: value" opens a mapping whose further keys sit under the first key.
            sub_indent = indent + (len(text) - len(item))
            lines[pos] = (no, sub_indent, item)
            value, pos = _map(lines, pos, sub_indent)
            out.append(value)
        else:
            out.append(_scalar(item, no))
            pos += 1
    return out, pos


def _is_key(text: str) -> bool:
    if text[:1] in "\"'{[":
        return False
    head = text.split(":", 1)
    return len(head) == 2 and bool(KEY_RE.match(head[0])) and (head[1] == "" or head[1][0] == " ")


def _split_key(text: str, no: int) -> tuple[str, str]:
    if not _is_key(text):
        raise RegistryError(f"line {no}: expected 'key: value'")
    key, rest = text.split(":", 1)
    return key, rest.strip()


FLOW_WORD_RE = re.compile(r"^[A-Za-z0-9._:/@+-]+$")


def _flow_words(text: str) -> list[str] | None:
    """A YAML flow list of plain words, ``[a, b-c, "d e"]``, as strings; None if it is not one."""
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1].strip()
    if not inner:
        return []
    out = []
    for item in (x.strip() for x in inner.split(",")):
        if len(item) >= 2 and item[0] == item[-1] and item[0] in "\"'":
            item = item[1:-1]
        elif not FLOW_WORD_RE.match(item):
            return None
        out.append(item)
    return out


def _scalar(text: str, no: int) -> Any:
    if text[0] in "&*!|>%@`":
        raise RegistryError(f"line {no}: references, tags and block text are not supported")
    if text[0] in "{[":
        try:
            return json.loads(text)
        except ValueError as exc:
            words = _flow_words(text)
            if words is not None:
                return words
            raise RegistryError(
                f"line {no}: a [...] value must be plain words separated by commas, and a "
                "{...} value must be JSON"
            ) from exc
    if text[0] == '"':
        try:
            value = json.loads(text)
        except ValueError as exc:
            raise RegistryError(f"line {no}: unterminated or invalid quoted text") from exc
        if not isinstance(value, str):
            raise RegistryError(f"line {no}: invalid quoted text")
        return value
    if text[0] == "'":
        if len(text) < 2 or not text.endswith("'"):
            raise RegistryError(f"line {no}: unterminated quoted text")
        inner = text[1:-1]
        if re.search(r"(?<!')'(?!')", inner.replace("''", "")):
            raise RegistryError(f"line {no}: write '' for a quote inside single quotes")
        return inner.replace("''", "'")
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    if ": " in text or text.endswith(":"):
        raise RegistryError(f"line {no}: quote a value that contains ': '")
    return text


HEADER = (
    "# Defenders for flagwake run. Strict subset of YAML: unknown fields are rejected.",
    "# Commands run in your own process, without a shell, from this folder (not sandboxed).",
    "# Any defender works, on any machine; pick the kind that matches how it runs:",
    '#   kind: command         command: "python my_agent.py"  (any language: JSON lines)',
    '#   kind: http            url: "http://127.0.0.1:8000/act"  (any local service)',
    '#   kind: mcp             command: "node server.js"  (any stdio MCP server, tool act)',
    '#   kind: model-endpoint  base_url: "http://localhost:8080/v1"  model: "<id>"',
    "#                         (any chat-completions endpoint, hosted or local; key_env names",
    "#                         the variable that holds a key, never the key itself)",
    '#   kind: baseline        baseline: "careful"  (a scripted program shipped with the check)',
    "# Guide: docs/TRY_YOUR_AGENT.md",
)


def missing_program(entry: dict[str, Any], folder: Path) -> str | None:
    """Why the entry's program cannot start on this machine, or None.

    A registry can be copied between machines; a command that names a program this machine
    does not have should say so plainly instead of failing every incident.
    """
    import shutil

    if entry["kind"] not in ("command", "mcp"):
        return None
    from cyberarena.rc.cli import split_command

    prog = split_command(entry["command"])[0]
    if shutil.which(prog) or (folder / prog).is_file() or Path(prog).is_file():
        return None
    return (
        f"{entry['name']}: the program {prog!r} in its command is not found on this machine "
        "(not on PATH and not a file); install it or edit the entry"
    )


def dump_yaml(doc: dict[str, Any]) -> str:
    """Write a registry document in the subset :func:`parse_yaml` reads (round-trips)."""
    out = [
        *HEADER,
        f"version: {doc.get('version', REGISTRY_VERSION)}",
    ]
    defenders = doc.get("defenders") or []
    if not defenders:
        out.append("defenders: []")
    else:
        out.append("defenders:")
        for entry in defenders:
            first = True
            for key in _ordered(entry):
                prefix = "  - " if first else "    "
                first = False
                out += _dump_field(prefix, key, entry[key], "      ")
    return "\n".join(out) + "\n"


def _ordered(entry: dict[str, Any]) -> list[str]:
    order = (
        list(COMMON[:3]) + [f for k in KINDS for f in sum(KIND_FIELDS[k], ())] + ["caps", "meta"]
    )
    seen = list(dict.fromkeys(order))
    return [k for k in seen if k in entry] + sorted(k for k in entry if k not in seen)


def _dump_field(prefix: str, key: str, value: Any, inner: str) -> list[str]:
    if isinstance(value, dict) and key in ("caps", "meta") and value:
        return [f"{prefix}{key}:"] + [f"{inner}{k}: {_dump_scalar(v)}" for k, v in value.items()]
    return [f"{prefix}{key}: {_dump_scalar(value)}"]


def _dump_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int | float):
        return json.dumps(value)
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


# --------------------------------------------------------------------------- validation


def validate(doc: Any) -> dict[str, Any]:
    """Check a parsed registry strictly; return it with its entries validated."""
    if doc in (None, {}):
        doc = {"version": REGISTRY_VERSION, "defenders": []}
    if not isinstance(doc, dict):
        raise RegistryError("the registry must be a mapping with version and defenders")
    unknown = sorted(set(doc) - {"version", "defenders"})
    if unknown:
        raise RegistryError(f"unknown top-level field(s): {', '.join(unknown)}")
    if doc.get("version") != REGISTRY_VERSION:
        raise RegistryError(f"version must be {REGISTRY_VERSION}")
    defenders = doc.get("defenders")
    if defenders is None:
        defenders = []
    if not isinstance(defenders, list):
        raise RegistryError("defenders must be a list")
    seen: set[str] = set()
    clean = []
    for i, entry in enumerate(defenders, 1):
        e = validate_entry(entry, where=f"defender {i}")
        if e["name"] in seen:
            raise RegistryError(f"defender {i}: the name {e['name']!r} is used twice")
        seen.add(e["name"])
        clean.append(e)
    return {"version": REGISTRY_VERSION, "defenders": clean}


def validate_entry(entry: Any, where: str = "entry") -> dict[str, Any]:
    """Check one defender entry; return a copy. Raise :class:`RegistryError` with the reason."""
    name, kind, where = _entry_shape(entry, where)
    out: dict[str, Any] = {"name": name, "kind": kind, "role": ROLE}
    out.update(_entry_fields(entry, where))
    if "key_env" in out and "base_url" in out:
        from cyberarena.rc.model_agent import key_transport_problem

        if key_transport_problem(out["base_url"], "set"):
            raise RegistryError(
                f"{where}: a key is only sent over https or to a server on this computer; "
                "use an https:// base_url, or leave out key_env"
            )
    mode = entry.get("mode", "native")
    if mode not in MODES:
        raise RegistryError(f"{where}: mode must be native or tools")
    if mode == "tools" and kind not in TOOLS_KINDS:
        raise RegistryError(
            f"{where}: mode tools runs a command (started with the tool addresses in its "
            "environment) or a shipped program; for anything else start it yourself against "
            "flagwake tools serve"
        )
    if mode != "native":
        out["mode"] = mode
    return out


def _entry_shape(entry: Any, where: str) -> tuple[str, str, str]:
    """The name and kind of an entry, with its fields checked against what that kind allows;
    (name, kind, where), where ``where`` now names the defender in messages."""
    if not isinstance(entry, dict):
        raise RegistryError(f"{where}: must be a mapping of fields")
    name = entry.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise RegistryError(
            f"{where}: name must be 1-40 characters of a-z, 0-9, '.', '_' or '-', "
            "starting with a letter or digit"
        )
    where = f"defender {name!r}"
    kind = entry.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        raise RegistryError(f"{where}: kind must be one of {', '.join(KINDS)}")
    required, optional = KIND_FIELDS[kind]
    allowed = set(COMMON) | set(required) | set(optional)
    for key in entry:
        if key in allowed:
            continue
        if str(key).lower() in SECRET_HINT:
            raise RegistryError(
                f"{where}: never put a key in flagwake.yaml; keep it in an environment variable "
                "and name the variable in key_env"
            )
        other = [k for k in KINDS if key in sum(KIND_FIELDS[k], ())]
        hint = f" (it belongs to kind {other[0]})" if other else ""
        raise RegistryError(f"{where}: unknown field {key!r} for kind {kind}{hint}")
    for key in required:
        if entry.get(key) in (None, ""):
            raise RegistryError(f"{where}: kind {kind} needs {key}")
    role = entry.get("role", ROLE)
    if role != ROLE:
        raise RegistryError(f"{where}: role must be {ROLE!r}; this check only runs defenders")
    return name, kind, where


def _entry_fields(entry: dict[str, Any], where: str) -> dict[str, Any]:
    """Each field an entry carries, checked and copied."""
    out: dict[str, Any] = {}
    if "command" in entry:
        out["command"] = _command(entry["command"], where)
    if "tool" in entry:
        out["tool"] = _text(entry["tool"], where, "tool", pattern=KEY_RE)
    if "url" in entry:
        out["url"] = _local_url(entry["url"], where)
    if "base_url" in entry:
        out["base_url"] = _base_url(entry["base_url"], where)
    if "model" in entry:
        out["model"] = _text(entry["model"], where, "model")
    if "key_env" in entry:
        out["key_env"] = _text(entry["key_env"], where, "key_env", pattern=ENV_RE)
    if "extra_body" in entry:
        out["extra_body"] = _extra_body(entry["extra_body"], where)
    if "baseline" in entry:
        from cyberarena.rc.baselines import ALL_AGENTS

        name = entry["baseline"]
        if not isinstance(name, str) or name not in ALL_AGENTS:
            raise RegistryError(f"{where}: baseline must be one of {', '.join(sorted(ALL_AGENTS))}")
        out["baseline"] = name
    if entry.get("caps") is not None:
        out["caps"] = _caps(entry["caps"], where)
    if entry.get("meta") is not None:
        out["meta"] = _meta(entry["meta"], where)
    if entry.get("world") not in (None, ""):
        out["world"] = _command(entry["world"], where).strip()
    return out


def _text(value: Any, where: str, field: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > TEXT_MAX:
        raise RegistryError(f"{where}: {field} must be text of 1-{TEXT_MAX} characters")
    if any(ord(c) < 32 for c in value):
        raise RegistryError(f"{where}: {field} must be one line of text")
    if pattern is not None and not pattern.match(value):
        raise RegistryError(f"{where}: {field} {value!r} has characters that are not allowed")
    return value


def _command(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise RegistryError(f"{where}: command must be one line of text (at most 1000 characters)")
    if any(ord(c) < 32 for c in value):
        raise RegistryError(f"{where}: command must be one line, with no control characters")
    from cyberarena.rc.cli import split_command

    try:
        argv = split_command(value)
    except ValueError as exc:
        raise RegistryError(f"{where}: command cannot be split into words ({exc})") from exc
    if not argv:
        raise RegistryError(f"{where}: command is empty")
    return value


def _local_url(value: Any, where: str) -> str:
    url = _text(value, where, "url")
    if not re.match(r"^http://(127\.0\.0\.1|localhost)(:\d{1,5})?(/[^\s]*)?$", url):
        raise RegistryError(f"{where}: url must be http://127.0.0.1 or http://localhost")
    return url


def _base_url(value: Any, where: str) -> str:
    url = _text(value, where, "base_url")
    if not re.match(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[^\s]*)?$", url):
        raise RegistryError(f"{where}: base_url must be an http:// or https:// address")
    return url


def _extra_body(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{where}: extra_body must be a JSON object")
    blocked = sorted(set(value) & set(RESERVED_BODY))
    if blocked:
        raise RegistryError(f"{where}: extra_body cannot set {', '.join(blocked)}")
    try:
        text = json.dumps(value, sort_keys=True, allow_nan=False)
    except ValueError as exc:
        raise RegistryError(f"{where}: extra_body must hold plain JSON values") from exc
    if len(text) > 4000:
        raise RegistryError(f"{where}: extra_body is longer than 4000 characters")
    return json.loads(text)


def _caps(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{where}: caps must be a mapping")
    out: dict[str, Any] = {}
    for key, v in value.items():
        if key not in CAPS:
            raise RegistryError(f"{where}: unknown cap {key!r}; caps are {', '.join(CAPS)}")
        lo, hi = CAPS[key]
        if isinstance(v, bool) or not isinstance(v, int | float) or not lo <= v <= hi:
            raise RegistryError(f"{where}: cap {key} must be a number from {lo:g} to {hi:g}")
        if key not in ("step_timeout", "incident_timeout") and not isinstance(v, int):
            raise RegistryError(f"{where}: cap {key} must be a whole number")
        out[key] = v
    return out


def _meta(value: Any, where: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RegistryError(f"{where}: meta must be a mapping")
    out: dict[str, str] = {}
    for key, v in value.items():
        if key not in META:
            raise RegistryError(f"{where}: unknown meta field {key!r}; meta is {', '.join(META)}")
        if isinstance(v, int | float) and not isinstance(v, bool):
            v = str(v)
        out[key] = _text(v, where, f"meta.{key}")
    return out


# --------------------------------------------------------------------------- the file


def find_registry(path: str | None = None) -> Path:
    """The registry path: the one given, else flagwake.yaml in the current folder."""
    return Path(path) if path else Path.cwd() / REGISTRY_FILE


def load(path: Path) -> dict[str, Any]:
    """Read and validate a registry file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RegistryError(f"{path} does not exist; run: flagwake init") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise RegistryError(f"cannot read {path}: {exc}") from exc
    return validate(parse_yaml(text))


def save(path: Path, doc: dict[str, Any]) -> None:
    """Validate and write a registry file (LF line endings, UTF-8)."""
    clean = validate(doc)
    text = dump_yaml(clean)
    if validate(parse_yaml(text)) != clean:  # pragma: no cover - a writer bug
        raise RegistryError("internal error: the registry would not read back the same")
    path.write_text(text, encoding="utf-8", newline="\n")


def get(doc: dict[str, Any], name: str) -> dict[str, Any]:
    for entry in doc["defenders"]:
        if entry["name"] == name:
            return entry
    names = ", ".join(e["name"] for e in doc["defenders"]) or "none yet"
    raise RegistryError(f"no defender named {name!r} (registered: {names})")


def entry_hash(entry: dict[str, Any]) -> str:
    """A short hash of an entry, so a stored conformance result is tied to its exact entry."""
    blob = json.dumps(entry, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def runs_dir(registry_path: Path) -> Path:
    return registry_path.resolve().parent / RUNS_DIR


# --------------------------------------------------------------------------- drivers


def caps_of(entry: dict[str, Any]) -> dict[str, Any]:
    """The entry's caps with the harness defaults filled in."""
    from cyberarena.rc.engine import MAX_COMMANDS
    from cyberarena.rc.protocol import DEFAULT_STEP_TIMEOUT, DEFAULT_WALL_TIMEOUT

    caps = {
        "max_commands": MAX_COMMANDS,
        "step_timeout": DEFAULT_STEP_TIMEOUT,
        "incident_timeout": DEFAULT_WALL_TIMEOUT,
    }
    caps.update(entry.get("caps") or {})
    return caps


def model_argv(entry: dict[str, Any]) -> list[str]:
    """The reference program's command line for a model endpoint: numbers only, no user text.

    Each model call gets the step timeout less 5 seconds, so a slow endpoint is given the time
    its entry allows instead of the program's own 40-second default.
    """
    argv = [sys.executable, "-m", "cyberarena.rc.model_agent"]
    caps = entry.get("caps") or {}
    flags = (("max_calls", "--max-calls"), ("token_budget", "--token-budget"),
             ("max_tokens", "--max-tokens"), ("requests_per_minute", "--rpm"))  # fmt: skip
    for cap, flag in flags:
        if cap in caps:
            argv += [flag, str(int(caps[cap]))]
    if "step_timeout" in caps:
        argv += ["--timeout", f"{max(1.0, float(caps['step_timeout']) - 5):g}"]
    return argv


def model_env(entry: dict[str, Any], key: str | None = None) -> dict[str, str]:
    """The environment for the reference program: the endpoint settings, never a key's value
    written anywhere but this child's environment. ``key`` is a key held in memory (the local
    page keeps one until it stops); otherwise ``key_env`` names the variable to read."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("FLAGWAKE_LLM_")}
    env["FLAGWAKE_LLM_BASE_URL"] = entry["base_url"]
    env["FLAGWAKE_LLM_MODEL"] = entry["model"]
    if entry.get("extra_body"):
        env["FLAGWAKE_LLM_EXTRA_BODY"] = json.dumps(entry["extra_body"], sort_keys=True)
    key_env = entry.get("key_env")
    if key:
        env["FLAGWAKE_LLM_KEY"] = key
    elif key_env and os.environ.get(key_env):
        env["FLAGWAKE_LLM_KEY"] = os.environ[key_env]
    return env


def driver_factory(entry: dict[str, Any], folder: Path, out: Path, key: str | None = None):
    """A per-incident driver factory for an entry, run from ``folder``, logs under ``out``;
    ``key`` is a model endpoint's key held in memory, never written anywhere."""
    from cyberarena.rc.cli import split_command
    from cyberarena.rc.protocol import http_driver_factory, subprocess_driver_factory

    caps = caps_of(entry)
    step, wall = float(caps["step_timeout"]), float(caps["incident_timeout"])
    kind = entry["kind"]
    out.mkdir(parents=True, exist_ok=True)
    log = str(out / "agent-stderr.log")
    if kind == "baseline":
        from cyberarena.rc.runner import baseline_driver

        name = entry["baseline"]
        return lambda: baseline_driver(name)
    if kind == "http":
        return http_driver_factory(entry["url"], step, wall)
    if kind == "command":
        return subprocess_driver_factory(split_command(entry["command"]), step, log, wall,
                                         cwd=str(folder))  # fmt: skip
    if kind == "model-endpoint":
        return subprocess_driver_factory(model_argv(entry), step, log, wall, cwd=str(folder),
                                         env=model_env(entry, key))  # fmt: skip
    if kind == "mcp":
        from cyberarena.rc.mcp_client import mcp_driver_factory

        return mcp_driver_factory(split_command(entry["command"]), entry.get("tool", "act"),
                                  step, log, wall, cwd=str(folder))  # fmt: skip
    raise RegistryError(f"unknown kind {kind!r}")  # pragma: no cover - validated earlier


def manifest(entry: dict[str, Any]) -> dict[str, Any]:
    """What the report records about the entry (self-reported; outside the hashed part)."""
    out = {k: v for k, v in entry.items() if k != "meta"}
    out["meta"] = dict(entry.get("meta") or {})
    return out
