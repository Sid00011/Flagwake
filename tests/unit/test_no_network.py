"""The package makes no network request on its own: the CLI and the scoring path import no
network library, and the only modules that touch the network are the local interface layer (a
localhost server, a localhost/subprocess agent adapter) and the reference model agent and
doctor, which call only the endpoint the user names.

``flagwake check --http`` and ``flagwake serve`` talk to localhost only, by the user's own
choice; ``flagwake mcp`` speaks over stdin/stdout. The example adapters are programs the user
runs, outside the package. The container and CI templates are checked for the same promises.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NETWORK = {"socket", "ssl", "urllib", "http", "requests", "httpx", "aiohttp", "ftplib", "smtplib",
           "poplib", "imaplib", "telnetlib", "xmlrpc", "websocket", "websockets"}  # fmt: skip

# The only package modules allowed to touch the network. They are the Responder Check's local
# interface layer and are pinned to localhost below; everything else sends nothing.
NETWORKED = {
    "src/cyberarena/rc/protocol.py",  # localhost HTTP adapter and subprocess harness
    "src/cyberarena/rc/serve.py",  # localhost-only static server for the report viewer
    # The local page (flagwake ui): binds 127.0.0.1, and its only outbound request is GET
    # /v1/models to fixed localhost ports, to find a model server on this computer.
    "src/cyberarena/rc/ui.py",
    # The reference model agent and the doctor call only the endpoint the user names in
    # FLAGWAKE_LLM_BASE_URL; nothing in the harness, the scoring or the tests calls a model.
    "src/cyberarena/rc/model_agent.py",
    "src/cyberarena/rc/doctor.py",
    # The company as tools: binds 127.0.0.1 only, and posts events only to callback URLs on this
    # machine that the defender registered.
    "src/cyberarena/rc/toolsrun.py",
    # The attempt log: reads Sigstore's public transparency log, only in the signing workflow
    # (flagwake ci attempt, check --attempt-ticket) and for verify --attempts; it sends a
    # ticket's sha256 and nothing else.
    "src/cyberarena/rc/attempt.py",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.add(node.module.split(".")[0])
    return out


def test_only_the_local_interface_layer_touches_the_network() -> None:
    files = sorted((ROOT / "src" / "cyberarena").rglob("*.py"))
    assert len(files) > 15
    networked = set()
    for f in files:
        if _imports(f) & NETWORK:
            networked.add(f.relative_to(ROOT).as_posix())
    assert networked == NETWORKED, networked


def test_cli_and_scoring_import_no_network_library() -> None:
    """check, verify, report and the scoring path send nothing anywhere."""
    assert not (_imports(ROOT / "src" / "cyberarena" / "cli.py") & NETWORK)
    for name in (
        "engine.py",
        "generator.py",
        "scoring.py",
        "metrics.py",
        "report.py",
        "verify.py",
        "baselines.py",
        "runner.py",
    ):
        assert not (_imports(ROOT / "src" / "cyberarena" / "rc" / name) & NETWORK), name


def test_networked_interface_modules_are_localhost_only() -> None:
    serve = (ROOT / "src" / "cyberarena" / "rc" / "serve.py").read_text(encoding="utf-8")
    assert '"127.0.0.1"' in serve  # the server binds localhost only
    proto = (ROOT / "src" / "cyberarena" / "rc" / "protocol.py").read_text(encoding="utf-8")
    assert "127.0.0.1" in proto and "localhost" in proto  # the HTTP adapter refuses other hosts


def test_example_adapters_take_names_not_keys_and_never_write_them() -> None:
    # The two reference scaffolds call the model endpoint (and, for the tool loop, the tools on
    # this machine) whose addresses and key names come from the environment.
    adapters = {"reference_llm_agent.py", "reference_tool_agent.py"}
    for f in sorted((ROOT / "examples").glob("*.py")):
        if f.name in adapters:
            text = f.read_text(encoding="utf-8")
            assert "os.environ" in text  # the key, if any, comes from the environment
            # It is never written to disk: no open(..., "w") near a key variable.
            assert "KEY" in text or "TOKEN" in text
            assert "open(" not in text.replace("urlopen(", "").replace("_OPENER.open(", "")
        else:
            assert not (_imports(f) & NETWORK), f.name


def test_container_and_ci_templates_keep_their_promises() -> None:
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "@sha256:" in docker.split("FROM", 1)[1].splitlines()[0]  # a pinned base image
    assert "USER flagwake" in docker and 'ENTRYPOINT ["flagwake"]' in docker
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert {".*", "*.md", "!README.md", "private"} <= set(ignore)  # hidden and local files stay out
    ci = (ROOT / "examples" / "ci" / "rc-check.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in ci
    assert "flagwake check" in ci
    assert "secrets." not in ci  # it needs no secret of its own


def test_the_local_page_binds_and_probes_localhost_only() -> None:
    import re

    text = (ROOT / "src" / "cyberarena" / "rc" / "ui.py").read_text(encoding="utf-8")
    assert 'Server(("127.0.0.1", port), Handler)' in text
    probes = re.findall(r"urlopen\(([^,]+),", text)
    assert probes == ['base + "/models"']  # the one outbound call...
    assert 'base = f"http://127.0.0.1:{port}/v1"' in text  # ...always to this computer


def _run_scripts(text: str) -> list[str]:
    """Every shell script of a workflow or action file (the lines under each run key)."""
    import re

    lines, out, i = text.splitlines(), [], 0
    while i < len(lines):
        m = re.match(r"(\s*)(- )?run: ?(.*)", lines[i])
        i += 1
        if not m:
            continue
        if m.group(3).strip() != "|":
            out.append(m.group(3))
            continue
        indent, block = len(m.group(1)) + (2 if m.group(2) else 0), []
        while i < len(lines) and (not lines[i].strip() or _indent(lines[i]) > indent):
            block.append(lines[i])
            i += 1
        out.append("\n".join(block))
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def test_the_signing_steps_never_paste_inputs_into_scripts_and_pin_every_action() -> None:
    import re

    files = ["action.yml", ".github/workflows/check.yml", ".github/workflows/signed-check.yml"]
    for name in files:
        text = (ROOT / name).read_text(encoding="utf-8")
        scripts = _run_scripts(text)
        assert scripts, name
        for script in scripts:  # inputs reach a script only through env
            assert "${{" not in script, (name, script[:80])
        for use in re.findall(r"^\s*(?:- )?uses: (\S+)", text, re.M):  # comments aside
            assert use.startswith("./") or re.search(r"@[0-9a-f]{40}$", use), (name, use)
    launch = (ROOT / "scripts" / "ci_launch.py").read_text(encoding="utf-8")
    assert "--record-ci" in launch and "--defender-user" in launch
    signed = (ROOT / "examples" / "ci" / "flagwake-signed.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in signed
    assert "id-token: write" in signed.split("jobs:", 1)[1]  # only for the job, not the workflow
