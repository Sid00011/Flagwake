"""Why a defender's replies held no command: the provider, the settings, or the model.

The reference model agent writes a line in place of a command it could not get:
``(model call failed: HTTP 429: <the provider's words>)`` when the call failed, or
``(no command in the model reply: <why>)`` when the reply held no command; the harness writes
``(invalid reply)`` for a line it could not read. Those lines, and the usage the model program
reports, tell apart problems that look the same in a score and need different fixes: the provider
refused or failed the calls (quota, rate limit, key, model, request size, outage), the reply limit
cut the answer off, a content filter blocked it, the model refused, or the model answered with text
that is not a command. Only the last two are about the model's behaviour.

Nothing here depends on a provider or a model: it reads HTTP status codes, the finish reason the
agent recorded, and the provider's own message as it was stored.
"""

from __future__ import annotations

import re
from typing import Any

FAILED = re.compile(r"^\(model call failed: (.*)\)$", re.S)
NO_COMMAND = re.compile(r"^\(no command in the model reply(?:: (.*))?\)$", re.S)
HTTP = re.compile(r"^HTTP (\d{3})(?:: (.*))?$", re.S)
ASKED_WAIT = re.compile(r"\[asked to wait (\d+) s\]")  # the wait a refusal asked for
LONG_WAIT = 600  # seconds: a refusal asking for longer is a daily (or longer) quota

# One plain sentence per cause: what happened and what to do. The provider's own words follow.
CAUSES = {
    "quota": (
        "The provider refused calls because a rate limit or quota was reached",
        "wait and try again, lower the pace (requests_per_minute in flagwake.yaml, --rpm), or "
        "use a plan with a larger allowance; a full run makes a few hundred calls",
    ),
    "key": (
        "The provider refused the key or this model",
        "check the key, and that this key may use this model, in the provider's console",
    ),
    "missing": (
        "The provider does not know this address or model",
        "check the address (usually ending in /v1) and the model id; providers retire old models",
    ),
    "rejected": (
        "The provider rejected the request",
        "lower the reply limit or remove an extra request field this model does not accept",
    ),
    "provider_error": (
        "The provider failed on its side",
        "try again later",
    ),
    "timeout": (
        "The provider did not answer in time",
        "allow more time per step (step_timeout), or use a faster model",
    ),
    "unreachable": (
        "The address could not be reached",
        "check the address and that the server is running",
    ),
    "cut_off": (
        "Replies were cut off by the reply limit before any answer: the model reasons first",
        "raise the reply limit (the page's model settings, max_tokens in flagwake.yaml, "
        "--max-tokens or FLAGWAKE_LLM_MAX_TOKENS) or lower the model's reasoning effort "
        "(extra request fields, FLAGWAKE_LLM_EXTRA_BODY)",
    ),
    "filtered": (
        "The provider's content filter blocked replies",
        "use a provider or model whose filter allows security-incident text",
    ),
    "refused": (
        "The model refused to answer",
        "use a model that accepts defensive security tasks",
    ),
    "empty": (
        "The model sent empty replies, with no reason given",
        "raise the reply limit or lower the reasoning effort; some models put their whole "
        "answer in a separate reasoning field",
    ),
    "unreadable": (
        "The model answered with text that is not a command",
        "try a model that follows instructions better",
    ),
}
# Causes that come from the provider or the settings, not from the model's decisions.
CONNECTION = frozenset(CAUSES) - {"unreadable", "refused", "empty"}


# Words in a provider's message that name the cause when its status code does not: some
# providers answer a bad key, an unknown model or a used-up quota with a plain HTTP 400.
KEY_WORDS = ("api key", "authorization", "unauthenticated", "unauthorized", "permission",
             "credential")  # fmt: skip
MISSING_WORDS = ("not found", "does not exist", "no such model", "unknown model")
QUOTA_WORDS = ("rate limit", "quota", "resource_exhausted", "too many requests")


def classify(code: int, message: str = "") -> str:
    """The cause of an error answer, from its status code and the provider's own words."""
    text = message.lower()
    if code == 429:
        return "quota"
    if code in (401, 403):
        return "key"
    if code == 404:
        return "missing"
    if 400 <= code < 500 and code != 413:
        for cause, words in (("key", KEY_WORDS), ("missing", MISSING_WORDS),
                             ("quota", QUOTA_WORDS)):  # fmt: skip
            if any(w in text for w in words):
                return cause
    if 400 <= code < 500:
        return "rejected"
    return "provider_error"


def _failure_cause(detail: str) -> str:
    m = HTTP.match(detail)
    if m:
        return classify(int(m.group(1)), m.group(2) or "")
    if detail.startswith("timeout") or "no time left" in detail:
        return "timeout"
    if detail.startswith("cannot connect"):
        return "unreachable"
    return "provider_error"


def _empty_cause(why: str | None) -> str:
    if not why:
        return "unreadable"
    if why.startswith("cut off"):
        return "cut_off"
    if why.startswith("blocked"):
        return "filtered"
    if why.startswith("the model refused"):
        return "refused"
    if why == "an empty reply":
        return "empty"
    return "unreadable"


def line_cause(line: str) -> tuple[str, str] | None:
    """The cause of one line that stands in for a command, with its words; None for a command."""
    if not isinstance(line, str) or not line.startswith("("):
        return None
    m = FAILED.match(line)
    if m:
        detail = ASKED_WAIT.sub("", m.group(1)).strip()
        return _failure_cause(detail), detail
    n = NO_COMMAND.match(line)
    if n:
        return _empty_cause(n.group(1)), n.group(1) or ""
    return "unreadable", ""  # (invalid reply) or another line the harness could not read


def diagnose(commands: list[str], usage: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """What the lines that stand in for commands say, or None when every reply was a command.

    Returns the number of such lines, a count per cause, the main cause (the most frequent), an
    example in the provider's or the program's own words, whether the cause is the connection
    rather than the model, and one plain sentence with the fix.
    """
    usage = usage or {}
    counts: dict[str, int] = {}
    example: dict[str, str] = {}
    longest = 0
    for c in commands:
        found = line_cause(c)
        if found is None:
            continue
        cause, said = found
        for w in ASKED_WAIT.findall(c):
            longest = max(longest, int(w))
        counts[cause] = counts.get(cause, 0) + 1
        if said and cause not in example:
            example[cause] = said[:160]
    if not counts:
        return None
    # Reports made before the reason was written into the line: the usage still counts the
    # replies the reply limit cut off.
    cut = int(usage.get("cut_off") or 0)
    if cut and counts.get("unreadable") and not counts.get("cut_off"):
        moved = min(cut, counts["unreadable"])
        counts["cut_off"] = moved
        counts["unreadable"] -= moved
        if not counts["unreadable"]:
            del counts["unreadable"]
    # A quota that ran out shows in the usage too: answers that asked to wait, then failures.
    main = max(sorted(counts), key=lambda k: (counts[k], k in CONNECTION))
    what, fix = CAUSES[main]
    words = example.get(main, "")
    waited = usage.get("waited_seconds") or 0
    limited = usage.get("rate_limited") or 0
    extra = ""
    if main == "quota" and longest >= LONG_WAIT:
        fix = (f"the provider asked to wait about {longest / 3600:.1f} h: a daily or longer "
               "quota; try again later, or use a plan with a larger allowance")  # fmt: skip
    elif main == "quota" and longest:
        fix = (f"the provider asked to wait {longest} s: a per-minute limit; set a pace a little "
               "below it (requests per minute in the page's model settings, "
               "requests_per_minute in flagwake.yaml, --rpm)")  # fmt: skip
    if main == "quota" and limited:
        answers = "answer" if limited == 1 else "answers"
        extra = f" ({limited} {answers} asked to wait, {waited:.0f} s in all)"
    text = f"{what}{extra}: {sum(counts.values())} of the replies carried no command. Fix: {fix}."
    if words:
        text += f" Details: {words}"
    return {
        "empty": sum(counts.values()),
        "causes": dict(sorted(counts.items())),
        "main": main,
        "connection": main in CONNECTION,
        "example": words,
        "text": text,
    }


def diagnose_incidents(incidents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """:func:`diagnose` over the transcripts of a run (their commands and summed usage)."""
    commands: list[str] = []
    usage: dict[str, float] = {}
    for inc in incidents:
        commands += [c for c in inc.get("commands") or [] if isinstance(c, str)]
        for k, v in (inc.get("usage") or {}).items():
            if isinstance(v, int | float) and not isinstance(v, bool):
                usage[k] = usage.get(k, 0) + v
    return diagnose(commands, usage)
