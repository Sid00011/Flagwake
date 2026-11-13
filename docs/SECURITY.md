# Responder Check — threat model and security

This is the threat model for the Responder Check: `report.html`, the report viewer and its loader,
the local server, and the harness. The repository's vulnerability-reporting policy is in the
top-level [SECURITY.md](../SECURITY.md); this document is about what the shipped code defends
against and what it does not.

## What is covered

**(a) A visitor to the report viewer.** The report viewer is a static page with a strict meta
Content-Security-Policy (`default-src 'none'`, only `'self'` scripts and styles, no external
origins). It makes no network request; a report is read from a local file.

**(b) Hostile content inside a report, an agent name or a log line.** Every
untrusted string is written with `textContent` or HTML-escaped before it reaches the page — the
HTML report builder, the static viewer and the failure-trace builder all escape. There is no
`innerHTML` with data, no `eval`/`Function`, and no inline event handlers. The viewer checks the
report's schema before rendering it. Planted "injection" text in incidents is harmless prose and is only ever displayed,
never executed.

**(c) A report made by someone else.** `flagwake verify` re-derives every score, incident
outcome and profile number from the transcript; a report cannot claim a score its own commands do
not produce, and verifying runs no code from the report. What the defender reports about itself
(model label, tokens, its connection-test result) is labelled self-reported and is not checked.
Size and time limits apply.

**(d) Supply chain.** The package has no runtime dependencies beyond the standard library. CI pins
its actions to commit hashes.

**(e) The local server.** `flagwake serve` binds `127.0.0.1` only, serves a fixed allowlist of
files with no directory listing and no path traversal, and makes no outbound request.

**(f) The harness.** Malformed JSON, oversize lines, binary junk, a slow agent, an agent that
never answers and an agent that prints thousands of lines are all bounded: lines are length-capped
and counted, a per-command and whole-incident timeout kills a hung child, output is capped, and the
child's stderr is captured to a log file.

## The local page (`flagwake ui`)

`flagwake ui` is a local server that can start processes, so it is locked down like one. It binds
127.0.0.1 only and answers only requests whose Host header names that address and port, which
defeats DNS rebinding. Every `/api/` request needs the random token made at launch, sent in a
header; the page reads it from the address's fragment, which browsers do not send to servers, and
the server logs nothing. Requests that change anything must also carry the page's own Origin and a
JSON body of at most 16 KB, so a page on another site can neither send them nor read the answers
(there are no cookies and no CORS headers). Static files come from a fixed list under a strict
content security policy (no inline script, no request to another address); every value is set as
text. Fields go through the registry's validation; a key typed into the page stays in the server's
memory until it stops and reaches only the reference program's environment, never a file, a log or
a report (a test runs a check and a run with a key and scans every file written). Defenders that
start a program on this computer are refused unless the page was started with `--allow-commands`,
and then each save, check and run asks for a confirmation. Its only outbound request is
`GET /v1/models` to a fixed list of ports on 127.0.0.1, to find a local model server.

## What is NOT covered (out of scope, stated plainly)

- **Running your agent's code.** `flagwake check --agent "..."` runs your program in your own
  process with your permissions. The harness does **not** sandbox it. Run only code you trust.
- **A hostile endpoint you choose.** `--http`, the reference model agent and `flagwake doctor`
  talk to the address you give them; that trust is yours. The key in `FLAGWAKE_LLM_KEY` is sent
  only in the request header to that address and never printed or written. The reference agents
  refuse to send it over plain http to another machine: use https, or a server on this machine.
- **The machine the tool runs on.** The tool assumes the local machine and the Python it runs are
  not already compromised.
- **What a signature vouches for.** A signed result (docs/SIGNED_RESULTS.md) shows which GitHub
  Actions run of which repository and commit wrote the report, and that Flagwake's signing
  workflow did; it does not vouch for the defender that run executed. In that workflow the
  defender runs as its own user without sudo (`flagwake check --defender-user`), so it cannot
  read the harness's memory or environment (the incident key, the run's signing token), write the
  output folder, or leave a process behind; `.github/workflows/signed-check.yml` runs a defender
  that tries each of these, and the same attempts without the separate user to show they are
  real. A self-hosted runner's signature is refused.

## Static hosting caveat

A static host that cannot set HTTP response headers gets the Content-Security-Policy only from the
viewer's `<meta>` tag, which cannot express everything a header can (for example
`frame-ancestors`). `flagwake serve` sends it as a header; where headers are available they
should be preferred.

## Reporting

A responsible-disclosure contact is in the top-level [SECURITY.md](../SECURITY.md).
