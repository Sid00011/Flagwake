"""Flagwake: a re-checkable test of how an AI defender behaves during a security
incident, scored with business cost. The code lives in ``cyberarena.rc``.

The package keeps its historical name ``cyberarena``. The generator's random-stream labels start
with the same word (``cyberarena/rc/1/...``) and must never change: every incident depends on them.
"""

__version__ = "0.5.2"

# Sent with every request to a model endpoint or to the public log. Some providers sit behind a
# firewall that refuses the default user agent of Python's HTTP client (HTTP 403 for every call).
USER_AGENT = f"flagwake/{__version__} (+https://github.com/Sid00011/Flagwake)"
