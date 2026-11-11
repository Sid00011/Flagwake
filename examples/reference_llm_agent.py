#!/usr/bin/env python3
"""The reference model agent: runs ``cyberarena.rc.model_agent`` (installed with flagwake).

It reads FLAGWAKE_LLM_BASE_URL, FLAGWAKE_LLM_MODEL and, if the endpoint needs one, FLAGWAKE_LLM_KEY
from os.environ; the key goes only into the request header. Options and limits:
``python examples/reference_llm_agent.py --help``. The code is in src/cyberarena/rc/model_agent.py;
copy that file to build your own agent.

    flagwake check --agent "python examples/reference_llm_agent.py" --pack practice --seeds 1
"""

from cyberarena.rc.model_agent import main

if __name__ == "__main__":
    raise SystemExit(main())
