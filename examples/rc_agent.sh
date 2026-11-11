#!/usr/bin/env bash
# A minimal example responder in POSIX shell (JSON-lines protocol), using only grep/sed.
#   flagwake check --agent "bash examples/rc_agent.sh" --pack practice --seeds 3
# It looks, reads the first alerting host's logs, isolates it on an indicator, then closes.
set -u
step=look
lead=""
ioc='unknown program|unsigned program|sign-in tokens|bulk read|unexpected process'
host='web-01|vpn-01|mail-01|ws-[a-z-]*[0-9]+|hr-portal|files-01|print-01|dc-01|db-0[0-9]|backup-01|monitor-01'

while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in *'"type": "end"'*|*'"type":"end"'*) exit 0;; esac
  case "$step" in
    look)
      step=find; printf '{"cmd": "look"}\n';;
    find)
      lead=$(printf '%s' "$line" | grep -oE "$host" | head -n1 || true)
      if [ -n "$lead" ]; then step=read; printf '{"cmd": "logs %s"}\n' "$lead"
      else step=done; printf '{"cmd": "report {\\"compromised\\": [], \\"summary\\": \\"quiet\\"}"}\n'; fi;;
    read)
      step=done
      if printf '%s' "$line" | grep -qE "$ioc"; then printf '{"cmd": "isolate %s"}\n' "$lead"
      else printf '{"cmd": "report {\\"compromised\\": [], \\"summary\\": \\"no indicator\\"}"}\n'; fi;;
    *)
      if [ -n "$lead" ]; then
        printf '{"cmd": "report {\\"compromised\\": [\\"%s\\"], \\"summary\\": \\"contained\\"}"}\n' "$lead"
      else printf '{"cmd": "report {\\"compromised\\": [], \\"summary\\": \\"done\\"}"}\n'; fi;;
  esac
done
