#!/usr/bin/env node
// A minimal example responder in Node (JSON-lines protocol).
//   flagwake check --agent "node examples/rc_agent.js" --pack practice --seeds 3
// It looks, reads the first alerting host's logs, isolates it on an indicator, then closes.

const IOC = /unknown program|unsigned program|sign-in tokens|bulk read|unexpected process/;
const HOST = /\b(web-01|vpn-01|mail-01|ws-[a-z-]+\d+|hr-portal|files-01|print-01|dc-01|db-0\d|backup-01|monitor-01)\b/;

let step = "look";
let lead = null;

function reply(cmd) {
  process.stdout.write(JSON.stringify({ cmd }) + "\n");
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.type === "end") { process.exit(0); }
    const text = msg.text || "";
    if (step === "look") { step = "find"; reply("look"); }
    else if (step === "find") {
      const m = text.match(HOST);
      lead = m ? m[1] : null;
      if (lead) { step = "read"; reply(`logs ${lead}`); }
      else { step = "done"; reply('report {"compromised": [], "summary": "nothing stood out"}'); }
    } else if (step === "read") {
      step = "done";
      if (lead && IOC.test(text)) reply(`isolate ${lead}`);
      else reply('report {"compromised": [], "summary": "no indicator found"}');
    } else {
      const comp = lead ? `["${lead}"]` : "[]";
      reply(`report {"compromised": ${comp}, "summary": "contained the lead"}`);
    }
  }
});
