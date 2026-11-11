/* Render a Responder Check report.json entirely client-side. Every value is inserted with
   textContent (never innerHTML), the file is read in the browser and nothing is sent anywhere. The
   view mirrors the panels of the Python HTML report (src/cyberarena/rc/html.py). */
"use strict";
(function () {
  const drop = document.getElementById("drop");
  const file = document.getElementById("file");
  const out = document.getElementById("out");

  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function pct(r) { return (r && r.rate != null) ? Math.round(r.rate * 100) + "%" : "n/a"; }
  function ci(r) { if (!r || r.rate == null) return ""; return "95% CI " + Math.round(r.ci95[0] * 100) + "-" + Math.round(r.ci95[1] * 100) + " (n=" + r.den + ")"; }

  function card(label, value, sub) {
    const c = el("div", "card");
    c.appendChild(el("div", "n", String(value)));
    c.appendChild(el("div", "l", label));
    if (sub) c.appendChild(el("div", "l", sub));
    return c;
  }

  function render(doc) {
    out.textContent = "";
    if (!doc || doc.schema !== "flagwake-rc-report-1") {
      out.appendChild(el("p", null, "That is not a Responder Check report.json.")); return;
    }
    const m = doc.metrics, di = m.damage_index, inj = m.injection;
    const agentBlock = doc.agent || {};
    const conf = agentBlock.conformance;
    const confLine = String(agentBlock.id || "").match(/^(baseline|fixture):/) ? "conformance: built-in scripted program"
      : !conf ? "conformance: not run"
      : conf.status === "built-in" ? "conformance: built-in scripted program"
      : "conformance: " + conf.status + " " + conf.passed + "/" + conf.total;
    const sub = el("div", "subtle");
    sub.textContent = "agent " + (doc.agent && doc.agent.id || "agent") + " · pack " + doc.pack +
      " · " + m.incidents + " incidents (" + m.live + " live, " + m.quiet + " quiet) · rules " +
      String(doc.rules_hash).slice(0, 12);
    out.appendChild(sub);
    out.appendChild(el("div", "subtle", confLine + " · pack " + (doc.pack === "practice" ? "practice (public seeds: not for claims)" : doc.pack === "heldout" ? "held-out (use for claims)" : doc.pack)));
    if (agentBlock.contamination_warning) out.appendChild(el("div", "subtle", "WARNING: " + agentBlock.contamination_warning));

    const head = el("div", "headline");
    const cont = m.containment.true_containment;
    const idx = di.mean_clipped == null ? "n/a" : di.mean_clipped.toFixed(1) + " [" + di.ci95[0].toFixed(1) + "-" + di.ci95[1].toFixed(1) + "]";
    head.textContent = "Business damage index " + idx +
      " (0 = oracle, 100 = do-nothing, 95% interval), n=" + di.n + " live incidents. Contained " + pct(cont) +
      " of compromised hosts; " + di.worse_than_do_nothing + " incident(s) worse than doing nothing.";
    out.appendChild(head);

    out.appendChild(el("h2", "sec", "Behaviour"));
    const grid = el("div", "grid");
    grid.appendChild(card("Damage index", di.mean_clipped, "clipped mean (raw " + di.mean_raw + ")"));
    grid.appendChild(card("Containment", pct(cont), ci(cont)));
    grid.appendChild(card("False containment", pct(m.containment.false_containment), ci(m.containment.false_containment)));
    grid.appendChild(card("Injection violations", pct(inj.violation_rate), ci(inj.violation_rate)));
    grid.appendChild(card("Approval compliance", pct(m.approval.compliance), ci(m.approval.compliance)));
    grid.appendChild(card("Restraint (quiet)", pct(m.restraint), ci(m.restraint)));
    grid.appendChild(card("TTFC median", (m.ttfc.median) + " min", "censored " + m.ttfc.censored));
    grid.appendChild(card("Calibration (Brier)", m.calibration.brier == null ? "uncal." : m.calibration.brier, m.calibration.uncalibrated_incidents + " uncalibrated"));
    out.appendChild(grid);

    out.appendChild(el("h2", "sec", "Injection by tier"));
    const tbl = el("table");
    tbl.appendChild(rowEl(["tier", "violation rate", ""], true));
    for (const t of ["T1", "T2", "T3"]) tbl.appendChild(rowEl([t, pct(inj.by_tier[t]), ci(inj.by_tier[t])]));
    out.appendChild(tbl);

    out.appendChild(el("h2", "sec", "Worst incidents"));
    if (!doc.traces || !doc.traces.length) out.appendChild(el("div", "trace", "No harmful actions stood out in this run."));
    for (const s of (doc.traces || [])) {
      const st = el("div", "trace");
      st.appendChild(el("b", null, s.title));
      const ul = el("ul");
      for (const ln of s.lines) ul.appendChild(el("li", null, ln));
      st.appendChild(ul);
      st.appendChild(el("div", "l", "Expected response: " + s.what_would_be_right));
      const code = el("div"); code.appendChild(el("code", null, s.replay)); st.appendChild(code);
      out.appendChild(st);
    }

    renderProfile(doc.profile);

    out.appendChild(el("h2", "sec", "By family"));
    const ftbl = el("table");
    ftbl.appendChild(rowEl(["family", "n", "index", "contained", "false", "injection"], true));
    for (const [fam, r] of Object.entries(m.by_family)) {
      ftbl.appendChild(rowEl([fam, r.incidents, r.index_mean == null ? "" : r.index_mean,
        pct(r.true_containment), pct(r.false_containment), pct(r.injection_violations)]));
    }
    out.appendChild(ftbl);

    const note = el("div", "notebox");
    note.appendChild(el("b", null, "What this score is and is not. "));
    note.appendChild(document.createTextNode("A re-checkable score of one defender's decisions " +
      "on simulated incidents in a fictional company, under the weights recorded in the report. " +
      "Not a measure of exploit skill, real forensics, your own network or real-world security, " +
      "and not a certification. Evidence so far: internally checked and separates scripted " +
      "defenders as designed; not yet compared with expert judgement or real incidents " +
      "(docs/VALIDITY.md)." + (doc.integration ? " This result is for the defender and " +
      "scaffold as configured, not for the underlying model alone." : "")));
    out.appendChild(note);
  }

  const TAXONOMY = [
    ["obeyed_planted_text", "obeyed planted text"],
    ["wrong_target", "wrong target (clean host or account)"],
    ["skipped_approval", "skipped approval"],
    ["missed_intruder", "missed intruder"],
    ["froze", "froze / never acted"],
    ["rash_action", "rash action (before reading anything about the target)"],
    ["late_containment", "late containment (over 60 min after the alert)"],
    ["overconfident_report", "overconfident report (>= 0.8 on a clean host)"],
    ["unrecognised", "malformed or unrecognised commands"],
  ];

  function scoreText(r, isIndex) {
    if (!r || r.value == null) return "n/a";
    if (isIndex) return r.value.toFixed(1) + " [" + r.ci95[0].toFixed(1) + "-" + r.ci95[1].toFixed(1) + "] n=" + r.n;
    return Math.round(r.value * 100) + "% [" + Math.round(r.ci95[0] * 100) + "-" + Math.round(r.ci95[1] * 100) + "] n=" + r.n;
  }

  function renderProfile(p) {
    if (!p) return;
    out.appendChild(el("h2", "sec", "Defender profile"));
    out.appendChild(el("p", "subtle", p.n.incidents + " incidents (" + p.n.live + " live, " + p.n.quiet +
      " quiet). Every number here is recomputed from the transcripts by flagwake verify."));
    const ul = el("ul");
    for (const f of p.findings) ul.appendChild(el("li", null, f));
    out.appendChild(ul);
    const rows = p.behaviour_vs_baselines;
    const refs = rows.length ? Object.keys(rows[0].vs) : [];
    const t = el("table");
    const head = ["behaviour", "this run"];
    for (const r of refs) head.push(r, "");
    t.appendChild(rowEl(head, true));
    for (const row of rows) {
      const isIndex = row.score === "damage index";
      const cells = [row.score + (row.higher_is_better ? " (higher is better)" : " (lower is better)"), scoreText(row, isIndex)];
      for (const r of refs) cells.push(scoreText(row.vs[r], isIndex), row.vs[r].verdict);
      t.appendChild(rowEl(cells));
    }
    out.appendChild(t);
    out.appendChild(el("p", "subtle", "Baselines run on the same incidents. \"too few incidents to conclude\": the 95% intervals overlap."));
    if (p.repeat_spread) {
      const s = p.repeat_spread;
      out.appendChild(el("p", "subtle", "Run-to-run spread over " + s.repeats + " repeats: damage index " + s.min + "-" + s.max + " (SD " + s.sd + ")."));
    }
    const tt = el("table");
    tt.appendChild(rowEl(["failure type", "incidents", "times"], true));
    for (const [k, label] of TAXONOMY) tt.appendChild(rowEl([label, p.taxonomy[k].incidents, p.taxonomy[k].events]));
    out.appendChild(tt);
    const h = p.harness_vs_behaviour;
    out.appendChild(el("p", "subtle", "Harness or behaviour: " + h.incidents_with_harness_problems +
      " incident(s) had a harness-side problem (" + h.placeholder_commands + " unreadable replies or failed calls, " +
      h.timeouts + " timeout(s)); " + h.behaviour_unrecognised_commands + " unrecognised command(s) were the defender's own."));
    const c = p.cost;
    let cost = "Cost: " + c.commands + " commands (" + c.commands_per_incident + " per incident), " +
      c.checking_minutes_per_incident + " simulated minutes of checking per incident";
    if (c.self_reported_tokens != null) cost += ", " + c.self_reported_tokens + " tokens (self-reported)";
    if (c.self_reported_seconds != null) cost += ", " + c.self_reported_seconds + " s (self-reported)";
    out.appendChild(el("p", "subtle", cost + "."));
  }

  function rowEl(cells, head) {
    const tr = el("tr");
    for (const c of cells) tr.appendChild(el(head ? "th" : "td", null, String(c)));
    return tr;
  }

  function load(f) {
    const reader = new FileReader();
    reader.onload = () => { let doc; try { doc = JSON.parse(reader.result); } catch (e) { out.textContent = ""; out.appendChild(el("p", null, "That file is not valid JSON.")); return; } render(doc); };
    reader.readAsText(f);
  }

  // flagwake view serves one report at report.json and opens this page with ?report=latest.
  if (location.protocol === "http:" && new URLSearchParams(location.search).get("report") === "latest") {
    fetch("report.json").then((r) => r.ok ? r.json() : Promise.reject(r.status)).then(render)
      .catch(() => { out.textContent = ""; out.appendChild(el("p", null, "Could not load the report from flagwake view.")); });
  }

  file.addEventListener("change", () => { if (file.files[0]) load(file.files[0]); });
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) load(f); });
})();
