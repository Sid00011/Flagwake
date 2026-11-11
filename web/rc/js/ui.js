/* The local page of flagwake ui. Every value is set with textContent or an SVG attribute (never
   innerHTML), every request carries the per-launch token from the address fragment, and nothing
   is stored in the browser. Headings type out like a receipt printer, once, and not at all when
   the reader prefers reduced motion. */
"use strict";
(function () {
  const TOKEN = new URLSearchParams(location.hash.slice(1)).get("t") || "";
  const REDUCE = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (id) => document.getElementById(id);
  const S = { state: null, current: null, view: "home", watching: null, result: null, runs: [] };
  const SVGNS = "http://www.w3.org/2000/svg";

  // ------------------------------------------------------------------ helpers
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function button(text, fn, cls) { const b = el("button", cls || "ghost", text); b.type = "button"; b.addEventListener("click", fn); return b; }
  function tip(node, text) {
    node.classList.add("q");
    node.tabIndex = 0;
    const t = el("span", "tip", text);
    t.setAttribute("role", "tooltip");
    node.appendChild(t);
    return node;
  }
  async function api(path, body) {
    const opt = { method: body === undefined ? "GET" : "POST", headers: { "X-Flagwake-Token": TOKEN } };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    let data = {};
    try { data = await r.json(); } catch (e) { data = {}; }
    if (!r.ok) throw new Error(data.error || ("That did not work (" + r.status + ")."));
    return data;
  }
  let toastTimer = 0;
  function notice(msg) {
    const n = $("notice");
    n.hidden = !msg;
    n.textContent = msg || "";
    clearTimeout(toastTimer);
    if (msg) toastTimer = setTimeout(() => { n.hidden = true; }, 9000);
  }
  function fail(e) { notice(e && e.message ? e.message : String(e)); }
  function fmtTime(sec) {
    if (sec == null) return "?";
    if (sec < 60) return Math.max(1, Math.round(sec)) + " s";
    if (sec < 3600) return Math.round(sec / 60) + " min";
    return (sec / 3600).toFixed(1) + " h";
  }
  function tone(score) {
    if (score == null) return "none";
    if (score <= 20) return "good";
    if (score <= 60) return "fair";
    if (score <= 105) return "poor";
    return "bad";
  }
  function defender(name) { return (S.state && S.state.defenders.find((d) => d.entry.name === name)) || null; }

  // ------------------------------------------------------------------ headings that print
  function scramble(node) {  // headings are shown as they are; kept as a hook for a heading change
    if (node && node.dataset.text) node.textContent = node.dataset.text;
  }
  function light() {}  // the live room and the result have no backdrop to light

  // ------------------------------------------------------------------ the live map and feed
  const ZONES = { edge: [210, 52], office: [92, 152], servers: [330, 150], core: [210, 246], security: [366, 254] };
  const LINKS = [["edge", "office"], ["edge", "servers"], ["office", "core"], ["servers", "core"], ["core", "security"]];
  const MAP = { nodes: {}, built: false };
  function mk(tag, attrs) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k of Object.keys(attrs)) e.setAttribute(k, String(attrs[k]));
    return e;
  }
  async function buildMap() {
    const key = S.current || "";
    if (MAP.built === key) return;
    MAP.built = key;
    const svg = $("map");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    MAP.nodes = {};
    const data = await api("/api/world?name=" + encodeURIComponent(key));
    const extra = (data.zones || []).filter((z) => !ZONES[z]);
    extra.forEach((z, i) => {  // zones of another company: on a ring around the middle
      const a = (2 * Math.PI * i) / Math.max(1, extra.length);
      ZONES[z] = [210 + Math.round(150 * Math.cos(a)), 150 + Math.round(95 * Math.sin(a))];
    });
    for (const [a, b] of LINKS) svg.appendChild(mk("line", { x1: ZONES[a][0], y1: ZONES[a][1], x2: ZONES[b][0], y2: ZONES[b][1], class: "link" }));
    const byZone = {};
    for (const h of data.hosts) (byZone[h.zone] = byZone[h.zone] || []).push(h);
    for (const z of Object.keys(byZone)) {
      const hosts = byZone[z];
      const [cx, cy] = ZONES[z] || [210, 150];
      const r = hosts.length > 4 ? 60 : hosts.length > 1 ? 34 : 26;
      svg.appendChild(mk("circle", { cx: cx, cy: cy, r: r + 12, class: "hub" }));
      const zl = mk("text", { x: cx, y: cy + 3, "text-anchor": "middle", class: "zone" });
      zl.textContent = z;
      svg.appendChild(zl);
      hosts.forEach((h, i) => {
        const a = (i / hosts.length) * Math.PI * 2 - Math.PI / 2;
        const x = cx + r * Math.cos(a), y = cy + r * Math.sin(a);
        svg.appendChild(mk("line", { x1: cx, y1: cy, x2: x.toFixed(1), y2: y.toFixed(1), class: "link" }));
        const halo = mk("circle", { cx: x.toFixed(1), cy: y.toFixed(1), r: 7, class: "halo" });
        const node = mk("circle", { cx: x.toFixed(1), cy: y.toFixed(1), r: (3.5 + h.crit * 0.9).toFixed(1), class: "node clean" });
        const title = document.createElementNS(SVGNS, "title");
        title.textContent = h.name + " (criticality " + h.crit + ")";
        node.appendChild(title);
        const lbl = mk("text", { x: x.toFixed(1), y: (y < cy - 1 ? y - 9 : y + 15).toFixed(1), "text-anchor": "middle", class: "lbl" });
        lbl.textContent = h.name;
        svg.appendChild(halo); svg.appendChild(node); svg.appendChild(lbl);
        MAP.nodes[h.name] = { node: node, halo: halo };
      });
    }
  }
  function renderFeed(ol, feed) {
    const key = JSON.stringify(feed || []);
    if (ol.dataset.key === key) return;
    ol.dataset.key = key;
    clear(ol);
    for (const f of feed || []) {
      const li = el("li");
      li.appendChild(el("span", "c", f.cmd));
      if (f.obs) li.appendChild(el("span", "o", f.obs));
      ol.appendChild(li);
    }
  }
  function renderLive(live) {
    if (!live) return;
    renderFeed($("lv-feed"), live.feed);
    $("lv-inc").textContent = "Incident " + live.number + " / " + live.total;
    $("lv-fam").textContent = (live.family || "").replace(/-/g, " ");
    $("lv-time").textContent = "min " + live.minute;
    $("lv-clock").setAttribute("width", String(Math.max(0, Math.min(480, live.minute))));
    $("lv-held").textContent = live.held == null ? "-" : live.held;
    $("lv-cont").textContent = live.contained == null ? "-" : live.contained;
    $("lv-wrong").textContent = live.wrong == null ? "-" : live.wrong;
    $("lv-cmds").textContent = live.commands;
    for (const name of Object.keys(MAP.nodes)) {
      const st = (live.hosts || {})[name] || "clean";
      MAP.nodes[name].node.setAttribute("class", "node " + st);
      MAP.nodes[name].halo.setAttribute("class", "halo" + (st === "held" ? " on" : ""));
    }
  }

  // ------------------------------------------------------------------ views
  function show(id) {
    for (const s of document.querySelectorAll("section.view")) {
      s.hidden = s.id !== id;
      s.classList.toggle("enter", s.id === id);
    }
    S.view = id;
    $("chapter").textContent = { s1: "Step 1 of 3", s2: "Step 2 of 3", s3: "Step 3 of 3", s4: "Running", s5: "Result" }[id] || "";
    for (const b of document.querySelectorAll("button.back")) b.hidden = id === "home";
    notice("");
    const h = document.querySelector("#" + id + " h1");
    if (h) { if (h.classList.contains("display")) scramble(h); h.focus({ preventScroll: true }); }
    if (id !== "s4" && id !== "s5") light(0, [155, 231, 255]);
    document.body.classList.toggle("calm", id !== "home");
    window.scrollTo(0, 0);
  }

  // ------------------------------------------------------------------ home
  async function refresh() {
    S.state = await api("/api/state");
    renderHome();
    followJob();
  }
  async function loadRuns() {
    S.runs = (await api("/api/runs")).runs;
    const ul = $("runs");
    clear(ul);
    $("past").hidden = !S.runs.length;
    for (const r of S.runs.slice(0, 12)) {
      const li = el("li");
      const b = button("", () => openResult(r.id).catch(fail));
      const left = el("span");
      left.appendChild(el("span", "nm", r.name));
      left.appendChild(el("span", "mono dim", "  " + r.when + " · " + r.incidents + (r.stopped ? " · stopped" : "")));
      b.appendChild(left);
      b.appendChild(el("span", "sc " + tone(r.damage), r.damage == null ? "-" : Math.round(r.damage)));
      b.setAttribute("aria-label", "Open result of " + r.name + " from " + r.when);
      li.appendChild(b);
      ul.appendChild(li);
    }
  }
  function renderHome() {
    const ul = $("defenders");
    clear(ul);
    const ds = S.state.defenders;
    $("mine").hidden = !ds.length;
    for (const d of ds) {
      const li = el("li");
      const head = el("b");
      head.appendChild(el("span", "dot " + (d.checked ? (d.passed ? "ok" : "no") : ""), ""));
      head.appendChild(document.createTextNode(d.entry.name));
      li.appendChild(head);
      li.appendChild(el("span", "dim", d.label));
      const acts = el("div", "acts");
      acts.appendChild(button("Check", () => goCheck(d.entry.name)));
      acts.appendChild(button("Run", () => goSize(d.entry.name)));
      const rm = button("×", () => removeDefender(d.entry.name), "ghost icon");
      rm.setAttribute("aria-label", "Remove " + d.entry.name);
      acts.appendChild(rm);
      li.appendChild(acts);
      ul.appendChild(li);
    }
    const job = S.state.job, banner = $("running-banner");
    clear(banner);
    banner.hidden = !(job && job.status === "running");
    if (!banner.hidden) {
      banner.appendChild(el("span", "mono", (job.kind === "run" ? "Running " : "Checking ") + job.name + " · " + job.done + " / " + job.total));
      banner.appendChild(button("Open", () => { S.current = job.name; S.watching = job.kind; if (job.kind === "run") buildMap().catch(() => {}); show(job.kind === "run" ? "s4" : "s2"); followJob(); }));
    }
  }
  async function removeDefender(name) {
    if (!window.confirm("Remove " + name + "? Its results stay.")) return;
    try { await api("/api/defenders/remove", { name: name }); await refresh(); } catch (e) { fail(e); }
  }
  function goHome() { show("home"); refresh().then(loadRuns).catch(fail); }

  // ------------------------------------------------------------------ 01 what
  function slug(text) {
    const s = String(text || "").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[^a-z0-9]+/, "").replace(/-+$/, "");
    return s.slice(0, 40) || "my-defender";
  }
  function pickWhat(what) {
    $("f-local").hidden = what !== "local";
    $("f-online").hidden = what !== "online";
    $("f-own").hidden = what !== "own";
    $("f-name").hidden = false;
    if (what === "local") detect();
    if (what === "online") $("name").value = slug($("o-model").value);
    if (what === "own") $("name").value = "my-service";
    ownChanged();
  }
  async function detect() {
    const status = $("detect-status"), list = $("detect-list");
    status.textContent = "Searching...";
    clear(list);
    try {
      const data = await api("/api/detect");
      if (!data.servers.length) { status.textContent = "No model running."; tip(status, data.help); return; }
      status.textContent = "Pick a model";
      let first = true;
      for (const srv of data.servers) {
        for (const m of srv.models) {
          const lab = el("label");
          const r = el("input"); r.type = "radio"; r.name = "local-model"; r.value = m; r.className = "sr";
          r.dataset.base = srv.base_url;
          r.setAttribute("aria-label", m);
          r.addEventListener("change", () => { $("name").value = slug(m); });
          if (first) { r.checked = true; $("name").value = slug(m); first = false; }
          lab.appendChild(r);
          lab.appendChild(el("span", null, m));
          lab.title = srv.base_url;
          list.appendChild(lab);
        }
      }
      if (first) status.textContent = "A server is running, but no model is loaded.";
    } catch (e) { status.textContent = e.message; }
  }
  function ownChanged() {
    const how = (document.querySelector("input[name=own]:checked") || {}).value;
    $("own-url").hidden = how !== "http";
    $("own-cmd-wrap").hidden = how !== "command";
    const allowed = !!(S.state && S.state.allow_commands);
    $("own-cmd-off").hidden = allowed;
    $("own-cmd-on").hidden = !allowed;
  }
  async function save() {
    const what = (document.querySelector("input[name=what]:checked") || {}).value;
    const body = { name: $("name").value.trim() };
    if (what === "local") {
      const r = document.querySelector("input[name=local-model]:checked");
      if (!r) { notice("Start a model, then search again."); return; }
      Object.assign(body, { kind: "model-endpoint", base_url: r.dataset.base, model: r.value });
    } else if (what === "online") {
      Object.assign(body, { kind: "model-endpoint", base_url: $("o-url").value.trim(), model: $("o-model").value.trim() });
      if ($("o-use-env").checked) body.key_env = $("o-env").value.trim();
      else if ($("o-key").value) body.key = $("o-key").value;
    } else if (what === "own") {
      const how = (document.querySelector("input[name=own]:checked") || {}).value;
      if (how === "http") Object.assign(body, { kind: "http", url: $("own-url").value.trim() });
      else Object.assign(body, { kind: "command", command: $("own-cmd").value.trim(), confirm_runs_code: $("own-confirm").checked });
      if (how !== "http" && $("own-tools").checked) body.mode = "tools";
    } else { notice("Pick one first."); return; }
    body.world = $("world-file").value.trim() || $("world").value;
    try {
      await api("/api/defenders", body);
      $("o-key").value = "";
      await refresh();
      goCheck(body.name);
    } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ 02 check
  function pips(state, results) {
    const box = $("pips");
    box.classList.toggle("busy", state === "busy");
    [...box.children].forEach((p, i) => {
      p.className = results && results[i] ? (results[i].passed ? "ok" : "no") : "";
    });
  }
  function goCheck(name) {
    S.current = name;
    const d = defender(name);
    show("s2");
    $("s2-who").textContent = d ? d.label : name;
    clear($("s2-checks"));
    $("s2-status").textContent = "";
    $("ck-feed").hidden = true;
    clear($("ck-feed"));
    pips("idle");
    $("to-s3").hidden = true;
    $("check").className = "cta";
    const e = d ? d.entry : {};
    const online = e.kind === "model-endpoint" && !/^http:\/\/(127\.0\.0\.1|localhost)/.test(e.base_url || "");
    $("s2-key").hidden = !(online && !e.key_env && d && !d.has_key);
    $("s2-confirm-wrap").hidden = !(d && d.runs_code);
    if (d && d.checked) showChecks(name).catch(fail);
  }
  async function saveKey() {
    try { await api("/api/key", { name: S.current, key: $("s2-key-input").value }); $("s2-key-input").value = ""; await refresh(); $("s2-key").hidden = true; }
    catch (e) { fail(e); }
  }
  async function startCheck() {
    try {
      await api("/api/check", { name: S.current, confirm_runs_code: $("s2-confirm").checked });
      S.watching = "check";
      $("s2-status").textContent = "Checking...";
      clear($("s2-checks"));
      pips("busy");
      $("to-s3").hidden = true;
      await refresh();
    } catch (e) { fail(e); }
  }
  async function showChecks(name) {
    const data = await api("/api/checks?name=" + encodeURIComponent(name));
    const ul = $("s2-checks");
    clear(ul);
    pips("done", data.checks);
    const bad = data.checks.filter((c) => !c.passed);
    for (const c of bad) {
      const li = el("li");
      li.appendChild(el("b", null, c.title));
      li.appendChild(el("span", null, c.text));
      ul.appendChild(li);
    }
    const ok = data.checks.length - bad.length;
    $("s2-status").textContent = data.passed ? "Connected · " + ok + " / " + data.checks.length
      : bad.length + (bad.length === 1 ? " problem" : " problems") + " · " + ok + " / " + data.checks.length;
    $("to-s3").hidden = false;
    $("check").className = "ghost";
  }

  // ------------------------------------------------------------------ 03 how much
  function goSize(name) {
    S.current = name;
    const d = defender(name);
    show("s3");
    for (const span of document.querySelectorAll(".est")) {
      const sec = d && d.estimates ? d.estimates[span.dataset.size] : null;
      span.textContent = sec == null ? "time unknown" : "≈ " + fmtTime(sec);
    }
    for (const em of document.querySelectorAll("em[data-count]")) {
      const n = d && d.incidents ? d.incidents[em.dataset.count] : null;
      em.textContent = n == null ? "-" : String(n);
    }
    $("s3-confirm-wrap").hidden = !(d && d.runs_code);
  }
  async function startRun() {
    const size = document.querySelector("input[name=size]:checked").value;
    const pack = document.querySelector("input[name=pack]:checked").value;
    try {
      await api("/api/run", { name: S.current, size: size, pack: pack, confirm_runs_code: $("s3-confirm").checked });
      S.watching = "run";
      buildMap().catch(() => {});
      show("s4");
      $("s4-who").textContent = (defender(S.current) || { label: S.current }).label;
      ring(0, 0);
      await refresh();
    } catch (e) {
      await refresh().catch(() => {});
      const job = S.state && S.state.job;
      if (job && job.status === "running" && job.kind === "run") { openLive(job); return; }
      fail(e);
    }
  }
  function openLive(job) {
    S.current = job.name; S.watching = "run";
    buildMap().catch(() => {});
    show("s4");
    $("s4-who").textContent = (defender(job.name) || { label: job.name }).label;
    followJob();
  }

  // ------------------------------------------------------------------ 04 running
  function ring(done, total) {
    const f = total ? done / total : 0;
    $("ring-fill").setAttribute("stroke-dashoffset", String(326.73 * (1 - f)));
    $("ring-pct").textContent = Math.round(f * 100) + "%";
    $("bar").setAttribute("aria-valuenow", String(Math.round(f * 100)));
    light(f);
  }
  function followJob() {
    const job = S.state && S.state.job;
    if (!job) return;
    if (job.kind === "check" && S.view === "s2" && job.name === S.current) {
      if (job.status === "running") {
        $("s2-status").textContent = "Checking · " + Math.min(job.done + 1, job.total) + " / " + job.total;
        pips("busy");
        if (job.live && job.live.feed.length) { $("ck-feed").hidden = false; renderFeed($("ck-feed"), job.live.feed.slice(-4)); }
      }
      else if (S.watching === "check") {
        S.watching = null;
        pips("idle");
        if (job.status === "failed") $("s2-status").textContent = job.error;
        else showChecks(job.name).catch(fail);
      }
    }
    if (job.kind === "run" && S.view === "s4") {
      ring(job.done, Math.max(1, job.total));
      renderLive(job.live);
      const left = job.remaining == null || job.done >= job.total ? "" : " · " + fmtTime(job.remaining) + " left";
      const stopping = job.status === "running" && job.message.startsWith("Stopping");
      $("s4-status").textContent = job.done + " / " + job.total + left + (stopping ? " · stopping" : "");
      $("stop").disabled = job.status !== "running";
      if (job.status !== "running" && S.watching === "run") {
        S.watching = null;
        if (job.status === "failed") { notice(job.error); return; }
        if (job.result_id) openResult(job.result_id).catch(fail);
        else $("s4-status").textContent = job.message;
      }
    }
  }
  async function stopRun() { try { await api("/api/stop", {}); await refresh(); } catch (e) { fail(e); } }

  // ------------------------------------------------------------------ 05 result
  const ARCS = [[0, 20, "good"], [20, 60, "fair"], [60, 105, "poor"], [105, 200, "bad"]];
  function polar(score, radius) {
    const a = (180 - Math.max(0, Math.min(200, score)) * 0.9) * Math.PI / 180;
    return [100 + radius * Math.cos(a), 100 - radius * Math.sin(a)];
  }
  function buildDial() {
    const svg = $("dial-svg");
    for (const [a, b, cls] of ARCS) {
      const p0 = polar(a + 1.2, 80), p1 = polar(b - 1.2, 80);
      const path = document.createElementNS(SVGNS, "path");
      path.setAttribute("d", "M" + p0[0].toFixed(2) + " " + p0[1].toFixed(2) + " A80 80 0 0 1 " + p1[0].toFixed(2) + " " + p1[1].toFixed(2));
      path.setAttribute("class", "arc " + cls);
      svg.insertBefore(path, svg.firstChild);
    }
  }
  function needle(score) {
    const [x, y] = polar(score == null ? 100 : score, 64);
    $("needle").setAttribute("x2", x.toFixed(2));
    $("needle").setAttribute("y2", y.toFixed(2));
  }
  function chipList(id, items, cls, empty) {
    const ul = $(id);
    clear(ul);
    if (!items.length) { ul.appendChild(el("li", "chip none", empty)); return; }
    for (const c of items) {
      const li = el("li", "chip " + cls, c.short);
      if (c.count) li.appendChild(el("em", null, c.count));
      tip(li, c.detail);
      ul.appendChild(li);
    }
  }
  function pos(v) { return (Math.max(0, Math.min(200, v)) / 2).toFixed(2) + "%"; }
  function barRow(label, value, range, note, cls) {
    const li = el("li", cls || null);
    li.appendChild(el("span", null, label));
    const track = el("span", "track");
    if (range) {
      const band = el("span", "band");
      track.appendChild(band);
      const lo = Math.max(0, Math.min(200, range[0])), hi = Math.max(0, Math.min(200, range[1]));
      band.animate([{ left: pos(lo), width: "0%" }, { left: pos(lo), width: ((hi - lo) / 2).toFixed(2) + "%" }],
        { duration: REDUCE ? 0 : 600, fill: "forwards" });
    }
    const pt = el("span", "pt");
    track.appendChild(pt);
    pt.animate([{ left: "0%" }, { left: pos(value) }], { duration: REDUCE ? 0 : 900, easing: "cubic-bezier(.2,.9,.2,1)", fill: "forwards" });
    li.appendChild(track);
    li.appendChild(el("span", "v", Math.round(value) + (note ? " · " + note : "")));
    return li;
  }
  async function openResult(id) {
    const data = await api("/api/result?id=" + encodeURIComponent(id));
    S.result = data;
    S.current = id.split("/")[0];
    show("s5");
    const p = data.plain, n = p.numbers;
    const score = n.damage;
    $("r-score").textContent = score == null ? "-" : Math.round(score);
    const ci = n.interval;
    $("r-range").textContent = ci && ci[0] != null && ci[1] != null
      ? "95% range " + Math.round(ci[0]) + "–" + Math.round(ci[1]) + " over " + n.live + " live incident" + (n.live === 1 ? "" : "s")
      : "";
    needle(score);
    $("r-name").textContent = S.current;
    showCosts(data.costs || {});
    showPair(data.pair || [], id);
    const example = id.startsWith("example-");
    $("tamper").hidden = !example;
    verifyButton(false);
    $("dial").className = "dial " + (p.tone || "");
    const kpis = $("r-kpis");
    clear(kpis);
    for (const item of data.kpis || []) {
      const tile = el("div", "panel kpi");
      tile.appendChild(el("span", null, item.label));
      tile.appendChild(el("b", item.tone || null, item.value));
      kpis.appendChild(tile);
    }
    clear($("verify-out"));
    $("again").firstChild.textContent = example ? "Test your own defender " : "Run again ";
    $("r-headline").textContent = p.verdict;
    $("r-headline").className = "verdict " + p.tone;
    $("r-long").textContent = p.headline;
    if ($("r-scope")) $("r-scope").textContent = (p.scope || []).join(" ");
    const rgb = { good: [89, 240, 176], fair: [185, 240, 106], poor: [255, 199, 87], bad: [255, 106, 92] }[p.tone] || [155, 231, 255];
    light(1, rgb);
    const packWord = p.pack.startsWith("fresh") ? "fresh" : p.pack.startsWith("held") ? "held-out" : "practice";
    $("r-meta").textContent = n.incidents + " incidents · " + packWord + (data.stopped ? " · stopped early" : "");
    const warn = $("r-warning");
    clear(warn);
    const warnText = [p.warning, p.contamination].filter(Boolean).join(" ");
    warn.hidden = !warnText;
    if (warnText) { warn.appendChild(document.createTextNode(p.warning && p.warning.startsWith("Too few") ? "Too few incidents to be sure" : "Rough result")); tip(warn, warnText); }
    chipList("r-well", p.good, "good", "nothing stood out");
    chipList("r-badly", p.bad, "bad", "nothing stood out");
    const bars = $("r-compare");
    clear(bars);
    if (p.bars) {
      bars.appendChild(barRow("This defender", p.bars.you, p.bars.you_range, "", "you"));
      for (const o of p.bars.others) bars.appendChild(barRow(o.name, o.value, o.range, o.verdict));
    }
    const ex = $("r-examples");
    clear(ex);
    for (const x of p.examples) {
      const box = el("div", "example");
      box.appendChild(el("b", null, x.title));
      box.appendChild(el("div", null, x.text));
      if (x.better) box.appendChild(el("span", null, x.better));
      ex.appendChild(box);
    }
    const ul = $("r-checks");
    clear(ul);
    const passed = data.checks.filter((c) => c.passed).length;
    $("r-checks-sum").textContent = data.checks.length ? "Connection · " + passed + " / " + data.checks.length : "Connection · not checked";
    for (const c of data.checks) {
      const li = el("li", c.passed ? "ok" : null);
      li.appendChild(el("b", null, c.title));
      li.appendChild(el("span", null, c.text));
      ul.appendChild(li);
    }
    $("r-verify").textContent = data.verify;
    await loadRuns();
    const pick = $("cmp-pick");
    clear(pick);
    for (const r of S.runs) {
      if (r.id === id) continue;
      const o = el("option", null, r.name + " · " + r.when + " · " + r.incidents);
      o.value = r.id;
      pick.appendChild(o);
    }
    $("cmp-go").disabled = !pick.options.length;
    $("cmp-table").hidden = true;
    $("cmp-note").textContent = pick.options.length ? "" : "No other result yet.";
  }
  async function download(file) {
    try {
      const r = await fetch("/api/download?id=" + encodeURIComponent(S.result.id) + "&file=" + file, { headers: { "X-Flagwake-Token": TOKEN } });
      if (!r.ok) throw new Error("The file could not be downloaded.");
      const url = URL.createObjectURL(await r.blob());
      const a = el("a");
      a.href = url;
      a.download = file;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) { fail(e); }
  }
  async function compare() {
    try {
      const b = $("cmp-pick").value;
      const data = await api("/api/compare?a=" + encodeURIComponent(S.result.id) + "&b=" + encodeURIComponent(b));
      $("cmp-a").textContent = "this";
      $("cmp-b").textContent = b.split("/")[0];
      const body = $("cmp-table").tBodies[0];
      clear(body);
      for (const row of data.rows) {
        const tr = el("tr");
        for (const cell of row) tr.appendChild(el("td", null, cell));
        body.appendChild(tr);
      }
      $("cmp-table").hidden = false;
      $("cmp-note").textContent = data.same_incidents ? "Same incidents." : "Different incidents: compare with care.";
    } catch (e) { fail(e); }
  }
  // ------------------------------------------------------------------ costs and the demo pair
  const pts = (n) => Number(n).toLocaleString("en-US");
  function showCosts(costs) {
    const rows = $("r-costs");
    clear(rows);
    for (const item of costs.items || []) {
      const li = el("li");
      li.appendChild(el("span", "what", item.label));
      const track = el("span", "track");
      const fill = el("i");
      fill.style.width = Math.max(item.share, 1) + "%";
      track.appendChild(fill);
      li.appendChild(track);
      li.appendChild(el("b", null, item.share ? item.share + "%" : "<1%"));
      li.appendChild(el("span", "pts", pts(item.value)));
      rows.appendChild(li);
    }
    if (!rows.children.length) rows.appendChild(el("li", "dim", "no damage recorded"));
    const scale = $("r-scale");
    clear(scale);
    for (const [label, key] of [["Total damage", "total"], ["Doing nothing would have cost", "nothing"], ["The reference response costs", "best"]]) {
      if (costs[key] == null) continue;
      const li = el("li");
      li.appendChild(el("span", null, label));
      li.appendChild(el("b", null, pts(costs[key])));
      scale.appendChild(li);
    }
    $("r-points-note").textContent = costs.note || "";
  }
  function showPair(pair, id) {
    const box = $("r-pair"), rows = $("r-pair-rows");
    clear(rows);
    box.hidden = pair.length < 2;
    for (const p of pair) {
      const b = el("button", "pair-row" + (p.id === id ? " on" : ""));
      b.type = "button";
      b.appendChild(el("b", p.tone || null, p.score == null ? "-" : String(Math.round(p.score))));
      const words = el("span");
      words.appendChild(el("strong", null, p.name));
      words.appendChild(el("em", null, p.verdict));
      b.appendChild(words);
      if (p.id === id) b.setAttribute("aria-current", "true");
      else b.addEventListener("click", () => openResult(p.id).catch(fail));
      rows.appendChild(b);
    }
  }
  function verifyButton(done) {
    const b = $("verify");
    b.className = done ? "ghost done" : "cta";
    b.lastElementChild.textContent = done ? "Verified" : "Verify";
  }

  // ------------------------------------------------------------------ the demo, verify, tamper
  async function runDemo() {
    const b = $("demo");
    b.disabled = true;
    try {
      const data = await api("/api/demo", {});
      await openResult(data.id);
    } catch (e) { fail(e); } finally { b.disabled = false; }
  }
  const ICONS = {
    ok: "M5 12.5l4.5 4.5L19 7.5",
    no: "M12 8v5M12 16.5v.5M10.3 3.9L2.6 17.3a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  };
  function banner(ok, title, lines, detail) {
    const out = $("verify-out");
    clear(out);
    const b = el("div", "note-banner " + (ok ? "ok" : "no"));
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.appendChild(mk("path", { d: ICONS[ok ? "ok" : "no"] }));
    b.appendChild(svg);
    b.appendChild(el("b", null, title));
    for (const line of lines) b.appendChild(el("p", null, line));
    if (detail) b.appendChild(el("p", "why", detail));
    out.appendChild(b);
  }
  async function verifyNow() {
    try {
      const v = await api("/api/verify", { id: S.result.id });
      verifyButton(v.ok);
      if (v.ok) banner(true, "Verified", ["Every number was re-derived from " + v.commands + " stored commands in " + v.incidents + " incidents and matches the report."]);
      else banner(false, "Does not verify", ["Some numbers do not match the stored commands."], v.problems.join(" "));
    } catch (e) { fail(e); }
  }
  async function tamperNow() {
    try {
      const v = await api("/api/tamper", { id: S.result.id });
      if (v.caught) banner(false, "Edited copy rejected", ["The damage index was changed from " + v.before + " to " + v.after + " in a copy of this report. The report itself is unchanged."], v.message);
      else banner(false, "The edit was not caught", ["Please report this as a problem."]);
    } catch (e) { fail(e); }
  }
  function again() {
    if (S.result && S.result.id.startsWith("example-")) show("s1");
    else goSize(S.current);
  }

  async function copyVerify() {
    try { await navigator.clipboard.writeText($("r-verify").textContent); notice("Copied."); } catch (e) { notice("Select the command and copy it."); }
  }

  // ------------------------------------------------------------------ wiring
  for (const r of document.querySelectorAll("input[name=what]")) r.addEventListener("change", () => pickWhat(r.value));
  for (const r of document.querySelectorAll("input[name=own]")) r.addEventListener("change", ownChanged);
  $("o-use-env").addEventListener("change", () => { $("o-env").hidden = !$("o-use-env").checked; $("o-key").hidden = $("o-use-env").checked; });
  $("o-model").addEventListener("input", () => { $("name").value = slug($("o-model").value); });
  $("add").addEventListener("click", () => show("s1"));
  $("detect-again").addEventListener("click", detect);
  $("save").addEventListener("click", save);
  $("s2-key-save").addEventListener("click", saveKey);
  $("check").addEventListener("click", startCheck);
  $("to-s3").addEventListener("click", () => goSize(S.current));
  $("start").addEventListener("click", startRun);
  $("stop").addEventListener("click", stopRun);
  $("dl-json").addEventListener("click", () => download("report.json"));
  $("dl-html").addEventListener("click", () => download("report.html"));
  $("again").addEventListener("click", again);
  $("cmp-go").addEventListener("click", compare);
  $("copy").addEventListener("click", copyVerify);
  $("demo").addEventListener("click", runDemo);
  $("verify").addEventListener("click", verifyNow);
  $("tamper").addEventListener("click", tamperNow);
  for (const b of document.querySelectorAll("button.back")) b.addEventListener("click", goHome);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && S.view !== "home" && S.view !== "s4") goHome(); });

  buildDial();
  scramble(document.querySelector("#home h1"));
  if (!TOKEN) {
    notice("Open the address printed in the window where you started Flagwake.");
    clearTimeout(toastTimer);
    return;
  }
  setInterval(() => {
    const job = S.state && S.state.job;
    if ((job && job.status === "running") || S.watching) refresh().catch(() => {});
  }, 1000);
  refresh().then(() => {
    const job = S.state.job;
    if (job && job.status === "running") {
      S.current = job.name; S.watching = job.kind;
      if (job.kind === "run") buildMap().catch(() => {});
      show(job.kind === "run" ? "s4" : "s2");
      $(job.kind === "run" ? "s4-who" : "s2-who").textContent = (defender(job.name) || { label: job.name }).label;
      followJob();
    }
    return loadRuns();
  }).catch(fail);
})();
