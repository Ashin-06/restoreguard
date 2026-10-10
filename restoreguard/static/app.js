"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { demo: null, busy: false, current: null, selected: null, rows: [], cases: [], presentation: "map" };
  const components = ["identity", "permissions", "secrets"];
  const checkpoints = ["A", "B", "C"];
  const own = (value, key) => value != null && Object.prototype.hasOwnProperty.call(value, key);
  const first = (...values) => values.find((value) => value !== undefined && value !== null);
  const array = (value) => Array.isArray(value) ? value : [];
  const json = (value) => JSON.stringify(value, null, 2) ?? "Not reported";
  const display = (value) => value === undefined ? "Not reported" : value === null ? "null" : typeof value === "object" ? json(value) : String(value);
  const plural = (n, noun) => `${n} ${noun}${n === 1 ? "" : "s"}`;
  const pretty = (value) => String(value || "").replaceAll("_", " ");
  const selectionKey = (selection) => components.map((name) => selection?.[name] || "?").join("");
  const date = (value) => { const d = new Date(value); return Number.isNaN(d.getTime()) ? display(value) : d.toLocaleString(undefined, { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }); };

  function el(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  }

  function announce(message, loading = false) {
    $("live-status").textContent = message;
    $("live-status").classList.toggle("loading", loading);
    $("live-status").hidden = !message;
  }

  function error(message) { $("error-banner").textContent = message; $("error-banner").hidden = false; }
  function clearError() { $("error-banner").textContent = ""; $("error-banner").hidden = true; }

  function statusOf(value, fallback = "INCONCLUSIVE") {
    const raw = typeof value === "string" ? value : value && first(value.status, value.outcome);
    const status = typeof raw === "string" ? raw.toUpperCase() : "";
    if (["PASS", "PASSED", "OK"].includes(status)) return "PASS";
    if (["FAIL", "FAILED"].includes(status)) return "FAIL";
    if (["INCONCLUSIVE", "UNRESOLVED", "ERROR"].includes(status)) return "INCONCLUSIVE";
    return fallback;
  }

  function pill(status, label) { return el("span", `pill ${status === "PASS" ? "pass" : status === "FAIL" ? "fail" : status === "INCONCLUSIVE" ? "inconclusive" : "neutral"}`, label || status); }

  function setPill(id, status, label) {
    const element = $(id);
    element.className = `pill ${status === "PASS" ? "pass" : status === "FAIL" ? "fail" : "inconclusive"}`;
    element.textContent = label || status;
  }

  async function api(path, options = {}) {
    let response;
    try { response = await fetch(path, { ...options, headers: { "Accept": "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } }); }
    catch { throw new Error("The local lab could not be reached. Check that the RestoreGuard server is running and try again."); }
    let data;
    try { data = await response.json(); }
    catch { throw new Error(`The server returned an unreadable response (${response.status}). No experiment result was accepted.`); }
    if (!response.ok) throw new Error(display(first(data?.error, data?.detail, data?.message, `Request failed (${response.status}).`)));
    return data;
  }

  function hasRoleTarget(row) {
    return array(row?.findings).some((finding) => typeof finding === "string" ? finding === "revived_role" : finding.kind === "revived_role" && (!finding.actor || finding.actor === "removed-user")) || array(row?.observations).some((observation) => observation.kind === "revived_role" && observation.actor === "removed-user" && statusOf(observation) === "FAIL");
  }

  function setBusy(busy, kind = "run") {
    state.busy = busy;
    ["run-button", "run-scenarios", "refresh-archive", "mode", "budget", "repeats"].forEach((id) => { $(id).disabled = busy || (["run-button", "mode"].includes(id) && !state.demo); });
    $("minimize-button").disabled = busy || !hasRoleTarget(state.selected);
    $("run-label").textContent = busy && kind === "run" ? "Testing recovery states…" : "Run recovery matrix";
    $("matrix-workspace").setAttribute("aria-busy", String(busy));
    document.querySelectorAll(".archive-open").forEach((button) => { button.disabled = busy; });
  }

  function activateView(name, focus = false) {
    document.querySelectorAll(".nav-tab").forEach((tab) => {
      const selected = tab.dataset.view === name;
      tab.classList.toggle("active", selected); tab.setAttribute("aria-selected", String(selected)); tab.tabIndex = selected ? 0 : -1;
      if (selected && focus) tab.focus();
    });
    document.querySelectorAll(".view").forEach((view) => { view.hidden = view.id !== `view-${name}`; });
    if (name === "archive") refreshArchive().catch((reason) => error(reason.message));
  }

  document.querySelectorAll(".nav-tab").forEach((tab, index, tabs) => {
    tab.addEventListener("click", () => activateView(tab.dataset.view));
    tab.addEventListener("keydown", (event) => {
      let target;
      if (event.key === "ArrowRight") target = (index + 1) % tabs.length;
      if (event.key === "ArrowLeft") target = (index + tabs.length - 1) % tabs.length;
      if (event.key === "Home") target = 0;
      if (event.key === "End") target = tabs.length - 1;
      if (target !== undefined) { event.preventDefault(); activateView(tabs[target].dataset.view, true); }
    });
  });

  function updateModeDescription() {
    $("mode-description").textContent = $("mode").value === "protected" ? "Checks the current independent policy after recovery. Use this as the protected comparison fixture." : "Trusts restored component state. Includes deliberately seeded recovery-security failures.";
  }
  $("mode").addEventListener("change", updateModeDescription);

  function filterMatch(row) { const filter = $("status-filter").value; return filter === "all" || statusOf(row) === filter; }

  function selectExperiment(row, scroll = false) {
    state.selected = row;
    $("minimize-result").hidden = true;
    $("selected-selection").textContent = components.map((name) => `${name.charAt(0).toUpperCase()}: ${row.selection?.[name] || "?"}`).join("  /  ");
    $("selected-json").textContent = json(row);
    const findings = $("selected-findings"); findings.replaceChildren();
    array(row.findings).forEach((finding) => {
      findings.append(el("span", "finding-chip", typeof finding === "string" ? pretty(finding) : [pretty(first(finding.kind, finding.code, "finding")), finding.actor].filter(Boolean).join(" · ")));
    });
    if (!array(row.findings).length) findings.append(pill(statusOf(row), statusOf(row) === "PASS" ? "No policy failures observed" : statusOf(row) === "INCONCLUSIVE" ? "Outcome not established" : "See recorded observations"));
    const container = $("observations"); container.replaceChildren();
    if (!array(row.observations).length) container.append(el("p", "empty-inline", "No structured observations were returned. Inspect the complete experiment record below."));
    array(row.observations).forEach((observation) => {
      const card = el("article", "observation"); const heading = el("div", "observation-head"); const title = el("div");
      title.append(el("strong", "", `${first(observation.actor, observation.actor_ref, "Unknown actor")} · ${pretty(observation.action || "probe")}`), el("small", "", `Resource: ${first(observation.resource, observation.resource_ref, "Not reported")}${observation.kind ? ` · ${pretty(observation.kind)}` : ""}`));
      const status = statusOf(observation); heading.append(title, pill(status)); card.append(heading);
      const values = el("div", "observation-values");
      const effect = observation.effect_occurred === true ? "Yes" : observation.effect_occurred === false ? "No" : "Unknown";
      const fields = [["Expected decision", first(observation.expected, observation.expected_decision), "Current independent policy"], ["Observed effect", first(observation.observed, observation.observed_effect), "Authoritative probe result"], ["Effect occurred", effect, "Protected action observed"], ["Transport status", observation.transport_status, "Supporting evidence only"]];
      fields.forEach(([label, value, hint], index) => { const cell = el("div"); cell.append(el("span", "", label), el("strong", index === 1 && status === "FAIL" ? "observed-fail" : "", display(value)), el("small", "", hint)); values.append(cell); });
      card.append(values); container.append(card);
    });
    const target = hasRoleTarget(row);
    $("minimize-button").disabled = state.busy || !target;
    const mode = first(state.current?.result?.mode, state.current?.mode, state.current?.config?.mode, "unknown");
    $("minimize-hint").textContent = target ? `Target found in ${selectionKey(row.selection)}. Reduction uses this run’s ${mode} fixture and keeps the same actor and failure kind.` : "Target unavailable in this selection. Choose a policy-failing tile with a revived role for removed-user; other failure kinds are not reduced by this demo.";
    renderMatrixViews();
    if (scroll) $("observation-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderMatrixViews() {
    const map = $("matrix-map"); map.replaceChildren();
    const records = new Map(state.rows.map((row) => [selectionKey(row.selection), row]));
    const selectedKey = state.selected ? selectionKey(state.selected.selection) : null;
    checkpoints.forEach((identity) => {
      const group = el("div", "matrix-group"); const heading = el("h3"); heading.append(document.createTextNode("Identity "), el("strong", "", identity));
      group.append(heading, el("p", "matrix-axis-note", "Columns: permissions · rows: secrets"));
      const grid = el("div", "matrix-grid"); grid.append(el("span", "axis-label", "")); checkpoints.forEach((label) => grid.append(el("span", "axis-label", label)));
      checkpoints.forEach((secrets) => {
        grid.append(el("span", "axis-label", secrets));
        checkpoints.forEach((permissions) => {
          const key = `${identity}${permissions}${secrets}`; const row = records.get(key); const filtered = row && !filterMatch(row); const status = row ? statusOf(row) : "NOT TESTED";
          const button = el("button", `matrix-cell ${!row ? "untested" : filtered ? "filtered" : status.toLowerCase()} ${selectedKey === key ? "selected" : ""}`, !row ? "—" : filtered ? "·" : status === "PASS" ? "✓" : status === "FAIL" ? "!" : "?");
          button.type = "button"; button.disabled = !row || filtered;
          button.setAttribute("aria-label", `Identity ${identity}, permissions ${permissions}, secrets ${secrets}: ${filtered ? "hidden by filter" : status === "FAIL" ? "policy failure" : status.toLowerCase()}`);
          button.setAttribute("aria-pressed", String(selectedKey === key)); button.title = `${key} · ${status}`;
          if (row) button.addEventListener("click", () => selectExperiment(row, window.matchMedia("(max-width: 620px)").matches));
          grid.append(button);
        });
      }); group.append(grid); map.append(group);
    });
    const body = $("matrix-body"); body.replaceChildren(); const matches = state.rows.filter(filterMatch);
    matches.forEach((row) => {
      const tr = el("tr", selectionKey(row.selection) === selectedKey ? "selected" : "");
      components.forEach((component) => tr.append(el("td", "", row.selection?.[component] || "?")));
      const resultCell = el("td"); resultCell.append(pill(statusOf(row))); tr.append(resultCell, el("td", "", array(row.findings).length));
      const action = el("td"); const button = el("button", "button secondary-button small-button", "Inspect ↗"); button.type = "button"; button.setAttribute("aria-label", `Inspect recovery combination ${selectionKey(row.selection)}`); button.addEventListener("click", () => selectExperiment(row, true)); action.append(button); tr.append(action); body.append(tr);
    });
    $("filter-empty").hidden = matches.length > 0;
  }

  function setPresentation(name) {
    state.presentation = name;
    $("matrix-map").hidden = name !== "map"; $("map-instructions").hidden = name !== "map"; $("matrix-table-wrap").hidden = name !== "table";
    ["map", "table"].forEach((view) => { $(`show-${view}`).classList.toggle("selected", view === name); $(`show-${view}`).setAttribute("aria-pressed", String(view === name)); });
  }
  $("show-map").addEventListener("click", () => setPresentation("map"));
  $("show-table").addEventListener("click", () => setPresentation("table"));
  $("status-filter").addEventListener("change", renderMatrixViews);

  function renderScope(result) {
    const container = $("run-limitations"); container.replaceChildren();
    if (result.scope) container.append(el("p", "", display(result.scope)));
    if (Array.isArray(result.limitations)) { const list = el("ul"); result.limitations.forEach((item) => list.append(el("li", "", display(item)))); container.append(list); }
    else if (result.limitations) container.append(el("p", "", display(result.limitations)));
    container.append(el("p", "", "These are synthetic SQLite fixture findings. No production Keycloak or Vault integration is exercised by this workbench."));
  }

  function renderExports(data) {
    const actions = $("export-actions"); actions.replaceChildren();
    [["report", "↓ Report"], ["json", "↓ JSON"], ["bundle", "↓ Bundle"]].forEach(([type, label]) => {
      const path = data.artifacts?.[type] || (data.case_id ? `/api/cases/${encodeURIComponent(data.case_id)}/${type}` : null);
      if (typeof path !== "string" || !path.startsWith("/api/cases/")) return;
      let url; try { url = new URL(path, window.location.origin); } catch { return; }
      if (url.origin !== window.location.origin) return;
      const link = el("a", "button secondary-button", label); link.href = url.pathname + url.search; link.setAttribute("download", ""); link.setAttribute("aria-label", `Download ${type === "report" ? "HTML report" : type === "json" ? "run JSON" : "evidence bundle"}`); actions.append(link);
    });
    $("case-meta").textContent = [data.case_id ? `Run ${data.case_id}` : "Run ID not reported", data.created_at ? date(data.created_at) : null].filter(Boolean).join(" · ");
  }

  function renderRun(payload) {
    const data = payload.case?.result ? payload.case : payload; const result = data.result || data; const summary = result.summary || {};
    state.current = data; state.rows = array(result.results); state.selected = null;
    const failed = Number(first(summary.failed, state.rows.filter((row) => statusOf(row) === "FAIL").length));
    const passed = Number(first(summary.passed, state.rows.filter((row) => statusOf(row) === "PASS").length));
    const inconclusive = Number(first(summary.inconclusive, state.rows.filter((row) => statusOf(row) === "INCONCLUSIVE").length));
    const attempted = Number(first(summary.attempted, state.rows.length)); const planned = Number(first(summary.planned, 27));
    const complete = summary.complete === true && attempted >= planned;
    const status = failed > 0 ? "FAIL" : inconclusive > 0 || !complete ? "INCONCLUSIVE" : statusOf(result);
    $("run-banner").className = `result-banner ${status === "PASS" ? "pass" : status === "INCONCLUSIVE" ? "inconclusive" : ""}`;
    $("run-status-icon").textContent = status === "PASS" ? "✓" : status === "FAIL" ? "!" : "?";
    $("run-eyebrow").textContent = `${String(first(result.mode, data.config?.mode, "fixture")).toUpperCase()} FIXTURE · ${complete ? "MATRIX COMPLETE" : "PARTIAL COVERAGE"}`;
    $("run-title").textContent = failed > 0 ? `${plural(failed, "configuration")} violated expected policy` : inconclusive > 0 ? "Some recovery outcomes remain inconclusive" : !complete ? "No policy failure observed; coverage incomplete" : "All tested recovery expectations held";
    $("run-description").textContent = failed > 0 ? "These are detected fixture failures, including returned authority or broken legitimate access. Select a combination to inspect its evidence." : complete && inconclusive === 0 ? "The declared matrix passed. This result is limited to the synthetic fixtures, checkpoints, and probes in this run." : `${attempted} of ${planned} planned combinations were attempted. Untested or inconclusive outcomes are not passes.`;
    setPill("run-status-pill", status, failed > 0 ? "FINDINGS" : !complete ? "INCOMPLETE" : status);
    $("metric-attempted").textContent = attempted; $("metric-planned").textContent = `of ${planned} combinations`;
    $("metric-failed").textContent = failed; $("metric-passed").textContent = passed; $("metric-inconclusive").textContent = inconclusive;
    $("metric-coverage").textContent = complete ? "Complete" : "Partial";
    $("status-filter").value = "all";
    renderExports(data); renderScope(result);
    $("matrix-empty").hidden = true; $("matrix-results").hidden = false;
    $("observation-panel").hidden = state.rows.length === 0;
    const initial = state.rows.find(hasRoleTarget) || state.rows.find((row) => statusOf(row) === "FAIL") || state.rows[0];
    if (initial) selectExperiment(initial); else { renderMatrixViews(); $("minimize-button").disabled = true; $("minimize-hint").textContent = "No evaluated combination is available for reduction."; }
    return { status, complete, failed, attempted };
  }

  $("run-form").addEventListener("submit", async (event) => {
    event.preventDefault(); if (state.busy) return;
    clearError(); setBusy(true); announce("Restoring isolated checkpoint combinations and checking current security expectations. Each experiment starts from a fresh synthetic fixture.", true);
    try {
      const data = await api("/api/run", { method: "POST", body: JSON.stringify({ mode: $("mode").value, max_experiments: Number($("budget").value), repeats: Number($("repeats").value) }) });
      const outcome = renderRun(data);
      announce(`Recovery matrix finished: ${outcome.attempted} combinations attempted, ${plural(outcome.failed, "configuration")} with policy failures. Coverage is ${outcome.complete ? "complete within the declared matrix" : "partial"}.`);
      await refreshArchive(true);
      if (window.matchMedia("(max-width: 900px)").matches) $("run-banner").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (reason) { announce(""); error(`Experiment could not complete: ${reason.message}`); }
    finally { setBusy(false); }
  });

  function renderRestoreSteps(container, selection) {
    container.replaceChildren();
    const restores = components.filter((component) => selection?.[component] && selection[component] !== "C");
    if (!restores.length) { container.append(el("p", "field-hint", "No restore operation; current checkpoint C is retained.")); return; }
    restores.forEach((component) => { const row = el("div", "restore-step"); row.append(el("span", "", selection[component]), document.createTextNode(`Restore ${component}`)); container.append(row); });
    const unchanged = components.filter((component) => selection?.[component] === "C");
    if (unchanged.length) container.append(el("p", "field-hint", `${unchanged.join(", ")} remain at current checkpoint C.`));
  }

  $("minimize-button").addEventListener("click", async () => {
    if (state.busy || !hasRoleTarget(state.selected)) return;
    const selection = { ...state.selected.selection }; const mode = first(state.current?.result?.mode, state.current?.mode, state.current?.config?.mode, "vulnerable");
    clearError(); setBusy(true, "minimize"); announce("Reducing this restore recipe while preserving the revived role for removed-user…", true);
    try {
      const data = await api("/api/minimize", { method: "POST", body: JSON.stringify({ selection, mode, target_kind: "revived_role", target_actor: "removed-user", max_evaluations: 100 }) });
      const status = statusOf(data); const minimal = data.one_minimal === true && data.budget_exhausted !== true && status === "FAIL";
      $("minimize-title").textContent = status === "FAIL" ? `${first(data.original_steps, "?")} → ${first(data.minimized_steps, "?")} restore operations` : status === "PASS" ? "The target failure was not reproduced" : "Reduction is inconclusive";
      setPill("minimize-pill", minimal ? "PASS" : "INCONCLUSIVE", minimal ? "1-MINIMAL" : data.budget_exhausted ? "BUDGET REACHED" : "UNCONFIRMED");
      renderRestoreSteps($("original-steps"), data.original_selection || selection);
      renderRestoreSteps($("minimized-steps"), data.minimized_selection || selection);
      $("minimize-description").textContent = `${first(data.evaluations, "Unknown number of")} evaluations. ${minimal ? "No single remaining restore operation can be removed while preserving the same target failure under the tested checks. This is not a proof of a globally shortest recipe." : "A 1-minimal reproduction has not been established. Review the reduction history and limitations before interpreting the recipe."}`;
      $("minimize-json").textContent = json(data); $("minimize-result").hidden = false;
      announce(minimal ? "The target failure was preserved in a 1-minimal restore recipe within the lab’s tested scope." : "Reduction finished without a confirmed 1-minimal witness. Review the result details.");
    } catch (reason) { announce(""); error(`Reduction could not complete: ${reason.message}`); }
    finally { setBusy(false); }
  });

  function renderScenarios(data) {
    const summary = data.summary || {}; const results = array(data.results); const status = statusOf(data);
    $("scenario-banner").className = `result-banner ${status === "PASS" ? "pass" : "inconclusive"}`;
    $("scenario-icon").textContent = status === "PASS" ? "✓" : "!";
    $("scenario-title").textContent = status === "PASS" ? "The lab identified the expected outcomes" : "Some scenario checks did not meet expectations";
    $("scenario-description").textContent = `${first(summary.passed, "?")} of ${first(summary.total, results.length)} scenario checks passed; ${first(summary.failed, "?")} failed. Seeded fixture failures remain failures, even when the check correctly detects them.`;
    setPill("scenario-pill", status);
    const list = $("scenario-list"); list.replaceChildren();
    results.forEach((item, index) => {
      const card = el("article", "scenario-card"); card.append(el("div", "scenario-id", first(item.id, `SCENARIO ${index + 1}`)));
      const heading = el("div", "scenario-card-head"); heading.append(el("h3", "", first(item.title, item.name, `Scenario ${index + 1}`)), pill(statusOf(item), `${statusOf(item)} CHECK`)); card.append(heading);
      card.append(el("p", "", `Expected fixture outcome: ${display(item.expected_outcome)} · Observed: ${display(item.observed_outcome)}`));
      if (item.expected_kind || array(item.observed_kinds).length) card.append(el("p", "", `Expected finding: ${pretty(item.expected_kind) || "none"}. Observed findings: ${array(item.observed_kinds).map(pretty).join(", ") || "none"}.`));
      const raw = el("details", "raw-details"); raw.append(el("summary", "", "Inspect scenario evidence"), el("pre", "", json(item))); card.append(raw); list.append(card);
    });
    $("scenario-json").textContent = json(data); $("scenarios-empty").hidden = true; $("scenario-results").hidden = false;
    return status;
  }

  $("run-scenarios").addEventListener("click", async () => {
    if (state.busy) return;
    clearError(); setBusy(true, "scenarios"); announce("Checking the seeded failures, protected control, and inconclusive scenarios…", true);
    try { const data = await api("/api/scenarios", { method: "POST", body: "{}" }); const status = renderScenarios(data); announce(status === "PASS" ? "All scenario expectations were correctly identified within the bundled suite." : "The scenario suite found unexpected outcomes. Inspect the individual checks."); }
    catch (reason) { announce(""); error(`Scenario checks could not complete: ${reason.message}`); }
    finally { setBusy(false); }
  });

  async function refreshArchive(quiet = false) {
    try {
      const data = await api("/api/cases"); state.cases = array(data.cases);
      $("archive-count").textContent = state.cases.length; $("archive-empty").hidden = state.cases.length > 0; $("archive-table-wrap").hidden = state.cases.length === 0;
      const body = $("archive-body"); body.replaceChildren();
      state.cases.forEach((item) => {
        const summary = item.summary || item.result?.summary || {}; const tr = el("tr");
        tr.append(el("td", "", item.case_id), el("td", "", date(item.created_at)), el("td", "", first(item.mode, item.config?.mode, item.result?.mode, "Not reported")));
        const status = el("td"); status.append(pill(statusOf(item))); tr.append(status);
        const attempted = first(summary.attempted, item.attempted, "?"); const planned = first(summary.planned, item.planned, 27);
        tr.append(el("td", "", `${attempted} / ${planned}`));
        const cell = el("td"); const button = el("button", "button secondary-button small-button archive-open", "Open ↗"); button.type = "button"; button.disabled = state.busy; button.setAttribute("aria-label", `Open run ${item.case_id}`); button.addEventListener("click", () => openRun(item.case_id)); cell.append(button); tr.append(cell); body.append(tr);
      });
    } catch (reason) { if (!quiet) throw reason; $("archive-count").textContent = "—"; }
  }

  async function openRun(caseId) {
    if (state.busy) return;
    clearError(); setBusy(true, "archive"); announce("Opening the saved recovery matrix…", true);
    try {
      const data = await api(`/api/cases/${encodeURIComponent(caseId)}/json`); renderRun(data); activateView("matrix");
      announce(`Opened run ${caseId}. Results use the saved configuration; the setup controls remain ready for your next experiment.`);
      $("run-banner").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (reason) { announce(""); error(`Could not open this run: ${reason.message}`); }
    finally { setBusy(false); }
  }

  $("refresh-archive").addEventListener("click", async () => {
    clearError(); try { await refreshArchive(); announce(`Archive refreshed. ${plural(state.cases.length, "run")} available.`); } catch (reason) { error(reason.message); }
  });

  async function initialize() {
    const results = await Promise.allSettled([api("/api/demo"), refreshArchive(true)]);
    const demo = results[0];
    if (demo.status === "fulfilled") {
      try {
        if (!array(demo.value.modes).length) throw new Error("No fixture modes were returned by the local lab.");
        state.demo = demo.value; $("mode").replaceChildren();
        demo.value.modes.forEach((value) => { const option = el("option", "", value === "vulnerable" ? "Vulnerable · seeded failures" : value === "protected" ? "Protected · current policy" : display(value)); option.value = String(value); $("mode").append(option); });
        if (demo.value.modes.includes("vulnerable")) $("mode").value = "vulnerable";
        updateModeDescription(); setBusy(false); $("connection").className = "connection connected"; $("connection-text").textContent = "Local lab connected";
      } catch (reason) { state.demo = null; setBusy(false); error(reason.message); $("connection").className = "connection disconnected"; $("connection-text").textContent = "Lab setup unavailable"; }
    } else { $("connection").className = "connection disconnected"; $("connection-text").textContent = "Local lab disconnected"; error(demo.reason.message); }
  }

  initialize();
})();
