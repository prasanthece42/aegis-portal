"use strict";
let monitoringGeneration = 0;
let monitoringState = { signal: "metrics", target: null, targets: [] };
function clearMonitoring() {
  monitoringGeneration++;
  $("monitoring-observed").textContent = "";
  signalState("");
  monitoringState = { signal: "metrics", target: null, targets: [] };
  for (const id of ["monitoring-content", "trace-spans", "monitoring-target"]) $(id).replaceChildren();
  $("trace-detail").hidden = true;
}
function signalState(message) { $("monitoring-state").textContent = message; }
async function monitoringView(selected) {
  if (!state.session) { show("sign-in"); return; }
  const apps = await api("/api/v1/applications");
  const targets = [];
  for (const app of apps.items) {
    for (const env of Object.keys(app.environments)) {
      const access = app.access;
      if (![...access.owner_user_ids, ...access.viewer_user_ids, ...(access.deployer_user_ids_by_environment[env] || [])].includes(state.session.user_id)) continue;
      targets.push({ id: `app:${app.app_id}:${env}`, label: `${app.display_name} · ${env.toUpperCase()}`, app: app.app_id, env });
    }
  }
  if (state.session.allowed_actions.includes("platform:view")) {
    targets.push({ id: "platform:portal", label: "Platform portal", platform: "portal" });
    targets.push({ id: "platform:cluster", label: "Cluster overview", platform: "cluster" });
  }
  clearMonitoring();
  monitoringState.targets = targets;
  $("monitoring-target").replaceChildren(...targets.map(target => new Option(target.label, target.id)));
  if (targets.some(target => target.id === selected)) $("monitoring-target").value = selected;
  show("monitoring");
  if (!targets.length) {
    signalState("No monitored applications are available to this identity.");
    $("monitoring-content").replaceChildren(); return;
  }
  await loadSignal("metrics");
}
function monitoringPath(traceId) {
  const target = monitoringState.targets.find(row => row.id === $("monitoring-target").value);
  if (!target) throw new Error("Select an application or platform service.");
  monitoringState.target = target;
  const base = target.platform ? `/api/v1/platform/observability/${target.platform}` : `/api/v1/applications/${encodeURIComponent(target.app)}/observability`;
  const query = new URLSearchParams({ window: $("monitoring-window").value });
  if (target.env) query.set("environment", target.env);
  return base + (traceId ? `/traces/${encodeURIComponent(traceId)}` : "/" + monitoringState.signal) + "?" + query;
}
function displayMetric(key, value) {
  if (!Number.isFinite(value)) return "No sample";
  if (key.includes("memory") || key.includes("capacity")) return (value / 1048576).toFixed(1) + " MiB";
  if (key === "latency") return (value * 1000).toFixed(1) + " ms";
  if (key === "requests") return value.toFixed(2) + " req/s";
  return value.toFixed(3) + " cores";
}
function svgElement(name, attrs, label) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, String(value));
  if (label !== undefined) element.textContent = label;
  return element;
}
function metricChart(series) {
  const card = node("article", undefined, "card metric-card");
  card.append(node("h2", series.label));
  const points = series.points.filter(row => row.length === 2 && row.every(Number.isFinite));
  if (!points.length) { card.append(node("p", "No samples in this window", "muted")); return card; }
  card.append(node("strong", displayMetric(series.key, points[points.length - 1][1]), "metric-value"));
  const svg = svgElement("svg", { viewBox: "0 0 600 160", role: "img", "aria-label": series.label + " over selected time window" });
  const minX = points[0][0], maxX = Math.max(minX + 1, points[points.length - 1][0]);
  const minY = Math.min(0, ...points.map(row => row[1]));
  const maxY = Math.max(minY + 0.001, ...points.map(row => row[1]));
  svg.append(svgElement("line", { x1: 12, y1: 145, x2: 588, y2: 145, stroke: "#dce3df" }));
  let path = "", previous = null;
  for (const [stamp, value] of points) {
    const x = 12 + (stamp - minX) / (maxX - minX) * 576, y = 140 - (value - minY) / (maxY - minY) * 125;
    path += `${previous === null || stamp - previous > 90 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)} `;
    previous = stamp;
  }
  svg.append(svgElement("path", { d: path, fill: "none", stroke: "#14694b", "stroke-width": 2.5 }));
  card.append(svg, node("small", `Samples shown: ${points.length} · latest chart point ${new Date(points[points.length - 1][0] * 1000).toLocaleTimeString()}`, "muted"));
  return card;
}
async function loadSignal(signal) {
  const generation = ++monitoringGeneration;
  monitoringState.signal = signal;
  for (const button of document.querySelectorAll("[data-signal]")) button.setAttribute("aria-selected", String(button.dataset.signal === signal));
  $("monitoring-content").replaceChildren(); $("trace-detail").hidden = true;
  $("monitoring-observed").textContent = "";
  $("trace-spans").replaceChildren();
  signalState("Loading authorized telemetry…");
  const path = monitoringPath();
  $("monitoring-title").textContent = monitoringState.target.label;
  if (monitoringState.target.platform === "cluster" && ["logs", "traces"].includes(signal)) {
    signalState("Select an application or the platform portal to inspect logs and traces."); return;
  }
  let data;
  try { data = await api(path); }
  catch (problem) {
    if (generation !== monitoringGeneration) return;
    signalState(problem.message); throw problem;
  }
  if (generation !== monitoringGeneration || !state.session) return;
  $("monitoring-observed").textContent = `Data fetched ${new Date(data.observed_at).toLocaleString()} · ${$("monitoring-window").selectedOptions[0].textContent}`;
  if (signal === "metrics") {
    signalState(data.application_signal === "fresh" ? "Application heartbeat observed within 90 seconds." : data.application_signal === "stale" ? "Application heartbeat is stale. Charts may contain historical samples." : monitoringState.target.platform === "cluster" ? "Cluster usage from the enrolled telemetry collector." : "Application heartbeat not observed. Container usage may still be available; application metrics require instrumentation.");
    const grid = node("div", undefined, "metric-grid");
    data.series.forEach(series => grid.append(metricChart(series))); $("monitoring-content").append(grid);
  } else if (signal === "logs") {
    signalState(data.logs.length ? `Showing ${data.logs.length} recent log records.` : "No log records observed in this window.");
    for (const log of data.logs) {
      const row = node("article", undefined, "card log-row");
      row.append(node("small", log.timestamp_ns ? new Date(Number(log.timestamp_ns) / 1000000).toLocaleString() : "Timestamp unavailable", "muted"), node("pre", log.line + (log.truncated ? " … [truncated]" : ""), "log-line"));
      if (log.trace_id) {
        const trace = node("button", "View trace →", "text-button"); trace.addEventListener("click", () => action(() => openTrace(log.trace_id))); row.append(trace);
      }
      $("monitoring-content").append(row);
    }
  } else if (signal === "alerts") {
    signalState(data.alerts.length ? `${data.alerts.length} pending or firing alerts.` : "No active alerts reported by the rules engine.");
    for (const alert of data.alerts) {
      const row = node("article", undefined, "card registration-row"); const text = node("div");
      text.append(node("h3", alert.name), node("p", alert.summary), node("small", alert.namespace || "Platform", "muted"));
      row.append(text, node("span", `${alert.state} · ${alert.severity}`, "pill owner-warning")); $("monitoring-content").append(row);
    }
  } else {
    signalState(data.traces.length ? `Showing ${data.traces.length} authorized traces.` : "No traces observed. Tracing requires application instrumentation and recent requests.");
    for (const trace of data.traces) {
      const row = node("article", undefined, "card registration-row"); const text = node("div");
      text.append(node("h3", trace.name), node("p", `${trace.service} · ${(trace.duration_ns / 1000000).toFixed(1)} ms · ${trace.span_count} spans`), node("small", trace.trace_id, "mono"));
      const view = node("button", "View trace →", "secondary"); view.addEventListener("click", () => action(() => openTrace(trace.trace_id)));
      row.append(text, view); $("monitoring-content").append(row);
    }
  }
}
async function openTrace(identity) {
  const generation = monitoringGeneration;
  const data = await api(monitoringPath(identity));
  if (generation !== monitoringGeneration || !state.session) return;
  $("trace-detail").hidden = false; $("trace-identity").textContent = data.trace_id;
  $("trace-spans").replaceChildren();
  const start = Math.min(...data.spans.map(span => span.start_ns));
  const duration = Math.max(1, ...data.spans.map(span => span.start_ns + span.duration_ns - start));
  for (const span of data.spans) {
    const row = node("div", undefined, "trace-row"); row.append(node("strong", span.name), node("small", `${span.service} · ${(span.duration_ns / 1000000).toFixed(2)} ms${span.error ? " · Error" : ""}`, "muted"));
    const svg = svgElement("svg", { viewBox: "0 0 600 20", role: "img", "aria-label": `${span.name} duration` });
    svg.append(svgElement("rect", { x: (span.start_ns - start) / duration * 590, y: 2, width: Math.max(2, span.duration_ns / duration * 590), height: 14, rx: 3, fill: span.error ? "#a64526" : "#26795b" }));
    row.append(svg); $("trace-spans").append(row);
  }
  $("trace-detail").scrollIntoView({ behavior: "smooth", block: "start" });
}
$("nav-monitoring").addEventListener("click", () => action(() => monitoringView()));
$("refresh-monitoring").addEventListener("click", () => action(() => loadSignal(monitoringState.signal)));
$("monitoring-target").addEventListener("change", () => loadSignal("metrics").catch(problem => error(problem.message)));
$("monitoring-window").addEventListener("change", () => loadSignal(monitoringState.signal).catch(problem => error(problem.message)));
for (const button of document.querySelectorAll("[data-signal]")) button.addEventListener("click", () => action(() => loadSignal(button.dataset.signal)));
$("close-trace").addEventListener("click", () => { $("trace-detail").hidden = true; $("trace-spans").replaceChildren(); });
