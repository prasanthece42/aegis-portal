"use strict";
let activeSetup = null, setupPreview = null, setupTimer = null, setupGeneration = 0;
function clearSetup() {
  setupGeneration++;
  clearTimeout(setupTimer); setupTimer = null;
  activeSetup = null; setupPreview = null;
  $("setup-files").replaceChildren(); $("setup-proposals").replaceChildren();
  $("setup-confirm").hidden = true; $("setup-approve").hidden = true; $("setup-deploy").hidden = true;
}
function setupKey(appId) { return `aegis.dev-setup.${state.session.user_id}.${appId}`; }
function storedSetup(appId) { try { return JSON.parse(sessionStorage.getItem(setupKey(appId))); } catch { return null; } }
function setupFiles(groups) {
  $("setup-files").replaceChildren();
  for (const [label, files] of groups) {
    $("setup-files").append(node("h3", label));
    for (const file of files || []) {
      const details = node("details");
      details.append(node("summary", `${file.path} · ${file.status}`), node("pre", file.content));
      $("setup-files").append(details);
    }
  }
}
function renderSetup(data) {
  const labels = { not_started: "Ready to review your DEV setup.", queued: "Setup is safely queued. The preparation service will resume it when available.", preparing: "The platform is preparing your setup proposals.", awaiting_review: "Review the proposed files, then approve the setup changes below.", building: "Pipeline and DEV target are prepared. CI is building and validating a release.", needs_attention: "Setup needs attention. Review the latest files and CI results below.", ready: "DEV preparation is complete. Select a validated release when you are ready to deploy." };
  $("setup-state").textContent = labels[data.state] || data.state;
  $("setup-stages").replaceChildren(...[["Pipeline installed", data.pipeline_ready], ["DEV target prepared", data.target_ready], ["Validated release and image cache", data.release_ready]].map(([label, done]) => node("li", `${done ? "✓" : "○"} ${label}`)));
  $("setup-proposals").replaceChildren();
  for (const [kind, pr] of Object.entries(data.pull_requests || {})) {
    const row = node("p", `${kind === "pipeline" ? "Pipeline" : "DEV target"}: ${pr.merged ? "Approved and merged" : pr.state === "open" ? pr.approved ? "Approved · Waiting for checks and installation" : "Review requested" : "Closed"} · `);
    const url = new URL(pr.url);
    if (url.origin === "https://github.com") { const link = node("a", `View proposal #${pr.number} ↗`); link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer"; row.append(link); }
    $("setup-proposals").append(row);
  }
  if (data.ci) {
    const row = node("p", `${data.ci.label}: ${data.ci.status === "completed" ? data.ci.conclusion : "Running"} · `);
    const url = new URL(data.ci.url);
    if (url.origin === "https://github.com") { const link = node("a", "View CI results ↗"); link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer"; row.append(link); }
    $("setup-proposals").append(row);
  }
  $("setup-approve").hidden = !Object.entries(data.pull_requests || {}).some(([kind, pr]) => pr.state === "open" && !pr.merged && !pr.approved && data[`can_approve_${kind}`]);
  $("setup-approve").textContent = data.can_approve_target ? "Approve setup changes" : "Approve pipeline changes";
  if (data.state === "awaiting_review" && !data.can_approve_target && data.pull_requests?.pipeline?.approved) $("setup-state").textContent = "Your pipeline is approved. The DEV target is waiting for platform owner approval.";
  $("setup-deploy").hidden = data.state !== "ready";
  $("setup-plan").hidden = data.state !== "not_started" && !data.can_replan;
  if (data.workflow_files) setupFiles([["Pipeline", data.workflow_files], ["DEV target", data.target_files]]);
}
async function setupView(appId) {
  clearSetup();
  const generation = setupGeneration;
  activeSetup = { appId, result: null };
  $("setup-title").textContent = `${appId} · Prepare for DEV`;
  $("setup-state").textContent = "Loading your preparation progress…";
  $("setup-blockers").replaceChildren(); $("setup-stages").replaceChildren(); $("setup-plan").hidden = false;
  show("dev-setup");
  const pending = storedSetup(appId);
  const result = await api(`/api/v1/applications/${encodeURIComponent(appId)}/dev-setup`);
  if (generation !== setupGeneration) return;
  activeSetup.result = result;
  if (pending && !result.setup_id) $("setup-state").textContent = "A confirmation was interrupted. Review again to recover the same setup request.";
  renderSetup(result);
  scheduleSetupRefresh();
}
function scheduleSetupRefresh() {
  clearTimeout(setupTimer);
  if (state.onboarding) return;
  if (activeSetup?.result?.setup_id && activeSetup.result.state !== "ready") setupTimer = setTimeout(async () => {
    if (!activeSetup || $("dev-setup").hidden || !state.session) return;
    if (state.busy) { scheduleSetupRefresh(); return; }
    try { await refreshSetup(); } catch (e) { if (activeSetup) $("setup-state").textContent = `${e.message} Use Refresh progress to retry.`; }
  }, 60000);
}
async function refreshSetup() {
  if (!activeSetup) return;
  const current = activeSetup, generation = setupGeneration;
  const result = await api(`/api/v1/applications/${encodeURIComponent(current.appId)}/dev-setup`);
  if (generation !== setupGeneration || activeSetup !== current) return;
  current.result = result; renderSetup(result); scheduleSetupRefresh();
}
$("setup-plan").addEventListener("click", () => action(async () => {
  const current = activeSetup, generation = setupGeneration;
  const preview = await api(`/api/v1/applications/${encodeURIComponent(current.appId)}/dev-setup-validations`, { method: "POST" });
  if (generation !== setupGeneration) return;
  setupPreview = preview;
  if (current.result?.state === "needs_attention") sessionStorage.removeItem(setupKey(current.appId));
  setupFiles([["Pipeline", preview.workflow_files], ["DEV target", preview.target_files]]);
  $("setup-blockers").replaceChildren(...preview.blockers.map((b) => node("p", b, "notice")));
  $("setup-confirm").hidden = preview.blockers.length > 0;
  $("setup-state").textContent = preview.worker_online ? "Review these files. Confirming authorizes the platform to propose this setup for approval." : "Review these files. Your request will be queued until the preparation service is available.";
}));
$("setup-confirm").addEventListener("click", () => action(async () => {
  if (!activeSetup || !setupPreview) throw new Error("Review the proposed setup first.");
  const current = activeSetup;
  let pending = storedSetup(current.appId);
  if (!pending) { pending = { key: crypto.randomUUID() }; sessionStorage.setItem(setupKey(current.appId), JSON.stringify(pending)); }
  const result = await api(`/api/v1/applications/${encodeURIComponent(current.appId)}/dev-setups`, { method: "POST", headers: { "Idempotency-Key": pending.key }, body: JSON.stringify({ review_token: setupPreview.review_token }) });
  if (activeSetup !== current) return;
  pending.setup_id = result.setup_id; sessionStorage.setItem(setupKey(current.appId), JSON.stringify(pending));
  current.result = result; setupPreview = null; $("setup-confirm").hidden = true; renderSetup(result); scheduleSetupRefresh();
}));
$("setup-approve").addEventListener("click", () => action(async () => {
  const current = activeSetup, result = current.result;
  const next = await api(`/api/v1/applications/${encodeURIComponent(current.appId)}/dev-setups/${encodeURIComponent(result.setup_id)}/approvals`, { method: "POST", body: JSON.stringify({ review_token: result.approval_token }) });
  if (activeSetup !== current) return;
  current.result = next; renderSetup(next); scheduleSetupRefresh();
}));
async function setupDeploy(appId) {
  const result = await api("/api/v1/applications"); state.applications = result.items;
  await deployment(appId);
}
$("setup-refresh").addEventListener("click", () => action(refreshSetup));
$("setup-back").addEventListener("click", () => action(applications));
$("setup-deploy").addEventListener("click", () => action(() => setupDeploy(activeSetup.appId)));
