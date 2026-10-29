"use strict";
let onboardingGeneration = 0, onboardingTimer = null;
const guidedPanes = ["progress", "dev-setup", "deployment", "delivery-progress", "pipeline", "platform", "workflow-review"];
const paneHomes = new Map();
for (const id of guidedPanes) {
  const marker = document.createComment(`home:${id}`);
  $(id).before(marker); paneHomes.set(id, marker);
}
function clearOnboarding() {
  if (state.onboarding && location.hash.startsWith("#onboard-")) history.replaceState(null, "", location.pathname);
  onboardingGeneration++; clearTimeout(onboardingTimer); onboardingTimer = null;
  state.onboarding = null; $("onboarding").hidden = true;
  if (typeof clearSetup === "function") clearSetup();
  document.title = "Aegis · Application platform";
}
function presentGuidedPane(name) {
  const guided = Boolean(state.onboarding && guidedPanes.includes(name));
  if (!guided && state.onboarding) clearOnboarding();
  $("onboarding").hidden = !guided;
  if (guided) { $("onboarding-content").append($(name)); state.onboarding.pane = name; if (state.onboarding.data) renderOnboarding(state.onboarding.data); }
  else if (guidedPanes.includes(name)) paneHomes.get(name).after($(name));
}
function scheduleOnboarding() {
  clearTimeout(onboardingTimer);
  if (!state.onboarding || state.onboarding.data?.phase === "healthy") return;
  onboardingTimer = setTimeout(async () => {
    if (!state.onboarding || !state.session) return;
    if (state.busy || state.onboarding.loading || document.hidden) { scheduleOnboarding(); return; }
    try { await refreshOnboarding(); }
    catch (e) { if (state.onboarding) $("onboarding-message").textContent = `${e.message} Your confirmed requests are preserved. Use Refresh progress to retry.`; scheduleOnboarding(); }
  }, 30000);
}
function renderOnboarding(data) {
  $("onboarding-title").textContent = `${data.app_id} · DEV`;
  $("onboarding-message").textContent = data.message;
  $("onboarding-actor").textContent = `Next action: ${data.actor}`;
  $("onboarding-observed").textContent = `Updated ${new Date().toLocaleTimeString()}. Progress refreshes automatically while you wait.`;
  const labels = ["Review & ownership", "Prepare", "Build", "Review release", "Deploy & health"];
  const index = (!data.setup && data.registration) ? 0 : { owner_review: 0, setup_review: 1, preparing: 1, setup_approval: 1, building: 2, release_review: 3, deploying: 4, healthy: 5 }[data.phase] ?? 1;
  $("onboarding-stages").replaceChildren(...labels.map((label, i) => {
    const item = node("li", `${i < index ? "✓ " : `${i + 1}. `}${label}`, i < index ? "done" : i === index ? "current" : "");
    if (i === index) item.setAttribute("aria-current", "step"); return item;
  }));
  $("onboarding-next").hidden = true;
  if (data.phase === "owner_review" && state.session.allowed_actions.includes("platform:view") && !["platform", "workflow-review"].includes(state.onboarding.pane)) {
    $("onboarding-next").hidden = false; $("onboarding-next").textContent = "Review owner requests";
  } else if (["pipeline", "platform", "workflow-review"].includes(state.onboarding.pane)) {
    $("onboarding-next").hidden = false; $("onboarding-next").textContent = "Return to progress";
  }
  document.title = `${["owner_review", "setup_review", "setup_approval", "release_review", "needs_attention"].includes(data.phase) ? "Action needed · " : ""}${data.app_id} · Aegis`;
}
async function onboardingView(appId, registrationId = null) {
  clearOnboarding();
  state.onboarding = { appId, registrationId, pane: null, data: null, loading: false };
  sessionStorage.setItem("aegis.active-onboarding", JSON.stringify({ user_id: state.session.user_id, appId, registrationId }));
  history.replaceState(null, "", `#onboard-${encodeURIComponent(appId)}`);
  await refreshOnboarding(true);
}
async function resumeOnboarding() {
  if (!location.hash.startsWith("#onboard-")) return;
  let saved; try { saved = JSON.parse(sessionStorage.getItem("aegis.active-onboarding")); } catch { return; }
  if (saved?.user_id === state.session.user_id && location.hash === `#onboard-${encodeURIComponent(saved.appId)}`) await onboardingView(saved.appId, saved.registrationId);
}
async function refreshOnboarding(force = false) {
  const current = state.onboarding, generation = onboardingGeneration;
  if (!current || current.loading) return;
  current.loading = true;
  try {
    const query = current.registrationId ? `?registration_id=${encodeURIComponent(current.registrationId)}` : "";
    const data = await api(`/api/v1/applications/${encodeURIComponent(current.appId)}/onboarding${query}`);
    if (generation !== onboardingGeneration || state.onboarding !== current) return;
    current.data = data;
    renderOnboarding(data);
    if (!force && ["pipeline", "platform", "workflow-review"].includes(current.pane)) return;
    if (data.phase === "owner_review" || (!data.setup && data.registration)) {
      if (current.pane !== "progress" || force) await progress(current.registrationId);
    } else if (["deploying", "healthy"].includes(data.phase) || (data.deployment && data.phase === "needs_attention")) {
      await deliveryProgress(data.deployment.request_id);
    } else if (data.phase === "release_review") {
      if (current.pane !== "deployment" || force) {
        state.applications = (await api("/api/v1/applications")).items;
        if (generation !== onboardingGeneration) return;
        await deployment(current.appId);
      }
    } else if (current.pane !== "dev-setup" || force) {
      await setupView(current.appId);
    } else if (activeSetup && !setupPreview) {
      activeSetup.result = data.setup; renderSetup(data.setup);
    }
  } finally {
    current.loading = false;
    if (generation === onboardingGeneration) scheduleOnboarding();
  }
}
$("onboarding-next").addEventListener("click", () => action(async () => {
  if (state.onboarding?.data?.phase === "owner_review" && state.onboarding.pane !== "platform" && state.onboarding.pane !== "workflow-review") { const pr = state.onboarding.data.registration?.pull_request; if (pr?.number) await workflowReview("platform", pr.number); else { await platformOverview(); ownerTab("reviews"); } }
  else await refreshOnboarding(true);
}));
$("onboarding-refresh").addEventListener("click", () => action(() => refreshOnboarding()));
$("onboarding-back").addEventListener("click", () => action(async () => { history.replaceState(null, "", location.pathname); await applications(); }));
document.addEventListener("visibilitychange", () => { if (!document.hidden && state.onboarding) scheduleOnboarding(); });
