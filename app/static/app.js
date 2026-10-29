"use strict";
const $ = (id) => document.getElementById(id);
const state = { status: null, session: null, repositories: [], preview: null, activeId: null, busy: false };
let pipelineSelection = null;
let pipelineGeneration = 0;
const sections = ["sign-in", "applications", "registration", "progress", "deployment", "delivery-progress", "platform", "workflow-review", "monitoring", "pipeline", "upload", "dev-setup"];

function node(tag, text, cls) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
}
function show(name) {
  if (typeof presentGuidedPane === "function") presentGuidedPane(name);
  for (const id of sections) $(id).hidden = id !== name;
  $("error").hidden = true;
  $("nav-apps").classList.toggle("active", name === "applications" || name === "progress" || name === "dev-setup");
  $("nav-register").classList.toggle("active", name === "registration");
  $("nav-monitoring").classList.toggle("active", name === "monitoring");
  $("nav-platform").classList.toggle("active", name === "platform" || name === "workflow-review");
  if (name !== "platform" && window.location.hash === "#platform") history.replaceState(null, "", window.location.pathname);
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function error(message) {
  $("error").textContent = message;
  $("error").hidden = false;
  $("error").focus();
}
async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (state.session) headers["X-CSRF-Token"] = state.session.csrf_token;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  let data;
  try {
    data = await response.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Invalid response");
  } catch {
    if (response.status === 401 && state.session) {
      state.session = null; show("sign-in"); renderIdentity();
    }
    throw new Error(`The portal could not complete the request (HTTP ${response.status}). Refresh and retry. If an operation was already confirmed, use its recovery action.`);
  }
  if (!response.ok) {
    if (response.status === 401 && state.session) {
      state.session = null;
      show("sign-in");
      renderIdentity();
    }
    const fields = data.error?.field_errors?.map((e) => `${e.field}: ${e.message}`).join("; ");
    throw new Error(fields || data.error?.message || "The request could not be completed.");
  }
  return data;
}
async function action(callback) {
  if (state.busy) return;
  state.busy = true;
  $("error").hidden = true;
  const buttons = [...document.querySelectorAll("button:not(:disabled)")];
  buttons.forEach((b) => { b.disabled = true; });
  try { await callback(); }
  catch (e) { error(e.message || "Connection interrupted. Retry the same confirmed submission."); }
  finally {
    state.busy = false;
    buttons.forEach((b) => { b.disabled = false; });
    if (state.status?.mode === "unconfigured") $("sign-in-button").disabled = true;
  }
}
function renderIdentity() {
  $("nav-monitoring").hidden = !state.session;
  if (!state.session) {
    if (typeof clearUpload === "function") clearUpload();
    if (typeof clearSetup === "function") clearSetup();
    if (typeof clearOnboarding === "function") clearOnboarding();
    pipelineGeneration++;
    pipelineSelection = null;
    $("pipeline-stages").replaceChildren();
    $("pipeline-summary").textContent = "";
  }
  if (!state.session && typeof clearMonitoring === "function") clearMonitoring();
  $("nav-platform").hidden = !state.session?.allowed_actions?.includes("platform:view");
  $("identity").replaceChildren();
  if (!state.session) { $("identity").textContent = "Not signed in"; return; }
  $("identity").append(node("span", state.session.login));
  const logout = node("button", "Sign out", "text-button");
  logout.addEventListener("click", () => action(async () => {
    await api("/auth/logout", { method: "POST" });
    state.session = null; renderIdentity(); show("sign-in");
  }));
  $("identity").append(logout);
}
async function loadSession() {
  state.session = await api("/api/v1/session");
  renderIdentity();
}
async function applications() {
  if (typeof clearOnboarding === "function") clearOnboarding();
  if (!state.session) { show("sign-in"); return; }
  const data = await api("/api/v1/registrations");
  const managed = await api("/api/v1/applications");
  show("applications");
  $("registration-count").textContent = data.items.length;
  let pending = null;
  try { pending = JSON.parse(sessionStorage.getItem("aegis.pending-registration")); } catch { /* corrupt state */ }
  $("pending-recovery").hidden = !pending || pending.user_id !== state.session.user_id;
  $("empty-state").hidden = data.items.length > 0;
  $("registration-list").replaceChildren();
  $("managed-applications").replaceChildren();
  state.applications = managed.items;
  let interrupted = null, lastDelivery = null;
  try { interrupted = JSON.parse(sessionStorage.getItem("aegis.pending-delivery")); lastDelivery = JSON.parse(sessionStorage.getItem("aegis.last-delivery")); } catch { /* discard corrupt browser metadata */ }
  $("pending-delivery-recovery").hidden = !interrupted || interrupted.user_id !== state.session.user_id;
  $("last-delivery").hidden = !lastDelivery || lastDelivery.user_id !== state.session.user_id;
  for (const app of managed.items) {
    const row = node("article", undefined, "card registration-row");
    const content = node("div");
    content.append(node("h3", app.display_name), node("p", `${app.source.owner}/${app.source.name} · ${Object.keys(app.environments).join(" / ").toUpperCase()}`));
    const request = node("button", "Request deployment →", "secondary");
    request.disabled = !state.status.deployment_enabled;
    request.addEventListener("click", () => action(() => deployment(app.app_id)));
    const monitor = node("button", "Monitor →", "secondary");
    monitor.addEventListener("click", () => action(() => monitoringView(`app:${app.app_id}:${Object.keys(app.environments)[0]}`)));
    const controls = node("div", undefined, "row-action"); controls.append(monitor, request);
    if (app.access.deployer_user_ids_by_environment.dev?.includes(state.session.user_id)) {
      const pipeline = node("button", "DEV pipeline →", "secondary");
      pipeline.addEventListener("click", () => action(() => pipelineView(app.app_id)));
      const prepare = node("button", "Open app journey →", "secondary");
      prepare.addEventListener("click", () => action(() => onboardingView(app.app_id)));
      controls.append(prepare, pipeline);
    }
    row.append(content, controls); $("managed-applications").append(row);
  }
  if (!managed.items.length) $("managed-applications").append(node("p", "No approved applications are available to your identity.", "muted"));
  for (const item of data.items) {
    const row = node("article", undefined, "card registration-row");
    const content = node("div");
    content.append(node("h3", item.display_name), node("p", `${item.app_id} · DEV onboarding`));
    const actions = node("div", undefined, "row-action");
    const catalogState = item.requirements[0].status;
    const label = catalogState === "closed_unmerged" ? "Registration closed" : catalogState === "approved" ? "Catalog approved" : "Onboarding pending";
    actions.append(node("span", label, "pill neutral"));
    const view = node("button", "View setup →", "text-button");
    view.addEventListener("click", () => action(() => onboardingView(item.app_id, item.registration_id)));
    actions.append(view); row.append(content, actions); $("registration-list").append(row);
  }
}
function profileDescription() {
  const profile = state.session.resource_profiles[$("resource-profile").value];
  $("resource-description").textContent = profile ? `Requests: ${profile.cpu_request} CPU / ${profile.memory_request} memory. Limits: ${profile.cpu_limit} CPU / ${profile.memory_limit} memory.` : "";
}
async function deployment(appId) {
  state.deliveryApp = state.applications.find((app) => app.app_id === appId);
  if (!state.deliveryApp) throw new Error("Application is unavailable.");
  state.deliveryPreview = null; state.releasePage = 1;
  $("deployment-title").textContent = `Deploy ${state.deliveryApp.display_name}`;
  $("deployment-environment").replaceChildren(...Object.keys(state.deliveryApp.environments)
    .filter((env) => state.deliveryApp.access.deployer_user_ids_by_environment[env]?.includes(state.session.user_id))
    .map((env) => new Option(env.toUpperCase(), env)));
  $("deployment-form").hidden = false; $("deployment-review").hidden = true;
  show("deployment"); await loadReleases();
}
function renderReleaseSelection() {
  const release = state.releases?.find((r) => r.release_id === $("deployment-release").value);
  $("deployment-release-identifiers").hidden = !release;
  $("deployment-release-summary").textContent = release
    ? `${release.build_label || "Validated build"} · Commit ${release.source_commit?.slice(0, 7) || "unavailable"}${release.published_at ? " · Built " + new Date(release.published_at).toLocaleString() : ""}`
    : "Choose a validated build to review its source and DEV destination.";
  $("deployment-release-raw").textContent = release ? `GitHub release: ${release.tag} · Release ID: ${release.release_id}${release.workflow_run_id ? " · Run: " + release.workflow_run_id : ""}` : "";
}
async function loadReleases() {
  const env = $("deployment-environment").value;
  if (!env) throw new Error("Your identity has no deployment grant for this application.");
  const data = await api(`/api/v1/applications/${encodeURIComponent(state.deliveryApp.app_id)}/releases?environment=${env}&page=${state.releasePage}`);
  state.releases = data.items;
  $("deployment-release").replaceChildren(new Option("Select a validated build", ""));
  for (const release of data.items) {
    const option = new Option(`${release.build_label || "Build"} · ${release.eligible ? "Ready for review · " + release.source_commit.slice(0, 7) : "Not eligible"}${release.run_attempt > 1 ? " · Attempt " + release.run_attempt : ""}`, release.release_id);
    option.disabled = !release.eligible;
    $("deployment-release").append(option);
  }
  renderReleaseSelection();
  state.nextReleasePage = data.next_page; $("more-releases").hidden = !data.next_page;
  $("deployment-release-note").textContent = "Only validated builds can be selected. The platform checks the release and destination readiness when you review it.";
}
async function previewDeployment() {
  const fields = { app_id: state.deliveryApp.app_id, environment: $("deployment-environment").value, release_id: $("deployment-release").value };
  state.deliveryPreview = await api("/api/v1/deployment-validations", { method: "POST", body: JSON.stringify(fields) });
  const preview = state.deliveryPreview, context = preview.context;
  const selected = state.releases?.find((r) => r.release_id === preview.fields.release_id);
  $("deployment-review-details").replaceChildren();
  for (const [label, value] of [["Build", selected?.build_label || "Validated build"], ["Application", fields.app_id], ["Environment", fields.environment.toUpperCase()],
    ["Source commit", context.source_commit], ["Immutable image", context.image_root_digest],
    ["Cluster", context.target.cluster_id], ["Namespace", context.target.namespace],
    ["Current desired state", context.expected_desired_fingerprint || "Initial deployment"]]) {
    $("deployment-review-details").append(node("dt", label), node("dd", value));
  }
  $("deployment-confirm-note").textContent = preview.requires_human_approval
    ? "PROD requires independent human approval of the current PR head, then authorized operator sync."
    : preview.requires_operator_sync ? "The approved GitOps change requires authorized operator sync."
    : "DEV deploys after GitOps admission and required checks pass. This review expires in five minutes.";
  $("deployment-form").hidden = true; $("deployment-review").hidden = false;
}
async function confirmDeployment() {
  const preview = state.deliveryPreview;
  if (!preview) throw new Error("Review the release and target first.");
  let pending;
  try { pending = JSON.parse(sessionStorage.getItem("aegis.pending-delivery")); } catch { pending = null; }
  if (!pending || pending.user_id !== state.session.user_id || JSON.stringify(pending.fields) !== JSON.stringify(preview.fields)) {
    pending = { user_id: state.session.user_id, fields: preview.fields, key: crypto.randomUUID() };
    sessionStorage.setItem("aegis.pending-delivery", JSON.stringify(pending));
  }
  const result = await api("/api/v1/deployment-requests", { method: "POST", headers: { "Idempotency-Key": pending.key }, body: JSON.stringify({ ...pending.fields, review_token: preview.review_token }) });
  sessionStorage.removeItem("aegis.pending-delivery");
  sessionStorage.setItem("aegis.last-delivery", JSON.stringify({ user_id: state.session.user_id, request_id: result.request_id }));
  await deliveryProgress(result.request_id);
}
async function deliveryProgress(id) {
  const result = await api(`/api/v1/deployment-requests/${encodeURIComponent(id)}`);
  state.activeDeliveryId = id; show("delivery-progress");
  $("delivery-pipeline").hidden = result.environment !== "dev";
  $("delivery-progress-title").textContent = `${result.app_id} · ${result.environment.toUpperCase()}`;
  $("delivery-request-id").textContent = result.request_id;
  const labels = { accepted: "Request accepted; GitOps processing is pending.", checking: "GitOps proposal created; required checks are running.", awaiting_review: "Waiting for current-head human PROD review.", closed_unmerged: "The GitOps proposal closed without merging.", reconciling: "GitOps change merged; waiting for measured rollout health.", healthy: "The observer verified Argo sync, rollout convergence and HTTP health.", superseded: "A newer request now owns this environment." };
  $("delivery-progress-state").textContent = labels[result.status] || `Request ${result.status}.`;
  $("delivery-progress-observed").textContent = `Status observed ${new Date(result.status_observed_at).toLocaleString()}${result.health_observed_at ? ` · Health measured ${new Date(result.health_observed_at).toLocaleString()}` : " · Health has not been verified"}`;
  $("delivery-issue-link").replaceChildren();
  if (result.issue?.url) {
    const url = new URL(result.issue.url);
    if (url.origin === "https://github.com") {
      const link = node("a", "View delivery request on GitHub ↗");
      link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
      $("delivery-issue-link").append(link);
    }
  }
  if (result.pull_request?.url) {
    const url = new URL(result.pull_request.url);
    if (url.origin === "https://github.com") {
      const link = node("a", "Open GitOps deployment PR ↗");
      link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
      const paragraph = node("p"); paragraph.append(link); $("delivery-issue-link").append(paragraph);
    }
  }
}
$("deployment-form").addEventListener("submit", (event) => { event.preventDefault(); action(previewDeployment); });
$("confirm-deployment").addEventListener("click", () => action(confirmDeployment));
$("edit-deployment").addEventListener("click", () => { state.deliveryPreview = null; $("deployment-review").hidden = true; $("deployment-form").hidden = false; });
$("deployment-release").addEventListener("change", renderReleaseSelection);
$("deployment-environment").addEventListener("change", () => action(async () => { state.releasePage = 1; await loadReleases(); }));
$("more-releases").addEventListener("click", () => action(async () => { state.releasePage = state.nextReleasePage; await loadReleases(); }));
for (const id of ["cancel-deployment", "delivery-back"]) $(id).addEventListener("click", () => action(applications));
$("refresh-delivery").addEventListener("click", () => action(() => deliveryProgress(state.activeDeliveryId)));
$("last-delivery").addEventListener("click", () => action(async () => {
  const saved = JSON.parse(sessionStorage.getItem("aegis.last-delivery") || "null");
  if (!saved || saved.user_id !== state.session.user_id) throw new Error("No saved request belongs to this identity.");
  await deliveryProgress(saved.request_id);
}));
$("recover-delivery").addEventListener("click", () => action(async () => {
  const pending = JSON.parse(sessionStorage.getItem("aegis.pending-delivery") || "null");
  if (!pending || pending.user_id !== state.session.user_id) throw new Error("No interrupted request belongs to this identity.");
  const result = await api("/api/v1/deployment-requests", { method: "POST", headers: { "Idempotency-Key": pending.key }, body: JSON.stringify({ ...pending.fields, prepare_dev: Boolean(pending.prepare_dev), review_token: "recover-existing-reservation-only" }) });
  sessionStorage.removeItem("aegis.pending-delivery");
  sessionStorage.setItem("aegis.last-delivery", JSON.stringify({ user_id: state.session.user_id, request_id: result.request_id }));
  await deliveryProgress(result.request_id);
}));
async function registration() {
  if (typeof clearOnboarding === "function") clearOnboarding();
  if (!state.session) { show("sign-in"); return; }
  if (!state.session.allowed_actions.includes("register")) throw new Error("Your identity is not enabled for onboarding.");
  const repos = await api("/api/v1/repositories");
  state.repositories = repos.items;
  $("repository").replaceChildren(new Option("Select a repository", ""));
  for (const repo of repos.items) $("repository").append(new Option(repo.full_name, repo.repository_id));
  $("owner").replaceChildren(...state.session.owner_choices.map((o) => new Option(o.label, o.user_id)));
  $("resource-profile").replaceChildren(...Object.keys(state.session.resource_profiles).map((id) => new Option(id, id)));
  profileDescription();
  state.preview = null;
  $("registration-form").hidden = false; $("review").hidden = true;
  $("step-config").classList.add("current"); $("step-review").classList.remove("current");
  show("registration");
  if (!repos.items.length) error("No eligible repositories. Check your GitHub App installation, source access and platform policy.");
}
function fields() {
  return {
    repository_id: $("repository").value, app_id: $("app-id").value,
    display_name: $("display-name").value, owner_user_ids: [$("owner").value],
    runtime: { profile_id: "python312-web", container_port: Number($("port").value),
      health_path: $("health-path").value, resource_profile_id: $("resource-profile").value }
  };
}
function detail(label, value) {
  $("review-details").append(node("dt", label), node("dd", value));
}
async function validate() {
  state.preview = await api("/api/v1/registration-validations?guided_setup=true", { method: "POST", body: JSON.stringify(fields()) });
  const preview = state.preview;
  $("review-details").replaceChildren();
  $("review-title").textContent = `Review ${preview.fields.display_name}`;
  detail("Repository", preview.source.full_name);
  detail("Application ID", preview.fields.app_id);
  detail("Owner", state.session.login);
  detail("Runtime", "Python 3.12 web app");
  detail("Port / health", `${preview.fields.runtime.container_port} · ${preview.fields.runtime.health_path}`);
  detail("Resource profile", preview.fields.runtime.resource_profile_id);
  detail("Source revision", preview.source.source_commit);
  detail("Initial delivery", "DEV · Explicit deployment confirmation");
  const automatic = preview.automatic_setup;
  $("registration-submit-notice").textContent = automatic ? "Submit once to request catalog approval and authorize the exact setup proposals shown above. Required owner reviews remain in place. Deployment requires a separate release review and confirmation." : "Submission creates a catalog proposal. Setup and deployment remain separate requirements.";
  $("registration-setup-review").hidden = !automatic;
  $("registration-setup-files").replaceChildren();
  $("registration-setup-blockers").replaceChildren();
  $("submit-registration").disabled = Boolean(automatic?.blockers?.length);
  if (automatic) {
    $("registration-setup-notice").textContent = automatic.notice;
    for (const f of [...automatic.workflow_files, ...automatic.target_files]) {
      const row = node("details"); row.append(node("summary", `${f.path} · ${f.status}`), node("pre", f.content));
      $("registration-setup-files").append(row);
    }
    $("registration-setup-blockers").append(...automatic.blockers.map((b) => node("p", b, "notice")));
  }
  $("detection-results").replaceChildren();
  for (const [label, key] of [["Dockerfile", "dockerfile_present"], ["Dependency lock candidate", "dependency_lock_present"], ["Pipeline file", "pipeline_file_present"]]) {
    const row = node("div", undefined, "check-row");
    row.append(node("strong", label), node("span", preview.detection[key] ? "Found · validation still required" : "Setup required"));
    $("detection-results").append(row);
  }
  $("registration-form").hidden = true; $("review").hidden = false;
  $("step-config").classList.remove("current"); $("step-review").classList.add("current");
  // Persist only confirmed intent and idempotency metadata. Never identity/access tokens.
  const previous = sessionStorage.getItem("aegis.pending-registration");
  let pending = null;
  try { pending = previous ? JSON.parse(previous) : null; } catch { /* discard corrupt local state */ }
  if (pending && (pending.user_id !== state.session.user_id || JSON.stringify(pending.fields) !== JSON.stringify(preview.fields))) sessionStorage.removeItem("aegis.pending-registration");
}
async function submit() {
  if (state.preview?.automatic_setup?.blockers?.length) throw new Error("Resolve the setup requirements before submitting.");
  if (!state.preview) throw new Error("Validate your configuration before submitting.");
  let pending;
  try { pending = JSON.parse(sessionStorage.getItem("aegis.pending-registration")); } catch { pending = null; }
  if (!pending || pending.user_id !== state.session.user_id || JSON.stringify(pending.fields) !== JSON.stringify(state.preview.fields)) {
    pending = { key: crypto.randomUUID(), fields: state.preview.fields, user_id: state.session.user_id, prepare_dev: Boolean(state.preview.automatic_setup) };
    sessionStorage.setItem("aegis.pending-registration", JSON.stringify(pending));
  }
  if (Boolean(pending.prepare_dev) !== Boolean(state.preview.automatic_setup)) throw new Error("Recover the earlier registration before changing its setup authorization.");
  const result = await api("/api/v1/registrations", { method: "POST", headers: { "Idempotency-Key": pending.key },
    body: JSON.stringify({ ...pending.fields, prepare_dev: Boolean(pending.prepare_dev), review_token: state.preview.review_token }) });
  sessionStorage.removeItem("aegis.pending-registration");
  sessionStorage.setItem("aegis.last-registration", result.registration_id);
  await onboardingView(result.app_id, result.registration_id);
}
async function recoverPending() {
  const pending = JSON.parse(sessionStorage.getItem("aegis.pending-registration") || "null");
  if (!pending || pending.user_id !== state.session.user_id) throw new Error("No interrupted submission belongs to this identity.");
  const result = await api("/api/v1/registrations", { method: "POST", headers: { "Idempotency-Key": pending.key },
    body: JSON.stringify({ ...pending.fields, prepare_dev: Boolean(pending.prepare_dev), review_token: "recover-existing-reservation-only" }) });
  sessionStorage.removeItem("aegis.pending-registration");
  await onboardingView(result.app_id, result.registration_id);
}
const statusLabels = {
  pending_review: "Awaiting review", approved: "Approved", closed_unmerged: "Closed without approval",
  pending_pr: "Recovering proposal", validation_required: "Validation required",
  operator_setup_required: "Preparation required", not_verified: "Not yet verified",
  verified: "Verified", pending_setup: "Preparation pending"
};
async function progress(id) {
  const result = await api(`/api/v1/registrations/${encodeURIComponent(id)}`);
  state.activeId = result.registration_id;
  state.progressApp = result.app_id;
  $("progress-prepare").hidden = !result.setup_available;
  $("progress-deploy").disabled = !result.deployment_available;
  show("progress");
  $("progress-title").textContent = result.display_name;
  $("registration-id").textContent = result.registration_id;
  $("status-observed").textContent = `Status observed: ${new Date(result.status_observed_at).toLocaleString()}. Refresh to check for changes.`;
  $("pr-link").replaceChildren();
  if (result.pull_request?.url) {
    const url = new URL(result.pull_request.url);
    if (url.origin === "https://github.com") {
      const link = node("a", "Open registration PR on GitHub ↗");
      link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
      $("pr-link").append(link);
    }
  } else $("pr-link").append(node("p", "Demo registration saved locally. No GitHub PR was created.", "muted"));
  $("requirements").replaceChildren();
  for (const requirement of result.requirements) {
    const row = node("div", undefined, "requirement");
    const title = node("div"); title.append(node("strong", requirement.name), node("small", requirement.actor));
    row.append(title, node("span", statusLabels[requirement.status] || requirement.status, "pill neutral"));
    $("requirements").append(row);
  }
}
$("repository").addEventListener("change", () => {
  const repo = state.repositories.find((r) => r.repository_id === $("repository").value);
  if (repo) {
    const name = repo.full_name.split("/")[1];
    $("app-id").value = name.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
    $("display-name").value = name.split("-").map((s) => s.charAt(0).toUpperCase() + s.slice(1)).join(" ");
  }
});
$("resource-profile").addEventListener("change", profileDescription);
for (const id of ["nav-register", "new-registration", "empty-register"]) $(id).addEventListener("click", () => action(registration));
for (const id of ["nav-apps", "refresh-apps", "cancel-registration", "back-applications"]) $(id).addEventListener("click", () => action(applications));
$("registration-form").addEventListener("submit", (event) => { event.preventDefault(); action(validate); });
$("edit-registration").addEventListener("click", () => {
  state.preview = null; $("review").hidden = true; $("registration-form").hidden = false;
  $("step-config").classList.add("current"); $("step-review").classList.remove("current");
});
$("submit-registration").addEventListener("click", () => action(submit));
$("recover-registration").addEventListener("click", () => action(recoverPending));
$("refresh-progress").addEventListener("click", () => action(() => progress(state.activeId)));
$("sign-in-button").addEventListener("click", () => action(async () => {
  if (state.status.mode === "demo") {
    await api("/auth/demo", { method: "POST" }); await loadSession(); await applications();
  } else if (state.status.mode === "live") window.location.assign("/auth/github/start");
}));
function ownerLink(label, address) {
  if (!address) return node("span", "Available with live integration", "muted");
  let url;
  try { url = new URL(address); } catch { return node("span", "Link unavailable", "muted"); }
  if (url.origin !== "https://github.com") return node("span", "Link unavailable", "muted");
  const link = node("a", label, "owner-link");
  link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
  return link;
}
function ownerTab(name) {
  for (const button of document.querySelectorAll("[data-owner-tab]")) {
    const selected = button.dataset.ownerTab === name;
    button.setAttribute("aria-selected", String(selected));
    $("owner-" + button.dataset.ownerTab).hidden = !selected;
  }
}
function ownerEmpty(target, text) { target.append(node("p", text, "notice")); }
function ownerCheck(target, label, value) {
  const row = node("div", undefined, "check-row");
  row.append(node("strong", label), node("span", value)); target.append(row);
}
async function platformOverview() {
  if (!state.session?.allowed_actions?.includes("platform:view")) throw new Error("Platform owner access is required.");
  show("platform"); ownerTab("overview"); if (!state.onboarding) window.location.hash = "platform";
  for (const id of ["owner-summary", "owner-safeguards", "owner-access", "owner-review-list", "owner-application-list", "owner-cluster-list", "owner-profile-list", "owner-policy-links", "owner-activity-list"]) $(id).replaceChildren();
  $("platform-observed").textContent = "Loading reviewed platform data…";
  const data = await api("/api/v1/platform/overview");
  $("platform-observed").textContent = `${data.mode === "demo" ? "DEMO · No live GitHub or cluster data. " : ""}Snapshot observed ${new Date(data.observed_at).toLocaleString()}`;
  const environments = data.applications.flatMap((app) => app.environments);
  for (const [label, value, note] of [["Managed applications", data.applications.length, "Approved catalog"], ["Healthy environments", environments.filter((env) => env.state === "healthy").length, "Fresh observer evidence"], ["Open reviews", data.review_total, "Platform + GitOps"], ["Cluster enrollments", data.clusters.length, "Configured targets"]]) {
    const card = node("div", undefined, "card owner-metric");
    card.append(node("span", label, "muted"), node("strong", String(value)), node("small", note)); $("owner-summary").append(card);
  }
  ownerCheck($("owner-safeguards"), "PROD human approval", data.policy.production_human_review_required ? "Required" : "Not configured");
  ownerCheck($("owner-safeguards"), "Protected sync", "Authorized " + data.policy.protected_sync_mode);
  ownerCheck($("owner-safeguards"), "Health freshness", "Healthy only with a matching observation within 5 minutes");
  ownerCheck($("owner-access"), "Signed-in owner", state.session.login);
  ownerCheck($("owner-access"), "Inventory access", "Read-only · Explicit platform grant");
  ownerCheck($("owner-access"), "Review actions", "Your current repository permissions and reviewer grants");
  ownerCheck($("owner-access"), "Configuration changes", "Reviewed GitHub pull requests");
  $("owner-access").append(ownerLink("Review owner policy ↗", data.policy.owner_policy_url));
  $("owner-review-count").textContent = `Showing ${data.reviews.length} of ${data.review_total}`;
  const checkLabels = { failing: "Checks failing", running: "Checks running", reported_passed: "Reported checks passed", unknown: "Checks not reported" };
  for (const review of data.reviews) {
    const row = node("article", undefined, "card registration-row"); const content = node("div");
    content.append(node("h3", review.title), node("p", `${review.repository} #${review.number} · ${review.branch} · ${review.draft ? "Draft" : "Open"}`));
    const actions = node("div", undefined, "row-action"); actions.append(node("span", checkLabels[review.ci_state] || "Unknown", "pill " + (review.ci_state === "failing" ? "owner-warning" : "neutral")));
    if (data.mode === "live") {
      const open = node("button", "Review changes", "secondary");
      open.addEventListener("click", () => action(() => workflowReview(review.repository_key || review.repository.toLowerCase(), review.number)));
      actions.append(open);
    } else actions.append(node("span", "Reviews available after live sign-in", "muted"));
    row.append(content, actions); $("owner-review-list").append(row);
  }
  if (!data.reviews.length) ownerEmpty($("owner-review-list"), "No open repository reviews.");
  const healthLabels = { healthy: "Observer verified", stale: "Stale observation", unverified: "Health not verified", not_deployed: "Not deployed" };
  for (const app of data.applications) {
    const card = node("article", undefined, "card form-card owner-app-card");
    const heading = node("div", undefined, "section-label"); heading.append(node("h2", app.display_name), ownerLink("Source ↗", app.source_url)); card.append(heading);
    card.append(node("p", `${app.source} · Owners: ${app.owner_user_ids.map((id) => id === state.session.user_id ? "You" : "GitHub user " + id).join(", ")}`, "muted"));
    for (const env of app.environments) {
      const row = node("div", undefined, "owner-env"); const content = node("div");
      content.append(node("strong", `${env.environment.toUpperCase()} · ${env.namespace}`), node("small", `${env.cluster_id} · Argo ${env.argo_application}`));
      if (env.image_digest) content.append(node("p", env.image_digest, "mono"));
      if (env.health_observed_at) content.append(node("small", "Health measured " + new Date(env.health_observed_at).toLocaleString()));
      const actions = node("div", undefined, "row-action");
      actions.append(node("span", healthLabels[env.state] || "Unavailable", "pill " + (env.state === "healthy" ? "" : "neutral")));
      if (env.values_url) actions.append(ownerLink("View desired state ↗", env.values_url));
      row.append(content, actions); card.append(row);
    }
    $("owner-application-list").append(card);
  }
  if (!data.applications.length) ownerEmpty($("owner-application-list"), "No approved applications are enrolled.");
  for (const cluster of data.clusters) {
    const card = node("article", undefined, "card form-card");
    card.append(node("h3", cluster.cluster_id), node("span", cluster.state === "enrolled" ? "Enrolled" : "Demo example", "pill neutral"), node("p", "Profile: " + cluster.profile_id), node("small", "Cluster UID"), node("p", cluster.cluster_uid, "mono")); $("owner-cluster-list").append(card);
  }
  for (const [name, profile] of Object.entries(data.policy.resource_profiles)) {
    const card = node("article", undefined, "card form-card"); card.append(node("h3", name));
    ownerCheck(card, "Requests", `${profile.requests.cpu} CPU · ${profile.requests.memory}`);
    ownerCheck(card, "Limits", `${profile.limits.cpu} CPU · ${profile.limits.memory}`); $("owner-profile-list").append(card);
  }
  $("owner-policy-links").append(ownerLink("Review delivery policy ↗", data.policy.delivery_policy_url), ownerLink("Review owner access ↗", data.policy.owner_policy_url));
  $("owner-activity-count").textContent = `Showing ${data.activity.length} of ${data.activity_total}`;
  for (const item of data.activity) {
    const row = node("article", undefined, "card registration-row"); const content = node("div");
    if (item.integrity === "verified") {
      content.append(node("h3", `${item.app_id} · ${item.environment.toUpperCase()}`), node("p", "Requested " + new Date(item.created_at).toLocaleString()), node("p", `Release ${item.release_id} · Requester GitHub user ${item.requester_user_id}`, "muted"), node("p", item.request_id, "mono"));
    } else content.append(node("h3", "Unverified or duplicate request record"), node("p", `Issue #${item.issue_number} · Inspect the original evidence`, "muted"));
    const actions = node("div", undefined, "row-action"); actions.append(node("span", item.integrity === "verified" ? (item.issuer_active ? "Signature verified" : "Historical issuer") : "Integrity needs review", "pill neutral"), ownerLink("Inspect request ↗", item.url));
    row.append(content, actions); $("owner-activity-list").append(row);
  }
  if (!data.activity.length) ownerEmpty($("owner-activity-list"), "No signed delivery request activity is available.");
}
async function workflowReview(repository, number) {
  const result = await api(`/api/v1/platform/reviews/${encodeURIComponent(repository)}/${number}`);
  state.workflow = { repository, number, view: result, operations: {} };
  show("workflow-review");
  $("workflow-title").textContent = result.title;
  $("workflow-target").textContent = `${repository} #${number} · ${result.branch} · ${result.head}`;
  $("workflow-result").textContent = result.merged ? "Merged. Deployment health is tracked separately." : "Review loaded from exact file contents.";
  $("workflow-history").replaceChildren();
  for (const review of result.reviews) $("workflow-history").append(node("p", `${review.user}: ${review.state} · ${review.commit || "No revision"}`, "muted"));
  $("workflow-files").replaceChildren();
  for (const file of result.files) {
    const card = node("details", undefined, "card form-card workflow-file");
    card.open = true;
    card.append(node("summary", `${file.status} · ${file.previous_path ? file.previous_path + " → " : ""}${file.path}`));
    if (file.binary) card.append(node("p", `Before: ${JSON.stringify(file.before)} · After: ${JSON.stringify(file.after)}`, "mono"));
    card.append(node("pre", file.diff || "No textual difference", "workflow-diff"));
    $("workflow-files").append(card);
  }
  $("workflow-ack").checked = false; $("workflow-reason").value = "";
  $("workflow-approve").hidden = !result.can_review;
  $("workflow-changes").hidden = !result.can_review;
  $("workflow-merge").hidden = !result.can_merge;
  $("workflow-form").hidden = !result.can_review && !result.can_merge;
}
async function workflowDecision(decision) {
  const current = state.workflow;
  if (!current || !$("workflow-ack").checked) throw new Error("Review the displayed changes and confirm before continuing.");
  const reason = $("workflow-reason").value;
  if (decision === "request_changes" && !reason.trim()) throw new Error("Explain which changes are required.");
  const operation = JSON.stringify([decision, reason]);
  current.operations[operation] ||= crypto.randomUUID();
  const result = await api(`/api/v1/platform/reviews/${encodeURIComponent(current.repository)}/${current.number}`, { method: "POST", body: JSON.stringify({ action: decision, review_token: current.view.review_token, operation_key: current.operations[operation], reason, acknowledge: true }) });
  $("workflow-result").textContent = result.status === "merged" ? "Merged. The deployment pipeline will report rollout health separately." : `Review recorded as ${state.session.login}. Refresh for current checks and review state.`;
  $("workflow-result").scrollIntoView({ behavior: "smooth", block: "center" });
  if (decision === "approve") $("workflow-approve").hidden = true;
  $("workflow-ack").checked = false;
  if (result.status === "merged") $("workflow-form").hidden = true;
  if (state.onboarding && ["approve", "merge"].includes(decision)) await refreshOnboarding(true);
}
$("workflow-form").addEventListener("submit", event => { event.preventDefault(); action(() => workflowDecision(event.submitter.value)); });
$("workflow-refresh").addEventListener("click", () => action(() => workflowReview(state.workflow.repository, state.workflow.number)));
$("workflow-back").addEventListener("click", () => action(async () => { await platformOverview(); ownerTab("reviews"); }));
$("nav-platform").addEventListener("click", () => action(platformOverview));
$("refresh-platform").addEventListener("click", () => action(platformOverview));
for (const button of document.querySelectorAll("[data-owner-tab]")) button.addEventListener("click", () => ownerTab(button.dataset.ownerTab));

action(async () => {
  state.status = await api("/api/v1/status");
  if (state.status.mode === "demo") {
    $("mode-banner").textContent = "LOCAL DEMO · Illustrative repositories and locally saved registration requests. No GitHub or cluster changes.";
    $("sign-in-button").textContent = "Enter local demo →";
    $("sign-in-note").textContent = "Uses a synthetic developer identity on this workstation.";
  } else if (state.status.mode === "live") {
    $("mode-banner").textContent = state.status.deployment_enabled
      ? "Authorized requests → GitOps review and checks → Argo deployment. PROD requires human approval."
      : "Catalog registration is available. Delivery setup is required before deployment requests can be enabled.";
  } else {
    $("mode-banner").textContent = "SETUP REQUIRED · Configure the GitHub App to enable registration, or start the explicit local demo.";
    $("sign-in-button").textContent = "GitHub App setup required"; $("sign-in-button").disabled = true;
  }
  if (state.status.registration_enabled) {
    try { const ownerRequested = window.location.hash === "#platform"; await loadSession(); if (ownerRequested && state.session.allowed_actions.includes("platform:view")) await platformOverview(); else { await applications(); if (typeof resumeOnboarding === "function") await resumeOnboarding(); } }
    catch (e) {
      show(state.session ? "applications" : "sign-in");
      if (state.session) error(e.message);
    }
  } else show("sign-in");
});

async function pipelineView(appId, requestId = null) {
  pipelineSelection = { appId, requestId };
  const generation = ++pipelineGeneration;
  const userId = state.session?.user_id;
  show("pipeline");
  $("pipeline-title").textContent = `${appId} · DEV pipeline`;
  $("pipeline-stages").replaceChildren();
  $("pipeline-summary").textContent = "Loading verified pipeline evidence…";
  const path = requestId
    ? `/api/v1/deployment-requests/${encodeURIComponent(requestId)}/pipeline`
    : `/api/v1/applications/${encodeURIComponent(appId)}/pipeline`;
  try {
    const data = await api(path);
    if (generation !== pipelineGeneration || state.session?.user_id !== userId || $("pipeline").hidden) return;
    $("pipeline-summary").textContent = data.message || `Source ${data.source_commit.slice(0, 12)} · Run ${data.run_id}, attempt ${data.run_attempt}`;
    for (const stage of data.stages) {
      const item = node("li", undefined, "pipeline-stage");
      const labels = { queued: "Queued", running: "Running", passed: "Passed", failed: "Failed", skipped: "Skipped", cancelled: "Cancelled", unknown: "Not verified" };
      item.append(node("strong", `${stage.number}. ${stage.name}`), node("span", labels[stage.state] || "Not verified", `pill pipeline-${stage.state}`));
      if (stage.message) item.append(node("p", stage.message, "muted"));
      $("pipeline-stages").append(item);
    }
  } catch (error) {
    if (generation === pipelineGeneration && state.session?.user_id === userId && !$("pipeline").hidden) {
      $("pipeline-stages").replaceChildren();
      $("pipeline-summary").textContent = error.message;
    }
  }
}
$("refresh-pipeline").addEventListener("click", () => { if (pipelineSelection) action(() => pipelineView(pipelineSelection.appId, pipelineSelection.requestId)); });
$("pipeline-back").addEventListener("click", () => action(applications));
$("delivery-pipeline").addEventListener("click", () => action(async () => {
  const result = await api(`/api/v1/deployment-requests/${encodeURIComponent(state.activeDeliveryId)}`);
  await pipelineView(result.app_id, result.request_id);
}));

$("progress-prepare").addEventListener("click", () => action(() => setupView(state.progressApp)));
$("progress-deploy").addEventListener("click", () => action(() => setupDeploy(state.progressApp)));
