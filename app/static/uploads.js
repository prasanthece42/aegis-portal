"use strict";
let currentUpload = null;
let uploadReview = null;
let uploadSettings = null;
function clearUpload() {
  currentUpload = null; uploadReview = null; uploadSettings = null;
  $("upload-file").value = "";
  $("upload-files").replaceChildren(); $("upload-proposals").replaceChildren();
  $("upload-preparation").hidden = true; $("upload-review").hidden = true;
  $("upload-destination").hidden = true;
}
function pendingUpload() {
  try {
    const pending = JSON.parse(sessionStorage.getItem("aegis.pending-upload"));
    return pending?.user_id === state.session?.user_id ? pending : null;
  } catch { return null; }
}
async function uploadView() {
  const capabilities = await api("/api/v1/upload-capabilities");
  clearUpload(); show("upload");
  $("upload-mode").textContent = capabilities.mode === "demo"
    ? "Local demo: repository creation is simulated. No GitHub repository, release or deployment is created."
    : capabilities.creation_enabled ? "Public repositories in the configured GitHub account only. Pipeline installation and deployment need separate authorization."
      : "ZIP inspection is available. An operator must configure the allowed GitHub account and authorize repository creation before live creation is available.";
  $("upload-org").value = capabilities.organization;
  $("recover-upload").hidden = !pendingUpload();
  $("upload-state").textContent = "Choose a ZIP to inspect its files before contacting GitHub.";
  $("upload-detection").replaceChildren(); $("upload-exclusions").replaceChildren();
  $("upload-profile").replaceChildren(...Object.keys(state.session.resource_profiles).map((id) => new Option(id, id)));
  uploadProfileDescription();
  setRuntimeForm("upload-", null);
}
function uploadProfileDescription() {
  const p = state.session?.resource_profiles[$("upload-profile").value];
  $("upload-profile-description").textContent = p ? `Requests: ${p.cpu_request} CPU / ${p.memory_request} memory. Limits: ${p.cpu_limit} CPU / ${p.memory_limit} memory.` : "";
}
function renderUpload(record) {
  currentUpload = record;
  $("upload-files").replaceChildren(...record.files.map((f) => node("li", `${f.path} · ${f.size} bytes`)));
  $("upload-exclusions").replaceChildren(node("p", `Excluded: ${record.excluded.join(", ") || "none"}.`));
  const d = record.detection;
  $("upload-detection").replaceChildren(node("p", `Runtime: ${d.runtime}. Dockerfile: ${d.dockerfile_present ? "found" : "missing"}. Dependencies: ${d.dependency_files.join(", ") || "missing"}. Tests: ${d.tests_present ? "found" : "missing"}. Existing workflows: ${d.existing_workflows.length} (excluded). Detection is preliminary; CI must validate the app.`));
  $("upload-state").textContent = record.status === "blocked"
    ? `Upload blocked. Likely secrets detected in: ${record.blocked.join(", ")}. Remove credentials and inspect a clean ZIP. Secret values are never shown.`
    : !record.python_supported ? "Unsupported project. This version requires Python source and requirements.txt or pyproject.toml."
      : `Upload status: ${record.status.replaceAll("_", " ")}.`;
  $("upload-destination").hidden = record.status !== "inspected" || !record.python_supported;
  $("upload-review").hidden = true;
  $("upload-preparation").hidden = record.status !== "uploaded";
  $("upload-continue").hidden = true;
  if (record.repository) $("upload-state").textContent += ` Repository already created: ${record.repository.full_name}.`;
  if (record.status === "uploaded") {
    $("upload-repository").textContent = `${record.repository.full_name} · public · Not registered · Not deployed`;
    const name = record.repository.full_name.split("/")[1];
    $("upload-app-id").value = name.toLowerCase().replaceAll("_", "-");
    $("upload-display").value = name;
    setRuntimeForm("upload-", record.detection.stack ? {profile_id:"python312-multiservice",stack:record.detection.stack} : null);
  }
  $("recover-upload").hidden = !pendingUpload();
}
$("open-upload").addEventListener("click", () => action(uploadView));
$("upload-back").addEventListener("click", () => action(registration));
$("upload-profile").addEventListener("change", uploadProfileDescription);
$("inspect-upload").addEventListener("click", () => action(async () => {
  const file = $("upload-file").files[0];
  if (!file || !file.name.toLowerCase().endsWith(".zip")) throw new Error("Choose a project ZIP first.");
  if (file.size > 5 * 1024 * 1024) throw new Error("ZIP uploads must be at most 5 MiB.");
  uploadReview = null; uploadSettings = null;
  const result = await api("/api/v1/uploads", { method: "POST", headers: { "Content-Type": "application/zip" }, body: file });
  if (result.status !== "blocked") sessionStorage.setItem("aegis.pending-upload", JSON.stringify({ user_id: state.session.user_id, upload_id: result.upload_id }));
  renderUpload(result);
  $("upload-name").value = file.name.replace(/\.zip$/i, "").replace(/[^A-Za-z0-9_-]/g, "-");
}));
$("upload-destination").addEventListener("submit", (event) => {
  event.preventDefault(); action(async () => {
    uploadReview = await api(`/api/v1/uploads/${currentUpload.upload_id}/review`, { method: "POST", body: JSON.stringify({ name: $("upload-name").value, visibility: "public" }) });
    $("upload-review-target").textContent = `${uploadReview.organization}/${uploadReview.name} · Public · ${uploadReview.files.length} files. Anyone can read these files once uploaded.`;
    $("upload-review").hidden = false;
  });
});
for (const id of ["upload-name", "upload-visibility"]) $(id).addEventListener("input", () => { uploadReview = null; $("upload-review").hidden = true; });
$("create-upload").addEventListener("click", () => action(async () => {
  if (!uploadReview) throw new Error("Review your destination first.");
  try {
    const result = await api(`/api/v1/uploads/${currentUpload.upload_id}/confirm`, { method: "POST", body: JSON.stringify({ review_token: uploadReview.review_token }) });
    renderUpload(result);
  } catch (e) {
    // Read durable state even if the response was lost after GitHub created the repository.
    try { renderUpload(await api(`/api/v1/uploads/${currentUpload.upload_id}`)); } catch { /* keep recovery ID */ }
    throw e;
  }
}));
$("recover-upload").addEventListener("click", () => action(async () => {
  const pending = pendingUpload();
  if (!pending) throw new Error("No upload belongs to the current signed-in identity.");
  let result = await api(`/api/v1/uploads/${pending.upload_id}`);
  renderUpload(result);
  if (!["inspected", "uploaded"].includes(result.status)) {
    result = await api(`/api/v1/uploads/${pending.upload_id}/resume`, { method: "POST" });
    renderUpload(result);
  }
  if (result.name) $("upload-name").value = result.name;
}));
$("upload-settings").addEventListener("submit", (event) => {
  event.preventDefault(); action(async () => {
    const proposedSettings = { repository_id: currentUpload.repository.repository_id, app_id: $("upload-app-id").value, display_name: $("upload-display").value,
      owner_user_ids: [state.session.user_id], runtime: runtimeFromForm("upload-") };
    const proposal = await api(`/api/v1/uploads/${currentUpload.upload_id}/preparation`, { method: "POST", body: JSON.stringify(proposedSettings) });
    uploadSettings = proposal.settings;
    $("upload-proposals").replaceChildren(node("h3", "Requirements to complete"), node("ul"));
    const list = $("upload-proposals").querySelector("ul");
    proposal.missing_requirements.forEach((message) => list.append(node("li", message)));
    $("upload-proposals").append(node("p", proposal.instructions, "notice"));
    for (const file of proposal.proposed_files) {
      const details = node("details"), code = node("pre", file.content), download = node("button", "Download proposed file", "secondary");
      download.type = "button";
      download.addEventListener("click", () => {
        const url = URL.createObjectURL(new Blob([file.content], { type: "text/plain" }));
        const link = node("a"); link.href = url; link.download = file.path.split("/").pop(); link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      });
      details.append(node("summary", file.path), code, download); $("upload-proposals").append(details);
    }
    $("upload-continue").hidden = false;
  });
});
$("upload-settings").addEventListener("input", () => { uploadSettings = null; $("upload-continue").hidden = true; $("upload-proposals").replaceChildren(); });
$("upload-continue").addEventListener("click", () => action(async () => {
  if (!uploadSettings) throw new Error("Confirm runtime settings and review pipeline requirements first.");
  const settings = uploadSettings;
  await registration();
  if (!state.repositories.some((r) => r.repository_id === settings.repository_id)) {
    $("repository").append(new Option(currentUpload.repository.full_name, settings.repository_id));
  }
  $("repository").value = settings.repository_id;
  $("app-id").value = settings.app_id; $("display-name").value = settings.display_name;
  setRuntimeForm("", settings.runtime);
  $("port").value = settings.runtime.container_port; $("health-path").value = settings.runtime.health_path;
  $("resource-profile").value = settings.runtime.resource_profile_id; profileDescription();
  await validate();
}));
