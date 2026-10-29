"""One read-only view of registration, preparation, release and signed DEV delivery."""

from app.errors import PortalError


def onboarding_status(session, app_id, registration_id, registrations, setup, delivery):
    registration = None
    if registration_id:
        registration = registrations.get(session, registration_id)
        if registration["app_id"] != app_id:
            raise PortalError(404, "REGISTRATION_NOT_FOUND", "Registration is unavailable.")
        catalog = registration["requirements"][0]["status"]
        if catalog != "approved":
            closed = catalog == "closed_unmerged"
            if (
                not closed
                and registration.get("automatic_setup")
                and hasattr(registrations.backend, "registration_preparation_status")
                and registrations.backend.registration_preparation_status(registration_id)
                in {"error", "failure"}
            ):
                return {
                    "app_id": app_id,
                    "registration_id": registration_id,
                    "phase": "needs_attention",
                    "actor": "Application and platform owners",
                    "message": "Source, access or setup policy changed. Ask the platform owner "
                    "to reconcile this registration before a fresh setup review. "
                    "No deployment has started.",
                    "registration": registration,
                    "setup": None,
                    "deployment": None,
                }
            return {
                "app_id": app_id,
                "registration_id": registration_id,
                "phase": "needs_attention" if closed else "owner_review",
                "message": "The registration was closed without approval."
                if closed
                else (
                    "Waiting for platform owner approval. "
                    "Preparation follows automatically when authorized."
                    if registration.get("automatic_setup")
                    else (
                        "Waiting for platform owner approval. "
                        "Setup review will follow on this page."
                    )
                ),
                "actor": "Platform owner",
                "registration": registration,
                "setup": None,
                "deployment": None,
            }
    observed = setup.latest(session, app_id)
    deployed = delivery.latest_for_app(session, app_id)
    phase, message, actor = "preparing", "The platform is preparing your app.", "Platform"
    if deployed and deployed["status"] not in {"closed_unmerged", "superseded"}:
        if deployed["status"] == "healthy" and deployed.get("security_verified"):
            phase, message, actor = "healthy", "Your app is healthy in DEV.", "Complete"
        elif deployed.get("health_check_failed"):
            phase, message, actor = (
                "needs_attention",
                "DEV health verification failed. Inspect the request and pipeline results.",
                "Application owner",
            )
        else:
            phase, message, actor = (
                "deploying",
                "Your confirmed release is moving through GitOps and health verification.",
                "Platform",
            )
    elif observed["state"] == "ready":
        phase, message, actor = (
            "release_review",
            "A validated release is ready. Review it and confirm DEV deployment.",
            "You",
        )
    elif observed["state"] == "not_started":
        phase, message, actor = (
            "setup_review",
            "Review the pipeline and DEV setup files to continue.",
            "You",
        )
    elif observed["state"] == "awaiting_review":
        phase, message, actor = (
            "setup_approval",
            "Review the generated changes. Required owner approvals are still needed.",
            "Application and platform owners",
        )
    elif observed["state"] == "building":
        phase, message, actor = (
            "building",
            "CI is validating the app and publishing a release. "
            "No deployment starts automatically.",
            "Application CI",
        )
    elif observed["state"] == "needs_attention":
        phase, message, actor = (
            "needs_attention",
            observed.get("message")
            or "Setup needs attention. Inspect requirements and CI results below.",
            "Application owner",
        )
    return {
        "app_id": app_id,
        "registration_id": registration_id,
        "phase": phase,
        "message": message,
        "actor": actor,
        "registration": registration,
        "setup": observed,
        "deployment": deployed,
    }
