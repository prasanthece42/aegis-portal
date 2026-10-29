"""Review-only pipeline proposals. Never install workflows with portal credentials."""

import json


def preparation(config, record, fields):
    is_stack = fields.runtime.profile_id == "python312-multiservice"
    versions = config.multiservice_versions if is_stack else config.versions
    paths = {f["path"] for f in record["files"]}
    missing = []
    if "Dockerfile" not in paths:
        missing.append(
            "Add and review a non-root Python 3.12 Dockerfile "
            "with the confirmed port and health endpoint."
        )
    for filename in ("requirements.txt", "requirements-prod.txt"):
        if filename not in paths:
            missing.append(
                f"Generate and review hash-locked {filename} "
                "for the platform's pip --require-hashes checks."
            )
    # Presence alone is not proof that lock files, tests or the image pass platform CI.
    missing.append(
        "Verify requirements.txt and requirements-prod.txt are hash-locked; "
        "development dependencies must include pytest and ruff."
    )
    if not record["detection"]["tests_present"]:
        missing.append("Add tests covering the application and health endpoint.")
    missing.append(
        "Run platform CI, resolve lint/test/image checks, and complete catalog "
        "and DEV target review before selecting a release."
    )
    proposed = []
    for kind in ("ci", "release"):
        trigger = "  pull_request:\n" if kind == "ci" else ""
        write = "read" if kind == "ci" else "write"
        packages = "" if kind == "ci" else "  packages: write\n"
        family = "python-stack" if is_stack else "python-web"
        content = (
            f"name: Aegis {kind}\n\non:\n{trigger}  push:\n"
            f"    branches: [{json.dumps(record['repository']['default_branch'])}]\n"
            "  workflow_dispatch:\n\n"
            f"permissions:\n  contents: {write}\n{packages}  actions: read\n\n"
            f"concurrency:\n  group: aegis-{kind}-${{{{ github.ref }}}}\n"
            "  cancel-in-progress: false\n\n"
            f"jobs:\n  validate:\n    uses: {config.platform_repository}/.github/workflows/"
            f"{family}-{kind}.yml@{versions.workflow_commit}\n"
            f"    with:\n      app-id: {fields.app_id}\n"
            + (
                ""
                if is_stack
                else f"      container-port: {json.dumps(str(fields.runtime.container_port))}\n"
                f"      health-path: {json.dumps(fields.runtime.health_path)}\n"
            )
        )
        if kind == "ci":
            content += '      platforms: \'["amd64","arm64"]\'\n'
        proposed.append({"path": f".github/workflows/{kind}.yml", "content": content})
    if is_stack:
        missing += [
            "The release must validate every service and publish the complete immutable bundle.",
            f"An operator must provision Secret {fields.runtime.credentials_secret} "
            "in the reviewed application namespace. Enter references only, never credentials.",
            "Review namespace budgets, persistent storage and Argo bindings before deployment.",
        ]
    return {
        "proposed_files": proposed,
        "missing_requirements": missing,
        "installation_method": "manual_reviewed_commit" if is_stack else "guided_dev_setup",
        "instructions": (
            (
                "Review these files. An authorized repository maintainer must commit "
                "them through GitHub or a workflow-authorized Git client. Portal credentials "
                "cannot install workflows. Existing workflows from the ZIP were excluded. "
                "Installing release.yml enables release builds; DEV deployment still requires "
                "a separate confirmed request."
            )
            if is_stack
            else "Continue to the combined registration and setup review. After catalog approval, "
            "the platform proposes and installs the approved pipeline files and prepares "
            "DEV permissions through its authorized preparation service. "
            "CI then builds a validated release. Deployment still requires a separate "
            "release selection and confirmation."
        ),
        "settings": fields.model_dump(),
    }
