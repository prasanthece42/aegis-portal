"""Review-only pipeline proposals. Never install workflows with portal credentials."""

import json


def preparation(config, record, fields):
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
        "Verify development and production requirements are hash-locked; "
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
        content = (
            f"name: Aegis {kind}\n\non:\n{trigger}  push:\n"
            f"    branches: [{json.dumps(record['repository']['default_branch'])}]\n"
            "  workflow_dispatch:\n\n"
            f"permissions:\n  contents: {write}\n{packages}  actions: read\n\n"
            f"concurrency:\n  group: aegis-{kind}-${{{{ github.ref }}}}\n"
            "  cancel-in-progress: false\n\n"
            f"jobs:\n  validate:\n    uses: {config.platform_repository}/.github/workflows/"
            f"python-web-{kind}.yml@{config.versions.workflow_commit}\n"
            f"    with:\n      app-id: {fields.app_id}\n"
            f"      container-port: {json.dumps(str(fields.runtime.container_port))}\n"
            f"      health-path: {json.dumps(fields.runtime.health_path)}\n"
        )
        if kind == "ci":
            content += '      platforms: \'["amd64","arm64"]\'\n'
        proposed.append({"path": f".github/workflows/{kind}.yml", "content": content})
    return {
        "proposed_files": proposed,
        "missing_requirements": missing,
        "installation_method": "manual_reviewed_commit",
        "instructions": (
            "Review and download these files. An authorized repository maintainer must commit "
            "them through GitHub or their own workflow-authorized Git client. Portal credentials "
            "cannot install workflows. Existing workflows from the ZIP were excluded. "
            "Installing release.yml enables release builds; DEV deployment still requires "
            "a separate confirmed request."
        ),
        "settings": fields.model_dump(),
    }
