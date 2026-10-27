"""Run with python -m app.export_schemas after changing API/data contracts."""

import json
from pathlib import Path

from aegis_platform.delivery import DeploymentFields, DeploymentSubmission

from app.contracts import (
    CatalogEntry,
    DeploymentIntent,
    DesiredState,
    RegistrationFields,
    RegistrationSubmission,
)


def export(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    for model, filename in [
        (CatalogEntry, "catalog-entry.v1.json"),
        (DeploymentIntent, "deployment-intent.v1.json"),
        (DesiredState, "desired-state.v1.json"),
        (RegistrationFields, "registration-fields.v1.json"),
        (RegistrationSubmission, "registration-submission.v1.json"),
        (DeploymentFields, "deployment-fields.v1.json"),
        (DeploymentSubmission, "deployment-submission.v1.json"),
    ]:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        (directory / filename).write_text(json.dumps(schema, indent=2) + "\n")


if __name__ == "__main__":
    export(Path(__file__).resolve().parent.parent / "schemas")
