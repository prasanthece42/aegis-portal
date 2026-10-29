"""Platform contracts plus explicit portal-specific preparation consent."""

from aegis_platform.contracts import (
    Access,
    AppId,
    CatalogEntry,
    Commit,
    Contract,
    DeploymentIntent,
    DesiredState,
    Digest,
    Environment,
    Identifier,
    PriorEvidence,
    RegistrationFields,
    Runtime,
    Source,
    Target,
    Versions,
)
from aegis_platform.contracts import (
    RegistrationSubmission as BaseRegistrationSubmission,
)
from pydantic import StrictBool


class RegistrationSubmission(BaseRegistrationSubmission):
    prepare_dev: StrictBool = False


__all__ = [
    "Access",
    "AppId",
    "CatalogEntry",
    "Commit",
    "Contract",
    "DeploymentIntent",
    "DesiredState",
    "Digest",
    "Environment",
    "Identifier",
    "PriorEvidence",
    "RegistrationFields",
    "RegistrationSubmission",
    "Runtime",
    "Source",
    "Target",
    "Versions",
]
