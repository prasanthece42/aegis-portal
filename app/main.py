import base64
import hashlib
import os
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from aegis_platform.contracts import AppId, Environment
from aegis_platform.delivery import DeploymentFields, DeploymentSubmission
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Request
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.contracts import RegistrationFields, RegistrationSubmission
from app.demo import DemoBackend, demo_config
from app.deployment import DeploymentService
from app.errors import PortalError
from app.github import GitHub
from app.monitoring import MonitoringService
from app.registration import RegistrationService
from app.security import Session, Sessions, Signer, strict_json
from app.telemetry import Telemetry, TelemetryMiddleware
from app.workflows import WorkflowService, WorkflowSubmission

STATIC = Path(__file__).parent / "static"


class RequestBoundary:
    """Reject oversized/ambiguous JSON before route parsing, without buffering unbounded input."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in {"GET", "HEAD"}:
            return await self.app(scope, receive, send)
        chunks, length = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            length += len(chunk)
            if length > 32768:
                response = JSONResponse(
                    {
                        "error": {
                            "code": "BODY_TOO_LARGE",
                            "message": "Request exceeds 32 KiB.",
                            "retryable": False,
                        }
                    },
                    status_code=413,
                )
                return await response(scope, receive, send)
            chunks.append(chunk)
            if not message.get("more_body"):
                break
        body = b"".join(chunks)
        if body and scope["path"].startswith("/api/"):
            try:
                strict_json(body)
            except (ValueError, UnicodeError):
                response = JSONResponse(
                    {
                        "error": {
                            "code": "INVALID_JSON",
                            "message": "JSON must be valid with unique keys.",
                            "retryable": False,
                        }
                    },
                    status_code=422,
                )
                return await response(scope, receive, send)
        consumed = False

        async def replay():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def create_app(
    settings: Settings | None = None, backend=None, signer: Signer | None = None
) -> FastAPI:
    settings = settings or Settings()
    config = settings.live
    if settings.mode == "demo":
        config = demo_config()
        backend = backend or DemoBackend(settings.demo_path)
        # This public fixture key is ONLY for isolated demo records, never live trust.
        signer = signer or Signer(
            Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(b"aegis-local-demo-only-v1").digest()
            ),
            config.signing_key_id,
        )
    elif settings.mode == "live":
        backend = backend or GitHub(config)
        if signer is None:
            key = serialization.load_pem_private_key(
                Path(os.environ["AEGIS_SIGNING_KEY_FILE"]).read_bytes(), password=None
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("Request signing requires a separate Ed25519 key")
            signer = Signer(key, config.signing_key_id)
        expected_public = os.getenv("AEGIS_SIGNING_PUBLIC_KEY_B64")
        if expected_public:
            actual_public = base64.b64encode(
                signer.key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ).decode()
            if not secrets.compare_digest(actual_public, expected_public):
                raise ValueError("Request signing key does not match its configured public binding")
    sessions = Sessions()
    service = RegistrationService(config, backend, signer) if config else None
    delivery = DeploymentService(config, backend, signer) if config else None
    workflows = WorkflowService(backend, signer) if config else None
    monitoring = MonitoringService(backend) if config else None

    @asynccontextmanager
    async def lifespan(_app):
        if settings.mode == "live" and os.getenv("KUBERNETES_SERVICE_HOST"):
            try:
                monitoring.policy()
                _app.state.telemetry = Telemetry("aegis-portal", "0.4.1")
                backend.telemetry = _app.state.telemetry
            except PortalError:
                pass  # The front door must remain available to repair monitoring.
        try:
            yield
        finally:
            if _app.state.telemetry:
                _app.state.telemetry.close()
            if monitoring:
                monitoring.close()
            if backend:
                backend.close()

    app = FastAPI(title="Aegis Portal", version="0.4.1", lifespan=lifespan)
    app.state.settings, app.state.sessions, app.state.service = settings, sessions, service
    app.state.delivery = delivery
    app.state.workflows = workflows
    app.state.monitoring, app.state.telemetry = monitoring, None
    app.add_middleware(RequestBoundary)
    app.add_middleware(TelemetryMiddleware, holder=app)

    @app.exception_handler(PortalError)
    async def portal_error(_request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "retryable": exc.retryable,
                    "correlation_id": secrets.token_hex(8),
                }
            },
            status_code=exc.status,
            headers={"Retry-After": "60"} if exc.status == 429 else None,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_fields(_request, exc):
        # Do not echo input values; review tokens and provider errors must not leak.
        fields = [
            {"field": ".".join(str(x) for x in e["loc"]), "message": e["msg"]} for e in exc.errors()
        ]
        return JSONResponse(
            {
                "error": {
                    "code": "INVALID_FIELDS",
                    "message": "Check the highlighted configuration fields.",
                    "field_errors": fields,
                    "retryable": False,
                }
            },
            status_code=422,
        )

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if settings.mode == "demo":
            if request.url.hostname not in {"127.0.0.1", "localhost", "testserver"}:
                return JSONResponse(
                    {"error": {"code": "DEMO_LOCAL_ONLY", "message": "Demo mode is local only."}},
                    status_code=403,
                )
            if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}:
                return JSONResponse(
                    {
                        "error": {
                            "code": "DEMO_LOCAL_ONLY",
                            "message": "Demo mode accepts loopback clients only.",
                        }
                    },
                    status_code=403,
                )
        if settings.mode == "live" and request.url.path not in {"/health", "/ready"}:
            # TLS may terminate at the configured local ingress; never trust arbitrary Host.
            if request.headers.get("host") != settings.origin.removeprefix("https://"):
                return JSONResponse(
                    {"error": {"code": "HOST_INVALID", "message": "Unrecognized portal origin."}},
                    status_code=400,
                )
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if settings.mode == "live":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def ready():
        if not service:
            raise PortalError(
                503, "SETUP_REQUIRED", "Configure the GitHub App or launch the explicit local demo."
            )

    def same_origin(request: Request):
        expected = settings.origin
        if settings.mode == "demo":
            expected = str(request.base_url).rstrip("/")
        if request.headers.get("origin") != expected:
            raise PortalError(403, "ORIGIN_INVALID", "Request origin does not match the portal.")

    def principal(request: Request) -> Session:
        ready()
        session = sessions.get(request.cookies.get(settings.cookie_name, ""))
        if not session:
            raise PortalError(401, "SIGN_IN_REQUIRED", "Sign in to continue.")
        if request.method not in {"GET", "HEAD"}:
            same_origin(request)
            if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf):
                raise PortalError(403, "CSRF_INVALID", "Refresh the page before submitting again.")
        return session

    Auth = Annotated[Session, Depends(principal)]

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ready")
    def readiness():
        ready()
        return {
            "status": "ready",
            "mode": settings.mode,
            "capabilities": ["registration"]
            + (["delivery_requests"] if config.delivery_workflow_commit else []),
            "deployment_enabled": bool(config and config.delivery_workflow_commit),
        }

    @app.get("/api/v1/status")
    def status():
        return {
            "mode": settings.mode,
            "registration_enabled": service is not None,
            "deployment_enabled": bool(config and config.delivery_workflow_commit),
            "version": "0.4.1",
            "operator_preview": os.getenv("AEGIS_OPERATOR_PREVIEW") == "1",
        }

    @app.get("/auth/github/start")
    def sign_in():
        ready()
        if settings.mode != "live":
            raise PortalError(409, "DEMO_SIGN_IN", "Use local demo sign-in in demo mode.")
        state, verifier = sessions.start_oauth()
        response = RedirectResponse(backend.oauth_url(state, verifier), status_code=303)
        response.set_cookie(
            "__Host-aegis_oauth",
            state,
            max_age=300,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/auth/github/callback")
    def callback(request: Request, state: str = "", code: str = ""):
        ready()
        if settings.mode != "live":
            raise PortalError(404, "AUTH_UNAVAILABLE", "GitHub callback is not enabled.")
        cookie_state = request.cookies.get("__Host-aegis_oauth", "")
        if not state or not secrets.compare_digest(state, cookie_state):
            raise PortalError(
                401, "AUTH_STATE_INVALID", "GitHub authorization state did not match."
            )
        verifier = sessions.consume_oauth(state)
        if not verifier or not code:
            raise PortalError(
                401, "AUTH_STATE_INVALID", "GitHub authorization expired or was already used."
            )
        user, token, lifetime = backend.exchange(code, verifier)
        sid = sessions.create(str(user["id"]), user["login"], token, lifetime)
        old = request.cookies.get(settings.cookie_name)
        if old:
            sessions.records.pop(old, None)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            settings.cookie_name,
            sid,
            max_age=lifetime,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        response.delete_cookie(
            "__Host-aegis_oauth", secure=True, httponly=True, samesite="lax", path="/"
        )
        return response

    @app.post("/auth/demo")
    def demo_sign_in(request: Request):
        if settings.mode != "demo":
            raise PortalError(404, "DEMO_DISABLED", "Demo sign-in is disabled.")
        same_origin(request)
        old = request.cookies.get(settings.cookie_name)
        if old:
            sessions.records.pop(old, None)
        sid = sessions.create("1", "demo-developer", "demo-not-a-github-token")
        response = JSONResponse({"signed_in": True, "mode": "demo"})
        response.set_cookie(
            settings.cookie_name, sid, max_age=28800, httponly=True, samesite="lax", path="/"
        )
        return response

    @app.post("/auth/logout")
    def logout(request: Request, session: Auth):
        sessions.records.pop(request.cookies.get(settings.cookie_name, ""), None)
        response = JSONResponse({"signed_out": True})
        response.delete_cookie(
            settings.cookie_name,
            path="/",
            secure=settings.mode == "live",
            httponly=True,
            samesite="lax",
        )
        return response

    @app.get("/api/v1/session")
    def get_session(session: Auth):
        actions = ["register"] if session.user_id in config.onboarding_user_ids else []
        owner_status = "not_granted"
        if hasattr(backend, "owner_allowed"):
            try:
                if backend.owner_allowed(session):
                    actions.append("platform:view")
                    owner_status = "granted"
            except PortalError:
                owner_status = "unavailable"
        return {
            "user_id": session.user_id,
            "login": session.login,
            "csrf_token": session.csrf,
            "allowed_actions": actions,
            "platform_owner_status": owner_status,
            "owner_choices": [{"user_id": session.user_id, "label": session.login}],
            "resource_profiles": config.model_dump()["resource_profiles"],
        }

    @app.get("/api/v1/platform/overview")
    def platform_overview(session: Auth):
        if not hasattr(backend, "owner_overview"):
            raise PortalError(403, "PLATFORM_FORBIDDEN", "Platform owner access is not enabled.")
        return backend.owner_overview(session)

    @app.get("/api/v1/platform/reviews/{repository}/{number}")
    def review_details(
        repository: Literal["platform", "portal", "gitops"],
        number: Annotated[int, ApiPath(ge=1)],
        session: Auth,
    ):
        result = workflows.details(session, repository, number)
        return {key: value for key, value in result.items() if key != "binding"}

    @app.post("/api/v1/platform/reviews/{repository}/{number}")
    def review_submit(
        repository: Literal["platform", "portal", "gitops"],
        number: Annotated[int, ApiPath(ge=1)],
        fields: WorkflowSubmission,
        session: Auth,
    ):
        return workflows.submit(session, repository, number, fields)

    @app.get("/api/v1/repositories")
    def repositories(session: Auth):
        return {"items": backend.repositories(session)}

    @app.get("/api/v1/applications/{app_id}/observability/{signal}")
    def app_observability(
        app_id: AppId,
        signal: Literal["metrics", "logs", "alerts", "traces"],
        session: Auth,
        environment: Environment = "dev",
        window: Literal["15m", "1h"] = "15m",
    ):
        context = monitoring.app_context(session, app_id, environment)
        return monitoring.query(context, signal, window)

    @app.get("/api/v1/applications/{app_id}/observability/traces/{trace_id}")
    def app_trace(
        app_id: AppId,
        trace_id: str,
        session: Auth,
        environment: Environment = "dev",
    ):
        context = monitoring.app_context(session, app_id, environment)
        return monitoring.trace(context, trace_id)

    @app.get("/api/v1/platform/observability/{target}/{signal}")
    def platform_observability(
        target: Literal["portal", "cluster"],
        signal: Literal["metrics", "logs", "alerts", "traces"],
        session: Auth,
        window: Literal["15m", "1h"] = "15m",
    ):
        context = monitoring.platform_context(session, target)
        return monitoring.query(context, signal, window)

    @app.get("/api/v1/platform/observability/portal/traces/{trace_id}")
    def platform_trace(trace_id: str, session: Auth):
        context = monitoring.platform_context(session, "portal")
        return monitoring.trace(context, trace_id)

    @app.post("/api/v1/registration-validations")
    def validate(fields: RegistrationFields, session: Auth):
        return service.preview(session, fields)

    @app.post("/api/v1/registrations", status_code=201)
    def submit(request: Request, fields: RegistrationSubmission, session: Auth):
        key = request.headers.get("idempotency-key", "")
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            key,
        ):
            raise PortalError(
                422,
                "IDEMPOTENCY_KEY_REQUIRED",
                "Use a UUID v4 idempotency key for confirmed registration.",
            )
        result = service.submit(session, fields, key.lower())
        return JSONResponse(
            result,
            status_code=201,
            headers={"Location": "/api/v1/registrations/" + result["registration_id"]},
        )

    @app.get("/api/v1/registrations")
    def list_registrations(session: Auth):
        return {"items": service.list(session)}

    @app.get("/api/v1/registrations/{registration_id}")
    def get_registration(registration_id: str, session: Auth):
        if not re.fullmatch(r"reg-[0-9a-f]{64}", registration_id):
            raise PortalError(404, "REGISTRATION_NOT_FOUND", "Registration is unavailable.")
        return service.get(session, registration_id)

    @app.get("/api/v1/applications")
    def list_applications(session: Auth):
        from app.contracts import CatalogEntry

        items = []
        for raw in backend.catalog():
            entry = CatalogEntry.model_validate(raw)
            access = entry.access
            if session.user_id in set(
                access.owner_user_ids
                + access.viewer_user_ids
                + [
                    user
                    for users in access.deployer_user_ids_by_environment.values()
                    for user in users
                ]
            ):
                items.append(entry.model_dump())
        return {"items": items}

    @app.get("/api/v1/applications/{app_id}/pipeline")
    def application_pipeline(app_id: AppId, session: Auth):
        from app.pipeline import discover

        delivery.enabled()
        return discover(backend, session, app_id)

    @app.get("/api/v1/deployment-requests/{request_id}/pipeline")
    def deployment_pipeline(request_id: str, session: Auth):
        from app.pipeline import discover

        if not re.fullmatch(r"req-[0-9a-f]{64}", request_id):
            raise PortalError(404, "REQUEST_UNAVAILABLE", "Request is unavailable.")
        result = delivery.get(session, request_id)
        if result["environment"] != "dev":
            raise PortalError(422, "DEV_ONLY", "Pipeline progress is currently available for DEV.")
        return discover(
            backend, session, result["app_id"], release_id=result["release_id"], delivery=result
        )

    @app.post("/api/v1/deployment-validations")
    def validate_deployment(fields: DeploymentFields, session: Auth):
        return delivery.preview(session, fields)

    @app.get("/api/v1/applications/{app_id}/releases")
    def list_releases(app_id: str, session: Auth, environment: str = "dev", page: int = 1):
        delivery.enabled()
        if (
            not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", app_id)
            or not 3 <= len(app_id) <= 40
            or environment not in {"dev", "staging", "prod"}
            or not 1 <= page <= 10
        ):
            raise PortalError(422, "INVALID_FIELDS", "Choose an application, environment and page.")
        return backend.delivery_releases(session, app_id, environment, page)

    @app.post("/api/v1/deployment-requests", status_code=202)
    def submit_deployment(request: Request, fields: DeploymentSubmission, session: Auth):
        key = request.headers.get("idempotency-key", "")
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            key,
        ):
            raise PortalError(422, "IDEMPOTENCY_KEY_REQUIRED", "Use a UUID v4 idempotency key.")
        result = delivery.submit(session, fields, key.lower())
        return JSONResponse(
            result,
            status_code=202,
            headers={"Location": "/api/v1/deployment-requests/" + result["request_id"]},
        )

    @app.get("/api/v1/deployment-requests/{request_id}")
    def get_deployment(request_id: str, session: Auth):
        if not re.fullmatch(r"req-[0-9a-f]{64}", request_id):
            raise PortalError(404, "REQUEST_UNAVAILABLE", "Request is unavailable.")
        return delivery.get(session, request_id)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    return app


app = create_app()
