"""Portal-only, bounded telemetry queries with fresh catalog authorization."""

import base64
import json
import math
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from functools import wraps
from types import SimpleNamespace

import httpx
from aegis_platform.canonical import strict_json
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import CatalogEntry
from aegis_platform.observability_policy import (
    OBS_NAMESPACE,
    ObservabilityPolicy,
    password_fingerprint,
    query_password,
)

from app.errors import PortalError

WINDOWS = {"15m": 900, "1h": 3600}
TRACE_ID = re.compile(r"[0-9a-f]{32}")


def bounded_payload(function):
    """Malformed private provider data must never become an unhandled portal failure."""

    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError) as exc:
            raise PortalError(
                503, "TELEMETRY_INVALID", "The telemetry backend returned invalid data."
            ) from exc

    return guarded


def finite(value):
    try:
        number = float(value)
        return number if math.isfinite(number) else None
    except (ValueError, TypeError, OverflowError):
        return None


def otlp_attributes(values):
    return {
        row.get("key"): row.get("value", {}).get("stringValue")
        for row in values
        if isinstance(row, dict)
    }


def hex_identifier(value, size):
    if not isinstance(value, str):
        return None
    if re.fullmatch("[0-9a-fA-F]{" + str(size * 2) + "}", value):
        return value.lower()
    try:
        raw = base64.b64decode(value, validate=True)
        return raw.hex() if len(raw) == size else None
    except (ValueError, TypeError):
        return None


@bounded_payload
def scoped_trace(payload, namespace, trace_id, cluster_uid):
    """A trace ID is not an authorization grant: exclude every other namespace's spans."""
    rows = []
    batches = payload.get("batches", payload.get("resourceSpans", []))
    for batch in batches:
        attrs = otlp_attributes(batch.get("resource", {}).get("attributes", []))
        if (
            attrs.get("k8s.namespace.name") != namespace
            or attrs.get("aegis.cluster.uid") != cluster_uid
        ):
            continue
        for group in batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", [])):
            for span in group.get("spans", []):
                if hex_identifier(span.get("traceId"), 16) != trace_id:
                    continue
                ident = hex_identifier(span.get("spanId"), 8)
                start, end = (
                    finite(span.get("startTimeUnixNano")),
                    finite(span.get("endTimeUnixNano")),
                )
                if (
                    ident is None
                    or start is None
                    or end is None
                    or end < start
                    or end - start > 3600000000000
                ):
                    continue
                rows.append(
                    {
                        "span_id": ident,
                        "parent_span_id": hex_identifier(span.get("parentSpanId"), 8),
                        "name": str(span.get("name", "Span"))[:160],
                        "service": str(attrs.get("service.name") or "Application")[:80],
                        "start_ns": int(start),
                        "duration_ns": int(end - start),
                        "error": span.get("status", {}).get("code") == 2,
                    }
                )
                if len(rows) > 200:
                    raise PortalError(
                        422, "TRACE_TOO_LARGE", "This trace exceeds the 200-span portal limit."
                    )
    if not rows:
        raise PortalError(
            404, "TRACE_NOT_FOUND", "No authorized spans are available for this trace."
        )
    return {
        "trace_id": trace_id,
        "namespace": namespace,
        "spans": sorted(rows, key=lambda r: r["start_ns"]),
    }


class MonitoringService:
    def __init__(self, backend, client=None):
        self.backend = backend
        self.client = client or httpx.Client(timeout=5, follow_redirects=False, trust_env=False)

    def close(self):
        self.client.close()

    def policy(self):
        backend = self.backend
        if not hasattr(backend, "catalog_snapshot") or not hasattr(backend, "client_secret"):
            raise PortalError(
                503,
                "MONITORING_SETUP_REQUIRED",
                "Monitoring requires the configured live platform.",
            )
        revision, delivery = backend.catalog_snapshot()
        raw = backend.file(
            backend.config.platform_repository,
            "policies/observability.json",
            revision,
            backend.platform_token(),
        )
        if raw is None:
            raise PortalError(
                503,
                "MONITORING_SETUP_REQUIRED",
                "The reviewed monitoring stack is not configured yet.",
            )
        try:
            policy = ObservabilityPolicy.model_validate(strict_json(raw))
            config = backend.config
            if (
                policy.platform_repository_id != config.platform_repository_id
                or policy.gitops_repository_id != config.gitops_repository_id
                or policy.gitops_repository != config.gitops_repository
                or policy.cluster_uid != config.cluster_uid
                or policy.cluster_id != config.cluster_id
            ):
                raise ValueError("Monitoring bindings differ")
            password = query_password(backend.client_secret, policy.cluster_uid)
            if password_fingerprint(password) != policy.query_password_sha256:
                raise ValueError("Query capability fingerprint differs")
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503,
                "MONITORING_POLICY_INVALID",
                "Monitoring identity or read capability could not be verified.",
            ) from exc
        return revision, policy, password

    def app_context(self, session, app_id, environment):
        revision, policy, password = self.policy()
        backend = self.backend
        self.verify_user(session)
        token = backend.platform_token()
        raw = backend.file(
            backend.config.platform_repository, f"catalog/apps/{app_id}.json", revision, token
        )
        if raw is None:
            raise PortalError(404, "APPLICATION_UNAVAILABLE", "Application is unavailable.")
        entry = CatalogEntry.model_validate(strict_json(raw))
        access = entry.access
        users = set(
            access.owner_user_ids
            + access.viewer_user_ids
            + access.deployer_user_ids_by_environment.get(environment, [])
        )
        if session.user_id not in users or environment not in entry.environments:
            raise PortalError(
                403, "MONITORING_FORBIDDEN", "No current application visibility grant."
            )
        target = entry.environments[environment]
        cluster = Cluster.model_validate(
            strict_json(
                backend.file(
                    backend.config.platform_repository,
                    f"catalog/clusters/{target.cluster_id}.json",
                    revision,
                    token,
                )
            )
        )
        catalog_policy = CatalogPolicy.model_validate(
            strict_json(
                backend.file(
                    backend.config.platform_repository, "policies/catalog.json", revision, token
                )
            )
        )
        Catalog([entry], [cluster], catalog_policy)
        if target.cluster_uid != policy.cluster_uid:
            raise PortalError(
                503,
                "MONITORING_CLUSTER_UNAVAILABLE",
                "This application has no enrolled monitoring backend.",
            )
        return SimpleNamespace(
            policy=policy,
            password=password,
            namespace=target.namespace,
            label=entry.display_name + " · " + environment.upper(),
        )

    def platform_context(self, session, kind):
        revision, policy, password = self.policy()
        self.verify_user(session)
        self.backend.owner_context(session)
        if kind == "portal":
            from aegis_platform.portal_system import PortalSystemPolicy

            system = PortalSystemPolicy.model_validate(
                strict_json(
                    self.backend.file(
                        self.backend.config.platform_repository,
                        "policies/portal-system.json",
                        revision,
                        self.backend.platform_token(),
                    )
                )
            )
            if system.configuration.cluster_uid != policy.cluster_uid:
                raise PortalError(
                    503, "MONITORING_POLICY_INVALID", "Platform service cluster identity differs."
                )
            if session.user_id not in system.operator_user_ids:
                raise PortalError(
                    403,
                    "MONITORING_FORBIDDEN",
                    "Platform service telemetry requires an operator grant.",
                )
            return SimpleNamespace(
                policy=policy,
                password=password,
                namespace="aegis-portal-system",
                label="Platform portal",
            )
        if kind == "cluster":
            return SimpleNamespace(
                policy=policy,
                password=password,
                namespace=None,
                label="Cluster · " + policy.cluster_id,
            )
        raise PortalError(404, "MONITORING_NOT_FOUND", "Unknown platform monitoring target.")

    def verify_user(self, session):
        user = self.backend.api("GET", "/user", session.user_token).json()
        if str(user.get("id")) != session.user_id or user.get("type") != "User":
            raise PortalError(401, "SIGN_IN_REQUIRED", "Sign in again to view private telemetry.")

    def get(self, context, provider, path, params=None):
        # Provider names and paths are server-owned; no URL, PromQL or LogQL from the browser.
        if provider not in {"prometheus", "loki", "tempo", "alertmanager"}:
            raise ValueError("Unknown telemetry provider")
        address = f"http://{provider}.{OBS_NAMESPACE}.svc.cluster.local:8080"
        try:
            with self.client.stream(
                "GET",
                address + path,
                params=params,
                auth=httpx.BasicAuth("query", context.password),
                headers={"Accept": "application/json"},
            ) as response:
                if response.status_code == 404:
                    raise PortalError(
                        404, "TELEMETRY_NOT_FOUND", "No telemetry is available for this selection."
                    )
                if response.status_code != 200:
                    raise PortalError(
                        503,
                        "TELEMETRY_UNAVAILABLE",
                        "The telemetry backend is unavailable. Retry safely.",
                        True,
                    )
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 2097152:
                        raise PortalError(
                            503,
                            "TELEMETRY_BUDGET_EXCEEDED",
                            "Telemetry exceeds the bounded response budget.",
                        )
            payload = strict_json(bytes(content))
            if not isinstance(payload, dict):
                raise ValueError("Expected a telemetry object")
            return payload
        except (httpx.HTTPError, ValueError) as exc:
            raise PortalError(
                503,
                "TELEMETRY_UNAVAILABLE",
                "The telemetry backend is unavailable. Retry safely.",
                True,
            ) from exc

    def selector(self, context, **extra):
        labels = {"aegis_cluster_uid": context.policy.cluster_uid, **extra}
        if context.namespace:
            labels["k8s_namespace_name"] = context.namespace
        return "{" + ",".join(key + "=" + json.dumps(value) for key, value in labels.items()) + "}"

    @bounded_payload
    def vector(self, context, query):
        result = self.get(context, "prometheus", "/api/v1/query", {"query": query})
        if result.get("status") != "success":
            raise PortalError(503, "TELEMETRY_UNAVAILABLE", "Metrics query did not complete.")
        values = result.get("data", {}).get("result", [])
        return finite(values[0]["value"][1]) if values else None

    @bounded_payload
    def metrics(self, context, window):
        seconds = WINDOWS[window]
        now = time.time()
        selector = self.selector(context)
        definitions = (
            [
                ("node_cpu", "Node CPU · cores", f"sum(k8s_node_cpu_usage{selector})"),
                (
                    "node_memory",
                    "Node memory · bytes",
                    f"sum(k8s_node_memory_usage_bytes{selector})",
                ),
                (
                    "node_capacity",
                    "Allocatable memory · bytes",
                    f"sum(k8s_node_allocatable_memory_bytes{selector})",
                ),
            ]
            if context.namespace is None
            else [
                (
                    "requests",
                    "Requests / second",
                    f"sum(rate(http_server_requests_total{selector}[1m]))",
                ),
                (
                    "latency",
                    "95th percentile latency · seconds",
                    (
                        "histogram_quantile(0.95, sum by (le) "
                        f"(rate(http_server_request_duration_seconds_bucket{selector}[5m])))"
                    ),
                ),
                ("cpu", "Pod CPU · cores", f"sum(k8s_pod_cpu_usage{selector})"),
                ("memory", "Pod memory · bytes", f"sum(k8s_pod_memory_usage_bytes{selector})"),
            ]
        )
        with ThreadPoolExecutor(max_workers=5) as pool:
            pending = [
                pool.submit(
                    self.get,
                    context,
                    "prometheus",
                    "/api/v1/query_range",
                    {"query": query, "start": int(now - seconds), "end": int(now), "step": 30},
                )
                for _, _, query in definitions
            ]
            heartbeat_query = (
                pool.submit(
                    self.vector,
                    context,
                    f"max(aegis_telemetry_heartbeat_timestamp_seconds{selector})",
                )
                if context.namespace
                else None
            )
            results = [future.result() for future in pending]
            heartbeat = heartbeat_query.result() if heartbeat_query else None
        rows = []
        for (key, label, _), data in zip(definitions, results, strict=True):
            if data.get("status") != "success":
                raise PortalError(503, "TELEMETRY_UNAVAILABLE", "Metrics query did not complete.")
            result = data.get("data", {}).get("result", [])
            if len(result) > 1:
                raise PortalError(503, "TELEMETRY_INVALID", "Unexpected unaggregated metrics.")
            samples = []
            for stamp, value in result[0].get("values", []) if result else []:
                stamp, value = finite(stamp), finite(value)
                if (
                    stamp is not None
                    and value is not None
                    and now - seconds - 30 <= stamp <= now + 30
                ):
                    samples.append([stamp, value])
                if len(samples) > 125:
                    raise PortalError(
                        503, "TELEMETRY_BUDGET_EXCEEDED", "Metrics exceed the chart sample budget."
                    )
            rows.append({"key": key, "label": label, "points": samples})
        age = now - heartbeat if heartbeat is not None else None
        return {
            "series": rows,
            "application_signal": (
                "fresh"
                if age is not None and -30 <= age <= 90
                else "stale"
                if age is not None
                else "not_observed"
            ),
            "heartbeat_at": heartbeat,
            "label": context.label,
            "observed_at": datetime.now(UTC).isoformat(),
            "window": window,
        }

    @bounded_payload
    def logs(self, context, window):
        if context.namespace is None:
            raise PortalError(
                403, "MONITORING_FORBIDDEN", "Select an application or platform service for logs."
            )
        now = time.time()
        query = (
            "{k8s_namespace_name="
            + json.dumps(context.namespace)
            + ",aegis_cluster_uid="
            + json.dumps(context.policy.cluster_uid)
            + "}"
        )
        data = self.get(
            context,
            "loki",
            "/loki/api/v1/query_range",
            {
                "query": query,
                "start": int((now - WINDOWS[window]) * 1e9),
                "end": int(now * 1e9),
                "limit": 100,
                "direction": "backward",
            },
        )
        if data.get("status") != "success":
            raise PortalError(503, "TELEMETRY_UNAVAILABLE", "Log query did not complete.")
        rows = []
        for stream in data.get("data", {}).get("result", []):
            labels = stream.get("stream", {})
            if (
                labels.get("k8s_namespace_name") != context.namespace
                or labels.get("aegis_cluster_uid") != context.policy.cluster_uid
            ):
                raise PortalError(503, "TELEMETRY_SCOPE_INVALID", "Unexpected log stream identity.")
            for value in stream.get("values", []):
                stamp = finite(value[0])
                line = str(value[1])
                trace_id = None
                try:
                    body = strict_json(line)
                    if isinstance(body, dict):
                        trace_id = body.get("trace_id")
                except ValueError:
                    pass
                if not isinstance(trace_id, str) or not TRACE_ID.fullmatch(trace_id):
                    trace_id = None
                rows.append(
                    {
                        "timestamp_ns": str(int(stamp)) if stamp is not None else None,
                        "line": line[:4096],
                        "truncated": len(line) > 4096,
                        "trace_id": trace_id,
                    }
                )
                if len(rows) > 100:
                    raise PortalError(
                        503, "TELEMETRY_BUDGET_EXCEEDED", "Logs exceed the row budget."
                    )
        rows.sort(key=lambda row: int(row["timestamp_ns"] or 0), reverse=True)
        return {"logs": rows, "label": context.label, "observed_at": datetime.now(UTC).isoformat()}

    @bounded_payload
    def alerts(self, context, window):
        data = self.get(context, "prometheus", "/api/v1/alerts")
        if data.get("status") != "success":
            raise PortalError(503, "TELEMETRY_UNAVAILABLE", "Alerts are unavailable.")
        rows = []
        for alert in data.get("data", {}).get("alerts", []):
            labels = alert.get("labels", {})
            if labels.get("aegis_cluster_uid") != context.policy.cluster_uid:
                continue
            if context.namespace and labels.get("k8s_namespace_name") != context.namespace:
                continue
            rows.append(
                {
                    "name": str(labels.get("alertname", "Alert"))[:100],
                    "severity": str(labels.get("severity", "warning"))[:30],
                    "state": str(alert.get("state", "unknown"))[:30],
                    "summary": str(alert.get("annotations", {}).get("summary", ""))[:300],
                    "active_at": alert.get("activeAt"),
                    "namespace": labels.get("k8s_namespace_name"),
                }
            )
            if len(rows) > 100:
                raise PortalError(503, "TELEMETRY_BUDGET_EXCEEDED", "Alerts exceed the row budget.")
        return {
            "alerts": rows,
            "label": context.label,
            "observed_at": datetime.now(UTC).isoformat(),
            "notifications": "in_portal_only",
        }

    @bounded_payload
    def trace(self, context, trace_id):
        if context.namespace is None or not TRACE_ID.fullmatch(trace_id):
            raise PortalError(404, "TRACE_NOT_FOUND", "Trace is unavailable.")
        payload = self.get(context, "tempo", "/api/traces/" + trace_id)
        result = scoped_trace(payload, context.namespace, trace_id, context.policy.cluster_uid)
        result.update(label=context.label, observed_at=datetime.now(UTC).isoformat())
        return result

    @bounded_payload
    def traces(self, context, window):
        if context.namespace is None:
            raise PortalError(
                403, "MONITORING_FORBIDDEN", "Select an application or service for traces."
            )
        now = int(time.time())
        query = (
            "{ resource.k8s.namespace.name = "
            + json.dumps(context.namespace)
            + " && resource.aegis.cluster.uid = "
            + json.dumps(context.policy.cluster_uid)
            + " }"
        )
        data = self.get(
            context,
            "tempo",
            "/api/search",
            {"q": query, "start": now - WINDOWS[window], "end": now, "limit": 10},
        )
        identities = []
        for trace in data.get("traces", [])[:10]:
            trace_id = str(trace.get("traceID", "")).lower()
            if TRACE_ID.fullmatch(trace_id) and trace_id not in identities:
                identities.append(trace_id)

        def read_trace(trace_id):
            try:
                return self.trace(context, trace_id)
            except PortalError as exc:
                if exc.status == 404:
                    return None
                raise

        with ThreadPoolExecutor(max_workers=10) as pool:
            details = list(pool.map(read_trace, identities))
        rows = []
        for trace_id, detail in zip(identities, details, strict=True):
            if detail is None:
                continue
            spans = detail["spans"]
            first = min(s["start_ns"] for s in spans)
            last = max(s["start_ns"] + s["duration_ns"] for s in spans)
            rows.append(
                {
                    "trace_id": trace_id,
                    "start_ns": str(first),
                    "duration_ns": last - first,
                    "span_count": len(spans),
                    "name": spans[0]["name"],
                    "service": spans[0]["service"],
                    "error": any(s["error"] for s in spans),
                }
            )
        return {
            "traces": rows,
            "label": context.label,
            "observed_at": datetime.now(UTC).isoformat(),
        }

    def query(self, context, signal, window):
        if signal not in {"metrics", "logs", "alerts", "traces"} or window not in WINDOWS:
            raise PortalError(
                422, "MONITORING_QUERY_INVALID", "Choose a supported signal and time window."
            )
        return getattr(self, signal)(context, window)
