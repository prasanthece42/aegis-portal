"""Explicit, sanitized OTel signals. No URL queries, headers, bodies or exceptions."""

import json
import time
from contextlib import contextmanager

import requests
from aegis_platform.observability_policy import COLLECTOR_ENDPOINT
from opentelemetry._logs import SeverityNumber
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.propagators.textmap import DefaultGetter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.metrics.view import ExplicitBucketHistogramAggregation, View
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


class Telemetry:
    def __init__(
        self, service, version, *, span_exporter=None, metric_reader=None, log_exporter=None
    ):
        resource = Resource(
            {
                "service.name": service,
                "service.version": version,
                "telemetry.sdk.language": "python",
                "aegis.log_source": "request",
            }
        )

        def session():
            transport = requests.Session()
            transport.trust_env = False
            return transport

        self.trace_provider = TracerProvider(resource=resource)
        self.trace_provider.add_span_processor(
            BatchSpanProcessor(
                span_exporter
                or OTLPSpanExporter(
                    endpoint=COLLECTOR_ENDPOINT + "/v1/traces",
                    headers={},
                    timeout=2,
                    max_request_size=262144,
                    session=session(),
                ),
                max_queue_size=256,
                max_export_batch_size=64,
                schedule_delay_millis=1000,
            )
        )
        self.tracer = self.trace_provider.get_tracer("aegis.http")
        reader = metric_reader or PeriodicExportingMetricReader(
            OTLPMetricExporter(
                endpoint=COLLECTOR_ENDPOINT + "/v1/metrics",
                headers={},
                timeout=2,
                max_request_size=262144,
                session=session(),
            ),
            export_interval_millis=15000,
            export_timeout_millis=3000,
        )
        self.meter_provider = MeterProvider(
            resource=resource,
            metric_readers=[reader],
            views=[
                View(
                    instrument_name="http.server.request.duration",
                    aggregation=ExplicitBucketHistogramAggregation(
                        (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
                    ),
                )
            ],
        )
        meter = self.meter_provider.get_meter("aegis.http")
        self.requests = meter.create_counter("http.server.requests")
        self.duration = meter.create_histogram("http.server.request.duration", unit="s")
        from opentelemetry.metrics import Observation

        meter.create_observable_gauge(
            "aegis.telemetry.heartbeat.timestamp",
            callbacks=[lambda _: [Observation(time.time())]],
            unit="s",
        )
        self.log_provider = LoggerProvider(resource=resource)
        self.log_provider.add_log_record_processor(
            BatchLogRecordProcessor(
                log_exporter
                or OTLPLogExporter(
                    endpoint=COLLECTOR_ENDPOINT + "/v1/logs",
                    headers={},
                    timeout=2,
                    max_request_size=262144,
                    session=session(),
                ),
                max_queue_size=256,
                max_export_batch_size=64,
                schedule_delay_millis=1000,
            )
        )
        self.logger = self.log_provider.get_logger("aegis.http")
        self.propagator = TraceContextTextMapPropagator()

    def record(self, method, route, status, duration, span):
        values = {
            "http.request.method": method,
            "http.route": route,
            "http.response.status_code": status,
        }
        self.requests.add(1, values)
        self.duration.record(duration, values)
        identity = span.get_span_context()
        body = {
            "message": "HTTP request completed",
            "route": route,
            "status": status,
            "trace_id": format(identity.trace_id, "032x") if identity.is_valid else None,
        }
        self.logger.emit(
            body=json.dumps(body, separators=(",", ":")),
            severity_number=SeverityNumber.ERROR if status >= 500 else SeverityNumber.INFO,
            attributes=values,
        )

    @contextmanager
    def client_span(self, name, address):
        with self.tracer.start_as_current_span(
            name,
            kind=SpanKind.CLIENT,
            attributes={"server.address": address},
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            yield span

    def flush(self):
        self.trace_provider.force_flush(3000)
        self.log_provider.force_flush(3000)
        self.meter_provider.force_flush(3000)

    def close(self):
        self.trace_provider.shutdown()
        self.log_provider.shutdown()
        self.meter_provider.shutdown(timeout_millis=3000)


class TelemetryMiddleware:
    def __init__(self, app, holder):
        self.app, self.holder = app, holder

    async def __call__(self, scope, receive, send):
        telemetry = self.holder.state.telemetry
        path = scope.get("path", "")
        if (
            scope["type"] != "http"
            or telemetry is None
            or path.startswith(("/auth/", "/static/"))
            or path in {"/health", "/ready", "/favicon.ico"}
        ):
            return await self.app(scope, receive, send)
        method = scope.get("method", "OTHER")
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            method = "OTHER"
        # Only W3C traceparent is propagated. Baggage, tracestate and credentials are excluded.
        carrier = {
            key.decode(): value.decode("ascii", errors="ignore")
            for key, value in scope.get("headers", [])
            if key.lower() == b"traceparent" and len(value) <= 128
        }
        context = telemetry.propagator.extract(carrier, getter=DefaultGetter())
        started = time.monotonic()
        status = 500

        async def response(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        with telemetry.tracer.start_as_current_span(
            "HTTP " + method,
            kind=SpanKind.SERVER,
            context=context,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            try:
                return await self.app(scope, receive, response)
            finally:
                route = getattr(scope.get("route"), "path", "unmatched")
                route = route if isinstance(route, str) and len(route) <= 160 else "unmatched"
                span.update_name(method + " " + route)
                span.set_attributes(
                    {
                        "http.request.method": method,
                        "http.route": route,
                        "http.response.status_code": status,
                    }
                )
                if status >= 500:
                    span.set_status(Status(StatusCode.ERROR))
                telemetry.record(method, route, status, time.monotonic() - started, span)
