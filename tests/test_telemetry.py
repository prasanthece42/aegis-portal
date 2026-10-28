import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from app.telemetry import Telemetry, TelemetryMiddleware


def instrumented():
    spans = InMemorySpanExporter()
    logs = InMemoryLogRecordExporter()
    metrics = InMemoryMetricReader()
    telemetry = Telemetry(
        "test-app", "test", span_exporter=spans, metric_reader=metrics, log_exporter=logs
    )
    app = FastAPI()
    app.state.telemetry = telemetry
    app.add_middleware(TelemetryMiddleware, holder=app)

    @app.get("/orders/{order_id}")
    def orders(order_id: str):
        return {"ok": True}

    @app.get("/boom")
    def failure():
        raise RuntimeError("sensitive-exception-body")

    @app.get("/health")
    def health():
        return {"ok": True}

    return app, telemetry, spans, logs, metrics


def test_request_signals_use_route_templates_and_never_capture_secrets():
    app, telemetry, spans, logs, metrics = instrumented()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get(
                "/orders/private-id?password=private-query",
                headers={
                    "Authorization": "Bearer private-header",
                    "Cookie": "session=private-cookie",
                    "traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01",
                    "tracestate": "vendor=private-state",
                },
            )
            assert response.status_code == 200
            assert client.get("/boom").status_code == 500
            client.get("/health")
        telemetry.flush()
        finished = spans.get_finished_spans()
        assert len(finished) == 2
        first = next(span for span in finished if span.name == "GET /orders/{order_id}")
        assert first.context.trace_id == int("a" * 32, 16)
        assert first.parent.span_id == int("b" * 16, 16)
        assert not first.context.trace_state
        assert (
            next(span for span in finished if span.name == "GET /boom").status.status_code
            == StatusCode.ERROR
        )
        assert all(not span.events for span in finished)
        emitted = logs.get_finished_logs()
        encoded = json.dumps(
            [
                {"body": row.log_record.body, "attributes": dict(row.log_record.attributes)}
                for row in emitted
            ]
        )
        encoded += str([dict(span.attributes) for span in finished])
        for private in [
            "private-id",
            "private-query",
            "private-header",
            "private-cookie",
            "private-state",
            "sensitive-exception-body",
        ]:
            assert private not in encoded
        metric_data = metrics.get_metrics_data()
        names = {
            metric.name
            for resource in metric_data.resource_metrics
            for scope in resource.scope_metrics
            for metric in scope.metrics
        }
        assert {
            "http.server.requests",
            "http.server.request.duration",
            "aegis.telemetry.heartbeat.timestamp",
        } <= names
    finally:
        telemetry.close()


def test_disabled_instrumentation_does_not_affect_business_requests():
    app = FastAPI()
    app.state.telemetry = None
    app.add_middleware(TelemetryMiddleware, holder=app)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok"}
