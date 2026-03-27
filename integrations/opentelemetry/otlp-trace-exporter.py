#!/usr/bin/env python3
"""
AegisBPF → OpenTelemetry OTLP Trace Exporter

Reads AegisBPF JSON events from stdin and exports them as OpenTelemetry
traces via OTLP (gRPC or HTTP). Each enforcement event becomes a span
with full process attribution and policy context.

Usage:
    # Export to local OTLP collector (Jaeger, Tempo, etc.)
    sudo aegisbpf daemon 2>&1 | python3 otlp-trace-exporter.py

    # Export to Grafana Tempo
    export OTEL_EXPORTER_OTLP_ENDPOINT="http://tempo.monitoring:4317"
    sudo aegisbpf daemon 2>&1 | python3 otlp-trace-exporter.py

    # Export via HTTP (instead of gRPC)
    export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
    export OTEL_EXPORTER_OTLP_ENDPOINT="http://collector:4318"
    sudo aegisbpf daemon 2>&1 | python3 otlp-trace-exporter.py

Environment Variables:
    OTEL_EXPORTER_OTLP_ENDPOINT  — Collector endpoint (default: http://localhost:4317)
    OTEL_EXPORTER_OTLP_PROTOCOL  — "grpc" or "http/protobuf" (default: grpc)
    OTEL_SERVICE_NAME            — Service name (default: aegisbpf)
    OTEL_RESOURCE_ATTRIBUTES     — Additional resource attributes (key=val,key=val)
    AEGIS_TRACE_EXEC_EVENTS      — Also trace exec events, not just blocks (default: 0)
    AEGIS_BATCH_TIMEOUT_MS       — Batch export timeout in ms (default: 5000)

Requires: Python 3.9+
    pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME
    from opentelemetry.trace import StatusCode, SpanKind
    from opentelemetry.semconv.trace import SpanAttributes
except ImportError:
    sys.stderr.write(
        "ERROR: OpenTelemetry SDK required. Install:\n"
        "  pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp\n"
    )
    sys.exit(1)


def _create_exporter():
    """Create OTLP exporter based on protocol configuration."""
    protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

    if protocol == "http/protobuf":
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError:
            sys.stderr.write(
                "ERROR: HTTP exporter required. Install:\n"
                "  pip install opentelemetry-exporter-otlp-proto-http\n"
            )
            sys.exit(1)
    else:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError:
            sys.stderr.write(
                "ERROR: gRPC exporter required. Install:\n"
                "  pip install opentelemetry-exporter-otlp-proto-grpc\n"
            )
            sys.exit(1)

    return OTLPSpanExporter()


def _build_resource() -> Resource:
    """Build OTel resource with AegisBPF attributes."""
    service_name = os.environ.get("OTEL_SERVICE_NAME", "aegisbpf")
    attrs = {
        SERVICE_NAME: service_name,
        "host.name": socket.gethostname(),
        "service.namespace": "security",
        "service.version": "0.1.0",
        "deployment.environment": os.environ.get("OTEL_DEPLOYMENT_ENV", "production"),
    }

    # Parse additional resource attributes from env
    extra = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
    if extra:
        for pair in extra.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                attrs[k.strip()] = v.strip()

    return Resource.create(attrs)


class AegisBPFTraceExporter:
    """Exports AegisBPF events as OpenTelemetry traces."""

    def __init__(self):
        resource = _build_resource()
        provider = TracerProvider(resource=resource)

        exporter = _create_exporter()
        batch_timeout = int(os.environ.get("AEGIS_BATCH_TIMEOUT_MS", "5000"))
        processor = BatchSpanProcessor(
            exporter,
            schedule_delay_millis=batch_timeout,
        )
        provider.add_span_processor(processor)

        trace.set_tracer_provider(provider)
        self.tracer = trace.get_tracer("aegisbpf.exporter", "0.1.0")
        self.provider = provider

        self.trace_exec = os.environ.get("AEGIS_TRACE_EXEC_EVENTS", "0") == "1"
        self.stats = {"traced": 0, "skipped": 0, "errors": 0}

    def _trace_block_event(self, event: dict):
        """Create a span for a file block event."""
        path = event.get("path", event.get("resolved_path", "unknown"))
        span_name = f"aegis.file_block"

        with self.tracer.start_as_current_span(
            span_name,
            kind=SpanKind.INTERNAL,
        ) as span:
            span.set_status(StatusCode.OK)

            # Process identity
            span.set_attribute("process.pid", event.get("pid", 0))
            span.set_attribute("process.ppid", event.get("ppid", 0))
            span.set_attribute("process.command", event.get("comm", ""))
            if "exec_id" in event:
                span.set_attribute("process.exec_id", event["exec_id"])

            # File attributes
            span.set_attribute("file.path", path)
            if "ino" in event:
                span.set_attribute("file.inode", str(event["ino"]))
            if "dev" in event:
                span.set_attribute("file.device", str(event["dev"]))

            # Enforcement attributes
            span.set_attribute("aegis.event_type", event.get("type", "block"))
            span.set_attribute("aegis.action", event.get("action", "deny"))
            span.set_attribute("aegis.rule_type", "deny_inode")
            span.set_attribute("aegis.outcome", "blocked")

            # Cgroup / K8s context
            if "cgroup_path" in event:
                span.set_attribute("aegis.cgroup_path", event["cgroup_path"])
            if "k8s_pod" in event:
                span.set_attribute("k8s.pod.name", event["k8s_pod"])
            if "k8s_namespace" in event:
                span.set_attribute("k8s.namespace.name", event["k8s_namespace"])
            if "k8s_service_account" in event:
                span.set_attribute(
                    "k8s.service_account.name", event["k8s_service_account"]
                )

            # Exec identity
            if "exec_identity_known" in event:
                span.set_attribute(
                    "aegis.exec_identity_known", event["exec_identity_known"]
                )
            if "verified_exec" in event:
                span.set_attribute("aegis.verified_exec", event["verified_exec"])

    def _trace_net_block_event(self, event: dict):
        """Create a span for a network block event."""
        event_type = event.get("type", "net_block")
        rule_type = event.get("rule_type", "unknown")
        span_name = f"aegis.net_block.{rule_type}"

        with self.tracer.start_as_current_span(
            span_name,
            kind=SpanKind.INTERNAL,
        ) as span:
            span.set_status(StatusCode.OK)

            # Process identity
            span.set_attribute("process.pid", event.get("pid", 0))
            span.set_attribute("process.ppid", event.get("ppid", 0))
            span.set_attribute("process.command", event.get("comm", ""))

            # Network attributes
            if "remote_ip" in event:
                span.set_attribute("net.peer.ip", event["remote_ip"])
            if "remote_port" in event:
                span.set_attribute("net.peer.port", event["remote_port"])
            if "local_port" in event:
                span.set_attribute("net.host.port", event["local_port"])
            if "protocol" in event:
                span.set_attribute("net.transport", event["protocol"])
            if "direction" in event:
                span.set_attribute("aegis.direction", event["direction"])

            # Enforcement attributes
            span.set_attribute("aegis.event_type", event_type)
            span.set_attribute("aegis.rule_type", rule_type)
            span.set_attribute("aegis.outcome", "blocked")

            # Cgroup / K8s
            if "cgroup_path" in event:
                span.set_attribute("aegis.cgroup_path", event["cgroup_path"])
            if "k8s_pod" in event:
                span.set_attribute("k8s.pod.name", event["k8s_pod"])
            if "k8s_namespace" in event:
                span.set_attribute("k8s.namespace.name", event["k8s_namespace"])

    def _trace_kernel_block_event(self, event: dict):
        """Create a span for a kernel security block event."""
        rule_type = event.get("rule_type", "unknown")
        span_name = f"aegis.kernel_block.{rule_type}"

        with self.tracer.start_as_current_span(
            span_name,
            kind=SpanKind.INTERNAL,
        ) as span:
            span.set_status(StatusCode.OK)

            # Process identity
            span.set_attribute("process.pid", event.get("pid", 0))
            span.set_attribute("process.ppid", event.get("ppid", 0))
            span.set_attribute("process.command", event.get("comm", ""))

            # Enforcement
            span.set_attribute("aegis.event_type", event.get("type", "kernel_block"))
            span.set_attribute("aegis.rule_type", rule_type)
            span.set_attribute("aegis.outcome", "blocked")

            if "target_pid" in event and event["target_pid"]:
                span.set_attribute("aegis.target_pid", event["target_pid"])

            if "cgroup_path" in event:
                span.set_attribute("aegis.cgroup_path", event["cgroup_path"])

    def _trace_exec_event(self, event: dict):
        """Create a span for a process exec event."""
        comm = event.get("comm", "unknown")
        span_name = f"aegis.exec.{comm}"

        with self.tracer.start_as_current_span(
            span_name,
            kind=SpanKind.INTERNAL,
        ) as span:
            span.set_status(StatusCode.OK)

            span.set_attribute("process.pid", event.get("pid", 0))
            span.set_attribute("process.ppid", event.get("ppid", 0))
            span.set_attribute("process.command", comm)
            if "exec_id" in event:
                span.set_attribute("process.exec_id", event["exec_id"])
            if "uid" in event:
                span.set_attribute("process.owner", str(event["uid"]))

            span.set_attribute("aegis.event_type", "exec")

            if "exec_identity_known" in event:
                span.set_attribute(
                    "aegis.exec_identity_known", event["exec_identity_known"]
                )
            if "verified_exec" in event:
                span.set_attribute("aegis.verified_exec", event["verified_exec"])

            if "cgroup_path" in event:
                span.set_attribute("aegis.cgroup_path", event["cgroup_path"])
            if "k8s_pod" in event:
                span.set_attribute("k8s.pod.name", event["k8s_pod"])

    def _trace_state_change(self, event: dict):
        """Create a span for a runtime state change."""
        state = event.get("state", "unknown")
        span_name = f"aegis.state_change.{state}"

        with self.tracer.start_as_current_span(
            span_name,
            kind=SpanKind.INTERNAL,
        ) as span:
            span.set_status(StatusCode.OK)
            span.set_attribute("aegis.event_type", "state_change")
            span.set_attribute("aegis.state", state)
            if "reason_code" in event:
                span.set_attribute("aegis.reason_code", event["reason_code"])

    def process_event(self, event: dict):
        """Route an event to the appropriate trace handler."""
        event_type = event.get("type", "")

        try:
            if event_type == "block" or event_type == "forensic_block":
                self._trace_block_event(event)
                self.stats["traced"] += 1
            elif event_type.startswith("net_"):
                self._trace_net_block_event(event)
                self.stats["traced"] += 1
            elif event_type.startswith("kernel_"):
                self._trace_kernel_block_event(event)
                self.stats["traced"] += 1
            elif event_type == "exec" and self.trace_exec:
                self._trace_exec_event(event)
                self.stats["traced"] += 1
            elif event_type == "state_change":
                self._trace_state_change(event)
                self.stats["traced"] += 1
            else:
                self.stats["skipped"] += 1
        except Exception as e:
            self.stats["errors"] += 1
            sys.stderr.write(f"ERROR: Failed to trace event: {e}\n")

    def run(self):
        """Main loop: read events from stdin, export as OTLP traces."""
        endpoint = os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
        )
        protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

        sys.stderr.write("AegisBPF → OpenTelemetry OTLP trace exporter started\n")
        sys.stderr.write(f"  Endpoint: {endpoint}\n")
        sys.stderr.write(f"  Protocol: {protocol}\n")
        sys.stderr.write(f"  Trace exec events: {self.trace_exec}\n")

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    self.process_event(event)
                except json.JSONDecodeError:
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            self.provider.shutdown()
            sys.stderr.write(
                f"Exporter stopped. Traced: {self.stats['traced']}, "
                f"Skipped: {self.stats['skipped']}, "
                f"Errors: {self.stats['errors']}\n"
            )


def main():
    exporter = AegisBPFTraceExporter()
    exporter.run()


if __name__ == "__main__":
    main()
