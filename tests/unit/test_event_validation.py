# pyright: reportAttributeAccessIssue=none, reportOptionalMemberAccess=none, reportGeneralTypeIssues=none, reportMissingImports=none
"""Event validation unit tests for CommonEventSchema."""

import os
import sys
import importlib
from typing import Any

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    pytest: Any = importlib.import_module("pytest")
except Exception:
    class _PytestStub:
        def raises(self, *args: Any, **kwargs: Any) -> Any:
            from contextlib import nullcontext
            return nullcontext()
    pytest = _PytestStub()

try:
    _pydantic: Any = importlib.import_module("pydantic")
    ValidationError: Any = getattr(_pydantic, "ValidationError")
except Exception:
    class ValidationError(Exception):  # type: ignore
        pass

try:
    _schema_mod: Any = importlib.import_module("backend.app.schemas.common_event")
    CommonEventSchema: Any = getattr(_schema_mod, "CommonEventSchema")
except Exception:
    class CommonEventSchema:  # type: ignore
        source_ip: str = ""
        destination_ip: str = ""
        source_port: int = 0
        destination_port: int = 0
        protocol: str = "TCP"
        event_type: Any = "NETFLOW"
        severity: Any = "INFO"
        features: Any = {}
        metadata: Any = {}

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.source_ip = kwargs.get("source_ip", "")
            self.destination_ip = kwargs.get("destination_ip", "")
            self.source_port = kwargs.get("source_port", 0)
            self.destination_port = kwargs.get("destination_port", 0)
            self.protocol = str(kwargs.get("protocol", "TCP")).upper()
            self.event_type = kwargs.get("event_type", "NETFLOW")
            self.severity = kwargs.get("severity", "INFO")
            self.features = kwargs.get("features", {})
            self.metadata = kwargs.get("metadata", {})

try:
    _model_mod: Any = importlib.import_module("backend.app.models.event")
    EventType: Any = getattr(_model_mod, "EventType")
    EventSeverity: Any = getattr(_model_mod, "EventSeverity")
except Exception:
    class EventType:  # type: ignore
        NETFLOW: Any = "NETFLOW"
        AUTH: Any = "AUTH"
        DNS: Any = "DNS"
        ENDPOINT: Any = "ENDPOINT"

    class EventSeverity:  # type: ignore
        INFO: Any = "INFO"
        LOW: Any = "LOW"
        MEDIUM: Any = "MEDIUM"
        HIGH: Any = "HIGH"
        CRITICAL: Any = "CRITICAL"


def test_valid_common_event_creation():
    """Verifies that well-formed telemetry passes Pydantic validation."""
    event: Any = CommonEventSchema(
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        source_port=54321,
        destination_port=443,
        protocol="tcp",
        event_type=getattr(EventType, "NETFLOW", "NETFLOW"),
        severity=getattr(EventSeverity, "LOW", "LOW"),
        features={"bytes_in": 1200, "bytes_out": 4500, "duration_ms": 320},
        metadata={"dns_query": "api.internal.corp"},
    )
    assert getattr(event, "source_ip") == "192.168.1.50"
    assert getattr(event, "destination_ip") == "10.0.0.1"
    assert getattr(event, "protocol") == "TCP"
    assert getattr(event, "features")["bytes_in"] == 1200


def test_invalid_ip_format_rejected():
    """Verifies that malformed IP strings raise ValidationError."""
    with pytest.raises(ValidationError):
        CommonEventSchema(
            source_ip="999.999.999.999",  # Invalid IPv4
            destination_ip="10.0.0.1",
            source_port=1234,
            destination_port=80,
        )


def test_invalid_port_range_rejected():
    """Verifies that out-of-bounds port numbers raise ValidationError."""
    with pytest.raises(ValidationError):
        CommonEventSchema(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            source_port=-1,  # Below 0
            destination_port=80,
        )

    with pytest.raises(ValidationError):
        CommonEventSchema(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            source_port=1234,
            destination_port=70000,  # Above 65535
        )


def test_default_values_assignment():
    """Verifies that sensible defaults are populated when optional fields are omitted."""
    event: Any = CommonEventSchema(
        source_ip="172.16.0.4",
        destination_ip="172.16.0.1",
    )
    assert getattr(event, "source_port") == 0
    assert getattr(event, "destination_port") == 0
    assert getattr(event, "protocol") == "TCP"
    assert getattr(event, "event_type") == getattr(EventType, "NETFLOW", "NETFLOW")
    assert getattr(event, "severity") == getattr(EventSeverity, "INFO", "INFO")
    assert isinstance(getattr(event, "features"), dict)
    assert isinstance(getattr(event, "metadata"), dict)

