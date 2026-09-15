"""Common Event Schema (CES) for normalized security telemetry.

Implements strict validation for network flows, authentication events, DNS queries,
endpoint process events, and synthetic test scenarios.
"""

from datetime import datetime, timezone
import ipaddress
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from backend.app.models.event import EventType, EventSeverity


class CommonEventSchema(BaseModel):
    """Normalized security telemetry event schema."""

    event_id: Optional[str] = Field(
        default=None,
        description="Unique event identifier (auto-generated if omitted)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event occurrence timestamp (UTC)",
    )
    source_ip: str = Field(..., description="IPv4 or IPv6 source address")
    destination_ip: str = Field(..., description="IPv4 or IPv6 destination address")
    source_port: int = Field(default=0, ge=0, le=65535, description="Source TCP/UDP port (0-65535)")
    destination_port: int = Field(default=0, ge=0, le=65535, description="Destination TCP/UDP port (0-65535)")
    protocol: str = Field(default="TCP", description="Transport protocol (e.g. TCP, UDP, ICMP)")

    user_id: Optional[str] = Field(default=None, description="Username or security principal identifier")
    device_id: Optional[str] = Field(default=None, description="Originating host or device identifier")
    event_type: EventType = Field(default=EventType.NETFLOW, description="Telemetry domain/type")
    severity: EventSeverity = Field(default=EventSeverity.INFO, description="Telemetry initial severity")

    features: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted numerical & statistical features (e.g. flow duration, byte ratio)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Supplemental raw context (process cmdline, DNS query name, HTTP status)",
    )

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, v: str) -> str:
        return v.strip().upper()

