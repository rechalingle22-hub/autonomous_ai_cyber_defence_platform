"""Zero-Trust Adaptive Access Control & Micro-Segmentation Package."""

from backend.app.zerotrust.engine import (
    ZeroTrustEngine,
    AccessDecision,
    ResourceSensitivity,
    AuthAssuranceLevel,
    zero_trust_engine,
)

__all__ = [
    "ZeroTrustEngine",
    "AccessDecision",
    "ResourceSensitivity",
    "AuthAssuranceLevel",
    "zero_trust_engine",
]

