"""Standard feature definitions, bounds, and unified attack taxonomy."""

from typing import List, Dict

# Unified attack categories matching Section 8 of platform specification
ATTACK_CATEGORIES: List[str] = [
    "BENIGN",
    "DOS_DDOS",
    "BRUTE_FORCE",
    "PORT_SCAN",
    "WEB_ATTACK",
    "BOTNET",
    "SUSPICIOUS_AUTH",
    "DATA_EXFILTRATION",
    "ANOMALOUS_OTHER",
]

# Standard numerical flow features used by ML detection and classification engines
NUMERICAL_FEATURES: List[str] = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean",
    "destination_port",
    "failed_logins_window",
    "port_entropy",
    "bytes_out_ratio",
]

# Categorical features for encoding
CATEGORICAL_FEATURES: List[str] = [
    "protocol",
    "event_type",
]

# Feature default values when missing in telemetry payloads
FEATURE_DEFAULTS: Dict[str, float] = {
    "flow_duration_ms": 100.0,
    "total_fwd_packets": 2.0,
    "total_bwd_packets": 2.0,
    "total_fwd_bytes": 128.0,
    "total_bwd_bytes": 128.0,
    "fwd_packet_length_mean": 64.0,
    "bwd_packet_length_mean": 64.0,
    "flow_bytes_per_sec": 256.0,
    "flow_packets_per_sec": 4.0,
    "flow_iat_mean": 50.0,
    "destination_port": 80.0,
    "failed_logins_window": 0.0,
    "port_entropy": 0.0,
    "bytes_out_ratio": 0.5,
}

