"""Isolated Cyber Range Synthetic Telemetry Generator.

Generates realistic, completely safe, defensive training & evaluation telemetry.
Does NOT execute any real offensive code or network transmissions.
Strictly outputs simulated CommonEventSchema-compliant dictionary records.
"""

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from backend.app.models.event import EventType, EventSeverity
from ml.features.definitions import FEATURE_DEFAULTS


class CyberRangeSyntheticGenerator:
    """Generates synthetic network and security telemetry for training, testing, and SOC demos."""

    def __init__(self, seed: Optional[int] = 42) -> None:
        if seed is not None:
            random.seed(seed)

    def generate_benign_traffic(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generates typical benign enterprise traffic (web, email, DNS, internal RPC)."""
        events = []
        base_time = datetime.now(timezone.utc) - timedelta(minutes=count)

        internal_subnets = ["10.0.1.", "10.0.2.", "192.168.1."]
        common_destinations = [
            ("8.8.8.8", 53, "UDP", EventType.DNS),
            ("1.1.1.1", 53, "UDP", EventType.DNS),
            ("142.250.190.46", 443, "TCP", EventType.NETFLOW),
            ("151.101.1.140", 443, "TCP", EventType.NETFLOW),
            ("10.0.0.5", 88, "TCP", EventType.AUTH),
            ("10.0.0.10", 445, "TCP", EventType.NETFLOW),
        ]

        for i in range(count):
            src_ip = f"{random.choice(internal_subnets)}{random.randint(10, 200)}"
            dst_ip, dst_port, proto, ev_type = random.choice(common_destinations)
            src_port = random.randint(32768, 61000)
            ts = base_time + timedelta(seconds=i * 2 + random.uniform(0.1, 1.5))

            fwd_pkts = random.randint(4, 25)
            bwd_pkts = random.randint(4, 30)
            fwd_bytes = fwd_pkts * random.randint(64, 400)
            bwd_bytes = bwd_pkts * random.randint(128, 1400)
            duration = random.uniform(50.0, 1500.0)

            features = {
                **FEATURE_DEFAULTS,
                "flow_duration_ms": duration,
                "total_fwd_packets": float(fwd_pkts),
                "total_bwd_packets": float(bwd_pkts),
                "total_fwd_bytes": float(fwd_bytes),
                "total_bwd_bytes": float(bwd_bytes),
                "fwd_packet_length_mean": float(fwd_bytes / max(1, fwd_pkts)),
                "bwd_packet_length_mean": float(bwd_bytes / max(1, bwd_pkts)),
                "flow_bytes_per_sec": float((fwd_bytes + bwd_bytes) / (duration / 1000.0)),
                "flow_packets_per_sec": float((fwd_pkts + bwd_pkts) / (duration / 1000.0)),
                "flow_iat_mean": duration / max(1, (fwd_pkts + bwd_pkts)),
                "destination_port": float(dst_port),
                "failed_logins_window": 0.0,
                "port_entropy": random.uniform(0.1, 0.4),
                "bytes_out_ratio": float(fwd_bytes / max(1, fwd_bytes + bwd_bytes)),
            }

            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": proto,
                "user_id": f"user_{random.randint(1, 20)}",
                "device_id": f"workstation_{src_ip.split('.')[-1]}",
                "event_type": ev_type.value,
                "severity": EventSeverity.INFO.value,
                "features": features,
                "metadata": {"synthetic_scenario": "BENIGN", "ground_truth": "BENIGN"},
                "label": "BENIGN",
            })
        return events

    def generate_scenario_1_suspicious_auth(self, count: int = 30) -> List[Dict[str, Any]]:
        """Scenario 1: Suspicious authentication pattern (Brute-force / Credential Stuffing)."""
        events = []
        attacker_ip = "192.168.1.150"
        target_server = "10.0.0.12"
        base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        usernames = ["admin", "root", "oracle", "deploy", "guest", "secops", "service_acc"]

        for i in range(count):
            ts = base_time + timedelta(seconds=i * 4 + random.uniform(0.05, 0.5))
            is_success = (i == count - 1)  # Only last login succeeds after repeated failures
            user = usernames[i % len(usernames)]

            features = {
                **FEATURE_DEFAULTS,
                "flow_duration_ms": random.uniform(80.0, 250.0),
                "total_fwd_packets": 6.0,
                "total_bwd_packets": 4.0,
                "total_fwd_bytes": 480.0,
                "total_bwd_bytes": 320.0,
                "destination_port": 22.0,  # SSH Port
                "failed_logins_window": float(min(i + 1, count)),
                "port_entropy": 0.05,
                "bytes_out_ratio": 0.6,
            }

            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": attacker_ip,
                "destination_ip": target_server,
                "source_port": 50000 + i,
                "destination_port": 22,
                "protocol": "TCP",
                "user_id": user,
                "device_id": "endpoint-150",
                "event_type": EventType.AUTH.value,
                "severity": EventSeverity.HIGH.value if is_success else EventSeverity.MEDIUM.value,
                "features": features,
                "metadata": {
                    "synthetic_scenario": "SCENARIO_1_BRUTE_FORCE",
                    "auth_status": "SUCCESS" if is_success else "FAILED",
                    "auth_service": "SSH",
                    "ground_truth": "BRUTE_FORCE",
                },
                "label": "BRUTE_FORCE",
            })
        return events

    def generate_scenario_2_port_scan(self, count: int = 50) -> List[Dict[str, Any]]:
        """Scenario 2: Port-scan-like synthetic traffic (Reconnaissance sweep)."""
        events = []
        scanner_ip = "192.168.1.188"
        target_ip = "10.0.0.50"
        base_time = datetime.now(timezone.utc) - timedelta(minutes=3)
        ports_to_sweep = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9092
        ]

        for i in range(count):
            port = ports_to_sweep[i % len(ports_to_sweep)]
            ts = base_time + timedelta(milliseconds=i * 80 + random.randint(5, 30))

            features = {
                **FEATURE_DEFAULTS,
                "flow_duration_ms": random.uniform(1.0, 15.0),
                "total_fwd_packets": 2.0,  # SYN only
                "total_bwd_packets": 1.0 if port in [80, 443, 22] else 0.0,
                "total_fwd_bytes": 120.0,
                "total_bwd_bytes": 60.0 if port in [80, 443, 22] else 0.0,
                "destination_port": float(port),
                "port_entropy": 0.96,  # Very high entropy across destination ports
                "flow_packets_per_sec": 850.0,
                "bytes_out_ratio": 0.95,
            }

            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": scanner_ip,
                "destination_ip": target_ip,
                "source_port": 40000 + i,
                "destination_port": port,
                "protocol": "TCP",
                "user_id": None,
                "device_id": "endpoint-188",
                "event_type": EventType.NETFLOW.value,
                "severity": EventSeverity.MEDIUM.value,
                "features": features,
                "metadata": {
                    "synthetic_scenario": "SCENARIO_2_PORT_SCAN",
                    "tcp_flags": "SYN",
                    "scan_type": "SYN_STEALTH_PROBE",
                    "ground_truth": "PORT_SCAN",
                },
                "label": "PORT_SCAN",
            })
        return events

    def generate_scenario_3_data_exfiltration(self, count: int = 25) -> List[Dict[str, Any]]:
        """Scenario 3: Abnormal data-transfer pattern (Data Exfiltration)."""
        events = []
        insider_ip = "10.0.1.75"
        external_c2 = "198.51.100.42"
        base_time = datetime.now(timezone.utc) - timedelta(minutes=4)

        for i in range(count):
            ts = base_time + timedelta(seconds=i * 8)
            fwd_bytes = random.randint(1_500_000, 8_000_000)  # Multi-megabyte chunks
            bwd_bytes = random.randint(500, 4_000)

            features = {
                **FEATURE_DEFAULTS,
                "flow_duration_ms": random.uniform(5000.0, 15000.0),
                "total_fwd_packets": 4500.0,
                "total_bwd_packets": 80.0,
                "total_fwd_bytes": float(fwd_bytes),
                "total_bwd_bytes": float(bwd_bytes),
                "flow_bytes_per_sec": float(fwd_bytes / 10.0),
                "destination_port": 443.0,
                "port_entropy": 0.05,
                "bytes_out_ratio": 0.998,  # Extreme outbound data skew
            }

            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": insider_ip,
                "destination_ip": external_c2,
                "source_port": 54100 + i,
                "destination_port": 443,
                "protocol": "TCP",
                "user_id": "developer_lead",
                "device_id": "macbook-pro-75",
                "event_type": EventType.NETFLOW.value,
                "severity": EventSeverity.HIGH.value,
                "features": features,
                "metadata": {
                    "synthetic_scenario": "SCENARIO_3_DATA_EXFILTRATION",
                    "direction": "EGRESS_OUTBOUND",
                    "channel": "ENCRYPTED_TLS",
                    "ground_truth": "DATA_EXFILTRATION",
                },
                "label": "DATA_EXFILTRATION",
            })
        return events

    def generate_scenario_4_compromised_account(self, count: int = 15) -> List[Dict[str, Any]]:
        """Scenario 4: Compromised-account behavior simulation (UEBA impossible travel / anomalous access)."""
        events = []
        user = "finance_analyst"
        base_time = datetime.now(timezone.utc) - timedelta(minutes=10)

        # 1. Normal morning login from office IP
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": (base_time).isoformat(),
            "source_ip": "10.0.1.30",
            "destination_ip": "10.0.0.10",
            "source_port": 49200,
            "destination_port": 443,
            "protocol": "TCP",
            "user_id": user,
            "device_id": "office-pc-30",
            "event_type": EventType.AUTH.value,
            "severity": EventSeverity.INFO.value,
            "features": {**FEATURE_DEFAULTS, "failed_logins_window": 0.0},
            "metadata": {"location": "New York, USA", "synthetic_scenario": "SCENARIO_4_COMPROMISED_ACCOUNT"},
            "label": "BENIGN",
        })

        # 2. 5 minutes later, login from foreign public IP (Impossible Travel)
        impossible_ip = "203.0.113.88"
        for i in range(1, count):
            ts = base_time + timedelta(minutes=5, seconds=i * 10)
            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": impossible_ip,
                "destination_ip": "10.0.0.25",  # Sensitive Database
                "source_port": 55000 + i,
                "destination_port": 5432,  # PostgreSQL Port
                "protocol": "TCP",
                "user_id": user,
                "device_id": "unknown-foreign-client",
                "event_type": EventType.AUTH.value,
                "severity": EventSeverity.HIGH.value,
                "features": {
                    **FEATURE_DEFAULTS,
                    "failed_logins_window": 0.0,
                    "destination_port": 5432.0,
                    "port_entropy": 0.1,
                },
                "metadata": {
                    "synthetic_scenario": "SCENARIO_4_COMPROMISED_ACCOUNT",
                    "location": "Bucharest, Romania",
                    "anomaly_type": "IMPOSSIBLE_TRAVEL_VELOCITY",
                    "ground_truth": "SUSPICIOUS_AUTH",
                },
                "label": "SUSPICIOUS_AUTH",
            })
        return events

    def generate_scenario_5_multistage_campaign(self) -> List[Dict[str, Any]]:
        """Scenario 5: Multi-stage APT attack campaign (Recon -> Access -> Lateral Movement -> Exfiltration)."""
        campaign_events = []
        base_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        attacker_ip = "198.51.100.99"
        dmz_server = "10.0.0.15"
        internal_core = "10.0.0.80"

        # Stage 1: Port Scan (Reconnaissance)
        for i, port in enumerate([22, 80, 443, 8080]):
            ts = base_time + timedelta(minutes=0, seconds=i * 15)
            campaign_events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": attacker_ip,
                "destination_ip": dmz_server,
                "source_port": 41000 + i,
                "destination_port": port,
                "protocol": "TCP",
                "user_id": None,
                "device_id": None,
                "event_type": EventType.NETFLOW.value,
                "severity": EventSeverity.LOW.value,
                "features": {**FEATURE_DEFAULTS, "destination_port": float(port), "port_entropy": 0.85},
                "metadata": {
                    "campaign_stage": "RECONNAISSANCE",
                    "mitre_technique": "T1046",
                    "ground_truth": "PORT_SCAN",
                },
                "label": "PORT_SCAN",
            })

        # Stage 2: Web Attack / Exploitation (Initial Access)
        for i in range(5):
            ts = base_time + timedelta(minutes=5, seconds=i * 20)
            campaign_events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": attacker_ip,
                "destination_ip": dmz_server,
                "source_port": 42000 + i,
                "destination_port": 8080,
                "protocol": "TCP",
                "user_id": "webapp",
                "device_id": "dmz-proxy-15",
                "event_type": EventType.APPLICATION.value,
                "severity": EventSeverity.HIGH.value,
                "features": {**FEATURE_DEFAULTS, "destination_port": 8080.0, "total_fwd_bytes": 1240.0},
                "metadata": {
                    "campaign_stage": "INITIAL_ACCESS",
                    "mitre_technique": "T1190",
                    "payload_indicator": "UNION SELECT username, password_hash FROM users--",
                    "ground_truth": "WEB_ATTACK",
                },
                "label": "WEB_ATTACK",
            })

        # Stage 3: Lateral Movement via SMB (Privilege Escalation & Lateral Movement)
        for i in range(8):
            ts = base_time + timedelta(minutes=12, seconds=i * 30)
            campaign_events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": dmz_server,
                "destination_ip": internal_core,
                "source_port": 45000 + i,
                "destination_port": 445,
                "protocol": "TCP",
                "user_id": "svc_admin",
                "device_id": "core-db-80",
                "event_type": EventType.NETFLOW.value,
                "severity": EventSeverity.HIGH.value,
                "features": {**FEATURE_DEFAULTS, "destination_port": 445.0, "failed_logins_window": 1.0},
                "metadata": {
                    "campaign_stage": "LATERAL_MOVEMENT",
                    "mitre_technique": "T1021.002",
                    "ground_truth": "SUSPICIOUS_AUTH",
                },
                "label": "SUSPICIOUS_AUTH",
            })

        # Stage 4: Data Exfiltration (Collection & Exfiltration)
        for i in range(6):
            ts = base_time + timedelta(minutes=20, seconds=i * 45)
            fwd_bytes = 4_500_000
            campaign_events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "source_ip": dmz_server,
                "destination_ip": attacker_ip,
                "source_port": 48000 + i,
                "destination_port": 443,
                "protocol": "TCP",
                "user_id": "svc_admin",
                "device_id": "dmz-proxy-15",
                "event_type": EventType.NETFLOW.value,
                "severity": EventSeverity.CRITICAL.value,
                "features": {
                    **FEATURE_DEFAULTS,
                    "flow_duration_ms": 12000.0,
                    "total_fwd_bytes": float(fwd_bytes),
                    "bytes_out_ratio": 0.995,
                },
                "metadata": {
                    "campaign_stage": "EXFILTRATION",
                    "mitre_technique": "T1048",
                    "ground_truth": "DATA_EXFILTRATION",
                },
                "label": "DATA_EXFILTRATION",
            })

        return campaign_events


synthetic_generator = CyberRangeSyntheticGenerator()

