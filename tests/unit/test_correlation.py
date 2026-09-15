# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit tests for Alert Correlation, MITRE ATT&CK Mapping, and Incident Engine."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import pytest  # type: ignore
from datetime import datetime, timezone, timedelta  # type: ignore

try:
    from backend.app.correlation.rules import CorrelationRules, STAGE_WEIGHTS  # type: ignore
    from backend.app.correlation.engine import AlertCorrelationEngine  # type: ignore
    from backend.app.models.incident import AttackStage  # type: ignore
    from backend.app.models.alert import AlertSeverity  # type: ignore
except (ImportError, ValueError):
    from app.correlation.rules import CorrelationRules, STAGE_WEIGHTS  # type: ignore
    from app.correlation.engine import AlertCorrelationEngine  # type: ignore
    from app.models.incident import AttackStage  # type: ignore
    from app.models.alert import AlertSeverity  # type: ignore



class TestCorrelationRules:
    """Tests for MITRE ATT&CK mapping, entity matching heuristics, and risk calculation."""

    def test_map_attack_stage_reconnaissance(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("PORT_SCAN")
        assert stage == AttackStage.RECONNAISSANCE
        assert tech == "T1046"
        assert tactic == "Reconnaissance"

    def test_map_attack_stage_initial_access(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("SSH_BRUTE_FORCE")
        assert stage == AttackStage.INITIAL_ACCESS
        assert tech == "T1110.001"
        assert tactic == "Credential Access"

    def test_map_attack_stage_execution(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("COMMAND_INJECTION")
        assert stage == AttackStage.EXECUTION
        assert tech == "T1059"

    def test_map_attack_stage_lateral_movement(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("PASS_THE_HASH")
        assert stage == AttackStage.LATERAL_MOVEMENT
        assert tech == "T1550.002"

    def test_map_attack_stage_exfiltration(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("DNS_TUNNELING")
        assert stage == AttackStage.EXFILTRATION
        assert tech == "T1071.004"

    def test_map_attack_stage_impact(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("RANSOMWARE")
        assert stage == AttackStage.IMPACT
        assert tech == "T1486"

    def test_map_attack_stage_fallback(self):
        stage, tech, tactic = CorrelationRules.map_attack_stage("UNKNOWN_WEIRD_ALERT")
        assert stage == AttackStage.INITIAL_ACCESS
        assert tech == "T1190"

        stage_none, _, _ = CorrelationRules.map_attack_stage(None)
        assert stage_none == AttackStage.INITIAL_ACCESS

    def test_evaluate_highest_stage(self):
        stages = [AttackStage.RECONNAISSANCE, AttackStage.INITIAL_ACCESS, AttackStage.LATERAL_MOVEMENT]
        highest = CorrelationRules.evaluate_highest_stage(stages)
        assert highest == AttackStage.LATERAL_MOVEMENT

    def test_calculate_composite_risk_score_monotonicity(self):
        # Recon stage risk vs Impact stage risk
        recon_score = CorrelationRules.calculate_composite_risk_score(
            confidences=[0.8],
            anomaly_scores=[0.7],
            highest_stage=AttackStage.RECONNAISSANCE,
        )
        impact_score = CorrelationRules.calculate_composite_risk_score(
            confidences=[0.8],
            anomaly_scores=[0.7],
            highest_stage=AttackStage.IMPACT,
        )
        assert 0.0 <= recon_score <= 100.0
        assert 0.0 <= impact_score <= 100.0
        assert impact_score > recon_score

    def test_determine_severity_thresholds(self):
        assert CorrelationRules.determine_severity(85.0) == AlertSeverity.CRITICAL
        assert CorrelationRules.determine_severity(65.0) == AlertSeverity.HIGH
        assert CorrelationRules.determine_severity(45.0) == AlertSeverity.MEDIUM
        assert CorrelationRules.determine_severity(20.0) == AlertSeverity.LOW

    def test_match_entities_shared_source(self):
        alert_entities = {"source_ip": "192.168.1.100", "destination_ip": "10.0.0.5"}
        inc_entities = {
            "source_ips": {"192.168.1.100"},
            "destination_ips": {"10.0.0.2"},
            "user_ids": set(),
            "asset_ids": set(),
        }
        matched, reason = CorrelationRules.match_entities(alert_entities, inc_entities)
        assert matched is True
        assert reason == "shared_source_ip"

    def test_match_entities_lateral_pivot(self):
        # Attacker pivot: alert source was previous target destination
        alert_entities = {"source_ip": "10.0.0.5", "destination_ip": "10.0.0.9"}
        inc_entities = {
            "source_ips": {"192.168.1.50"},
            "destination_ips": {"10.0.0.5"},
            "user_ids": set(),
            "asset_ids": set(),
        }
        matched, reason = CorrelationRules.match_entities(alert_entities, inc_entities)
        assert matched is True
        assert reason == "lateral_movement_pivot_from_target"

    def test_match_entities_shared_user(self):
        alert_entities = {"source_ip": "172.16.0.4", "user_id": "admin_svc"}
        inc_entities = {
            "source_ips": {"10.10.10.10"},
            "destination_ips": set(),
            "user_ids": {"admin_svc"},
            "asset_ids": set(),
        }
        matched, reason = CorrelationRules.match_entities(alert_entities, inc_entities)
        assert matched is True
        assert reason == "shared_compromised_user"

    def test_match_entities_no_match(self):
        alert_entities = {"source_ip": "192.168.1.1", "destination_ip": "10.0.0.1"}
        inc_entities = {
            "source_ips": {"172.16.5.5"},
            "destination_ips": {"10.0.0.2"},
            "user_ids": set(),
            "asset_ids": set(),
        }
        matched, reason = CorrelationRules.match_entities(alert_entities, inc_entities)
        assert matched is False
        assert reason is None


class TestAlertCorrelationEngine:
    """Tests for sliding-window temporal grouping and incremental clustering."""

    @pytest.fixture
    def engine(self):
        return AlertCorrelationEngine(window_seconds=900)

    @pytest.mark.asyncio
    async def test_correlate_single_alert_creates_incident(self, engine):
        now = datetime.now(timezone.utc)
        alert = {
            "alert_id": "ALT-001",
            "title": "Port Scan Detected",
            "attack_type": "PORT_SCAN",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "confidence": 0.85,
            "anomaly_score": 0.75,
            "timestamp": now.isoformat(),
        }
        res = await engine.correlate_alert(alert, db_session=None)
        assert res["action"] == "CREATED_NEW_INCIDENT"
        assert res["attack_stage"] == AttackStage.RECONNAISSANCE.value
        assert res["correlated_alert_count"] == 1
        assert "incident_id" in res

    @pytest.mark.asyncio
    async def test_correlate_subsequent_alert_clusters_into_existing(self, engine):
        now = datetime.now(timezone.utc)
        # Alert 1: Reconnaissance
        alert1 = {
            "alert_id": "ALT-001",
            "title": "Port Scan Detected",
            "attack_type": "PORT_SCAN",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "confidence": 0.85,
            "anomaly_score": 0.75,
            "timestamp": now.isoformat(),
        }
        res1 = await engine.correlate_alert(alert1, db_session=None)
        inc_id = res1["incident_id"]

        # Alert 2: 3 minutes later from same source IP doing SSH Brute Force
        alert2 = {
            "alert_id": "ALT-002",
            "title": "SSH Brute Force",
            "attack_type": "SSH_BRUTE_FORCE",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "confidence": 0.95,
            "anomaly_score": 0.90,
            "timestamp": (now + timedelta(minutes=3)).isoformat(),
        }
        res2 = await engine.correlate_alert(alert2, db_session=None)
        assert res2["action"] == "CORRELATED_INTO_EXISTING"
        assert res2["incident_id"] == inc_id
        assert res2["correlated_alert_count"] == 2
        # Stage escalated from RECONNAISSANCE to INITIAL_ACCESS
        assert res2["attack_stage"] == AttackStage.INITIAL_ACCESS.value

    @pytest.mark.asyncio
    async def test_sliding_window_expiration(self, engine):
        base_time = datetime(2026, 9, 13, 0, 0, 0, tzinfo=timezone.utc)
        alert1 = {
            "alert_id": "ALT-001",
            "title": "Scan",
            "attack_type": "PORT_SCAN",
            "source_ip": "192.168.1.100",
            "timestamp": base_time.isoformat(),
        }
        res1 = await engine.correlate_alert(alert1, db_session=None)
        inc1_id = res1["incident_id"]

        # Alert 2 arrives 20 minutes later (outside 15-minute window)
        alert2 = {
            "alert_id": "ALT-002",
            "title": "Another Scan",
            "attack_type": "PORT_SCAN",
            "source_ip": "192.168.1.100",
            "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
        }
        res2 = await engine.correlate_alert(alert2, db_session=None)
        # Should create a new incident because previous candidate timed out
        assert res2["action"] == "CREATED_NEW_INCIDENT"
        assert res2["incident_id"] != inc1_id

    @pytest.mark.asyncio
    async def test_batch_correlation(self, engine):
        now = datetime.now(timezone.utc)
        alerts = [
            {
                "alert_id": "B-1",
                "attack_type": "PORT_SCAN",
                "source_ip": "10.1.1.50",
                "destination_ip": "10.1.1.10",
                "timestamp": now.isoformat(),
            },
            {
                "alert_id": "B-2",
                "attack_type": "EXPLOIT",
                "source_ip": "10.1.1.50",
                "destination_ip": "10.1.1.10",
                "timestamp": (now + timedelta(seconds=60)).isoformat(),
            },
            {
                "alert_id": "B-3",
                "attack_type": "DATA_EXFIL",
                "source_ip": "10.1.1.10",  # Pivot exfiltration from compromised host
                "destination_ip": "203.0.113.88",
                "timestamp": (now + timedelta(seconds=120)).isoformat(),
            },
        ]
        results = await engine.correlate_batch(alerts, db_session=None)
        assert len(results) == 3
        assert results[0]["action"] == "CREATED_NEW_INCIDENT"
        assert results[1]["action"] == "CORRELATED_INTO_EXISTING"
        assert results[2]["action"] == "CORRELATED_INTO_EXISTING"
        # Final attack stage reached EXFILTRATION
        assert results[2]["attack_stage"] == AttackStage.EXFILTRATION.value
        assert results[2]["correlated_alert_count"] == 3

