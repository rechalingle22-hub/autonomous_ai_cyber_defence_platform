# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Unit test suite for Phase 10 Multi-Agent AI SOC Investigation Engine."""

import os
import sys
import uuid
import pytest
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.investigation.agents.triage_agent import TriageAnalystAgent
from backend.app.investigation.agents.evidence_hunter import EvidenceHunterAgent
from backend.app.investigation.agents.forensic_agent import ForensicMitreAgent
from backend.app.investigation.agents.lead_investigator import LeadInvestigatorAgent
from backend.app.investigation.coordinator import InvestigationCoordinator


@pytest.mark.asyncio
async def test_triage_agent_critical_ransomware_incident():
    """Verifies Triage Agent assigns P1_CRITICAL and low false-positive probability for ransomware."""
    agent = TriageAnalystAgent()
    incident_ctx = {
        "id": "inc-rw-101",
        "title": "Suspected Ransomware File Encryption",
        "attack_category": "RANSOMWARE",
        "severity": "CRITICAL",
        "composite_risk_score": 92.0,
        "source_ip": "198.51.100.55",
        "alerts": [{"id": "alt-1"}, {"id": "alt-2"}],
    }

    res = await agent.analyze(incident_ctx)
    assert res["urgency"] == "P1_CRITICAL"
    assert res["false_positive_probability"] <= 0.10
    assert len(res["evidence"]) >= 1
    assert len(res["hypotheses"]) >= 1
    assert len(res["scratchpad"]) >= 2


@pytest.mark.asyncio
async def test_triage_agent_detects_likely_false_positive():
    """Verifies Triage Agent flags low-risk operational/maintenance traffic as potential false positive."""
    agent = TriageAnalystAgent()
    incident_ctx = {
        "id": "inc-fp-202",
        "title": "Nightly Database Backup Volume Spike",
        "attack_category": "BACKUP_MAINTENANCE",
        "severity": "LOW",
        "composite_risk_score": 25.0,
        "source_ip": "127.0.0.1",
        "alerts": [{"id": "alt-single"}],
    }

    res = await agent.analyze(incident_ctx)
    assert res["urgency"] == "P4_LOW"
    assert res["false_positive_probability"] >= 0.60
    assert "false positive" in res["hypotheses"][0]["claim"].lower()


@pytest.mark.asyncio
async def test_evidence_hunter_c2_threat_intelligence_enrichment():
    """Verifies Evidence Hunter queries Phase 8 CTI cache and confirms malicious C2 infrastructure."""
    agent = EvidenceHunterAgent()
    # 198.51.100.2 is seeded in Phase 8 as APT29 C2
    incident_ctx = {
        "id": "inc-apt-303",
        "source_ip": "198.51.100.2",
        "destination_ip": "10.0.0.50",
        "target_host": "srv-domain-controller",
        "user_id": "service_account",
    }

    res = await agent.analyze(incident_ctx)
    evidence = res["evidence"]
    hypotheses = res["hypotheses"]

    assert len(evidence) >= 1
    c2_ev = next((e for e in evidence if e["entity_value"] == "198.51.100.2"), None)
    assert c2_ev is not None
    assert c2_ev["source"] == "CTI"
    assert "APT29" in c2_ev["description"]

    c2_hyp = next((h for h in hypotheses if "198.51.100.2" in h["claim"]), None)
    assert c2_hyp is not None
    assert c2_ev["evidence_id"] in c2_hyp["supporting_evidence_ids"]
    assert c2_hyp["risk_level"] == "CRITICAL"


@pytest.mark.asyncio
async def test_forensic_agent_mitre_and_cve_correlation():
    """Verifies Forensic Specialist correlates vulnerable service ports with CVE signatures."""
    agent = ForensicMitreAgent()
    incident_ctx = {
        "id": "inc-log4j-404",
        "attack_stage": "INITIAL_ACCESS",
        "destination_port": 8080,
        "attack_category": "EXPLOITATION",
    }

    res = await agent.analyze(incident_ctx)
    evidence = res["evidence"]
    hypotheses = res["hypotheses"]

    # Check port CVE match (Log4Shell / Spring4Shell on port 8080)
    cve_ev = next((e for e in evidence if e["entity_type"] == "PORT_VULNERABILITY"), None)
    assert cve_ev is not None
    assert "CVE-2021-44228" in cve_ev["description"] or "CVE-2022-22965" in cve_ev["description"]

    # Check MITRE ATT&CK technique T1190
    mitre_ev = next((e for e in evidence if e["entity_type"] == "MITRE_TTP"), None)
    assert mitre_ev is not None
    assert mitre_ev["entity_value"] == "T1190"


@pytest.mark.asyncio
async def test_lead_investigator_anti_hallucination_guardrail():
    """Verifies Lead Investigator suppresses ungrounded hypotheses lacking evidence citations."""
    agent = LeadInvestigatorAgent()
    valid_ev_id = "ev-grounded-001"

    working_mem = {
        "evidence": [
            {
                "evidence_id": valid_ev_id,
                "source": "CTI",
                "entity_type": "IP",
                "entity_value": "198.51.100.77",
                "description": "Verified C2 beacon endpoint",
            }
        ],
        "hypotheses": [
            {
                "hypothesis_id": "hyp-valid",
                "claim": "Grounded claim linked to verified IP beacon.",
                "supporting_evidence_ids": [valid_ev_id],
                "confidence": 0.85,
                "risk_level": "HIGH",
            },
            {
                "hypothesis_id": "hyp-hallucinated",
                "claim": "Ungrounded hallucination: attacker stole payroll database via Bluetooth.",
                "supporting_evidence_ids": ["ev-non-existent-999"],  # Bogus citation
                "confidence": 0.99,
                "risk_level": "CRITICAL",
            },
        ],
        "false_positive_probability": 0.04,
        "urgency": "P1_CRITICAL",
    }

    incident_ctx = {
        "id": "inc-anti-hallucination-505",
        "title": "Suspected Lateral Breach",
        "attack_stage": "EXFILTRATION",
        "attack_category": "Data Exfiltration",
        "composite_risk_score": 88.0,
    }

    report = await agent.analyze(incident_ctx, working_mem)

    # Validate segregation
    grounded_hyps = report["inferred_hypotheses"]["items"]
    assert len(grounded_hyps) == 1
    assert grounded_hyps[0]["hypothesis_id"] == "hyp-valid"

    # Executive & technical analysis must be populated
    assert "EXECUTIVE SUMMARY" in report["executive_summary"]
    assert "Technical Forensic Dossier" in report["technical_analysis"]
    assert report["recommended_playbook"] == "PB-EXFILTRATION-01"


@pytest.mark.asyncio
async def test_investigation_coordinator_pipeline():
    """Tests the full multi-agent investigation execution flow through the coordinator."""
    coord = InvestigationCoordinator()
    incident_ctx = {
        "id": "inc-pipeline-606",
        "title": "Unauthorized SSH Brute Force Campaign",
        "attack_stage": "INITIAL_ACCESS",
        "attack_category": "BRUTE_FORCE",
        "composite_risk_score": 78.0,
        "source_ip": "198.51.100.2",
        "destination_port": 22,
        "target_host": "srv-ssh-gateway",
    }

    result = await coord.run_investigation(incident_ctx, analyst_id="analyst_alice")
    assert result["status"] == "COMPLETED"
    assert result["incident_id"] == "inc-pipeline-606"
    assert result["analyst_id"] == "analyst_alice"
    assert result["duration_seconds"] >= 0.0
    assert "items" in result["observed_evidence"]
    assert "items" in result["inferred_hypotheses"]
    assert "triage" in result["agent_scratchpad"]
    assert "evidence_hunter" in result["agent_scratchpad"]
    assert "forensic" in result["agent_scratchpad"]
    assert "lead_investigator" in result["agent_scratchpad"]
    assert result["recommended_playbook"] == "PB-CREDENTIAL-01"

    stats = coord.get_stats()
    assert stats["total_investigations"] >= 1
    assert stats["completed_count"] >= 1

