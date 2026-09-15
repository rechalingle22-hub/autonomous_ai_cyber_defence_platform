# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Cyber Range synthetic simulation API router.

Allows SOC analysts to trigger safe, isolated attack scenario telemetry into the platform.
"""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path:
        sys.path.insert(0, p)

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.database.session import get_db
from backend.app.models.event import SecurityEvent, EventType, EventSeverity
from backend.app.api.websockets.manager import ws_manager
from backend.app.audit.service import audit_service
from ml.datasets.synthetic_generator import synthetic_generator

router = APIRouter(prefix="/simulations", tags=["Cyber Range Simulation"])


class SimulationRunRequest(BaseModel):
    scenario_id: str = Field(
        ...,
        description="Scenario identifier: SCENARIO_1, SCENARIO_2, SCENARIO_3, SCENARIO_4, SCENARIO_5, or BENIGN",
    )
    event_count: int = Field(default=20, ge=1, le=200, description="Number of synthetic events to generate")


SCENARIO_CATALOG: Dict[str, Dict[str, Any]] = {
    "BENIGN": {
        "name": "Normal Enterprise Telemetry",
        "description": "Baseline business operations: web traffic, internal DNS, and routine authentication.",
        "attack_type": "BENIGN",
        "mitre_technique": None,
        "severity": "INFO",
    },
    "SCENARIO_1": {
        "name": "Scenario 1: Suspicious Authentication Pattern",
        "description": "Brute-force password guessing against SSH service followed by successful access.",
        "attack_type": "BRUTE_FORCE",
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
    },
    "SCENARIO_2": {
        "name": "Scenario 2: Port-Scan Traffic",
        "description": "High-entropy SYN sweep probing common enterprise service ports.",
        "attack_type": "PORT_SCAN",
        "mitre_technique": "T1046",
        "severity": "MEDIUM",
    },
    "SCENARIO_3": {
        "name": "Scenario 3: Abnormal Data-Transfer Pattern",
        "description": "Sustained high-volume outbound data flow to an external destination.",
        "attack_type": "DATA_EXFILTRATION",
        "mitre_technique": "T1048",
        "severity": "HIGH",
    },
    "SCENARIO_4": {
        "name": "Scenario 4: Compromised-Account Behavior",
        "description": "Impossible-travel authentication followed by anomalous database access.",
        "attack_type": "SUSPICIOUS_AUTH",
        "mitre_technique": "T1078",
        "severity": "HIGH",
    },
    "SCENARIO_5": {
        "name": "Scenario 5: Multi-Stage APT Campaign",
        "description": "Chained attack: Reconnaissance sweep -> SQLi web exploitation -> SMB lateral movement -> Exfiltration.",
        "attack_type": "MULTI_STAGE_CAMPAIGN",
        "mitre_technique": "T1046, T1190, T1021.002, T1048",
        "severity": "CRITICAL",
    },
}


@router.get("/scenarios")
async def list_scenarios() -> List[Dict[str, Any]]:
    """Returns available safe cyber range simulation scenarios."""
    return [
        {"scenario_id": k, **v}
        for k, v in SCENARIO_CATALOG.items()
    ]


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
async def run_simulation(
    req: SimulationRunRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Triggers generation of synthetic cyber telemetry and ingests it into the platform pipeline."""
    scenario_key = req.scenario_id.upper()
    if scenario_key not in SCENARIO_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario ID: {req.scenario_id}. Supported: {list(SCENARIO_CATALOG.keys())}",
        )

    # Generate synthetic event records
    if scenario_key == "BENIGN":
        raw_events = synthetic_generator.generate_benign_traffic(req.event_count)
    elif scenario_key == "SCENARIO_1":
        raw_events = synthetic_generator.generate_scenario_1_suspicious_auth(req.event_count)
    elif scenario_key == "SCENARIO_2":
        raw_events = synthetic_generator.generate_scenario_2_port_scan(req.event_count)
    elif scenario_key == "SCENARIO_3":
        raw_events = synthetic_generator.generate_scenario_3_data_exfiltration(req.event_count)
    elif scenario_key == "SCENARIO_4":
        raw_events = synthetic_generator.generate_scenario_4_compromised_account(req.event_count)
    elif scenario_key == "SCENARIO_5":
        raw_events = synthetic_generator.generate_scenario_5_multistage_campaign()
    else:
        raw_events = []

    ingested_records: List[SecurityEvent] = []
    for ev in raw_events:
        db_event = SecurityEvent(
            id=ev["event_id"],
            timestamp=datetime_from_iso(ev["timestamp"]),
            event_type=EventType(ev["event_type"]),
            severity=EventSeverity(ev["severity"]),
            source_ip=ev["source_ip"],
            destination_ip=ev["destination_ip"],
            source_port=ev["source_port"],
            destination_port=ev["destination_port"],
            protocol=ev["protocol"],
            user_id=ev.get("user_id"),
            device_id=ev.get("device_id"),
            raw_payload=ev.get("metadata", {}),
            normalized_features=ev.get("features", {}),
        )
        db.add(db_event)
        ingested_records.append(db_event)

    await db.commit()

    # Broadcast simulation notice to connected SOC clients
    await ws_manager.broadcast({
        "type": "SIMULATION_TRIGGERED",
        "data": {
            "scenario_id": scenario_key,
            "scenario_name": SCENARIO_CATALOG[scenario_key]["name"],
            "events_generated": len(ingested_records),
        }
    })

    # Record to SOC audit log
    await audit_service.log_event(
        db=db,
        action="SIMULATION_TRIGGERED",
        resource_type="CYBER_RANGE",
        resource_id=scenario_key,
        details={"scenario": scenario_key, "events_count": len(ingested_records)},
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "SIMULATION_EXECUTED",
        "scenario_id": scenario_key,
        "scenario_name": SCENARIO_CATALOG[scenario_key]["name"],
        "events_ingested": len(ingested_records),
        "sample_event_ids": [e.id for e in ingested_records[:5]],
    }


def datetime_from_iso(iso_str: str):
    """Parses ISO timestamp string safely into datetime."""
    from datetime import datetime
    return datetime.fromisoformat(iso_str)

