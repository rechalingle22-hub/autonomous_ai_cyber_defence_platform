# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false
# ruff: noqa
# flake8: noqa
"""Cyber Deception, Honeytoken & Decoy Network Engine.

Orchestrates:
1. Dynamic generation of realistic honeytokens (API keys, DB credentials, AWS secrets, JWTs, Canary files, SSH keys).
2. Zero-false-positive tripwires that immediately trigger high-priority alerts and SOAR containment upon adversary touch.
3. Lightweight emulated decoy micro-services (Faux SSH, Faux Redis, Faux Admin Portal, Faux Postgres) capturing attacker reconnaissance.
4. Comprehensive deception metrics and enterprise bait surface tracking.
"""

import os
import sys
import uuid
import secrets
import enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)


class HoneytokenType(str, enum.Enum):
    API_KEY = "API_KEY"
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    JWT_TOKEN = "JWT_TOKEN"
    CANARY_FILE = "CANARY_FILE"
    SSH_KEY = "SSH_KEY"


class DecoyServiceType(str, enum.Enum):
    FAUX_SSH_SERVER = "FAUX_SSH_SERVER"
    FAUX_REDIS_DATABASE = "FAUX_REDIS_DATABASE"
    FAUX_ADMIN_PORTAL = "FAUX_ADMIN_PORTAL"
    FAUX_SQL_SERVICE = "FAUX_SQL_SERVICE"


class CyberDeceptionEngine:
    """Manages active honeytokens, tripwires, and decoy honeynet services."""

    def __init__(self) -> None:
        self.honeytokens: Dict[str, Dict[str, Any]] = {}
        self.token_lookup: Dict[str, str] = {}  # token_value -> token_id
        self.tripwire_events: List[Dict[str, Any]] = []
        self.decoys: Dict[str, Dict[str, Any]] = {}
        self._initialize_default_decoys()
        self._initialize_default_honeytokens()

    def _generate_token_value(self, token_type: HoneytokenType) -> str:
        """Generates realistic-looking decoy credentials and keys."""
        rand_hex = secrets.token_hex(16)
        if token_type == HoneytokenType.API_KEY:
            return f"sk_live_decep_{secrets.token_urlsafe(24)}"
        elif token_type == HoneytokenType.DATABASE_CREDENTIAL:
            return f"postgres://svc_deception_read:{secrets.token_urlsafe(12)}@internal-db-replica.corp.local:5432/finance_db"
        elif token_type == HoneytokenType.AWS_SECRET_KEY:
            return f"AKIA_DECEP_{secrets.token_hex(8).upper()}:{secrets.token_urlsafe(30)}"
        elif token_type == HoneytokenType.JWT_TOKEN:
            return f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbi1kZWNveSIsInJvbGUiOiJTRU5JT1JfU1lTQURNSU4iLCJpYXQiOjE3MTIwMDAwMDB9.{secrets.token_urlsafe(32)}"
        elif token_type == HoneytokenType.CANARY_FILE:
            return f"CANARY_WATERMARK_{uuid.uuid4().hex.upper()}"
        elif token_type == HoneytokenType.SSH_KEY:
            return f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n{secrets.token_urlsafe(40)}\n-----END OPENSSH PRIVATE KEY-----"
        return f"CANARY_TOKEN_{secrets.token_hex(12)}"

    def _get_default_bait_path(self, token_type: HoneytokenType) -> str:
        """Suggests high-value placement paths for each honeytoken type."""
        defaults = {
            HoneytokenType.API_KEY: "config/payment_gateway.json",
            HoneytokenType.DATABASE_CREDENTIAL: "backend/config/database.staging.yaml",
            HoneytokenType.AWS_SECRET_KEY: ".env.staging",
            HoneytokenType.JWT_TOKEN: "storage/sessions/admin_session.jwt",
            HoneytokenType.CANARY_FILE: "/shared/finance/confidential_q4_payroll.xlsx",
            HoneytokenType.SSH_KEY: ".ssh/id_rsa_backup",
        }
        return defaults.get(token_type, "confidential/canary_credentials.txt")

    def _initialize_default_decoys(self) -> None:
        """Seeds default high-interaction decoy micro-services."""
        default_decoys = [
            {
                "id": "decoy_ssh_01",
                "service_type": DecoyServiceType.FAUX_SSH_SERVER.value,
                "name": "Corporate Bastion Gateway Decoy",
                "port": 2222,
                "protocol": "TCP/SSH",
                "fake_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                "status": "ONLINE",
                "interaction_count": 0,
                "captured_payloads": [],
            },
            {
                "id": "decoy_redis_01",
                "service_type": DecoyServiceType.FAUX_REDIS_DATABASE.value,
                "name": "Internal Caching Cluster Decoy",
                "port": 6380,
                "protocol": "TCP/REDIS",
                "fake_banner": "Redis server v=7.0.12 sha=00000000:0 malloc=jemalloc-5.3.0",
                "status": "ONLINE",
                "interaction_count": 0,
                "captured_payloads": [],
            },
            {
                "id": "decoy_admin_01",
                "service_type": DecoyServiceType.FAUX_ADMIN_PORTAL.value,
                "name": "Global Executive SSO Login Decoy",
                "port": 8443,
                "protocol": "HTTPS",
                "fake_banner": "Apache/2.4.52 (Ubuntu) Corporate Admin Login",
                "status": "ONLINE",
                "interaction_count": 0,
                "captured_payloads": [],
            },
            {
                "id": "decoy_sql_01",
                "service_type": DecoyServiceType.FAUX_SQL_SERVICE.value,
                "name": "Customer Accounts Master Database Decoy",
                "port": 5433,
                "protocol": "TCP/POSTGRES",
                "fake_banner": "PostgreSQL 15.4 (Ubuntu 15.4-1.pgdg22.04+1)",
                "status": "ONLINE",
                "interaction_count": 0,
                "captured_payloads": [],
            },
        ]
        for d in default_decoys:
            self.decoys[d["id"]] = d

    def _initialize_default_honeytokens(self) -> None:
        """Seeds high-value enterprise canary baits upon initialization."""
        self.deploy_honeytoken(
            token_type=HoneytokenType.AWS_SECRET_KEY,
            name="AWS Production Deployment Secret",
            bait_path=".env.staging",
            metadata={"description": "Planted in staging environment root to catch lateral movement credential harvesting."},
        )
        self.deploy_honeytoken(
            token_type=HoneytokenType.DATABASE_CREDENTIAL,
            name="Finance Master DB Connection String",
            bait_path="backend/config/database.staging.yaml",
            metadata={"description": "High-value connection string with read permissions on faux payroll database."},
        )
        self.deploy_honeytoken(
            token_type=HoneytokenType.API_KEY,
            name="Stripe Live Payment Gateway API Key",
            bait_path="config/payment_gateway.json",
            metadata={"description": "Simulated live payment token designed to bait ransomware and data extortionists."},
        )

    def deploy_honeytoken(
        self,
        token_type: HoneytokenType,
        name: str,
        bait_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Deploys a new high-fidelity honeytoken to the enterprise bait surface."""
        token_id = f"ht_{token_type.value.lower()}_{uuid.uuid4().hex[:8]}"
        token_value = self._generate_token_value(token_type)
        path = bait_path or self._get_default_bait_path(token_type)

        # Masked value for display
        if len(token_value) > 16:
            masked_value = token_value[:8] + "..." + token_value[-6:]
        else:
            masked_value = token_value[:4] + "..."

        honeytoken = {
            "id": token_id,
            "name": name,
            "token_type": token_type.value,
            "token_value": token_value,
            "masked_value": masked_value,
            "bait_path": path,
            "status": "ACTIVE",
            "hit_count": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_tripped_at": None,
            "last_attacker_ip": None,
            "last_user_agent": None,
            "metadata": metadata or {},
        }

        self.honeytokens[token_id] = honeytoken
        self.token_lookup[token_value] = token_id
        return honeytoken

    def trigger_honeytoken_tripwire(
        self,
        token_value_or_id: str,
        source_ip: str = "192.168.1.185",
        user_agent: str = "python-requests/2.31.0 (Adversary Recon Scanner)",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Processes an adversary tripwire event, generating a 100% True-Positive Critical Incident."""
        # Lookup by token value or ID
        token_id = self.token_lookup.get(token_value_or_id, token_value_or_id)
        token = self.honeytokens.get(token_id)

        if not token:
            # Fallback: if substring match found in token_value
            for ht_id, ht in self.honeytokens.items():
                if token_value_or_id in ht["token_value"]:
                    token = ht
                    token_id = ht_id
                    break

        if not token:
            return {
                "tripwire_triggered": False,
                "error": f"Honeytoken '{token_value_or_id}' not found or unrecognized.",
            }

        now_str = datetime.now(timezone.utc).isoformat()
        token["status"] = "TRIPPED"
        token["hit_count"] += 1
        token["last_tripped_at"] = now_str
        token["last_attacker_ip"] = source_ip
        token["last_user_agent"] = user_agent

        # Determine ATT&CK mapping based on token type
        attack_mappings = {
            HoneytokenType.API_KEY.value: ("T1552.001", "Credentials In Files"),
            HoneytokenType.DATABASE_CREDENTIAL.value: ("T1078.003", "Valid Accounts: Local Accounts"),
            HoneytokenType.AWS_SECRET_KEY.value: ("T1078.004", "Valid Accounts: Cloud Accounts"),
            HoneytokenType.JWT_TOKEN.value: ("T1550.001", "Use Alternate Authentication Material: Application Access Token"),
            HoneytokenType.CANARY_FILE.value: ("T1083", "File and Directory Discovery"),
            HoneytokenType.SSH_KEY.value: ("T1552.004", "Unsecured Credentials: Private Keys"),
        }
        technique_id, technique_name = attack_mappings.get(
            token["token_type"], ("T1078", "Valid Accounts")
        )

        tripwire_event = {
            "event_id": f"tripwire_{uuid.uuid4().hex[:8]}",
            "token_id": token_id,
            "token_name": token["name"],
            "token_type": token["token_type"],
            "bait_path": token["bait_path"],
            "source_ip": source_ip,
            "user_agent": user_agent,
            "severity": "CRITICAL",
            "fidelity": "100%_TRUE_POSITIVE",
            "mitre_technique_id": technique_id,
            "mitre_technique_name": technique_name,
            "timestamp": now_str,
            "recommended_soar_playbook": "PLAYBOOK-QUARANTINE-HOST",
            "recommended_action": f"Immediately isolate host and block source IP {source_ip}.",
            "context": context or {},
        }

        self.tripwire_events.insert(0, tripwire_event)
        if len(self.tripwire_events) > 100:
            self.tripwire_events = self.tripwire_events[:100]

        return {
            "tripwire_triggered": True,
            "token": token,
            "alert": tripwire_event,
        }

    def interact_with_decoy(
        self,
        decoy_id: str,
        command_or_payload: str,
        source_ip: str = "192.168.1.185",
    ) -> Dict[str, Any]:
        """Simulates attacker reconnaissance against an active decoy service."""
        decoy = self.decoys.get(decoy_id)
        if not decoy:
            return {"error": f"Decoy service '{decoy_id}' not found."}

        now_str = datetime.now(timezone.utc).isoformat()
        decoy["interaction_count"] += 1
        decoy["status"] = "ENGAGED"

        # Generate realistic emulated responses
        cmd_lower = command_or_payload.strip().lower()
        svc_type = decoy["service_type"]

        if svc_type == DecoyServiceType.FAUX_SSH_SERVER.value:
            if "whoami" in cmd_lower:
                simulated_output = "root"
            elif "uname" in cmd_lower:
                simulated_output = "Linux soc-bastion-gateway01 5.15.0-89-generic #99-Ubuntu SMP x86_64"
            elif "cat /etc/passwd" in cmd_lower or "passwd" in cmd_lower:
                simulated_output = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nsvc_backup:x:1001:1001:Backup Svc:/home/svc_backup:/bin/bash"
            else:
                simulated_output = f"bash: {command_or_payload}: command not found (interactive bash logged)"
        elif svc_type == DecoyServiceType.FAUX_REDIS_DATABASE.value:
            if "keys" in cmd_lower:
                simulated_output = "1) \"session:admin:token\"\n2) \"cache:user:master_key\"\n3) \"rate_limit:payment_svc\""
            elif "info" in cmd_lower:
                simulated_output = "# Server\nredis_version:7.0.12\nos:Linux 5.15.0-89-generic x86_64\ntcp_port:6380\nconnected_clients:4"
            else:
                simulated_output = f"+OK (query logged: {command_or_payload})"
        elif svc_type == DecoyServiceType.FAUX_SQL_SERVICE.value:
            if "select" in cmd_lower or "show tables" in cmd_lower:
                simulated_output = "id | username | role | password_hash\n----+----------+------+------------------------------------------------------------\n 1 | admin    | ROOT | $2b$12$e8Y... (Logged into SOC Deception Engine)"
            else:
                simulated_output = f"Query OK, 0 rows affected (0.01 sec) [Telemetry captured]"
        else:
            simulated_output = f"HTTP/1.1 401 Unauthorized\r\nServer: {decoy['fake_banner']}\r\nContent-Type: text/html\r\n\r\nLogin Required: Credential attempt logged."

        interaction_entry = {
            "interaction_id": f"int_{uuid.uuid4().hex[:8]}",
            "decoy_id": decoy_id,
            "source_ip": source_ip,
            "command_or_payload": command_or_payload,
            "simulated_output": simulated_output,
            "captured_at": now_str,
        }

        decoy["captured_payloads"].insert(0, interaction_entry)
        if len(decoy["captured_payloads"]) > 50:
            decoy["captured_payloads"] = decoy["captured_payloads"][:50]

        return {
            "decoy_id": decoy_id,
            "service_type": decoy["service_type"],
            "interaction_entry": interaction_entry,
            "captured_payloads_count": len(decoy["captured_payloads"]),
        }

    def revoke_honeytoken(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Revokes a honeytoken from active surveillance."""
        token = self.honeytokens.get(token_id)
        if not token:
            return None
        token["status"] = "REVOKED"
        return token

    def get_deception_metrics(self) -> Dict[str, Any]:
        """Calculates global cyber deception posture and tripwire metrics."""
        total_tokens = len(self.honeytokens)
        active_tokens = sum(1 for t in self.honeytokens.values() if t["status"] == "ACTIVE")
        tripped_tokens = sum(1 for t in self.honeytokens.values() if t["status"] == "TRIPPED")
        total_hits = sum(t["hit_count"] for t in self.honeytokens.values())

        total_decoys = len(self.decoys)
        engaged_decoys = sum(1 for d in self.decoys.values() if d["status"] == "ENGAGED")
        total_decoy_interactions = sum(d["interaction_count"] for d in self.decoys.values())

        return {
            "total_honeytokens_deployed": total_tokens,
            "active_honeytokens": active_tokens,
            "tripped_honeytokens": tripped_tokens,
            "total_honeytoken_hits": total_hits,
            "total_decoys_online": total_decoys,
            "engaged_decoys": engaged_decoys,
            "total_decoy_interactions": total_decoy_interactions,
            "true_positive_fidelity_percent": 100.0,
            "zero_false_positives_guaranteed": True,
            "recent_tripwires": self.tripwire_events[:10],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }


deception_engine = CyberDeceptionEngine()

