# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Action handlers package and global registry."""

from typing import Dict
from backend.app.models.response import ActionType
from backend.app.response.actions.base import BaseActionHandler
from backend.app.response.actions.firewall import BlockIPActionHandler
from backend.app.response.actions.host_isolation import IsolateHostActionHandler
from backend.app.response.actions.identity import (
    RevokeSessionActionHandler,
    ThrottleBandwidthActionHandler,
    IncreaseMonitoringActionHandler,
    SimulateRecoveryActionHandler,
)

block_ip_handler = BlockIPActionHandler()
isolate_host_handler = IsolateHostActionHandler()
revoke_session_handler = RevokeSessionActionHandler()
throttle_bandwidth_handler = ThrottleBandwidthActionHandler()
increase_monitoring_handler = IncreaseMonitoringActionHandler()
simulate_recovery_handler = SimulateRecoveryActionHandler()

ACTION_REGISTRY: Dict[ActionType, BaseActionHandler] = {
    ActionType.BLOCK_IP: block_ip_handler,
    ActionType.ISOLATE_HOST: isolate_host_handler,
    ActionType.REVOKE_SESSION: revoke_session_handler,
    ActionType.THROTTLE_BANDWIDTH: throttle_bandwidth_handler,
    ActionType.INCREASE_MONITORING: increase_monitoring_handler,
    ActionType.SIMULATE_RECOVERY: simulate_recovery_handler,
}

__all__ = [
    "BaseActionHandler",
    "BlockIPActionHandler",
    "IsolateHostActionHandler",
    "RevokeSessionActionHandler",
    "ThrottleBandwidthActionHandler",
    "IncreaseMonitoringActionHandler",
    "SimulateRecoveryActionHandler",
    "ACTION_REGISTRY",
    "block_ip_handler",
    "isolate_host_handler",
    "revoke_session_handler",
    "throttle_bandwidth_handler",
    "increase_monitoring_handler",
    "simulate_recovery_handler",
]

