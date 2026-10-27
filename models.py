"""Shared data models for AeroNix Guard."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class MissionState(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    SAFE_MODE = "SAFE_MODE"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSource(str, Enum):
    SIMULATOR = "simulator"
    IDS = "ids"
    GATEWAY = "gateway"
    NAVIGATION = "navigation"
    COMMUNICATION = "communication"
    SAFETY = "safety"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


@dataclass
class SecurityEvent:
    """A security or operational event observed by the system."""

    event_id: str
    source: EventSource
    event_type: str
    severity: Severity
    message: str
    timestamp: datetime = field(default_factory=utc_now)
    simulated: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    incident_id: str | None = None


@dataclass
class Command:
    """A command submitted for authorization by the gateway."""

    command_id: str
    sender_id: str
    command_type: str
    payload: dict[str, Any]
    sequence_number: int
    timestamp: datetime = field(default_factory=utc_now)
    signature: str = ""


@dataclass
class Incident:
    """A group of correlated events representing one incident."""

    incident_id: str
    title: str
    severity: Severity
    summary: str
    recommended_action: str
    event_ids: list[str] = field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
