"""Incident correlation engine for AeroNix Guard."""

from collections.abc import Iterable
from hashlib import sha256

from models import Incident, SecurityEvent, Severity


CORRELATION_WINDOW_SECONDS = 120.0


def _build_incident(
    events: list[SecurityEvent],
    title: str,
    severity: Severity,
    summary: str,
    recommended_action: str,
) -> Incident:
    """Create an incident and associate its source events."""
    unique_events = {event.event_id: event for event in events}
    event_ids = sorted(unique_events)

    fingerprint = "|".join(event_ids).encode("utf-8")
    incident_id = "inc-" + sha256(fingerprint).hexdigest()[:12]

    incident = Incident(
        incident_id=incident_id,
        title=title,
        severity=severity,
        summary=summary,
        recommended_action=recommended_action,
        event_ids=event_ids,
    )

    for event in unique_events.values():
        event.incident_id = incident_id

    return incident


def _within_window(
    first: SecurityEvent,
    second: SecurityEvent,
) -> bool:
    """Return whether two events are within the correlation window."""
    delta = abs((first.timestamp - second.timestamp).total_seconds())
    return delta <= CORRELATION_WINDOW_SECONDS


def correlate_events(
    events: Iterable[SecurityEvent],
) -> list[Incident]:
    """Group relevant security events into actionable incidents."""
    event_list = list(events)
    incidents: list[Incident] = []
    consumed_ids: set[str] = set()

    # Navigation anomaly combined with loss of communication heartbeat.
    gnss_events = [
        event for event in event_list
        if event.event_type == "GNSS_POSITION_DEVIATION"
    ]
    heartbeat_events = [
        event for event in event_list
        if event.event_type == "HEARTBEAT_LOSS"
    ]

    correlated_gnss = [
        gnss for gnss in gnss_events
        if any(_within_window(gnss, hb) for hb in heartbeat_events)
    ]
    correlated_heartbeats = [
        hb for hb in heartbeat_events
        if any(_within_window(hb, gnss) for gnss in gnss_events)
    ]

    if correlated_gnss and correlated_heartbeats:
        cluster = correlated_gnss + correlated_heartbeats

        incidents.append(
            _build_incident(
                events=cluster,
                title="Navigation anomaly with communication loss",
                severity=Severity.CRITICAL,
                summary=(
                    "A GNSS position anomaly and heartbeat loss occurred "
                    "within the correlation window. The cause is not "
                    "confirmed, but the combined condition requires "
                    "a safety response."
                ),
                recommended_action="ENTER_SAFE_MODE",
            )
        )
        consumed_ids.update(event.event_id for event in cluster)

    remaining_gnss = [
        event for event in gnss_events
        if event.event_id not in consumed_ids
    ]

    if remaining_gnss:
        incidents.append(
            _build_incident(
                events=remaining_gnss,
                title="Navigation anomaly detected",
                severity=Severity.HIGH,
                summary=(
                    "Position deviation exceeded the configured "
                    "demonstration threshold."
                ),
                recommended_action="ENTER_DEGRADED",
            )
        )
        consumed_ids.update(event.event_id for event in remaining_gnss)

    remaining_heartbeats = [
        event for event in heartbeat_events
        if event.event_id not in consumed_ids
    ]

    if remaining_heartbeats:
        incidents.append(
            _build_incident(
                events=remaining_heartbeats,
                title="Communication heartbeat lost",
                severity=Severity.HIGH,
                summary=(
                    "The expected heartbeat is missing. The mission "
                    "simulator must apply its configured contingency policy."
                ),
                recommended_action="ENTER_DEGRADED",
            )
        )
        consumed_ids.update(
            event.event_id for event in remaining_heartbeats
        )

    # Correlate the gateway rejection with the corresponding IDS alert.
    rejected_commands = [
        event for event in event_list
        if event.event_type == "COMMAND_REJECTED"
    ]
    command_alerts = [
        event for event in event_list
        if event.event_type == "UNAUTHORIZED_COMMAND_ATTEMPT"
    ]

    for rejection in rejected_commands:
        if rejection.event_id in consumed_ids:
            continue

        command_id = rejection.metadata.get("command_id")
        matching_alerts = [
            alert for alert in command_alerts
            if alert.event_id not in consumed_ids
            and alert.metadata.get("command_id") == command_id
        ]

        cluster = [rejection, *matching_alerts]

        incidents.append(
            _build_incident(
                events=cluster,
                title="Unauthorized command attempt blocked",
                severity=Severity.HIGH,
                summary=(
                    "The gateway rejected a command and the IDS recorded "
                    "the attempt. No command execution is implied."
                ),
                recommended_action="KEEP_COMMAND_BLOCKED",
            )
        )
        consumed_ids.update(event.event_id for event in cluster)

    # Keep unmatched IDS command alerts visible as incidents too.
    for alert in command_alerts:
        if alert.event_id in consumed_ids:
            continue

        incidents.append(
            _build_incident(
                events=[alert],
                title="Suspicious command attempt detected",
                severity=Severity.HIGH,
                summary=alert.message,
                recommended_action="KEEP_COMMAND_BLOCKED",
            )
        )
        consumed_ids.add(alert.event_id)

    # Handle gateway rejections even if no IDS alert was provided.
    for rejection in rejected_commands:
        if rejection.event_id in consumed_ids:
            continue

        incidents.append(
            _build_incident(
                events=[rejection],
                title="Unauthorized command rejected",
                severity=Severity.HIGH,
                summary=rejection.message,
                recommended_action="KEEP_COMMAND_BLOCKED",
            )
        )
        consumed_ids.add(rejection.event_id)

    return incidents
