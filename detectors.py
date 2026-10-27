"""Rule-based anomaly detection for AeroNix Guard."""

from collections.abc import Iterable

from models import EventSource, SecurityEvent, Severity


# Demonstration threshold only; must be calibrated for a real platform.
GNSS_DEVIATION_THRESHOLD_M = 100.0


def analyze_event(event: SecurityEvent) -> list[SecurityEvent]:
    """Inspect one event and return any detected security anomalies."""

    # A rejected command is security-relevant evidence from the gateway.
    if event.event_type == "COMMAND_REJECTED":
        return [
            SecurityEvent(
                event_id=f"ids-{event.event_id}-command",
                source=EventSource.IDS,
                event_type="UNAUTHORIZED_COMMAND_ATTEMPT",
                severity=Severity.HIGH,
                message=(
                    "The command gateway rejected a suspicious command. "
                    "Review the sender identity and rejection reason."
                ),
                simulated=True,
                metadata={
                    "detector": "rejected_command_monitor",
                    "source_event_id": event.event_id,
                    "command_id": event.metadata.get("command_id"),
                    "sender_id": event.metadata.get("sender_id"),
                    "gateway_reason": event.message,
                },
            )
        ]

    if event.event_type != "TELEMETRY_SAMPLE":
        return []

    findings: list[SecurityEvent] = []
    metadata = event.metadata

    deviation = metadata.get("position_deviation_m")

    if (
        isinstance(deviation, (int, float))
        and not isinstance(deviation, bool)
        and deviation > GNSS_DEVIATION_THRESHOLD_M
    ):
        findings.append(
            SecurityEvent(
                event_id=f"ids-{event.event_id}-gnss",
                source=EventSource.IDS,
                event_type="GNSS_POSITION_DEVIATION",
                severity=Severity.HIGH,
                message=(
                    f"Position deviation of {deviation:.1f} m exceeds "
                    f"the demonstration threshold of "
                    f"{GNSS_DEVIATION_THRESHOLD_M:.1f} m."
                ),
                simulated=True,
                metadata={
                    "detector": "gnss_deviation",
                    "source_event_id": event.event_id,
                    "position_deviation_m": deviation,
                    "threshold_m": GNSS_DEVIATION_THRESHOLD_M,
                },
            )
        )

    if metadata.get("heartbeat_ok") is False:
        findings.append(
            SecurityEvent(
                event_id=f"ids-{event.event_id}-heartbeat",
                source=EventSource.IDS,
                event_type="HEARTBEAT_LOSS",
                severity=Severity.HIGH,
                message="Telemetry indicates that the heartbeat is missing.",
                simulated=True,
                metadata={
                    "detector": "heartbeat_monitor",
                    "source_event_id": event.event_id,
                },
            )
        )

    return findings


def analyze_events(events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
    """Analyze multiple events and return all detected anomalies."""
    findings: list[SecurityEvent] = []

    for event in events:
        findings.extend(analyze_event(event))

    return findings
