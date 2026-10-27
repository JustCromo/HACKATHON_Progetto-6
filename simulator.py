"""Synthetic mission data for AeroNix Guard demonstrations.

All values produced here are simulated. No real drone or ABzero system
is contacted or controlled.
"""

from models import Command, EventSource, SecurityEvent, Severity


def _telemetry_sample(
    event_id: str,
    sequence_number: int,
    position_deviation_m: float,
    heartbeat_ok: bool,
    message: str,
) -> SecurityEvent:
    """Build one synthetic telemetry sample for the IDS to evaluate."""
    return SecurityEvent(
        event_id=event_id,
        source=EventSource.SIMULATOR,
        event_type="TELEMETRY_SAMPLE",
        severity=Severity.INFO,
        message=message,
        simulated=True,
        metadata={
            "sequence_number": sequence_number,
            "position_deviation_m": position_deviation_m,
            "heartbeat_ok": heartbeat_ok,
        },
    )


def build_normal_mission() -> list[SecurityEvent]:
    """Return a short, healthy baseline mission sequence."""
    mission_started = SecurityEvent(
        event_id="sim-normal-001",
        source=EventSource.SIMULATOR,
        event_type="MISSION_STARTED",
        severity=Severity.INFO,
        message="Simulated medical transport mission started.",
        simulated=True,
        metadata={"mission_id": "mission-demo-001"},
    )

    telemetry = [
        _telemetry_sample(
            event_id="sim-normal-002",
            sequence_number=1,
            position_deviation_m=3.0,
            heartbeat_ok=True,
            message="Normal telemetry sample: position and heartbeat are nominal.",
        ),
        _telemetry_sample(
            event_id="sim-normal-003",
            sequence_number=2,
            position_deviation_m=5.0,
            heartbeat_ok=True,
            message="Normal telemetry sample: position and heartbeat remain nominal.",
        ),
    ]
    return [mission_started, *telemetry]


def build_unauthorized_command() -> Command:
    """Return a synthetic command from an untrusted sender."""
    return Command(
        command_id="cmd-demo-unauthorized-001",
        sender_id="unknown-device",
        command_type="CHANGE_ROUTE",
        payload={"destination": "UNAUTHORIZED_DESTINATION"},
        sequence_number=9001,
        signature="invalid-demo-signature",
    )


def build_gnss_link_loss_scenario() -> list[SecurityEvent]:
    """Return telemetry with a GNSS anomaly followed by link loss.

    The simulator supplies observations. The IDS must decide whether
    the position deviation or missing heartbeat is anomalous.
    """
    mission_started = SecurityEvent(
        event_id="sim-gnss-001",
        source=EventSource.SIMULATOR,
        event_type="MISSION_STARTED",
        severity=Severity.INFO,
        message="Simulated mission started before navigation anomaly scenario.",
        simulated=True,
        metadata={"mission_id": "mission-demo-002"},
    )

    telemetry = [
        _telemetry_sample(
            event_id="sim-gnss-002",
            sequence_number=1,
            position_deviation_m=4.0,
            heartbeat_ok=True,
            message="Baseline telemetry before simulated anomaly.",
        ),
        _telemetry_sample(
            event_id="sim-gnss-003",
            sequence_number=2,
            position_deviation_m=850.0,
            heartbeat_ok=True,
            message="Telemetry sample with a large position deviation.",
        ),
        _telemetry_sample(
            event_id="sim-gnss-004",
            sequence_number=3,
            position_deviation_m=910.0,
            heartbeat_ok=False,
            message="Telemetry sample with position deviation and missing heartbeat.",
        ),
    ]
    return [mission_started, *telemetry]
