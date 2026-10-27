"""Safety state machine for the AeroNix Guard demo.

All actions affect only the simulated mission state. No real drone is
controlled. Recovery authorization is represented by demo-only inputs.
"""

from uuid import uuid4

from models import (
    EventSource,
    Incident,
    MissionState,
    SecurityEvent,
    Severity,
)


class SafetyController:
    """Apply authorized safety policies to the simulated mission."""

    def __init__(
        self,
        initial_state: MissionState = MissionState.NORMAL,
    ) -> None:
        self.state = initial_state
        self.events: list[SecurityEvent] = []
        self._handled_incidents: set[str] = set()

    def _record(
        self,
        event_type: str,
        severity: Severity,
        message: str,
        previous_state: MissionState,
        *,
        incident_id: str | None = None,
        action: str | None = None,
    ) -> SecurityEvent:
        """Record a safety decision or state transition."""
        event = SecurityEvent(
            event_id=f"safety-{uuid4().hex}",
            source=EventSource.SAFETY,
            event_type=event_type,
            severity=severity,
            message=message,
            simulated=True,
            incident_id=incident_id,
            metadata={
                "previous_state": previous_state.value,
                "current_state": self.state.value,
                "action": action,
            },
        )
        self.events.append(event)
        return event

    def apply_incident(self, incident: Incident) -> SecurityEvent:
        """Apply the response policy associated with an incident."""
        previous_state = self.state
        action = incident.recommended_action

        if incident.incident_id in self._handled_incidents:
            return self._record(
                "DUPLICATE_INCIDENT_IGNORED",
                Severity.LOW,
                "Incident was already processed; no action repeated.",
                previous_state,
                incident_id=incident.incident_id,
                action=action,
            )

        self._handled_incidents.add(incident.incident_id)

        if action == "KEEP_COMMAND_BLOCKED":
            return self._record(
                "COMMAND_REMAINS_BLOCKED",
                Severity.INFO,
                "Rejected command remains blocked; mission state unchanged.",
                previous_state,
                incident_id=incident.incident_id,
                action=action,
            )

        if action == "ENTER_DEGRADED":
            if self.state == MissionState.NORMAL:
                self.state = MissionState.DEGRADED
            else:
                return self._record(
                    "SAFETY_ACTION_NO_STATE_CHANGE",
                    Severity.INFO,
                    "Current state is not downgraded by this incident.",
                    previous_state,
                    incident_id=incident.incident_id,
                    action=action,
                )

        elif action == "ENTER_SAFE_MODE":
            if self.state != MissionState.SAFE_MODE:
                self.state = MissionState.SAFE_MODE
            else:
                return self._record(
                    "SAFETY_ACTION_NO_STATE_CHANGE",
                    Severity.INFO,
                    "Mission is already in SAFE_MODE.",
                    previous_state,
                    incident_id=incident.incident_id,
                    action=action,
                )

        else:
            return self._record(
                "SAFETY_ACTION_REJECTED",
                Severity.HIGH,
                "Unknown or unsupported safety action; state unchanged.",
                previous_state,
                incident_id=incident.incident_id,
                action=action,
            )

        return self._record(
            "MISSION_STATE_TRANSITION",
            Severity.CRITICAL
            if self.state == MissionState.SAFE_MODE
            else Severity.HIGH,
            f"Mission state changed from {previous_state.value} "
            f"to {self.state.value}.",
            previous_state,
            incident_id=incident.incident_id,
            action=action,
        )

    def report_link_restored(self) -> SecurityEvent:
        """Record link restoration without automatically resuming the mission."""
        previous_state = self.state

        if self.state != MissionState.SAFE_MODE:
            return self._record(
                "LINK_RESTORATION_NO_STATE_CHANGE",
                Severity.INFO,
                "Link restoration does not change the current mission state.",
                previous_state,
            )

        self.state = MissionState.RECOVERY_REQUIRED

        return self._record(
            "RECOVERY_REQUIRED",
            Severity.HIGH,
            "Link restored; checks and authorization are required before "
            "normal operations resume.",
            previous_state,
        )

    def authorize_recovery(
        self,
        *,
        authorization_verified: bool,
        recovery_checks_passed: bool,
    ) -> SecurityEvent:
        """Resume the simulated mission only after both checks pass.

        These booleans are demo inputs, not real authentication mechanisms.
        A production integration must obtain them from trusted verification
        and recovery-check components.
        """
        previous_state = self.state

        if self.state != MissionState.RECOVERY_REQUIRED:
            return self._record(
                "RECOVERY_REJECTED",
                Severity.MEDIUM,
                "Recovery is not permitted from the current state.",
                previous_state,
            )

        if not authorization_verified or not recovery_checks_passed:
            return self._record(
                "RECOVERY_REJECTED",
                Severity.HIGH,
                "Recovery requires verified authorization and successful "
                "recovery checks.",
                previous_state,
            )

        self.state = MissionState.NORMAL

        return self._record(
            "RECOVERY_AUTHORIZED",
            Severity.INFO,
            "Demo recovery checks passed; mission returned to NORMAL.",
            previous_state,
        )
