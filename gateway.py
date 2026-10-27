"""Demo-only secure command gateway for AeroNix Guard.

This module verifies simulated commands. It does not control a real drone.
Demo credentials are intentionally local and must never be used in production.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from uuid import uuid4

from models import Command, EventSource, SecurityEvent, Severity


@dataclass(frozen=True)
class TrustedIdentity:
    """A locally configured identity for demonstration purposes."""

    secret: bytes
    allowed_commands: frozenset[str]


# DEMO ONLY: replace with proper key provisioning in a real system.
DEMO_IDENTITIES: dict[str, TrustedIdentity] = {
    "operator-console": TrustedIdentity(
        secret=b"aeronix-demo-operator-key-not-for-production",
        allowed_commands=frozenset({
            "STATUS_REQUEST",
            "CHANGE_ROUTE",
        }),
    ),
    "maintenance-console": TrustedIdentity(
        secret=b"aeronix-demo-maintenance-key-not-for-production",
        allowed_commands=frozenset({
            "STATUS_REQUEST",
        }),
    ),
}


@dataclass(frozen=True)
class GatewayDecision:
    """Result of checking a command."""

    accepted: bool
    reason: str
    event: SecurityEvent


def _canonical_command(command: Command) -> bytes:
    """Serialize the signed command fields deterministically."""
    data = {
        "command_id": command.command_id,
        "sender_id": command.sender_id,
        "command_type": command.command_type,
        "payload": command.payload,
        "sequence_number": command.sequence_number,
        "timestamp": command.timestamp.isoformat(),
    }

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_command(command: Command, secret: bytes) -> str:
    """Generate a demo HMAC-SHA256 signature for a command."""
    return hmac.new(
        secret,
        _canonical_command(command),
        hashlib.sha256,
    ).hexdigest()


class SecureCommandGateway:
    """Verify command identity, integrity, permissions and replay status."""

    def __init__(
        self,
        identities: dict[str, TrustedIdentity] | None = None,
    ) -> None:
        self._identities = (
            dict(DEMO_IDENTITIES)
            if identities is None
            else dict(identities)
        )
        self._last_sequence: dict[str, int] = {}

    def _decision(
        self,
        command: Command,
        accepted: bool,
        reason: str,
    ) -> GatewayDecision:
        """Create a structured decision and its audit-ready event."""
        event = SecurityEvent(
            event_id=f"gateway-{uuid4().hex}",
            source=EventSource.GATEWAY,
            event_type=(
                "COMMAND_ACCEPTED" if accepted else "COMMAND_REJECTED"
            ),
            severity=Severity.INFO if accepted else Severity.HIGH,
            message=reason,
            simulated=True,
            metadata={
                "command_id": command.command_id,
                "sender_id": command.sender_id,
                "command_type": command.command_type,
                "sequence_number": command.sequence_number,
                "decision": "ACCEPTED" if accepted else "REJECTED",
                "reason": reason,
            },
        )
        return GatewayDecision(accepted, reason, event)

    def evaluate(self, command: Command) -> GatewayDecision:
        """Validate a command without executing it."""
        identity = self._identities.get(command.sender_id)

        if identity is None:
            return self._decision(
                command,
                False,
                "UNKNOWN_SENDER: sender identity is not trusted.",
            )

        expected_signature = sign_command(command, identity.secret)

        if not hmac.compare_digest(
            expected_signature,
            command.signature,
        ):
            return self._decision(
                command,
                False,
                "INVALID_SIGNATURE: command authenticity or integrity failed.",
            )

        if command.command_type not in identity.allowed_commands:
            return self._decision(
                command,
                False,
                "COMMAND_NOT_AUTHORIZED: sender lacks this permission.",
            )

        if (
            not isinstance(command.sequence_number, int)
            or isinstance(command.sequence_number, bool)
            or command.sequence_number < 1
        ):
            return self._decision(
                command,
                False,
                "INVALID_SEQUENCE: sequence number must be a positive integer.",
            )

        last_sequence = self._last_sequence.get(command.sender_id, 0)

        if command.sequence_number <= last_sequence:
            return self._decision(
                command,
                False,
                "REPLAY_DETECTED: sequence number was already used or is stale.",
            )

        self._last_sequence[command.sender_id] = command.sequence_number

        return self._decision(
            command,
            True,
            "COMMAND_ACCEPTED: identity, signature, permission and sequence verified.",
        )
