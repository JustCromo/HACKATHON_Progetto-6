"""JSON Lines audit trail for AeroNix Guard."""

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_AUDIT_PATH = PROJECT_DIR / "data" / "audit.jsonl"


def _to_jsonable(value: Any) -> Any:
    """Convert supported Python objects into JSON-compatible values."""
    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value.isoformat()

    if is_dataclass(value) and not isinstance(value, type):
        return _to_jsonable(asdict(value))

    if isinstance(value, dict):
        return {
            str(key): _to_jsonable(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    raise TypeError(
        f"Unsupported audit value type: {type(value).__name__}"
    )


def append_record(
    record: Any,
    path: Path = DEFAULT_AUDIT_PATH,
) -> dict[str, Any]:
    """Append one event or incident to a JSON Lines audit file."""
    if not is_dataclass(record) or isinstance(record, type):
        raise TypeError("record must be a dataclass instance")

    entry = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "record_type": type(record).__name__,
        "data": _to_jsonable(record),
    }

    serialized = json.dumps(
        entry,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as audit_file:
        audit_file.write(serialized + "\n")

    return entry


def read_records(
    path: Path = DEFAULT_AUDIT_PATH,
) -> list[dict[str, Any]]:
    """Read audit records, rejecting malformed JSON lines."""
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as audit_file:
        for line_number, line in enumerate(audit_file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in audit file at line {line_number}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Invalid audit record at line {line_number}"
                )

            records.append(record)

    return records
