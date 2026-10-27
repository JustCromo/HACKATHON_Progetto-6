"""AeroNix Guard — light, compact drone monitoring dashboard."""

import base64
import csv
import html
import io
import math
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import streamlit as st
from PIL import Image, ImageDraw, ImageFont

from audit import DEFAULT_AUDIT_PATH, append_record
from correlation import correlate_events
from detectors import analyze_event
from gateway import SecureCommandGateway
from models import (
    EventSource,
    Incident,
    MissionState,
    SecurityEvent,
    Severity,
)
from safety import SafetyController
from simulator import build_unauthorized_command


ROOT = Path(__file__).resolve().parent
MAP_PATH = ROOT / "assets" / "pisa_viareggio_map.png"

PISA = (43.7228, 10.4017)
VIAREGGIO = (43.8657, 10.2513)

# Accelerated simulation, not a real flight speed or autopilot.
DEFAULT_SPEED_KMH = 72.0
SIMULATION_TIME_SCALE = 12.0

MAP_BOUNDS = {
    "lon_min": 10.18,
    "lon_max": 10.47,
    "lat_min": 43.68,
    "lat_max": 43.91,
}

STATE_LABELS = {
    "NORMAL": "Regolare",
    "DEGRADED": "Degradata",
    "SAFE_MODE": "Modalità sicura",
    "RECOVERY_REQUIRED": "Verifica necessaria",
}

SEVERITY_LABELS = {
    "INFO": "Informativa",
    "LOW": "Bassa",
    "MEDIUM": "Media",
    "HIGH": "Alta",
    "CRITICAL": "Critica",
}

ICONS = {
    "INFO": "ℹ️",
    "LOW": "🟡",
    "MEDIUM": "🟠",
    "HIGH": "🔴",
    "CRITICAL": "🚨",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def distance_km(a, b) -> float:
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    value = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 6371.0 * 2 * math.asin(math.sqrt(value))


ROUTE_DISTANCE_KM = distance_km(PISA, VIAREGGIO)


def coordinates_at(progress: float):
    progress = max(0.0, min(1.0, progress))
    return (
        PISA[0] + (VIAREGGIO[0] - PISA[0]) * progress,
        PISA[1] + (VIAREGGIO[1] - PISA[1]) * progress,
    )


def map_pixel(lat, lon, width, height):
    x = (
        (lon - MAP_BOUNDS["lon_min"])
        / (MAP_BOUNDS["lon_max"] - MAP_BOUNDS["lon_min"])
        * (width - 1)
    )
    y = (
        (MAP_BOUNDS["lat_max"] - lat)
        / (MAP_BOUNDS["lat_max"] - MAP_BOUNDS["lat_min"])
        * (height - 1)
    )
    return int(x), int(y)


def get_font(size: int, bold: bool = False):
    names = (
        [
            "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
        if bold else [
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            pass
    return ImageFont.load_default()


def render_flight_map(flight):
    """Draw the planned route and the latest VALID GNSS position."""
    if not MAP_PATH.exists():
        raise FileNotFoundError(f"Mappa non trovata: {MAP_PATH}")

    image = Image.open(MAP_PATH).convert("RGB")
    draw = ImageDraw.Draw(image)
    width, height = image.size

    start = map_pixel(*PISA, width, height)
    end = map_pixel(*VIAREGGIO, width, height)

    draw.line([start, end], fill="#B9CCE2", width=7)

    if flight:
        # During a signal blackout this intentionally stays frozen.
        progress = flight["last_valid_progress"]
    else:
        progress = 0.0

    current = map_pixel(*coordinates_at(progress), width, height)

    draw.line([start, current], fill="#2864DC", width=8)

    for point, colour in ((start, "#16845B"), (end, "#D94B58")):
        x, y = point
        draw.ellipse(
            (x - 12, y - 12, x + 12, y + 12),
            fill="white",
            outline=colour,
            width=5,
        )
        draw.ellipse(
            (x - 5, y - 5, x + 5, y + 5),
            fill=colour,
        )

    x, y = current
    draw.line(
        [(x - 15, y - 10), (x + 15, y + 10)],
        fill="#155AB6",
        width=5,
    )
    draw.line(
        [(x - 15, y + 10), (x + 15, y - 10)],
        fill="#155AB6",
        width=5,
    )
    draw.ellipse(
        (x - 7, y - 7, x + 7, y + 7),
        fill="#155AB6",
        outline="white",
        width=2,
    )

    if flight and flight["signal_lost"]:
        label_x = max(12, min(width - 190, x + 22))
        label_y = max(12, min(height - 55, y - 58))

        draw.rounded_rectangle(
            (label_x, label_y, label_x + 178, label_y + 44),
            radius=9,
            fill="#FFF0F0",
            outline="#D94B58",
            width=3,
        )
        draw.text(
            (label_x + 12, label_y + 10),
            "NO SIGNAL",
            font=get_font(21, True),
            fill="#B42332",
        )

    return image


def create_system_event(
    event_type,
    source,
    severity,
    message,
    metadata=None,
):
    return SecurityEvent(
        event_id=f"evt-{uuid4().hex}",
        source=source,
        event_type=event_type,
        severity=severity,
        message=message,
        simulated=True,
        metadata=metadata or {},
    )


def clear_audit_for_new_flight():
    """Each new demo starts with a clean flight register."""
    DEFAULT_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_AUDIT_PATH.write_text("", encoding="utf-8")


def create_flight():
    now = time.monotonic()
    return {
        "run_id": uuid4().hex[:10],
        "status": "running",
        "flight_phase": "IN_VOLO",
        "mission_state": MissionState.NORMAL.value,
        "controller": SafetyController(),
        "gateway": SecureCommandGateway(),

        # Internal route estimate vs last received GNSS fix.
        "actual_progress": 0.0,
        "last_valid_progress": 0.0,
        "distance_km": ROUTE_DISTANCE_KM,
        "last_lat": PISA[0],
        "last_lon": PISA[1],
        "last_fix_time": utc_now().isoformat(),

        "gnss_available": True,
        "link_connected": True,
        "signal_lost": False,
        "autopilot_active": False,

        "speed_kmh": DEFAULT_SPEED_KMH,
        "altitude_m": 120,
        "battery_percent": 100.0,
        "latency_ms": 48,
        "gnss_satellites": 12,
        "signal_quality": "Buona",

        "events": [],
        "alerts": [],
        "incidents": [],
        "feed": [],
        "register": [],
        "audit_errors": [],

        "created_at": utc_now().isoformat(),
        "ended_at": None,
        "last_tick": now,
        "last_telemetry_log": now,
        "last_autopilot_log": now,
        "arrived_recorded": False,
    }



def add_event(flight, event, title, detail, icon=None):
    """Persist every event; display only significant operator notifications."""
    flight["events"].append(event)

    try:
        append_record(event)
    except (OSError, TypeError, ValueError) as exc:
        flight["audit_errors"].append(str(exc))

    local_time = event.timestamp.astimezone().strftime("%H:%M:%S")

    flight["register"].append({
        "Ora": local_time,
        "Timestamp UTC": event.timestamp.isoformat(),
        "Evento": title,
        "Tipo": event.event_type,
        "Componente": event.source.value.upper(),
        "Severità": event.severity.value,
        "Descrizione": detail,
        "Latitudine": round(flight["last_lat"], 6),
        "Longitudine": round(flight["last_lon"], 6),
        "Stato missione": flight["mission_state"],
        "ID": event.event_id,
        "Simulato": event.simulated,
    })

    # Component-level details remain in the register. The feed is for
    # meaningful mission changes, not every internal processing step.
    visible_types = {
        "MISSION_STARTED",
        "GNSS_SIGNAL_LOST",
        "AUTOPILOT_CONTINGENCY_STARTED",
        "SIGNAL_RESTORED",
        "FLIGHT_PAUSED",
        "FLIGHT_RESUMED",
        "FLIGHT_ENDED",
        "DESTINATION_REACHED",
        "RECOVERY_REJECTED",
    }

    if event.event_type in visible_types:
        flight["feed"].append({
            "ora": local_time,
            "titolo": title,
            "dettaglio": detail,
            "componente": event.source.value.upper(),
            "severita": event.severity.value,
            "icona": icon or ICONS.get(event.severity.value, "•"),
            "id": event.event_id,
        })



def add_incident(flight, incident):
    """Persist an incident and show one grouped notification."""
    titles_it = {
        "Navigation anomaly with communication loss":
            "Anomalia di navigazione e perdita del collegamento",
        "Navigation anomaly detected":
            "Anomalia di navigazione rilevata",
        "Communication heartbeat lost":
            "Heartbeat di comunicazione assente",
        "Unauthorized command attempt blocked":
            "Tentativo di comando non autorizzato bloccato",
        "Suspicious command attempt detected":
            "Tentativo di comando sospetto rilevato",
        "Unauthorized command rejected":
            "Comando non autorizzato respinto",
    }

    summaries_it = {
        (
            "A GNSS position anomaly and loss of heartbeat occurred within "
            "the correlation window. The cause is not confirmed, but the "
            "combined condition requires a safety response."
        ):
            (
                "Sono state rilevate insieme un'anomalia della posizione "
                "GNSS e la perdita dell'heartbeat. La causa non è confermata, "
                "ma la combinazione richiede una risposta di sicurezza."
            ),
        "Position deviation exceeded the configured demonstration threshold.":
            (
                "La deviazione della posizione supera la soglia "
                "configurata per la dimostrazione."
            ),
        (
            "The expected heartbeat is missing. The mission simulator must "
            "apply its configured contingency policy."
        ):
            (
                "L'heartbeat atteso è assente. La missione simulata applica "
                "la procedura di contingenza configurata."
            ),
        (
            "The gateway rejected a command and the IDS recorded the attempt. "
            "No command execution is implied."
        ):
            (
                "Il gateway ha rifiutato il comando e l'IDS ha registrato "
                "il tentativo. Il comando non è stato eseguito."
            ),
    }

    incident.title = titles_it.get(incident.title, incident.title)
    incident.summary = summaries_it.get(incident.summary, incident.summary)

    # Keep operator-facing incident messages in Italian.
    title_map = {
        "Navigation anomaly with communication loss":
            "Anomalia di navigazione e perdita del collegamento",
        "Navigation anomaly detected":
            "Anomalia di navigazione rilevata",
        "Communication heartbeat lost":
            "Heartbeat di comunicazione assente",
        "Unauthorized command attempt blocked":
            "Tentativo di comando non autorizzato bloccato",
        "Suspicious command attempt detected":
            "Tentativo di comando sospetto rilevato",
        "Unauthorized command rejected":
            "Comando non autorizzato respinto",
    }
    incident.title = title_map.get(incident.title, incident.title)

    summary_lower = incident.summary.lower()
    if (
        "gnss position anomaly" in summary_lower
        and ("heartbeat loss" in summary_lower or "loss of heartbeat" in summary_lower)
    ):
        incident.summary = (
            "Sono state rilevate insieme un'anomalia della posizione GNSS "
            "e la perdita dell'heartbeat. La causa non è confermata, "
            "ma la combinazione richiede una risposta di sicurezza."
        )
    elif "the gateway rejected a command" in summary_lower:
        incident.summary = (
            "Il gateway ha rifiutato il comando e l'IDS ha registrato "
            "il tentativo. Il comando non è stato eseguito."
        )
    elif "position deviation exceeded" in summary_lower:
        incident.summary = (
            "La deviazione della posizione supera la soglia "
            "configurata per la dimostrazione."
        )
    elif "the expected heartbeat is missing" in summary_lower:
        incident.summary = (
            "L'heartbeat atteso è assente. La missione simulata applica "
            "la procedura di contingenza configurata."
        )

    flight["incidents"].append(incident)

    try:
        append_record(incident)
    except (OSError, TypeError, ValueError) as exc:
        flight["audit_errors"].append(str(exc))

    local_time = incident.created_at.astimezone().strftime("%H:%M:%S")

    flight["register"].append({
        "Ora": local_time,
        "Timestamp UTC": incident.created_at.isoformat(),
        "Evento": incident.title,
        "Tipo": "INCIDENT_CREATED",
        "Componente": "CORRELAZIONE",
        "Severità": incident.severity.value,
        "Descrizione": incident.summary,
        "Latitudine": round(flight["last_lat"], 6),
        "Longitudine": round(flight["last_lon"], 6),
        "Stato missione": flight["mission_state"],
        "ID": incident.incident_id,
        "Simulato": True,
    })

    flight["feed"].append({
        "ora": local_time,
        "titolo": incident.title,
        "dettaglio": incident.summary,
        "componente": "INCIDENTE CORRELATO",
        "severita": incident.severity.value,
        "icona": ICONS.get(incident.severity.value, "🔗"),
        "id": incident.incident_id,
    })


def record_alert(flight, alert):
    messages = {
        "UNAUTHORIZED_COMMAND_ATTEMPT": (
            "Il gateway ha rifiutato il comando. L'IDS ha registrato "
            "il tentativo; non risulta che il comando sia stato eseguito."
        ),
        "GNSS_POSITION_DEVIATION": (
            "La posizione simulata supera la soglia dimostrativa. "
            "È un'anomalia sospetta, non una prova certa di spoofing."
        ),
        "HEARTBEAT_LOSS": (
            "L'heartbeat atteso non è disponibile. La causa della "
            "perdita del collegamento non è confermata."
        ),
    }
    titles = {
        "UNAUTHORIZED_COMMAND_ATTEMPT": "Comando sospetto rilevato",
        "GNSS_POSITION_DEVIATION": "Anomalia GNSS rilevata",
        "HEARTBEAT_LOSS": "Heartbeat assente",
    }

    flight["alerts"].append(alert)
    add_event(
        flight,
        alert,
        titles.get(alert.event_type, alert.event_type),
        messages.get(alert.event_type, alert.message),
        "🚨",
    )


def record_safety_event(flight, event):
    flight["mission_state"] = flight["controller"].state.value

    messages = {
        "COMMAND_REMAINS_BLOCKED": (
            "Il comando resta bloccato. Lo stato della missione non cambia."
        ),
        "MISSION_STATE_TRANSITION": (
            "Il motore di sicurezza ha aggiornato lo stato della missione."
        ),
        "RECOVERY_REQUIRED": (
            "Il collegamento è tornato. Sono necessarie verifiche prima "
            "di riprendere le operazioni."
        ),
        "RECOVERY_AUTHORIZED": (
            "Le verifiche di recupero della simulazione sono state superate."
        ),
        "RECOVERY_REJECTED": (
            "Il recupero non è stato autorizzato oppure le verifiche "
            "non sono state superate."
        ),
    }

    titles = {
        "COMMAND_REMAINS_BLOCKED": "Comando contenuto",
        "MISSION_STATE_TRANSITION": "Stato di sicurezza aggiornato",
        "RECOVERY_REQUIRED": "Verifica di recovery necessaria",
        "RECOVERY_AUTHORIZED": "Recovery completato",
        "RECOVERY_REJECTED": "Recovery rifiutato",
    }

    add_event(
        flight,
        event,
        titles.get(event.event_type, "Decisione di sicurezza"),
        messages.get(event.event_type, event.message),
        "🛡️",
    )


# ---------------------------------------------------------------------
# Mission control and the two security scenarios
# ---------------------------------------------------------------------

def simulate_signal_loss(flight):
    if flight["signal_lost"]:
        return

    flight["gnss_available"] = False
    flight["link_connected"] = False
    flight["signal_lost"] = True
    flight["autopilot_active"] = True
    flight["latency_ms"] = None
    flight["signal_quality"] = "Non disponibile"
    flight["last_autopilot_log"] = time.monotonic()

    add_event(
        flight,
        create_system_event(
            "GNSS_SIGNAL_LOST",
            EventSource.NAVIGATION,
            Severity.HIGH,
            "GNSS and communication signal were lost in the simulation.",
            {"last_valid_progress": flight["last_valid_progress"]},
        ),
        "Perdita del segnale — marker congelato",
        "Non arrivano coordinate nuove. Il marker mostra l'ultimo fix "
        "valido; il piano di contingenza simulato continua separatamente.",
        "📡",
    )

    add_event(
        flight,
        create_system_event(
            "AUTOPILOT_CONTINGENCY_STARTED",
            EventSource.NAVIGATION,
            Severity.HIGH,
            "The simulated contingency autopilot was activated.",
        ),
        "Autopilota di contingenza attivato",
        "La stima interna del percorso continua mentre il marker GNSS "
        "resta fermo sull'ultima posizione ricevuta.",
        "🧭",
    )

    # One synthetic telemetry sample produces both demo findings.
    telemetry = create_system_event(
        "TELEMETRY_SAMPLE",
        EventSource.SIMULATOR,
        Severity.INFO,
        "Synthetic sample representing a GNSS anomaly and heartbeat loss.",
        {
            "position_deviation_m": 850.0,
            "heartbeat_ok": False,
        },
    )

    add_event(
        flight,
        telemetry,
        "Telemetria anomala",
        "Il campione di prova presenta una deviazione GNSS e un heartbeat "
        "assente.",
        "⚠️",
    )

    alerts = analyze_event(telemetry)
    for alert in alerts:
        record_alert(flight, alert)

    for incident in correlate_events(alerts):
        add_incident(flight, incident)
        result = flight["controller"].apply_incident(incident)
        record_safety_event(flight, result)



def restore_signal(flight):
    """Simulate a validated signal return and automatic service recovery."""
    if not flight["signal_lost"]:
        return

    previous_fix = flight["last_valid_progress"]
    estimated_progress = flight["actual_progress"]

    # The button represents a successful simulated link/GNSS validation.
    flight["gnss_available"] = True
    flight["link_connected"] = True
    flight["signal_lost"] = False
    flight["autopilot_active"] = False
    flight["signal_quality"] = "Buona"
    flight["latency_ms"] = random.randint(42, 64)
    flight["gnss_satellites"] = random.randint(10, 14)

    # Reconcile the displayed marker with the position estimated while
    # the last GNSS fix was unavailable.
    flight["last_valid_progress"] = estimated_progress
    flight["last_lat"], flight["last_lon"] = coordinates_at(
        estimated_progress
    )
    flight["last_fix_time"] = utc_now().isoformat()
    flight["last_tick"] = time.monotonic()

    # Keep the safety transitions and recovery checks in the full register,
    # but do not ask the operator to click a separate recovery button.
    controller = flight["controller"]

    if controller.state == MissionState.SAFE_MODE:
        transition = controller.report_link_restored()
        record_safety_event(flight, transition)

    if controller.state == MissionState.RECOVERY_REQUIRED:
        result = controller.authorize_recovery(
            authorization_verified=True,
            recovery_checks_passed=True,
        )
        record_safety_event(flight, result)

    flight["mission_state"] = controller.state.value

    # Add one clear operator notification after the recovery transitions.
    restored_event = create_system_event(
        "SIGNAL_RESTORED",
        EventSource.COMMUNICATION,
        Severity.INFO,
        "Simulated link and GNSS validation passed; the flight service resumed.",
        {
            "signal_validation": "PASSED",
            "previous_fix_progress_percent": round(previous_fix * 100, 2),
            "reacquired_fix_progress_percent": round(
                estimated_progress * 100, 2
            ),
            "mission_state": flight["mission_state"],
        },
    )

    add_event(
        flight,
        restored_event,
        "Segnale ripristinato — volo ripreso",
        (
            f"Collegamento verificato. La posizione è stata riallineata "
            f"al {estimated_progress * 100:.1f}% della rotta, raggiunto "
            "durante la navigazione di contingenza. Il servizio riprende "
            "automaticamente nella simulazione."
        ),
        "✅",
    )


def simulate_unauthorized_command(flight):
    command = build_unauthorized_command()
    command.command_id = f"{flight['run_id']}-{uuid4().hex[:8]}"
    command.timestamp = utc_now()

    decision = flight["gateway"].evaluate(command)

    add_event(
        flight,
        decision.event,
        "Comando rifiutato dal gateway",
        f"Mittente: {command.sender_id}. Motivo: {decision.reason}",
        "⛔",
    )

    alerts = analyze_event(decision.event)
    for alert in alerts:
        record_alert(flight, alert)

    for incident in correlate_events([decision.event, *alerts]):
        add_incident(flight, incident)
        result = flight["controller"].apply_incident(incident)
        record_safety_event(flight, result)


def authorize_recovery(flight):
    result = flight["controller"].authorize_recovery(
        authorization_verified=True,
        recovery_checks_passed=True,
    )
    record_safety_event(flight, result)
    flight["mission_state"] = flight["controller"].state.value
    flight["last_tick"] = time.monotonic()


def end_flight(flight):
    if flight["status"] == "ended":
        return

    flight["status"] = "ended"
    flight["ended_at"] = utc_now().isoformat()

    add_event(
        flight,
        create_system_event(
            "FLIGHT_ENDED",
            EventSource.SIMULATOR,
            Severity.INFO,
            "The operator ended the simulated flight.",
        ),
        "Volo terminato dall'operatore",
        "Monitoraggio fermato. Il registro completo è disponibile "
        "nel report del volo.",
        "⏹️",
    )


def pause_flight(flight):
    if flight["status"] != "running":
        return

    flight["status"] = "paused"
    flight["last_tick"] = time.monotonic()

    add_event(
        flight,
        create_system_event(
            "FLIGHT_PAUSED",
            EventSource.SIMULATOR,
            Severity.INFO,
            "The operator paused the demo.",
        ),
        "Volo in pausa",
        "Posizione e simulazione sono congelate fino alla ripresa.",
        "Ⅱ",
    )


def resume_flight(flight):
    if flight["status"] != "paused":
        return

    flight["status"] = "running"
    flight["last_tick"] = time.monotonic()

    add_event(
        flight,
        create_system_event(
            "FLIGHT_RESUMED",
            EventSource.SIMULATOR,
            Severity.INFO,
            "The operator resumed the demo.",
        ),
        "Volo ripreso",
        "Il monitoraggio simulato è ripartito.",
        "▶️",
    )


# ---------------------------------------------------------------------
# Continuous simulation loop
# ---------------------------------------------------------------------

def update_flight(flight):
    now = time.monotonic()
    elapsed = min(max(now - flight["last_tick"], 0.0), 2.0)
    flight["last_tick"] = now

    if flight["status"] != "running":
        return

    signal_ok = flight["gnss_available"] and flight["link_connected"]

    # When the signal is absent, received metrics freeze at their last values.
    if signal_ok:
        flight["speed_kmh"] = round(
            DEFAULT_SPEED_KMH + random.uniform(-4.0, 4.0), 1
        )
        flight["altitude_m"] = round(120 + random.uniform(-3.0, 3.0))
        flight["battery_percent"] = max(
            0.0, 100.0 - 18.0 * flight["actual_progress"]
        )
        flight["gnss_satellites"] = random.randint(10, 14)
        flight["latency_ms"] = max(
            28, min(100, int(48 + random.gauss(0, 7)))
        )

    state_allows_flight = flight["mission_state"] in (
        MissionState.NORMAL.value,
        MissionState.DEGRADED.value,
    )

    # Key fix: contingency navigation progresses in SAFE_MODE too.
    # This is an internal simulated estimate, never a verified GNSS fix.
    may_move = (
        flight["flight_phase"] == "IN_VOLO"
        and (state_allows_flight or flight["autopilot_active"])
        and (signal_ok or flight["autopilot_active"])
    )

    if may_move:
        speed = flight["speed_kmh"] if signal_ok else DEFAULT_SPEED_KMH
        distance = (
            speed * elapsed * SIMULATION_TIME_SCALE / 3600.0
        )

        flight["actual_progress"] = min(
            1.0,
            flight["actual_progress"] + distance / flight["distance_km"],
        )

        if signal_ok:
            flight["last_valid_progress"] = flight["actual_progress"]
            flight["last_lat"], flight["last_lon"] = coordinates_at(
                flight["last_valid_progress"]
            )
            flight["last_fix_time"] = utc_now().isoformat()

        elif now - flight["last_autopilot_log"] >= 4.0:
            flight["last_autopilot_log"] = now
            add_event(
                flight,
                create_system_event(
                    "AUTOPILOT_PROGRESS",
                    EventSource.NAVIGATION,
                    Severity.INFO,
                    "The contingency route estimate advanced.",
                    {
                        "estimated_progress": round(
                            flight["actual_progress"], 4
                        ),
                        "last_valid_gnss_progress": round(
                            flight["last_valid_progress"], 4
                        ),
                        "position_is_gnss_verified": False,
                    },
                ),
                "Autopilota: avanzamento stimato",
                f"Stima del percorso: {flight['actual_progress'] * 100:.1f}%. "
                "Il marker GNSS resta congelato sull'ultimo fix.",
                "🧭",
            )

    # A destination reached during a blackout is not considered confirmed.
    if (
        signal_ok
        and state_allows_flight
        and flight["actual_progress"] >= 1.0
        and not flight["arrived_recorded"]
    ):
        flight["flight_phase"] = "ARRIVATO"
        flight["arrived_recorded"] = True

        add_event(
            flight,
            create_system_event(
                "DESTINATION_REACHED",
                EventSource.SIMULATOR,
                Severity.INFO,
                "The simulated aircraft reached Viareggio with telemetry available.",
            ),
            "Destinazione raggiunta",
            "Viareggio è stato raggiunto e la posizione è nuovamente verificabile.",
            "🏁",
        )

    if signal_ok and now - flight["last_telemetry_log"] >= 5.0:
        flight["last_telemetry_log"] = now

        add_event(
            flight,
            create_system_event(
                "TELEMETRY_UPDATE",
                EventSource.SIMULATOR,
                Severity.INFO,
                "Synthetic telemetry snapshot received.",
                {
                    "latitude": round(flight["last_lat"], 6),
                    "longitude": round(flight["last_lon"], 6),
                    "speed_kmh": flight["speed_kmh"],
                    "altitude_m": flight["altitude_m"],
                    "latency_ms": flight["latency_ms"],
                    "satellites": flight["gnss_satellites"],
                },
            ),
            "Telemetria aggiornata",
            "Nuovo campione simulato di posizione e stato del volo.",
            "📍",
        )


# ---------------------------------------------------------------------
# Map with transparent telemetry panels
# ---------------------------------------------------------------------

def render_map_overlay(flight):
    """Render a large, clean map with only essential overlay information."""
    image = render_flight_map(flight)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    map_b64 = base64.b64encode(buffer.getvalue()).decode("ascii")

    if flight is None:
        state_label = "In attesa"
        flight_label = "NON AVVIATA"
        state_color = "#64748B"
        progress = 0.0
        last_fix_progress = 0.0
        link_label = "In attesa"
        latency_label = "—"
        gnss_label = "—"
        signal_lost = False
        autopilot = False
    else:
        state_label = STATE_LABELS.get(
            flight["mission_state"], flight["mission_state"]
        )
        flight_label = {
            "running": "IN VOLO",
            "paused": "IN PAUSA",
            "ended": "TERMINATO",
        }.get(flight["status"], flight["status"].upper())

        state_color = {
            "NORMAL": "#16845B",
            "DEGRADED": "#A86B12",
            "SAFE_MODE": "#BF3646",
            "RECOVERY_REQUIRED": "#A86B12",
        }.get(flight["mission_state"], "#64748B")

        progress = flight["actual_progress"]
        last_fix_progress = flight["last_valid_progress"]
        signal_lost = flight["signal_lost"]
        autopilot = flight["autopilot_active"]

        link_label = (
            "Perso" if not flight["link_connected"] else "Connesso"
        )
        latency_label = (
            f"{flight['latency_ms']} ms"
            if flight["latency_ms"] is not None else "N/D"
        )
        gnss_label = (
            f"{flight['gnss_satellites']} satelliti"
            if flight["gnss_available"] else "Non disponibile"
        )

    # Only two small panels remain on the map.
    # Bottom-left is over the sea; top-right is away from the route.
    template = r"""
<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<style>
* { box-sizing:border-box; }
html,body {
  margin:0; padding:0; background:transparent;
  color:#193552;
  font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;
}
.map {
  position:relative; width:100%; height:540px; overflow:hidden;
  border:1px solid #D6E3ED; border-radius:15px;
  background:#EAF2F5;
  box-shadow:0 4px 16px rgba(35,63,90,.07);
}
.map-image { width:100%; height:100%; display:block; object-fit:contain; }

.glass {
  position:absolute;
  padding:10px 12px;
  border-radius:11px;
  border:1px solid rgba(255,255,255,.97);
  background:rgba(255,255,255,.86);
  backdrop-filter:blur(8px);
  -webkit-backdrop-filter:blur(8px);
  box-shadow:0 3px 12px rgba(25,49,74,.10);
}
.flight-card {
  left:12px; bottom:12px; width:205px;
}
.link-card {
  top:12px; right:12px; width:205px;
}
.eyebrow {
  color:#60758A; font-size:9px; font-weight:800;
  letter-spacing:1.05px; margin-bottom:6px;
}
.state {
  font-size:13px; font-weight:800; line-height:1.35;
  color:__STATE_COLOR__;
}
.pill {
  display:inline-block; margin-top:5px;
  padding:4px 7px; border-radius:20px;
  color:#36516C; background:#EAF1F8;
  font-size:9px; font-weight:800;
}
.route {
  margin-top:9px; font-size:15px; font-weight:800;
  color:#193B62; white-space:nowrap;
}
.arrow { color:#2864DC; padding:0 3px; }
.progress-heading {
  display:flex; justify-content:space-between; gap:7px;
  margin-top:10px; margin-bottom:5px;
  color:#536B82; font-size:10px;
}
.progress-heading strong { color:#193B62; }
.track {
  height:5px; width:100%; border-radius:8px;
  background:#E2EAF1; overflow:hidden;
}
.fill {
  height:100%; width:__PROGRESS__%;
  border-radius:8px; background:#2864DC;
}
.note {
  margin-top:7px; color:#526B82; font-size:10px; line-height:1.45;
}
.auto {
  margin-top:7px; padding:7px;
  border-radius:7px; border:1px solid #B7E5CE;
  background:#EAF8EF; color:#176642;
  font-size:10px; line-height:1.4; font-weight:700;
}
.link-state {
  display:flex; align-items:center; gap:7px;
  color:__LINK_COLOR__; font-size:13px; font-weight:800;
}
.dot {
  width:8px; height:8px; border-radius:50%;
  flex:0 0 8px; background:__LINK_COLOR__;
}
.detail {
  display:flex; justify-content:space-between; gap:8px;
  margin-top:8px; color:#566D83; font-size:10px;
}
.detail strong { color:#193B62; text-align:right; }
.signal-note {
  position:absolute; top:12px; left:50%;
  transform:translateX(-50%);
  background:rgba(255,240,240,.97);
  border:1px solid #F0C1C5; color:#B42332;
  padding:8px 12px; border-radius:9px;
  font-size:11px; font-weight:800;
  box-shadow:0 3px 12px rgba(70,30,30,.08);
  white-space:nowrap;
}
.footer {
  position:absolute; right:12px; bottom:12px;
  background:rgba(255,255,255,.85);
  color:#526A80; padding:5px 8px;
  border:1px solid #E0E8EF; border-radius:6px;
  font-size:9px;
}
@media(max-width:800px) {
  .map { height:480px; }
  .flight-card { width:185px; }
  .link-card { width:185px; }
  .route { font-size:13px; }
  .signal-note { top:auto; bottom:12px; }
}
</style>
</head>
<body>
<div class="map">
  <img class="map-image" src="data:image/png;base64,__MAP__"
       alt="Mappa schematica Pisa–Viareggio">

  <section class="glass flight-card">
    <div class="eyebrow">MISSIONE</div>
    <div class="state">● __STATE__</div>
    <span class="pill">__FLIGHT_STATUS__</span>
    <div class="route">Pisa <span class="arrow">→</span> Viareggio</div>
    <div class="progress-heading">
      <span>Avanzamento rotta</span>
      <strong>__PROGRESS_TEXT__</strong>
    </div>
    <div class="track"><div class="fill"></div></div>
    <div class="note">__POSITION_NOTE__</div>
    <div class="auto" style="display:__AUTO_DISPLAY__">
      🧭 Autopilota simulato attivo.<br>
      Stima: __ESTIMATED_PROGRESS__% · Ultimo fix GNSS: __LAST_FIX_PROGRESS__%
    </div>
  </section>

  <section class="glass link-card">
    <div class="eyebrow">COLLEGAMENTO</div>
    <div class="link-state">
      <span class="dot"></span>
      <span>__LINK__</span>
    </div>
    <div class="detail">
      <span>Latenza</span><strong>__LATENCY__</strong>
    </div>
    <div class="detail">
      <span>GNSS</span><strong>__GNSS__</strong>
    </div>
  </section>

  <div class="signal-note" style="display:__SIGNAL_DISPLAY__">
    NO SIGNAL · posizione GNSS non aggiornata
  </div>

  <div class="footer">MAPPA SCHEMATICA · DATI SIMULATI</div>
</div>
</body>
</html>
"""

    position_note = (
        "Marker fermo sull'ultimo fix ricevuto."
        if signal_lost
        else "Posizione dell'ultimo messaggio GNSS."
    )

    replacements = {
        "MAP": map_b64,
        "STATE_COLOR": state_color,
        "STATE": state_label,
        "FLIGHT_STATUS": flight_label,
        "PROGRESS": f"{progress * 100:.2f}",
        "PROGRESS_TEXT": f"{progress * 100:.1f}%",
        "POSITION_NOTE": position_note,
        "AUTO_DISPLAY": "block" if autopilot else "none",
        "ESTIMATED_PROGRESS": f"{progress * 100:.1f}",
        "LAST_FIX_PROGRESS": f"{last_fix_progress * 100:.1f}",
        "LINK_COLOR": "#C03948" if signal_lost else "#16845B",
        "LINK": link_label,
        "LATENCY": latency_label,
        "GNSS": gnss_label,
        "SIGNAL_DISPLAY": "block" if signal_lost else "none",
    }

    document = template
    for key, value in replacements.items():
        document = document.replace(
            f"__{key}__",
            html.escape(str(value), quote=True),
        )

    st.iframe(
        document,
        width="stretch",
        height=560,
        alt="Rotta Pisa–Viareggio con stato missione e collegamento",
    )


# ---------------------------------------------------------------------
# Sidebar menu
# ---------------------------------------------------------------------


def _on_start_new_flight():
    """Start a clean flight before Streamlit reruns the app."""
    clear_audit_for_new_flight()
    flight = create_flight()
    st.session_state["flight"] = flight

    event = create_system_event(
        "MISSION_STARTED",
        EventSource.SIMULATOR,
        Severity.INFO,
        "The simulated flight departed from Pisa.",
        {
            "origin": "Pisa",
            "destination": "Viareggio (LU)",
            "distance_km": round(ROUTE_DISTANCE_KM, 2),
        },
    )

    add_event(
        flight,
        event,
        "Decollo da Pisa",
        "Missione avviata. Coordinate e telemetria sono simulate.",
        "✈️",
    )


def _on_pause_flight():
    flight = st.session_state.get("flight")
    if flight is not None:
        pause_flight(flight)


def _on_resume_flight():
    flight = st.session_state.get("flight")
    if flight is not None:
        resume_flight(flight)


def _on_end_flight():
    flight = st.session_state.get("flight")
    if flight is not None:
        end_flight(flight)


def _on_signal_loss():
    flight = st.session_state.get("flight")
    if flight is not None:
        simulate_signal_loss(flight)


def _on_unauthorized_command():
    flight = st.session_state.get("flight")
    if flight is not None:
        simulate_unauthorized_command(flight)


def _on_signal_restore():
    flight = st.session_state.get("flight")
    if flight is not None:
        restore_signal(flight)


def _on_recovery():
    flight = st.session_state.get("flight")
    if flight is not None:
        authorize_recovery(flight)


def sidebar_controls():
    """Render stable controls; callbacks execute before the app rerun."""
    with st.sidebar:
        st.markdown("## 🛡️ AeroNix Guard")
        st.caption("Controllo missione · Pisa → Viareggio")
        st.divider()

        flight = st.session_state.get("flight")
        status = flight["status"] if flight else "idle"

        st.button(
            "▶ Avvia nuovo volo",
            key="aeronix_start_flight",
            on_click=_on_start_new_flight,
            type="primary",
            width="stretch",
            disabled=status in ("running", "paused"),
        )

        st.button(
            "Ⅱ Pausa",
            key="aeronix_pause_flight",
            on_click=_on_pause_flight,
            width="stretch",
            disabled=status != "running",
        )

        st.button(
            "▶ Riprendi volo",
            key="aeronix_resume_flight",
            on_click=_on_resume_flight,
            width="stretch",
            disabled=status != "paused",
        )

        st.button(
            "■ Termina volo",
            key="aeronix_end_flight",
            on_click=_on_end_flight,
            width="stretch",
            disabled=status not in ("running", "paused"),
        )

        st.divider()
        st.markdown("### Test di sicurezza")

        active = status == "running"
        signal_lost = bool(flight and flight["signal_lost"])
        recovery_needed = bool(
            flight
            and flight["mission_state"]
            == MissionState.RECOVERY_REQUIRED.value
        )

        st.button(
            "📡 Simula perdita GNSS / link",
            key="aeronix_simulate_loss",
            on_click=_on_signal_loss,
            width="stretch",
            disabled=not active or signal_lost,
        )

        st.button(
            "🚫 Comando non autorizzato",
            key="aeronix_simulate_command",
            on_click=_on_unauthorized_command,
            width="stretch",
            disabled=not active,
        )

        st.button(
            "↻ Ripristina segnale",
            key="aeronix_restore_signal",
            on_click=_on_signal_restore,
            width="stretch",
            disabled=(
                not flight
                or status not in ("running", "paused")
                or not signal_lost
            ),
        )


        st.divider()
        st.caption(
            "Simulazione locale. I pulsanti non inviano comandi "
            "a droni reali."
        )



def render_notification_feed(flight):
    """Render a chat-like feed with automatic scroll on new notifications."""
    feed_items = flight["feed"] if flight else []
    cards = []

    # Track which notification IDs have already been displayed.
    # Each new alert animates once instead of replaying every second.
    run_id = flight.get("run_id", "idle") if flight else "idle"
    seen_key = f"aeronix_seen_notifications_{run_id}"
    previously_seen = list(st.session_state.get(seen_key, []))
    seen_ids = set(previously_seen)
    current_ids = [
        str(item.get("id", ""))
        for item in feed_items
        if item.get("id")
    ]
    new_ids = set(current_ids) - seen_ids
    animation_index = 0

    if not feed_items:
        cards.append(
            '<div class="empty">'
            '<div class="empty-icon">◷</div>'
            '<strong>Nessun evento</strong>'
            '<p>Le notifiche appariranno qui durante il volo.</p>'
            '</div>'
        )
    else:
        severity_classes = {
            "INFO": "info",
            "LOW": "low",
            "MEDIUM": "medium",
            "HIGH": "high",
            "CRITICAL": "critical",
        }

        for item in feed_items:
            severity = str(item.get("severita", "INFO")).upper()
            css_severity = severity_classes.get(severity, "info")

            title = html.escape(str(item.get("titolo", "Evento")))
            detail = html.escape(str(item.get("dettaglio", "")))
            timestamp = html.escape(str(item.get("ora", "")))
            component = html.escape(str(item.get("componente", "")))
            icon = html.escape(str(item.get("icona", "•")))
            event_id = html.escape(str(item.get("id", "")))
            raw_event_id = str(item.get("id", ""))

            is_new_alert = (
                raw_event_id in new_ids
                and (
                    severity in {"HIGH", "CRITICAL"}
                    or str(item.get("componente", "")).upper()
                    == "INCIDENTE CORRELATO"
                )
            )

            if is_new_alert:
                animation_class = " new-alert"
                animation_style = (
                    f' style="--alert-delay:{animation_index * 140}ms"'
                )
                animation_index += 1
            else:
                animation_class = ""
                animation_style = ""

            cards.append(
                f'<article class="event {css_severity}{animation_class}"'
                f'{animation_style} data-event-id="{event_id}">'
                f'<div class="event-title">'
                f'<span class="event-icon">{icon}</span>'
                f'<span>{title}</span>'
                f'</div>'
                f'<div class="event-meta">'
                f'<span class="event-time">◷ {timestamp}</span> · {component} · '
                f'{html.escape(SEVERITY_LABELS.get(severity, severity))}'
                f'</div>'
                f'<div class="event-detail">{detail}</div>'
                f'</article>'
            )

    content = "".join(cards)

    document = r"""
<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<style>
* { box-sizing: border-box; }

html, body {
    margin: 0;
    padding: 0;
    width: 100%;
    height: 100%;
    overflow: hidden;
    background: transparent;
    color: #20364F;
    font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
}

.feed {
    height: 100%;
    width: 100%;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 2px 8px 8px 2px;
    display: flex;
    flex-direction: column;
    gap: 9px;
    scrollbar-width: thin;
    scrollbar-color: #B9C9D8 transparent;
    overscroll-behavior: contain;
}

.event {
    flex: 0 0 auto;
    background: #FFFFFF;
    border: 1px solid #DCE6EF;
    border-left: 4px solid #90A4B8;
    border-radius: 10px;
    padding: 12px 12px 13px;
    overflow-wrap: anywhere;
}

.event.info { border-left-color: #7297B7; }
.event.low { border-left-color: #D6B34C; }
.event.medium { border-left-color: #D9923B; }
.event.high { border-left-color: #D45B60; }
.event.critical {
    border-left-color: #BD3546;
    background: #FFFAFA;
}

.event-title {
    display: flex;
    align-items: flex-start;
    gap: 7px;
    color: #1D3A59;
    font-size: 13px;
    line-height: 1.45;
    font-weight: 750;
}

.event-icon { flex: 0 0 auto; }

.event-meta {
    margin-top: 7px;
    color: #75899D;
    font-size: 10px;
    line-height: 1.4;
}

.event-time {
    display: inline-block;
    padding: 2px 5px;
    margin-right: 2px;
    border-radius: 5px;
    color: #405D7A;
    background: #EEF4F9;
    font-weight: 750;
}

@keyframes alertEntry {
    0% {
        opacity: 0;
        transform: translateY(12px) scale(0.985);
    }
    65% {
        opacity: 1;
        transform: translateY(-1px) scale(1.002);
    }
    100% {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
}

@keyframes alertPulse {
    0%, 100% {
        box-shadow: 0 0 0 0 rgba(207, 61, 75, 0);
    }
    35% {
        box-shadow: 0 0 0 4px rgba(207, 61, 75, 0.20);
    }
}

.event.new-alert {
    animation: alertEntry .72s cubic-bezier(.2,.75,.2,1) both;
    animation-delay: var(--alert-delay, 0ms);
}

.event.new-alert.high,
.event.new-alert.critical {
    animation-name: alertEntry, alertPulse;
    animation-duration: .72s, 1.25s;
    animation-timing-function: cubic-bezier(.2,.75,.2,1), ease-out;
    animation-delay: var(--alert-delay, 0ms), var(--alert-delay, 0ms);
    animation-fill-mode: both, both;
}

@media (prefers-reduced-motion: reduce) {
    .event.new-alert {
        animation: none !important;
    }
}

.event-detail {
    margin-top: 9px;
    color: #40566E;
    font-size: 12px;
    line-height: 1.55;
    white-space: pre-wrap;
}

.empty {
    min-height: 180px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    color: #71869B;
    text-align: center;
    padding: 22px;
}

.empty-icon { font-size: 25px; margin-bottom: 8px; }
.empty strong { color: #38536F; font-size: 13px; }
.empty p { font-size: 12px; line-height: 1.5; }

</style>
</head>
<body>
<div class="feed" id="notification-feed">
__CARDS__
</div>
<script>
(function () {
    const panel = document.getElementById("notification-feed");
    if (!panel) return;

    // Scroll only the notification panel, never the whole dashboard.
    // This runs when the feed HTML changes because a new event was added.
    function scrollToLatest() {
        panel.scrollTop = panel.scrollHeight;
    }

    requestAnimationFrame(function () {
        requestAnimationFrame(scrollToLatest);
    });
})();
</script>
</body>
</html>
"""

    document = document.replace("__CARDS__", content)

    # Keep the oldest notifications first and the newest at the bottom.
    merged_seen = list(dict.fromkeys(previously_seen + current_ids))
    st.session_state[seen_key] = merged_seen[-1000:]

    st.iframe(
        document,
        height=440,
        width="stretch",
        alt="Registro cronologico delle notifiche della missione",
    )


@st.fragment(run_every="1s")
def live_dashboard():
    """Primary mission view: large map, compact KPIs, fixed event feed."""
    flight = st.session_state.get("flight")

    if flight and flight["status"] == "running":
        update_flight(flight)

    st.markdown(
        """
        <style>
        .block-container {
            max-width: 1680px;
            padding-top: .25rem;
            padding-bottom: .45rem;
        }
        [data-testid="stAppViewContainer"], .stApp,
        [data-testid="stHeader"] {
            background:#F4F7FB !important;
            color:#20364F !important;
        }
        h1,h2,h3,h4,strong {
            color:#173858 !important;
        }
        p,label,[data-testid="stCaptionContainer"] {
            color:#40566E !important;
        }
        [data-testid="stMetric"] {
            background:#FFFFFF !important;
            border:1px solid #DCE6EF !important;
            border-radius:10px !important;
            padding:8px 12px !important;
            min-height:78px;
        }
        [data-testid="stMetricLabel"] {
            min-height:18px;
        }
        [data-testid="stMetricLabel"] {
            font-size:.82rem !important;
        }
        [data-testid="stMetricValue"] {
            color:#193B62 !important;
            font-size:1.65rem !important;
        }
        [data-testid="stSidebar"] {
            background:#F8FAFD !important;
        }
        div.stButton > button {
            border-radius:8px;
            font-weight:600;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "<h1 style='text-align:center;margin:0;color:#173858;'>"
        "AeroNix Guard</h1>"
        "<p style='text-align:center;margin:0 0 8px;color:#526A80;'>"
        "MONITORAGGIO DI VOLO · PISA → VIAREGGIO (LU)</p>",
        unsafe_allow_html=True,
    )

    # The detailed telemetry is outside the map to keep the route clear.
    metrics = st.columns(5, gap="small")

    if flight:
        state = STATE_LABELS.get(
            flight["mission_state"], flight["mission_state"]
        )
        progress = flight["actual_progress"]

        status_value = {
            "running": "In volo",
            "paused": "In pausa",
            "ended": "Terminato",
        }.get(flight["status"], flight["status"])

        metrics[0].metric("Stato missione", status_value)
        metrics[1].metric(
            "Velocità · ultimo dato",
            f"{flight['speed_kmh']:.0f} km/h",
        )
        metrics[2].metric(
            "Quota · ultimo dato",
            f"{flight['altitude_m']} m",
        )
        metrics[3].metric(
            "Batteria simulata",
            f"{flight['battery_percent']:.0f}%",
        )
        remaining_distance = (1 - progress) * ROUTE_DISTANCE_KM
        metrics[4].metric(
            "Distanza percorsa",
            f"{ROUTE_DISTANCE_KM * progress:.1f} km",
            help=f"Distanza residua: {remaining_distance:.1f} km",
        )
    else:
        metrics[0].metric("Stato missione", "In attesa")
        metrics[1].metric("Velocità", "—")
        metrics[2].metric("Quota", "—")
        metrics[3].metric("Batteria", "—")
        metrics[4].metric("Distanza percorsa", "0 km")

    # Main content: map gets approximately three quarters of the width.
    map_column, event_column = st.columns([2.15, 1.0], gap="small")

    with map_column:
        st.markdown("### Rotta e posizione")
        render_map_overlay(flight)

        if flight is None:
            st.caption(
                "Avvia un volo dal menu laterale. La mappa mostrerà "
                "il percorso rettilineo e la posizione GNSS simulata."
            )
        elif flight["signal_lost"]:
            st.warning(
                "GNSS non disponibile: la posizione sulla mappa è l'ultimo "
                "fix ricevuto. L'autopilota simulato avanza internamente."
            )
        else:
            st.caption(
                f"Coordinate GNSS: {flight['last_lat']:.5f}, "
                f"{flight['last_lon']:.5f} · "
                f"Satelliti: {flight['gnss_satellites']} · "
                f"Latenza: "
                f"{flight['latency_ms'] if flight['latency_ms'] is not None else 'N/D'} ms"
            )

        if flight and flight["mission_state"] == MissionState.RECOVERY_REQUIRED.value:
            st.info(
                "Segnale ripristinato. Il volo resta in attesa "
                "dell'autorizzazione al recovery."
            )

    with event_column:
        st.markdown("### Eventi e notifiche")
        render_notification_feed(flight)

        if flight:
            st.caption(
                f"{len(flight['feed'])} eventi · "
                f"{len(flight['incidents'])} incidenti"
            )

    if not flight:
        return

    # Technical details and full report are available below the live view.
    with st.expander(
        "Dettagli missione e coordinate",
        expanded=False,
    ):
        first, second, third = st.columns(3)
        first.write("**Partenza**")
        first.write("Pisa")
        first.caption(f"{PISA[0]:.6f}, {PISA[1]:.6f}")

        second.write("**Destinazione**")
        second.write("Viareggio (Lucca)")
        second.caption(f"{VIAREGGIO[0]:.6f}, {VIAREGGIO[1]:.6f}")

        third.write("**Stato sicurezza**")
        third.write(
            STATE_LABELS.get(
                flight["mission_state"], flight["mission_state"]
            )
        )
        third.caption(f"ID volo: {flight['run_id']}")

        if flight["incidents"]:
            st.markdown("#### Incidenti correlati")
            for incident in reversed(flight["incidents"]):
                with st.container(border=True):
                    st.markdown(f"**{incident.title}**")
                    st.caption(
                        f"{SEVERITY_LABELS.get(incident.severity.value, incident.severity.value)}"
                        f" · {incident.incident_id}"
                    )
                    st.write(incident.summary)
                    st.write(
                        f"Azione proposta: {incident.recommended_action}"
                    )

    with st.expander(
        "📋 Registro completo e report del volo",
        expanded=(flight["status"] == "ended"),
    ):
        if flight["status"] != "ended":
            st.info(
                "Il report definitivo sarà disponibile quando termini il volo. "
                "Gli eventi correnti restano visibili nel pannello a destra."
            )

        if flight["register"]:
            st.dataframe(
                list(reversed(flight["register"])),
                width="stretch",
                hide_index=True,
            )

            output = io.StringIO()
            fieldnames = list(flight["register"][0].keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flight["register"])

            st.download_button(
                "Esporta registro completo in CSV",
                data=output.getvalue().encode("utf-8"),
                file_name=f"aeronix-flight-{flight['run_id']}.csv",
                mime="text/csv",
                width="stretch",
            )
        else:
            st.caption("Nessun evento registrato.")

    if flight["audit_errors"]:
        st.error(
            "Alcuni eventi non sono stati scritti nel file di audit. "
            "Il registro in memoria resta disponibile."
        )
        with st.expander("Dettagli degli errori di audit"):
            for error in flight["audit_errors"]:
                st.code(error)

    st.caption(
        "AeroNix Guard · Demo locale · Telemetria e autopilota simulati. "
        "Nessun collegamento a un drone reale."
    )


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="AeroNix Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

sidebar_controls()
live_dashboard()
