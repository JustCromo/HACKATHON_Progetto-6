# AeroNix Guard

**Cybersecurity and mission-safety monitoring for simulated autonomous medical-drone missions.**

AeroNix Guard is a hackathon prototype demonstrating telemetry monitoring, intrusion detection, incident correlation, command validation and safety-state management in a single operational dashboard.

## Features

- **Flight monitoring:** simulated route from Pisa to Viareggio, GNSS coordinates, speed, altitude, battery and communication latency.
- **Intrusion detection:** detection of suspicious navigation telemetry, heartbeat loss and unauthorized command attempts.
- **Secure command gateway:** rejection of commands from untrusted senders.
- **Incident correlation:** grouping related events into incidents with severity, explanation and proposed response.
- **Safety state machine:** simulated transitions between NORMAL, DEGRADED, SAFE_MODE and RECOVERY_REQUIRED.
- **Contingency simulation:** internal route estimation during GNSS and communication loss, distinct from the last valid GNSS position.
- **Audit trail:** JSON Lines records and CSV export of flight reports.
- **Interactive dashboard:** route visualization, telemetry overlays, notifications and manual security scenarios.

## Quick start

Requirements: Python and pip.

Create an environment and install dependencies:

    git clone <YOUR_REPOSITORY_URL>
    cd AeroNix-Guard
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python scripts/generate_map.py
    streamlit run app.py

Streamlit prints the local dashboard URL when the application starts.

## Project structure

    AeroNix-Guard/
    ├── app.py
    ├── models.py
    ├── simulator.py
    ├── detectors.py
    ├── gateway.py
    ├── correlation.py
    ├── safety.py
    ├── audit.py
    ├── requirements.txt
    ├── assets/
    │   └── pisa_viareggio_map.png
    ├── scripts/
    │   └── generate_map.py
    ├── data/
    │   └── .gitkeep
    └── .streamlit/
        └── config.toml

## Demonstration scenarios

1. **Unauthorized command:** the gateway rejects an untrusted sender, the IDS records the attempt, and the correlation engine creates an incident.
2. **Navigation and communication anomaly:** simulated GNSS deviation and heartbeat loss are correlated, triggering the configured safety response.
3. **Signal restoration:** the simulated position is reconciled with the contingency route estimate and recovery is recorded.

## Limitations

**This is a simulation prototype, not a certified flight-control or medical-transport system.**

- All telemetry, network conditions and security events are synthetic.
- The map is schematic, not a live navigation map.
- The contingency autopilot demonstrates route estimation; it is not a validated navigation algorithm.
- Gateway identity checks and recovery authorization are not production authentication mechanisms.
- The prototype does not control or monitor a real drone, ABzero capsule or medical cargo.
- The audit file is an application log, not a tamper-proof forensic store.

Real-world deployment would require system documentation, trusted cryptographic identity mechanisms, validated fail-safe requirements, hardware-in-the-loop testing and appropriate safety validation.

## Technology

- Python
- Streamlit
- Pillow

## Project status

Hackathon prototype — under active development.
