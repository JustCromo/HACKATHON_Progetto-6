# AeroNix Guard

**Cybersecurity and mission-safety monitoring for simulated autonomous medical-drone missions.**

AeroNix Guard is a cybersecurity hackathon prototype designed to demonstrate how security monitoring, intrusion detection, incident correlation and safety-state management can work together during a simulated autonomous medical-drone mission.

The project combines a simulated flight environment with a defensive monitoring dashboard. It allows operators to observe telemetry, investigate suspicious events, simulate security incidents and inspect the system's response through a single interface.

The prototype focuses on the intersection of **cybersecurity, autonomous systems and mission safety**, with particular attention to communication loss, navigation anomalies, unauthorized commands and recovery procedures.

> **Disclaimer:** AeroNix Guard is a simulation prototype. It is not a certified flight-control system, does not control a real drone and must not be used to make operational decisions involving real aircraft or medical cargo.

## Table of Contents

- [Project Goals](#project-goals)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Demonstration Scenarios](#demonstration-scenarios)
- [Technology Stack](#technology-stack)
- [Requirements](#requirements)
- [Installation and Quick Start](#installation-and-quick-start)
- [Project Structure](#project-structure)
- [Security and Safety Limitations](#security-and-safety-limitations)
- [Future Development](#future-development)
- [Project Status](#project-status)

## Project Goals

AeroNix Guard explores how a monitoring layer could help an operator understand and respond to security-related events during a simulated autonomous mission.

The main objectives are:

- **Mission visibility:** present flight telemetry and communication conditions in an interactive dashboard.
- **Threat detection:** identify simulated navigation anomalies, heartbeat loss and unauthorized command attempts.
- **Incident correlation:** group related events into incidents with meaningful explanations and severity.
- **Safety-state awareness:** represent degraded operation, safe-mode transitions and recovery requirements.
- **Operator assistance:** provide notifications and contextual information to support incident investigation.
- **Auditability:** record application events and support report export for later analysis.

The goal is to demonstrate a coherent monitoring workflow rather than a collection of disconnected security checks.

## Key Features

### 1. Flight and Telemetry Monitoring

The application simulates a medical-drone mission along a route between Pisa and Viareggio.

The dashboard presents simulated flight information, including:

- GNSS coordinates and estimated position.
- Flight speed and altitude.
- Battery level.
- Communication latency and heartbeat status.
- Route visualization and telemetry overlays.

The map provides geographical context for the simulation. All mission telemetry is synthetic and should not be interpreted as live flight information.

### 2. Intrusion Detection

The detection components evaluate simulated events and identify conditions that may indicate a security or mission-integrity problem.

Demonstration cases include:

- Suspicious navigation telemetry.
- Communication heartbeat loss.
- Unauthorized command attempts.
- Related events affecting the availability or integrity of the simulated mission.

Detection events can be passed to the incident-correlation workflow so that the operator can review them in context.

### 3. Command Validation Gateway

The command gateway evaluates simulated commands and rejects commands from untrusted senders according to the prototype's configured rules.

The gateway demonstrates a defensive control point between incoming commands and the simulated mission environment.

Rejected commands can generate security events that are subsequently presented to the monitoring and incident-management components.

**Scope limitation:** the gateway demonstrates command validation concepts. It does not provide production-grade cryptographic identity verification, secure key management or a complete authorization system.

### 4. Incident Correlation

Individual alerts can provide limited context when viewed in isolation. AeroNix Guard includes a correlation component intended to group related security and mission events into incidents.

Incident information can include:

- Severity classification.
- Related events.
- Human-readable explanations.
- Proposed responses.

This helps demonstrate how raw detection events can be transformed into a more understandable operational picture for an operator.

### 5. Safety-State Management

The safety component models the simulated mission's response state.

The prototype includes the following states:

| State | Description |
|---|---|
| `NORMAL` | Normal simulated operation. |
| `DEGRADED` | The simulated mission is affected by an anomaly. |
| `SAFE_MODE` | A configured simulated safety response is active. |
| `RECOVERY_REQUIRED` | Recovery action is required before the system can return to normal operation. |

These states are application-level representations used to demonstrate safety-oriented logic. They are not certified flight-control modes, and their behavior should not be interpreted as a validated safety system.

### 6. GNSS and Communication-Loss Simulation

AeroNix Guard demonstrates how loss of navigation information and communication availability can affect the monitoring workflow.

The simulation distinguishes between:

- The last valid GNSS position.
- The internally estimated position used by the contingency simulation.

During simulated signal loss, the contingency estimate can advance independently of the last valid GNSS fix. When the signal is restored, the application demonstrates position reconciliation and recovery behavior.

This separation makes it possible to show the difference between a previously received position and an internally estimated position.

The contingency route estimate is illustrative only. It is not a validated navigation algorithm and does not establish the true position of a real aircraft.

### 7. Audit Trail and Reporting

The audit component records application events in JSON Lines format, allowing individual records to be stored as newline-delimited JSON entries.

The prototype also supports CSV export of flight reports.

These features support demonstration reviews and basic event analysis. The audit log is not a tamper-proof forensic store and does not provide cryptographic integrity guarantees.

### 8. Interactive Monitoring Dashboard

The Streamlit dashboard brings the principal simulation and monitoring components together.

The interface supports:

- Mission and route visualization.
- Telemetry monitoring.
- Security notifications.
- Incident information.
- Safety-state visualization.
- Manual security-scenario simulation.
- Event review and audit-related information.

The dashboard is intended to make the interaction between simulated mission conditions, security findings and safety responses visible during a demonstration.

## Architecture

The codebase is organized into Python modules with distinct responsibilities.

| Component | Responsibility |
|---|---|
| `app.py` | Streamlit dashboard, operator interaction and presentation of monitoring information. |
| `models.py` | Data models used to represent application information. |
| `simulator.py` | Synthetic mission and telemetry simulation. |
| `detectors.py` | Detection of simulated security and mission anomalies. |
| `gateway.py` | Simulated command validation and rejection. |
| `correlation.py` | Correlation of related events into incidents. |
| `safety.py` | Safety-state management and configured response logic. |
| `audit.py` | Audit-event recording and report export. |
| `scripts/generate_map.py` | Generation of the schematic route map. |

### Conceptual Event Flow

The intended monitoring workflow follows this sequence:

1. **Simulation:** the mission simulator produces synthetic telemetry and events.
2. **Evaluation:** detection components assess relevant conditions, while the command gateway evaluates incoming simulated commands.
3. **Event generation:** suspicious conditions and rejected commands can produce security events.
4. **Correlation:** related events are grouped into incidents.
5. **Safety response:** the safety component manages the configured simulated response state.
6. **Visualization:** the dashboard presents telemetry, notifications, incidents and state changes.
7. **Audit:** application events are recorded for later review.

This is a conceptual overview of the prototype. The actual implementation and event handling are defined by the code in each module.

## Demonstration Scenarios

AeroNix Guard includes manual controls for exercising key security and mission-safety behaviors.

### Scenario 1 — Unauthorized Command

**Objective:** demonstrate command validation and security-event handling.

The simulated environment receives a command from an untrusted sender. The gateway rejects the command, the detection workflow records the attempted action and the correlation component can create an incident from the resulting event.

The dashboard allows the operator to inspect the security notification and its associated context.

### Scenario 2 — Navigation Anomaly and Communication Loss

**Objective:** demonstrate the relationship between suspicious telemetry, availability problems and safety-state management.

The simulation introduces a navigation anomaly and communication heartbeat loss. The monitoring components evaluate the resulting conditions, related events can be correlated and the configured safety logic demonstrates the corresponding response.

The scenario illustrates how several related events can be considered together instead of being reviewed as isolated alerts.

### Scenario 3 — Signal Restoration and Recovery

**Objective:** demonstrate the recovery workflow after a simulated signal interruption.

When the signal is restored, the application demonstrates reconciliation between the last valid GNSS position and the internal contingency estimate, followed by the recording of recovery-related behavior.

This scenario focuses on observability and state management rather than validating real-world navigation or recovery procedures.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic, simulation and security-monitoring components. |
| Streamlit | Interactive monitoring dashboard. |
| Pillow | Image processing and support for the generated route map. |
| JSON Lines | Local audit-event storage. |
| CSV | Flight-report export. |
| Git and GitHub | Source-code version control and project collaboration. |

## Requirements

To run the prototype, you need:

- Python installed on your system.
- `pip` for dependency installation.
- The project source files.
- The dependencies specified in `requirements.txt`.

Using a virtual environment is recommended to keep project dependencies separate from system Python packages.

## Installation and Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/JustCromo/HACKATHON_Progetto-6.git
cd HACKATHON_Progetto-6
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Launch the dashboard

```bash
streamlit run app.py
```

When the application starts, Streamlit prints a local URL in the terminal. Open that address in your browser to access the dashboard.

### Optional: Regenerate the Route Map

The repository includes a generated map at `assets/pisa_viareggio_map.png`.

To regenerate it, run:

```bash
python scripts/generate_map.py
```

Then start or restart the dashboard as necessary.

## Project Structure

The main project files are organized as follows:

```text
HACKATHON_Progetto-6/
├── .streamlit/
│   └── config.toml
├── assets/
│   └── pisa_viareggio_map.png
├── data/
│   └── .gitkeep
├── scripts/
│   └── generate_map.py
├── app.py
├── audit.py
├── correlation.py
├── detectors.py
├── gateway.py
├── models.py
├── requirements.txt
├── safety.py
├── simulator.py
├── README.md
├── AeroNixGuard_presentation.html
├── LICENSE
└── .gitignore
```

The structure above describes the principal project files. Local runtime artifacts, temporary files and development backups are not intended to be part of the published source tree.

## Security and Safety Limitations

AeroNix Guard is an experimental hackathon prototype. It must not be treated as a production-ready cybersecurity product, certified flight-control system or medical-transport solution.

The following limitations are important:

- **Synthetic data:** telemetry, network conditions and security events are simulated.
- **Schematic navigation:** the route map is not a live navigation map.
- **Unvalidated contingency logic:** the estimated route position is illustrative and has not been validated for real flight.
- **Prototype command security:** command validation is not a substitute for cryptographic authentication and authorization.
- **Uncertified safety behavior:** the modeled states and transitions do not establish compliance with aviation safety requirements.
- **No real-world integration:** the application does not control or monitor a real drone, an ABzero capsule or medical cargo.
- **Limited audit guarantees:** application logs are not guaranteed to be tamper-proof or forensically complete.
- **No operational assurance:** the prototype has not established the reliability, resilience or safety properties required for deployment.

A real-world implementation would require, at minimum:

- Clearly specified security and safety requirements.
- A documented threat model and security architecture.
- Trusted cryptographic identities and secure key management.
- Validated command authorization and replay protection.
- Defined and tested fail-safe behavior.
- Hardware-in-the-loop and integration testing.
- Failure analysis, recovery testing and operational validation.
- Appropriate aviation, cybersecurity and medical-system safety assessments.

These are areas for future investigation, not capabilities claimed by the current prototype.

## Future Development

Potential areas for further development include:

- More structured and testable detection rules.
- Expanded incident-correlation logic.
- Additional network and mission-failure scenarios.
- Improved separation between simulation, detection and presentation layers.
- More comprehensive unit and integration tests.
- Structured event schemas and clearer audit semantics.
- Reproducible scenario execution and automated demonstration tests.
- Stronger identity and authorization models for a future non-simulated environment.

These are possible development directions and should not be interpreted as features already implemented.

## Project Status

**Hackathon prototype — under active development.**

AeroNix Guard demonstrates how simulated mission telemetry, defensive security monitoring, incident correlation and safety-state visualization can be combined in one interactive application.

The project is intended for educational purposes, cybersecurity experimentation and hackathon demonstration. It does not establish that the same mechanisms are suitable for controlling or protecting real autonomous aircraft.

## Repository

GitHub: https://github.com/JustCromo/HACKATHON_Progetto-6

