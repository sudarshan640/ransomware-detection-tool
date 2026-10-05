# Ransomware Detection Toolkit (Windows-focused prototype)

A research-oriented Windows ransomware detection prototype built in Python. This project focuses on rule-based behavioral detection for suspicious file encryption, process abuse, and persistence-related activity. It is intended for cybersecurity learning, demos, and internal lab exercises, not for production endpoint deployment.

## Features

- Detects suspicious file-encryption patterns
- Flags rapid file modifications across many files
- Identifies common ransomware process behaviors
- Monitors for ransom-note creation or execution patterns
- Scans JSON event streams and simulated telemetry
- Produces severity levels and actionable alerts
- Lightweight CLI with sample demo mode

## Project structure

- `main.py` – CLI entry point
- `src/ransomware_detector/detector.py` – detection logic
- `src/ransomware_detector/simulator.py` – synthetic event generation
- `examples/sample_events.json` – sample detections and benign activity

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# or .venv\Scripts\activate  # Windows
pip install -r requirements.txt
PYTHONPATH=src python main.py simulate --events 200
PYTHONPATH=src python main.py scan --file examples/sample_events.json
```

## Example commands

```bash
PYTHONPATH=src python main.py simulate --events 100 --seed 7
PYTHONPATH=src python main.py scan --file examples/sample_events.json --format json
PYTHONPATH=src python main.py scan --file examples/sample_events.json --format text
```

## Detection logic

The detector evaluates events such as:

- file rename or file write count spikes
- many files changed within a short period
- suspicious file extensions (`.locked`, `.encrypted`, `.crypt`, `.ransom`)
- suspicious commands such as `vssadmin`, `wbadmin`, `powershell`, `cmd`, or `certutil`
- ransom-note file creation patterns
- registry or service changes often used for persistence
- mass encryption speed and volume thresholds

## Alert severity

- `INFO` – low-risk or informational activity
- `WARNING` – suspicious but inconclusive behavior
- `CRITICAL` – likely ransomware-like actions

## Notes

This prototype is intentionally rule-based and conservative. It is designed for classroom and research use. For real deployments, a production-grade solution should include:

- EDR/telemetry integration
- Windows Event Log correlation
- YARA/AV signature review
- Safe incident response workflows
- Controlled testing in an isolated lab environment

## License

MIT
