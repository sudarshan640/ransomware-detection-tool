#!/usr/bin/env python3
"""CLI for the ransomware detection prototype."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ransomware_detector.detector import RansomwareDetector
from ransomware_detector.simulator import generate_sample_events


def _load_events(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("events", [])
    raise ValueError("Input file must contain a list of events or an object with an 'events' key.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows-focused ransomware detector prototype")
    parser.add_argument("command", choices=["scan", "simulate"], help="Action to perform")
    parser.add_argument("--file", type=str, help="Path to a JSON file with events")
    parser.add_argument("--events", type=int, default=150, help="Number of events to generate in simulation mode")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic sample generation")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    detector = RansomwareDetector()

    if args.command == "simulate":
        events = generate_sample_events(args.events, args.seed)
        findings = detector.analyze(events)
        if args.format == "json":
            print(json.dumps(findings, indent=2))
        else:
            for item in findings:
                print(f"[{item['severity']}] {item['title']} | {item['details']}")
        return

    if not args.file:
        raise ValueError("Please provide --file when using the scan command.")

    events = _load_events(args.file)
    findings = detector.analyze(events)
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        for item in findings:
            print(f"[{item['severity']}] {item['title']} | {item['details']}")


if __name__ == "__main__":
    main()
