from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List


class RansomwareDetector:
    """Rule-based Windows ransomware heuristic detector."""

    def __init__(self) -> None:
        self.suspicious_extensions = {
            ".locked",
            ".encrypted",
            ".crypt",
            ".ransom",
            ".id_",
            ".bitlocker",
            ".!decrypt",
        }
        self.suspicious_processes = {
            "powershell",
            "cmd",
            "certutil",
            "vssadmin",
            "wbadmin",
            "bcdedit",
            "reg",
            "rundll32",
            "wmic",
        }
        self.ransom_note_markers = {
            "decrypt",
            "pay",
            "bitcoin",
            "ransom",
            "restore",
            "recover",
            "unlock",
        }

    def analyze(self, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        file_events = []
        process_events = []
        registry_events = []
        note_events = []

        for event in events:
            event_type = str(event.get("type", "")).lower()
            if event_type in {"file", "file_write", "file_rename", "file_delete"}:
                file_events.append(event)
            elif event_type in {"process", "execution", "command"}:
                process_events.append(event)
            elif event_type in {"registry", "service", "persistence"}:
                registry_events.append(event)
            elif event_type in {"note", "ransom_note", "text"}:
                note_events.append(event)

        settings = {
            "rapid_file_threshold": 50,
            "time_window_seconds": 30,
            "suspicious_process_threshold": 2,
        }

        rapid_file_count = self._count_rapid_file_activity(file_events, settings)
        if rapid_file_count > 0:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "title": "Rapid file encryption pattern detected",
                    "details": f"Observed {rapid_file_count} file changes in a short time window, a common ransomware behavior.",
                }
            )

        suspicious_extensions = self._count_suspicious_extensions(file_events)
        if suspicious_extensions > 0:
            findings.append(
                {
                    "severity": "WARNING",
                    "title": "Suspicious encrypted-file naming detected",
                    "details": f"Detected {suspicious_extensions} files using suspicious extension patterns.",
                }
            )

        suspicious_process_hits = self._detect_suspicious_process_activity(process_events)
        if suspicious_process_hits:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "title": "Suspicious process execution chain detected",
                    "details": "; ".join(suspicious_process_hits),
                }
            )

        if self._detect_shadow_copy_activity(process_events, registry_events):
            findings.append(
                {
                    "severity": "CRITICAL",
                    "title": "Possible shadow-copy deletion or backup disruption observed",
                    "details": "System recovery mechanisms may be under attack.",
                }
            )

        if self._detect_ransom_note(note_events):
            findings.append(
                {
                    "severity": "CRITICAL",
                    "title": "Ransom note pattern detected",
                    "details": "An instruction or message resembling a ransom note was created or executed.",
                }
            )

        if not findings:
            findings.append(
                {
                    "severity": "INFO",
                    "title": "No ransomware indicators detected",
                    "details": "The evaluated telemetry does not currently match typical ransomware behavior.",
                }
            )

        return findings

    def _count_rapid_file_activity(self, events: List[Dict[str, Any]], settings: Dict[str, Any]) -> int:
        if not events:
            return 0

        bucket: Dict[float, int] = defaultdict(int)
        for event in events:
            timestamp = self._event_ts(event)
            if timestamp is None:
                continue
            bucket[round(timestamp, 0)] += 1

        max_per_bucket = max(bucket.values(), default=0)
        return max_per_bucket if max_per_bucket >= settings["rapid_file_threshold"] else 0

    def _count_suspicious_extensions(self, events: List[Dict[str, Any]]) -> int:
        count = 0
        for event in events:
            path = str(event.get("path", ""))
            if any(path.lower().endswith(ext) for ext in self.suspicious_extensions):
                count += 1
        return count

    def _detect_suspicious_process_activity(self, events: List[Dict[str, Any]]) -> List[str]:
        hits: List[str] = []
        for event in events:
            command = str(event.get("command", "") or event.get("name", "")).lower()
            if not command:
                continue
            matched = [proc for proc in self.suspicious_processes if proc in command]
            if matched:
                hits.append(f"Suspicious process pattern: {command}")
        return hits[:5]

    def _detect_shadow_copy_activity(self, process_events: List[Dict[str, Any]], registry_events: List[Dict[str, Any]]) -> bool:
        for event in process_events:
            command = str(event.get("command", "") or event.get("name", "")).lower()
            if "vssadmin" in command or "wbadmin" in command or "bcdedit" in command:
                return True
        for event in registry_events:
            key = str(event.get("key", "") or event.get("path", "")).lower()
            if "shadow" in key or "volume" in key or "backup" in key:
                return True
        return False

    def _detect_ransom_note(self, events: List[Dict[str, Any]]) -> bool:
        for event in events:
            content = str(event.get("content", "") or event.get("message", "") or event.get("name", "")).lower()
            if any(marker in content for marker in self.ransom_note_markers):
                return True
        return False

    @staticmethod
    def _event_ts(event: Dict[str, Any]) -> float | None:
        ts = event.get("timestamp")
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            return float(ts)
        try:
            return datetime.fromisoformat(str(ts)).timestamp()
        except ValueError:
            return None
