#!/usr/bin/env python3
"""
Data Validation Script for Cybersecurity Data Engineering
Validates all generated log types against ECS schema and data quality rules.
Covers all log types: network, DNS, Suricata, Windows, Sysmon, PowerShell,
Linux syslog, Rsyslog, Firewall, Threat Intel, Application, Kafka, Logstash.
"""

import json
import re
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import logging

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== SCHEMAS ====================

# Required ECS base fields present in every event
ECS_REQUIRED_FIELDS = ["@timestamp", "event", "ecs"]

# Per-dataset required fields
DATASET_REQUIRED_FIELDS = {
    "zeek.connection":       ["source.ip", "destination.ip", "network.protocol"],
    "zeek.dns":              ["dns.question.name", "dns.response_code"],
    "suricata.alert":        ["rule.name", "source.ip", "destination.ip"],
    "windows.security":      ["winlog.event_id", "winlog.computer_name"],
    "sysmon.operational":    ["winlog.event_id", "process.name"],
    "windows.powershell":    ["winlog.event_data.ScriptBlockText"],
    "linux.syslog":          ["message", "host.name"],
    "linux.syslog.structured": ["message"],
    "firewall.iptables":     ["source.ip", "destination.ip", "event.action"],
    "threatintel.indicator": ["threat.indicator.type"],
    "application.access":    ["http.request.method", "http.response.status_code"],
}

# Timestamp pattern
TS_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

# Known valid event datasets
KNOWN_DATASETS = set(DATASET_REQUIRED_FIELDS.keys()) | {
    "application.access", "kafka_pipeline", "logstash_enriched"
}


# ==================== VALIDATOR ====================

class DataValidator:

    def __init__(self):
        self.results: Dict[str, Any] = {
            "total_events": 0,
            "valid_events": 0,
            "invalid_events": 0,
            "errors": [],
            "dataset_counts": defaultdict(int),
            "attack_events": 0,
            "files_processed": 0
        }

    # ---- Core validation helpers ----

    def _get_nested(self, obj: Dict, dotpath: str) -> Any:
        """Retrieve a nested field using dot-notation path."""
        parts = dotpath.split(".")
        cur = obj
        for p in parts:
            if not isinstance(cur, dict) or p not in cur:
                return None
            cur = cur[p]
        return cur

    def _check_timestamp(self, event: Dict) -> List[str]:
        errors = []
        ts = event.get("@timestamp")
        if not ts:
            errors.append("Missing @timestamp")
        elif not TS_PATTERN.match(str(ts)):
            errors.append(f"Invalid @timestamp format: {ts!r}")
        return errors

    def _check_ecs_base(self, event: Dict) -> List[str]:
        errors = []
        for field in ECS_REQUIRED_FIELDS:
            if self._get_nested(event, field) is None:
                errors.append(f"Missing required ECS field: {field}")
        event_obj = event.get("event", {})
        if not isinstance(event_obj, dict):
            errors.append("'event' field must be an object")
        elif "dataset" not in event_obj:
            errors.append("Missing event.dataset")
        return errors

    def _check_dataset_fields(self, event: Dict, dataset: str) -> List[str]:
        errors = []
        required = DATASET_REQUIRED_FIELDS.get(dataset, [])
        for field in required:
            if self._get_nested(event, field) is None:
                errors.append(f"Missing dataset-required field: {field}")
        return errors

    def _check_network_fields(self, event: Dict) -> List[str]:
        errors = []
        src_ip = self._get_nested(event, "source.ip")
        dst_ip = self._get_nested(event, "destination.ip")
        for label, ip in [("source.ip", src_ip), ("destination.ip", dst_ip)]:
            if ip is not None:
                parts = str(ip).split(".")
                if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    errors.append(f"Invalid IP in {label}: {ip!r}")
        return errors

    def _check_windows_event(self, event: Dict) -> List[str]:
        errors = []
        event_id = self._get_nested(event, "winlog.event_id")
        if event_id is not None and not isinstance(event_id, int):
            errors.append(f"winlog.event_id should be int, got {type(event_id).__name__}")
        return errors

    def _check_threat_intel(self, event: Dict) -> List[str]:
        errors = []
        itype = self._get_nested(event, "threat.indicator.type")
        valid_types = {"ip", "domain", "hash", "url"}
        if itype and itype not in valid_types:
            errors.append(f"threat.indicator.type must be one of {valid_types}, got {itype!r}")
        return errors

    def validate_event(self, event: Dict) -> Tuple[bool, List[str]]:
        """Validate a single event. Returns (is_valid, [errors])."""
        errors: List[str] = []
        errors.extend(self._check_timestamp(event))
        errors.extend(self._check_ecs_base(event))
        if errors:
            return False, errors

        dataset = self._get_nested(event, "event.dataset") or ""
        errors.extend(self._check_dataset_fields(event, dataset))

        # Type-specific checks
        if "network" in dataset or "connection" in dataset or "firewall" in dataset:
            errors.extend(self._check_network_fields(event))
        if "windows" in dataset or "sysmon" in dataset:
            errors.extend(self._check_windows_event(event))
        if "threatintel" in dataset:
            errors.extend(self._check_threat_intel(event))

        return len(errors) == 0, errors

    # ---- File and directory validation ----

    def validate_file(self, filepath: Path) -> Dict:
        result = {
            "file": str(filepath),
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "errors": [],
            "datasets": defaultdict(int),
            "attack_events": 0
        }

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    result["total"] += 1
                    try:
                        event = json.loads(line)
                        is_valid, errs = self.validate_event(event)
                        if is_valid:
                            result["valid"] += 1
                            dataset = self._get_nested(event, "event.dataset") or "unknown"
                            result["datasets"][dataset] += 1
                            if event.get("labels", {}).get("attack_type"):
                                result["attack_events"] += 1
                        else:
                            result["invalid"] += 1
                            result["errors"].append({
                                "line": line_num,
                                "errors": errs
                            })
                    except json.JSONDecodeError as e:
                        result["invalid"] += 1
                        result["errors"].append({"line": line_num, "errors": [f"JSON error: {e}"]})
                    except Exception as e:
                        result["invalid"] += 1
                        result["errors"].append({"line": line_num, "errors": [f"Unexpected: {e}"]})
        except IOError as e:
            result["errors"].append({"line": 0, "errors": [f"File read error: {e}"]})

        return result

    def validate_directory(self, directory: Path, pattern: str = "*.ndjson") -> Dict:
        files = sorted(directory.glob(pattern))
        if not files:
            logger.warning(f"No {pattern} files found in {directory}")
            return {"directory": str(directory), "files": [], "total_events": 0, "valid_events": 0, "invalid_events": 0}

        agg = {
            "directory": str(directory),
            "files": [],
            "total_events": 0,
            "valid_events": 0,
            "invalid_events": 0,
            "total_errors": 0,
            "dataset_counts": defaultdict(int),
            "attack_events": 0,
            "files_processed": 0
        }

        for fp in files:
            result = self.validate_file(fp)
            agg["files"].append(result)
            agg["total_events"] += result["total"]
            agg["valid_events"] += result["valid"]
            agg["invalid_events"] += result["invalid"]
            agg["total_errors"] += len(result["errors"])
            agg["attack_events"] += result.get("attack_events", 0)
            agg["files_processed"] += 1
            for ds, count in result.get("datasets", {}).items():
                agg["dataset_counts"][ds] += count

        return agg

    # ---- Reporting ----

    def generate_report(self, results: Dict) -> str:
        total = results["total_events"]
        valid = results["valid_events"]
        invalid = results["invalid_events"]
        pct = (valid / total * 100) if total > 0 else 0.0

        lines = [
            "=" * 50,
            "DATA VALIDATION REPORT",
            "=" * 50,
            f"Directory:     {results.get('directory', 'N/A')}",
            f"Files:         {results.get('files_processed', len(results.get('files', [])))}",
            f"Total Events:  {total:,}",
            f"Valid:         {valid:,}  ({pct:.1f}%)",
            f"Invalid:       {invalid:,}",
            f"Total Errors:  {results.get('total_errors', 0)}",
            f"Attack Events: {results.get('attack_events', 0):,}",
            ""
        ]

        # Dataset breakdown
        ds_counts = results.get("dataset_counts", {})
        if ds_counts:
            lines.append("Dataset Breakdown:")
            lines.append("-" * 40)
            for ds, count in sorted(ds_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {ds:<35} {count:>8,}")
            lines.append("")

        # Per-file summary (show only problematic files)
        problem_files = [f for f in results.get("files", []) if f.get("invalid", 0) > 0]
        if problem_files:
            lines.append(f"Files with Errors ({len(problem_files)}):")
            lines.append("-" * 40)
            for fr in problem_files[:20]:  # Show up to 20
                name = Path(fr["file"]).name
                lines.append(f"  {name}: {fr['valid']}/{fr['total']} valid, {len(fr['errors'])} errors")
                for err in fr["errors"][:3]:
                    lines.append(f"    Line {err['line']}: {'; '.join(err['errors'])}")

        lines.append("=" * 50)
        return "\n".join(lines)

    def check_coverage(self, results: Dict) -> List[str]:
        """Check that all expected log types are present (data completeness)."""
        expected_datasets = set(DATASET_REQUIRED_FIELDS.keys())
        found_datasets = set(results.get("dataset_counts", {}).keys())
        missing = expected_datasets - found_datasets
        warnings = []
        if missing:
            for ds in sorted(missing):
                warnings.append(f"Missing dataset coverage: {ds}")
        return warnings


# ==================== MAIN ====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate generated cybersecurity data")
    parser.add_argument("--directory", "-d", default="../historical_data/",
                        help="Directory containing .ndjson data files")
    parser.add_argument("--streaming", "-s", default=None,
                        help="Also validate streaming data directory")
    parser.add_argument("--output", "-o", default="validation_report.txt",
                        help="Output report file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show per-file error details")
    args = parser.parse_args()

    validator = DataValidator()

    # Validate historical data
    hist_dir = Path(args.directory)
    if not hist_dir.exists():
        logger.error(f"Directory not found: {hist_dir}")
        sys.exit(1)

    print(f"Validating historical data in {hist_dir}...")
    hist_results = validator.validate_directory(hist_dir)
    report = validator.generate_report(hist_results)
    print(report)

    # Coverage check
    warnings = validator.check_coverage(hist_results)
    if warnings:
        print("Coverage Warnings:")
        for w in warnings:
            print(f"  ⚠  {w}")

    # Optionally validate streaming data
    if args.streaming:
        stream_dir = Path(args.streaming)
        if stream_dir.exists():
            print(f"\nValidating streaming data in {stream_dir}...")
            stream_results = validator.validate_directory(stream_dir)
            stream_report = validator.generate_report(stream_results)
            print(stream_report)
            report += "\n\n" + stream_report

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nReport saved to {args.output}")
