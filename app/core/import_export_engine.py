# app/core/import_export_engine.py
"""Import/Export Engine for common penetration testing formats.

Supports parsing and exporting findings in Nessus XML, Burp Suite XML,
SARIF JSON, CSV, and plain JSON formats. Handles malformed records
gracefully by logging warnings and continuing processing.
"""

import csv
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.logger import logger


@dataclass
class ImportRecord:
    """Normalized record from any import format."""

    host: str = ""
    port: int = 0
    vulnerability_name: str = ""
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    source_format: str = ""
    raw_data: Dict = field(default_factory=dict)


# Nessus severity mapping: numeric level -> label
NESSUS_SEVERITY_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}

# Burp severity normalization
BURP_SEVERITY_MAP = {
    "information": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
}

# SARIF severity normalization
SARIF_SEVERITY_MAP = {
    "none": "info",
    "note": "info",
    "warning": "medium",
    "error": "high",
}


class ImportExportEngine(QObject):
    """Engine for importing and exporting findings in industry-standard formats.

    Signals:
        import_progress(int, int): Emitted during import with (current, total) counts.
        import_warning(str): Emitted when a malformed record is skipped.
    """

    import_progress = pyqtSignal(int, int)
    import_warning = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def parse_nessus_xml(self, file_path: str) -> Tuple[List[ImportRecord], List[str]]:
        """Parse a Nessus XML v2 file into ImportRecord objects.

        Expected structure:
            <NessusClientData_v2>
              <Report>
                <ReportHost name="...">
                  <ReportItem port="..." pluginName="..." severity="...">
                    <plugin_output>...</plugin_output>
                    <description>...</description>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>

        Args:
            file_path: Path to the Nessus XML file.

        Returns:
            Tuple of (records, warnings).
        """
        records: List[ImportRecord] = []
        warnings: List[str] = []

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            msg = f"Failed to parse Nessus XML: {e}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings
        except FileNotFoundError as e:
            msg = f"Nessus file not found: {file_path}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings

        # Count total items for progress
        report_items = []
        for report_host in root.iter("ReportHost"):
            host_name = report_host.get("name", "unknown")
            for item in report_host.findall("ReportItem"):
                report_items.append((host_name, item))

        total = len(report_items)
        for idx, (host_name, item) in enumerate(report_items):
            try:
                plugin_name = item.get("pluginName", "")
                severity_num = item.get("severity", "0")
                port = item.get("port", "0")

                if not plugin_name:
                    msg = f"Skipping Nessus item at index {idx}: missing pluginName"
                    warnings.append(msg)
                    logger.warning(msg)
                    self.import_warning.emit(msg)
                    continue

                description_el = item.find("description")
                description = description_el.text if description_el is not None and description_el.text else ""

                plugin_output_el = item.find("plugin_output")
                plugin_output = plugin_output_el.text if plugin_output_el is not None and plugin_output_el.text else ""

                severity = NESSUS_SEVERITY_MAP.get(severity_num, "info")

                record = ImportRecord(
                    host=host_name,
                    port=int(port) if port.isdigit() else 0,
                    vulnerability_name=plugin_name,
                    severity=severity,
                    description=description,
                    evidence=plugin_output,
                    source_format="nessus",
                    raw_data={
                        "pluginName": plugin_name,
                        "severity": severity_num,
                        "port": port,
                        "host": host_name,
                    },
                )
                records.append(record)
            except Exception as e:
                msg = f"Skipping malformed Nessus item at index {idx}: {e}"
                warnings.append(msg)
                logger.warning(msg)
                self.import_warning.emit(msg)

            self.import_progress.emit(idx + 1, total)

        return records, warnings

    def parse_burp_xml(self, file_path: str) -> Tuple[List[ImportRecord], List[str]]:
        """Parse a Burp Suite XML export file into ImportRecord objects.

        Expected structure:
            <issues>
              <issue>
                <name>...</name>
                <severity>...</severity>
                <host>...</host>
                <path>...</path>
                <issueDetail>...</issueDetail>
                <request>...</request>
                <response>...</response>
              </issue>
            </issues>

        Args:
            file_path: Path to the Burp XML file.

        Returns:
            Tuple of (records, warnings).
        """
        records: List[ImportRecord] = []
        warnings: List[str] = []

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            msg = f"Failed to parse Burp XML: {e}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings
        except FileNotFoundError as e:
            msg = f"Burp file not found: {file_path}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings

        issues = root.findall("issue")
        total = len(issues)

        for idx, issue in enumerate(issues):
            try:
                name_el = issue.find("name")
                name = name_el.text if name_el is not None and name_el.text else ""

                if not name:
                    msg = f"Skipping Burp issue at index {idx}: missing name"
                    warnings.append(msg)
                    logger.warning(msg)
                    self.import_warning.emit(msg)
                    continue

                severity_el = issue.find("severity")
                severity_raw = (severity_el.text if severity_el is not None and severity_el.text else "information").lower()
                severity = BURP_SEVERITY_MAP.get(severity_raw, "info")

                host_el = issue.find("host")
                host = host_el.text if host_el is not None and host_el.text else ""

                path_el = issue.find("path")
                path = path_el.text if path_el is not None and path_el.text else ""

                detail_el = issue.find("issueDetail")
                detail = detail_el.text if detail_el is not None and detail_el.text else ""

                request_el = issue.find("request")
                request = request_el.text if request_el is not None and request_el.text else ""

                response_el = issue.find("response")
                response = response_el.text if response_el is not None and response_el.text else ""

                # Build evidence from request/response pair
                evidence_parts = []
                if request:
                    evidence_parts.append(f"=== REQUEST ===\n{request}")
                if response:
                    evidence_parts.append(f"=== RESPONSE ===\n{response}")
                evidence = "\n\n".join(evidence_parts)

                # Extract port from host URL if present
                port = 0
                if host:
                    if ":443" in host or host.startswith("https"):
                        port = 443
                    elif ":80" in host or host.startswith("http"):
                        port = 80
                    # Try to extract specific port
                    try:
                        if "://" in host:
                            host_part = host.split("://", 1)[1]
                        else:
                            host_part = host
                        if ":" in host_part:
                            port_str = host_part.split(":")[1].split("/")[0]
                            port = int(port_str)
                    except (ValueError, IndexError):
                        pass

                record = ImportRecord(
                    host=host,
                    port=port,
                    vulnerability_name=name,
                    severity=severity,
                    description=detail,
                    evidence=evidence,
                    source_format="burp",
                    raw_data={
                        "name": name,
                        "severity": severity_raw,
                        "host": host,
                        "path": path,
                    },
                )
                records.append(record)
            except Exception as e:
                msg = f"Skipping malformed Burp issue at index {idx}: {e}"
                warnings.append(msg)
                logger.warning(msg)
                self.import_warning.emit(msg)

            self.import_progress.emit(idx + 1, total)

        return records, warnings

    def parse_sarif(self, file_path: str) -> Tuple[List[ImportRecord], List[str]]:
        """Parse a SARIF (Static Analysis Results Interchange Format) JSON file.

        Expected structure:
            {
              "runs": [{
                "tool": {"driver": {"rules": [...]}},
                "results": [{
                  "ruleId": "...",
                  "message": {"text": "..."},
                  "level": "...",
                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "..."}}}]
                }]
              }]
            }

        Args:
            file_path: Path to the SARIF JSON file.

        Returns:
            Tuple of (records, warnings).
        """
        records: List[ImportRecord] = []
        warnings: List[str] = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                sarif_data = json.load(f)
        except json.JSONDecodeError as e:
            msg = f"Failed to parse SARIF JSON: {e}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings
        except FileNotFoundError:
            msg = f"SARIF file not found: {file_path}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings

        runs = sarif_data.get("runs", [])
        if not runs:
            msg = "SARIF file contains no runs"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings

        # Collect all results across all runs for total count
        all_results = []
        for run in runs:
            # Build rule lookup for this run
            rules = {}
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                rules[rule_id] = rule

            results = run.get("results", [])
            for result in results:
                all_results.append((result, rules))

        total = len(all_results)

        for idx, (result, rules) in enumerate(all_results):
            try:
                rule_id = result.get("ruleId", "")
                message = result.get("message", {})
                message_text = message.get("text", "") if isinstance(message, dict) else str(message)
                level = result.get("level", "warning").lower()

                # Look up rule details
                rule = rules.get(rule_id, {})
                rule_name = ""
                rule_description = ""
                if rule:
                    rule_name = rule.get("name", rule.get("shortDescription", {}).get("text", ""))
                    full_desc = rule.get("fullDescription", {})
                    rule_description = full_desc.get("text", "") if isinstance(full_desc, dict) else ""

                # Extract location info
                locations = result.get("locations", [])
                location_str = ""
                if locations:
                    loc = locations[0]
                    physical_loc = loc.get("physicalLocation", {})
                    artifact_loc = physical_loc.get("artifactLocation", {})
                    uri = artifact_loc.get("uri", "")
                    region = physical_loc.get("region", {})
                    start_line = region.get("startLine", 0)
                    if uri:
                        location_str = f"{uri}"
                        if start_line:
                            location_str += f":{start_line}"

                vulnerability_name = rule_name or rule_id or "Unknown"
                severity = SARIF_SEVERITY_MAP.get(level, "info")
                description = rule_description or message_text

                record = ImportRecord(
                    host=location_str,
                    port=0,
                    vulnerability_name=vulnerability_name,
                    severity=severity,
                    description=description,
                    evidence=message_text,
                    source_format="sarif",
                    raw_data={
                        "ruleId": rule_id,
                        "level": level,
                        "location": location_str,
                        "message": message_text,
                    },
                )
                records.append(record)
            except Exception as e:
                msg = f"Skipping malformed SARIF result at index {idx}: {e}"
                warnings.append(msg)
                logger.warning(msg)
                self.import_warning.emit(msg)

            self.import_progress.emit(idx + 1, total)

        return records, warnings

    def parse_csv(
        self, file_path: str, column_mapping: Dict[str, str]
    ) -> Tuple[List[ImportRecord], List[str]]:
        """Parse a CSV file with configurable column mapping.

        The column_mapping dict maps CSV column names to ImportRecord field names.
        Example: {"IP Address": "host", "Port": "port", "Vulnerability": "vulnerability_name"}

        Args:
            file_path: Path to the CSV file.
            column_mapping: Dict mapping CSV column headers to ImportRecord fields.

        Returns:
            Tuple of (records, warnings).
        """
        records: List[ImportRecord] = []
        warnings: List[str] = []

        try:
            with open(file_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
        except FileNotFoundError:
            msg = f"CSV file not found: {file_path}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings
        except Exception as e:
            msg = f"Failed to read CSV: {e}"
            warnings.append(msg)
            logger.warning(msg)
            self.import_warning.emit(msg)
            return records, warnings

        total = len(rows)

        for idx, row in enumerate(rows):
            try:
                record_kwargs = {}
                raw_data = dict(row)

                for csv_col, record_field in column_mapping.items():
                    value = row.get(csv_col, "")
                    if record_field == "port":
                        try:
                            record_kwargs["port"] = int(value) if value else 0
                        except ValueError:
                            record_kwargs["port"] = 0
                    else:
                        record_kwargs[record_field] = value if value else ""

                record_kwargs["source_format"] = "csv"
                record_kwargs["raw_data"] = raw_data

                record = ImportRecord(**record_kwargs)
                records.append(record)
            except Exception as e:
                msg = f"Skipping malformed CSV row at index {idx}: {e}"
                warnings.append(msg)
                logger.warning(msg)
                self.import_warning.emit(msg)

            self.import_progress.emit(idx + 1, total)

        return records, warnings

    def export_findings(
        self, findings: List[Dict], format: str, output_path: str
    ) -> bool:
        """Export findings in the specified format.

        Supported formats: 'nessus', 'burp', 'sarif', 'csv', 'json'

        Args:
            findings: List of finding dicts with keys: title, severity,
                description, host, port, evidence, cvss_score, cwe_id, etc.
            format: Output format string.
            output_path: Path to write the output file.

        Returns:
            True if export succeeded, False otherwise.
        """
        format_lower = format.lower()

        try:
            if format_lower == "nessus":
                return self._export_nessus(findings, output_path)
            elif format_lower == "burp":
                return self._export_burp(findings, output_path)
            elif format_lower == "sarif":
                return self._export_sarif(findings, output_path)
            elif format_lower == "csv":
                return self._export_csv(findings, output_path)
            elif format_lower == "json":
                return self._export_json(findings, output_path)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
        except Exception as e:
            logger.error(f"Export failed for format '{format}': {e}")
            return False

    def _export_nessus(self, findings: List[Dict], output_path: str) -> bool:
        """Export findings as Nessus XML v2 format."""
        # Reverse severity map
        severity_to_num = {v: k for k, v in NESSUS_SEVERITY_MAP.items()}

        root = ET.Element("NessusClientData_v2")
        report = ET.SubElement(root, "Report", name="Huginn Export")

        # Group findings by host
        hosts: Dict[str, List[Dict]] = {}
        for finding in findings:
            host = finding.get("host", "unknown")
            hosts.setdefault(host, []).append(finding)

        for host_name, host_findings in hosts.items():
            report_host = ET.SubElement(report, "ReportHost", name=host_name)
            for finding in host_findings:
                severity_label = finding.get("severity", "info").lower()
                severity_num = severity_to_num.get(severity_label, "0")
                port = str(finding.get("port", 0))

                item = ET.SubElement(
                    report_host,
                    "ReportItem",
                    port=port,
                    pluginName=finding.get("title", ""),
                    severity=severity_num,
                )
                desc = ET.SubElement(item, "description")
                desc.text = finding.get("description", "")
                output = ET.SubElement(item, "plugin_output")
                output.text = finding.get("evidence", "")

        tree = ET.ElementTree(root)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)
        return True

    def _export_burp(self, findings: List[Dict], output_path: str) -> bool:
        """Export findings as Burp Suite XML format."""
        root = ET.Element("issues")

        for finding in findings:
            issue = ET.SubElement(root, "issue")

            name_el = ET.SubElement(issue, "name")
            name_el.text = finding.get("title", "")

            severity_el = ET.SubElement(issue, "severity")
            severity = finding.get("severity", "Information")
            # Capitalize for Burp format
            severity_el.text = severity.capitalize() if severity != "info" else "Information"

            host_el = ET.SubElement(issue, "host")
            host_el.text = finding.get("host", "")

            path_el = ET.SubElement(issue, "path")
            path_el.text = finding.get("path", "/")

            detail_el = ET.SubElement(issue, "issueDetail")
            detail_el.text = finding.get("description", "")

            request_el = ET.SubElement(issue, "request")
            request_el.text = finding.get("request", "")

            response_el = ET.SubElement(issue, "response")
            response_el.text = finding.get("response", "")

        tree = ET.ElementTree(root)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)
        return True

    def _export_sarif(self, findings: List[Dict], output_path: str) -> bool:
        """Export findings as SARIF JSON format."""
        # Reverse severity map
        severity_to_level = {v: k for k, v in SARIF_SEVERITY_MAP.items()}
        # Prefer more specific mappings
        severity_to_level.update({
            "info": "note",
            "low": "note",
            "medium": "warning",
            "high": "error",
            "critical": "error",
        })

        results = []
        rules = []
        rule_ids_seen = set()

        for idx, finding in enumerate(findings):
            rule_id = finding.get("cwe_id", f"FINDING-{idx + 1}")
            title = finding.get("title", "Unknown Finding")
            severity = finding.get("severity", "info").lower()
            level = severity_to_level.get(severity, "warning")

            # Add rule if not seen
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": finding.get("description", "")},
                })

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.get("description", title)},
                "locations": [],
            }

            host = finding.get("host", "")
            if host:
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": host},
                    }
                })

            results.append(result)

        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Huginn",
                            "version": "1.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_output, f, indent=2)
        return True

    def _export_csv(self, findings: List[Dict], output_path: str) -> bool:
        """Export findings as CSV format."""
        if not findings:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["title", "severity", "host", "port", "description", "evidence", "cvss_score", "cwe_id"])
            return True

        fieldnames = ["title", "severity", "host", "port", "description", "evidence", "cvss_score", "cwe_id", "category", "status"]

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)
        return True

    def _export_json(self, findings: List[Dict], output_path: str) -> bool:
        """Export findings as JSON format."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, default=str)
        return True
