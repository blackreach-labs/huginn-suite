# tests/test_import_export_engine.py
"""Tests for the import/export engine."""

import csv
import json
import xml.etree.ElementTree as ET

import pytest

from app.core.import_export_engine import (
    ImportExportEngine,
    ImportRecord,
    NESSUS_SEVERITY_MAP,
    BURP_SEVERITY_MAP,
    SARIF_SEVERITY_MAP,
)


# --- Fixtures: sample file content ---

SAMPLE_NESSUS_XML = """\
<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.10">
      <ReportItem port="443" pluginName="SSL Certificate Expired" severity="2">
        <description>The SSL certificate has expired.</description>
        <plugin_output>Certificate expired on 2023-01-01</plugin_output>
      </ReportItem>
      <ReportItem port="80" pluginName="HTTP Server Banner" severity="0">
        <description>The remote web server type is Apache.</description>
        <plugin_output>Apache/2.4.41</plugin_output>
      </ReportItem>
    </ReportHost>
    <ReportHost name="192.168.1.20">
      <ReportItem port="22" pluginName="SSH Weak Algorithms" severity="3">
        <description>SSH server supports weak key exchange.</description>
        <plugin_output>diffie-hellman-group1-sha1</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

SAMPLE_BURP_XML = """\
<?xml version="1.0"?>
<issues>
  <issue>
    <name>Cross-site scripting (reflected)</name>
    <severity>High</severity>
    <host>https://example.com:8443</host>
    <path>/search</path>
    <issueDetail>The application reflects user input in the response.</issueDetail>
    <request>GET /search?q=&lt;script&gt; HTTP/1.1</request>
    <response>HTTP/1.1 200 OK\r\nContent-Type: text/html</response>
  </issue>
  <issue>
    <name>Cookie without HttpOnly flag</name>
    <severity>Low</severity>
    <host>http://example.com</host>
    <path>/login</path>
    <issueDetail>A cookie is set without the HttpOnly flag.</issueDetail>
    <request></request>
    <response></response>
  </issue>
</issues>
"""

SAMPLE_SARIF_JSON = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "TestScanner",
                    "version": "1.0.0",
                    "rules": [
                        {
                            "id": "SQL001",
                            "name": "SQL Injection",
                            "shortDescription": {"text": "SQL Injection vulnerability"},
                            "fullDescription": {"text": "User input is concatenated into SQL queries without parameterization."},
                        },
                        {
                            "id": "XSS001",
                            "name": "Cross-Site Scripting",
                            "shortDescription": {"text": "XSS vulnerability"},
                            "fullDescription": {"text": "User input is reflected in HTML output without encoding."},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "SQL001",
                    "level": "error",
                    "message": {"text": "SQL injection in login form"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/auth/login.py"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "XSS001",
                    "level": "warning",
                    "message": {"text": "Reflected XSS in search parameter"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/views/search.py"},
                                "region": {"startLine": 15},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}

SAMPLE_CSV_CONTENT = """\
IP Address,Port,Vulnerability,Severity,Description
192.168.1.1,80,XSS,high,Cross-site scripting found
192.168.1.2,443,SQLi,critical,SQL injection in login
10.0.0.1,22,Weak SSH,medium,Weak SSH key exchange
"""


@pytest.fixture
def engine():
    """Create an ImportExportEngine instance."""
    return ImportExportEngine()


@pytest.fixture
def nessus_file(tmp_path):
    """Write sample Nessus XML to a temp file."""
    path = tmp_path / "scan.nessus"
    path.write_text(SAMPLE_NESSUS_XML, encoding="utf-8")
    return str(path)


@pytest.fixture
def burp_file(tmp_path):
    """Write sample Burp XML to a temp file."""
    path = tmp_path / "burp_export.xml"
    path.write_text(SAMPLE_BURP_XML, encoding="utf-8")
    return str(path)


@pytest.fixture
def sarif_file(tmp_path):
    """Write sample SARIF JSON to a temp file."""
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(SAMPLE_SARIF_JSON), encoding="utf-8")
    return str(path)


@pytest.fixture
def csv_file(tmp_path):
    """Write sample CSV to a temp file."""
    path = tmp_path / "findings.csv"
    path.write_text(SAMPLE_CSV_CONTENT, encoding="utf-8")
    return str(path)


class TestImportRecord:
    """Tests for the ImportRecord dataclass."""

    def test_default_values(self):
        """ImportRecord should have sensible defaults."""
        record = ImportRecord()
        assert record.host == ""
        assert record.port == 0
        assert record.vulnerability_name == ""
        assert record.severity == "info"
        assert record.description == ""
        assert record.evidence == ""
        assert record.source_format == ""
        assert record.raw_data == {}

    def test_custom_values(self):
        """ImportRecord should accept custom values."""
        record = ImportRecord(
            host="10.0.0.1",
            port=443,
            vulnerability_name="SQL Injection",
            severity="critical",
            description="Input not sanitized",
            evidence="sqlmap output here",
            source_format="nessus",
            raw_data={"key": "value"},
        )
        assert record.host == "10.0.0.1"
        assert record.port == 443
        assert record.vulnerability_name == "SQL Injection"
        assert record.severity == "critical"


class TestParseNessusXML:
    """Tests for parse_nessus_xml()."""

    def test_parse_valid_file(self, engine, nessus_file):
        """Should parse all report items from valid Nessus XML."""
        records, warnings = engine.parse_nessus_xml(nessus_file)
        assert len(records) == 3
        assert len(warnings) == 0

    def test_host_extraction(self, engine, nessus_file):
        """Should extract host names correctly."""
        records, _ = engine.parse_nessus_xml(nessus_file)
        hosts = {r.host for r in records}
        assert "192.168.1.10" in hosts
        assert "192.168.1.20" in hosts

    def test_severity_mapping(self, engine, nessus_file):
        """Should map numeric severity to labels."""
        records, _ = engine.parse_nessus_xml(nessus_file)
        severities = {r.vulnerability_name: r.severity for r in records}
        assert severities["SSL Certificate Expired"] == "medium"
        assert severities["HTTP Server Banner"] == "info"
        assert severities["SSH Weak Algorithms"] == "high"

    def test_port_extraction(self, engine, nessus_file):
        """Should extract port numbers."""
        records, _ = engine.parse_nessus_xml(nessus_file)
        port_map = {r.vulnerability_name: r.port for r in records}
        assert port_map["SSL Certificate Expired"] == 443
        assert port_map["HTTP Server Banner"] == 80
        assert port_map["SSH Weak Algorithms"] == 22

    def test_description_and_evidence(self, engine, nessus_file):
        """Should extract description and plugin_output as evidence."""
        records, _ = engine.parse_nessus_xml(nessus_file)
        ssl_record = next(r for r in records if r.vulnerability_name == "SSL Certificate Expired")
        assert "expired" in ssl_record.description.lower()
        assert "2023-01-01" in ssl_record.evidence

    def test_source_format(self, engine, nessus_file):
        """All records should have source_format='nessus'."""
        records, _ = engine.parse_nessus_xml(nessus_file)
        for record in records:
            assert record.source_format == "nessus"

    def test_file_not_found(self, engine):
        """Should return empty records and a warning for missing file."""
        records, warnings = engine.parse_nessus_xml("/nonexistent/path.nessus")
        assert len(records) == 0
        assert len(warnings) == 1
        assert "not found" in warnings[0].lower()

    def test_malformed_xml(self, engine, tmp_path):
        """Should handle malformed XML gracefully."""
        bad_file = tmp_path / "bad.nessus"
        bad_file.write_text("<invalid><xml>", encoding="utf-8")
        records, warnings = engine.parse_nessus_xml(str(bad_file))
        assert len(records) == 0
        assert len(warnings) == 1

    def test_missing_plugin_name_skipped(self, engine, tmp_path):
        """Items without pluginName should be skipped with a warning."""
        xml_content = """\
<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="10.0.0.1">
      <ReportItem port="80" pluginName="" severity="1">
        <description>No name</description>
      </ReportItem>
      <ReportItem port="443" pluginName="Valid Finding" severity="2">
        <description>Has a name</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""
        f = tmp_path / "partial.nessus"
        f.write_text(xml_content, encoding="utf-8")
        records, warnings = engine.parse_nessus_xml(str(f))
        assert len(records) == 1
        assert records[0].vulnerability_name == "Valid Finding"
        assert len(warnings) == 1

    def test_progress_signal(self, engine, nessus_file, qtbot):
        """import_progress signal should be emitted during parsing."""
        progress_calls = []
        engine.import_progress.connect(lambda cur, tot: progress_calls.append((cur, tot)))
        engine.parse_nessus_xml(nessus_file)
        assert len(progress_calls) == 3
        assert progress_calls[-1] == (3, 3)


class TestParseBurpXML:
    """Tests for parse_burp_xml()."""

    def test_parse_valid_file(self, engine, burp_file):
        """Should parse all issues from valid Burp XML."""
        records, warnings = engine.parse_burp_xml(burp_file)
        assert len(records) == 2
        assert len(warnings) == 0

    def test_severity_mapping(self, engine, burp_file):
        """Should map Burp severity labels correctly."""
        records, _ = engine.parse_burp_xml(burp_file)
        sev_map = {r.vulnerability_name: r.severity for r in records}
        assert sev_map["Cross-site scripting (reflected)"] == "high"
        assert sev_map["Cookie without HttpOnly flag"] == "low"

    def test_host_and_port_extraction(self, engine, burp_file):
        """Should extract host and port from URL."""
        records, _ = engine.parse_burp_xml(burp_file)
        xss_record = next(r for r in records if "scripting" in r.vulnerability_name)
        assert "example.com" in xss_record.host
        assert xss_record.port == 8443

    def test_evidence_contains_request_response(self, engine, burp_file):
        """Should build evidence from request/response pair."""
        records, _ = engine.parse_burp_xml(burp_file)
        xss_record = next(r for r in records if "scripting" in r.vulnerability_name)
        assert "REQUEST" in xss_record.evidence
        assert "RESPONSE" in xss_record.evidence

    def test_source_format(self, engine, burp_file):
        """All records should have source_format='burp'."""
        records, _ = engine.parse_burp_xml(burp_file)
        for record in records:
            assert record.source_format == "burp"

    def test_file_not_found(self, engine):
        """Should return empty records and a warning for missing file."""
        records, warnings = engine.parse_burp_xml("/nonexistent/burp.xml")
        assert len(records) == 0
        assert len(warnings) == 1

    def test_missing_name_skipped(self, engine, tmp_path):
        """Issues without name should be skipped."""
        xml_content = """\
<?xml version="1.0"?>
<issues>
  <issue>
    <name></name>
    <severity>High</severity>
    <host>http://example.com</host>
  </issue>
  <issue>
    <name>Valid Issue</name>
    <severity>Medium</severity>
    <host>http://example.com</host>
  </issue>
</issues>
"""
        f = tmp_path / "partial_burp.xml"
        f.write_text(xml_content, encoding="utf-8")
        records, warnings = engine.parse_burp_xml(str(f))
        assert len(records) == 1
        assert records[0].vulnerability_name == "Valid Issue"
        assert len(warnings) == 1


class TestParseSARIF:
    """Tests for parse_sarif()."""

    def test_parse_valid_file(self, engine, sarif_file):
        """Should parse all results from valid SARIF."""
        records, warnings = engine.parse_sarif(sarif_file)
        assert len(records) == 2
        assert len(warnings) == 0

    def test_rule_name_extraction(self, engine, sarif_file):
        """Should use rule name as vulnerability_name."""
        records, _ = engine.parse_sarif(sarif_file)
        names = {r.vulnerability_name for r in records}
        assert "SQL Injection" in names
        assert "Cross-Site Scripting" in names

    def test_severity_mapping(self, engine, sarif_file):
        """Should map SARIF levels to severity labels."""
        records, _ = engine.parse_sarif(sarif_file)
        sev_map = {r.vulnerability_name: r.severity for r in records}
        assert sev_map["SQL Injection"] == "high"  # error -> high
        assert sev_map["Cross-Site Scripting"] == "medium"  # warning -> medium

    def test_location_extraction(self, engine, sarif_file):
        """Should extract file location into host field."""
        records, _ = engine.parse_sarif(sarif_file)
        sql_record = next(r for r in records if r.vulnerability_name == "SQL Injection")
        assert "login.py" in sql_record.host
        assert ":42" in sql_record.host

    def test_description_from_rule(self, engine, sarif_file):
        """Should use fullDescription from rule as description."""
        records, _ = engine.parse_sarif(sarif_file)
        sql_record = next(r for r in records if r.vulnerability_name == "SQL Injection")
        assert "parameterization" in sql_record.description

    def test_source_format(self, engine, sarif_file):
        """All records should have source_format='sarif'."""
        records, _ = engine.parse_sarif(sarif_file)
        for record in records:
            assert record.source_format == "sarif"

    def test_file_not_found(self, engine):
        """Should return empty records and a warning for missing file."""
        records, warnings = engine.parse_sarif("/nonexistent/results.sarif")
        assert len(records) == 0
        assert len(warnings) == 1

    def test_invalid_json(self, engine, tmp_path):
        """Should handle invalid JSON gracefully."""
        bad_file = tmp_path / "bad.sarif"
        bad_file.write_text("not json {{{", encoding="utf-8")
        records, warnings = engine.parse_sarif(str(bad_file))
        assert len(records) == 0
        assert len(warnings) == 1

    def test_empty_runs(self, engine, tmp_path):
        """Should warn when SARIF has no runs."""
        sarif = {"version": "2.1.0", "runs": []}
        f = tmp_path / "empty.sarif"
        f.write_text(json.dumps(sarif), encoding="utf-8")
        records, warnings = engine.parse_sarif(str(f))
        assert len(records) == 0
        assert len(warnings) == 1


class TestParseCSV:
    """Tests for parse_csv()."""

    def test_parse_valid_file(self, engine, csv_file):
        """Should parse all rows with column mapping."""
        mapping = {
            "IP Address": "host",
            "Port": "port",
            "Vulnerability": "vulnerability_name",
            "Severity": "severity",
            "Description": "description",
        }
        records, warnings = engine.parse_csv(csv_file, mapping)
        assert len(records) == 3
        assert len(warnings) == 0

    def test_column_mapping(self, engine, csv_file):
        """Should map CSV columns to ImportRecord fields."""
        mapping = {
            "IP Address": "host",
            "Port": "port",
            "Vulnerability": "vulnerability_name",
            "Severity": "severity",
            "Description": "description",
        }
        records, _ = engine.parse_csv(csv_file, mapping)
        assert records[0].host == "192.168.1.1"
        assert records[0].port == 80
        assert records[0].vulnerability_name == "XSS"
        assert records[0].severity == "high"

    def test_port_conversion(self, engine, csv_file):
        """Should convert port strings to integers."""
        mapping = {"IP Address": "host", "Port": "port"}
        records, _ = engine.parse_csv(csv_file, mapping)
        assert all(isinstance(r.port, int) for r in records)
        assert records[1].port == 443

    def test_source_format(self, engine, csv_file):
        """All records should have source_format='csv'."""
        mapping = {"IP Address": "host"}
        records, _ = engine.parse_csv(csv_file, mapping)
        for record in records:
            assert record.source_format == "csv"

    def test_file_not_found(self, engine):
        """Should return empty records and a warning for missing file."""
        records, warnings = engine.parse_csv("/nonexistent/data.csv", {"a": "host"})
        assert len(records) == 0
        assert len(warnings) == 1

    def test_partial_mapping(self, engine, csv_file):
        """Should work with partial column mapping (unmapped cols ignored)."""
        mapping = {"IP Address": "host", "Severity": "severity"}
        records, _ = engine.parse_csv(csv_file, mapping)
        assert len(records) == 3
        assert records[0].host == "192.168.1.1"
        assert records[0].severity == "high"
        # Unmapped fields keep defaults
        assert records[0].vulnerability_name == ""

    def test_raw_data_contains_all_columns(self, engine, csv_file):
        """raw_data should contain the full original row."""
        mapping = {"IP Address": "host"}
        records, _ = engine.parse_csv(csv_file, mapping)
        assert "Port" in records[0].raw_data
        assert "Vulnerability" in records[0].raw_data


class TestExportFindings:
    """Tests for export_findings()."""

    @pytest.fixture
    def sample_findings(self):
        """Sample finding data for export tests."""
        return [
            {
                "title": "SQL Injection",
                "severity": "critical",
                "host": "192.168.1.1",
                "port": 80,
                "description": "Input not sanitized in login form",
                "evidence": "sqlmap confirmed injection",
                "cvss_score": 9.8,
                "cwe_id": "CWE-89",
                "category": "web",
                "status": "open",
            },
            {
                "title": "Weak SSH Keys",
                "severity": "medium",
                "host": "10.0.0.5",
                "port": 22,
                "description": "Server uses weak key exchange algorithms",
                "evidence": "nmap script output",
                "cvss_score": 5.3,
                "cwe_id": "CWE-327",
                "category": "network",
                "status": "open",
            },
        ]

    def test_export_json(self, engine, sample_findings, tmp_path):
        """Should export findings as valid JSON."""
        output = str(tmp_path / "findings.json")
        result = engine.export_findings(sample_findings, "json", output)
        assert result is True

        with open(output, "r") as f:
            data = json.load(f)
        assert len(data) == 2
        assert data[0]["title"] == "SQL Injection"

    def test_export_csv(self, engine, sample_findings, tmp_path):
        """Should export findings as valid CSV."""
        output = str(tmp_path / "findings.csv")
        result = engine.export_findings(sample_findings, "csv", output)
        assert result is True

        with open(output, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["title"] == "SQL Injection"
        assert rows[0]["severity"] == "critical"

    def test_export_nessus(self, engine, sample_findings, tmp_path):
        """Should export findings as valid Nessus XML."""
        output = str(tmp_path / "export.nessus")
        result = engine.export_findings(sample_findings, "nessus", output)
        assert result is True

        tree = ET.parse(output)
        root = tree.getroot()
        assert root.tag == "NessusClientData_v2"
        items = list(root.iter("ReportItem"))
        assert len(items) == 2

    def test_export_burp(self, engine, sample_findings, tmp_path):
        """Should export findings as valid Burp XML."""
        output = str(tmp_path / "export_burp.xml")
        result = engine.export_findings(sample_findings, "burp", output)
        assert result is True

        tree = ET.parse(output)
        root = tree.getroot()
        assert root.tag == "issues"
        issues = root.findall("issue")
        assert len(issues) == 2

    def test_export_sarif(self, engine, sample_findings, tmp_path):
        """Should export findings as valid SARIF JSON."""
        output = str(tmp_path / "export.sarif")
        result = engine.export_findings(sample_findings, "sarif", output)
        assert result is True

        with open(output, "r") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 2

    def test_export_unsupported_format(self, engine, sample_findings, tmp_path):
        """Should return False for unsupported format."""
        output = str(tmp_path / "findings.xyz")
        result = engine.export_findings(sample_findings, "xyz", output)
        assert result is False

    def test_export_empty_findings_csv(self, engine, tmp_path):
        """Should handle empty findings list for CSV."""
        output = str(tmp_path / "empty.csv")
        result = engine.export_findings([], "csv", output)
        assert result is True

    def test_export_creates_directories(self, engine, sample_findings, tmp_path):
        """Should create parent directories if they don't exist."""
        output = str(tmp_path / "nested" / "dir" / "findings.json")
        result = engine.export_findings(sample_findings, "json", output)
        assert result is True


class TestWarningSignal:
    """Tests for import_warning signal emission."""

    def test_warning_on_malformed_nessus(self, engine, tmp_path, qtbot):
        """import_warning should emit for malformed XML."""
        bad_file = tmp_path / "bad.nessus"
        bad_file.write_text("<broken>xml", encoding="utf-8")
        with qtbot.waitSignal(engine.import_warning, timeout=1000):
            engine.parse_nessus_xml(str(bad_file))

    def test_warning_on_missing_file(self, engine, qtbot):
        """import_warning should emit for missing file."""
        with qtbot.waitSignal(engine.import_warning, timeout=1000):
            engine.parse_burp_xml("/no/such/file.xml")


class TestRoundTrip:
    """Tests for import->export->reimport consistency."""

    def test_nessus_roundtrip(self, engine, nessus_file, tmp_path):
        """Parsing Nessus then exporting as Nessus should preserve core data."""
        records, _ = engine.parse_nessus_xml(nessus_file)

        # Convert records to finding dicts for export
        findings = []
        for r in records:
            findings.append({
                "title": r.vulnerability_name,
                "severity": r.severity,
                "host": r.host,
                "port": r.port,
                "description": r.description,
                "evidence": r.evidence,
            })

        output = str(tmp_path / "roundtrip.nessus")
        engine.export_findings(findings, "nessus", output)

        # Re-import
        records2, _ = engine.parse_nessus_xml(output)
        assert len(records2) == len(records)

        # Verify key data preserved
        names_original = {r.vulnerability_name for r in records}
        names_reimported = {r.vulnerability_name for r in records2}
        assert names_original == names_reimported
