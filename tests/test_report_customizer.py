# tests/test_report_customizer.py
"""Tests for the Report Customizer engine."""

import json
import os
import pytest

from app.core.report_customizer import (
    ReportCustomizer,
    ReportTemplate,
    ReportSection,
    SEVERITY_LEVELS,
    DEFAULT_SECTIONS,
    DEFAULT_BRANDING,
)
from app.core.engagement_database import EngagementDatabase


@pytest.fixture
def tmp_templates_dir(tmp_path):
    """Create a temporary templates directory."""
    templates_dir = str(tmp_path / "report_templates")
    os.makedirs(templates_dir, exist_ok=True)
    return templates_dir


@pytest.fixture
def customizer(tmp_templates_dir):
    """Create a ReportCustomizer with temporary directory."""
    return ReportCustomizer(templates_dir=tmp_templates_dir)


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database with test data."""
    db_path = str(tmp_path / "test_engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def engagement_db_with_data(engagement_db):
    """Engagement database populated with sample findings and mappings."""
    # Insert findings with various severities
    findings = [
        ("SQL Injection", "critical", "SQL injection in login", "Full DB compromise",
         "Use parameterized queries", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "CWE-89", "web_application", "open"),
        ("XSS Stored", "high", "Stored XSS in comment field", "Session hijacking",
         "Sanitize user input", 7.5, None, "CWE-79", "web_application", "open"),
        ("Missing HSTS", "medium", "HSTS header not set", "Downgrade attack possible",
         "Add Strict-Transport-Security header", 5.0, None, "CWE-319", "web_application", "open"),
        ("Information Disclosure", "low", "Server version disclosed", "Assists attacker recon",
         "Remove server version headers", 3.0, None, "CWE-200", "web_application", "open"),
        ("Cookie without Secure flag", "informational", "Non-critical cookie lacks Secure flag",
         "Minor data exposure risk", "Add Secure flag", 1.0, None, "CWE-614", "web_application", "open"),
    ]
    for f in findings:
        engagement_db.execute_write(
            """INSERT INTO findings (title, severity, description, impact, remediation,
               cvss_score, cvss_vector, cwe_id, category, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            f + ("2024-01-01T00:00:00", "2024-01-01T00:00:00"),
        )

    # Insert ATT&CK mappings
    engagement_db.execute_write(
        """INSERT INTO attack_mappings (finding_id, technique_id, tactic, procedure_description, status)
           VALUES (?, ?, ?, ?, ?)""",
        (1, "T1190", "initial-access", "Exploited SQL injection", "successful"),
    )
    engagement_db.execute_write(
        """INSERT INTO attack_mappings (finding_id, technique_id, tactic, procedure_description, status)
           VALUES (?, ?, ?, ?, ?)""",
        (2, "T1059.007", "execution", "Used XSS for script execution", "tested"),
    )

    # Insert timeline entries
    engagement_db.execute_write(
        """INSERT INTO timeline_entries (action_type, actor, description, timestamp)
           VALUES (?, ?, ?, ?)""",
        ("scan_start", "tester", "Started web application scan", "2024-01-01T09:00:00"),
    )
    engagement_db.execute_write(
        """INSERT INTO timeline_entries (action_type, actor, description, timestamp)
           VALUES (?, ?, ?, ?)""",
        ("finding_discovered", "tester", "Discovered SQL injection", "2024-01-01T09:30:00"),
    )

    return engagement_db


@pytest.fixture
def saved_template(customizer):
    """Create and save a template for tests that need a pre-existing template."""
    template = customizer.create_template("Test Template")
    customizer.save_template(template)
    return template


class TestTemplateCreation:
    """Tests for template creation."""

    def test_create_template_default(self, customizer):
        """Creating a template with defaults should use default sections and branding."""
        template = customizer.create_template("My Report")
        assert template.name == "My Report"
        assert len(template.sections) == len(DEFAULT_SECTIONS)
        assert template.severity_threshold == "low"
        assert template.branding["cover_page"] is True
        assert template.created_at != ""
        assert template.updated_at != ""

    def test_create_template_custom_sections(self, customizer):
        """Template with custom sections should only include specified sections."""
        sections = [
            {"id": "findings", "title": "Findings", "enabled": True,
             "conditional": False, "condition_key": None},
            {"id": "executive_summary", "title": "Executive Summary", "enabled": True,
             "conditional": False, "condition_key": None},
        ]
        template = customizer.create_template("Custom Report", sections=sections)
        assert len(template.sections) == 2
        assert template.sections[0].id == "findings"
        assert template.sections[1].id == "executive_summary"

    def test_create_template_custom_branding(self, customizer):
        """Template with custom branding should store branding values."""
        branding = {
            "logo_path": "/path/to/logo.png",
            "company_name": "Test Corp",
            "primary_color": "#ff0000",
            "secondary_color": "#00ff00",
            "header_text": "Confidential",
            "footer_text": "© 2024 Test Corp",
            "cover_page": False,
        }
        template = customizer.create_template("Branded Report", branding=branding)
        assert template.branding["company_name"] == "Test Corp"
        assert template.branding["primary_color"] == "#ff0000"
        assert template.branding["cover_page"] is False

    def test_create_template_severity_threshold(self, customizer):
        """Template should store severity threshold correctly."""
        template = customizer.create_template("High Only", severity_threshold="high")
        assert template.severity_threshold == "high"

    def test_create_template_empty_name_raises(self, customizer):
        """Empty template name should raise ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            customizer.create_template("")

    def test_create_template_whitespace_name_raises(self, customizer):
        """Whitespace-only template name should raise ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            customizer.create_template("   ")

    def test_create_template_invalid_severity_raises(self, customizer):
        """Invalid severity threshold should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid severity threshold"):
            customizer.create_template("Bad Threshold", severity_threshold="extreme")

    def test_create_template_emits_signal(self, customizer, qtbot):
        """template_created signal should be emitted."""
        with qtbot.waitSignal(customizer.template_created, timeout=1000) as blocker:
            customizer.create_template("Signal Test")
        assert blocker.args == ["Signal Test"]


class TestTemplateSaveLoad:
    """Tests for template save and load."""

    def test_save_template(self, customizer, tmp_templates_dir):
        """Saving a template should write a JSON file to disk."""
        template = customizer.create_template("Save Test")
        filepath = customizer.save_template(template)
        assert os.path.exists(filepath)
        assert filepath.endswith(".json")

    def test_save_template_content(self, customizer, tmp_templates_dir):
        """Saved template should contain correct JSON data."""
        template = customizer.create_template("Content Test",
                                              severity_threshold="high")
        filepath = customizer.save_template(template)
        with open(filepath, 'r') as f:
            data = json.load(f)
        assert data["name"] == "Content Test"
        assert data["severity_threshold"] == "high"
        assert len(data["sections"]) == len(DEFAULT_SECTIONS)

    def test_load_template(self, customizer):
        """Loading a saved template should restore all properties."""
        template = customizer.create_template("Load Test",
                                              severity_threshold="medium")
        customizer.save_template(template)

        loaded = customizer.load_template("Load Test")
        assert loaded.name == "Load Test"
        assert loaded.severity_threshold == "medium"
        assert len(loaded.sections) == len(DEFAULT_SECTIONS)

    def test_load_nonexistent_raises(self, customizer):
        """Loading a non-existent template should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Template not found"):
            customizer.load_template("Does Not Exist")

    def test_save_updates_timestamp(self, customizer):
        """Saving a template should update the updated_at field."""
        template = customizer.create_template("Timestamp Test")
        first_save = template.updated_at
        customizer.save_template(template)
        assert template.updated_at >= first_save

    def test_save_template_emits_signal(self, customizer, qtbot):
        """template_saved signal should be emitted on save."""
        template = customizer.create_template("Signal Save")
        with qtbot.waitSignal(customizer.template_saved, timeout=1000):
            customizer.save_template(template)

    def test_save_empty_name_raises(self, customizer):
        """Saving a template with empty name should raise ValueError."""
        template = ReportTemplate(name="")
        with pytest.raises(ValueError, match="cannot be empty"):
            customizer.save_template(template)


class TestTemplateDelete:
    """Tests for template deletion."""

    def test_delete_existing(self, customizer, saved_template):
        """Deleting an existing template should remove the file."""
        result = customizer.delete_template("Test Template")
        assert result is True
        assert "test template" not in [t.lower() for t in customizer.list_templates()]

    def test_delete_nonexistent(self, customizer):
        """Deleting a non-existent template should return False."""
        result = customizer.delete_template("Ghost Template")
        assert result is False

    def test_delete_emits_signal(self, customizer, saved_template, qtbot):
        """template_deleted signal should be emitted."""
        with qtbot.waitSignal(customizer.template_deleted, timeout=1000):
            customizer.delete_template("Test Template")


class TestListTemplates:
    """Tests for listing templates."""

    def test_list_empty(self, customizer):
        """Empty directory should return empty list."""
        assert customizer.list_templates() == []

    def test_list_multiple(self, customizer):
        """Should list all saved templates."""
        t1 = customizer.create_template("Alpha")
        t2 = customizer.create_template("Beta")
        customizer.save_template(t1)
        customizer.save_template(t2)
        templates = customizer.list_templates()
        assert len(templates) == 2
        assert "alpha" in templates
        assert "beta" in templates


class TestSectionReordering:
    """Tests for drag-and-drop section reordering."""

    def test_reorder_sections(self, customizer):
        """Should reorder sections according to the new_order list."""
        template = customizer.create_template("Reorder Test")
        original_ids = [s.id for s in template.sections]

        # Reverse the order
        new_order = list(reversed(original_ids))
        customizer.reorder_sections(template, new_order)

        result_ids = [s.id for s in template.sections]
        assert result_ids == new_order

    def test_reorder_partial(self, customizer):
        """Partial reorder should put specified sections first, rest appended."""
        template = customizer.create_template("Partial Reorder")
        customizer.reorder_sections(template, ["findings", "executive_summary"])

        assert template.sections[0].id == "findings"
        assert template.sections[1].id == "executive_summary"
        # Rest are appended
        assert len(template.sections) == len(DEFAULT_SECTIONS)

    def test_reorder_invalid_id_raises(self, customizer):
        """Invalid section ID in new_order should raise ValueError."""
        template = customizer.create_template("Invalid Reorder")
        with pytest.raises(ValueError, match="Unknown section ID"):
            customizer.reorder_sections(template, ["nonexistent_section"])


class TestSeverityFiltering:
    """Tests for severity threshold filtering."""

    def test_filter_critical_only(self, customizer, engagement_db_with_data):
        """Threshold 'critical' should only include critical findings."""
        template = customizer.create_template("Critical Only",
                                              severity_threshold="critical")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        assert len(data["findings"]) == 1
        assert data["findings"][0][2] == "critical"

    def test_filter_high_and_above(self, customizer, engagement_db_with_data):
        """Threshold 'high' should include critical and high."""
        template = customizer.create_template("High Plus",
                                              severity_threshold="high")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        assert len(data["findings"]) == 2
        severities = {f[2] for f in data["findings"]}
        assert severities == {"critical", "high"}

    def test_filter_medium_and_above(self, customizer, engagement_db_with_data):
        """Threshold 'medium' should include critical, high, and medium."""
        template = customizer.create_template("Medium Plus",
                                              severity_threshold="medium")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        assert len(data["findings"]) == 3
        severities = {f[2] for f in data["findings"]}
        assert severities == {"critical", "high", "medium"}

    def test_filter_low_includes_almost_all(self, customizer, engagement_db_with_data):
        """Threshold 'low' should include everything except informational."""
        template = customizer.create_template("Low Plus",
                                              severity_threshold="low")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        assert len(data["findings"]) == 4
        severities = {f[2] for f in data["findings"]}
        assert "informational" not in severities

    def test_filter_informational_includes_all(self, customizer, engagement_db_with_data):
        """Threshold 'informational' should include all findings."""
        template = customizer.create_template("All Findings",
                                              severity_threshold="informational")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        assert len(data["findings"]) == 5


class TestConditionalSections:
    """Tests for conditional section logic."""

    def test_conditional_section_included_with_data(self, customizer, engagement_db_with_data):
        """ATT&CK coverage section should appear when mappings exist."""
        template = customizer.create_template("Conditional Test")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        active_sections = customizer._resolve_sections(template, data)

        section_ids = [s.id for s in active_sections]
        assert "attack_coverage" in section_ids

    def test_conditional_section_excluded_without_data(self, customizer, engagement_db):
        """ATT&CK coverage section should NOT appear when no mappings exist."""
        template = customizer.create_template("No Mappings")
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db, template)
        active_sections = customizer._resolve_sections(template, data)

        section_ids = [s.id for s in active_sections]
        assert "attack_coverage" not in section_ids

    def test_disabled_section_excluded(self, customizer, engagement_db_with_data):
        """Disabled sections should not appear regardless of data."""
        sections = [
            {"id": "findings", "title": "Findings", "enabled": False,
             "conditional": False, "condition_key": None},
            {"id": "executive_summary", "title": "Executive Summary", "enabled": True,
             "conditional": False, "condition_key": None},
        ]
        template = customizer.create_template("Disabled Test", sections=sections)
        customizer.save_template(template)

        data = customizer._gather_report_data(engagement_db_with_data, template)
        active_sections = customizer._resolve_sections(template, data)

        section_ids = [s.id for s in active_sections]
        assert "findings" not in section_ids
        assert "executive_summary" in section_ids


class TestReportGeneration:
    """Tests for multi-format report generation."""

    def test_generate_markdown(self, customizer, engagement_db_with_data, tmp_path):
        """Should generate a valid Markdown file."""
        template = customizer.create_template("MD Report")
        customizer.save_template(template)

        output = str(tmp_path / "report.md")
        result = customizer.generate_report("MD Report", engagement_db_with_data,
                                            output, "markdown")
        assert os.path.exists(result)
        content = open(result, 'r', encoding='utf-8').read()
        assert "## Executive Summary" in content
        assert "## Findings" in content
        assert "SQL Injection" in content

    def test_generate_html(self, customizer, engagement_db_with_data, tmp_path):
        """Should generate a valid HTML file."""
        template = customizer.create_template("HTML Report")
        customizer.save_template(template)

        output = str(tmp_path / "report.html")
        result = customizer.generate_report("HTML Report", engagement_db_with_data,
                                            output, "html")
        assert os.path.exists(result)
        content = open(result, 'r', encoding='utf-8').read()
        assert "<!DOCTYPE html>" in content
        assert "SQL Injection" in content

    def test_generate_pdf(self, customizer, engagement_db_with_data, tmp_path):
        """Should generate a PDF file (requires reportlab)."""
        pytest.importorskip("reportlab")
        template = customizer.create_template("PDF Report")
        customizer.save_template(template)

        output = str(tmp_path / "report.pdf")
        result = customizer.generate_report("PDF Report", engagement_db_with_data,
                                            output, "pdf")
        assert os.path.exists(result)
        # PDF files start with %PDF
        with open(result, 'rb') as f:
            header = f.read(4)
        assert header == b'%PDF'

    def test_generate_docx(self, customizer, engagement_db_with_data, tmp_path):
        """Should generate a DOCX file (requires python-docx)."""
        pytest.importorskip("docx")
        template = customizer.create_template("DOCX Report")
        customizer.save_template(template)

        output = str(tmp_path / "report.docx")
        result = customizer.generate_report("DOCX Report", engagement_db_with_data,
                                            output, "docx")
        assert os.path.exists(result)
        # DOCX files are ZIP archives starting with PK
        with open(result, 'rb') as f:
            header = f.read(2)
        assert header == b'PK'

    def test_generate_unsupported_format_raises(self, customizer, engagement_db_with_data, tmp_path):
        """Unsupported format should raise ValueError."""
        template = customizer.create_template("Bad Format")
        customizer.save_template(template)

        output = str(tmp_path / "report.xyz")
        with pytest.raises(ValueError, match="Unsupported output format"):
            customizer.generate_report("Bad Format", engagement_db_with_data,
                                       output, "xyz")

    def test_generate_nonexistent_template_raises(self, customizer, engagement_db_with_data, tmp_path):
        """Non-existent template should raise FileNotFoundError."""
        output = str(tmp_path / "report.md")
        with pytest.raises(FileNotFoundError):
            customizer.generate_report("Ghost Template", engagement_db_with_data,
                                       output, "markdown")

    def test_generate_report_emits_signal(self, customizer, engagement_db_with_data, tmp_path, qtbot):
        """report_generated signal should be emitted on success."""
        template = customizer.create_template("Signal Report")
        customizer.save_template(template)

        output = str(tmp_path / "report.md")
        with qtbot.waitSignal(customizer.report_generated, timeout=1000):
            customizer.generate_report("Signal Report", engagement_db_with_data,
                                       output, "markdown")

    def test_severity_filter_in_generated_report(self, customizer, engagement_db_with_data, tmp_path):
        """Generated report should respect severity threshold."""
        template = customizer.create_template("High Severity Report",
                                              severity_threshold="high")
        customizer.save_template(template)

        output = str(tmp_path / "report.md")
        customizer.generate_report("High Severity Report", engagement_db_with_data,
                                   output, "markdown")
        content = open(output, 'r', encoding='utf-8').read()
        # Should include critical and high
        assert "SQL Injection" in content
        assert "XSS Stored" in content
        # Should NOT include medium, low, or informational
        assert "Missing HSTS" not in content
        assert "Information Disclosure" not in content

    def test_conditional_section_in_generated_report(self, customizer, engagement_db, tmp_path):
        """Report without ATT&CK data should not have ATT&CK section."""
        template = customizer.create_template("No Attack Data")
        customizer.save_template(template)

        output = str(tmp_path / "report.md")
        customizer.generate_report("No Attack Data", engagement_db,
                                   output, "markdown")
        content = open(output, 'r', encoding='utf-8').read()
        assert "ATT&CK Coverage" not in content

    def test_branding_in_generated_report(self, customizer, engagement_db_with_data, tmp_path):
        """Branding elements should appear in generated report."""
        branding = {
            "logo_path": "",
            "company_name": "Acme Security",
            "primary_color": "#ff0000",
            "secondary_color": "#00ff00",
            "header_text": "CONFIDENTIAL",
            "footer_text": "© 2024 Acme Security",
            "cover_page": True,
        }
        template = customizer.create_template("Branded", branding=branding)
        customizer.save_template(template)

        output = str(tmp_path / "report.md")
        customizer.generate_report("Branded", engagement_db_with_data,
                                   output, "markdown")
        content = open(output, 'r', encoding='utf-8').read()
        assert "Acme Security" in content
        assert "© 2024 Acme Security" in content


class TestReportSectionDataclass:
    """Tests for ReportSection dataclass."""

    def test_to_dict(self):
        """to_dict should produce a valid dictionary."""
        section = ReportSection(id="test", title="Test Section",
                                enabled=True, conditional=False, condition_key=None)
        d = section.to_dict()
        assert d["id"] == "test"
        assert d["title"] == "Test Section"
        assert d["enabled"] is True

    def test_from_dict(self):
        """from_dict should create a valid ReportSection."""
        data = {"id": "findings", "title": "Findings",
                "enabled": True, "conditional": False, "condition_key": None}
        section = ReportSection.from_dict(data)
        assert section.id == "findings"
        assert section.title == "Findings"

    def test_from_dict_minimal(self):
        """from_dict with minimal data should use defaults."""
        data = {"id": "test", "title": "Test"}
        section = ReportSection.from_dict(data)
        assert section.enabled is True
        assert section.conditional is False
        assert section.condition_key is None


class TestReportTemplateDataclass:
    """Tests for ReportTemplate dataclass."""

    def test_roundtrip(self):
        """to_dict/from_dict should be a lossless roundtrip."""
        template = ReportTemplate(
            name="Roundtrip Test",
            sections=[ReportSection(id="findings", title="Findings")],
            branding={"company_name": "Test", "cover_page": True,
                      "logo_path": "", "primary_color": "#000",
                      "secondary_color": "#fff", "header_text": "",
                      "footer_text": ""},
            severity_threshold="high",
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )
        d = template.to_dict()
        restored = ReportTemplate.from_dict(d)
        assert restored.name == template.name
        assert restored.severity_threshold == template.severity_threshold
        assert len(restored.sections) == len(template.sections)
        assert restored.branding["company_name"] == "Test"
