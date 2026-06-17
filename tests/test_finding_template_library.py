"""Tests for the FindingTemplateLibrary engine.

Covers:
- Template CRUD operations
- FTS5 search across multiple fields
- Template-to-finding conversion with isolation
- JSON export/import round-trip
- Built-in template seeding
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from app.core.finding_template_library import (
    FindingTemplateLibrary,
    BUILTIN_TEMPLATES,
    TEMPLATE_CATEGORIES,
    VALID_SEVERITIES,
)
from app.core.engagement_database import EngagementDatabase


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary templates database path."""
    return str(tmp_path / "templates" / "finding_templates.db")


@pytest.fixture
def library(tmp_db):
    """Create a FindingTemplateLibrary with a temp database."""
    lib = FindingTemplateLibrary(db_path=tmp_db)
    yield lib
    lib.close()


@pytest.fixture
def empty_library(tmp_path):
    """Create a FindingTemplateLibrary that won't auto-seed (by pre-creating a template)."""
    db_path = str(tmp_path / "empty_templates" / "finding_templates.db")
    lib = FindingTemplateLibrary(db_path=db_path)
    yield lib
    lib.close()


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database for finding creation tests."""
    db_path = str(tmp_path / "engagement" / "engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


# ===========================================================================
# Built-in Template Seeding Tests
# ===========================================================================

class TestBuiltinSeeding:
    """Tests for automatic seeding of built-in templates."""

    def test_seeds_builtin_templates_on_first_init(self, library):
        count = library.get_template_count()
        assert count >= 50, f"Expected at least 50 built-in templates, got {count}"

    def test_builtin_templates_count_matches_constant(self, library):
        count = library.get_template_count()
        assert count == len(BUILTIN_TEMPLATES)

    def test_all_builtin_templates_marked_as_builtin(self, library):
        templates = library.list_templates()
        for t in templates:
            assert t["is_builtin"] is True

    def test_does_not_reseed_on_second_init(self, tmp_db):
        # First init seeds
        lib1 = FindingTemplateLibrary(db_path=tmp_db)
        count1 = lib1.get_template_count()
        lib1.close()

        # Second init should not reseed
        lib2 = FindingTemplateLibrary(db_path=tmp_db)
        count2 = lib2.get_template_count()
        lib2.close()

        assert count1 == count2

    def test_builtin_templates_cover_all_categories(self, library):
        categories = library.get_categories()
        for expected_cat in TEMPLATE_CATEGORIES:
            assert expected_cat in categories, f"Missing category: {expected_cat}"

    def test_builtin_templates_cover_owasp_top_10(self, library):
        results = library.search_templates("owasp-top-10")
        assert len(results) >= 10, "Expected at least 10 OWASP Top 10 templates"


# ===========================================================================
# CRUD Tests
# ===========================================================================

class TestTemplateCRUD:
    """Tests for create, read, update, delete operations."""

    def test_create_template_returns_id(self, library):
        tid = library.create_template(
            title="Test Template",
            severity="High",
            category="Web Application",
            description="Test description",
            impact="Test impact",
            remediation="Test remediation",
        )
        assert tid is not None
        assert len(tid) == 36  # UUID format

    def test_create_template_with_all_fields(self, library):
        tid = library.create_template(
            title="Full Template",
            severity="Critical",
            category="Network",
            description="Full description",
            impact="Full impact",
            remediation="Full remediation",
            references=["https://example.com"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-89",
            tags=["sql", "injection"],
        )
        template = library.get_template(tid)
        assert template is not None
        assert template["title"] == "Full Template"
        assert template["severity"] == "Critical"
        assert template["category"] == "Network"
        assert template["references"] == ["https://example.com"]
        assert template["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert template["cwe_id"] == "CWE-89"
        assert template["tags"] == ["sql", "injection"]

    def test_get_template_returns_none_for_nonexistent(self, library):
        result = library.get_template("nonexistent-id")
        assert result is None

    def test_update_template_title(self, library):
        tid = library.create_template(
            title="Original Title",
            severity="Medium",
            category="Infrastructure",
            description="desc",
            impact="impact",
            remediation="fix",
        )
        result = library.update_template(tid, title="Updated Title")
        assert result is True

        template = library.get_template(tid)
        assert template["title"] == "Updated Title"

    def test_update_template_multiple_fields(self, library):
        tid = library.create_template(
            title="Multi Update",
            severity="Low",
            category="Cloud",
            description="old desc",
            impact="old impact",
            remediation="old fix",
        )
        library.update_template(
            tid,
            severity="High",
            description="new desc",
            tags=["cloud", "iam"],
        )
        template = library.get_template(tid)
        assert template["severity"] == "High"
        assert template["description"] == "new desc"
        assert template["tags"] == ["cloud", "iam"]

    def test_update_nonexistent_template_returns_false(self, library):
        result = library.update_template("nonexistent-id", title="New")
        assert result is False

    def test_delete_template(self, library):
        tid = library.create_template(
            title="To Delete",
            severity="Low",
            category="Physical",
            description="desc",
            impact="impact",
            remediation="fix",
        )
        result = library.delete_template(tid)
        assert result is True
        assert library.get_template(tid) is None

    def test_delete_nonexistent_template_returns_false(self, library):
        result = library.delete_template("nonexistent-id")
        assert result is False

    def test_list_templates_returns_all(self, library):
        templates = library.list_templates()
        assert len(templates) == len(BUILTIN_TEMPLATES)

    def test_list_templates_filter_by_category(self, library):
        templates = library.list_templates(category="Web Application")
        assert all(t["category"] == "Web Application" for t in templates)
        assert len(templates) > 0

    def test_list_templates_filter_by_severity(self, library):
        templates = library.list_templates(severity="Critical")
        assert all(t["severity"] == "Critical" for t in templates)
        assert len(templates) > 0


# ===========================================================================
# FTS5 Search Tests
# ===========================================================================

class TestSearch:
    """Tests for FTS5 full-text search functionality."""

    def test_search_by_title(self, library):
        results = library.search_templates("SQL Injection")
        assert len(results) > 0
        # Should find the SQL Injection template
        titles = [r["title"] for r in results]
        assert any("SQL Injection" in t for t in titles)

    def test_search_by_cwe_id(self, library):
        results = library.search_templates("CWE-79")
        assert len(results) > 0
        # Should find XSS templates
        cwe_ids = [r["cwe_id"] for r in results]
        assert any("CWE-79" in c for c in cwe_ids if c)

    def test_search_by_category(self, library):
        results = library.search_templates("Network")
        assert len(results) > 0

    def test_search_by_tag(self, library):
        results = library.search_templates("owasp-top-10")
        assert len(results) >= 10

    def test_search_by_description_keyword(self, library):
        results = library.search_templates("brute-force")
        assert len(results) > 0

    def test_search_empty_query_returns_all(self, library):
        results = library.search_templates("")
        assert len(results) == library.get_template_count()

    def test_search_no_results(self, library):
        results = library.search_templates("xyznonexistentterm123")
        assert len(results) == 0

    def test_search_partial_match(self, library):
        # Search for partial term - should use prefix matching
        results = library.search_templates("inject")
        assert len(results) > 0

    def test_search_finds_custom_template(self, library):
        library.create_template(
            title="Custom UniqueSearchTerm Template",
            severity="High",
            category="Web Application",
            description="A custom template for testing search",
            impact="Test impact",
            remediation="Test remediation",
            tags=["custom", "unique-tag-xyz"],
        )
        results = library.search_templates("UniqueSearchTerm")
        assert len(results) >= 1
        assert any("UniqueSearchTerm" in r["title"] for r in results)


# ===========================================================================
# Template → Finding Conversion Tests
# ===========================================================================

class TestCreateFindingFromTemplate:
    """Tests for creating findings from templates."""

    def test_create_finding_copies_all_fields(self, library, engagement_db):
        # Get a known template
        templates = library.list_templates(category="Web Application")
        assert len(templates) > 0
        template = templates[0]

        finding_id = library.create_finding_from_template(
            template["id"], engagement_db
        )
        assert finding_id is not None
        assert finding_id > 0

        # Verify the finding was created with template fields
        rows = engagement_db.execute_query(
            "SELECT title, severity, description, impact, remediation, cvss_vector, cwe_id, category, template_id FROM findings WHERE id = ?",
            (finding_id,),
        )
        assert len(rows) == 1
        row = rows[0]
        assert row[0] == template["title"]
        assert row[1] == template["severity"]
        assert row[2] == template["description"]
        assert row[3] == template["impact"]
        assert row[4] == template["remediation"]
        assert row[5] == template["cvss_vector"]
        assert row[6] == template["cwe_id"]
        assert row[7] == template["category"]
        assert row[8] == template["id"]  # template_id stored as reference

    def test_create_finding_with_overrides(self, library, engagement_db):
        templates = library.list_templates()
        template = templates[0]

        finding_id = library.create_finding_from_template(
            template["id"],
            engagement_db,
            overrides={"title": "Custom Title", "severity": "Low"},
        )

        rows = engagement_db.execute_query(
            "SELECT title, severity FROM findings WHERE id = ?",
            (finding_id,),
        )
        assert rows[0][0] == "Custom Title"
        assert rows[0][1] == "Low"

    def test_create_finding_nonexistent_template_returns_none(self, library, engagement_db):
        result = library.create_finding_from_template("nonexistent-id", engagement_db)
        assert result is None

    def test_template_isolation_from_findings(self, library, engagement_db):
        """Editing a template MUST NOT affect an already-created finding (Req 2.6)."""
        tid = library.create_template(
            title="Isolation Test Template",
            severity="High",
            category="Network",
            description="Original description",
            impact="Original impact",
            remediation="Original remediation",
        )

        # Create a finding from the template
        finding_id = library.create_finding_from_template(tid, engagement_db)

        # Now update the template
        library.update_template(
            tid,
            title="Modified Title",
            description="Modified description",
            severity="Critical",
        )

        # Verify the finding is UNCHANGED
        rows = engagement_db.execute_query(
            "SELECT title, severity, description FROM findings WHERE id = ?",
            (finding_id,),
        )
        assert rows[0][0] == "Isolation Test Template"
        assert rows[0][1] == "High"
        assert rows[0][2] == "Original description"

        # Verify the template IS changed
        template = library.get_template(tid)
        assert template["title"] == "Modified Title"
        assert template["severity"] == "Critical"


# ===========================================================================
# Export / Import Tests
# ===========================================================================

class TestExportImport:
    """Tests for JSON export and import functionality."""

    def test_export_creates_json_file(self, library, tmp_path):
        output_path = str(tmp_path / "export" / "templates.json")
        result = library.export_templates(output_path)
        assert result is True
        assert Path(output_path).exists()

    def test_export_contains_all_templates(self, library, tmp_path):
        output_path = str(tmp_path / "export.json")
        library.export_templates(output_path)

        with open(output_path, "r") as f:
            data = json.load(f)

        assert data["template_count"] == library.get_template_count()
        assert len(data["templates"]) == library.get_template_count()
        assert "version" in data
        assert "export_date" in data

    def test_export_specific_templates(self, library, tmp_path):
        templates = library.list_templates()
        selected_ids = [templates[0]["id"], templates[1]["id"]]
        output_path = str(tmp_path / "partial_export.json")

        library.export_templates(output_path, template_ids=selected_ids)

        with open(output_path, "r") as f:
            data = json.load(f)

        assert data["template_count"] == 2
        assert len(data["templates"]) == 2

    def test_import_round_trip(self, library, tmp_path):
        """Export then import produces identical templates (Req 2.8)."""
        # Export from original library
        export_path = str(tmp_path / "roundtrip.json")
        library.export_templates(export_path)
        original_count = library.get_template_count()
        original_templates = library.list_templates()

        # Create a new library and import
        new_db_path = str(tmp_path / "import_test" / "templates.db")
        new_lib = FindingTemplateLibrary(db_path=new_db_path)

        # The new library auto-seeded, so clear it by using overwrite
        imported, skipped, warnings = new_lib.import_templates(
            export_path, overwrite_existing=True
        )

        # Verify the templates match
        for orig in original_templates:
            imported_template = new_lib.get_template(orig["id"])
            assert imported_template is not None, f"Template {orig['id']} not found after import"
            assert imported_template["title"] == orig["title"]
            assert imported_template["severity"] == orig["severity"]
            assert imported_template["category"] == orig["category"]
            assert imported_template["description"] == orig["description"]
            assert imported_template["impact"] == orig["impact"]
            assert imported_template["remediation"] == orig["remediation"]

        new_lib.close()

    def test_import_skips_existing_without_overwrite(self, library, tmp_path):
        export_path = str(tmp_path / "skip_test.json")
        library.export_templates(export_path)

        # Import into same library without overwrite
        imported, skipped, warnings = library.import_templates(
            export_path, overwrite_existing=False
        )

        assert imported == 0
        assert skipped == library.get_template_count()

    def test_import_handles_malformed_file(self, library, tmp_path):
        bad_file = str(tmp_path / "bad.json")
        with open(bad_file, "w") as f:
            f.write("not valid json{{{")

        imported, skipped, warnings = library.import_templates(bad_file)
        assert imported == 0
        assert len(warnings) > 0

    def test_import_handles_missing_fields(self, library, tmp_path):
        partial_file = str(tmp_path / "partial.json")
        data = {
            "version": "1.0",
            "templates": [
                {"title": "Incomplete Template"},  # Missing required fields
                {
                    "id": "valid-import-id",
                    "title": "Valid Template",
                    "severity": "High",
                    "category": "Network",
                    "description": "A valid template",
                    "impact": "Some impact",
                    "remediation": "Some fix",
                },
            ],
        }
        with open(partial_file, "w") as f:
            json.dump(data, f)

        imported, skipped, warnings = library.import_templates(partial_file)
        # The valid template should import, the incomplete should be skipped
        assert imported == 1
        assert skipped == 1
        assert len(warnings) > 0

    def test_import_nonexistent_file(self, library):
        imported, skipped, warnings = library.import_templates("/nonexistent/path.json")
        assert imported == 0
        assert len(warnings) > 0


# ===========================================================================
# Category and Utility Tests
# ===========================================================================

class TestUtilities:
    """Tests for utility methods."""

    def test_get_categories_returns_distinct(self, library):
        categories = library.get_categories()
        assert len(categories) > 0
        # No duplicates
        assert len(categories) == len(set(categories))

    def test_get_template_count(self, library):
        count = library.get_template_count()
        assert count == len(BUILTIN_TEMPLATES)

    def test_custom_template_not_marked_builtin(self, library):
        tid = library.create_template(
            title="Custom Template",
            severity="Low",
            category="Mobile",
            description="desc",
            impact="impact",
            remediation="fix",
            is_builtin=False,
        )
        template = library.get_template(tid)
        assert template["is_builtin"] is False
