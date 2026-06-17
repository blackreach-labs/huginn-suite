# tests/test_attack_mapper.py
"""Tests for the ATT&CK mapper engine."""

import pytest

from app.core.engagement_database import EngagementDatabase
from app.core.attack_mapper import (
    ATTACKMapper,
    ATTACK_ENTERPRISE_MATRIX,
    TACTICS,
    MAPPING_STATUSES,
)


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database for testing."""
    db_path = str(tmp_path / "test_engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def mapper(engagement_db):
    """Create an ATTACKMapper with a connected database."""
    m = ATTACKMapper()
    m.set_database(engagement_db)
    return m


@pytest.fixture
def sample_finding(engagement_db):
    """Insert a sample finding and return its ID."""
    finding_id = engagement_db.execute_write(
        """INSERT INTO findings (title, severity, description, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)""",
        ("SQL Injection in Login", "critical",
         "SQL injection vulnerability allowing authentication bypass via login form",
         "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
    )
    return finding_id


@pytest.fixture
def sample_finding_with_evidence(engagement_db):
    """Insert a finding with linked evidence."""
    finding_id = engagement_db.execute_write(
        """INSERT INTO findings (title, severity, description, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)""",
        ("PowerShell Execution", "high",
         "Adversary used PowerShell to execute malicious commands",
         "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
    )
    evidence_id = engagement_db.execute_write(
        """INSERT INTO evidence (evidence_type, title, data, sha256_hash, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        ("screenshot", "PowerShell Screenshot", b"img_data",
         "abc123hash", "2024-01-01T00:00:00"),
    )
    engagement_db.execute_write(
        """INSERT INTO evidence_finding_links (evidence_id, finding_id, linked_at)
           VALUES (?, ?, ?)""",
        (evidence_id, finding_id, "2024-01-01T00:00:00"),
    )
    return {"finding_id": finding_id, "evidence_id": evidence_id}


class TestATTACKMapperSetup:
    """Tests for database configuration and initialization."""

    def test_no_database_raises(self):
        """Operations should raise RuntimeError if no database is set."""
        m = ATTACKMapper()
        with pytest.raises(RuntimeError, match="No database set"):
            m.map_finding_to_technique(1, "T1059", "execution")

    def test_set_database(self, engagement_db):
        """set_database should configure the internal database reference."""
        m = ATTACKMapper()
        assert m.database is None
        m.set_database(engagement_db)
        assert m.database is engagement_db

    def test_bundled_matrix_has_minimum_techniques(self):
        """The bundled matrix should contain at least 50 techniques."""
        assert len(ATTACK_ENTERPRISE_MATRIX) >= 50

    def test_all_14_tactics_covered(self):
        """The bundled matrix should have techniques for all 14 tactics."""
        covered_tactics = set()
        for technique in ATTACK_ENTERPRISE_MATRIX:
            for tactic in technique["tactics"]:
                covered_tactics.add(tactic)
        for tactic in TACTICS:
            assert tactic in covered_tactics, f"Tactic '{tactic}' has no techniques"

    def test_technique_structure(self):
        """Each technique should have required fields."""
        required_fields = {"technique_id", "name", "tactics", "platforms",
                          "data_sources", "description"}
        for technique in ATTACK_ENTERPRISE_MATRIX:
            for field in required_fields:
                assert field in technique, f"Technique {technique.get('technique_id', '?')} missing '{field}'"


class TestTechniqueAccess:
    """Tests for technique data retrieval methods."""

    def test_get_all_techniques(self, mapper):
        """get_all_techniques returns all bundled techniques."""
        techniques = mapper.get_all_techniques()
        assert len(techniques) == len(ATTACK_ENTERPRISE_MATRIX)

    def test_get_technique_by_id(self, mapper):
        """get_technique returns the correct technique for a valid ID."""
        technique = mapper.get_technique("T1059.001")
        assert technique is not None
        assert technique["name"] == "PowerShell"
        assert "execution" in technique["tactics"]

    def test_get_technique_nonexistent(self, mapper):
        """get_technique returns None for unknown ID."""
        assert mapper.get_technique("T9999") is None

    def test_get_techniques_by_tactic(self, mapper):
        """get_techniques_by_tactic returns techniques for a specific tactic."""
        exec_techniques = mapper.get_techniques_by_tactic("execution")
        assert len(exec_techniques) > 0
        for t in exec_techniques:
            assert "execution" in t["tactics"]

    def test_get_techniques_by_tactic_empty(self, mapper):
        """get_techniques_by_tactic returns empty for unknown tactic."""
        assert mapper.get_techniques_by_tactic("nonexistent") == []

    def test_get_techniques_by_platform(self, mapper):
        """get_techniques_by_platform filters by platform."""
        windows_techniques = mapper.get_techniques_by_platform("Windows")
        assert len(windows_techniques) > 0
        for t in windows_techniques:
            assert "Windows" in t["platforms"]

    def test_get_techniques_by_data_source(self, mapper):
        """get_techniques_by_data_source filters by data source."""
        network_techniques = mapper.get_techniques_by_data_source("Network Traffic")
        assert len(network_techniques) > 0
        for t in network_techniques:
            assert "Network Traffic" in t["data_sources"]


class TestMapFindingToTechnique:
    """Tests for map_finding_to_technique()."""

    def test_basic_mapping(self, mapper, sample_finding):
        """Should create a mapping record and return its ID."""
        mapping_id = mapper.map_finding_to_technique(
            finding_id=sample_finding,
            technique_id="T1190",
            tactic="initial-access",
            procedure_description="Exploited SQL injection in login page",
            status="successful",
        )
        assert isinstance(mapping_id, int)
        assert mapping_id > 0

    def test_mapping_stored_in_db(self, mapper, sample_finding, engagement_db):
        """Mapping should be persisted in the attack_mappings table."""
        mapper.map_finding_to_technique(
            finding_id=sample_finding,
            technique_id="T1190",
            tactic="initial-access",
            procedure_description="Exploited web app",
            status="tested",
        )
        rows = engagement_db.execute_query(
            "SELECT technique_id, tactic, procedure_description, status FROM attack_mappings WHERE finding_id = ?",
            (sample_finding,),
        )
        assert len(rows) == 1
        assert rows[0][0] == "T1190"
        assert rows[0][1] == "initial-access"
        assert rows[0][2] == "Exploited web app"
        assert rows[0][3] == "tested"

    def test_mapping_default_status(self, mapper, sample_finding, engagement_db):
        """Default status should be 'tested'."""
        mapper.map_finding_to_technique(
            finding_id=sample_finding,
            technique_id="T1190",
            tactic="initial-access",
        )
        rows = engagement_db.execute_query(
            "SELECT status FROM attack_mappings WHERE finding_id = ?",
            (sample_finding,),
        )
        assert rows[0][0] == "tested"

    def test_mapping_invalid_technique_raises(self, mapper, sample_finding):
        """Unknown technique_id should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown technique_id"):
            mapper.map_finding_to_technique(
                finding_id=sample_finding,
                technique_id="T9999",
                tactic="execution",
            )

    def test_mapping_invalid_tactic_raises(self, mapper, sample_finding):
        """Invalid tactic should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid tactic"):
            mapper.map_finding_to_technique(
                finding_id=sample_finding,
                technique_id="T1059",
                tactic="nonexistent_tactic",
            )

    def test_mapping_invalid_status_raises(self, mapper, sample_finding):
        """Invalid status should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid status"):
            mapper.map_finding_to_technique(
                finding_id=sample_finding,
                technique_id="T1059",
                tactic="execution",
                status="invalid_status",
            )

    def test_mapping_technique_tactic_mismatch_raises(self, mapper, sample_finding):
        """Mapping technique to wrong tactic should raise ValueError."""
        # T1059 is execution, not lateral-movement
        with pytest.raises(ValueError, match="does not belong to tactic"):
            mapper.map_finding_to_technique(
                finding_id=sample_finding,
                technique_id="T1059",
                tactic="lateral-movement",
            )

    def test_mapping_emits_signals(self, mapper, sample_finding, qtbot):
        """mapping_created and coverage_updated signals should be emitted."""
        with qtbot.waitSignal(mapper.mapping_created, timeout=1000) as blocker:
            mapping_id = mapper.map_finding_to_technique(
                finding_id=sample_finding,
                technique_id="T1190",
                tactic="initial-access",
            )
        assert blocker.args == [mapping_id]

    def test_multiple_mappings_per_finding(self, mapper, sample_finding, engagement_db):
        """A finding can have multiple technique mappings."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access")
        mapper.map_finding_to_technique(sample_finding, "T1059", "execution")

        rows = engagement_db.execute_query(
            "SELECT COUNT(*) FROM attack_mappings WHERE finding_id = ?",
            (sample_finding,),
        )
        assert rows[0][0] == 2

    def test_get_mappings_for_finding(self, mapper, sample_finding):
        """get_mappings_for_finding returns all mappings for a finding."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access", "Exploited web app")
        mapper.map_finding_to_technique(sample_finding, "T1059", "execution", "Ran commands")

        mappings = mapper.get_mappings_for_finding(sample_finding)
        assert len(mappings) == 2
        technique_ids = {m["technique_id"] for m in mappings}
        assert "T1190" in technique_ids
        assert "T1059" in technique_ids


class TestDeleteMapping:
    """Tests for delete_mapping()."""

    def test_delete_existing_mapping(self, mapper, sample_finding, engagement_db):
        """Should remove the mapping from the database."""
        mapping_id = mapper.map_finding_to_technique(
            sample_finding, "T1190", "initial-access"
        )
        result = mapper.delete_mapping(mapping_id)
        assert result is True

        rows = engagement_db.execute_query(
            "SELECT COUNT(*) FROM attack_mappings WHERE id = ?", (mapping_id,)
        )
        assert rows[0][0] == 0

    def test_delete_nonexistent_returns_false(self, mapper):
        """Deleting a non-existent mapping returns False."""
        result = mapper.delete_mapping(99999)
        assert result is False


class TestCoverageMatrix:
    """Tests for get_coverage_matrix()."""

    def test_empty_coverage(self, mapper):
        """With no mappings, all techniques should be not_covered."""
        matrix = mapper.get_coverage_matrix()
        assert len(matrix) == len(ATTACK_ENTERPRISE_MATRIX)
        for entry in matrix:
            assert entry["coverage_status"] == "not_covered"
            assert entry["mapping_count"] == 0

    def test_tested_coverage(self, mapper, sample_finding):
        """Techniques with 'tested' mappings should show as 'tested'."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access", status="tested")

        matrix = mapper.get_coverage_matrix()
        t1190_entry = next(e for e in matrix if e["technique_id"] == "T1190")
        assert t1190_entry["coverage_status"] == "tested"
        assert t1190_entry["mapping_count"] == 1

    def test_successful_coverage(self, mapper, sample_finding):
        """Techniques with 'successful' mappings should show as 'successful'."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access", status="successful")

        matrix = mapper.get_coverage_matrix()
        t1190_entry = next(e for e in matrix if e["technique_id"] == "T1190")
        assert t1190_entry["coverage_status"] == "successful"

    def test_successful_overrides_tested(self, mapper, engagement_db):
        """If any mapping is 'successful', the technique is 'successful'."""
        # Create two findings
        f1 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("Finding 1", "high", "2024-01-01", "2024-01-01"),
        )
        f2 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("Finding 2", "medium", "2024-01-01", "2024-01-01"),
        )
        mapper.map_finding_to_technique(f1, "T1190", "initial-access", status="tested")
        mapper.map_finding_to_technique(f2, "T1190", "initial-access", status="successful")

        matrix = mapper.get_coverage_matrix()
        t1190_entry = next(e for e in matrix if e["technique_id"] == "T1190")
        assert t1190_entry["coverage_status"] == "successful"
        assert t1190_entry["mapping_count"] == 2

    def test_filter_by_tactic(self, mapper, sample_finding):
        """Filtering by tactic should only return techniques for that tactic."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access")

        matrix = mapper.get_coverage_matrix(tactic_filter="initial-access")
        for entry in matrix:
            assert "initial-access" in entry["tactics"]

        # The filtered matrix should be smaller than total
        full_matrix = mapper.get_coverage_matrix()
        assert len(matrix) < len(full_matrix)

    def test_filter_by_platform(self, mapper, sample_finding):
        """Filtering by platform should only return matching techniques."""
        matrix = mapper.get_coverage_matrix(platform_filter="Windows")
        for entry in matrix:
            assert "Windows" in entry["platforms"]

    def test_filter_by_data_source(self, mapper, sample_finding):
        """Filtering by data source should only return matching techniques."""
        matrix = mapper.get_coverage_matrix(data_source_filter="Network Traffic")
        for entry in matrix:
            assert "Network Traffic" in entry["data_sources"]

    def test_matrix_entry_structure(self, mapper):
        """Each matrix entry should have required fields."""
        matrix = mapper.get_coverage_matrix()
        required_fields = {"technique_id", "name", "tactics", "platforms",
                          "data_sources", "coverage_status", "mapping_count"}
        for entry in matrix:
            for field in required_fields:
                assert field in entry


class TestGetFindingsForTechnique:
    """Tests for get_findings_for_technique()."""

    def test_basic_findings_retrieval(self, mapper, sample_finding):
        """Should return findings mapped to a technique."""
        mapper.map_finding_to_technique(
            sample_finding, "T1190", "initial-access",
            procedure_description="Exploited SQL injection",
            status="successful",
        )

        results = mapper.get_findings_for_technique("T1190")
        assert len(results) == 1
        result = results[0]
        assert result["finding_id"] == sample_finding
        assert result["finding_title"] == "SQL Injection in Login"
        assert result["finding_severity"] == "critical"
        assert result["tactic"] == "initial-access"
        assert result["procedure_description"] == "Exploited SQL injection"
        assert result["status"] == "successful"

    def test_findings_include_evidence(self, mapper, sample_finding_with_evidence):
        """Should include linked evidence for each finding."""
        fid = sample_finding_with_evidence["finding_id"]
        eid = sample_finding_with_evidence["evidence_id"]

        mapper.map_finding_to_technique(fid, "T1059.001", "execution", "Used PowerShell")

        results = mapper.get_findings_for_technique("T1059.001")
        assert len(results) == 1
        assert len(results[0]["evidence"]) == 1
        assert results[0]["evidence"][0]["id"] == eid
        assert results[0]["evidence"][0]["evidence_type"] == "screenshot"

    def test_no_findings_returns_empty(self, mapper):
        """Should return empty list for technique with no mappings."""
        results = mapper.get_findings_for_technique("T1190")
        assert results == []

    def test_multiple_findings_for_technique(self, mapper, engagement_db):
        """Multiple findings mapped to same technique should all be returned."""
        f1 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("Finding A", "high", "First finding", "2024-01-01", "2024-01-01"),
        )
        f2 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("Finding B", "medium", "Second finding", "2024-01-02", "2024-01-02"),
        )
        mapper.map_finding_to_technique(f1, "T1059", "execution", "First procedure")
        mapper.map_finding_to_technique(f2, "T1059", "execution", "Second procedure")

        results = mapper.get_findings_for_technique("T1059")
        assert len(results) == 2
        titles = {r["finding_title"] for r in results}
        assert "Finding A" in titles
        assert "Finding B" in titles


class TestSuggestTechniques:
    """Tests for suggest_techniques()."""

    def test_suggest_from_description(self, mapper):
        """Should suggest relevant techniques from description keywords."""
        suggestions = mapper.suggest_techniques("PowerShell malicious commands execution")
        assert len(suggestions) > 0
        # PowerShell technique should be highly ranked
        technique_ids = [s["technique_id"] for s in suggestions]
        assert "T1059.001" in technique_ids

    def test_suggest_phishing(self, mapper):
        """Should suggest phishing techniques for phishing-related descriptions."""
        suggestions = mapper.suggest_techniques("phishing email with malicious attachment")
        assert len(suggestions) > 0
        technique_ids = [s["technique_id"] for s in suggestions]
        assert "T1566" in technique_ids or "T1566.001" in technique_ids

    def test_suggest_brute_force(self, mapper):
        """Should suggest brute force for password attack descriptions."""
        suggestions = mapper.suggest_techniques("brute force password attack dictionary")
        assert len(suggestions) > 0
        technique_ids = [s["technique_id"] for s in suggestions]
        assert "T1110" in technique_ids or "T1110.001" in technique_ids

    def test_suggest_empty_description(self, mapper):
        """Empty description should return no suggestions."""
        suggestions = mapper.suggest_techniques("")
        assert suggestions == []

    def test_suggest_max_results(self, mapper):
        """Should respect max_suggestions limit."""
        suggestions = mapper.suggest_techniques("attack command system", max_suggestions=3)
        assert len(suggestions) <= 3

    def test_suggest_includes_score(self, mapper):
        """Each suggestion should include a relevance score."""
        suggestions = mapper.suggest_techniques("credential dumping LSASS memory")
        assert len(suggestions) > 0
        for s in suggestions:
            assert "score" in s
            assert s["score"] > 0

    def test_suggest_sorted_by_score(self, mapper):
        """Suggestions should be sorted by score descending."""
        suggestions = mapper.suggest_techniques("remote desktop lateral movement")
        if len(suggestions) > 1:
            for i in range(len(suggestions) - 1):
                assert suggestions[i]["score"] >= suggestions[i + 1]["score"]

    def test_suggest_technique_id_in_description(self, mapper):
        """Mentioning a technique ID in description should boost that technique."""
        suggestions = mapper.suggest_techniques("Observed T1059.001 usage in the environment")
        assert len(suggestions) > 0
        # T1059.001 should be among top suggestions due to ID mention
        top_ids = [s["technique_id"] for s in suggestions[:3]]
        assert "T1059.001" in top_ids


class TestReportSummary:
    """Tests for get_report_summary()."""

    def test_empty_summary(self, mapper):
        """With no mappings, summary should show zero coverage."""
        summary = mapper.get_report_summary()
        assert summary["total_techniques"] == len(ATTACK_ENTERPRISE_MATRIX)
        assert summary["techniques_tested"] == 0
        assert summary["techniques_successful"] == 0
        assert summary["techniques_not_covered"] == len(ATTACK_ENTERPRISE_MATRIX)
        assert summary["overall_coverage_percentage"] == 0.0
        assert summary["total_mappings"] == 0

    def test_summary_with_mappings(self, mapper, engagement_db):
        """Summary should reflect mapped techniques correctly."""
        f1 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("Finding 1", "high", "2024-01-01", "2024-01-01"),
        )
        f2 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("Finding 2", "critical", "2024-01-01", "2024-01-01"),
        )

        mapper.map_finding_to_technique(f1, "T1190", "initial-access", status="tested")
        mapper.map_finding_to_technique(f2, "T1059.001", "execution", status="successful")

        summary = mapper.get_report_summary()
        assert summary["techniques_tested"] == 2  # 1 tested + 1 successful
        assert summary["techniques_successful"] == 1
        assert summary["techniques_not_covered"] == len(ATTACK_ENTERPRISE_MATRIX) - 2
        assert summary["total_mappings"] == 2
        assert summary["overall_coverage_percentage"] > 0

    def test_summary_coverage_by_tactic(self, mapper, sample_finding):
        """Summary should include per-tactic coverage breakdown."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access", status="successful")

        summary = mapper.get_report_summary()
        assert "coverage_by_tactic" in summary
        assert len(summary["coverage_by_tactic"]) == len(TACTICS)

        # initial-access tactic should have some coverage
        ia_coverage = summary["coverage_by_tactic"]["initial-access"]
        assert ia_coverage["tested"] > 0
        assert ia_coverage["successful"] > 0
        assert ia_coverage["total"] > 0
        assert ia_coverage["coverage_percentage"] > 0

    def test_summary_tactic_structure(self, mapper):
        """Each tactic in coverage_by_tactic should have required fields."""
        summary = mapper.get_report_summary()
        required_fields = {"total", "tested", "successful", "not_covered", "coverage_percentage"}
        for tactic, data in summary["coverage_by_tactic"].items():
            for field in required_fields:
                assert field in data, f"Tactic '{tactic}' missing field '{field}'"

    def test_summary_total_consistency(self, mapper, sample_finding):
        """Total should equal tested + not_covered (tested includes successful)."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access", status="successful")
        mapper.map_finding_to_technique(sample_finding, "T1059", "execution", status="tested")

        summary = mapper.get_report_summary()
        total = summary["total_techniques"]
        tested = summary["techniques_tested"]
        not_covered = summary["techniques_not_covered"]
        assert total == tested + not_covered


class TestFiltering:
    """Tests for filtering capabilities across methods."""

    def test_coverage_combined_filters(self, mapper, sample_finding):
        """Multiple filters should be applied simultaneously."""
        mapper.map_finding_to_technique(sample_finding, "T1190", "initial-access")

        # Filter by both tactic and platform
        matrix = mapper.get_coverage_matrix(
            tactic_filter="initial-access",
            platform_filter="Windows",
        )
        for entry in matrix:
            assert "initial-access" in entry["tactics"]
            assert "Windows" in entry["platforms"]

    def test_platform_filter_pre(self, mapper):
        """PRE platform filter should return recon/resource-dev techniques."""
        matrix = mapper.get_coverage_matrix(platform_filter="PRE")
        assert len(matrix) > 0
        for entry in matrix:
            assert "PRE" in entry["platforms"]
