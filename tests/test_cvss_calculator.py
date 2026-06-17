"""Tests for the CVSS Calculator engine.

Validates CVSS v3.1 and v4.0 scoring against known reference vectors
from the NVD and FIRST specification examples.
"""

import pytest

from app.core.cvss_calculator import (
    CVSSCalculator,
    CVSSVersion,
    SEVERITY_RANGES,
)


@pytest.fixture
def calc():
    """Create a CVSSCalculator instance."""
    return CVSSCalculator()


# ---------------------------------------------------------------------------
# CVSS v3.1 Base Score Tests (NVD reference vectors)
# ---------------------------------------------------------------------------

class TestV31BaseScore:
    """Test CVSS v3.1 base score computation against known values."""

    def test_critical_all_high(self, calc):
        """CVE-2017-0144 (EternalBlue): CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.1"""
        metrics = {"AV": "N", "AC": "H", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 8.1

    def test_critical_network_low_complexity(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8"""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 9.8

    def test_max_score_scope_changed(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0"""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "C", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 10.0

    def test_medium_score(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 4.3"""
        metrics = {"AV": "N", "AC": "L", "PR": "L", "UI": "N",
                   "S": "U", "C": "L", "I": "N", "A": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 4.3

    def test_low_score_physical(self, calc):
        """CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 2.4"""
        metrics = {"AV": "P", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "L", "I": "N", "A": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 2.4

    def test_zero_score_no_impact(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N = 0.0"""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "N", "I": "N", "A": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 0.0

    def test_high_score_scope_changed_user_interaction(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1"""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "R",
                   "S": "C", "C": "L", "I": "L", "A": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 6.1

    def test_high_privileges_required(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2"""
        metrics = {"AV": "N", "AC": "L", "PR": "H", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 7.2

    def test_adjacent_network(self, calc):
        """CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.8"""
        metrics = {"AV": "A", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 8.8

    def test_local_access(self, calc):
        """CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.4"""
        metrics = {"AV": "L", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 8.4

    def test_scope_changed_low_priv(self, calc):
        """CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9"""
        metrics = {"AV": "N", "AC": "L", "PR": "L", "UI": "N",
                   "S": "C", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert base == 9.9


# ---------------------------------------------------------------------------
# CVSS v3.1 Temporal Score Tests
# ---------------------------------------------------------------------------

class TestV31TemporalScore:
    """Test CVSS v3.1 temporal score computation."""

    def test_temporal_all_not_defined(self, calc):
        """Temporal with all X (not defined) equals base score."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "E": "X", "RL": "X", "RC": "X"}
        base, temporal, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert temporal == base

    def test_temporal_reduces_score(self, calc):
        """Temporal with mitigating factors reduces score."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "E": "P", "RL": "T", "RC": "R"}
        base, temporal, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert temporal < base
        assert temporal > 0.0

    def test_temporal_functional_exploit(self, calc):
        """Temporal with functional exploit and official fix."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "E": "F", "RL": "O", "RC": "C"}
        base, temporal, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        # E:F=0.97, RL:O=0.95, RC:C=1.0 -> temporal = roundup(9.8 * 0.97 * 0.95 * 1.0)
        assert temporal == 9.1

    def test_temporal_unproven(self, calc):
        """Temporal with unproven exploit."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "E": "U", "RL": "X", "RC": "X"}
        base, temporal, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        # E:U=0.91 -> roundup(9.8 * 0.91) = roundup(8.918) = 9.0
        assert temporal == 9.0


# ---------------------------------------------------------------------------
# CVSS v3.1 Environmental Score Tests
# ---------------------------------------------------------------------------

class TestV31EnvironmentalScore:
    """Test CVSS v3.1 environmental score computation."""

    def test_environmental_all_not_defined(self, calc):
        """Environmental with all X equals base score (no temporal modifiers)."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, env = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert env == base

    def test_environmental_modified_av(self, calc):
        """Environmental with modified Attack Vector reduces score."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "MAV": "L"}
        _, _, env = calc.compute_score(CVSSVersion.V3_1, metrics)
        # Modified AV from N(0.85) to L(0.55) should reduce score
        assert env < 9.8

    def test_environmental_high_requirements(self, calc):
        """Environmental with high confidentiality requirement increases score."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "L", "I": "N", "A": "N",
                   "CR": "H"}
        base, _, env = calc.compute_score(CVSSVersion.V3_1, metrics)
        # High CR multiplier (1.5) on confidentiality should increase environmental
        assert env >= base

    def test_environmental_low_requirements(self, calc):
        """Environmental with low requirements decreases score."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "CR": "L", "IR": "L", "AR": "L"}
        base, _, env = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert env < base


# ---------------------------------------------------------------------------
# CVSS v4.0 Base Score Tests
# ---------------------------------------------------------------------------

class TestV40BaseScore:
    """Test CVSS v4.0 base score computation."""

    def test_max_v40_score(self, calc):
        """Maximum v4.0 score: all worst case metrics."""
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V4_0, metrics)
        assert base == 10.0

    def test_v40_high_complexity(self, calc):
        """v4.0 with high complexity and attack requirements."""
        metrics = {"AV": "N", "AC": "H", "AT": "P", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V4_0, metrics)
        assert base < 10.0
        assert base > 0.0

    def test_v40_no_impact(self, calc):
        """v4.0 with no impact on either system still scores based on exploitability."""
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V4_0, metrics)
        # Even with no impact, max exploitability yields a moderate score
        # due to the MacroVector lookup approach (EQ3=2, EQ4=1 but EQ1=0, EQ2=0)
        assert base < 7.0
        assert base > 0.0

    def test_v40_physical_access(self, calc):
        """v4.0 with physical access requirement."""
        metrics = {"AV": "P", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V4_0, metrics)
        # Physical access reduces exploitability
        assert base < 10.0

    def test_v40_returns_zero_temporal_env(self, calc):
        """v4.0 always returns 0.0 for temporal and environmental (unified model)."""
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"}
        _, temporal, env = calc.compute_score(CVSSVersion.V4_0, metrics)
        assert temporal == 0.0
        assert env == 0.0

    def test_v40_low_impact_low_exploitability(self, calc):
        """v4.0 with reduced metrics across the board."""
        metrics = {"AV": "P", "AC": "H", "AT": "P", "PR": "H", "UI": "A",
                   "VC": "L", "VI": "L", "VA": "L", "SC": "N", "SI": "N", "SA": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V4_0, metrics)
        assert base < 4.0


# ---------------------------------------------------------------------------
# Vector String Generation Tests
# ---------------------------------------------------------------------------

class TestVectorStringGeneration:
    """Test vector string generation."""

    def test_v31_base_only(self, calc):
        """Generate v3.1 vector with base metrics only."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        vector = calc.generate_vector_string(CVSSVersion.V3_1, metrics)
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_v31_with_temporal(self, calc):
        """Generate v3.1 vector with temporal metrics (non-X values only)."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "E": "F", "RL": "O", "RC": "C"}
        vector = calc.generate_vector_string(CVSSVersion.V3_1, metrics)
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"

    def test_v31_temporal_x_omitted(self, calc):
        """Generate v3.1 vector - temporal X values are omitted."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "E": "X", "RL": "X", "RC": "X"}
        vector = calc.generate_vector_string(CVSSVersion.V3_1, metrics)
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_v40_base(self, calc):
        """Generate v4.0 vector string."""
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"}
        vector = calc.generate_vector_string(CVSSVersion.V4_0, metrics)
        assert vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

    def test_v31_with_environmental(self, calc):
        """Generate v3.1 vector with environmental metrics."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H",
                   "MAV": "L", "CR": "H"}
        vector = calc.generate_vector_string(CVSSVersion.V3_1, metrics)
        assert "MAV:L" in vector
        assert "CR:H" in vector


# ---------------------------------------------------------------------------
# Vector String Parsing Tests
# ---------------------------------------------------------------------------

class TestVectorStringParsing:
    """Test vector string parsing."""

    def test_parse_v31_base(self, calc):
        """Parse v3.1 base vector string."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        version, metrics = calc.parse_vector_string(vector)
        assert version == CVSSVersion.V3_1
        assert metrics == {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                          "S": "U", "C": "H", "I": "H", "A": "H"}

    def test_parse_v31_with_temporal(self, calc):
        """Parse v3.1 vector with temporal metrics."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
        version, metrics = calc.parse_vector_string(vector)
        assert version == CVSSVersion.V3_1
        assert metrics["E"] == "F"
        assert metrics["RL"] == "O"
        assert metrics["RC"] == "C"

    def test_parse_v40(self, calc):
        """Parse v4.0 vector string."""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        version, metrics = calc.parse_vector_string(vector)
        assert version == CVSSVersion.V4_0
        assert metrics["AT"] == "N"
        assert metrics["VC"] == "H"
        assert metrics["SC"] == "H"

    def test_parse_invalid_empty(self, calc):
        """Parsing empty string raises ValueError."""
        with pytest.raises(ValueError):
            calc.parse_vector_string("")

    def test_parse_invalid_no_version(self, calc):
        """Parsing string without valid version raises ValueError."""
        with pytest.raises(ValueError):
            calc.parse_vector_string("CVSS:2.0/AV:N/AC:L")

    def test_parse_invalid_format(self, calc):
        """Parsing malformed metric raises ValueError."""
        with pytest.raises(ValueError):
            calc.parse_vector_string("CVSS:3.1/AVN/ACL")

    def test_parse_unknown_metric(self, calc):
        """Parsing unknown metric raises ValueError."""
        with pytest.raises(ValueError):
            calc.parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:X")


# ---------------------------------------------------------------------------
# Severity Label Tests
# ---------------------------------------------------------------------------

class TestSeverityLabel:
    """Test severity label mapping."""

    def test_none_severity(self, calc):
        assert calc.get_severity_label(0.0) == "None"

    def test_low_severity_boundary(self, calc):
        assert calc.get_severity_label(0.1) == "Low"
        assert calc.get_severity_label(3.9) == "Low"

    def test_medium_severity_boundary(self, calc):
        assert calc.get_severity_label(4.0) == "Medium"
        assert calc.get_severity_label(6.9) == "Medium"

    def test_high_severity_boundary(self, calc):
        assert calc.get_severity_label(7.0) == "High"
        assert calc.get_severity_label(8.9) == "High"

    def test_critical_severity_boundary(self, calc):
        assert calc.get_severity_label(9.0) == "Critical"
        assert calc.get_severity_label(10.0) == "Critical"

    def test_mid_range_values(self, calc):
        assert calc.get_severity_label(2.0) == "Low"
        assert calc.get_severity_label(5.5) == "Medium"
        assert calc.get_severity_label(7.5) == "High"
        assert calc.get_severity_label(9.5) == "Critical"

    def test_out_of_range_raises(self, calc):
        with pytest.raises(ValueError):
            calc.get_severity_label(-0.1)
        with pytest.raises(ValueError):
            calc.get_severity_label(10.1)


# ---------------------------------------------------------------------------
# Vector String Round-Trip Tests
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Test that generating then parsing a vector returns original metrics."""

    def test_v31_round_trip(self, calc):
        """Generate then parse v3.1 vector returns original metrics."""
        original_metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                           "S": "U", "C": "H", "I": "H", "A": "H"}
        vector = calc.generate_vector_string(CVSSVersion.V3_1, original_metrics)
        version, parsed = calc.parse_vector_string(vector)
        assert version == CVSSVersion.V3_1
        assert parsed == original_metrics

    def test_v31_round_trip_with_temporal(self, calc):
        """Generate then parse v3.1 vector with temporal returns original."""
        original_metrics = {"AV": "A", "AC": "H", "PR": "L", "UI": "R",
                           "S": "C", "C": "L", "I": "H", "A": "N",
                           "E": "P", "RL": "T", "RC": "R"}
        vector = calc.generate_vector_string(CVSSVersion.V3_1, original_metrics)
        version, parsed = calc.parse_vector_string(vector)
        assert version == CVSSVersion.V3_1
        assert parsed == original_metrics

    def test_v40_round_trip(self, calc):
        """Generate then parse v4.0 vector returns original metrics."""
        original_metrics = {"AV": "A", "AC": "H", "AT": "P", "PR": "L", "UI": "P",
                           "VC": "L", "VI": "H", "VA": "N", "SC": "N", "SI": "L", "SA": "H"}
        vector = calc.generate_vector_string(CVSSVersion.V4_0, original_metrics)
        version, parsed = calc.parse_vector_string(vector)
        assert version == CVSSVersion.V4_0
        assert parsed == original_metrics


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_missing_base_metric_v31(self, calc):
        """Missing required base metric raises ValueError."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H"}  # Missing A
        with pytest.raises(ValueError, match="Missing required base metric"):
            calc.compute_score(CVSSVersion.V3_1, metrics)

    def test_missing_base_metric_v40(self, calc):
        """Missing required v4.0 metric raises ValueError."""
        metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H"}  # Missing SA
        with pytest.raises(ValueError, match="Missing required v4.0 base metric"):
            calc.compute_score(CVSSVersion.V4_0, metrics)

    def test_invalid_metric_value_v31(self, calc):
        """Invalid metric value raises KeyError."""
        metrics = {"AV": "Z", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        with pytest.raises(KeyError):
            calc.compute_score(CVSSVersion.V3_1, metrics)


# ---------------------------------------------------------------------------
# Score-Severity Consistency Tests
# ---------------------------------------------------------------------------

class TestScoreSeverityConsistency:
    """Verify scores map to correct severity labels."""

    def test_computed_v31_severity_labels(self, calc):
        """Verify various computed scores produce expected severity labels."""
        # 9.8 -> Critical
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert calc.get_severity_label(base) == "Critical"

        # 4.3 -> Medium
        metrics = {"AV": "N", "AC": "L", "PR": "L", "UI": "N",
                   "S": "U", "C": "L", "I": "N", "A": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert calc.get_severity_label(base) == "Medium"

        # 0.0 -> None
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "N", "I": "N", "A": "N"}
        base, _, _ = calc.compute_score(CVSSVersion.V3_1, metrics)
        assert calc.get_severity_label(base) == "None"
