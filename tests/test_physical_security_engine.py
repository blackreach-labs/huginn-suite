# tests/test_physical_security_engine.py
"""Tests for the physical security assessment tracking engine."""

import json
import pytest

from app.core.engagement_database import EngagementDatabase
from app.core.physical_security_engine import (
    PhysicalSecurityEngine,
    VALID_METHODS,
    VALID_OUTCOMES,
    VALID_ANNOTATION_TYPES,
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
def engine(engagement_db):
    """Create a PhysicalSecurityEngine with a connected database."""
    eng = PhysicalSecurityEngine()
    eng.set_database(engagement_db)
    return eng


@pytest.fixture
def sample_evidence(engagement_db):
    """Insert a sample evidence record and return its ID."""
    import hashlib

    data = b"FLOOR_PLAN_IMAGE_DATA"
    sha256 = hashlib.sha256(data).hexdigest()
    evidence_id = engagement_db.execute_write(
        """INSERT INTO evidence (evidence_type, title, data, sha256_hash, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        ("screenshot", "Floor Plan", data, sha256, "2024-06-01T10:00:00"),
    )
    return evidence_id


# ==================================================================
# Database Setup Tests
# ==================================================================


class TestPhysicalSecuritySetup:
    """Tests for database configuration."""

    def test_no_database_raises(self):
        """Operations should raise RuntimeError if no database is set."""
        eng = PhysicalSecurityEngine()
        with pytest.raises(RuntimeError, match="No database set"):
            eng.log_attempt("Lobby", "2024-06-01T09:00:00", "tailgating", "success")

    def test_set_database(self, engagement_db):
        """set_database should configure the internal database reference."""
        eng = PhysicalSecurityEngine()
        assert eng.database is None
        eng.set_database(engagement_db)
        assert eng.database is engagement_db


# ==================================================================
# Attempt Logging Tests
# ==================================================================


class TestLogAttempt:
    """Tests for log_attempt() method."""

    def test_log_basic_attempt(self, engine):
        """Log a basic attempt and verify it returns an ID."""
        attempt_id = engine.log_attempt(
            location="Main Lobby",
            attempt_time="2024-06-01T09:00:00",
            method="tailgating",
            outcome="success",
        )
        assert attempt_id is not None
        assert isinstance(attempt_id, int)
        assert attempt_id > 0

    def test_log_attempt_with_all_fields(self, engine, sample_evidence):
        """Log an attempt with all optional fields."""
        attempt_id = engine.log_attempt(
            location="Server Room",
            attempt_time="2024-06-01T10:30:00",
            method="lock_bypass",
            outcome="failure",
            evidence_id=sample_evidence,
            notes="Attempted bump key on deadbolt lock.",
        )
        assert attempt_id > 0

        # Verify stored data
        attempts = engine.get_attempts()
        assert len(attempts) == 1
        attempt = attempts[0]
        assert attempt["location"] == "Server Room"
        assert attempt["method"] == "lock_bypass"
        assert attempt["outcome"] == "failure"
        assert attempt["evidence_id"] == sample_evidence
        assert attempt["notes"] == "Attempted bump key on deadbolt lock."

    def test_log_attempt_all_valid_methods(self, engine):
        """All valid methods should be accepted."""
        for i, method in enumerate(VALID_METHODS):
            attempt_id = engine.log_attempt(
                location=f"Location {i}",
                attempt_time=f"2024-06-01T{10+i:02d}:00:00",
                method=method,
                outcome="success",
            )
            assert attempt_id > 0

    def test_log_attempt_all_valid_outcomes(self, engine):
        """All valid outcomes should be accepted."""
        for i, outcome in enumerate(VALID_OUTCOMES):
            attempt_id = engine.log_attempt(
                location=f"Location {i}",
                attempt_time=f"2024-06-01T{10+i:02d}:00:00",
                method="tailgating",
                outcome=outcome,
            )
            assert attempt_id > 0

    def test_log_attempt_emits_signal(self, engine, qtbot):
        """log_attempt should emit attempt_logged signal with attempt data dict."""
        with qtbot.waitSignal(engine.attempt_logged, timeout=1000) as blocker:
            engine.log_attempt(
                location="Parking Garage",
                attempt_time="2024-06-01T11:00:00",
                method="badge_cloning",
                outcome="partial",
            )
        signal_data = blocker.args[0]
        assert isinstance(signal_data, dict)
        assert signal_data["location"] == "Parking Garage"
        assert signal_data["method"] == "badge_cloning"
        assert signal_data["outcome"] == "partial"

    def test_log_attempt_strips_whitespace(self, engine):
        """Location and time should be trimmed of whitespace."""
        attempt_id = engine.log_attempt(
            location="  Lobby  ",
            attempt_time="  2024-06-01T09:00:00  ",
            method="tailgating",
            outcome="success",
        )
        attempts = engine.get_attempts()
        assert attempts[0]["location"] == "Lobby"
        assert attempts[0]["attempt_time"] == "2024-06-01T09:00:00"


# ==================================================================
# Method Validation Tests
# ==================================================================


class TestMethodValidation:
    """Tests for method validation in log_attempt()."""

    def test_invalid_method_raises(self, engine):
        """An invalid method should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid method"):
            engine.log_attempt(
                location="Lobby",
                attempt_time="2024-06-01T09:00:00",
                method="teleportation",
                outcome="success",
            )

    def test_invalid_outcome_raises(self, engine):
        """An invalid outcome should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid outcome"):
            engine.log_attempt(
                location="Lobby",
                attempt_time="2024-06-01T09:00:00",
                method="tailgating",
                outcome="maybe",
            )

    def test_empty_location_raises(self, engine):
        """Empty location should raise ValueError."""
        with pytest.raises(ValueError, match="Location must not be empty"):
            engine.log_attempt(
                location="",
                attempt_time="2024-06-01T09:00:00",
                method="tailgating",
                outcome="success",
            )

    def test_empty_attempt_time_raises(self, engine):
        """Empty attempt_time should raise ValueError."""
        with pytest.raises(ValueError, match="Attempt time must not be empty"):
            engine.log_attempt(
                location="Lobby",
                attempt_time="",
                method="tailgating",
                outcome="success",
            )


# ==================================================================
# Site Annotation Tests
# ==================================================================


class TestSiteAnnotations:
    """Tests for add_site_annotation() and get_annotations()."""

    def test_add_basic_annotation(self, engine, sample_evidence):
        """Add a basic annotation to a floor plan."""
        ann_id = engine.add_site_annotation(
            floor_plan_evidence_id=sample_evidence,
            annotation_type="entry_point",
            coordinates={"x": 100, "y": 200, "width": 30, "height": 30},
            label="Main Entrance",
        )
        assert ann_id > 0

    def test_add_annotation_all_types(self, engine, sample_evidence):
        """All valid annotation types should be accepted."""
        for ann_type in VALID_ANNOTATION_TYPES:
            ann_id = engine.add_site_annotation(
                floor_plan_evidence_id=sample_evidence,
                annotation_type=ann_type,
                coordinates={"x": 50, "y": 50, "width": 20, "height": 20},
            )
            assert ann_id > 0

    def test_add_annotation_emits_signal(self, engine, sample_evidence, qtbot):
        """add_site_annotation should emit annotation_added signal with ID."""
        with qtbot.waitSignal(engine.annotation_added, timeout=1000) as blocker:
            engine.add_site_annotation(
                floor_plan_evidence_id=sample_evidence,
                annotation_type="camera",
                coordinates={"x": 150, "y": 300, "width": 10, "height": 10},
            )
        assert isinstance(blocker.args[0], int)
        assert blocker.args[0] > 0

    def test_annotation_stores_coordinates_as_json(self, engine, sample_evidence):
        """Coordinates should be stored and retrieved as a dict (from JSON)."""
        coords = {"x": 100, "y": 200, "width": 30, "height": 30}
        engine.add_site_annotation(
            floor_plan_evidence_id=sample_evidence,
            annotation_type="entry_point",
            coordinates=coords,
            label="Side Door",
            notes="Usually propped open",
        )
        annotations = engine.get_annotations(floor_plan_evidence_id=sample_evidence)
        assert len(annotations) == 1
        assert annotations[0]["coordinates"] == coords
        assert annotations[0]["label"] == "Side Door"
        assert annotations[0]["notes"] == "Usually propped open"

    def test_add_annotation_invalid_type_raises(self, engine, sample_evidence):
        """Invalid annotation type should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid annotation_type"):
            engine.add_site_annotation(
                floor_plan_evidence_id=sample_evidence,
                annotation_type="invalid_type",
                coordinates={"x": 10, "y": 10},
            )

    def test_add_annotation_empty_coordinates_raises(self, engine, sample_evidence):
        """Empty coordinates should raise ValueError."""
        with pytest.raises(ValueError, match="Coordinates must be a non-empty"):
            engine.add_site_annotation(
                floor_plan_evidence_id=sample_evidence,
                annotation_type="camera",
                coordinates={},
            )

    def test_get_annotations_filters_by_floor_plan(self, engine, engagement_db):
        """get_annotations should filter by floor_plan_evidence_id."""
        import hashlib

        # Create two floor plan evidence records
        data1 = b"FLOOR_PLAN_1"
        data2 = b"FLOOR_PLAN_2"
        plan1_id = engagement_db.execute_write(
            """INSERT INTO evidence (evidence_type, title, data, sha256_hash, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            ("screenshot", "Plan 1", data1, hashlib.sha256(data1).hexdigest(), "2024-06-01T10:00:00"),
        )
        plan2_id = engagement_db.execute_write(
            """INSERT INTO evidence (evidence_type, title, data, sha256_hash, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            ("screenshot", "Plan 2", data2, hashlib.sha256(data2).hexdigest(), "2024-06-01T11:00:00"),
        )

        engine.add_site_annotation(plan1_id, "entry_point", {"x": 1, "y": 1})
        engine.add_site_annotation(plan1_id, "camera", {"x": 2, "y": 2})
        engine.add_site_annotation(plan2_id, "access_control_zone", {"x": 3, "y": 3})

        plan1_annotations = engine.get_annotations(floor_plan_evidence_id=plan1_id)
        plan2_annotations = engine.get_annotations(floor_plan_evidence_id=plan2_id)
        all_annotations = engine.get_annotations()

        assert len(plan1_annotations) == 2
        assert len(plan2_annotations) == 1
        assert len(all_annotations) == 3


# ==================================================================
# Control Rating Tests
# ==================================================================


class TestRateControl:
    """Tests for rate_control() and get_ratings()."""

    def test_rate_basic_control(self, engine):
        """Rate a control and verify it returns an ID."""
        rating_id = engine.rate_control(
            location="Main Entrance",
            control_type="badge_reader",
            effectiveness_rating=4,
            notes="Modern proximity badge system.",
        )
        assert rating_id > 0

    def test_rate_control_stores_data(self, engine):
        """Verify rated control data is correctly stored and retrieved."""
        engine.rate_control(
            location="Server Room",
            control_type="biometric_lock",
            effectiveness_rating=5,
            notes="Fingerprint + PIN required",
            assessed_at="2024-06-15T14:00:00",
        )
        ratings = engine.get_ratings()
        assert len(ratings) == 1
        r = ratings[0]
        assert r["location"] == "Server Room"
        assert r["control_type"] == "biometric_lock"
        assert r["effectiveness_rating"] == 5
        assert r["notes"] == "Fingerprint + PIN required"
        assert r["assessed_at"] == "2024-06-15T14:00:00"

    def test_rate_control_defaults_assessed_at(self, engine):
        """If assessed_at is not provided, it should default to current time."""
        engine.rate_control(
            location="Lobby",
            control_type="cctv",
            effectiveness_rating=3,
        )
        ratings = engine.get_ratings()
        assert ratings[0]["assessed_at"] is not None
        assert len(ratings[0]["assessed_at"]) > 0

    def test_rate_control_invalid_rating_below_range(self, engine):
        """Rating below 1 should raise ValueError."""
        with pytest.raises(ValueError, match="Effectiveness rating must be an integer"):
            engine.rate_control(
                location="Lobby",
                control_type="cctv",
                effectiveness_rating=0,
            )

    def test_rate_control_invalid_rating_above_range(self, engine):
        """Rating above 5 should raise ValueError."""
        with pytest.raises(ValueError, match="Effectiveness rating must be an integer"):
            engine.rate_control(
                location="Lobby",
                control_type="cctv",
                effectiveness_rating=6,
            )

    def test_rate_control_empty_location_raises(self, engine):
        """Empty location should raise ValueError."""
        with pytest.raises(ValueError, match="Location must not be empty"):
            engine.rate_control(
                location="",
                control_type="cctv",
                effectiveness_rating=3,
            )

    def test_rate_control_empty_control_type_raises(self, engine):
        """Empty control_type should raise ValueError."""
        with pytest.raises(ValueError, match="Control type must not be empty"):
            engine.rate_control(
                location="Lobby",
                control_type="",
                effectiveness_rating=3,
            )

    def test_get_ratings_filter_by_location(self, engine):
        """get_ratings should support filtering by location."""
        engine.rate_control("Server Room", "biometric", 5)
        engine.rate_control("Main Lobby", "cctv", 3)
        engine.rate_control("Server Room", "fire_suppression", 4)

        server_ratings = engine.get_ratings(location="Server Room")
        assert len(server_ratings) == 2
        for r in server_ratings:
            assert "Server Room" in r["location"]

    def test_get_ratings_filter_by_control_type(self, engine):
        """get_ratings should support filtering by control type."""
        engine.rate_control("Lobby", "cctv", 3)
        engine.rate_control("Parking", "cctv", 2)
        engine.rate_control("Lobby", "badge_reader", 4)

        cctv_ratings = engine.get_ratings(control_type="cctv")
        assert len(cctv_ratings) == 2
        for r in cctv_ratings:
            assert r["control_type"] == "cctv"


# ==================================================================
# Summary Generation Tests
# ==================================================================


class TestGenerateSummary:
    """Tests for generate_summary()."""

    def test_generate_empty_summary(self, engine):
        """Summary on empty database should return zero counts."""
        summary = engine.generate_summary()
        assert summary["total_attempts"] == 0
        assert summary["attempts_by_method"] == {}
        assert summary["successful_access_points"] == []
        assert summary["control_ratings"] == {}
        assert summary["average_ratings_by_location"] == {}
        assert summary["annotations_by_floor_plan"] == {}
        assert "generated_at" in summary

    def test_generate_summary_with_data(self, engine, sample_evidence):
        """Summary with populated data should contain expected aggregations."""
        # Log some attempts
        engine.log_attempt("Lobby", "2024-06-01T09:00:00", "tailgating", "success")
        engine.log_attempt("Lobby", "2024-06-01T09:30:00", "tailgating", "failure")
        engine.log_attempt("Server Room", "2024-06-01T10:00:00", "lock_bypass", "success")
        engine.log_attempt("Dumpster", "2024-06-01T11:00:00", "dumpster_diving", "partial")

        # Add some ratings
        engine.rate_control("Lobby", "cctv", 3)
        engine.rate_control("Lobby", "badge_reader", 4)
        engine.rate_control("Server Room", "biometric", 5)

        # Add annotations
        engine.add_site_annotation(sample_evidence, "entry_point", {"x": 1, "y": 1})
        engine.add_site_annotation(sample_evidence, "camera", {"x": 2, "y": 2})

        summary = engine.generate_summary()

        # Verify attempt stats
        assert summary["total_attempts"] == 4
        assert summary["attempts_by_method"]["tailgating"]["success"] == 1
        assert summary["attempts_by_method"]["tailgating"]["failure"] == 1
        assert summary["attempts_by_method"]["lock_bypass"]["success"] == 1
        assert summary["attempts_by_method"]["dumpster_diving"]["partial"] == 1

        # Verify successful access points
        assert len(summary["successful_access_points"]) == 2
        locations = [p["location"] for p in summary["successful_access_points"]]
        assert "Lobby" in locations
        assert "Server Room" in locations

        # Verify control ratings
        assert "Lobby" in summary["control_ratings"]
        assert len(summary["control_ratings"]["Lobby"]) == 2
        assert summary["average_ratings_by_location"]["Lobby"] == 3.5
        assert summary["average_ratings_by_location"]["Server Room"] == 5.0

        # Verify annotations
        assert sample_evidence in summary["annotations_by_floor_plan"]
        assert summary["annotations_by_floor_plan"][sample_evidence]["entry_point"] == 1
        assert summary["annotations_by_floor_plan"][sample_evidence]["camera"] == 1

    def test_generate_summary_no_db_raises(self):
        """generate_summary should raise if no database is set."""
        eng = PhysicalSecurityEngine()
        with pytest.raises(RuntimeError, match="No database set"):
            eng.generate_summary()


# ==================================================================
# Filtering Tests
# ==================================================================


class TestGetAttempts:
    """Tests for get_attempts() filtering."""

    def test_filter_by_location(self, engine):
        """get_attempts should support filtering by location."""
        engine.log_attempt("Main Lobby", "2024-06-01T09:00:00", "tailgating", "success")
        engine.log_attempt("Server Room", "2024-06-01T10:00:00", "lock_bypass", "failure")
        engine.log_attempt("Main Lobby Annex", "2024-06-01T11:00:00", "social_engineering", "partial")

        lobby_attempts = engine.get_attempts(location="Lobby")
        assert len(lobby_attempts) == 2  # Main Lobby and Main Lobby Annex

    def test_filter_by_method(self, engine):
        """get_attempts should support filtering by method."""
        engine.log_attempt("Lobby", "2024-06-01T09:00:00", "tailgating", "success")
        engine.log_attempt("Lobby", "2024-06-01T10:00:00", "lock_bypass", "failure")
        engine.log_attempt("Lobby", "2024-06-01T11:00:00", "tailgating", "failure")

        tailgating_attempts = engine.get_attempts(method="tailgating")
        assert len(tailgating_attempts) == 2

    def test_filter_invalid_method_raises(self, engine):
        """get_attempts with an invalid method filter should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid method"):
            engine.get_attempts(method="invalid_method")

    def test_get_attempts_ordered_by_time_desc(self, engine):
        """Attempts should be returned in descending time order."""
        engine.log_attempt("A", "2024-06-01T09:00:00", "tailgating", "success")
        engine.log_attempt("B", "2024-06-01T11:00:00", "tailgating", "success")
        engine.log_attempt("C", "2024-06-01T10:00:00", "tailgating", "success")

        attempts = engine.get_attempts()
        times = [a["attempt_time"] for a in attempts]
        assert times == sorted(times, reverse=True)
