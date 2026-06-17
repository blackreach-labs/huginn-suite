"""Unit tests for app.core.version module."""

import pytest
from unittest.mock import patch, PropertyMock
from pathlib import Path

from app.core.version import (
    VersionError,
    get_version,
    parse_version,
    compare_versions,
    VERSION_FILE,
)


class TestVersionError:
    """Tests for the VersionError exception class."""

    def test_is_exception(self):
        assert issubclass(VersionError, Exception)

    def test_can_be_raised_with_message(self):
        with pytest.raises(VersionError, match="test message"):
            raise VersionError("test message")


class TestGetVersion:
    """Tests for the get_version function."""

    def test_reads_valid_version(self, tmp_path, monkeypatch):
        version_file = tmp_path / "VERSION"
        version_file.write_text("8.0.0", encoding="utf-8")
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        assert get_version() == "8.0.0"

    def test_strips_whitespace(self, tmp_path, monkeypatch):
        version_file = tmp_path / "VERSION"
        version_file.write_text("  1.2.3  \n", encoding="utf-8")
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        assert get_version() == "1.2.3"

    def test_raises_when_file_missing(self, tmp_path, monkeypatch):
        version_file = tmp_path / "VERSION"
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        with pytest.raises(VersionError, match="not found"):
            get_version()

    def test_raises_on_malformed_version(self, tmp_path, monkeypatch):
        version_file = tmp_path / "VERSION"
        version_file.write_text("not-a-version", encoding="utf-8")
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        with pytest.raises(VersionError, match="malformed"):
            get_version()

    def test_raises_on_version_with_v_prefix(self, tmp_path, monkeypatch):
        """get_version expects raw MAJOR.MINOR.PATCH in file, no v prefix."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("v8.0.0", encoding="utf-8")
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        with pytest.raises(VersionError, match="malformed"):
            get_version()

    def test_raises_on_two_component_version(self, tmp_path, monkeypatch):
        version_file = tmp_path / "VERSION"
        version_file.write_text("8.0", encoding="utf-8")
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        with pytest.raises(VersionError, match="malformed"):
            get_version()

    def test_raises_on_four_component_version(self, tmp_path, monkeypatch):
        version_file = tmp_path / "VERSION"
        version_file.write_text("8.0.0.1", encoding="utf-8")
        monkeypatch.setattr("app.core.version.VERSION_FILE", version_file)
        with pytest.raises(VersionError, match="malformed"):
            get_version()

    def test_reads_actual_version_file(self):
        """Integration test: verify we can read the real VERSION file."""
        version = get_version()
        assert version == "8.0.0"


class TestParseVersion:
    """Tests for the parse_version function."""

    def test_parses_simple_version(self):
        assert parse_version("8.0.0") == (8, 0, 0)

    def test_parses_with_v_prefix(self):
        assert parse_version("v8.1.2") == (8, 1, 2)

    def test_parses_with_uppercase_v_prefix(self):
        assert parse_version("V8.1.2") == (8, 1, 2)

    def test_parses_large_numbers(self):
        assert parse_version("100.200.300") == (100, 200, 300)

    def test_parses_zeros(self):
        assert parse_version("0.0.0") == (0, 0, 0)

    def test_strips_whitespace(self):
        assert parse_version("  1.2.3  ") == (1, 2, 3)

    def test_strips_whitespace_with_prefix(self):
        assert parse_version("  v1.2.3  ") == (1, 2, 3)

    def test_raises_on_empty_string(self):
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("")

    def test_raises_on_nonsense(self):
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("hello")

    def test_raises_on_two_components(self):
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("1.2")

    def test_raises_on_four_components(self):
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("1.2.3.4")

    def test_raises_on_non_numeric(self):
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("a.b.c")

    def test_raises_on_double_v_prefix(self):
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("vv1.2.3")

    def test_v_prefix_equivalence(self):
        """Same version with and without v prefix should parse identically."""
        assert parse_version("v1.2.3") == parse_version("1.2.3")


class TestCompareVersions:
    """Tests for the compare_versions function."""

    def test_equal_versions(self):
        assert compare_versions("8.0.0", "8.0.0") == 0

    def test_current_less_than_remote_major(self):
        assert compare_versions("7.0.0", "8.0.0") == -1

    def test_current_less_than_remote_minor(self):
        assert compare_versions("8.0.0", "8.1.0") == -1

    def test_current_less_than_remote_patch(self):
        assert compare_versions("8.0.0", "8.0.1") == -1

    def test_current_greater_than_remote_major(self):
        assert compare_versions("9.0.0", "8.0.0") == 1

    def test_current_greater_than_remote_minor(self):
        assert compare_versions("8.2.0", "8.1.0") == 1

    def test_current_greater_than_remote_patch(self):
        assert compare_versions("8.0.2", "8.0.1") == 1

    def test_handles_v_prefix_on_remote(self):
        assert compare_versions("8.0.0", "v8.1.0") == -1

    def test_handles_v_prefix_on_both(self):
        assert compare_versions("v8.0.0", "v8.0.0") == 0

    def test_major_takes_precedence_over_minor(self):
        assert compare_versions("2.99.99", "3.0.0") == -1

    def test_minor_takes_precedence_over_patch(self):
        assert compare_versions("1.2.99", "1.3.0") == -1
