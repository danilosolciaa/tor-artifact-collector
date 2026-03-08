"""
Unit Tests for Normalizers Module

Tests the conversion of source-specific artifacts to UnifiedEvent objects.

Test Strategy:
- Use mock data (no real artifacts required)
- Validate schema compliance
- Test edge cases (empty data, malformed data)
- Verify confidence scoring logic
"""

import pytest
from datetime import datetime

from src.models import (
    UnifiedEvent,
    EventType,
    ConfidenceLevel,
    TimestampConfidence,
    RecoveryStatus
)
from src.normalizers import (
    normalize_userassist,
    normalize_prefetch,
    normalize_places_sqlite,
    normalize_places_wal,
    normalize_evtx,
    normalize_batch,
    normalize_windows_path,
    filetime_to_iso8601,
    firefox_timestamp_to_iso8601,
    rot13_decode,
    is_tor_related
)


# ==============================================================================
# TEST FIXTURES
# ==============================================================================

@pytest.fixture
def mock_userassist_data():
    """Mock UserAssist data for testing."""
    return {
        "encoded_name": "P:\\Hfref\\Nyvpr\\Qrfxgbc\\Gbe Oebjfre\\Oebjfre\\gbe.rkr",  # ROT13 encoded
        "run_count": 10,
        "last_execution": 132840000000000000,  # Example FILETIME
        "focus_time": 120000,
        "hive_path": "C:\\Users\\Alice\\NTUSER.DAT",
        "registry_path": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count"
    }


@pytest.fixture
def mock_places_data():
    """Mock places.sqlite data for testing."""
    return {
        "url": "http://3g2upl4pq6kufc4m.onion",
        "title": "DuckDuckGo Search Engine",
        "visit_count": 42,
        "last_visit_date": 1702653930000000,  # Firefox timestamp (microseconds)
        "places_db_path": "C:\\Users\\Alice\\AppData\\Roaming\\Tor Browser\\places.sqlite"
    }


@pytest.fixture
def mock_prefetch_data():
    """Mock Prefetch data for testing."""
    return {
        "executable": "TOR.EXE",
        "run_count": 15,
        "last_run_times": [
            datetime(2024, 12, 15, 14, 32, 15),
            datetime(2024, 12, 15, 11, 45, 30)
        ],
        "prefetch_path": "C:\\Windows\\Prefetch\\TOR.EXE-A1B2C3D4.pf"
    }


@pytest.fixture
def mock_evtx_data():
    """Mock EVTX data for testing."""
    return {
        "event_id": 4688,
        "timestamp": "2024-12-15T14:32:15.123Z",
        "process_name": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\tor.exe",
        "command_line": "tor.exe --defaults-torrc torrc-defaults -f torrc",
        "parent_process": "Start Tor Browser.exe",
        "evtx_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
    }


# ==============================================================================
# UTILITY FUNCTION TESTS
# ==============================================================================

class TestUtilityFunctions:
    """Test utility functions used by normalizers."""

    def test_normalize_windows_path(self):
        """Test Windows path normalization."""
        assert normalize_windows_path("C:\\Program Files\\Tor Browser") == "c:\\program files\\tor browser"
        assert normalize_windows_path("C:/Users/Alice/Desktop") == "c:\\users\\alice\\desktop"
        assert normalize_windows_path("") == ""

    def test_filetime_to_iso8601(self):
        """Test FILETIME to ISO 8601 conversion."""
        # FILETIME for 2024-01-01 00:00:00 UTC
        # = (1704067200 + 11644473600) * 10_000_000 = 133485408000000000
        filetime = 133485408000000000
        result = filetime_to_iso8601(filetime)
        assert isinstance(result, str)
        assert result.endswith("Z")
        assert "2024" in result

    def test_firefox_timestamp_to_iso8601(self):
        """Test Firefox timestamp to ISO 8601 conversion."""
        # Firefox timestamp for 2024-12-15 16:45:30 (microseconds)
        firefox_time = 1702653930000000
        result = firefox_timestamp_to_iso8601(firefox_time)
        assert isinstance(result, str)
        assert result.endswith("Z")

    def test_rot13_decode(self):
        """Test ROT13 decoding (used in UserAssist)."""
        encoded = "gbe.rkr"
        decoded = rot13_decode(encoded)
        assert decoded == "tor.exe"

        encoded = "P:\\Hfref\\Nyvpr\\Qrfxgbc\\Gbe Oebjfre"
        decoded = rot13_decode(encoded)
        assert "tor browser" in decoded.lower()

    def test_is_tor_related(self):
        """Test Tor-related path detection."""
        assert is_tor_related("C:\\Users\\Alice\\Desktop\\Tor Browser\\tor.exe") is True
        assert is_tor_related("C:\\Program Files\\Tor Browser\\firefox.exe") is True
        assert is_tor_related("C:\\Windows\\System32\\notepad.exe") is False
        assert is_tor_related("tor.exe") is True


# ==============================================================================
# NORMALIZER TESTS
# ==============================================================================

class TestNormalizeUserAssist:
    """Test Registry UserAssist normalizer."""

    def test_normalize_valid_userassist(self, mock_userassist_data):
        """Test normalization of valid UserAssist data."""
        result = normalize_userassist(
            mock_userassist_data,
            mock_userassist_data["registry_path"],
            mock_userassist_data["hive_path"]
        )

        assert result is not None
        assert isinstance(result, UnifiedEvent)
        assert result.event_type == EventType.TOR_EXECUTION
        assert result.run_count == 10
        assert len(result.sources) == 1
        assert result.sources[0].artifact == "NTUSER.DAT"
        assert result.timestamp_confidence == TimestampConfidence.LOW  # UserAssist has hour granularity
        assert result.confidence == ConfidenceLevel.MEDIUM

    def test_normalize_non_tor_userassist(self):
        """Test that non-Tor executables are filtered out."""
        non_tor_data = {
            "encoded_name": "abgrCnq.rkr",  # notepad.exe in ROT13
            "run_count": 5,
            "last_execution": 132840000000000000,
            "hive_path": "C:\\Users\\Alice\\NTUSER.DAT",
            "registry_path": "HKCU\\...\\Count"
        }

        result = normalize_userassist(non_tor_data, non_tor_data["registry_path"], non_tor_data["hive_path"])
        assert result is None  # Should filter out non-Tor executables


class TestNormalizePlacesSqlite:
    """Test places.sqlite normalizer."""

    def test_normalize_valid_places(self, mock_places_data):
        """Test normalization of valid places.sqlite data."""
        result = normalize_places_sqlite(mock_places_data)

        assert result is not None
        assert isinstance(result, UnifiedEvent)
        assert result.event_type == EventType.TOR_HISTORY
        assert len(result.onion_domains) == 1
        assert result.onion_domains[0].domain == "3g2upl4pq6kufc4m.onion"
        assert result.onion_domains[0].visit_count == 42
        assert result.recovery_status == RecoveryStatus.ACTIVE
        assert result.confidence == ConfidenceLevel.HIGH

    def test_normalize_non_onion_url(self):
        """Test that non-.onion URLs are filtered out."""
        non_onion_data = {
            "url": "https://www.google.com",
            "title": "Google",
            "visit_count": 100,
            "last_visit_date": 1702653930000000,
            "places_db_path": "places.sqlite"
        }

        result = normalize_places_sqlite(non_onion_data)
        assert result is None  # Should filter out non-.onion URLs


class TestNormalizePrefetch:
    """Test Prefetch normalizer."""

    def test_normalize_valid_prefetch(self, mock_prefetch_data):
        """Test normalization of valid Prefetch data."""
        result = normalize_prefetch(mock_prefetch_data, mock_prefetch_data["prefetch_path"])

        assert result is not None
        assert isinstance(result, UnifiedEvent)
        assert result.event_type == EventType.TOR_EXECUTION
        assert result.run_count == 15
        assert result.timestamp_confidence == TimestampConfidence.HIGH  # Prefetch has sub-second precision
        assert result.confidence == ConfidenceLevel.HIGH

    def test_normalize_prefetch_accepts_string_timestamps(self):
        """Real extractor output uses ISO strings, not datetime objects."""
        raw_data = {
            "executable": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "run_count": 15,
            "last_run_times": [
                "2024-12-15T14:32:15Z",
                "2024-12-15T11:45:30Z",
            ],
            "prefetch_path": "C:\\Windows\\Prefetch\\TOR.EXE-A1B2C3D4.pf",
        }

        result = normalize_prefetch(raw_data, raw_data["prefetch_path"])

        assert result is not None
        assert result.timestamp == "2024-12-15T14:32:15Z"
        assert "2024-12-15T11:45:30Z" in result.notes


class TestNormalizeEvtx:
    """Test EVTX normalizer."""

    def test_normalize_valid_evtx(self, mock_evtx_data):
        """Test normalization of valid EVTX data."""
        result = normalize_evtx(mock_evtx_data)

        assert result is not None
        assert isinstance(result, UnifiedEvent)
        assert result.event_type == EventType.TOR_EXECUTION
        assert result.timestamp_confidence == TimestampConfidence.HIGH
        assert result.confidence == ConfidenceLevel.VERY_HIGH  # EVTX is most authoritative
        assert any("EVTX Event ID 4688" in reason for reason in result.confidence_reasons)


# ==============================================================================
# BATCH NORMALIZATION TESTS
# ==============================================================================

class TestNormalizeBatch:
    """Test batch normalization."""

    def test_batch_normalize_userassist(self, mock_userassist_data):
        """Test batch normalization of UserAssist data."""
        raw_events = [mock_userassist_data]
        results = normalize_batch(raw_events, "userassist")

        assert len(results) == 1
        assert all(isinstance(event, UnifiedEvent) for event in results)

    def test_batch_normalize_empty_list(self):
        """Test batch normalization with empty input."""
        results = normalize_batch([], "userassist")
        assert results == []

    def test_batch_normalize_invalid_type(self):
        """Test batch normalization with invalid artifact type."""
        results = normalize_batch([{"test": "data"}], "invalid_type")
        assert results == []


# ==============================================================================
# INTEGRATION TESTS
# ==============================================================================

class TestNormalizerIntegration:
    """Integration tests for multiple normalizers."""

    def test_multiple_sources_same_event(self, mock_userassist_data, mock_prefetch_data, mock_evtx_data):
        """Test normalization of the same event from multiple sources."""
        # Normalize each source
        ua_event = normalize_userassist(
            mock_userassist_data,
            mock_userassist_data["registry_path"],
            mock_userassist_data["hive_path"]
        )
        pf_event = normalize_prefetch(mock_prefetch_data, mock_prefetch_data["prefetch_path"])
        evtx_event = normalize_evtx(mock_evtx_data)

        # All should produce valid events
        assert ua_event is not None
        assert pf_event is not None
        assert evtx_event is not None

        # All should be TOR_EXECUTION events
        assert ua_event.event_type == EventType.TOR_EXECUTION
        assert pf_event.event_type == EventType.TOR_EXECUTION
        assert evtx_event.event_type == EventType.TOR_EXECUTION

        # Confidence should increase: UserAssist < Prefetch < EVTX
        confidence_order = {
            ConfidenceLevel.LOW: 0,
            ConfidenceLevel.MEDIUM: 1,
            ConfidenceLevel.HIGH: 2,
            ConfidenceLevel.VERY_HIGH: 3
        }
        assert confidence_order[ua_event.confidence] <= confidence_order[pf_event.confidence]
        assert confidence_order[pf_event.confidence] <= confidence_order[evtx_event.confidence]


# ==============================================================================
# EDGE CASE TESTS
# ==============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_normalize_with_none_values(self):
        """Test normalization with None values."""
        data = {
            "url": None,
            "title": None,
            "visit_count": 0,
            "last_visit_date": 0,
            "places_db_path": "places.sqlite"
        }

        result = normalize_places_sqlite(data)
        assert result is None  # Should handle gracefully

    def test_normalize_with_missing_keys(self):
        """Test normalization with missing dictionary keys."""
        incomplete_data = {
            "url": "http://test.onion"
            # Missing other required fields
        }

        # Should not crash, either return None or handle with defaults
        try:
            result = normalize_places_sqlite(incomplete_data)
            # If it returns something, it should be valid or None
            assert result is None or isinstance(result, UnifiedEvent)
        except KeyError:
            pytest.fail("Normalizer should handle missing keys gracefully")

    def test_wal_normalizer_uses_estimated_artifact_time(self):
        """WAL events should not use the current system time."""
        raw_data = {
            "url": "http://testhiddenservice.onion",
            "title": "Recovered title",
            "wal_offset": 4096,
            "wal_path": "places.sqlite-wal",
            "wal_mtime": "2024-12-15T14:40:00Z",
        }

        result = normalize_places_wal(raw_data)

        assert result is not None
        assert result.timestamp == "2024-12-15T14:40:00Z"
        assert result.timestamp_confidence == TimestampConfidence.ESTIMATED


# ==============================================================================
# RUN TESTS
# ==============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
