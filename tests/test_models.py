"""
Unit Tests for Models Module

Tests the data structures and serialization logic.
"""

import pytest
import json

from src.models import (
    UnifiedEvent,
    ArtifactSource,
    OnionDomain,
    ForensicTimeline,
    EventType,
    ConfidenceLevel,
    TimestampConfidence,
    RecoveryStatus
)


class TestArtifactSource:
    """Test ArtifactSource data class."""

    def test_create_artifact_source(self):
        """Test creation of ArtifactSource."""
        source = ArtifactSource(
            artifact="NTUSER.DAT",
            extraction_method="UserAssist",
            file_path="C:\\Users\\Alice\\NTUSER.DAT"
        )

        assert source.artifact == "NTUSER.DAT"
        assert source.extraction_method == "UserAssist"
        assert source.file_path == "C:\\Users\\Alice\\NTUSER.DAT"

    def test_artifact_source_to_dict(self):
        """Test serialization to dictionary."""
        source = ArtifactSource(
            artifact="Prefetch",
            extraction_method="Prefetch file TOR.EXE.pf"
        )

        result = source.to_dict()
        assert isinstance(result, dict)
        assert result["artifact"] == "Prefetch"


class TestOnionDomain:
    """Test OnionDomain data class."""

    def test_create_onion_domain(self):
        """Test creation of OnionDomain."""
        domain = OnionDomain(
            domain="3g2upl4pq6kufc4m.onion",
            title="DuckDuckGo",
            visit_count=42
        )

        assert domain.domain == "3g2upl4pq6kufc4m.onion"
        assert domain.title == "DuckDuckGo"
        assert domain.visit_count == 42


class TestUnifiedEvent:
    """Test UnifiedEvent data class."""

    def test_create_unified_event(self):
        """Test creation of UnifiedEvent."""
        source = ArtifactSource(
            artifact="EVTX",
            extraction_method="Event ID 4688"
        )

        event = UnifiedEvent(
            timestamp="2024-12-15T14:32:15Z",
            event_type=EventType.TOR_EXECUTION,
            sources=[source],
            executable_path="C:\\tor.exe"
        )

        assert event.timestamp == "2024-12-15T14:32:15Z"
        assert event.event_type == EventType.TOR_EXECUTION
        assert len(event.sources) == 1
        assert event.metadata_hash  # Should auto-generate

    def test_unified_event_to_json(self):
        """Test JSON serialization."""
        source = ArtifactSource(
            artifact="Registry",
            extraction_method="UserAssist"
        )

        event = UnifiedEvent(
            timestamp="2024-12-15T14:32:15Z",
            event_type=EventType.TOR_EXECUTION,
            sources=[source]
        )

        json_str = event.to_json()
        assert isinstance(json_str, str)

        # Parse back to verify
        data = json.loads(json_str)
        assert data["timestamp"] == "2024-12-15T14:32:15Z"
        assert data["event_type"] == "tor_execution"

    def test_unified_event_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "event_id": "test-123",
            "timestamp": "2024-12-15T14:32:15Z",
            "timestamp_confidence": "high",
            "event_type": "tor_execution",
            "sources": [
                {
                    "artifact": "EVTX",
                    "extraction_method": "Event ID 4688"
                }
            ],
            "onion_domains": [],
            "recovery_status": "active",
            "confidence": "very_high",
            "confidence_reasons": [],
            "metadata_hash": "abc123"
        }

        event = UnifiedEvent.from_dict(data)
        assert event.timestamp == "2024-12-15T14:32:15Z"
        assert event.event_type == EventType.TOR_EXECUTION


class TestForensicTimeline:
    """Test ForensicTimeline data class."""

    def test_create_timeline(self):
        """Test creation of ForensicTimeline."""
        source = ArtifactSource(artifact="Test", extraction_method="Test")
        event = UnifiedEvent(
            timestamp="2024-12-15T14:32:15Z",
            event_type=EventType.TOR_EXECUTION,
            sources=[source]
        )

        timeline = ForensicTimeline(events=[event])
        assert len(timeline.events) == 1

    def test_timeline_to_json(self):
        """Test timeline JSON serialization."""
        timeline = ForensicTimeline(events=[])
        json_str = timeline.to_json()
        data = json.loads(json_str)

        assert "collection_timestamp" in data
        assert data["run_mode"] == "collection"
        assert data["data_origin"] == "artifact"
        assert "event_count" in data
        assert data["event_count"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
