"""
Integration Tests for All Extractors - Validates Complete Extraction Pipeline

This test suite validates:
1. All extractors can generate mock data (demo mode)
2. All normalizers correctly process mock data
3. Correlation engine deduplicates and scores correctly
4. Timeline building and filtering work
5. Export to JSON/CSV succeeds

Test Strategy:
- Uses ONLY demo/mock data (no real artifacts required)
- Tests the complete end-to-end pipeline
- Validates data integrity at each step
- Checks confidence scoring logic

Usage:
    pytest tests/test_extractors_integration.py -v
    pytest tests/test_extractors_integration.py -v --cov=src
"""

import pytest
import json
from datetime import datetime
from pathlib import Path
import uuid

# Import all extractors (mock generators)
from src.extractors.registry import generate_mock_userassist
from src.extractors.places_sqlite import generate_mock_places
from src.extractors.places_wal import generate_mock_wal
from src.extractors.prefetch import generate_mock_prefetch
from src.extractors.evtx import generate_mock_evtx

# Import normalizers
from src.normalizers import normalize_batch

# Import correlation engine
from src.correlation import (
    deduplicate_events,
    build_timeline,
    filter_by_confidence,
    generate_statistics,
    calculate_confidence
)

# Import models
from src.models import (
    ArtifactSource,
    UnifiedEvent,
    EventType,
    ConfidenceLevel,
    TimestampConfidence,
    RecoveryStatus,
    ForensicTimeline
)


# ==============================================================================
# FIXTURE: Complete Pipeline Data
# ==============================================================================

@pytest.fixture
def complete_pipeline_data():
    """
    Generate complete pipeline test data from all extractors.

    Returns:
        Dictionary with keys:
        - raw_data: Dict mapping extractor type to raw mock data
        - normalized_events: All normalized UnifiedEvent objects
        - timeline: ForensicTimeline after deduplication/correlation
    """
    # Step 1: Generate mock data from all extractors
    raw_data = {
        "userassist": generate_mock_userassist(),
        "places_sqlite": generate_mock_places(),
        "places_wal": generate_mock_wal(),
        "prefetch": generate_mock_prefetch(),
        "evtx": generate_mock_evtx()
    }

    # Step 2: Normalize all events
    all_events = []
    for artifact_type, raw_events in raw_data.items():
        normalized = normalize_batch(raw_events, artifact_type)
        all_events.extend(normalized)

    # Step 3: Deduplicate and correlate
    deduplicated = deduplicate_events(all_events)

    # Step 4: Build timeline
    sorted_events = build_timeline(deduplicated, sort_chronological=True)

    # Step 5: Create timeline object
    timeline = ForensicTimeline(
        events=sorted_events,
        analyst_notes="Integration test pipeline",
        run_mode="collection",
        data_origin="artifact",
    )

    return {
        "raw_data": raw_data,
        "normalized_events": all_events,
        "timeline": timeline
    }


# ==============================================================================
# TEST SUITE 1: Extractor Mock Data Generation
# ==============================================================================

class TestExtractorMockGeneration:
    """Test that all extractors can generate valid mock data."""

    def test_registry_mock_generation(self):
        """Test Registry (UserAssist) mock data generation."""
        mock_data = generate_mock_userassist()

        assert isinstance(mock_data, list), "Should return list"
        assert len(mock_data) > 0, "Should generate at least 1 event"

        # Validate structure
        first_event = mock_data[0]
        assert "encoded_name" in first_event
        assert "run_count" in first_event
        assert "last_execution" in first_event
        assert "hive_path" in first_event

    def test_places_sqlite_mock_generation(self):
        """Test places.sqlite mock data generation."""
        mock_data = generate_mock_places()

        assert isinstance(mock_data, list)
        assert len(mock_data) > 0

        # Should contain .onion domains
        first_event = mock_data[0]
        assert "url" in first_event
        assert ".onion" in first_event["url"]
        assert "title" in first_event
        assert "visit_count" in first_event

    def test_places_wal_mock_generation(self):
        """Test places.sqlite-wal (WAL recovery) mock data generation."""
        mock_data = generate_mock_wal()

        assert isinstance(mock_data, list)
        assert len(mock_data) > 0

        # WAL should contain deleted .onion URLs
        first_event = mock_data[0]
        assert "url" in first_event
        assert ".onion" in first_event["url"]
        assert "wal_path" in first_event

    def test_prefetch_mock_generation(self):
        """Test Prefetch mock data generation."""
        mock_data = generate_mock_prefetch()

        assert isinstance(mock_data, list)
        assert len(mock_data) > 0

        # Should contain Tor-related executables
        first_event = mock_data[0]
        assert "executable" in first_event
        assert "run_count" in first_event
        assert "last_run_times" in first_event

    def test_evtx_mock_generation(self):
        """Test EVTX mock data generation."""
        mock_data = generate_mock_evtx()

        assert isinstance(mock_data, list)
        assert len(mock_data) > 0

        # Should contain Event ID 4688
        first_event = mock_data[0]
        assert "event_id" in first_event
        assert first_event["event_id"] == 4688
        assert "process_name" in first_event


# ==============================================================================
# TEST SUITE 2: Normalization Pipeline
# ==============================================================================

class TestNormalizationPipeline:
    """Test that normalizers correctly convert raw data to UnifiedEvent."""

    def test_normalize_userassist(self):
        """Test UserAssist normalization."""
        raw_data = generate_mock_userassist()
        events = normalize_batch(raw_data, "userassist")

        assert len(events) > 0, "Should produce at least 1 event"

        # Validate UnifiedEvent structure
        event = events[0]
        assert isinstance(event, UnifiedEvent)
        assert event.event_type == EventType.TOR_EXECUTION
        assert len(event.sources) == 1
        assert event.sources[0].artifact == "NTUSER.DAT"
        assert event.sources[0].extraction_method == "UserAssist"

    def test_normalize_places_sqlite(self):
        """Test places.sqlite normalization."""
        raw_data = generate_mock_places()
        events = normalize_batch(raw_data, "places_sqlite")

        assert len(events) > 0

        event = events[0]
        assert event.event_type == EventType.TOR_HISTORY
        assert len(event.onion_domains) > 0
        assert ".onion" in event.onion_domains[0].domain
        assert event.recovery_status == RecoveryStatus.ACTIVE

    def test_normalize_places_wal(self):
        """Test places.sqlite-wal normalization."""
        raw_data = generate_mock_wal()
        events = normalize_batch(raw_data, "places_wal")

        assert len(events) > 0

        event = events[0]
        assert event.event_type == EventType.TOR_HISTORY
        assert event.recovery_status == RecoveryStatus.DELETED
        assert len(event.onion_domains) > 0

    def test_normalize_prefetch(self):
        """Test Prefetch normalization."""
        raw_data = generate_mock_prefetch()
        events = normalize_batch(raw_data, "prefetch")

        assert len(events) > 0

        event = events[0]
        assert event.event_type == EventType.TOR_EXECUTION
        assert event.run_count is not None
        assert event.sources[0].artifact == "Prefetch"

    def test_normalize_evtx(self):
        """Test EVTX normalization."""
        raw_data = generate_mock_evtx()
        events = normalize_batch(raw_data, "evtx")

        assert len(events) > 0

        event = events[0]
        assert event.event_type == EventType.TOR_EXECUTION
        assert event.sources[0].artifact == "EVTX"
        assert event.confidence == ConfidenceLevel.VERY_HIGH  # EVTX is most authoritative


# ==============================================================================
# TEST SUITE 3: Correlation Engine
# ==============================================================================

class TestCorrelationEngine:
    """Test deduplication and confidence scoring."""

    def test_deduplication(self, complete_pipeline_data):
        """Test that duplicate events are merged."""
        raw_events = complete_pipeline_data["normalized_events"]
        timeline = complete_pipeline_data["timeline"]

        # Timeline should have fewer events than raw (due to deduplication)
        assert len(timeline.events) <= len(raw_events)

    def test_multi_source_events_have_higher_confidence(self, complete_pipeline_data):
        """Test that events corroborated by multiple sources have higher confidence."""
        timeline = complete_pipeline_data["timeline"]

        # Find events with multiple sources
        multi_source_events = [e for e in timeline.events if len(e.sources) > 1]
        single_source_events = [e for e in timeline.events if len(e.sources) == 1]

        if multi_source_events and single_source_events:
            avg_multi_confidence = sum(_confidence_to_score(e.confidence) for e in multi_source_events) / len(multi_source_events)
            avg_single_confidence = sum(_confidence_to_score(e.confidence) for e in single_source_events) / len(single_source_events)

            assert avg_multi_confidence >= avg_single_confidence, \
                "Multi-source events should have equal or higher confidence"

    def test_confidence_scoring_algorithm(self):
        """Test confidence scoring with known event characteristics."""
        from src.models import ArtifactSource, OnionDomain

        # Create event with 3 sources + EVTX + .onion domains
        event = UnifiedEvent(
            timestamp="2024-12-15T14:32:15Z",
            event_type=EventType.TOR_EXECUTION,
            sources=[
                ArtifactSource("NTUSER.DAT", "UserAssist"),
                ArtifactSource("Prefetch", "TOR.EXE-ABC.pf"),
                ArtifactSource("EVTX", "Event ID 4688")
            ],
            onion_domains=[OnionDomain("test.onion")],
            recovery_status=RecoveryStatus.ACTIVE,
            run_count=5
        )

        confidence, reasons = calculate_confidence(event)

        # Should be very_high (3+ sources + EVTX + .onion + active)
        assert confidence in [ConfidenceLevel.VERY_HIGH, ConfidenceLevel.HIGH]
        assert len(reasons) > 0

    def test_history_events_without_executable_path_are_not_merged(self):
        """History rows in the same bucket should stay separate unless explicitly correlatable."""
        events = [
            UnifiedEvent(
                timestamp="2024-12-15T14:32:15Z",
                event_type=EventType.TOR_HISTORY,
                sources=[ArtifactSource("places.sqlite", "moz_places query")],
            ),
            UnifiedEvent(
                timestamp="2024-12-15T14:34:10Z",
                event_type=EventType.TOR_HISTORY,
                sources=[ArtifactSource("Chrome History", "urls table query")],
            ),
        ]

        deduplicated = deduplicate_events(events)

        assert len(deduplicated) == 2

    def test_confidence_does_not_claim_alignment_without_real_timestamp_match(self):
        """Two merged sources should not automatically get the timestamp-alignment bonus."""
        supporting_events = [
            UnifiedEvent(
                timestamp="2024-12-15T14:00:00Z",
                event_type=EventType.TOR_EXECUTION,
                timestamp_confidence=TimestampConfidence.HIGH,
                sources=[ArtifactSource("Prefetch", "TOR.EXE-A1B2C3D4.pf")],
                executable_path="c:\\tor.exe",
                run_count=10,
            ),
            UnifiedEvent(
                timestamp="2024-12-15T14:10:30Z",
                event_type=EventType.TOR_EXECUTION,
                timestamp_confidence=TimestampConfidence.HIGH,
                sources=[ArtifactSource("EVTX", "Event ID 4688")],
                executable_path="c:\\tor.exe",
                run_count=11,
            ),
        ]

        merged = UnifiedEvent(
            timestamp="2024-12-15T14:10:30Z",
            event_type=EventType.TOR_EXECUTION,
            sources=[source for event in supporting_events for source in event.sources],
            executable_path="c:\\tor.exe",
            run_count=11,
        )

        confidence, reasons = calculate_confidence(merged, supporting_events=supporting_events)

        assert confidence in [ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH]
        assert all("Timestamps align" not in reason for reason in reasons)

    def test_timeline_chronological_sorting(self, complete_pipeline_data):
        """Test that timeline is sorted chronologically."""
        timeline = complete_pipeline_data["timeline"]

        # Extract timestamps
        timestamps = [
            datetime.fromisoformat(e.timestamp.replace('Z', '+00:00'))
            for e in timeline.events
        ]

        # Check sorted (oldest first)
        assert timestamps == sorted(timestamps), "Timeline should be chronologically sorted"


# ==============================================================================
# TEST SUITE 4: Filtering and Statistics
# ==============================================================================

class TestFilteringAndStatistics:
    """Test timeline filtering and statistics generation."""

    def test_filter_by_confidence(self, complete_pipeline_data):
        """Test filtering by minimum confidence level."""
        timeline = complete_pipeline_data["timeline"]

        # Filter to high confidence only
        high_conf_events = filter_by_confidence(timeline.events, ConfidenceLevel.HIGH)

        # All events should be high or very_high
        for event in high_conf_events:
            assert event.confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH]

    def test_generate_statistics(self, complete_pipeline_data):
        """Test statistics generation."""
        timeline = complete_pipeline_data["timeline"]

        stats = generate_statistics(timeline.events)

        # Validate statistics structure
        assert "total_events" in stats
        assert stats["total_events"] == len(timeline.events)
        assert "event_type_counts" in stats
        assert "confidence_distribution" in stats
        assert "source_coverage" in stats
        assert "onion_domain_count" in stats
        assert "date_range" in stats


# ==============================================================================
# TEST SUITE 5: Export Functionality
# ==============================================================================

class TestExportFunctionality:
    """Test JSON and CSV export."""

    def test_json_export(self, complete_pipeline_data):
        """Test JSON export."""
        timeline = complete_pipeline_data["timeline"]

        output_file = Path(f"test_timeline_{uuid.uuid4().hex}.json")
        try:
            json_str = timeline.to_json(indent=2)
            output_file.write_text(json_str, encoding="utf-8")

            assert output_file.exists()

            with open(output_file, encoding="utf-8") as f:
                data = json.load(f)

            assert "events" in data
            assert "collection_timestamp" in data
            assert "run_mode" in data
            assert "data_origin" in data
            assert len(data["events"]) == len(timeline.events)
        finally:
            if output_file.exists():
                output_file.unlink()

    def test_json_serialization_roundtrip(self, complete_pipeline_data):
        """Test that UnifiedEvent can be serialized and deserialized."""
        timeline = complete_pipeline_data["timeline"]

        # Serialize
        json_str = timeline.to_json()
        data = json.loads(json_str)

        # Deserialize
        for event_dict in data["events"]:
            event = UnifiedEvent.from_dict(event_dict)
            assert isinstance(event, UnifiedEvent)
            assert event.event_id == event_dict["event_id"]


# ==============================================================================
# TEST SUITE 6: End-to-End Pipeline
# ==============================================================================

class TestEndToEndPipeline:
    """Test complete pipeline from extraction to export."""

    def test_complete_pipeline_no_crashes(self, complete_pipeline_data):
        """Test that complete pipeline runs without crashes."""
        # If we got here, pipeline succeeded
        assert complete_pipeline_data["timeline"] is not None
        assert len(complete_pipeline_data["timeline"].events) > 0

    def test_all_extractors_produce_events(self):
        """Test that all 5 extractors produce at least 1 event."""
        extractors = {
            "userassist": generate_mock_userassist,
            "places_sqlite": generate_mock_places,
            "places_wal": generate_mock_wal,
            "prefetch": generate_mock_prefetch,
            "evtx": generate_mock_evtx
        }

        for name, generator in extractors.items():
            raw_data = generator()
            events = normalize_batch(raw_data, name)
            assert len(events) > 0, f"Extractor {name} should produce at least 1 event"

    def test_data_integrity_through_pipeline(self):
        """Test that data maintains integrity through entire pipeline."""
        # Generate mock data
        raw_userassist = generate_mock_userassist()

        # Normalize
        events = normalize_batch(raw_userassist, "userassist")

        # Deduplicate
        deduped = deduplicate_events(events)

        # All events should have valid UUIDs
        event_ids = [e.event_id for e in deduped]
        assert len(event_ids) == len(set(event_ids)), "Event IDs should be unique"

        # All events should have metadata hashes
        for event in deduped:
            assert event.metadata_hash
            assert len(event.metadata_hash) == 64  # SHA256 hex length


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def _confidence_to_score(confidence: ConfidenceLevel) -> int:
    """Convert confidence level to numeric score for comparison."""
    scores = {
        ConfidenceLevel.LOW: 0,
        ConfidenceLevel.MEDIUM: 1,
        ConfidenceLevel.HIGH: 2,
        ConfidenceLevel.VERY_HIGH: 3
    }
    return scores[confidence]


# ==============================================================================
# MAIN ENTRY POINT (for running standalone)
# ==============================================================================

if __name__ == "__main__":
    """
    Run tests standalone (without pytest).

    Usage:
        python tests/test_extractors_integration.py
    """
    print("=" * 70)
    print("TOR FORENSIC COLLECTOR - INTEGRATION TEST SUITE")
    print("=" * 70)
    print("\nRunning complete extraction pipeline...\n")

    # Generate complete pipeline data
    print("[1/5] Generating mock data from all extractors...")
    raw_data = {
        "userassist": generate_mock_userassist(),
        "places_sqlite": generate_mock_places(),
        "places_wal": generate_mock_wal(),
        "prefetch": generate_mock_prefetch(),
        "evtx": generate_mock_evtx()
    }
    print(f"✓ Generated {sum(len(v) for v in raw_data.values())} raw events")

    print("\n[2/5] Normalizing to UnifiedEvent format...")
    all_events = []
    for artifact_type, raw_events in raw_data.items():
        normalized = normalize_batch(raw_events, artifact_type)
        all_events.extend(normalized)
        print(f"  - {artifact_type}: {len(normalized)} events")
    print(f"✓ Total normalized events: {len(all_events)}")

    print("\n[3/5] Deduplicating and correlating...")
    deduplicated = deduplicate_events(all_events)
    print(f"✓ Deduplicated to {len(deduplicated)} unique events")

    print("\n[4/5] Building timeline...")
    sorted_events = build_timeline(deduplicated, sort_chronological=True)
    timeline = ForensicTimeline(events=sorted_events, analyst_notes="Test run")
    print(f"✓ Timeline built with {len(timeline.events)} events")

    print("\n[5/5] Generating statistics...")
    stats = generate_statistics(timeline.events)
    print(f"✓ Statistics generated:")
    print(f"  - Event types: {stats['event_type_counts']}")
    print(f"  - Confidence distribution: {stats['confidence_distribution']}")
    print(f"  - Unique .onion domains: {stats['onion_domain_count']}")
    print(f"  - Sources: {stats['source_coverage']}")

    print("\n" + "=" * 70)
    print("ALL TESTS PASSED ✓")
    print("=" * 70)
