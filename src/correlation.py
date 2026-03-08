"""
Deduplicates events from different artifact sources and scores their confidence.

The core idea: the same execution of tor.exe will leave traces in multiple
places (Registry, Prefetch, Event Log). By grouping events that fall within
the same time window and share the same executable path, we can merge those
traces into a single higher-confidence finding.
"""

import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from datetime import datetime, timezone
from collections import defaultdict

from .models import (
    UnifiedEvent,
    EventType,
    ConfidenceLevel,
    TimestampConfidence,
    RecoveryStatus,
    ArtifactSource,
    OnionDomain,
)
from .config import CORRELATION_TIME_BUCKET_SECONDS, CORRELATION_TIMESTAMP_TOLERANCE

logger = logging.getLogger(__name__)

TEMPORAL_BUCKET_WINDOW = CORRELATION_TIME_BUCKET_SECONDS
TIMESTAMP_ALIGNMENT_TOLERANCE = CORRELATION_TIMESTAMP_TOLERANCE


def _datetime_to_iso8601(dt: datetime) -> str:
    """Return a timezone-aware ISO 8601 UTC string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def deduplicate_events(events: List[UnifiedEvent]) -> List[UnifiedEvent]:
    """
    Merge events that likely represent the same real-world occurrence.

    Events are grouped by (5-minute time bucket, normalized executable path).
    Multiple artifacts within the same window pointing to the same executable
    get merged into a single event with all their sources combined.
    """
    if not events:
        return []

    sorted_events = sorted(
        events,
        key=lambda e: datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")),
    )

    buckets: Dict[Tuple[str, str], List[UnifiedEvent]] = defaultdict(list)
    path_cache: Dict[str, str] = {}

    for event in sorted_events:
        bucket_ts = _bucket_timestamp(event.timestamp, TEMPORAL_BUCKET_WINDOW)
        bucket_key = _build_bucket_key(event, bucket_ts, path_cache)
        buckets[bucket_key].append(event)

    merged_events = []
    total_merges = 0

    for bucket_events in buckets.values():
        if len(bucket_events) == 1:
            merged_events.append(bucket_events[0])
        else:
            merged_events.append(_merge_events(bucket_events))
            total_merges += len(bucket_events) - 1

    logger.info(
        f"Deduplicated {len(events)} events into {len(merged_events)} ({total_merges} merges)"
    )
    return merged_events


def _bucket_timestamp(iso_timestamp: str, window_seconds: int) -> str:
    """Round a timestamp down to the nearest window boundary."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        bucket_seconds = (dt.timestamp() // window_seconds) * window_seconds
        return _datetime_to_iso8601(datetime.fromtimestamp(bucket_seconds, timezone.utc))
    except Exception as e:
        logger.warning(f"Error bucketing timestamp {iso_timestamp}: {e}")
        return iso_timestamp


def _build_bucket_key(
    event: UnifiedEvent,
    bucket_ts: str,
    path_cache: Dict[str, str],
) -> Tuple[str, str]:
    """
    Build a deduplication key.

    Execution artifacts are merged by time bucket and normalized executable
    path. History artifacts stay separate unless they carry an executable path,
    because merging browser history rows by time alone creates false unions.
    """
    exe = event.executable_path or ""
    if event.event_type == EventType.TOR_EXECUTION and exe:
        if exe not in path_cache:
            path_cache[exe] = _normalize_path_for_comparison(exe)
        return (bucket_ts, path_cache[exe])
    return (bucket_ts, f"event:{event.event_id}")


def _normalize_path_for_comparison(path: str) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").lower().rstrip("\\")


def _merge_events(events: List[UnifiedEvent]) -> UnifiedEvent:
    """Merge a list of events (same bucket) into a single corroborated event."""
    if len(events) == 1:
        return events[0]

    # Use the most precisely timestamped event as the base
    best = max(events, key=lambda e: _timestamp_confidence_score(e.timestamp_confidence))

    all_sources: List[ArtifactSource] = []
    for e in events:
        all_sources.extend(e.sources)

    all_domains: List[OnionDomain] = []
    for e in events:
        all_domains.extend(e.onion_domains)

    run_counts = [e.run_count for e in events if e.run_count]

    merged = UnifiedEvent(
        event_id=best.event_id,
        timestamp=best.timestamp,
        timestamp_confidence=best.timestamp_confidence,
        event_type=events[0].event_type,
        executable_path=best.executable_path,
        run_count=max(run_counts) if run_counts else None,
        sources=_deduplicate_sources(all_sources),
        onion_domains=_deduplicate_domains(all_domains),
        recovery_status=_highest_recovery_status([e.recovery_status for e in events]),
        notes=f"Merged from {len(events)} sources",
    )

    merged.confidence, merged.confidence_reasons = calculate_confidence(
        merged,
        supporting_events=events,
    )
    return merged


def _timestamp_confidence_score(confidence: TimestampConfidence) -> int:
    scores = {
        TimestampConfidence.HIGH: 3,
        TimestampConfidence.MEDIUM: 2,
        TimestampConfidence.LOW: 1,
        TimestampConfidence.ESTIMATED: 0,
    }
    return scores.get(confidence, 0)


def _deduplicate_sources(sources: List[ArtifactSource]) -> List[ArtifactSource]:
    seen: Set[str] = set()
    unique = []
    for s in sources:
        key = f"{s.artifact}:{s.extraction_method}"
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


def _deduplicate_domains(domains: List[OnionDomain]) -> List[OnionDomain]:
    domain_map: Dict[str, OnionDomain] = {}
    for d in domains:
        if d.domain not in domain_map:
            domain_map[d.domain] = d
        else:
            existing = domain_map[d.domain]
            existing.visit_count += d.visit_count
            if d.last_visit and (not existing.last_visit or d.last_visit > existing.last_visit):
                existing.last_visit = d.last_visit
    return list(domain_map.values())


def _highest_recovery_status(statuses: List[RecoveryStatus]) -> RecoveryStatus:
    priority = {RecoveryStatus.ACTIVE: 2, RecoveryStatus.DELETED: 1, RecoveryStatus.CARVED: 0}
    return max(statuses, key=lambda s: priority.get(s, 0))


def calculate_confidence(
    event: UnifiedEvent,
    supporting_events: Optional[List[UnifiedEvent]] = None,
) -> Tuple[ConfidenceLevel, List[str]]:
    """
    Score confidence based on how many independent sources corroborate the event.

    Points breakdown:
      3+ sources → +40  (2 sources → +25, 1 source → +10)
      Timestamps align across sources → +30
      Run counts consistent → +20
      .onion domain present → +10
      EVTX as a source → +20
      Event is ACTIVE (not deleted) → +10

    Thresholds: >=90 very_high | >=70 high | >=50 medium | else low
    """
    score = 0
    reasons = []

    source_count = len(event.sources)
    if source_count >= 3:
        score += 40
        reasons.append(f"Corroborated across {source_count} independent sources")
    elif source_count == 2:
        score += 25
        reasons.append(f"Corroborated across {source_count} sources")
    else:
        score += 10
        reasons.append("Single source evidence")

    if _check_timestamp_alignment(supporting_events or [event]):
        score += 30
        reasons.append(f"Timestamps align within {TIMESTAMP_ALIGNMENT_TOLERANCE}s")

    if _check_run_count_consistency(supporting_events or [event]):
        score += 20
        reasons.append("Execution counts consistent across sources")

    if event.onion_domains:
        score += 10
        reasons.append(f"Direct .onion access evidence ({len(event.onion_domains)} domains)")

    if any(s.artifact == "EVTX" for s in event.sources):
        score += 20
        reasons.append("EVTX Event Log (definitive execution proof)")

    if event.recovery_status == RecoveryStatus.ACTIVE:
        score += 10
        reasons.append("Active artifact (not deleted)")
    elif event.recovery_status == RecoveryStatus.DELETED:
        reasons.append("Recovered from deleted data")

    if score >= 90:
        level = ConfidenceLevel.VERY_HIGH
    elif score >= 70:
        level = ConfidenceLevel.HIGH
    elif score >= 50:
        level = ConfidenceLevel.MEDIUM
    else:
        level = ConfidenceLevel.LOW

    reasons.append(f"Confidence score: {score}/100")
    return level, reasons


def _check_timestamp_alignment(events: List[UnifiedEvent]) -> bool:
    """
    Require at least two non-estimated medium/high precision timestamps.

    This avoids awarding an alignment bonus just because two sources were
    merged into the same bucket.
    """
    precise_times = [
        datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
        for e in events
        if e.timestamp_confidence in (TimestampConfidence.HIGH, TimestampConfidence.MEDIUM)
    ]
    if len(precise_times) < 2:
        return False

    delta_seconds = (max(precise_times) - min(precise_times)).total_seconds()
    return delta_seconds <= TIMESTAMP_ALIGNMENT_TOLERANCE


def _check_run_count_consistency(events: List[UnifiedEvent]) -> bool:
    run_counts = [e.run_count for e in events if e.run_count is not None]
    return len(run_counts) >= 2 and len(set(run_counts)) == 1


def build_timeline(
    events: List[UnifiedEvent],
    sort_chronological: bool = True,
) -> List[UnifiedEvent]:
    """Sort events chronologically (oldest first by default)."""
    return sorted(
        events,
        key=lambda e: datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")),
        reverse=not sort_chronological,
    )


def filter_by_confidence(
    events: List[UnifiedEvent],
    min_confidence: ConfidenceLevel,
) -> List[UnifiedEvent]:
    order = {
        ConfidenceLevel.LOW: 0,
        ConfidenceLevel.MEDIUM: 1,
        ConfidenceLevel.HIGH: 2,
        ConfidenceLevel.VERY_HIGH: 3,
    }
    min_score = order[min_confidence]
    filtered = [e for e in events if order[e.confidence] >= min_score]
    logger.info(f"Filtered to {len(filtered)} events with confidence >= {min_confidence.value}")
    return filtered


def filter_by_date_range(
    events: List[UnifiedEvent],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> List[UnifiedEvent]:
    filtered = events

    if start_date:
        start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        filtered = [
            e for e in filtered
            if datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")) >= start_dt
        ]

    if end_date:
        end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        filtered = [
            e for e in filtered
            if datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")) <= end_dt
        ]

    logger.info(f"After date filter: {len(filtered)} events remaining")
    return filtered


def generate_statistics(events: List[UnifiedEvent]) -> Dict[str, Any]:
    """Summarize a timeline: event types, confidence distribution, .onion domains, date range."""
    if not events:
        return {"total_events": 0}

    stats: Dict[str, Any] = {
        "total_events": len(events),
        "event_type_counts": defaultdict(int),
        "confidence_distribution": defaultdict(int),
        "source_coverage": set(),
        "onion_domains": set(),
        "date_range": {"earliest": None, "latest": None},
    }

    timestamps = []
    for event in events:
        stats["event_type_counts"][event.event_type.value] += 1
        stats["confidence_distribution"][event.confidence.value] += 1
        for src in event.sources:
            stats["source_coverage"].add(src.artifact)
        for domain in event.onion_domains:
            stats["onion_domains"].add(domain.domain)
        timestamps.append(
            datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        )

    if timestamps:
        stats["date_range"]["earliest"] = _datetime_to_iso8601(min(timestamps))
        stats["date_range"]["latest"] = _datetime_to_iso8601(max(timestamps))

    stats["source_coverage"] = list(stats["source_coverage"])
    stats["onion_domains"] = list(stats["onion_domains"])
    stats["onion_domain_count"] = len(stats["onion_domains"])
    stats["event_type_counts"] = dict(stats["event_type_counts"])
    stats["confidence_distribution"] = dict(stats["confidence_distribution"])

    return stats
