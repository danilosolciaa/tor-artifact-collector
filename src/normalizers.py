"""
Converts raw extractor output into UnifiedEvent objects.

Each normalizer handles one artifact type, filters for Tor-related entries,
and normalizes timestamps and paths into a consistent format.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import os
import codecs
import logging

from .models import (
    UnifiedEvent,
    ArtifactSource,
    OnionDomain,
    EventType,
    TimestampConfidence,
    RecoveryStatus,
    ConfidenceLevel,
)

logger = logging.getLogger(__name__)


def _utc_now_iso8601() -> str:
    """Return a timezone-aware UTC timestamp with a trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_iso8601_utc(value: Any) -> Optional[str]:
    """
    Normalize a datetime-like value to ISO 8601 UTC.

    Accepts datetime objects or ISO 8601 strings. Returns None for values that
    cannot be parsed cleanly.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def normalize_windows_path(path: str) -> str:
    """Lowercase and normalize slashes so paths from different artifacts compare correctly."""
    if not path:
        return ""
    return path.replace("/", "\\").lower()


def filetime_to_iso8601(filetime: int) -> str:
    """
    Convert a Windows FILETIME integer to ISO 8601.

    FILETIME counts 100-nanosecond intervals since 1601-01-01. Dividing by
    10,000,000 gives seconds, then subtracting the offset to the Unix epoch
    (11644473600s) gives a standard Unix timestamp.
    """
    FILETIME_EPOCH_DIFF = 11644473600
    try:
        unix_ts = (filetime / 10_000_000) - FILETIME_EPOCH_DIFF
        return datetime.fromtimestamp(unix_ts, timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OSError) as e:
        logger.warning(f"Invalid FILETIME {filetime}: {e}")
        return _utc_now_iso8601()


def firefox_timestamp_to_iso8601(firefox_time: int) -> str:
    """Firefox stores timestamps as microseconds since the Unix epoch."""
    try:
        return (
            datetime.fromtimestamp(firefox_time / 1_000_000, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (ValueError, OSError) as e:
        logger.warning(f"Invalid Firefox timestamp {firefox_time}: {e}")
        return _utc_now_iso8601()


def rot13_decode(encoded: str) -> str:
    """
    Decode a ROT13-encoded string.

    The Windows Registry UserAssist key obfuscates executable paths with ROT13
    to prevent trivial string searches. It's not encryption, just light obfuscation.
    """
    return codecs.decode(encoded, "rot_13")


def is_tor_related(path: str) -> bool:
    """Check whether a file path belongs to a Tor Browser installation.

    Covers both direct .exe paths and .lnk shortcuts (UserAssist records the
    shortcut launch, not the underlying executable).
    """
    indicators = [
        "tor browser",
        "torbrowser",
        "tor.exe",
        "\\tor\\",
        "\\browser\\firefox.exe",
    ]
    path_lower = path.lower()
    return any(ind in path_lower for ind in indicators)


def normalize_userassist(
    raw_data: Dict[str, Any],
    registry_path: str,
    hive_path: str,
) -> Optional[UnifiedEvent]:
    """
    Convert a UserAssist registry entry to a UnifiedEvent.

    Returns None if the entry isn't Tor-related.

    Note: UserAssist rounds last-run timestamps to the nearest hour (a Windows
    privacy feature), so TimestampConfidence is LOW even though the data is reliable.
    """
    try:
        decoded_path = rot13_decode(raw_data.get("encoded_name", ""))
        if not is_tor_related(decoded_path):
            return None

        timestamp = filetime_to_iso8601(raw_data.get("last_execution", 0))

        source = ArtifactSource(
            artifact="NTUSER.DAT",
            extraction_method="UserAssist",
            file_path=hive_path,
            registry_path=registry_path,
            raw_value=str(raw_data),
        )

        return UnifiedEvent(
            timestamp=timestamp,
            timestamp_confidence=TimestampConfidence.LOW,
            event_type=EventType.TOR_EXECUTION,
            executable_path=normalize_windows_path(decoded_path),
            run_count=raw_data.get("run_count", 1),
            sources=[source],
            recovery_status=RecoveryStatus.ACTIVE,
            confidence=ConfidenceLevel.MEDIUM,
            confidence_reasons=["Registry UserAssist - survives uninstallation"],
            notes="Timestamp rounded to nearest hour (Windows privacy feature)",
        )
    except Exception as e:
        logger.error(f"Error normalizing UserAssist data: {e}", exc_info=True)
        return None


def normalize_prefetch(
    raw_data: Dict[str, Any],
    prefetch_path: str,
) -> Optional[UnifiedEvent]:
    """Convert a Prefetch entry to a UnifiedEvent. Returns None if not Tor-related."""
    try:
        executable = raw_data.get("executable", "")
        if not is_tor_related(executable):
            return None

        last_run_times = raw_data.get("last_run_times", [])
        if not last_run_times:
            return None

        normalized_run_times = [
            normalized
            for normalized in (_to_iso8601_utc(ts) for ts in last_run_times)
            if normalized is not None
        ]
        if not normalized_run_times:
            return None

        timestamp = max(
            normalized_run_times,
            key=lambda ts: datetime.fromisoformat(ts.replace("Z", "+00:00")),
        )

        source = ArtifactSource(
            artifact="Prefetch",
            extraction_method=f"Prefetch file {os.path.basename(prefetch_path)}",
            file_path=prefetch_path,
            raw_value=str(raw_data),
        )

        return UnifiedEvent(
            timestamp=timestamp,
            timestamp_confidence=TimestampConfidence.HIGH,
            event_type=EventType.TOR_EXECUTION,
            executable_path=normalize_windows_path(executable),
            run_count=raw_data.get("run_count", len(last_run_times)),
            sources=[source],
            recovery_status=RecoveryStatus.ACTIVE,
            confidence=ConfidenceLevel.HIGH,
            confidence_reasons=[
                "Prefetch - persists after uninstall",
                f"Last {len(normalized_run_times)} executions recorded",
            ],
            notes=f"Last executions: {', '.join(normalized_run_times)}",
        )
    except Exception as e:
        logger.error(f"Error normalizing Prefetch data: {e}", exc_info=True)
        return None


def normalize_places_sqlite(raw_data: Dict[str, Any]) -> Optional[UnifiedEvent]:
    """Convert a places.sqlite row to a UnifiedEvent. Returns None if not .onion."""
    try:
        url = raw_data.get("url", "")
        if not url or ".onion" not in url.lower():
            return None

        from urllib.parse import urlparse
        parsed = urlparse(url)
        onion_domain = parsed.netloc or parsed.path.split("/")[0]

        timestamp = firefox_timestamp_to_iso8601(raw_data.get("last_visit_date", 0))

        domain_obj = OnionDomain(
            domain=onion_domain,
            title=raw_data.get("title"),
            visit_count=raw_data.get("visit_count", 1),
            last_visit=timestamp,
            source="places.sqlite",
        )

        source = ArtifactSource(
            artifact="places.sqlite",
            extraction_method="moz_places query",
            file_path=raw_data.get("places_db_path"),
            raw_value=str(raw_data),
        )

        return UnifiedEvent(
            timestamp=timestamp,
            timestamp_confidence=TimestampConfidence.MEDIUM,
            event_type=EventType.TOR_HISTORY,
            sources=[source],
            onion_domains=[domain_obj],
            recovery_status=RecoveryStatus.ACTIVE,
            confidence=ConfidenceLevel.HIGH,
            confidence_reasons=[
                "Active browser history - direct .onion access proof",
                f"Visited {domain_obj.visit_count} times",
            ],
            notes=f"URL: {url}",
        )
    except Exception as e:
        logger.error(f"Error normalizing places.sqlite data: {e}", exc_info=True)
        return None


def normalize_places_wal(raw_data: Dict[str, Any]) -> Optional[UnifiedEvent]:
    """
    Convert a WAL-recovered entry to a UnifiedEvent.

    Since the record was deleted at some point, we don't have a reliable
    timestamp and mark it ESTIMATED. Recovery from WAL is itself evidence
    of a deletion attempt.
    """
    try:
        url = raw_data.get("url", "")
        if not url or ".onion" not in url.lower():
            return None

        from urllib.parse import urlparse
        parsed = urlparse(url)
        onion_domain = parsed.netloc or parsed.path.split("/")[0]

        domain_obj = OnionDomain(
            domain=onion_domain,
            title=raw_data.get("title"),
            visit_count=0,
            source="places.sqlite-wal",
        )

        source = ArtifactSource(
            artifact="places.sqlite-wal",
            extraction_method="WAL binary carving",
            file_path=raw_data.get("wal_path"),
            raw_value=f"Offset {raw_data.get('wal_offset')}: {url}",
        )

        return UnifiedEvent(
            timestamp=raw_data.get("wal_mtime") or _utc_now_iso8601(),
            timestamp_confidence=TimestampConfidence.ESTIMATED,
            event_type=EventType.TOR_HISTORY,
            sources=[source],
            onion_domains=[domain_obj],
            recovery_status=RecoveryStatus.DELETED,
            confidence=ConfidenceLevel.MEDIUM,
            confidence_reasons=[
                "Recovered from WAL - evidence of deletion attempt",
                "Timestamp estimated from WAL file modification time",
            ],
            notes=(
                f"Deleted URL recovered from WAL at offset {raw_data.get('wal_offset')}; "
                "timestamp is an upper-bound estimate, not the visit time"
            ),
        )
    except Exception as e:
        logger.error(f"Error normalizing places.sqlite-wal data: {e}", exc_info=True)
        return None


def normalize_evtx(raw_data: Dict[str, Any]) -> Optional[UnifiedEvent]:
    """Convert an EVTX Event ID 4688 record to a UnifiedEvent. Returns None if not Tor-related."""
    try:
        process_name = raw_data.get("process_name", "")
        if not is_tor_related(process_name):
            return None

        timestamp = raw_data.get("timestamp", _utc_now_iso8601())

        source = ArtifactSource(
            artifact="EVTX",
            extraction_method=f"Event ID {raw_data.get('event_id', 4688)}",
            file_path=raw_data.get("evtx_path"),
            raw_value=str(raw_data),
        )

        return UnifiedEvent(
            timestamp=timestamp,
            timestamp_confidence=TimestampConfidence.HIGH,
            event_type=EventType.TOR_EXECUTION,
            executable_path=normalize_windows_path(process_name),
            sources=[source],
            recovery_status=RecoveryStatus.ACTIVE,
            confidence=ConfidenceLevel.VERY_HIGH,
            confidence_reasons=[
                "EVTX Event ID 4688 - definitive execution proof",
                "Requires audit policy (reduces false positives)",
            ],
            notes=(
                f"Command line: {raw_data.get('command_line', 'N/A')} | "
                f"Parent: {raw_data.get('parent_process', 'N/A')}"
            ),
        )
    except Exception as e:
        logger.error(f"Error normalizing EVTX data: {e}", exc_info=True)
        return None


def normalize_chrome_history(raw_data: Dict[str, Any]) -> Optional[UnifiedEvent]:
    """
    Convert a Chromium browser history entry to a UnifiedEvent.

    .onion URLs in Chrome/Edge/Brave almost always represent failed DNS lookups
    since Tor isn't configured. Still forensically relevant: it shows the user
    knew the address and intended to visit it.
    """
    try:
        url = raw_data.get("url", "")
        if not url or ".onion" not in url.lower():
            return None

        from .extractors.chrome_history import webkit_timestamp_to_iso8601
        timestamp = webkit_timestamp_to_iso8601(raw_data.get("last_visit_time", 0))

        from urllib.parse import urlparse
        parsed = urlparse(url)
        onion_domain = parsed.netloc or parsed.path.split("/")[0]

        title = raw_data.get("title") or ""
        is_likely_failed = any(e in title.lower() for e in [
            "can't be reached", "not found", "dns_probe", "nxdomain", "err_name_not_resolved",
        ])

        domain_obj = OnionDomain(
            domain=onion_domain,
            title=title if not is_likely_failed else f"{title} (FAILED LOOKUP)",
            visit_count=raw_data.get("visit_count", 1),
            last_visit=timestamp,
            source=raw_data.get("browser", "Chrome"),
        )

        typed_count = raw_data.get("typed_count", 0)
        manual_note = " (MANUALLY TYPED)" if typed_count > 0 else ""

        source = ArtifactSource(
            artifact=f"{raw_data.get('browser', 'Chrome')} History",
            extraction_method="urls table query",
            file_path=raw_data.get("history_db_path"),
            raw_value=str(raw_data),
        )

        return UnifiedEvent(
            timestamp=timestamp,
            timestamp_confidence=TimestampConfidence.HIGH,
            event_type=EventType.TOR_HISTORY,
            sources=[source],
            onion_domains=[domain_obj],
            recovery_status=RecoveryStatus.ACTIVE,
            confidence=ConfidenceLevel.MEDIUM if is_likely_failed else ConfidenceLevel.HIGH,
            confidence_reasons=[
                f"{raw_data.get('browser', 'Chrome')} History - .onion access attempt",
                "Failed DNS lookup (Tor not configured)" if is_likely_failed
                else "Successful access (Tor proxy configured)",
                f"Visited {domain_obj.visit_count} times{manual_note}",
            ],
            notes=f"URL: {url} | accessed without Tor = intent to reach darknet",
        )
    except Exception as e:
        logger.error(f"Error normalizing Chrome history data: {e}", exc_info=True)
        return None


def normalize_jump_list(raw_data: Dict[str, Any]) -> Optional[UnifiedEvent]:
    """
    Convert a Jump List entry to a UnifiedEvent.

    Jump Lists record application launches via Windows Explorer shortcuts.
    Launching Tor Browser from a desktop shortcut creates an entry here that
    survives browser history clears and standard uninstallation.
    """
    try:
        app_path = raw_data.get("app_path") or ""
        if not is_tor_related(app_path):
            if not app_path:
                app_path = "unknown (path not recovered)"
            else:
                return None

        timestamp = raw_data.get("timestamp") or _utc_now_iso8601()
        ts_source = raw_data.get("timestamp_source", "file_mtime")
        ts_confidence = (
            TimestampConfidence.HIGH
            if ts_source == "lnk_write_time"
            else TimestampConfidence.ESTIMATED
        )

        recovery_method = raw_data.get("recovery_method", "unknown")
        source = ArtifactSource(
            artifact="Jump List",
            extraction_method=f"AutomaticDestinations ({recovery_method})",
            file_path=raw_data.get("jump_list_path"),
            raw_value=str(raw_data),
        )

        return UnifiedEvent(
            timestamp=timestamp,
            timestamp_confidence=ts_confidence,
            event_type=EventType.TOR_EXECUTION,
            executable_path=normalize_windows_path(app_path),
            sources=[source],
            recovery_status=RecoveryStatus.ACTIVE,
            confidence=ConfidenceLevel.HIGH,
            confidence_reasons=[
                "Jump List — Explorer-managed, survives uninstallation and history clears",
                f"Timestamp from {ts_source}",
            ],
            notes="Launch via desktop shortcut recorded in AutomaticDestinations",
        )
    except Exception as e:
        logger.error(f"Error normalizing Jump List data: {e}", exc_info=True)
        return None


def normalize_batch(
    raw_events: List[Dict[str, Any]],
    artifact_type: str,
) -> List[UnifiedEvent]:
    """Normalize a list of raw events from a single artifact type."""
    normalizer_map = {
        "userassist": lambda d: normalize_userassist(
            d, d.get("registry_path", ""), d.get("hive_path", "")
        ),
        "prefetch": lambda d: normalize_prefetch(d, d.get("prefetch_path", "")),
        "places_sqlite": normalize_places_sqlite,
        "places_wal": normalize_places_wal,
        "evtx": normalize_evtx,
        "chrome_history": normalize_chrome_history,
        "jump_list": normalize_jump_list,
    }

    normalizer = normalizer_map.get(artifact_type)
    if not normalizer:
        logger.error(f"Unknown artifact type: {artifact_type}")
        return []

    result = [e for e in (normalizer(raw) for raw in raw_events) if e is not None]
    logger.info(f"Normalized {len(result)}/{len(raw_events)} {artifact_type} events")
    return result
