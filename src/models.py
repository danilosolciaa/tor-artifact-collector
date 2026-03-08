"""Unified event schema for normalized forensic artifacts.

All extractors convert their source-specific output into these structures,
making cross-source correlation possible regardless of where the data came from.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
import hashlib
import json
import uuid


def _utc_now_iso8601() -> str:
    """Return a timezone-aware UTC timestamp with a trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class EventType(Enum):
    TOR_EXECUTION = "tor_execution"
    TOR_HISTORY = "tor_history"
    TOR_INSTALLATION = "tor_installation"
    TOR_CONFIGURATION = "tor_configuration"


class TimestampConfidence(Enum):
    """
    How precise the timestamp actually is.

    Different Windows artifacts store time at very different granularities:
    - HIGH: sub-second (EVTX, Prefetch)
    - MEDIUM: second-level (SQLite)
    - LOW: hour-granularity (Registry UserAssist rounds to the nearest hour)
    - ESTIMATED: inferred, not directly recorded
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ESTIMATED = "estimated"


class RecoveryStatus(Enum):
    ACTIVE = "active"
    DELETED = "deleted"
    CARVED = "carved"


class ConfidenceLevel(Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ArtifactSource:
    """Tracks where a piece of evidence came from (chain of custody)."""
    artifact: str
    extraction_method: str
    file_path: Optional[str] = None
    registry_path: Optional[str] = None
    raw_value: Optional[str] = None
    extraction_timestamp: str = field(default_factory=_utc_now_iso8601)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class OnionDomain:
    domain: str
    title: Optional[str] = None
    visit_count: int = 1
    last_visit: Optional[str] = None
    source: str = "places.sqlite"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class UnifiedEvent:
    """
    A single normalized forensic event, potentially corroborated by multiple sources.

    The sources list drives confidence scoring: the more independent artifacts
    point to the same event, the more reliable the finding.
    """
    timestamp: str
    event_type: EventType
    sources: List[ArtifactSource]

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_confidence: TimestampConfidence = TimestampConfidence.MEDIUM
    executable_path: Optional[str] = None
    run_count: Optional[int] = None
    onion_domains: List[OnionDomain] = field(default_factory=list)
    recovery_status: RecoveryStatus = RecoveryStatus.ACTIVE
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    confidence_reasons: List[str] = field(default_factory=list)
    metadata_hash: str = field(default="")
    notes: str = ""

    def __post_init__(self):
        if not self.metadata_hash:
            self.metadata_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        # SHA256 over the serialized sources so tampering with evidence can be detected
        sources_json = json.dumps(
            [src.to_dict() for src in self.sources],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(sources_json.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "timestamp_confidence": self.timestamp_confidence.value,
            "event_type": self.event_type.value,
            "executable_path": self.executable_path,
            "run_count": self.run_count,
            "sources": [src.to_dict() for src in self.sources],
            "onion_domains": [d.to_dict() for d in self.onion_domains],
            "recovery_status": self.recovery_status.value,
            "confidence": self.confidence.value,
            "confidence_reasons": self.confidence_reasons,
            "metadata_hash": self.metadata_hash,
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnifiedEvent":
        data["event_type"] = EventType(data["event_type"])
        data["timestamp_confidence"] = TimestampConfidence(data["timestamp_confidence"])
        data["recovery_status"] = RecoveryStatus(data["recovery_status"])
        data["confidence"] = ConfidenceLevel(data["confidence"])
        data["sources"] = [ArtifactSource(**src) for src in data["sources"]]
        data["onion_domains"] = [OnionDomain(**d) for d in data.get("onion_domains", [])]
        return cls(**data)


@dataclass
class ForensicTimeline:
    events: List[UnifiedEvent]
    collection_timestamp: str = field(default_factory=_utc_now_iso8601)
    analyst_notes: str = ""
    run_mode: str = "collection"
    data_origin: str = "artifact"
    # Phase label for multi-snapshot workflows (e.g. "A" baseline, "B" active, "C" post-deletion)
    phase: Optional[str] = None
    # SHA-256 of each source artifact file, computed before extraction (chain of custody)
    artifact_hashes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "collection_timestamp": self.collection_timestamp,
            "analyst_notes": self.analyst_notes,
            "run_mode": self.run_mode,
            "data_origin": self.data_origin,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }
        if self.phase:
            d["phase"] = self.phase
        if self.artifact_hashes:
            d["artifact_hashes"] = self.artifact_hashes
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def sort_by_timestamp(self, reverse: bool = False):
        self.events.sort(
            key=lambda e: datetime.fromisoformat(e.timestamp.replace("Z", "+00:00")),
            reverse=reverse,
        )

    def filter_by_confidence(self, min_level: ConfidenceLevel) -> "ForensicTimeline":
        order = {
            ConfidenceLevel.LOW: 0,
            ConfidenceLevel.MEDIUM: 1,
            ConfidenceLevel.HIGH: 2,
            ConfidenceLevel.VERY_HIGH: 3,
        }
        filtered = [e for e in self.events if order[e.confidence] >= order[min_level]]
        return ForensicTimeline(
            events=filtered,
            analyst_notes=f"Filtered by confidence >= {min_level.value}",
            run_mode=self.run_mode,
            data_origin=self.data_origin,
            phase=self.phase,
        )


SourceList = List[ArtifactSource]
DomainList = List[OnionDomain]
EventList = List[UnifiedEvent]
