"""CLI entry point for the collector.

Parses arguments, orchestrates extraction from all artifact sources,
deduplicates events, and exports the final timeline as JSON or CSV.
"""

import argparse
import hashlib
import logging
import sys
import json
import csv
import re
from pathlib import Path
from typing import List, Tuple

from . import __version__
from .models import UnifiedEvent, ForensicTimeline, ConfidenceLevel, RecoveryStatus
from .extractors.registry import extract_userassist, extract_userassist_live, generate_mock_userassist
from .extractors.places_sqlite import extract_places_sqlite, generate_mock_places
from .extractors.places_wal import extract_places_wal, generate_mock_wal
from .extractors.prefetch import extract_prefetch, extract_all_prefetch, generate_mock_prefetch
from .extractors.evtx import extract_evtx, generate_mock_evtx
from .extractors.chrome_history import (
    extract_chrome_history,
    generate_mock_chrome,
    generate_mock_edge,
    generate_mock_brave,
)
from .extractors.jump_lists import extract_all_jump_lists, generate_mock_jump_list
from .extractors.vss import enumerate_vss_shadows, find_tor_places_in_vss
from .normalizers import normalize_batch
from .correlation import (
    deduplicate_events,
    build_timeline,
    filter_by_confidence,
    filter_by_date_range,
    generate_statistics,
)
from .config import get_artifact_paths, create_output_directory, LOG_FORMAT
from .hashing import collect_artifact_hashes, hash_file

logger = logging.getLogger(__name__)


_USAGE_EXAMPLES = """\
Examples:
  Demo mode:
    python -m src.cli --demo --output demo_timeline.json --pretty

  Mounted disk image:
    python -m src.cli --mount "E:\\" --output timeline.json --pretty

  Mounted disk image with phase label and hash:
    python -m src.cli --mount "E:\\" --phase B --hash --output output\\phase_b.json

  Multiple mounted snapshots in one command:
    python -m src.cli --snapshot A=E:\\ --snapshot B=F:\\ --snapshot C=G:\\ --output-dir output --hash --pretty

  Verify artifacts before collection:
    python -m src.cli --verify
"""


def setup_logging(verbose: bool = False):
    """Configure root logger for CLI output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("collection.log"),
        ],
    )


def create_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="collector",
        description="Extract and correlate Tor Browser execution artifacts",
        epilog=_USAGE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version", action="version", version=__version__
    )

    input_group = parser.add_argument_group("Input Sources")
    input_group.add_argument(
        "--mount",
        type=str,
        help="Path to mounted disk image root (e.g., E:\\ or /mnt/evidence). Enables auto-discovery.",
    )
    input_group.add_argument(
        "--snapshot",
        action="append",
        metavar="LABEL=PATH",
        help=(
            "Analyze multiple mounted images in one run. Repeat the flag, e.g. "
            "--snapshot A=E:\\ --snapshot B=F:\\"
        ),
    )
    input_group.add_argument(
        "--auto",
        action="store_true",
        help="Automatically discover artifacts from --mount path or current system",
    )
    input_group.add_argument("--ntuser", type=str, help="Path to NTUSER.DAT file")
    input_group.add_argument("--places", type=str, help="Path to places.sqlite file")
    input_group.add_argument("--places-wal", type=str, help="Path to places.sqlite-wal file")
    input_group.add_argument(
        "--prefetch",
        type=str,
        help="Path to Prefetch directory (default: C:\\Windows\\Prefetch)",
    )
    input_group.add_argument(
        "--evtx",
        type=str,
        help="Path to Security.evtx (default: C:\\Windows\\System32\\winevt\\Logs\\Security.evtx)",
    )
    input_group.add_argument("--chrome", type=str, help="Path to Chrome History database file")
    input_group.add_argument("--edge", type=str, help="Path to Edge History database file")
    input_group.add_argument("--brave", type=str, help="Path to Brave History database file")

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        type=str,
        default="timeline.json",
        help="Output file path (default: timeline.json)",
    )
    output_group.add_argument(
        "--output-dir",
        type=str,
        default="output",
        help="Output directory for multi-snapshot runs (default: output)",
    )
    output_group.add_argument(
        "-f", "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    output_group.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    output_group.add_argument(
        "--phase",
        type=str,
        metavar="LABEL",
        help="Phase label for multi-snapshot workflows (e.g. A, B, C). Embedded in output JSON.",
    )
    output_group.add_argument(
        "--hash",
        action="store_true",
        help="Write a SHA-256 checksum sidecar file next to the output (output.json.sha256)",
    )

    filter_group = parser.add_argument_group("Filtering Options")
    filter_group.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high", "very_high"],
        help="Minimum confidence level to include",
    )
    filter_group.add_argument(
        "--start-date",
        type=str,
        help="Filter events after this date (ISO 8601: 2024-01-01T00:00:00Z)",
    )
    filter_group.add_argument(
        "--end-date",
        type=str,
        help="Filter events before this date (ISO 8601: 2024-12-31T23:59:59Z)",
    )

    extractor_group = parser.add_argument_group("Extractor Control")
    extractor_group.add_argument("--no-registry", action="store_true", help="Disable UserAssist extraction")
    extractor_group.add_argument("--no-places", action="store_true", help="Disable places.sqlite extraction")
    extractor_group.add_argument("--no-wal", action="store_true", help="Disable WAL recovery extraction")
    extractor_group.add_argument("--no-prefetch", action="store_true", help="Disable Prefetch extraction")
    extractor_group.add_argument("--no-evtx", action="store_true", help="Disable EVTX extraction")
    extractor_group.add_argument("--no-jump-lists", action="store_true", help="Disable Jump List extraction")
    extractor_group.add_argument(
        "--jump-lists",
        type=str,
        metavar="DIR",
        help="Path to AutomaticDestinations directory (auto-discovered when --mount is used)",
    )
    extractor_group.add_argument(
        "--vss",
        action="store_true",
        help="Enumerate Volume Shadow Copies for deleted Tor history (Windows, requires Admin)",
    )

    debug_group = parser.add_argument_group("Debug / Workflow Options")
    debug_group.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode (uses mock data instead of real artifacts)",
    )
    debug_group.add_argument("--stats", action="store_true", help="Print timeline statistics to console")
    debug_group.add_argument(
        "--verify",
        action="store_true",
        help="Print PowerShell commands to verify artifact availability, then exit",
    )
    debug_group.add_argument(
        "--examples",
        action="store_true",
        help="Print copy-paste example commands, then exit",
    )
    debug_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG)")

    return parser


# ==============================================================================
# VERIFICATION HELPER
# ==============================================================================

_VERIFY_COMMANDS = """\
Run these in an elevated PowerShell session to confirm artifacts exist
before running the full collection:

  # Event ID 4688 requires this policy to be enabled:
  auditpol /get /subcategory:"Process Creation"

  # Prefetch files (need elevation to read on some systems):
  Get-ChildItem C:\\Windows\\Prefetch\\TOR*.pf, C:\\Windows\\Prefetch\\FIREFOX*.pf

  # Tor Browser history and WAL:
  Get-Item "$env:APPDATA\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\places.sqlite"
  Get-Item "$env:APPDATA\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\places.sqlite-wal"

  # NTUSER.DAT:
  Test-Path "$env:USERPROFILE\\NTUSER.DAT"

  # Chromium browsers:
  Test-Path "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\History"
  Test-Path "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\History"
  Test-Path "$env:LOCALAPPDATA\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History"

  # UserAssist entries (check for non-empty output):
  Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count'

  # Jump Lists (AutomaticDestinations):
  Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticDestinations-ms" | Select-Object Name, LastWriteTime

  # Volume Shadow Copies (requires elevation):
  vssadmin list shadows /for=C:
"""


# ==============================================================================
# EXTRACTION ORCHESTRATION
# ==============================================================================

def extract_all_sources(args: argparse.Namespace, artifact_hashes: dict) -> List[UnifiedEvent]:
    """
    Extract artifacts from all enabled sources.

    Supports three modes: demo (mock data), auto-discovery (--mount/--auto),
    and manual (explicit paths or system defaults).
    artifact_hashes is populated in-place with SHA-256 hashes of source files
    before each file is read.
    """
    if args.demo:
        logger.info("Running in DEMO mode - using mock data")
        return extract_demo_data(args)

    if args.mount or args.auto:
        return _extract_auto_discovery(args, artifact_hashes)

    return _extract_manual(args, artifact_hashes)


def _extract_auto_discovery(args: argparse.Namespace, artifact_hashes: dict) -> List[UnifiedEvent]:
    """Extract from a mounted disk image using auto-discovered artifact paths."""
    from .artifact_locator import locate_artifacts, print_discovery_report
    from .extractors.chrome_history import extract_all_chromium_browsers

    root_path = args.mount or "."
    logger.info(f"=== AUTO-DISCOVERY MODE ===")
    logger.info(f"Scanning for artifacts from: {root_path}")

    discovered = locate_artifacts(root_path, verbose=True)
    print_discovery_report(discovered)

    # Hash all discovered files before extraction (chain of custody)
    source_paths = (
        [p for _, p in discovered["ntuser_dat"]]
        + discovered["tor_browser"]
        + discovered["firefox"]
        + discovered["chrome"]
        + discovered["edge"]
        + discovered["brave"]
        + discovered["prefetch"]
        + discovered["evtx"]
    )
    artifact_hashes.update(collect_artifact_hashes(source_paths))

    all_events = []

    if not args.no_registry:
        for username, ntuser_path in discovered["ntuser_dat"]:
            logger.info(f"Extracting Registry for user: {username}")
            try:
                raw_data = extract_userassist(ntuser_path)
                events = normalize_batch(raw_data, "userassist")
                all_events.extend(events)
                logger.info(f"  → {len(events)} UserAssist events")
            except Exception as e:
                logger.error(f"  → Error extracting UserAssist: {e}")

    if not args.no_places:
        for places_path in discovered["tor_browser"] + discovered["firefox"]:
            logger.info(f"Extracting Firefox/Tor history from: {places_path}")
            try:
                raw_data = extract_places_sqlite(places_path)
                events = normalize_batch(raw_data, "places_sqlite")
                all_events.extend(events)
                logger.info(f"  → {len(events)} history events")
            except Exception as e:
                logger.error(f"  → Error extracting history: {e}")

    if not args.no_wal:
        for places_path in discovered["tor_browser"] + discovered["firefox"]:
            wal_path = places_path + "-wal"
            if Path(wal_path).exists():
                logger.info(f"Extracting WAL recovery from: {wal_path}")
                try:
                    raw_data = extract_places_wal(wal_path)
                    events = normalize_batch(raw_data, "places_wal")
                    all_events.extend(events)
                    logger.info(f"  → {len(events)} WAL recovery events")
                except Exception as e:
                    logger.error(f"  → Error extracting WAL: {e}")

    chromium_paths = {
        "chrome_paths": discovered["chrome"],
        "edge_paths": discovered["edge"],
        "brave_paths": discovered["brave"],
    }
    if any(chromium_paths.values()):
        logger.info("Extracting Chromium-based browser history...")
        try:
            raw_data = extract_all_chromium_browsers(**chromium_paths)
            events = normalize_batch(raw_data, "chrome_history")
            all_events.extend(events)
            logger.info(f"  → {len(events)} .onion access attempts")
        except Exception as e:
            logger.error(f"  → Error extracting Chromium history: {e}")

    if not args.no_prefetch:
        for pf_path in discovered["prefetch"]:
            logger.info(f"Extracting Prefetch: {pf_path}")
            try:
                raw_data = extract_prefetch(pf_path)
                events = normalize_batch(raw_data, "prefetch")
                all_events.extend(events)
                logger.info(f"  → {len(events)} Prefetch events")
            except Exception as e:
                logger.error(f"  → Error extracting Prefetch {pf_path}: {e}")

    if not args.no_evtx:
        for evtx_path in discovered["evtx"]:
            logger.info(f"Extracting EVTX: {evtx_path}")
            try:
                raw_data = extract_evtx(evtx_path)
                events = normalize_batch(raw_data, "evtx")
                all_events.extend(events)
                logger.info(f"  → {len(events)} EVTX events")
                if not events:
                    logger.warning(
                        "  → 0 Tor events in EVTX. "
                        "Run: auditpol /get /subcategory:\"Process Creation\""
                    )
            except Exception as e:
                logger.error(f"  → Error extracting EVTX {evtx_path}: {e}")

    if not getattr(args, "no_jump_lists", False):
        for jl_dir in discovered.get("jump_lists", []):
            logger.info(f"Extracting Jump Lists from: {jl_dir}")
            try:
                raw_data = extract_all_jump_lists(jl_dir)
                events = normalize_batch(raw_data, "jump_list")
                all_events.extend(events)
                logger.info(f"  -> {len(events)} Jump List events")
            except Exception as e:
                logger.error(f"  -> Error extracting Jump Lists: {e}")

    logger.info(f"=== AUTO-DISCOVERY COMPLETE: {len(all_events)} events ===")
    return all_events


def _extract_manual(args: argparse.Namespace, artifact_hashes: dict) -> List[UnifiedEvent]:
    """Extract using explicitly specified paths or system defaults."""
    artifact_paths = get_artifact_paths()
    all_events = []

    # Collect all explicitly-specified paths, hash before reading (chain of custody)
    specified_paths = [
        p for p in [
            args.ntuser if hasattr(args, "ntuser") else None,
            args.places if hasattr(args, "places") else None,
            (args.places + "-wal") if (hasattr(args, "places") and args.places) else None,
            getattr(args, "places_wal", None),
            args.evtx if hasattr(args, "evtx") else None,
            getattr(args, "chrome", None),
            getattr(args, "edge", None),
            getattr(args, "brave", None),
        ] if p
    ]
    artifact_hashes.update(collect_artifact_hashes(specified_paths))

    if not args.no_registry:
        if args.ntuser:
            # Explicit offline path — forensic image or manually copied hive
            if Path(args.ntuser).exists():
                logger.info(f"Extracting Registry UserAssist from {args.ntuser}")
                try:
                    raw_data = extract_userassist(args.ntuser)
                    events = normalize_batch(raw_data, "userassist")
                    all_events.extend(events)
                    logger.info(f"Extracted {len(events)} UserAssist events")
                except PermissionError:
                    logger.error(
                        "NTUSER.DAT is locked (Windows holds it while the user is logged in). "
                        "Use an offline image, or omit --ntuser to fall back to live winreg."
                    )
                except Exception as e:
                    logger.error(f"Error extracting UserAssist: {e}", exc_info=True)
            else:
                logger.warning(f"NTUSER.DAT not found at {args.ntuser}")
        elif sys.platform == "win32":
            # Live Windows system — read UserAssist directly via winreg.
            # NTUSER.DAT is always locked while the user is logged in; winreg
            # reads the same data without any file access or elevation.
            logger.info("Extracting UserAssist from live registry (winreg, no elevation needed)")
            try:
                raw_data = extract_userassist_live()
                events = normalize_batch(raw_data, "userassist")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} live UserAssist events")
            except Exception as e:
                logger.error(f"Error extracting live UserAssist: {e}", exc_info=True)
        else:
            ntuser_path = artifact_paths.get("ntuser_dat")
            if ntuser_path and Path(ntuser_path).exists():
                logger.info(f"Extracting Registry UserAssist from {ntuser_path}")
                try:
                    raw_data = extract_userassist(ntuser_path)
                    events = normalize_batch(raw_data, "userassist")
                    all_events.extend(events)
                    logger.info(f"Extracted {len(events)} UserAssist events")
                except Exception as e:
                    logger.error(f"Error extracting UserAssist: {e}", exc_info=True)
            else:
                logger.warning("NTUSER.DAT not found and not on Windows — registry extraction skipped")

    if not args.no_places:
        places_path = args.places or artifact_paths.get("places_sqlite")
        if places_path and Path(places_path).exists():
            logger.info(f"Extracting places.sqlite from {places_path}")
            try:
                raw_data = extract_places_sqlite(places_path)
                events = normalize_batch(raw_data, "places_sqlite")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} places.sqlite events")
            except Exception as e:
                logger.error(f"Error extracting places.sqlite: {e}", exc_info=True)
        else:
            logger.warning(f"places.sqlite not found at {places_path}")

    if not args.no_wal:
        wal_path = args.places_wal
        if not wal_path and args.places:
            wal_path = args.places + "-wal"
        if wal_path and Path(wal_path).exists():
            logger.info(f"Extracting WAL recovery from {wal_path}")
            try:
                raw_data = extract_places_wal(wal_path)
                events = normalize_batch(raw_data, "places_wal")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} WAL recovery events")
            except Exception as e:
                logger.error(f"Error extracting WAL: {e}", exc_info=True)
        else:
            logger.info("places.sqlite-wal not found (may not exist if DB is idle)")

    if not args.no_prefetch:
        prefetch_dir = args.prefetch or "C:\\Windows\\Prefetch"
        if Path(prefetch_dir).exists():
            logger.info(f"Extracting Prefetch from {prefetch_dir}")
            try:
                raw_data = extract_all_prefetch(prefetch_dir)
                events = normalize_batch(raw_data, "prefetch")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} Prefetch events")
            except PermissionError:
                logger.error(
                    "Cannot read Prefetch directory — requires elevation. "
                    "Re-run as Administrator, or use --mount with an offline image."
                )
            except Exception as e:
                logger.error(f"Error extracting Prefetch: {e}", exc_info=True)
        else:
            logger.info(f"Prefetch directory not found: {prefetch_dir}")

    if not args.no_evtx:
        evtx_path = args.evtx or "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        if Path(evtx_path).exists():
            logger.info(f"Extracting EVTX from {evtx_path}")
            try:
                raw_data = extract_evtx(evtx_path)
                events = normalize_batch(raw_data, "evtx")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} EVTX events")
                if not events:
                    logger.warning(
                        "0 Tor-related events found. Either audit policy was not enabled "
                        "when Tor ran, or this is a Windows Home system. "
                        "Enable it before next session: "
                        "auditpol /set /subcategory:\"Process Creation\" /success:enable"
                    )
            except PermissionError:
                logger.error(
                    "Cannot read Security.evtx — requires elevation. "
                    "Re-run as Administrator, or use --mount with an offline image."
                )
            except Exception as e:
                logger.error(f"Error extracting EVTX: {e}", exc_info=True)
        else:
            logger.info(f"Security.evtx not found: {evtx_path}")

    # Chromium browsers (manual paths via --chrome/--edge/--brave)
    for browser_name, history_path in [
        ("Chrome", args.chrome),
        ("Edge", args.edge),
        ("Brave", args.brave),
    ]:
        if not history_path:
            continue
        if Path(history_path).exists():
            logger.info(f"Extracting {browser_name} history from {history_path}")
            try:
                raw_data = extract_chrome_history(history_path, browser_name=browser_name)
                events = normalize_batch(raw_data, "chrome_history")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} {browser_name} .onion events")
            except Exception as e:
                logger.error(f"Error extracting {browser_name}: {e}", exc_info=True)
        else:
            logger.warning(f"{browser_name} History not found at {history_path}")

    # Jump Lists
    if not getattr(args, "no_jump_lists", False):
        jl_dir = getattr(args, "jump_lists", None)
        if not jl_dir:
            import os
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                jl_dir = os.path.join(appdata, "Microsoft", "Windows", "Recent", "AutomaticDestinations")
        if jl_dir:
            logger.info(f"Extracting Jump Lists from {jl_dir}")
            try:
                raw_data = extract_all_jump_lists(jl_dir)
                events = normalize_batch(raw_data, "jump_list")
                all_events.extend(events)
                logger.info(f"Extracted {len(events)} Jump List events")
            except Exception as e:
                logger.error(f"Error extracting Jump Lists: {e}", exc_info=True)

    # Volume Shadow Copy recovery (opt-in, requires Admin)
    if getattr(args, "vss", False):
        logger.info("=== VSS RECOVERY ===")
        try:
            shadow_roots = enumerate_vss_shadows()
            vss_hits = find_tor_places_in_vss(shadow_roots)
            for hit in vss_hits:
                places_path = hit["places_path"]
                shadow_root = hit["shadow_root"]
                snapshot_idx = hit["snapshot_index"]
                logger.info(f"VSS snapshot {snapshot_idx}: extracting {places_path}")
                try:
                    artifact_hashes.update(collect_artifact_hashes([places_path]))
                    raw_data = extract_places_sqlite(places_path)
                    events = normalize_batch(raw_data, "places_sqlite")
                    for event in events:
                        event.recovery_status = RecoveryStatus.CARVED
                        event.notes += f" [VSS snapshot {snapshot_idx}: {shadow_root}]"
                        event.confidence_reasons.append(
                            f"Recovered from Volume Shadow Copy (snapshot {snapshot_idx})"
                        )
                    all_events.extend(events)
                    logger.info(f"  -> {len(events)} VSS-recovered history events")
                except Exception as e:
                    logger.error(f"  -> Error extracting VSS places.sqlite: {e}")
        except Exception as e:
            logger.error(f"VSS enumeration failed: {e}", exc_info=True)

    return all_events


def extract_demo_data(args: argparse.Namespace) -> List[UnifiedEvent]:
    """Generate mock data for demo mode — exercises all extractors and normalizers."""
    all_events = []

    if not args.no_registry:
        raw_data = generate_mock_userassist()
        events = normalize_batch(raw_data, "userassist")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock UserAssist events")

    if not args.no_places:
        raw_data = generate_mock_places()
        events = normalize_batch(raw_data, "places_sqlite")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock places.sqlite events")

        raw_data = generate_mock_chrome() + generate_mock_edge() + generate_mock_brave()
        events = normalize_batch(raw_data, "chrome_history")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock Chromium history events")

    if not args.no_wal:
        raw_data = generate_mock_wal()
        events = normalize_batch(raw_data, "places_wal")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock WAL recovery events")

    if not args.no_prefetch:
        raw_data = generate_mock_prefetch()
        events = normalize_batch(raw_data, "prefetch")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock Prefetch events")

    if not args.no_evtx:
        raw_data = generate_mock_evtx()
        events = normalize_batch(raw_data, "evtx")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock EVTX events")

    if not getattr(args, "no_jump_lists", False):
        raw_data = generate_mock_jump_list()
        events = normalize_batch(raw_data, "jump_list")
        all_events.extend(events)
        logger.info(f"Generated {len(events)} mock Jump List events")

    return all_events


# ==============================================================================
# OUTPUT EXPORT
# ==============================================================================

def export_json(timeline: ForensicTimeline, output_path: str, pretty: bool = False):
    """Export timeline to a JSON file."""
    indent = 2 if pretty else None
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(timeline.to_json(indent=indent))
    logger.info(f"Exported timeline to {output_path}")


def export_csv(timeline: ForensicTimeline, output_path: str):
    """Export timeline to a CSV file."""
    if not timeline.events:
        logger.warning("No events to export")
        return

    fieldnames = [
        "timestamp",
        "event_type",
        "confidence",
        "executable_path",
        "run_count",
        "source_count",
        "onion_domains",
        "recovery_status",
        "notes",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in timeline.events:
            writer.writerow({
                "timestamp": event.timestamp,
                "event_type": event.event_type.value,
                "confidence": event.confidence.value,
                "executable_path": event.executable_path or "",
                "run_count": event.run_count or "",
                "source_count": len(event.sources),
                "onion_domains": ", ".join(d.domain for d in event.onion_domains),
                "recovery_status": event.recovery_status.value,
                "notes": event.notes,
            })

    logger.info(f"Exported timeline to {output_path}")


def write_hash_sidecar(output_path: str):
    """Compute SHA-256 of the output file and write a .sha256 sidecar."""
    with open(output_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    sidecar_path = output_path + ".sha256"
    with open(sidecar_path, "w") as f:
        f.write(f"{digest}  {Path(output_path).name}\n")
    logger.info(f"SHA-256: {digest}")
    logger.info(f"Hash written to {sidecar_path}")


def print_demo_timeline(timeline: ForensicTimeline):
    """Print demo JSON directly to the terminal for a self-contained walkthrough."""
    print("\nDEMO TIMELINE JSON")
    print("=" * 60)
    print(timeline.to_json(indent=2))


def parse_snapshot_specs(snapshot_specs: List[str]) -> List[Tuple[str, str]]:
    """Parse repeated LABEL=PATH snapshot specs."""
    parsed_specs: List[Tuple[str, str]] = []

    for spec in snapshot_specs:
        if "=" not in spec:
            raise ValueError(f"Invalid snapshot spec '{spec}'. Use LABEL=PATH.")

        label, path = spec.split("=", 1)
        label = label.strip()
        path = path.strip()

        if not label or not path:
            raise ValueError(f"Invalid snapshot spec '{spec}'. Use LABEL=PATH.")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
            raise ValueError(
                f"Invalid snapshot label '{label}'. Use only letters, numbers, '_' or '-'."
            )

        parsed_specs.append((label, path))

    return parsed_specs


def build_forensic_timeline(args: argparse.Namespace) -> ForensicTimeline:
    """Run extraction, correlation, and filtering, then return a timeline object."""
    artifact_hashes: dict = {}
    logger.info("=" * 60)
    logger.info("STEP 1: Extracting artifacts from all sources")
    logger.info("=" * 60)
    all_events = extract_all_sources(args, artifact_hashes)

    if not all_events:
        raise ValueError("No events extracted.")

    logger.info(f"Total events extracted: {len(all_events)}")

    logger.info("=" * 60)
    logger.info("STEP 2: Deduplicating and correlating events")
    logger.info("=" * 60)
    deduplicated = deduplicate_events(all_events)
    logger.info(f"Events after deduplication: {len(deduplicated)}")

    logger.info("=" * 60)
    logger.info("STEP 3: Building forensic timeline")
    logger.info("=" * 60)
    sorted_events = build_timeline(deduplicated, sort_chronological=True)

    logger.info("=" * 60)
    logger.info("STEP 4: Applying filters")
    logger.info("=" * 60)
    if args.min_confidence:
        confidence_map = {
            "low": ConfidenceLevel.LOW,
            "medium": ConfidenceLevel.MEDIUM,
            "high": ConfidenceLevel.HIGH,
            "very_high": ConfidenceLevel.VERY_HIGH,
        }
        sorted_events = filter_by_confidence(sorted_events, confidence_map[args.min_confidence])

    if args.start_date or args.end_date:
        sorted_events = filter_by_date_range(sorted_events, args.start_date, args.end_date)

    return ForensicTimeline(
        events=sorted_events,
        analyst_notes="",
        run_mode="demo" if args.demo else "collection",
        data_origin="synthetic" if args.demo else "artifact",
        phase=args.phase,
        artifact_hashes=artifact_hashes,
    )


def export_timeline(args: argparse.Namespace, timeline: ForensicTimeline, output_path: str):
    """Export a timeline and any optional sidecars/statistics."""
    logger.info("=" * 60)
    logger.info("STEP 5: Exporting timeline")
    logger.info("=" * 60)
    if args.format == "json":
        export_json(timeline, output_path, pretty=args.pretty)
    elif args.format == "csv":
        export_csv(timeline, output_path)

    if args.hash:
        write_hash_sidecar(output_path)

    if args.stats:
        logger.info("=" * 60)
        logger.info("TIMELINE STATISTICS")
        logger.info("=" * 60)
        stats = generate_statistics(timeline.events)
        print(json.dumps(stats, indent=2))

    if args.demo and args.format == "json":
        print_demo_timeline(timeline)

    logger.info("=" * 60)
    logger.info("COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Timeline exported to: {output_path}")
    logger.info(f"Total events: {len(timeline.events)}")


def run_multi_snapshot_mode(args: argparse.Namespace):
    """Process multiple labeled mounted images in a single command."""
    if args.demo:
        raise ValueError("--snapshot cannot be combined with --demo.")
    if args.mount:
        raise ValueError("Use either --mount or --snapshot, not both.")

    snapshots = parse_snapshot_specs(args.snapshot or [])
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for label, mount_path in snapshots:
        logger.info("=" * 60)
        logger.info(f"SNAPSHOT {label}: {mount_path}")
        logger.info("=" * 60)

        snapshot_args = argparse.Namespace(**vars(args))
        snapshot_args.mount = mount_path
        snapshot_args.phase = label
        snapshot_args.snapshot = None

        output_name = f"phase_{label.lower()}.{args.format}"
        output_path = str(output_dir / output_name)

        timeline = build_forensic_timeline(snapshot_args)
        export_timeline(snapshot_args, timeline, output_path)


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # --verify: just print artifact-check commands and exit, no extraction needed
    if args.verify:
        print(_VERIFY_COMMANDS)
        sys.exit(0)

    if args.examples:
        print(_USAGE_EXAMPLES)
        sys.exit(0)

    setup_logging(args.verbose)
    logger.info(f"Starting collection v{__version__}")
    create_output_directory()
    try:
        if args.snapshot:
            run_multi_snapshot_mode(args)
            return

        if args.phase:
            logger.info(f"Phase: {args.phase}")

        timeline = build_forensic_timeline(args)
        export_timeline(args, timeline, args.output)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
