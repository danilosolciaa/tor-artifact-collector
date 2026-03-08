"""
Windows Prefetch extractor — parses .pf files via the windowsprefetch library.

Prefetch files live in C:\\Windows\\Prefetch\\ and survive application
uninstallation. Windows 8+ stores the last 8 execution timestamps per binary.
"""

import logging
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
import glob

from ..logging_utils import extractor, log_extraction_context, safe_read_file

logger = logging.getLogger(__name__)

try:
    import windowsprefetch.prefetch as prefetch_parser
    PREFETCH_AVAILABLE = True
except ImportError:
    PREFETCH_AVAILABLE = False


@extractor("Prefetch", timeout=10.0, required_extensions=[".pf", ".PF"])
def extract_prefetch(prefetch_path: str) -> List[Dict[str, Any]]:
    """
    Parse a single Prefetch file.

    Returns a list with one dict containing:
      executable    - executable name
      run_count     - total execution count
      last_run_times - list of ISO 8601 timestamps (up to 8, most recent first)
      prefetch_path - path to the .pf file
      prefetch_hash - 8-char hex hash from the filename
      loaded_files  - DLLs and files loaded (first 50)
      version       - Prefetch format version
    """
    if not PREFETCH_AVAILABLE:
        logger.error("windowsprefetch not installed. Cannot parse Prefetch files.")
        return []

    try:
        log_extraction_context("Prefetch", prefetch_path)

        pf_data = safe_read_file(prefetch_path, mode="rb", max_size=10 * 1024 * 1024)
        if not pf_data:
            return []

        try:
            pf = prefetch_parser.Prefetch(pf_data)
        except Exception as e:
            logger.error(f"Failed to parse Prefetch file: {e}")
            return []

        executable = getattr(pf, "executableName", Path(prefetch_path).stem.split("-")[0])
        run_count = getattr(pf, "runCount", 0)

        last_run_times = []
        for ts in (getattr(pf, "timestamps", None) or [])[:8]:
            try:
                last_run_times.append(
                    ts.isoformat() + "Z" if isinstance(ts, datetime) else str(ts)
                )
            except Exception:
                continue

        resources = getattr(pf, "resources", None) or getattr(pf, "filenames", None) or []
        loaded_files = [str(f) for f in resources[:50]]

        prefetch_hash = ""
        stem = Path(prefetch_path).stem
        if "-" in stem:
            prefetch_hash = stem.split("-")[-1]

        logger.debug(f"Parsed {executable} ({run_count} executions)")

        return [{
            "executable": executable,
            "run_count": run_count,
            "last_run_times": last_run_times,
            "prefetch_path": prefetch_path,
            "prefetch_hash": prefetch_hash,
            "loaded_files": loaded_files,
            "version": getattr(pf, "version", 0),
        }]

    except Exception as e:
        logger.error(f"Unexpected error parsing {prefetch_path}: {type(e).__name__}: {e}")
        return []


def extract_all_prefetch(prefetch_dir: str = "C:\\Windows\\Prefetch") -> List[Dict[str, Any]]:
    """Parse all Tor/Firefox-related .pf files in a Prefetch directory."""
    if not Path(prefetch_dir).exists():
        logger.error(f"Prefetch directory not found: {prefetch_dir}")
        return []

    pf_files = glob.glob(str(Path(prefetch_dir) / "*.pf"))
    logger.info(f"Found {len(pf_files)} .pf files in {prefetch_dir}")

    results = []
    for pf_file in pf_files:
        if any(kw in pf_file.upper() for kw in ("TOR", "FIREFOX")):
            results.extend(extract_prefetch(pf_file))

    return results


def generate_mock_prefetch() -> List[Dict[str, Any]]:
    """Generate mock Prefetch data for demo mode."""
    return [
        {
            "executable": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "run_count": 15,
            "last_run_times": [
                datetime(2024, 12, 15, 14, 32, 15),
                datetime(2024, 12, 15, 11, 45, 30),
                datetime(2024, 12, 14, 16, 20, 10),
                datetime(2024, 12, 14, 9, 15, 0),
                datetime(2024, 12, 13, 18, 30, 45),
                datetime(2024, 12, 13, 12, 10, 20),
                datetime(2024, 12, 12, 20, 5, 30),
                datetime(2024, 12, 12, 14, 50, 15),
            ],
            "prefetch_path": "C:\\Windows\\Prefetch\\TOR.EXE-A1B2C3D4.pf",
            "prefetch_hash": "A1B2C3D4",
            "loaded_files": [
                "C:\\Windows\\System32\\ntdll.dll",
                "C:\\Windows\\System32\\kernel32.dll",
                "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            ],
        },
        {
            "executable": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\firefox.exe",
            "run_count": 18,
            "last_run_times": [
                datetime(2024, 12, 15, 14, 32, 20),
                datetime(2024, 12, 15, 11, 45, 35),
                datetime(2024, 12, 14, 16, 20, 15),
                datetime(2024, 12, 14, 9, 15, 5),
                datetime(2024, 12, 13, 18, 30, 50),
                datetime(2024, 12, 13, 12, 10, 25),
                datetime(2024, 12, 12, 20, 5, 35),
                datetime(2024, 12, 12, 14, 50, 20),
            ],
            "prefetch_path": "C:\\Windows\\Prefetch\\FIREFOX.EXE-5E6F7A8B.pf",
            "prefetch_hash": "5E6F7A8B",
            "loaded_files": [
                "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\firefox.exe",
                "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\xul.dll",
            ],
        },
    ]
