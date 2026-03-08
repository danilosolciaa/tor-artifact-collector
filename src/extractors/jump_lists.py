"""
Windows Jump List extractor for Tor Browser execution evidence.

Jump Lists (.automaticDestinations-ms) are OLE Compound File Binary (CFB)
documents stored in:
  %%APPDATA%%/Microsoft/Windows/Recent/AutomaticDestinations/

Each file corresponds to one application. Inside, every OLE stream is an LNK
(Shell Link) record for a recently-launched item. When Tor Browser is launched
via a desktop shortcut, an entry is written here.

Jump List entries survive browser history clears and standard uninstallation
because they are managed by Windows Explorer, not by the application itself.

Parsing strategy:
  1. If `olefile` is available: open the CFB document, parse each numeric
     stream as an LNK file, read the LNK target timestamps and extract paths.
  2. Fallback: raw binary carving for Tor path strings (ASCII and UTF-16 LE).
"""

import logging
import re
import struct
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logging_utils import extractor, log_extraction_context, safe_read_file

logger = logging.getLogger(__name__)

try:
    import olefile
    _HAS_OLEFILE = True
except ImportError:
    _HAS_OLEFILE = False

# LNK magic: HeaderSize field is always 0x4C (76)
_LNK_MAGIC = b"\x4c\x00\x00\x00"

# FILETIME epoch offset in seconds
_FILETIME_EPOCH_DIFF = 11644473600

# Tor path indicators — searched in both ASCII and decoded UTF-16 LE
_TOR_INDICATORS = [
    "tor browser",
    "torbrowser",
    "tor.exe",
    "\\tor\\",
]

# UTF-16 LE encoded versions of the above for binary carving
_TOR_INDICATORS_UTF16 = [s.encode("utf-16-le") for s in _TOR_INDICATORS]


# ── LNK header parsing ───────────────────────────────────────────────────────

def _filetime_to_iso8601(filetime: int) -> Optional[str]:
    """Convert a Windows FILETIME integer to ISO 8601 UTC, or None if invalid."""
    if filetime == 0:
        return None
    try:
        unix_ts = (filetime / 10_000_000) - _FILETIME_EPOCH_DIFF
        return (
            datetime.fromtimestamp(unix_ts, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (ValueError, OSError):
        return None


def _file_mtime_iso8601(path: str) -> str:
    """Return a file's modification time as ISO 8601 UTC."""
    return (
        datetime.fromtimestamp(Path(path).stat().st_mtime, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_lnk_write_time(lnk_data: bytes) -> Optional[str]:
    """
    Extract the write time from an LNK file header.

    LNK header layout (all little-endian):
      0-3:   HeaderSize (0x4C)
      4-19:  LinkCLSID
      20-23: LinkFlags
      24-27: FileAttributes
      28-35: CreationTime (FILETIME)
      36-43: AccessTime  (FILETIME)
      44-51: WriteTime   (FILETIME)
    """
    if len(lnk_data) < 52:
        return None
    if lnk_data[:4] != _LNK_MAGIC:
        return None
    try:
        write_time = struct.unpack_from("<Q", lnk_data, 44)[0]
        return _filetime_to_iso8601(write_time)
    except struct.error:
        return None


def _contains_tor_indicator(data: bytes) -> bool:
    """Return True if the byte string contains any Tor path indicator."""
    data_lower = data.lower()
    for ind in _TOR_INDICATORS:
        if ind.encode("ascii") in data_lower:
            return True
    for ind_utf16 in _TOR_INDICATORS_UTF16:
        if ind_utf16.lower() in data_lower:
            return True
    return False


def _extract_path_from_binary(data: bytes) -> Optional[str]:
    """
    Heuristically extract a Windows filesystem path from binary data.

    Tries UTF-16 LE decoding first, then ASCII. Returns the longest
    candidate that contains a Tor indicator.
    """
    candidates: List[str] = []

    # Try UTF-16 LE decoding in overlapping 512-byte windows
    for start in range(0, len(data) - 1, 2):
        chunk = data[start : start + 512]
        try:
            decoded = chunk.decode("utf-16-le", errors="ignore")
            path_matches = re.findall(
                r"[A-Za-z]:\\[^\x00<>:\"|?*\n\r]{4,200}", decoded
            )
            for m in path_matches:
                if any(ind in m.lower() for ind in _TOR_INDICATORS):
                    candidates.append(m.rstrip("\x00 "))
        except Exception:
            continue

    # ASCII fallback
    ascii_matches = re.findall(
        rb"[A-Za-z]:\\[^\x00<>:\"\|?*\n\r]{4,200}", data
    )
    for m in ascii_matches:
        decoded = m.decode("ascii", errors="ignore").rstrip("\x00 ")
        if any(ind in decoded.lower() for ind in _TOR_INDICATORS):
            candidates.append(decoded)

    if not candidates:
        return None
    # Prefer the longest match (most complete path)
    return max(candidates, key=len)


# ── Per-file extraction ──────────────────────────────────────────────────────

@extractor("Jump List", timeout=30.0, required_extensions=[".ms"])
def extract_jump_list_file(path: str) -> List[Dict[str, Any]]:
    """
    Extract Tor Browser entries from a single .automaticDestinations-ms file.

    Uses olefile when available for structured OLE parsing; falls back to
    raw binary carving otherwise.
    """
    log_extraction_context("Jump List", path)

    file_data = safe_read_file(path, mode="rb", max_size=10 * 1024 * 1024)
    if not file_data:
        return []

    if _HAS_OLEFILE:
        results = _extract_with_olefile(path, file_data)
    else:
        results = _extract_binary_carve(path, file_data)

    logger.debug(f"Found {len(results)} Tor entry(ies) in {Path(path).name}")
    return results


def _extract_with_olefile(path: str, file_data: bytes) -> List[Dict[str, Any]]:
    """Parse the OLE CFB structure and inspect each LNK stream."""
    results = []
    try:
        ole = olefile.OleFileIO(file_data)
        for entry in ole.listdir():
            if len(entry) != 1:
                continue  # skip nested directories
            stream_name = entry[0]
            # Jump List streams are numeric string IDs
            if not stream_name.isdigit():
                continue
            try:
                lnk_data = ole.openstream(stream_name).read()
            except Exception:
                continue

            if not _contains_tor_indicator(lnk_data):
                continue

            app_path = _extract_path_from_binary(lnk_data)
            write_time = _parse_lnk_write_time(lnk_data)

            results.append({
                "app_path": app_path,
                "jump_list_path": path,
                "timestamp": write_time or _file_mtime_iso8601(path),
                "timestamp_source": "lnk_write_time" if write_time else "file_mtime",
                "recovery_method": "olefile",
                "stream_id": stream_name,
            })
        ole.close()
    except Exception as e:
        logger.warning(f"olefile failed on {path}: {e}; falling back to binary carve")
        return _extract_binary_carve(path, file_data)
    return results


def _extract_binary_carve(path: str, file_data: bytes) -> List[Dict[str, Any]]:
    """Search raw bytes for Tor path indicators when olefile is unavailable."""
    if not _contains_tor_indicator(file_data):
        return []

    app_path = _extract_path_from_binary(file_data)

    return [{
        "app_path": app_path,
        "jump_list_path": path,
        "timestamp": _file_mtime_iso8601(path),
        "timestamp_source": "file_mtime",
        "recovery_method": "binary_carving",
        "stream_id": None,
    }]


# ── Directory-level extraction ───────────────────────────────────────────────

def extract_all_jump_lists(jump_list_dir: str) -> List[Dict[str, Any]]:
    """
    Scan a directory and extract Tor entries from all Jump List files in it.

    jump_list_dir should be:
      %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations
    """
    results = []
    jl_dir = Path(jump_list_dir)

    if not jl_dir.exists():
        logger.info(f"Jump List directory not found: {jump_list_dir}")
        return []

    files = list(jl_dir.glob("*.automaticDestinations-ms"))
    logger.info(f"Found {len(files)} Jump List file(s) in {jump_list_dir}")

    for jl_file in files:
        try:
            entries = extract_jump_list_file(str(jl_file))
            results.extend(entries)
        except Exception as e:
            logger.error(f"Error processing {jl_file.name}: {e}")

    return results


# ── Mock data ────────────────────────────────────────────────────────────────

def generate_mock_jump_list() -> List[Dict[str, Any]]:
    """Mock Jump List entry for demo mode."""
    jl_dir = (
        "C:\\Users\\Alice\\AppData\\Roaming\\Microsoft\\Windows"
        "\\Recent\\AutomaticDestinations"
    )
    return [
        {
            "app_path": (
                "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\firefox.exe"
            ),
            "jump_list_path": f"{jl_dir}\\3e6ffe2f15c4c2d6.automaticDestinations-ms",
            "timestamp": "2024-12-15T13:45:00Z",
            "timestamp_source": "lnk_write_time",
            "recovery_method": "olefile",
            "stream_id": "1",
        },
    ]
