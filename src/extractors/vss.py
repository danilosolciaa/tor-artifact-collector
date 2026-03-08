"""
Volume Shadow Copy (VSS) extractor for deleted Tor Browser history recovery.

If the system had VSS (Shadow Copies) enabled, previous versions of
places.sqlite may exist in shadow copies even after the user deleted their
Tor Browser history or uninstalled the browser.

This module:
  1. Enumerates available shadow copies via `vssadmin list shadows` (Windows only).
  2. Locates places.sqlite under each shadow copy root.
  3. Returns path info so the caller can extract using the standard SQLite extractor.

Only works on live Windows systems. Requires administrative privileges.
"""

import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Tor Browser places.sqlite paths relative to a user profile directory
_PLACES_RELATIVE_PATHS = [
    "AppData\\Roaming\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\places.sqlite",
    "AppData\\Local\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\places.sqlite",
]


def enumerate_vss_shadows(drive_letter: str = "C:") -> List[str]:
    """
    Return a list of shadow copy root paths for the given drive.

    Parses the output of `vssadmin list shadows /for=<drive>`.
    Each returned string is a root path like:
      \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\

    Returns an empty list on non-Windows platforms, if vssadmin is unavailable,
    or if elevation is insufficient.
    """
    if sys.platform != "win32":
        logger.info("VSS enumeration is only supported on Windows")
        return []

    drive = drive_letter.rstrip("\\").rstrip("/")
    if not drive.endswith(":"):
        drive += ":"

    try:
        result = subprocess.run(
            ["vssadmin", "list", "shadows", f"/for={drive}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        logger.warning("vssadmin not found — VSS extraction skipped")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("vssadmin timed out")
        return []
    except PermissionError:
        logger.error("vssadmin requires Administrator privileges")
        return []

    if result.returncode != 0:
        if "no shadow copies" in result.stdout.lower():
            logger.info(f"No VSS shadow copies found for {drive}")
        else:
            logger.warning(f"vssadmin returned {result.returncode}: {result.stderr.strip()}")
        return []

    # Extract "Shadow Copy Volume:" lines
    shadows: List[str] = []
    for line in result.stdout.splitlines():
        m = re.search(r"Shadow Copy Volume:\s*(\\\\\?\\GLOBALROOT[^\s]+)", line, re.IGNORECASE)
        if m:
            root = m.group(1)
            # Ensure trailing backslash for path joining
            if not root.endswith("\\"):
                root += "\\"
            shadows.append(root)

    logger.info(f"Found {len(shadows)} VSS shadow copy(ies) for {drive}")
    return shadows


def find_tor_places_in_vss(
    shadow_roots: List[str],
    users_subdir: str = "Users",
) -> List[Dict[str, Any]]:
    """
    Search each shadow copy for Tor Browser places.sqlite files.

    For each shadow copy, walks the Users directory to find per-user profiles
    and checks for Tor Browser history databases.

    Returns a list of dicts with:
      - places_path:   full path to places.sqlite inside the shadow copy
      - shadow_root:   shadow copy root path
      - username:      extracted username (or 'Unknown')
      - snapshot_index: 1-based index of the shadow copy
    """
    found: List[Dict[str, Any]] = []

    for idx, shadow_root in enumerate(shadow_roots, start=1):
        users_path = Path(shadow_root) / users_subdir
        if not users_path.exists():
            logger.debug(f"VSS snapshot {idx}: Users directory not found at {users_path}")
            continue

        for user_dir in users_path.iterdir():
            if not user_dir.is_dir():
                continue
            username = user_dir.name
            for rel_path in _PLACES_RELATIVE_PATHS:
                candidate = user_dir / rel_path
                if candidate.exists():
                    logger.info(
                        f"VSS snapshot {idx}: found places.sqlite for {username} at {candidate}"
                    )
                    found.append({
                        "places_path": str(candidate),
                        "shadow_root": shadow_root,
                        "username": username,
                        "snapshot_index": idx,
                    })

    return found
