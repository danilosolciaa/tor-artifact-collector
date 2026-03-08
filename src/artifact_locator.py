"""
Automatic discovery of forensic artifacts from a mounted disk image or live system.

Given a root path (e.g. E:\\ or /mnt/evidence), walks the filesystem to locate
NTUSER.DAT files, browser history databases, Prefetch files, and EVTX logs.
Handles case-insensitive paths so Windows images mounted on Linux work correctly.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Set
import os

logger = logging.getLogger(__name__)


TOR_BROWSER_PATTERNS = [
    "Users/*/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite",
    "Users/*/AppData/Local/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite",
    "Users/*/Downloads/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite",
    "Program Files/Tor Browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite",
]

FIREFOX_PATTERNS = [
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
    "Users/*/AppData/Local/Mozilla/Firefox/Profiles/*/places.sqlite",
]

CHROME_PATTERNS = [
    "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
    "Users/*/AppData/Local/Google/Chrome/User Data/Profile */History",
]

EDGE_PATTERNS = [
    "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/Profile */History",
]

BRAVE_PATTERNS = [
    "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
    "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data/Profile */History",
]

NTUSER_PATTERNS = [
    "Users/*/NTUSER.DAT",
]

PREFETCH_PATTERNS = [
    "Windows/Prefetch/TOR*.pf",
    "Windows/Prefetch/FIREFOX*.pf",
    "Windows/Prefetch/*TOR*.pf",
]

EVTX_PATTERNS = [
    "Windows/System32/winevt/Logs/Security.evtx",
    "Windows/System32/winevt/Logs/System.evtx",
]

JUMP_LIST_PATTERNS = [
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
]


def locate_artifacts(root_path: str, verbose: bool = True) -> Dict[str, Any]:
    """
    Discover all relevant forensic artifacts starting from root_path.

    Returns a dict with lists of found paths keyed by artifact type:
    ntuser_dat, tor_browser, firefox, chrome, edge, brave, prefetch, evtx.
    """
    root = Path(root_path)

    if not root.exists():
        logger.error(f"Root path does not exist: {root_path}")
        return _empty_artifacts()

    if verbose:
        logger.info(f"Starting artifact discovery from: {root_path}")

    artifacts = {
        "ntuser_dat": [],
        "tor_browser": [],
        "firefox": [],
        "chrome": [],
        "edge": [],
        "brave": [],
        "prefetch": [],
        "evtx": [],
        "jump_lists": [],
    }

    artifacts["ntuser_dat"] = _find_ntuser_dat(root)
    artifacts["tor_browser"] = _find_artifacts(root, TOR_BROWSER_PATTERNS)
    artifacts["firefox"] = _find_artifacts(root, FIREFOX_PATTERNS)
    artifacts["chrome"] = _find_artifacts(root, CHROME_PATTERNS)
    artifacts["edge"] = _find_artifacts(root, EDGE_PATTERNS)
    artifacts["brave"] = _find_artifacts(root, BRAVE_PATTERNS)
    artifacts["prefetch"] = _find_artifacts(root, PREFETCH_PATTERNS)
    artifacts["evtx"] = _find_artifacts(root, EVTX_PATTERNS)
    artifacts["jump_lists"] = _find_artifacts(root, JUMP_LIST_PATTERNS)

    if verbose:
        chromium_count = len(artifacts["chrome"]) + len(artifacts["edge"]) + len(artifacts["brave"])
        browser_count = len(artifacts["tor_browser"]) + len(artifacts["firefox"]) + chromium_count
        logger.info(
            f"Discovery complete: {len(artifacts['ntuser_dat'])} user profiles, "
            f"{browser_count} browser databases, "
            f"{len(artifacts['prefetch'])} prefetch files, "
            f"{len(artifacts['evtx'])} event logs, "
            f"{len(artifacts['jump_lists'])} jump list dir(s)"
        )

    return artifacts


def _find_ntuser_dat(root: Path) -> List[tuple]:
    """Find NTUSER.DAT files and extract the username from the path."""
    results = []
    for pattern in NTUSER_PATTERNS:
        for path in _glob_case_insensitive(root, pattern):
            try:
                parts = Path(path).parts
                users_idx = next(i for i, p in enumerate(parts) if p.lower() == "users")
                username = parts[users_idx + 1]
                results.append((username, str(path)))
            except (StopIteration, IndexError):
                results.append(("Unknown", str(path)))
    return results


def _find_artifacts(root: Path, patterns: List[str]) -> List[str]:
    results = []
    for pattern in patterns:
        results.extend(str(p) for p in _glob_case_insensitive(root, pattern))
    return results


def _glob_case_insensitive(root: Path, pattern: str) -> List[Path]:
    """
    Case-insensitive glob for finding Windows artifacts on Linux-mounted images.

    Tries a direct glob first (fast path, works on Windows or exact matches).
    Falls back to a manual case-insensitive directory walk if nothing is found.
    """
    matches: Set[Path] = set()

    try:
        # Fast path
        for match in Path().glob(str(root / pattern)):
            if match.exists():
                matches.add(match.resolve())

        if matches:
            return list(matches)

        # Slow path: walk each path component case-insensitively
        parts = pattern.split("/")
        current_paths = [root]

        for part in parts:
            if not current_paths:
                break

            next_paths = []
            for current in current_paths:
                if not current.is_dir():
                    continue
                try:
                    if "*" in part or "?" in part:
                        next_paths.extend(current.glob(part))
                    else:
                        for child in current.iterdir():
                            if child.name.lower() == part.lower():
                                next_paths.append(child)
                except (PermissionError, OSError) as e:
                    logger.debug(f"Cannot access {current}: {e}")

            current_paths = next_paths

        for path in current_paths:
            if path.exists():
                matches.add(path.resolve())

    except Exception as e:
        logger.warning(f"Error in glob for pattern {pattern}: {e}")

    return list(matches)


def _empty_artifacts() -> Dict[str, Any]:
    return {
        "ntuser_dat": [],
        "tor_browser": [],
        "firefox": [],
        "chrome": [],
        "edge": [],
        "brave": [],
        "prefetch": [],
        "evtx": [],
        "jump_lists": [],
    }


def extract_user_profiles(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Group discovered artifacts by user profile."""
    profiles = {}

    for username, ntuser_path in artifacts["ntuser_dat"]:
        if username not in profiles:
            profiles[username] = {
                "username": username,
                "ntuser_dat": ntuser_path,
                "browser_databases": [],
            }

    for browser_type, db_list in [
        ("tor", artifacts["tor_browser"]),
        ("firefox", artifacts["firefox"]),
        ("chrome", artifacts["chrome"]),
        ("edge", artifacts["edge"]),
        ("brave", artifacts["brave"]),
    ]:
        for db_path in db_list:
            username = _extract_username_from_path(db_path)
            if username and username in profiles:
                profiles[username]["browser_databases"].append({
                    "browser": browser_type,
                    "path": db_path,
                })

    return list(profiles.values())


def _extract_username_from_path(path: str) -> str:
    try:
        parts = Path(path).parts
        users_idx = next(i for i, p in enumerate(parts) if p.lower() == "users")
        return parts[users_idx + 1]
    except (StopIteration, IndexError):
        return None


def validate_artifacts(artifacts: Dict[str, Any]) -> Dict[str, str]:
    """Check how many of the discovered artifact paths are actually readable."""
    validation = {}

    readable_ntuser = sum(1 for _, p in artifacts["ntuser_dat"] if Path(p).exists())
    validation["ntuser_dat"] = f"{readable_ntuser}/{len(artifacts['ntuser_dat'])} readable"

    all_browser = (
        artifacts["tor_browser"] + artifacts["firefox"]
        + artifacts["chrome"] + artifacts["edge"] + artifacts["brave"]
    )
    readable_browser = sum(1 for p in all_browser if Path(p).exists())
    validation["browser_databases"] = f"{readable_browser}/{len(all_browser)} readable"

    readable_pf = sum(1 for p in artifacts["prefetch"] if Path(p).exists())
    validation["prefetch"] = f"{readable_pf}/{len(artifacts['prefetch'])} readable"

    readable_evtx = sum(1 for p in artifacts["evtx"] if Path(p).exists())
    validation["evtx"] = f"{readable_evtx}/{len(artifacts['evtx'])} readable"

    return validation


def print_discovery_report(artifacts: Dict[str, Any]):
    """Print a human-readable summary of what was found."""
    print("\n" + "=" * 70)
    print("ARTIFACT DISCOVERY REPORT")
    print("=" * 70)

    print(f"\nUser Profiles ({len(artifacts['ntuser_dat'])} found):")
    for username, path in artifacts["ntuser_dat"]:
        print(f"  {username}: {path}")

    print(f"\nTor Browser ({len(artifacts['tor_browser'])} found):")
    for path in artifacts["tor_browser"]:
        print(f"  {path}")

    print(f"\nFirefox ({len(artifacts['firefox'])} found):")
    for path in artifacts["firefox"]:
        print(f"  {path}")

    chromium_total = len(artifacts["chrome"]) + len(artifacts["edge"]) + len(artifacts["brave"])
    print(f"\nChromium-based Browsers ({chromium_total} found):")
    for browser, key in [("Chrome", "chrome"), ("Edge", "edge"), ("Brave", "brave")]:
        for path in artifacts[key]:
            print(f"  {browser}: {path}")

    print(f"\nPrefetch Files ({len(artifacts['prefetch'])} found):")
    for path in artifacts["prefetch"]:
        print(f"  {path}")

    print(f"\nEvent Logs ({len(artifacts['evtx'])} found):")
    for path in artifacts["evtx"]:
        print(f"  {path}")

    print(f"\nJump List Directories ({len(artifacts.get('jump_lists', []))} found):")
    for path in artifacts.get("jump_lists", []):
        print(f"  {path}")

    print("\n" + "=" * 70)
