"""Default artifact paths and configuration constants.

Paths are for a typical Windows 10/11 installation.
Use --mount to point at a mounted disk image instead.
"""

import os
from pathlib import Path
from typing import Dict, List


DEFAULT_USER_PROFILE = os.environ.get("USERPROFILE", "C:\\Users\\YourUsername")

NTUSER_DAT_PATH = os.path.join(DEFAULT_USER_PROFILE, "NTUSER.DAT")
SYSTEM_HIVE_PATH = "C:\\Windows\\System32\\config\\SYSTEM"

TOR_BROWSER_PATHS = [
    os.path.join(DEFAULT_USER_PROFILE, "Desktop\\Tor Browser"),
    os.path.join(DEFAULT_USER_PROFILE, "AppData\\Local\\Tor Browser"),
    os.path.join(DEFAULT_USER_PROFILE, "Downloads\\Tor Browser"),
    "C:\\Program Files\\Tor Browser",
]


def get_tor_profile_path() -> str:
    """Try to find places.sqlite across the common Tor Browser install locations."""
    for base_path in TOR_BROWSER_PATHS:
        profile_dir = os.path.join(
            base_path,
            "Browser\\TorBrowser\\Data\\Browser\\profile.default",
        )
        if Path(profile_dir).exists():
            return os.path.join(profile_dir, "places.sqlite")
    return ""


PREFETCH_DIR = "C:\\Windows\\Prefetch"
SECURITY_EVTX_PATH = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
SYSTEM_EVTX_PATH = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"

OUTPUT_DIR = Path("./output")
OUTPUT_FORMATS = ["json", "csv"]
DEFAULT_OUTPUT_NAME = "timeline"

EXTRACTORS_ENABLED = {
    "userassist": True,
    "prefetch": True,
    "places_sqlite": True,
    "places_wal": True,
    "evtx": True,
}

# How close two timestamps need to be (seconds) to treat them as the same event
TEMPORAL_BUCKET_SECONDS = 300
TIMESTAMP_ALIGNMENT_TOLERANCE = 60

MIN_CONFIDENCE_LEVEL = None

TOR_EXECUTABLES = [
    "tor.exe",
    "firefox.exe",
    "start tor browser.exe",
]

ONION_DOMAIN_PATTERN = r"[a-z0-9]{16,56}\.onion"

KNOWN_ONION_SITES = [
    "3g2upl4pq6kufc4m.onion",
    "thehiddenwiki.onion",
    "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
]

LOG_LEVEL = "INFO"
LOG_FILE = "collection.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

EXTRACTOR_TIMEOUT_REGISTRY = 15.0
EXTRACTOR_TIMEOUT_SQLITE = 30.0
EXTRACTOR_TIMEOUT_WAL = 30.0
EXTRACTOR_TIMEOUT_PREFETCH = 10.0
EXTRACTOR_TIMEOUT_EVTX = 60.0

SQLITE_BATCH_SIZE = 1000
MAX_WAL_SIZE = 100 * 1024 * 1024
MAX_REGISTRY_SIZE = 500 * 1024 * 1024

CORRELATION_TIME_BUCKET_SECONDS = 300
CORRELATION_TIMESTAMP_TOLERANCE = 60

TOOL_VERSION = "1.0.0"

DEMO_MODE = False


def get_artifact_paths() -> Dict[str, str]:
    """Return default artifact paths for the current user profile."""
    return {
        "ntuser_dat": NTUSER_DAT_PATH,
        "system_hive": SYSTEM_HIVE_PATH,
        "places_sqlite": get_tor_profile_path(),
        "prefetch_dir": PREFETCH_DIR,
        "security_evtx": SECURITY_EVTX_PATH,
    }


def validate_artifact_paths() -> Dict[str, bool]:
    """Check which of the default artifact paths actually exist on disk."""
    paths = get_artifact_paths()
    return {
        artifact: Path(path).exists()
        for artifact, path in paths.items()
        if path
    }


def create_output_directory():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
