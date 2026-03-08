"""
Windows Event Log extractor — pulls process creation events (Event ID 4688).

Event ID 4688 requires the "Audit Process Creation" policy to be enabled.
It records the full executable path, PID, parent process, and (optionally)
the command line, making it the most authoritative execution evidence available.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
import xml.etree.ElementTree as ET

from ..logging_utils import extractor, log_extraction_context

logger = logging.getLogger(__name__)

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


@extractor("EVTX", timeout=60.0, required_extensions=[".evtx", ".EVTX"])
def extract_evtx(evtx_path: str, event_id: int = 4688, filter_tor: bool = True) -> List[Dict[str, Any]]:
    """
    Extract process creation events from a Security.evtx file.

    Returns dicts with: event_id, timestamp, process_name, process_id,
    parent_process, command_line, user_account, evtx_path.

    Set filter_tor=False to return all process creation events.
    """
    if not EVTX_AVAILABLE:
        logger.error("python-evtx not installed. Cannot parse EVTX files.")
        return []

    results = []

    try:
        log_extraction_context("EVTX", evtx_path)

        with evtx.Evtx(evtx_path) as log:
            record_count = 0

            for record in log.records():
                record_count += 1
                if record_count % 10000 == 0:
                    logger.debug(f"Processed {record_count} records, {len(results)} matches so far")

                try:
                    root = ET.fromstring(record.xml())

                    event_id_elem = root.find(".//{*}EventID")
                    if event_id_elem is None:
                        continue
                    try:
                        current_event_id = int(event_id_elem.text)
                    except (ValueError, TypeError):
                        continue

                    if current_event_id != event_id:
                        continue

                    timestamp_elem = root.find(".//{*}TimeCreated")
                    timestamp = (
                        timestamp_elem.get("SystemTime", "") if timestamp_elem is not None else ""
                    )

                    def get_data(name: str) -> str:
                        elem = root.find(f".//*[@Name='{name}']")
                        return elem.text if elem is not None else None

                    process_name = get_data("NewProcessName")
                    if not process_name:
                        continue

                    if filter_tor:
                        if not any(kw in process_name.lower() for kw in ("tor", "firefox", "browser")):
                            continue

                    subject_user = root.find(".//{*}Data[@Name='SubjectUserName']")
                    subject_domain = root.find(".//{*}Data[@Name='SubjectDomainName']")
                    user_account = None
                    if subject_user is not None and subject_domain is not None:
                        user_account = f"{subject_domain.text}\\{subject_user.text}"

                    results.append({
                        "event_id": current_event_id,
                        "timestamp": timestamp,
                        "process_name": process_name,
                        "process_id": get_data("NewProcessId"),
                        "parent_process": get_data("ParentProcessName"),
                        "command_line": get_data("CommandLine"),
                        "user_account": user_account,
                        "evtx_path": evtx_path,
                    })

                except ET.ParseError as e:
                    logger.debug(f"XML parse error: {e}")
                    continue
                except Exception as e:
                    logger.debug(f"Error processing record: {e}")
                    continue

            logger.debug(
                f"Processed {record_count} EVTX records, extracted {len(results)} Tor-related events"
            )

    except OSError as e:
        if "denied" in str(e).lower():
            logger.error(f"Permission denied reading EVTX (requires admin): {evtx_path}")
        else:
            logger.error(f"OS error reading EVTX: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error parsing {evtx_path}: {type(e).__name__}: {e}")
        return []

    return results


def is_audit_policy_enabled() -> bool:
    """Check if process creation auditing is enabled. Not yet implemented."""
    logger.warning("Audit policy check not implemented")
    return False


def extract_process_termination(evtx_path: str) -> List[Dict[str, Any]]:
    """Extract Event ID 4689 (process termination). Not yet implemented."""
    logger.warning("Process termination extraction not implemented")
    return []


def generate_mock_evtx() -> List[Dict[str, Any]]:
    """Generate mock Event ID 4688 records for demo mode.

    Includes background noise (notepad, chrome) so the Tor filter is exercised.
    Timestamps match the Prefetch most-recent entry (2024-12-15 14:32 UTC).
    """
    evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
    return [
        # Background noise — filtered by normalize_evtx / is_tor_related()
        {
            "event_id": 4688,
            "timestamp": "2024-12-15T09:15:30.456Z",
            "process_name": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "process_id": 4112,
            "parent_process": "C:\\Windows\\explorer.exe",
            "command_line": "chrome.exe",
            "user_account": "DESKTOP-ABC123\\Alice",
            "evtx_path": evtx_path,
        },
        {
            "event_id": 4688,
            "timestamp": "2024-12-15T14:31:02.001Z",
            "process_name": "C:\\Windows\\System32\\notepad.exe",
            "process_id": 5280,
            "parent_process": "C:\\Windows\\explorer.exe",
            "command_line": "notepad.exe",
            "user_account": "DESKTOP-ABC123\\Alice",
            "evtx_path": evtx_path,
        },
        # Tor Browser processes — corroborates Prefetch and UserAssist
        {
            "event_id": 4688,
            "timestamp": "2024-12-15T14:32:15.123Z",
            "process_name": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "process_id": 5432,
            "parent_process": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Start Tor Browser.exe",
            "command_line": "tor.exe --defaults-torrc torrc-defaults -f torrc",
            "user_account": "DESKTOP-ABC123\\Alice",
            "evtx_path": evtx_path,
        },
        {
            "event_id": 4688,
            "timestamp": "2024-12-15T14:32:20.456Z",
            "process_name": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Browser\\firefox.exe",
            "process_id": 5436,
            "parent_process": "C:\\Users\\Alice\\Desktop\\Tor Browser\\Start Tor Browser.exe",
            "command_line": 'firefox.exe -profile "TorBrowser\\Data\\Browser\\profile.default"',
            "user_account": "DESKTOP-ABC123\\Alice",
            "evtx_path": evtx_path,
        },
    ]
