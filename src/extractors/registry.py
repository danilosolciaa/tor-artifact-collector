"""
NTUSER.DAT extractor — pulls UserAssist entries via the yarp library.

UserAssist tracks GUI application launches. Paths are ROT13-encoded,
and the binary value holds run count + last execution time as a FILETIME.
The data survives application uninstallation, which makes it valuable.
"""

import logging
from typing import List, Dict, Any
import codecs
import struct

from ..logging_utils import extractor, log_extraction_context

logger = logging.getLogger(__name__)

try:
    from yarp import Registry
    YARP_AVAILABLE = True
except ImportError:
    YARP_AVAILABLE = False


@extractor("NTUSER.DAT Registry", timeout=15.0, required_extensions=[".dat", ".DAT"])
def extract_userassist(hive_path: str) -> List[Dict[str, Any]]:
    """
    Extract UserAssist entries from NTUSER.DAT.

    Returns a list of dicts with:
      encoded_name  - ROT13-encoded executable path
      run_count     - number of executions
      last_execution - last run time as a Windows FILETIME integer
      focus_time    - total focus time in milliseconds
      hive_path     - source file
      registry_path - full registry key path

    Binary value layout (Win7+):
      Offset 0-3:   version (always 0x00000005)
      Offset 4-7:   run count (DWORD, subtract 5 to get real count)
      Offset 8-11:  focus time in ms (DWORD)
      Offset 60-67: last execution FILETIME (64-bit)
    """
    if not YARP_AVAILABLE:
        logger.error("yarp not installed. Cannot extract UserAssist.")
        return []

    results = []

    try:
        log_extraction_context("NTUSER.DAT", hive_path)
        reg = Registry(hive_path)

        # Windows creates two UserAssist GUIDs by default
        userassist_guids = [
            "CEBFF5CD-ACE2-4F4F-9178-9926F41749EA",
            "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F",
        ]

        for guid in userassist_guids:
            try:
                key_path = (
                    f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                    f"\\UserAssist\\{{{guid}}}\\Count"
                )
                key = reg.open(key_path)

                for value in key.values():
                    try:
                        value_name = value.name()
                        value_data = value.data()

                        if not value_data or not isinstance(value_data, bytes):
                            continue
                        if len(value_data) < 68:
                            continue

                        run_count = int.from_bytes(value_data[4:8], byteorder="little")
                        # Windows 7+ adds 5 to the count as minor obfuscation
                        if run_count > 5:
                            run_count -= 5

                        filetime = int.from_bytes(value_data[60:68], byteorder="little")
                        focus_time = int.from_bytes(value_data[8:12], byteorder="little")

                        if filetime == 0 or run_count == 0:
                            continue

                        results.append({
                            "encoded_name": value_name,
                            "run_count": run_count,
                            "last_execution": filetime,
                            "focus_time": focus_time,
                            "hive_path": hive_path,
                            "registry_path": f"HKEY_CURRENT_USER\\{key_path}",
                        })

                    except (ValueError, IndexError, struct.error) as e:
                        logger.debug(f"Binary parse error for {value_name}: {e}")
                        continue
                    except UnicodeDecodeError as e:
                        logger.debug(f"Unicode error on value name: {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error parsing UserAssist value: {e}")
                        continue

            except Exception as e:
                logger.debug(f"UserAssist key for GUID {guid} not accessible: {e}")
                continue

        logger.debug(f"Extracted {len(results)} UserAssist entries from {hive_path}")

    except Exception as e:
        logger.error(f"Failed to parse registry hive {hive_path}: {type(e).__name__}: {e}")
        return []

    return results


def extract_userassist_live() -> List[Dict[str, Any]]:
    """
    Extract UserAssist directly from the live Windows registry using winreg.

    NTUSER.DAT is exclusively locked by Windows while the user is logged in,
    so the yarp-based extractor only works on offline forensic images. This
    function reads the same data via the winreg stdlib module — no elevation
    needed, no file access, works on any live Windows system.

    Returns the same dict format as extract_userassist().
    """
    try:
        import winreg
    except ImportError:
        logger.error("winreg not available (not running on Windows)")
        return []

    results = []
    guids = [
        "CEBFF5CD-ACE2-4F4F-9178-9926F41749EA",
        "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F",
    ]

    for guid in guids:
        key_path = (
            rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            rf"\UserAssist\{{{guid}}}\Count"
        )
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        except FileNotFoundError:
            logger.debug(f"UserAssist key not found: {guid}")
            continue
        except Exception as e:
            logger.debug(f"Cannot open UserAssist key {guid}: {e}")
            continue

        i = 0
        while True:
            try:
                name, data, dtype = winreg.EnumValue(key, i)
                i += 1

                # dtype 3 = REG_BINARY; binary value layout same as in extract_userassist
                if dtype != 3 or not isinstance(data, bytes) or len(data) < 68:
                    continue

                run_count = int.from_bytes(data[4:8], byteorder="little")
                if run_count > 5:
                    run_count -= 5

                filetime = int.from_bytes(data[60:68], byteorder="little")
                focus_time = int.from_bytes(data[8:12], byteorder="little")

                if filetime == 0 or run_count == 0:
                    continue

                results.append({
                    "encoded_name": name,
                    "run_count": run_count,
                    "last_execution": filetime,
                    "focus_time": focus_time,
                    "hive_path": "LIVE:HKCU",
                    "registry_path": f"HKEY_CURRENT_USER\\{key_path}",
                })

            except OSError:
                break  # no more values
            except Exception as e:
                logger.debug(f"Error reading UserAssist value at index {i}: {e}")
                i += 1
                continue

        winreg.CloseKey(key)

    logger.debug(f"Live winreg: extracted {len(results)} UserAssist entries")
    return results


def extract_shimcache(system_hive_path: str) -> List[Dict[str, Any]]:
    """
    Extract ShimCache (AppCompat Cache) from the SYSTEM hive.

    Not yet implemented — requires parsing a complex binary structure that
    differs between Windows versions. Needs the SYSTEM hive, not NTUSER.DAT.
    """
    logger.warning("ShimCache extraction not yet implemented (requires SYSTEM hive)")
    return []


def extract_shellbags(hive_path: str) -> List[Dict[str, Any]]:
    """
    Extract ShellBags from NTUSER.DAT (folder access history).

    Not yet implemented — ShellItem binary structures are complex to parse
    and the MRU chain reconstruction needs dedicated tooling.
    """
    logger.warning("ShellBags extraction not yet implemented")
    return []


def generate_mock_userassist() -> List[Dict[str, Any]]:
    """Generate mock UserAssist entries for demo/testing (no real NTUSER.DAT needed)."""
    def rot13(s: str) -> str:
        return codecs.encode(s, "rot_13")

    # UserAssist records shortcut (.lnk) launches, not direct .exe invocations.
    # base_filetime ≈ 2024-12-15 14:32:00 UTC
    base_filetime = 133787467200000000
    one_day = 864000000000  # 100-ns intervals

    registry_path = (
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count"
    )

    # (encoded_path, run_count, last_execution, focus_time_ms)
    entries = [
        # Tor Browser shortcuts
        (rot13("C:\\Users\\Alice\\Desktop\\Tor Browser.lnk"),
         15, base_filetime, 300000),
        (rot13("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Tor Browser.lnk"),
         8, base_filetime - 2 * one_day, 180000),
        # Background noise — filtered out by is_tor_related()
        (rot13("C:\\Windows\\System32\\notepad.exe"),
         3, base_filetime - 5 * one_day, 15000),
        (rot13("%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe"),
         42, base_filetime - one_day, 450000),
    ]

    return [
        {
            "encoded_name": encoded_name,
            "run_count": run_count,
            "last_execution": last_execution,
            "focus_time": focus_time,
            "hive_path": "C:\\Users\\Alice\\NTUSER.DAT",
            "registry_path": registry_path,
        }
        for encoded_name, run_count, last_execution, focus_time in entries
    ]
