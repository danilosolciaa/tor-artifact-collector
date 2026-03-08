"""
Unit Tests for registry.py — extract_userassist_live()

Tests the live winreg extraction path using mocked winreg calls.
No real registry access is required.
"""

import codecs
import struct
import pytest
from unittest import mock

from src.extractors.registry import extract_userassist_live


def _make_blob(run_count: int, filetime: int, focus_time_ms: int = 0) -> bytes:
    """
    Build a valid UserAssist REG_BINARY blob (68 bytes).

    Layout (Win7+):
      Offset 4-7:   run count stored as (real_count + 5)
      Offset 8-11:  focus time in ms
      Offset 60-67: last execution FILETIME (little-endian 64-bit)
    """
    data = bytearray(68)
    data[4:8] = (run_count + 5).to_bytes(4, "little")
    data[8:12] = focus_time_ms.to_bytes(4, "little")
    data[60:68] = filetime.to_bytes(8, "little")
    return bytes(data)


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


# Reusable test data
_FILETIME = 133787467200000000  # 2024-12-15 14:32 UTC
_TOR_NAME = _rot13(r"C:\Users\Alice\Desktop\Tor Browser.lnk")
_NOISE_NAME = _rot13(r"C:\Windows\System32\notepad.exe")
_TOR_BLOB = _make_blob(15, _FILETIME, 300000)
_NOISE_BLOB = _make_blob(3, _FILETIME - 10 ** 9, 5000)


def _enum_side_effect(values):
    """
    Return a side_effect function for winreg.EnumValue.

    Yields items from `values` by index, then raises OSError to signal
    end-of-values (matching the real winreg behaviour).
    """
    def side_effect(key, index):
        if index < len(values):
            return values[index]
        raise OSError
    return side_effect


class TestExtractUserAssistLive:
    """Unit tests for extract_userassist_live()."""

    def test_returns_all_entries_for_both_guids(self):
        """Each GUID key contributes its entries independently."""
        values = [(_TOR_NAME, _TOR_BLOB, 3), (_NOISE_NAME, _NOISE_BLOB, 3)]

        with mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.EnumValue", side_effect=_enum_side_effect(values)), \
             mock.patch("winreg.CloseKey"):
            results = extract_userassist_live()

        # Two GUIDs × two values each = 4 entries (extractor returns all, no Tor filter)
        assert len(results) == 4

    def test_entry_fields_are_correct(self):
        """Returned dicts have the expected keys and correctly decoded values."""
        values = [(_TOR_NAME, _TOR_BLOB, 3)]

        with mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.EnumValue", side_effect=_enum_side_effect(values)), \
             mock.patch("winreg.CloseKey"):
            results = extract_userassist_live()

        assert len(results) >= 1
        entry = results[0]
        assert entry["encoded_name"] == _TOR_NAME
        assert entry["run_count"] == 15          # stored as 20, subtract 5
        assert entry["last_execution"] == _FILETIME
        assert entry["focus_time"] == 300000
        assert entry["hive_path"] == "LIVE:HKCU"
        assert "HKEY_CURRENT_USER" in entry["registry_path"]

    def test_key_not_found_returns_empty(self):
        """FileNotFoundError on OpenKey means the key doesn't exist — return []."""
        with mock.patch("winreg.OpenKey", side_effect=FileNotFoundError):
            results = extract_userassist_live()

        assert results == []

    def test_short_blob_is_skipped(self):
        """Values with fewer than 68 bytes of data are silently skipped."""
        short_blob = b"\x00" * 20
        values = [(_TOR_NAME, short_blob, 3)]

        with mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.EnumValue", side_effect=_enum_side_effect(values)), \
             mock.patch("winreg.CloseKey"):
            results = extract_userassist_live()

        assert results == []

    def test_zero_filetime_is_skipped(self):
        """Entries with filetime == 0 (no recorded execution time) are skipped."""
        blob = _make_blob(run_count=5, filetime=0)
        values = [(_TOR_NAME, blob, 3)]

        with mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.EnumValue", side_effect=_enum_side_effect(values)), \
             mock.patch("winreg.CloseKey"):
            results = extract_userassist_live()

        assert results == []

    def test_zero_run_count_is_skipped(self):
        """Entries where the raw stored run_count is 0 are skipped."""
        # The code subtracts 5 only when raw value > 5. A raw value of 0
        # stays at 0 and triggers the `run_count == 0` skip condition.
        data = bytearray(68)
        data[60:68] = _FILETIME.to_bytes(8, "little")  # valid filetime; run_count bytes stay 0
        blob = bytes(data)
        values = [(_TOR_NAME, blob, 3)]

        with mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.EnumValue", side_effect=_enum_side_effect(values)), \
             mock.patch("winreg.CloseKey"):
            results = extract_userassist_live()

        assert results == []

    def test_non_binary_dtype_is_skipped(self):
        """Only REG_BINARY (dtype 3) values are parsed; other types are skipped."""
        values = [(_TOR_NAME, _TOR_BLOB, 1)]  # dtype 1 = REG_SZ

        with mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.EnumValue", side_effect=_enum_side_effect(values)), \
             mock.patch("winreg.CloseKey"):
            results = extract_userassist_live()

        assert results == []
