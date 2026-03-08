"""
Test Suite for Tor Forensic Collector

This package contains unit tests for all modules using pytest.

Test Coverage:
- models.py: Data structure validation
- normalizers.py: Source-specific conversion logic
- correlation.py: Deduplication and confidence scoring
- extractors: Mock data generation and parsing
- cli.py: Command-line interface behavior

Run tests:
    pytest
    pytest --cov=src --cov-report=html
    pytest -v tests/test_normalizers.py
"""
