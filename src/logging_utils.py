"""
Logging setup and the @extractor decorator used by all extractors.

The decorator handles file existence checks, timeout enforcement (Unix only),
and ensures that no single extractor can crash the whole collection run.
"""

import logging
import functools
import time
import signal
from typing import List, Dict, Any, Callable, Optional, TypeVar
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

T = TypeVar("T")


def setup_structured_logging(
    log_file: str = "collection.log",
    log_level: str = "INFO",
    console_output: bool = True,
) -> logging.Logger:
    """Configure logging with ISO 8601 timestamps and optional console output."""
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    handlers = [file_handler]
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        handlers.append(console_handler)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    for handler in handlers:
        root_logger.addHandler(handler)

    return root_logger


class _ExtractorTimeout(Exception):
    """Raised when an extractor exceeds its time limit."""
    pass


def _timeout_signal_handler(signum, frame):
    raise _ExtractorTimeout("Extractor timed out")


def with_timeout(seconds: float) -> Callable:
    """
    Decorator that enforces a maximum execution time via SIGALRM.

    Only works on Unix/Linux. On Windows this is a no-op since SIGALRM
    isn't available — the function just runs without a timeout.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if hasattr(signal, "SIGALRM"):
                old_handler = signal.signal(signal.SIGALRM, _timeout_signal_handler)
                signal.alarm(int(seconds))
                try:
                    return func(*args, **kwargs)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


def extractor(
    artifact_type: str,
    timeout: float = 30.0,
    required_extensions: Optional[List[str]] = None,
) -> Callable:
    """
    Decorator for all forensic artifact extractors.

    Handles:
    - File existence and empty-file checks before calling the function
    - Optional file extension validation (warns but continues if wrong)
    - Timeout enforcement (Unix only)
    - Catches all exceptions so one bad artifact can't abort the run
    - Validates that the function returns a list
    """
    def decorator(func: Callable[..., List[Dict[str, Any]]]) -> Callable[..., List[Dict[str, Any]]]:
        @functools.wraps(func)
        def wrapper(path: str, *args, **kwargs) -> List[Dict[str, Any]]:
            start_time = time.time()

            if not Path(path).exists():
                logger.warning(f"{artifact_type} not found at {path}")
                return []

            try:
                file_size = Path(path).stat().st_size
                if file_size == 0:
                    logger.warning(f"{artifact_type} is empty (0 bytes): {path}")
                    return []
            except OSError as e:
                logger.warning(f"Cannot stat {artifact_type} at {path}: {e}")
                return []

            if required_extensions:
                ext = Path(path).suffix.lower()
                if ext not in required_extensions:
                    logger.warning(f"{artifact_type} has unexpected extension {ext}: {path}")

            try:
                if hasattr(signal, "SIGALRM"):
                    @with_timeout(timeout)
                    def timed_func():
                        return func(path, *args, **kwargs)
                    result = timed_func()
                else:
                    result = func(path, *args, **kwargs)

                if not isinstance(result, list):
                    logger.error(f"{func.__name__} returned {type(result)} instead of list")
                    return []

                elapsed = time.time() - start_time
                logger.info(f"Extracted {len(result)} records from {artifact_type} in {elapsed:.2f}s")
                return result

            except _ExtractorTimeout:
                logger.error(f"{artifact_type} extraction timed out after {timeout}s: {path}")
                return []
            except PermissionError as e:
                logger.error(f"Permission denied accessing {artifact_type}: {path} - {e}")
                return []
            except OSError as e:
                logger.error(f"OS error reading {artifact_type}: {path} - {e}")
                return []
            except UnicodeDecodeError as e:
                logger.error(f"Encoding error in {artifact_type}: {path} - {e}")
                return []
            except Exception as e:
                logger.error(
                    f"Unexpected error extracting {artifact_type} from {path}: "
                    f"{type(e).__name__}: {e}",
                    exc_info=True,
                )
                return []

        return wrapper
    return decorator


class PerformanceMetrics:
    """Tracks timing and record counts per extractor for profiling."""

    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = {}

    def record(self, operation: str, duration: float, record_count: int):
        if operation not in self.metrics:
            self.metrics[operation] = {
                "total_duration": 0.0,
                "total_records": 0,
                "call_count": 0,
                "min_duration": float("inf"),
                "max_duration": 0.0,
            }
        m = self.metrics[operation]
        m["total_duration"] += duration
        m["total_records"] += record_count
        m["call_count"] += 1
        m["min_duration"] = min(m["min_duration"], duration)
        m["max_duration"] = max(m["max_duration"], duration)

    def get_summary(self) -> Dict[str, Any]:
        summary = {}
        for op, m in self.metrics.items():
            calls = m["call_count"]
            summary[op] = {
                "total_duration_seconds": round(m["total_duration"], 2),
                "total_records": m["total_records"],
                "call_count": calls,
                "avg_duration_seconds": round(m["total_duration"] / calls, 2) if calls else 0,
                "avg_records_per_call": round(m["total_records"] / calls, 1) if calls else 0,
                "min_duration_seconds": round(m["min_duration"], 2),
                "max_duration_seconds": round(m["max_duration"], 2),
            }
        return summary

    def log_summary(self):
        for op, stats in self.get_summary().items():
            logger.info(
                f"{op}: {stats['total_duration_seconds']}s total, "
                f"{stats['total_records']} records, "
                f"{stats['avg_duration_seconds']}s avg"
            )


performance_metrics = PerformanceMetrics()


def log_extraction_context(
    artifact_type: str,
    path: str,
    additional_info: Optional[Dict[str, Any]] = None,
):
    context = {
        "artifact_type": artifact_type,
        "path": path,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file_size": Path(path).stat().st_size if Path(path).exists() else 0,
    }
    if additional_info:
        context.update(additional_info)
    logger.debug(f"Extraction context: {context}")


def safe_read_file(
    path: str,
    mode: str = "rb",
    max_size: Optional[int] = None,
    chunk_size: int = 8192,
) -> Optional[bytes]:
    """
    Read a file with an optional size limit.

    For small files, reads in one shot. For larger ones, reads in chunks
    so we don't load multi-hundred-MB artifacts into memory at once.
    """
    try:
        file_size = Path(path).stat().st_size

        if max_size and file_size > max_size:
            logger.warning(f"File exceeds max size ({file_size} > {max_size}): {path}")
            return None

        if file_size < chunk_size * 10:
            with open(path, mode) as f:
                return f.read()

        data = bytearray()
        with open(path, mode) as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                data.extend(chunk)
                if max_size and len(data) > max_size:
                    logger.warning(f"File exceeded max size during read: {path}")
                    return None
        return bytes(data)

    except Exception as e:
        logger.error(f"Error reading file {path}: {e}")
        return None
