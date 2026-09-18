"""Runtime dependency loading, file-descriptor limits, and event-loop noise filtering."""

from __future__ import annotations

import asyncio
import importlib
import os
import subprocess
import sys
from typing import Optional

# 3.10 is the real floor: aiohttp 3.14+ requires >=3.10, so 3.9 cannot even
# install this project's dependencies. CI proved it (py3.9 job failed).
MIN_PYTHON = (3, 10)


def python_version_ok() -> bool:
    return sys.version_info >= MIN_PYTHON


def _try_install(package: str) -> bool:
    """Attempt a normal install, then fall back to a --user install."""
    base = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--quiet",
    ]
    for command in (base + [package], base + ["--user", package]):
        try:
            subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            continue
    return False


def import_or_install(import_name: str, package_name: Optional[str] = None):
    """Import a dependency, installing it on first use if it is missing."""
    try:
        return importlib.import_module(import_name)
    except Exception:
        package = package_name or import_name
        print(f"Installing missing dependency: {package}", file=sys.stderr)
        if not _try_install(package):
            raise RuntimeError(
                f"Missing dependency '{package}' and auto-install failed. "
                f"Install it manually: pip install {package}"
            )
        return importlib.import_module(import_name)


def ensure_runtime_deps():
    """Load every network dependency once and hand them back to the caller."""
    aiohttp = import_or_install("aiohttp")
    python_socks_asyncio = import_or_install("python_socks.async_.asyncio", "python-socks")
    return aiohttp, python_socks_asyncio


def maybe_raise_nofile_limit(expected_connections: int) -> None:
    """Raise the descriptor ceiling on POSIX so high worker counts do not fail."""
    try:
        import resource
    except Exception:
        return  # Windows has no RLIMIT_NOFILE; the default handle count is ample.

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY:
            target = max(soft, min(65535, expected_connections * 3 + 1024))
        else:
            target = min(hard, max(soft, expected_connections * 3 + 1024))
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        return


def connector_cleanup_closed_enabled() -> bool:
    """aiohttp's cleanup_closed thread is itself the source of the noise on Windows."""
    return os.name != "nt"


def _is_benign_windows_proactor_reset(context: dict) -> bool:
    if os.name != "nt":
        return False
    exc = context.get("exception")
    if not isinstance(exc, ConnectionResetError):
        return False
    if getattr(exc, "winerror", None) != 10054:
        return False
    message = str(context.get("message") or "")
    handle = context.get("handle")
    handle_repr = repr(handle) if handle is not None else ""
    return "_ProactorBasePipeTransport._call_connection_lost" in f"{message} {handle_repr}"


def _is_benign_windows_overlapped_cancel(context: dict) -> bool:
    if os.name != "nt":
        return False
    if "Cancelling an overlapped future failed" not in str(context.get("message") or ""):
        return False
    exc = context.get("exception")
    if not isinstance(exc, OSError):
        return False
    return getattr(exc, "winerror", None) in {6, 10038}


def install_asyncio_exception_filter() -> None:
    """Silence two harmless Windows transport warnings without hiding real errors."""
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()

    def handler(loop_obj, context):
        if _is_benign_windows_proactor_reset(context) or _is_benign_windows_overlapped_cancel(context):
            return
        if previous_handler is not None:
            previous_handler(loop_obj, context)
        else:
            loop_obj.default_exception_handler(context)

    loop.set_exception_handler(handler)
