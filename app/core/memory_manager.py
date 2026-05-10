# app/core/memory_manager.py
"""
Memory usage monitoring and optimisation.

Runs a background thread that periodically checks RSS memory usage and
triggers garbage collection when usage exceeds the configured threshold.
"""
import gc
import os
import threading
import time
from typing import Optional, Callable

from app.core.logger import logger

# Default threshold: warn at 500 MB, trigger GC at 750 MB
_WARN_MB = 500
_GC_MB = 750
_CHECK_INTERVAL_SECONDS = 30


def _get_rss_mb() -> float:
    """Return current process RSS memory in megabytes."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except ImportError:
        # psutil not available — fall back to resource module (Unix only)
        try:
            import resource
            # getrusage returns KB on Linux, bytes on macOS
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # Linux: KB; macOS: bytes
            if os.uname().sysname == 'Darwin':
                return usage / (1024 * 1024)
            return usage / 1024
        except Exception:
            return 0.0


class MemoryManager:
    """Monitors process memory and triggers GC when usage is high.

    Usage::

        from app.core.memory_manager import memory_manager
        memory_manager.start_monitoring()   # called once at startup
        # ...
        memory_manager.stop_monitoring()    # called at shutdown
    """

    def __init__(
        self,
        warn_mb: float = _WARN_MB,
        gc_mb: float = _GC_MB,
        interval: float = _CHECK_INTERVAL_SECONDS,
    ):
        self.warn_mb = warn_mb
        self.gc_mb = gc_mb
        self.interval = interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._callback: Optional[Callable[[float], None]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_monitoring(self, callback: Optional[Callable[[float], None]] = None):
        """Start the background monitoring thread.

        Args:
            callback: Optional callable that receives the current RSS (MB)
                      on each check.  Useful for updating a status-bar widget.
        """
        if self._thread and self._thread.is_alive():
            return  # Already running

        self._callback = callback
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="MemoryMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.debug("Memory monitoring started")

    def stop_monitoring(self):
        """Stop the background monitoring thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.debug("Memory monitoring stopped")

    def get_memory_usage(self) -> float:
        """Return current RSS memory usage in MB."""
        return _get_rss_mb()

    def optimize_memory(self):
        """Force a full garbage collection cycle."""
        before = _get_rss_mb()
        gc.collect()
        after = _get_rss_mb()
        freed = max(0.0, before - after)
        logger.info(
            f"Memory optimisation: {before:.1f} MB → {after:.1f} MB "
            f"(freed ~{freed:.1f} MB)"
        )
        return after

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        while not self._stop_event.wait(timeout=self.interval):
            try:
                rss = _get_rss_mb()

                if self._callback:
                    try:
                        self._callback(rss)
                    except Exception as e:
                        logger.debug(f"Memory callback error: {e}")

                if rss >= self.gc_mb:
                    logger.warning(
                        f"Memory usage {rss:.1f} MB exceeds GC threshold "
                        f"({self.gc_mb} MB) — running garbage collection"
                    )
                    self.optimize_memory()
                elif rss >= self.warn_mb:
                    logger.warning(
                        f"Memory usage {rss:.1f} MB exceeds warning threshold "
                        f"({self.warn_mb} MB)"
                    )

            except Exception as e:
                logger.debug(f"Memory monitor error: {e}", exc_info=True)


# Global instance
memory_manager = MemoryManager()
