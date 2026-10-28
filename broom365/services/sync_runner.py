"""Runs a sync job (inventory or scan) on a background thread. One job at a time."""
from __future__ import annotations

import threading
from typing import Any, Callable

_lock = threading.Lock()


def is_running() -> bool:
    return _lock.locked()


def start_job(connect: Callable[[], Any], job: Callable[[Any], object]) -> bool:
    """Run `job(conn)` on a thread with its own connection. Returns False if a job is already running."""
    if not _lock.acquire(blocking=False):
        return False

    def work() -> None:
        conn = connect()
        try:
            job(conn)
        except Exception:  # the harness already recorded the failure on the sync_runs row
            pass
        finally:
            conn.close()
            _lock.release()

    threading.Thread(target=work, name="broom365-sync", daemon=True).start()
    return True
