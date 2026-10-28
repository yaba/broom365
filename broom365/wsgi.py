"""Entry point for the production server: `gunicorn broom365.wsgi:application`.

It serves the installer while Broom365 does not know where its data lives (or cannot reach it) and the real application otherwise.
When the installer finishes, the real application is started in the same process, so no restart is needed.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Iterable

from . import bootstrap, create_app
from .installer import create_setup_app

log = logging.getLogger("broom365")


class Switch:
    """A WSGI application that is either the installer or the real application."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._app: Callable[..., Iterable[bytes]] | None = None

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        return self._current()(environ, start_response)

    def _current(self) -> Callable[..., Iterable[bytes]]:
        with self._lock:
            if self._app is None:
                self._app = self._build()
            return self._app

    def _build(self) -> Callable[..., Iterable[bytes]]:
        if bootstrap.needs_setup():
            return create_setup_app(self.rebuild)
        try:
            return create_app()
        except Exception as exc:  # noqa: BLE001 - whatever is wrong, the person must be able to fix it from the browser
            log.error("Broom365 could not start: %s", bootstrap.explain_db_error(exc))
            return create_setup_app(self.rebuild, error=f"Broom365 could not start: {bootstrap.explain_db_error(exc)}", repair=True)

    def rebuild(self) -> None:
        """Start the real application now (called by the installer after it saved the settings). Raises if it cannot start."""
        app = create_app()
        with self._lock:
            self._app = app


application = Switch()


if __name__ == "__main__":      # `python -m broom365.wsgi`: the same entry point with the development server
    import os

    from werkzeug.serving import run_simple

    run_simple(os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "5000")), application, use_reloader=False)
