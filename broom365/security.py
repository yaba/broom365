"""Minimal CSRF protection for state-changing requests.

A per-session token is exposed to templates as `csrf_token()`. Every POST/PUT/PATCH/DELETE
must send it back, as the `X-CSRF-Token` header (fetch) or a `csrf_token` form field.
"""
from __future__ import annotations

import hmac
import secrets

from flask import Flask, abort, request, session

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def csrf_token() -> str:
    """The current session's token, created on first use."""
    token = session.get("_csrf")
    if not token:
        token = session["_csrf"] = secrets.token_urlsafe(32)
    return str(token)


def register_csrf(app: Flask) -> None:
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def _check_csrf() -> None:
        if request.method in _SAFE_METHODS:
            return
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
        stored = str(session.get("_csrf", ""))
        # An empty stored token must never match an empty submitted one.
        if not stored or not hmac.compare_digest(sent, stored):
            abort(400, "Missing or invalid CSRF token")
