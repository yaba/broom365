"""The configuration in effect for the current request: environment defaults overridden by what was saved in Settings."""
from __future__ import annotations

import dataclasses

from flask import current_app, g, has_request_context

from .config import Config
from .db import get_db
from .services import appconfig


def credentials() -> appconfig.Credentials:
    """Tenant, client id and client secret in effect (database first, then environment), read once per request."""
    if has_request_context() and "creds" in g:
        return g.creds  # type: ignore[no-any-return]
    cfg: Config = current_app.config["BROOM_CONFIG"]
    env = appconfig.Credentials(cfg.tenant_id, cfg.client_id, cfg.client_secret)
    creds = env if current_app.config.get("DEMO") else appconfig.load_credentials(get_db(), env)
    if has_request_context():
        g.creds = creds
    return creds


def effective_config() -> Config:
    cfg: Config = current_app.config["BROOM_CONFIG"]
    c = credentials()
    return dataclasses.replace(cfg, tenant_id=c.tenant_id, client_id=c.client_id, client_secret=c.client_secret)
