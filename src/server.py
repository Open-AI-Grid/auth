"""Auth service application factory and runner."""

import logging
import os
import secrets

import yaml
from aiohttp import web

from .auth.jwt_handler import JWTHandler
from .auth.passkey import PasskeyHandler
from .auth.totp import TOTPHandler
from .handlers.auth_handlers import AuthHandlers
from .store.user_store import UserStore

logger = logging.getLogger(__name__)


def _load_config(config_path: str = None) -> dict:
    if not config_path:
        config_path = "config/default_config.yaml"
    try:
        with open(config_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


async def create_app(config_path: str = None) -> web.Application:
    cfg = _load_config(config_path)
    auth_cfg = cfg.get("auth", {})

    jwt_secret = (
        auth_cfg.get("jwt_secret")
        or os.environ.get("JWT_SECRET")
        or secrets.token_hex(32)
    )
    db_path = auth_cfg.get("db_path", "data/users.db")
    rp_id = auth_cfg.get("rp_id", "localhost")
    rp_name = auth_cfg.get("rp_name", "Open AI Grid")
    origin = auth_cfg.get("origin", "http://localhost:8800")

    store = UserStore(db_path=db_path)
    await store.initialize()

    handlers = AuthHandlers(
        store=store,
        jwt=JWTHandler(secret_key=jwt_secret),
        totp=TOTPHandler(),
        passkey=PasskeyHandler(rp_id=rp_id, rp_name=rp_name, origin=origin),
    )

    app = web.Application()
    app["config"] = auth_cfg
    app["passkey_challenges"] = {}  # swap for Redis in production
    handlers.setup_routes(app)
    return app


async def run_server(
    config_path: str = None, port: int = 8800
):
    app = await create_app(config_path)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", port)
    await site.start()
    logger.info("Auth service listening on localhost:%d", port)
    return runner, site
