"""HTTP handlers for the Open AI Grid Auth Service.

Endpoint map
------------
POST   /auth/register
POST   /auth/login
POST   /auth/refresh
GET    /auth/me

POST   /auth/mfa/setup           → returns TOTP secret + QR URI
POST   /auth/mfa/enable          → verifies first TOTP code and activates MFA
POST   /auth/mfa/verify          → completes MFA-gated login
POST   /auth/mfa/disable

POST   /auth/passkey/register/begin
POST   /auth/passkey/register/complete
POST   /auth/passkey/login/begin
POST   /auth/passkey/login/complete

GET    /auth/contributions        → own contribution stats
POST   /auth/contributions/record → called by node with task result
GET    /auth/leaderboard

GET    /health
"""

import dataclasses
import logging
from datetime import datetime

from aiohttp import web

from ..auth.jwt_handler import JWTHandler
from ..auth.passkey import PasskeyHandler
from ..auth.password import hash_password, verify_password
from ..auth.totp import TOTPHandler
from ..models.user import User
from ..store.user_store import UserStore

logger = logging.getLogger(__name__)

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _ok(data: dict, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, headers=_CORS)


def _err(msg: str, status: int = 400) -> web.Response:
    return web.json_response({"error": msg}, status=status, headers=_CORS)


class AuthHandlers:
    def __init__(
        self,
        store: UserStore,
        jwt: JWTHandler,
        totp: TOTPHandler,
        passkey: PasskeyHandler,
    ):
        self.store = store
        self.jwt = jwt
        self.totp = totp
        self.passkey = passkey

    # ── Auth helper ───────────────────────────────────────────────────────────

    async def _require_user(self, request: web.Request) -> User:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise web.HTTPUnauthorized(reason="Missing or invalid Authorization header")
        payload = self.jwt.verify_access_token(auth[7:])
        if not payload:
            raise web.HTTPUnauthorized(reason="Invalid or expired token")
        user = await self.store.get_by_id(payload["sub"])
        if not user or not user.is_active:
            raise web.HTTPUnauthorized(reason="User not found or inactive")
        return user

    # ── CORS preflight ────────────────────────────────────────────────────────

    async def options(self, _request: web.Request) -> web.Response:
        return web.Response(headers=_CORS)

    # ── Registration / Login ──────────────────────────────────────────────────

    async def register(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            username = (data.get("username") or "").strip()
            email = (data.get("email") or "").strip().lower()
            password = data.get("password") or ""

            if len(username) < 3:
                return _err("Username must be at least 3 characters")
            if "@" not in email:
                return _err("Valid email required")
            if len(password) < 8:
                return _err("Password must be at least 8 characters")

            if await self.store.get_by_username(username):
                return _err("Username already taken", 409)
            if await self.store.get_by_email(email):
                return _err("Email already registered", 409)

            user = User.create(username, email, hash_password(password))
            if not await self.store.create_user(user):
                return _err("Registration failed", 500)

            return _ok({"message": "Registration successful", "user_id": user.user_id}, 201)
        except Exception as exc:
            logger.error("register: %s", exc)
            return _err("Internal error", 500)

    async def login(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""

            user = await self.store.get_by_username(username)
            if not user or not verify_password(password, user.password_hash):
                return _err("Invalid credentials", 401)
            if not user.is_active:
                return _err("Account disabled", 403)

            if user.mfa_enabled:
                partial = self.jwt.create_partial_token(user.user_id)
                return _ok({"mfa_required": True, "partial_token": partial})

            return _ok(self._full_token_response(user))
        except Exception as exc:
            logger.error("login: %s", exc)
            return _err("Internal error", 500)

    async def refresh(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            payload = self.jwt.verify_refresh_token(data.get("refresh_token", ""))
            if not payload:
                return _err("Invalid refresh token", 401)
            user = await self.store.get_by_id(payload["sub"])
            if not user or not user.is_active:
                return _err("User not found", 401)
            return _ok(
                {
                    "access_token": self.jwt.create_access_token(user.user_id),
                    "token_type": "bearer",
                }
            )
        except Exception as exc:
            logger.error("refresh: %s", exc)
            return _err("Internal error", 500)

    async def me(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            return _ok(user.to_public_dict())
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("me: %s", exc)
            return _err("Internal error", 500)

    # ── MFA ───────────────────────────────────────────────────────────────────

    async def mfa_setup(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            if user.mfa_enabled:
                return _err("MFA already enabled")
            secret = self.totp.generate_secret()
            uri = self.totp.get_provisioning_uri(secret, user.username)
            user.mfa_secret = secret
            await self.store.update_user(user)
            return _ok(
                {
                    "secret": secret,
                    "qr_uri": uri,
                    "message": "Scan with your authenticator app, then call /auth/mfa/enable",
                }
            )
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("mfa_setup: %s", exc)
            return _err("Internal error", 500)

    async def mfa_enable(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            data = await request.json()
            if not user.mfa_secret:
                return _err("Call /auth/mfa/setup first")
            if not self.totp.verify(user.mfa_secret, str(data.get("code") or "")):
                return _err("Invalid TOTP code")
            user.mfa_enabled = True
            await self.store.update_user(user)
            return _ok({"message": "MFA enabled"})
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("mfa_enable: %s", exc)
            return _err("Internal error", 500)

    async def mfa_verify(self, request: web.Request) -> web.Response:
        """Complete an MFA-gated login using the partial token."""
        try:
            data = await request.json()
            payload = self.jwt.verify_partial_token(data.get("partial_token", ""))
            if not payload:
                return _err("Invalid or expired MFA session", 401)
            user = await self.store.get_by_id(payload["sub"])
            if not user or not user.mfa_secret:
                return _err("Invalid session", 401)
            if not self.totp.verify(user.mfa_secret, str(data.get("code") or "")):
                return _err("Invalid TOTP code")
            return _ok(self._full_token_response(user))
        except Exception as exc:
            logger.error("mfa_verify: %s", exc)
            return _err("Internal error", 500)

    async def mfa_disable(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            data = await request.json()
            if not user.mfa_enabled or not user.mfa_secret:
                return _err("MFA not enabled")
            if not self.totp.verify(user.mfa_secret, str(data.get("code") or "")):
                return _err("Invalid TOTP code")
            user.mfa_enabled = False
            user.mfa_secret = None
            await self.store.update_user(user)
            return _ok({"message": "MFA disabled"})
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("mfa_disable: %s", exc)
            return _err("Internal error", 500)

    # ── Passkeys ──────────────────────────────────────────────────────────────

    async def passkey_register_begin(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            options, challenge = self.passkey.generate_registration_options(user)
            request.app["passkey_challenges"][user.user_id] = challenge
            return _ok(options)
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("passkey_register_begin: %s", exc)
            return _err("Internal error", 500)

    async def passkey_register_complete(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            data = await request.json()
            challenge = request.app["passkey_challenges"].pop(user.user_id, None)
            if not challenge:
                return _err("No pending challenge – call /begin first")
            credential = self.passkey.verify_registration(data, challenge)
            if not credential:
                return _err("Passkey verification failed")
            name = (data.get("name") or f"Passkey {len(user.passkeys) + 1}")
            user.passkeys.append(
                {
                    **credential,
                    "name": name,
                    "created_at": datetime.utcnow().isoformat(),
                }
            )
            await self.store.update_user(user)
            return _ok({"message": "Passkey registered", "passkeys_count": len(user.passkeys)})
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("passkey_register_complete: %s", exc)
            return _err("Internal error", 500)

    async def passkey_login_begin(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            user = await self.store.get_by_username((data.get("username") or "").strip())
            if not user or not user.passkeys:
                return _err("No passkeys registered for that user")
            options, challenge = self.passkey.generate_authentication_options(user)
            request.app["passkey_challenges"][user.user_id] = challenge
            return _ok(options)
        except Exception as exc:
            logger.error("passkey_login_begin: %s", exc)
            return _err("Internal error", 500)

    async def passkey_login_complete(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            user = await self.store.get_by_username((data.get("username") or "").strip())
            if not user:
                return _err("User not found", 404)
            challenge = request.app["passkey_challenges"].pop(user.user_id, None)
            if not challenge:
                return _err("No pending challenge")
            verified, new_count = self.passkey.verify_authentication(data, challenge, user)
            if not verified:
                return _err("Passkey authentication failed", 401)
            cred_id = data.get("id")
            for pk in user.passkeys:
                if pk["credential_id"] == cred_id:
                    pk["sign_count"] = new_count
            await self.store.update_user(user)
            return _ok(self._full_token_response(user))
        except Exception as exc:
            logger.error("passkey_login_complete: %s", exc)
            return _err("Internal error", 500)

    # ── Contributions (SETI@Home-style) ───────────────────────────────────────

    async def contributions(self, request: web.Request) -> web.Response:
        try:
            user = await self._require_user(request)
            return _ok(
                {
                    "user_id": user.user_id,
                    "username": user.username,
                    "rank": user.compute_rank(),
                    "stats": dataclasses.asdict(user.stats),
                }
            )
        except web.HTTPException as exc:
            return _err(exc.reason, exc.status_code)
        except Exception as exc:
            logger.error("contributions: %s", exc)
            return _err("Internal error", 500)

    async def record_contribution(self, request: web.Request) -> web.Response:
        """Called by a node after a task completes.

        Expects header ``X-Internal-Key`` matching the configured internal_api_key.
        Body: { user_id, task_type, status, execution_time_ms, tokens_generated }
        """
        try:
            api_key = request.headers.get("X-Internal-Key", "")
            expected = request.app["config"].get("internal_api_key", "")
            if expected and api_key != expected:
                return _err("Unauthorized", 401)

            data = await request.json()
            user = await self.store.get_by_id(data.get("user_id") or "")
            if not user:
                return _err("User not found", 404)

            status = data.get("status", "completed")
            exec_ms = float(data.get("execution_time_ms") or 0)
            tokens = int(data.get("tokens_generated") or 0)
            now = datetime.utcnow().isoformat()

            user.stats.tasks_submitted += 1
            if status == "completed":
                user.stats.tasks_completed += 1
                user.stats.total_compute_time_ms += exec_ms
                user.stats.total_tokens_generated += tokens
                user.stats.last_contribution = now
                if not user.stats.first_contribution:
                    user.stats.first_contribution = now
            elif status == "failed":
                user.stats.tasks_failed += 1

            await self.store.update_user(user)
            return _ok(
                {
                    "recorded": True,
                    "rank": user.compute_rank(),
                    "stats": dataclasses.asdict(user.stats),
                }
            )
        except Exception as exc:
            logger.error("record_contribution: %s", exc)
            return _err("Internal error", 500)

    async def leaderboard(self, request: web.Request) -> web.Response:
        try:
            limit = min(int(request.rel_url.query.get("limit", 20)), 100)
            entries = await self.store.get_leaderboard(limit)
            return _ok({"leaderboard": entries, "count": len(entries)})
        except Exception as exc:
            logger.error("leaderboard: %s", exc)
            return _err("Internal error", 500)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _full_token_response(self, user: User) -> dict:
        return {
            "access_token": self.jwt.create_access_token(user.user_id),
            "refresh_token": self.jwt.create_refresh_token(user.user_id),
            "token_type": "bearer",
            "user": user.to_public_dict(),
        }

    # ── Route registration ────────────────────────────────────────────────────

    def setup_routes(self, app: web.Application) -> None:
        app.router.add_route("OPTIONS", "/{path:.*}", self.options)

        app.router.add_post("/auth/register", self.register)
        app.router.add_post("/auth/login", self.login)
        app.router.add_post("/auth/refresh", self.refresh)
        app.router.add_get("/auth/me", self.me)

        app.router.add_post("/auth/mfa/setup", self.mfa_setup)
        app.router.add_post("/auth/mfa/enable", self.mfa_enable)
        app.router.add_post("/auth/mfa/verify", self.mfa_verify)
        app.router.add_post("/auth/mfa/disable", self.mfa_disable)

        app.router.add_post("/auth/passkey/register/begin", self.passkey_register_begin)
        app.router.add_post("/auth/passkey/register/complete", self.passkey_register_complete)
        app.router.add_post("/auth/passkey/login/begin", self.passkey_login_begin)
        app.router.add_post("/auth/passkey/login/complete", self.passkey_login_complete)

        app.router.add_get("/auth/contributions", self.contributions)
        app.router.add_post("/auth/contributions/record", self.record_contribution)
        app.router.add_get("/auth/leaderboard", self.leaderboard)

        app.router.add_get("/health", lambda _r: web.json_response({"status": "healthy"}))
