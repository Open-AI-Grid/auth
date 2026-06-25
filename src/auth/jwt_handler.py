"""JWT access / refresh / partial-MFA token management."""

import logging
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt

logger = logging.getLogger(__name__)


class JWTHandler:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    # ── factories ────────────────────────────────────────────────────────────

    def _make(self, sub: str, token_type: str, ttl: timedelta) -> str:
        now = datetime.utcnow()
        return jwt.encode(
            {"sub": sub, "type": token_type, "iat": now, "exp": now + ttl},
            self.secret_key,
            algorithm=self.algorithm,
        )

    def create_access_token(self, user_id: str) -> str:
        return self._make(user_id, "access", timedelta(minutes=15))

    def create_refresh_token(self, user_id: str) -> str:
        return self._make(user_id, "refresh", timedelta(days=7))

    def create_partial_token(self, user_id: str) -> str:
        """Short-lived token used while waiting for the MFA code."""
        return self._make(user_id, "partial", timedelta(minutes=5))

    # ── verification ─────────────────────────────────────────────────────────

    def _verify(self, token: str, expected_type: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            if payload.get("type") != expected_type:
                return None
            return payload
        except JWTError as exc:
            logger.debug("JWT verify failed: %s", exc)
            return None

    def verify_access_token(self, token: str) -> Optional[dict]:
        return self._verify(token, "access")

    def verify_refresh_token(self, token: str) -> Optional[dict]:
        return self._verify(token, "refresh")

    def verify_partial_token(self, token: str) -> Optional[dict]:
        return self._verify(token, "partial")
