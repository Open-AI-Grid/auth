"""SQLite-backed async user store."""

import dataclasses
import json
import logging
import os
from typing import List, Optional

import aiosqlite

from ..models.user import ContributionStats, User

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    email        TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    is_active    INTEGER DEFAULT 1,
    mfa_enabled  INTEGER DEFAULT 0,
    mfa_secret   TEXT,
    passkeys     TEXT DEFAULT '[]',
    stats        TEXT DEFAULT '{}'
)
"""


class UserStore:
    def __init__(self, db_path: str = "data/users.db"):
        self.db_path = db_path

    async def initialize(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(_CREATE_TABLE)
            await db.commit()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _to_row(self, user: User) -> tuple:
        return (
            user.user_id,
            user.username,
            user.email,
            user.password_hash,
            user.created_at,
            int(user.is_active),
            int(user.mfa_enabled),
            user.mfa_secret,
            json.dumps(user.passkeys),
            json.dumps(dataclasses.asdict(user.stats)),
        )

    def _from_row(self, row) -> User:
        raw = json.loads(row["stats"] or "{}")
        stats = ContributionStats(
            tasks_submitted=raw.get("tasks_submitted", 0),
            tasks_completed=raw.get("tasks_completed", 0),
            tasks_failed=raw.get("tasks_failed", 0),
            total_compute_time_ms=float(raw.get("total_compute_time_ms", 0.0)),
            total_tokens_generated=int(raw.get("total_tokens_generated", 0)),
            first_contribution=raw.get("first_contribution"),
            last_contribution=raw.get("last_contribution"),
        )
        return User(
            user_id=row["user_id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            created_at=row["created_at"],
            is_active=bool(row["is_active"]),
            mfa_enabled=bool(row["mfa_enabled"]),
            mfa_secret=row["mfa_secret"],
            passkeys=json.loads(row["passkeys"] or "[]"),
            stats=stats,
        )

    # ── CRUD ─────────────────────────────────────────────────────────────────

    async def create_user(self, user: User) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """INSERT INTO users
                       (user_id, username, email, password_hash, created_at,
                        is_active, mfa_enabled, mfa_secret, passkeys, stats)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    self._to_row(user),
                )
                await db.commit()
            return True
        except Exception as exc:
            logger.error("Failed to create user: %s", exc)
            return False

    async def get_by_username(self, username: str) -> Optional[User]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ) as cur:
                row = await cur.fetchone()
                return self._from_row(row) if row else None

    async def get_by_email(self, email: str) -> Optional[User]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ) as cur:
                row = await cur.fetchone()
                return self._from_row(row) if row else None

    async def get_by_id(self, user_id: str) -> Optional[User]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ) as cur:
                row = await cur.fetchone()
                return self._from_row(row) if row else None

    async def update_user(self, user: User) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """UPDATE users SET
                       mfa_enabled=?, mfa_secret=?, passkeys=?, stats=?, is_active=?
                       WHERE user_id=?""",
                    (
                        int(user.mfa_enabled),
                        user.mfa_secret,
                        json.dumps(user.passkeys),
                        json.dumps(dataclasses.asdict(user.stats)),
                        int(user.is_active),
                        user.user_id,
                    ),
                )
                await db.commit()
            return True
        except Exception as exc:
            logger.error("Failed to update user: %s", exc)
            return False

    async def get_leaderboard(self, limit: int = 20) -> List[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT user_id, username, stats FROM users WHERE is_active=1"
            ) as cur:
                rows = await cur.fetchall()

        entries = []
        for row in rows:
            s = json.loads(row["stats"] or "{}")
            entries.append(
                {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "tasks_completed": s.get("tasks_completed", 0),
                    "total_compute_time_ms": s.get("total_compute_time_ms", 0),
                    "total_tokens_generated": s.get("total_tokens_generated", 0),
                }
            )

        entries.sort(key=lambda x: x["tasks_completed"], reverse=True)
        return entries[:limit]
