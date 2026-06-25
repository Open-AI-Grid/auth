"""User model and contribution statistics for Open AI Grid Auth Service."""

import dataclasses
import uuid
from datetime import datetime
from typing import List, Optional


@dataclasses.dataclass
class ContributionStats:
    """SETI@Home-style contribution tracking per user."""

    tasks_submitted: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_compute_time_ms: float = 0.0
    total_tokens_generated: int = 0
    first_contribution: Optional[str] = None
    last_contribution: Optional[str] = None


@dataclasses.dataclass
class User:
    """Core user record."""

    user_id: str
    username: str
    email: str
    password_hash: str
    created_at: str
    is_active: bool = True
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    passkeys: List[dict] = dataclasses.field(default_factory=list)
    stats: ContributionStats = dataclasses.field(default_factory=ContributionStats)

    @classmethod
    def create(cls, username: str, email: str, password_hash: str) -> "User":
        return cls(
            user_id=str(uuid.uuid4()),
            username=username,
            email=email,
            password_hash=password_hash,
            created_at=datetime.utcnow().isoformat(),
        )

    def compute_rank(self) -> str:
        c = self.stats.tasks_completed
        if c >= 10_000:
            return "Diamond"
        if c >= 1_000:
            return "Platinum"
        if c >= 100:
            return "Gold"
        if c >= 10:
            return "Silver"
        return "Bronze"

    def to_public_dict(self) -> dict:
        """Safe representation without secrets."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at,
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
            "passkeys_count": len(self.passkeys),
            "stats": dataclasses.asdict(self.stats),
            "rank": self.compute_rank(),
        }
