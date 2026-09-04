from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    token: str
    owner_ids: frozenset[int]
    database_path: Path
    log_level: str
    auto_sync: bool
    default_prefix: str


def load_settings() -> Settings:
    load_dotenv()
    token = os.getenv("DISCORD_TOKEN", "").strip()
    if not token:
        raise RuntimeError("DISCORD_TOKEN is required")
    owners = frozenset(int(value.strip()) for value in os.getenv("OWNER_IDS", "").split(",") if value.strip().isdigit())
    return Settings(
        token=token,
        owner_ids=owners,
        database_path=Path(os.getenv("DATABASE_PATH", "data/antinikki.sqlite3")),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        auto_sync=os.getenv("AUTO_SYNC_COMMANDS", "true").lower() in {"1", "true", "yes", "on"},
        default_prefix=os.getenv("DEFAULT_PREFIX", "!")[:10] or "!",
    )
