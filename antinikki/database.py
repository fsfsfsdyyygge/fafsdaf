from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import aiosqlite


SCHEMA = """
CREATE TABLE IF NOT EXISTS guild_config(guild_id INTEGER PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(
 id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL, actor_id INTEGER,
 event TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = asyncio.Lock()

    async def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    async def get(self, guild_id: int) -> dict[str, Any] | None:
        async with self.lock, aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            row = await (await db.execute("SELECT data FROM guild_config WHERE guild_id=?", (guild_id,))).fetchone()
            return json.loads(row["data"]) if row else None

    async def set(self, guild_id: int, data: dict[str, Any]) -> None:
        async with self.lock, aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO guild_config(guild_id,data) VALUES(?,?) ON CONFLICT(guild_id) DO UPDATE SET data=excluded.data",
                (guild_id, json.dumps(data)),
            )
            await db.commit()

    async def incident(self, guild_id: int, actor_id: int | None, event: str, action: str, details: dict[str, Any]) -> None:
        async with self.lock, aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO incidents(guild_id,actor_id,event,action,details) VALUES(?,?,?,?,?)",
                (guild_id, actor_id, event, action, json.dumps(details)),
            )
            await db.commit()

    async def incidents(self, guild_id: int, limit: int = 10) -> list[aiosqlite.Row]:
        async with self.lock, aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            return await (await db.execute(
                "SELECT * FROM incidents WHERE guild_id=? ORDER BY id DESC LIMIT ?", (guild_id, limit)
            )).fetchall()
