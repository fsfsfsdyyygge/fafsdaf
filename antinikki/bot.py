from __future__ import annotations

import logging

import discord
from discord import app_commands
from discord.ext import commands

from .config import Settings, load_settings
from .database import Database
from .protection import AntiNikki


async def dynamic_prefix(bot: "AntiNikkiBot", message: discord.Message):
    prefix = bot.settings.default_prefix
    if message.guild is not None:
        saved = await bot.db.get(message.guild.id)
        if saved:
            prefix = str(saved.get("prefix", prefix))[:10] or prefix
    return commands.when_mentioned_or(prefix)(bot, message)


class AntiNikkiBot(commands.Bot):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True
        intents.moderation = True
        intents.message_content = True
        super().__init__(command_prefix=dynamic_prefix, intents=intents, help_command=None)
        self.settings = settings
        self.db = Database(settings.database_path)
        self.log = logging.getLogger("antinikki")

    async def setup_hook(self) -> None:
        await self.db.init()
        await self.add_cog(AntiNikki(self))
        if self.settings.auto_sync:
            synced = await self.tree.sync()
            self.log.info("Synced %s slash commands", len(synced))

    async def on_ready(self) -> None:
        self.log.info("ANTINIKKI online as %s (%s)", self.user, self.user.id if self.user else "unknown")
        await self.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="for server nukes"))

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        self.log.exception("Slash command failed", exc_info=error)
        message = "ANTINIKKI could not complete that command. Check its permissions and role position."
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)


def run() -> None:
    settings = load_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    AntiNikkiBot(settings).run(settings.token, log_handler=None)
