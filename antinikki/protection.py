from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import time
from collections import defaultdict, deque
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands


RULES: dict[str, dict[str, Any]] = {
    "channel_delete": {"action": discord.AuditLogAction.channel_delete, "limit": 2, "window": 20},
    "channel_create": {"action": discord.AuditLogAction.channel_create, "limit": 5, "window": 30},
    "channel_update": {"action": discord.AuditLogAction.channel_update, "limit": 5, "window": 30},
    "role_delete": {"action": discord.AuditLogAction.role_delete, "limit": 2, "window": 20},
    "role_create": {"action": discord.AuditLogAction.role_create, "limit": 5, "window": 30},
    "role_update": {"action": discord.AuditLogAction.role_update, "limit": 3, "window": 30},
    "ban": {"action": discord.AuditLogAction.ban, "limit": 3, "window": 30},
    "kick": {"action": discord.AuditLogAction.kick, "limit": 3, "window": 30},
    "bot_add": {"action": discord.AuditLogAction.bot_add, "limit": 1, "window": 60},
    "webhook": {"action": discord.AuditLogAction.webhook_create, "limit": 2, "window": 30},
    "guild_update": {"action": discord.AuditLogAction.guild_update, "limit": 2, "window": 30},
}

DANGEROUS = discord.Permissions(
    administrator=True, manage_guild=True, manage_roles=True, manage_channels=True,
    ban_members=True, kick_members=True, manage_webhooks=True, moderate_members=True,
)


def default_config() -> dict[str, Any]:
    return {
        "enabled": True, "log_channel_id": None, "whitelist_users": [], "whitelist_roles": [],
        "punishment": "strip_roles", "lockdown_on_trigger": True,
        "rules": {name: {"enabled": True, "limit": meta["limit"], "window": meta["window"]} for name, meta in RULES.items()},
        "lockdown_roles": [],
    }


class AntiNikki(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.log = logging.getLogger("antinikki.protection")
        self.events: dict[tuple[int, int, str], deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self.cooldowns: dict[tuple[int, int, str], float] = {}

    antinikki = app_commands.Group(name="antinikki", description="ANTINIKKI anti-nuke protection")

    async def config(self, guild_id: int) -> dict[str, Any]:
        saved = await self.bot.db.get(guild_id)
        base = default_config()
        if saved:
            base.update(saved)
            for name, rule in base["rules"].items():
                merged = default_config()["rules"].get(name, {})
                merged.update(rule)
                base["rules"][name] = merged
        return base

    async def require_owner(self, interaction: discord.Interaction) -> bool:
        allowed = bool(interaction.guild and (interaction.user.id == interaction.guild.owner_id or interaction.user.id in self.bot.settings.owner_ids))
        if not allowed:
            await interaction.response.send_message("Only the Discord server owner or an ANTINIKKI owner can use this command.", ephemeral=True)
        return allowed

    def owner_member(self, member: discord.Member) -> bool:
        return member.id == member.guild.owner_id or member.id in self.bot.settings.owner_ids

    async def panel_embed(self, guild: discord.Guild) -> discord.Embed:
        cfg = await self.config(guild.id)
        me = guild.me
        required = ["view_audit_log", "manage_roles", "manage_channels", "ban_members", "kick_members", "moderate_members", "manage_webhooks"]
        missing = [name for name in required if me is None or not getattr(me.guild_permissions, name)]
        e = discord.Embed(title="ANTINIKKI Security Panel", color=discord.Color.green() if cfg["enabled"] and not missing else discord.Color.orange())
        e.description = "Dedicated anti-nuke protection and emergency controls."
        e.add_field(name="Protection", value="Enabled" if cfg["enabled"] else "Disabled", inline=True)
        e.add_field(name="Response", value=cfg["punishment"].replace("_", " ").title(), inline=True)
        e.add_field(name="Rules", value=f"{sum(rule['enabled'] for rule in cfg['rules'].values())}/{len(cfg['rules'])}", inline=True)
        e.add_field(name="Trusted", value=f"{len(cfg['whitelist_users'])} users · {len(cfg['whitelist_roles'])} roles", inline=True)
        e.add_field(name="Missing permissions", value=", ".join(missing) or "None", inline=False)
        prefix = str(cfg.get("prefix", self.bot.settings.default_prefix))
        e.set_footer(text=f"Prefix: {prefix} · Commands: {prefix}help")
        return e

    async def log_incident(self, guild: discord.Guild, actor: discord.Member | None, event: str, action: str, details: dict[str, Any]) -> None:
        await self.bot.db.incident(guild.id, actor.id if actor else None, event, action, details)
        cfg = await self.config(guild.id)
        channel = guild.get_channel(int(cfg.get("log_channel_id") or 0))
        if isinstance(channel, discord.TextChannel):
            e = discord.Embed(title="ANTINIKKI Security Incident", color=discord.Color.red(), timestamp=discord.utils.utcnow())
            e.add_field(name="Event", value=event.replace("_", " ").title(), inline=True)
            e.add_field(name="Actor", value=actor.mention if actor else "Unknown", inline=True)
            e.add_field(name="Response", value=action, inline=True)
            e.description = json.dumps(details, indent=2)[:1500]
            try:
                await channel.send(embed=e)
            except discord.HTTPException:
                self.log.exception("Could not send incident log")

    async def find_actor(self, guild: discord.Guild, event: str, target_id: int | None = None) -> discord.Member | None:
        await asyncio.sleep(0.8)
        try:
            async for entry in guild.audit_logs(limit=8, action=RULES[event]["action"]):
                if (discord.utils.utcnow() - entry.created_at).total_seconds() > 15:
                    continue
                if target_id is not None and getattr(entry.target, "id", None) != target_id:
                    continue
                return guild.get_member(entry.user.id) if entry.user else None
        except (discord.Forbidden, discord.HTTPException):
            self.log.exception("Audit log lookup failed in guild %s", guild.id)
        return None

    def trusted(self, guild: discord.Guild, member: discord.Member, cfg: dict[str, Any]) -> bool:
        return (
            member.id == guild.owner_id or member.id == self.bot.user.id or
            member.id in self.bot.settings.owner_ids or member.id in cfg["whitelist_users"] or
            any(role.id in cfg["whitelist_roles"] for role in member.roles)
        )

    async def lockdown(self, guild: discord.Guild, cfg: dict[str, Any], reason: str) -> int:
        me = guild.me
        if me is None:
            return 0
        changed = 0
        saved: list[dict[str, Any]] = cfg.get("lockdown_roles", [])
        known = {item["id"] for item in saved}
        for role in guild.roles:
            if role.is_default() or role.managed or role >= me.top_role or role.id in known:
                continue
            dangerous = role.permissions.value & DANGEROUS.value
            if not dangerous:
                continue
            saved.append({"id": role.id, "permissions": role.permissions.value})
            permissions = discord.Permissions(role.permissions.value & ~DANGEROUS.value)
            try:
                await role.edit(permissions=permissions, reason=reason)
                changed += 1
            except discord.HTTPException:
                self.log.exception("Could not secure role %s", role.id)
        cfg["lockdown_roles"] = saved
        await self.bot.db.set(guild.id, cfg)
        return changed

    async def respond(self, guild: discord.Guild, actor: discord.Member, event: str, cfg: dict[str, Any]) -> None:
        action = cfg.get("punishment", "strip_roles")
        me = guild.me
        if me is None or actor.top_role >= me.top_role:
            await self.log_incident(guild, actor, event, "blocked_by_role_hierarchy", {"requested": action})
            return
        try:
            if action == "ban":
                await actor.ban(reason=f"ANTINIKKI triggered: {event}")
            elif action == "kick":
                await actor.kick(reason=f"ANTINIKKI triggered: {event}")
            elif action == "timeout":
                await actor.timeout(discord.utils.utcnow() + dt.timedelta(hours=24), reason=f"ANTINIKKI triggered: {event}")
            elif action == "strip_roles":
                removable = [role for role in actor.roles if not role.is_default() and not role.managed and role < me.top_role]
                if removable:
                    await actor.remove_roles(*removable, reason=f"ANTINIKKI triggered: {event}")
            elif action != "log_only":
                action = "log_only"
        except discord.HTTPException as exc:
            action = f"failed_{action}"
            self.log.exception("Response failed")
        locked = await self.lockdown(guild, cfg, f"ANTINIKKI emergency lockdown: {event}") if cfg.get("lockdown_on_trigger") else 0
        await self.log_incident(guild, actor, event, action, {"lockdown_roles_secured": locked})

    async def record(self, guild: discord.Guild, event: str, target_id: int | None = None) -> None:
        cfg = await self.config(guild.id)
        rule = cfg["rules"].get(event, {})
        if not cfg["enabled"] or not rule.get("enabled", True):
            return
        actor = await self.find_actor(guild, event, target_id)
        if actor is None:
            # A member_remove event is also emitted for ordinary voluntary leaves.
            # Without a matching kick audit entry, it is not a security incident.
            if event != "kick":
                await self.log_incident(guild, None, event, "log_only_unknown_actor", {"target_id": target_id})
            return
        if self.trusted(guild, actor, cfg):
            return
        now = time.monotonic()
        key = (guild.id, actor.id, event)
        bucket = self.events[key]
        bucket.append(now)
        window = max(5, int(rule.get("window", 30)))
        hits = sum(now - stamp <= window for stamp in bucket)
        if hits < max(1, int(rule.get("limit", 3))) or now < self.cooldowns.get(key, 0):
            return
        self.cooldowns[key] = now + window
        await self.respond(guild, actor, event, cfg)

    @antinikki.command(name="setup", description="Enable protection and set the private incident-log channel")
    async def setup(self, interaction: discord.Interaction, log_channel: discord.TextChannel) -> None:
        if not await self.require_owner(interaction): return
        cfg = await self.config(interaction.guild_id)
        cfg["enabled"] = True
        cfg["log_channel_id"] = log_channel.id
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message("ANTINIKKI is enabled. Review `/antinikki status` and place its role above every role it must secure.", ephemeral=True)

    @antinikki.command(name="status", description="Show protection status and permission readiness")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        await interaction.response.send_message(embed=await self.panel_embed(interaction.guild), ephemeral=True)

    @antinikki.command(name="panel", description="Open the ANTINIKKI security panel")
    async def panel(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        await interaction.response.send_message(embed=await self.panel_embed(interaction.guild), ephemeral=True)

    @antinikki.command(name="enabled", description="Enable or disable ANTINIKKI protection")
    async def enabled(self, interaction: discord.Interaction, value: bool) -> None:
        if not await self.require_owner(interaction): return
        cfg = await self.config(interaction.guild_id); cfg["enabled"] = value
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message(f"ANTINIKKI protection is now **{'enabled' if value else 'disabled'}**.", ephemeral=True)

    @antinikki.command(name="incidents", description="Show recent ANTINIKKI security incidents")
    async def incidents(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        rows = await self.bot.db.incidents(interaction.guild_id, 10)
        e = discord.Embed(title="Recent ANTINIKKI Incidents", color=discord.Color.red())
        e.description = "\n".join(
            f"`#{row['id']}` **{row['event']}** · {row['action']} · <@{row['actor_id']}> · {row['created_at']}"
            for row in rows
        ) or "No incidents recorded."
        await interaction.response.send_message(embed=e, ephemeral=True)

    @antinikki.command(name="whitelist", description="Trust a user or role")
    async def whitelist(self, interaction: discord.Interaction, user: discord.Member | None = None, role: discord.Role | None = None) -> None:
        if not await self.require_owner(interaction): return
        if not user and not role:
            await interaction.response.send_message("Choose a user or role.", ephemeral=True); return
        cfg = await self.config(interaction.guild_id)
        key, value = ("whitelist_users", user.id) if user else ("whitelist_roles", role.id)
        if value not in cfg[key]: cfg[key].append(value)
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message("Whitelist updated.", ephemeral=True)

    @antinikki.command(name="unwhitelist", description="Remove a trusted user or role")
    async def unwhitelist(self, interaction: discord.Interaction, user: discord.Member | None = None, role: discord.Role | None = None) -> None:
        if not await self.require_owner(interaction): return
        cfg = await self.config(interaction.guild_id)
        if user: cfg["whitelist_users"] = [item for item in cfg["whitelist_users"] if item != user.id]
        if role: cfg["whitelist_roles"] = [item for item in cfg["whitelist_roles"] if item != role.id]
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message("Whitelist updated.", ephemeral=True)

    @antinikki.command(name="response", description="Choose what happens when protection triggers")
    @app_commands.choices(action=[app_commands.Choice(name=name.replace("_", " ").title(), value=name) for name in ("strip_roles", "timeout", "kick", "ban", "log_only")])
    async def response_command(self, interaction: discord.Interaction, action: app_commands.Choice[str]) -> None:
        if not await self.require_owner(interaction): return
        cfg = await self.config(interaction.guild_id); cfg["punishment"] = action.value
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message(f"Response set to **{action.name}**.", ephemeral=True)

    @antinikki.command(name="rule", description="Configure an event threshold")
    async def rule(self, interaction: discord.Interaction, event: str, enabled: bool, limit: app_commands.Range[int, 1, 25], seconds: app_commands.Range[int, 5, 600]) -> None:
        if not await self.require_owner(interaction): return
        if event not in RULES:
            await interaction.response.send_message("Events: " + ", ".join(RULES), ephemeral=True); return
        cfg = await self.config(interaction.guild_id); cfg["rules"][event] = {"enabled": enabled, "limit": limit, "window": seconds}
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message(f"Rule `{event}` updated.", ephemeral=True)

    @antinikki.command(name="lockdown", description="Immediately remove dangerous permissions from manageable roles")
    async def lockdown_command(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        await interaction.response.defer(ephemeral=True)
        cfg = await self.config(interaction.guild_id)
        count = await self.lockdown(interaction.guild, cfg, f"Manual ANTINIKKI lockdown by {interaction.user}")
        await interaction.followup.send(f"Lockdown complete. Secured `{count}` roles. Use `/antinikki unlock` after reviewing the incident.", ephemeral=True)

    @antinikki.command(name="unlock", description="Restore permissions saved by ANTINIKKI lockdown")
    async def unlock(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        await interaction.response.defer(ephemeral=True)
        cfg = await self.config(interaction.guild_id); me = interaction.guild.me; restored = 0
        remaining = []
        for item in cfg.get("lockdown_roles", []):
            role = interaction.guild.get_role(int(item["id"]))
            if role is None: continue
            if me is None or role >= me.top_role: remaining.append(item); continue
            try:
                await role.edit(permissions=discord.Permissions(int(item["permissions"])), reason=f"ANTINIKKI unlock by {interaction.user}")
                restored += 1
            except discord.HTTPException: remaining.append(item)
        cfg["lockdown_roles"] = remaining; await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.followup.send(f"Restored `{restored}` roles. `{len(remaining)}` could not be restored.", ephemeral=True)

    @commands.command(name="antinikki", aliases=["panel", "security"])
    @commands.guild_only()
    async def prefix_panel(self, ctx: commands.Context) -> None:
        """Open the owner-only security panel using the server prefix."""
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author):
            await ctx.reply("Only the server owner or an ANTINIKKI owner can open this panel.", mention_author=False)
            return
        await ctx.reply(embed=await self.panel_embed(ctx.guild), mention_author=False)

    @commands.command(name="prefix")
    @commands.guild_only()
    async def prefix_change(self, ctx: commands.Context, new_prefix: str | None = None) -> None:
        """Show or change ANTINIKKI's text-command prefix."""
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author):
            await ctx.reply("Only the server owner or an ANTINIKKI owner can change the prefix.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        if new_prefix is None:
            await ctx.reply(f"Current prefix: `{cfg.get('prefix', self.bot.settings.default_prefix)}`", mention_author=False)
            return
        new_prefix = new_prefix.strip()
        if not 1 <= len(new_prefix) <= 10 or any(character.isspace() for character in new_prefix):
            await ctx.reply("Choose a prefix from 1–10 characters with no spaces.", mention_author=False)
            return
        cfg["prefix"] = new_prefix
        await self.bot.db.set(ctx.guild.id, cfg)
        await ctx.reply(f"Prefix changed to `{new_prefix}`. Open the panel with `{new_prefix}antinikki`.", mention_author=False)

    @commands.command(name="help")
    @commands.guild_only()
    async def prefix_help(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author):
            return
        cfg = await self.config(ctx.guild.id)
        prefix = str(cfg.get("prefix", self.bot.settings.default_prefix))
        e = discord.Embed(title="ANTINIKKI Prefix Commands", color=discord.Color.blurple())
        e.description = (
            f"`{prefix}antinikki` or `{prefix}panel` — security panel\n"
            f"`{prefix}prefix` — show the current prefix\n"
            f"`{prefix}prefix <new>` — change the prefix\n"
            f"`{prefix}help` — show this command list\n\n"
            "Use `/antinikki` for setup, protection rules, whitelists, incidents, lockdown, and recovery."
        )
        await ctx.reply(embed=e, mention_author=False)

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel): await self.record(channel.guild, "channel_delete", channel.id)
    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel): await self.record(channel.guild, "channel_create", channel.id)
    @commands.Cog.listener()
    async def on_guild_channel_update(self, before, after): await self.record(after.guild, "channel_update", after.id)
    @commands.Cog.listener()
    async def on_guild_role_delete(self, role): await self.record(role.guild, "role_delete", role.id)
    @commands.Cog.listener()
    async def on_guild_role_create(self, role): await self.record(role.guild, "role_create", role.id)
    @commands.Cog.listener()
    async def on_guild_role_update(self, before, after):
        if before.permissions != after.permissions or before.position != after.position: await self.record(after.guild, "role_update", after.id)
    @commands.Cog.listener()
    async def on_member_ban(self, guild, user): await self.record(guild, "ban", user.id)
    @commands.Cog.listener()
    async def on_member_remove(self, member): await self.record(member.guild, "kick", member.id)
    @commands.Cog.listener()
    async def on_member_join(self, member):
        if member.bot: await self.record(member.guild, "bot_add", member.id)
    @commands.Cog.listener()
    async def on_webhooks_update(self, channel): await self.record(channel.guild, "webhook")
    @commands.Cog.listener()
    async def on_guild_update(self, before, after): await self.record(after, "guild_update", after.id)
