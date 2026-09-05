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


class SecurityPanel(discord.ui.View):
    def __init__(self, cog: "AntiNikki", owner_id: int) -> None:
        super().__init__(timeout=600)
        self.cog = cog
        self.owner_id = owner_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id or interaction.guild is None:
            await interaction.response.send_message("Only the owner who opened this panel can use it.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Refresh", style=discord.ButtonStyle.secondary)
    async def refresh(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await interaction.response.edit_message(embed=await self.cog.panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Enable / Disable", style=discord.ButtonStyle.primary)
    async def toggle(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if not isinstance(interaction.user, discord.Member) or not self.cog.owner_member(interaction.user):
            await interaction.response.send_message("Only the Discord server owner can enable or disable anti-nuke protection.", ephemeral=True)
            return
        cfg = await self.cog.config(interaction.guild_id)
        cfg["enabled"] = not cfg["enabled"]
        await self.cog.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.edit_message(embed=await self.cog.panel_embed(interaction.guild), view=self)

    @discord.ui.button(label="Recent Incidents", style=discord.ButtonStyle.secondary)
    async def incidents(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        rows = await self.cog.bot.db.incidents(interaction.guild_id, 10)
        e = discord.Embed(title="Recent ANTINIKKI Incidents", color=discord.Color.red())
        e.description = "\n".join(
            f"`#{row['id']}` **{row['event']}** · {row['action']} · <@{row['actor_id']}> · {row['created_at']}"
            for row in rows
        ) or "No incidents recorded."
        await interaction.response.send_message(embed=e, ephemeral=True)


class HelpView(discord.ui.View):
    def __init__(self, cog: "AntiNikki", prefix: str) -> None:
        super().__init__(timeout=600)
        self.cog = cog
        self.prefix = prefix

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not isinstance(interaction.user, discord.Member) or not await self.cog.security_admin(interaction.user):
            await interaction.response.send_message("Only the server owner or an Anti-Nuke Admin can use this help panel.", ephemeral=True)
            return False
        return True

    async def show(self, interaction: discord.Interaction, page: str) -> None:
        await interaction.response.edit_message(embed=self.cog.help_embed(self.prefix, page), view=self)

    @discord.ui.button(label="Overview", style=discord.ButtonStyle.primary)
    async def overview(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await self.show(interaction, "overview")

    @discord.ui.button(label="Protection", style=discord.ButtonStyle.secondary)
    async def protection(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await self.show(interaction, "protection")

    @discord.ui.button(label="Whitelist & Admins", style=discord.ButtonStyle.secondary)
    async def access(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await self.show(interaction, "access")

    @discord.ui.button(label="Owner Controls", style=discord.ButtonStyle.danger)
    async def owner(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await self.show(interaction, "owner")


def default_config() -> dict[str, Any]:
    return {
        "enabled": True, "log_channel_id": None, "whitelist_users": [], "whitelist_roles": [], "admin_roles": [], "admin_users": [],
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

    antinikki = app_commands.Group(name="antinuke", description="ANTINIKKI anti-nuke protection")

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

    async def security_admin(self, member: discord.Member) -> bool:
        if self.owner_member(member):
            return True
        cfg = await self.config(member.guild.id)
        return member.id in cfg.get("admin_users", []) or any(role.id in cfg.get("admin_roles", []) for role in member.roles)

    async def require_security_admin(self, interaction: discord.Interaction) -> bool:
        allowed = isinstance(interaction.user, discord.Member) and await self.security_admin(interaction.user)
        if not allowed:
            await interaction.response.send_message("Only the server owner or a configured Anti-Nuke Admin can manage the whitelist.", ephemeral=True)
        return allowed

    async def panel_embed(self, guild: discord.Guild) -> discord.Embed:
        cfg = await self.config(guild.id)
        me = guild.me
        required = ["view_audit_log", "manage_roles", "manage_channels", "ban_members", "kick_members", "moderate_members", "manage_webhooks"]
        missing = [name for name in required if me is None or not getattr(me.guild_permissions, name)]
        e = discord.Embed(title="ANTINIKKI Security Panel", color=discord.Color.green() if cfg["enabled"] and not missing else discord.Color.orange())
        e.description = "Every protection and its current state."
        e.add_field(name="Protection", value="Enabled" if cfg["enabled"] else "Disabled", inline=True)
        e.add_field(name="Response", value=cfg["punishment"].replace("_", " ").title(), inline=True)
        e.add_field(name="Rules", value=f"{sum(rule['enabled'] for rule in cfg['rules'].values())}/{len(cfg['rules'])}", inline=True)
        e.add_field(name="Trusted", value=f"{len(cfg['whitelist_users'])} users · {len(cfg['whitelist_roles'])} roles", inline=True)
        rule_rows = []
        for name, rule in cfg["rules"].items():
            state = "✅ Enabled" if rule.get("enabled", True) else "❌ Disabled"
            rule_rows.append(f"**{name.replace('_', ' ').title()}** — {state} · `{rule.get('limit', 1)}` / `{rule.get('window', 30)}s`")
        e.add_field(name="Protection Status & Thresholds", value="\n".join(rule_rows), inline=False)
        e.add_field(name="Emergency Lockdown", value="✅ Enabled" if cfg.get("lockdown_on_trigger") else "❌ Disabled", inline=True)
        log_channel = guild.get_channel(int(cfg.get("log_channel_id") or 0))
        e.add_field(name="Incident Logs", value=log_channel.mention if isinstance(log_channel, discord.TextChannel) else "❌ Not configured", inline=True)
        e.add_field(name="Missing permissions", value=", ".join(missing) or "None", inline=False)
        prefix = str(cfg.get("prefix", self.bot.settings.default_prefix))
        e.set_footer(text=f"Prefix: {prefix} · Commands: {prefix}help")
        return e

    def help_embed(self, prefix: str, page: str = "overview") -> discord.Embed:
        pages = {
            "overview": (
                "Overview",
                f"`{prefix}antinuke panel` — full live protection panel\n"
                f"`{prefix}antinuke whitelist list` — whitelisted users\n"
                f"`{prefix}antinuke admin list` — Anti-Nuke Admin users\n"
                f"`{prefix}an config` — thresholds and configuration\n"
                f"`{prefix}an logs` — recent incidents\n"
                f"`{prefix}help` — open this clickable help panel",
            ),
            "protection": (
                "Protection Commands",
                f"`{prefix}an status` / `st` — protection status\n"
                f"`{prefix}an config` / `cfg` — all thresholds\n"
                f"`{prefix}an logs` / `lg` — incident logs\n"
                f"`{prefix}an lockdown` / `ld` — emergency lockdown (owner)\n"
                f"`{prefix}an on` / `off` — enable or disable protection (owner)\n"
                "`/antinuke rule` — change a protection threshold (owner)",
            ),
            "access": (
                "Whitelist & Admin Commands",
                f"`{prefix}an wl @user-or-role` — add whitelist entry\n"
                f"`{prefix}an uwl @user-or-role` — remove whitelist entry\n"
                f"`{prefix}antinuke whitelist list` — list whitelisted users\n"
                f"`{prefix}an admin @user-or-ID` — add immune admin (owner)\n"
                f"`{prefix}an admin remove @user-or-ID` — remove admin (owner)\n"
                f"`{prefix}antinuke admin list` — list all Anti-Nuke Admin users",
            ),
            "owner": (
                "Server Owner Controls",
                f"`{prefix}prefix <new>` — change the bot prefix\n"
                f"`{prefix}an on` / `off` — protection switch\n"
                f"`{prefix}an lockdown` — secure dangerous roles\n"
                f"`{prefix}an admin @user-or-ID` — assign Anti-Nuke Admin\n"
                "`/antinuke setup` — configure logging and enable protection\n"
                "`/antinuke response` — choose the trigger response\n"
                "`/antinuke unlock` — restore roles after lockdown",
            ),
        }
        title, description = pages.get(page, pages["overview"])
        embed = discord.Embed(title=f"ANTINIKKI Help · {title}", description=description, color=discord.Color.blurple())
        embed.set_footer(text="Only the server owner and Anti-Nuke Admins can access this panel.")
        return embed

    async def config_embed(self, guild: discord.Guild) -> discord.Embed:
        cfg = await self.config(guild.id)
        log_channel = guild.get_channel(int(cfg.get("log_channel_id") or 0))
        rows = []
        for name, rule in cfg["rules"].items():
            state = "ON" if rule.get("enabled", True) else "OFF"
            rows.append(f"`{name}` — **{state}** · `{rule.get('limit', 1)}` actions / `{rule.get('window', 30)}s`")
        e = discord.Embed(title="ANTINIKKI Configuration", color=discord.Color.blurple())
        e.description = "\n".join(rows)
        e.add_field(name="Response", value=cfg.get("punishment", "strip_roles").replace("_", " ").title(), inline=True)
        e.add_field(name="Logs", value=log_channel.mention if isinstance(log_channel, discord.TextChannel) else "Not configured", inline=True)
        e.add_field(name="Anti-Nuke Admin Roles", value=" ".join(f"<@&{role_id}>" for role_id in cfg.get("admin_roles", [])) or "Owner only", inline=False)
        e.add_field(name="Direct Anti-Nuke Admins", value=" ".join(f"<@{user_id}>" for user_id in cfg.get("admin_users", [])) or "None", inline=False)
        e.add_field(name="Whitelist", value=f"{len(cfg['whitelist_users'])} users · {len(cfg['whitelist_roles'])} roles", inline=True)
        e.set_footer(text="Anti-Nuke Admins have read-only configuration access. Only the server owner can change thresholds or protection settings.")
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
            member.id in self.bot.settings.owner_ids or member.id in cfg.get("admin_users", []) or member.id in cfg["whitelist_users"] or
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
        await interaction.response.send_message("ANTINIKKI is enabled. Review `/antinuke status` and place its role above every role it must secure.", ephemeral=True)

    @antinikki.command(name="status", description="Show protection status and permission readiness")
    async def status(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        await interaction.response.send_message(embed=await self.panel_embed(interaction.guild), ephemeral=True)

    @antinikki.command(name="panel", description="Open the ANTINIKKI security panel")
    async def panel(self, interaction: discord.Interaction) -> None:
        if not await self.require_owner(interaction): return
        await interaction.response.send_message(embed=await self.panel_embed(interaction.guild), view=SecurityPanel(self, interaction.user.id), ephemeral=True)

    @antinikki.command(name="config", description="Show all thresholds, logging, admins, and whitelist totals")
    async def config_command(self, interaction: discord.Interaction) -> None:
        if not isinstance(interaction.user, discord.Member) or not await self.security_admin(interaction.user):
            await interaction.response.send_message("Only the server owner or an Anti-Nuke Admin can view this configuration.", ephemeral=True)
            return
        await interaction.response.send_message(embed=await self.config_embed(interaction.guild), ephemeral=True)

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
        if not await self.require_security_admin(interaction): return
        if not user and not role:
            await interaction.response.send_message("Choose a user or role.", ephemeral=True); return
        cfg = await self.config(interaction.guild_id)
        key, value = ("whitelist_users", user.id) if user else ("whitelist_roles", role.id)
        if value not in cfg[key]: cfg[key].append(value)
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message("Whitelist updated.", ephemeral=True)

    @antinikki.command(name="unwhitelist", description="Remove a trusted user or role")
    async def unwhitelist(self, interaction: discord.Interaction, user: discord.Member | None = None, role: discord.Role | None = None) -> None:
        if not await self.require_security_admin(interaction): return
        cfg = await self.config(interaction.guild_id)
        if user: cfg["whitelist_users"] = [item for item in cfg["whitelist_users"] if item != user.id]
        if role: cfg["whitelist_roles"] = [item for item in cfg["whitelist_roles"] if item != role.id]
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message("Whitelist updated.", ephemeral=True)

    @antinikki.command(name="admin_role", description="Set the role allowed to manage the anti-nuke whitelist")
    async def admin_role(self, interaction: discord.Interaction, role: discord.Role, enabled: bool = True) -> None:
        if not await self.require_owner(interaction): return
        cfg = await self.config(interaction.guild_id)
        roles = cfg.setdefault("admin_roles", [])
        if enabled and role.id not in roles:
            roles.append(role.id)
        elif not enabled:
            cfg["admin_roles"] = [role_id for role_id in roles if role_id != role.id]
        await self.bot.db.set(interaction.guild_id, cfg)
        await interaction.response.send_message(f"{role.mention} {'can now' if enabled else 'can no longer'} manage the anti-nuke whitelist.", ephemeral=True)

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
        await interaction.followup.send(f"Lockdown complete. Secured `{count}` roles. Use `/antinuke unlock` after reviewing the incident.", ephemeral=True)

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

    @commands.group(name="antinuke", aliases=["antinikki", "panel", "security"], invoke_without_command=True)
    @commands.guild_only()
    async def prefix_panel(self, ctx: commands.Context) -> None:
        """Open the protected security panel using the server prefix."""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can open this panel.", mention_author=False)
            return
        await ctx.reply(embed=await self.panel_embed(ctx.guild), view=SecurityPanel(self, ctx.author.id), mention_author=False)

    @prefix_panel.command(name="panel", aliases=["status"])
    async def prefix_panel_open(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can open this panel.", mention_author=False)
            return
        await ctx.reply(embed=await self.panel_embed(ctx.guild), view=SecurityPanel(self, ctx.author.id), mention_author=False)

    @prefix_panel.group(name="whitelist", aliases=["wl"], invoke_without_command=True)
    async def prefix_panel_whitelist(self, ctx: commands.Context) -> None:
        await ctx.reply(f"Use `{ctx.prefix}antinuke whitelist list` to view whitelisted users.", mention_author=False)

    @prefix_panel_whitelist.command(name="list")
    async def prefix_panel_whitelist_list(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can view the whitelist.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        lines = []
        for user_id in cfg.get("whitelist_users", []):
            member = ctx.guild.get_member(int(user_id))
            lines.append(f"{member.mention if member else f'<@{user_id}>'} · `{user_id}`")
        embed = discord.Embed(title="ANTINIKKI Whitelisted Users", description="\n".join(lines) or "No users are directly whitelisted.", color=discord.Color.green())
        await ctx.reply(embed=embed, mention_author=False)

    @prefix_panel.group(name="admin", invoke_without_command=True)
    async def prefix_panel_admin(self, ctx: commands.Context) -> None:
        await ctx.reply(f"Use `{ctx.prefix}antinuke admin list` to view Anti-Nuke Admin users.", mention_author=False)

    @prefix_panel_admin.command(name="list")
    async def prefix_panel_admin_list(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can view this list.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        admin_role_ids = set(cfg.get("admin_roles", []))
        members = {ctx.guild.owner} if ctx.guild.owner else set()
        members.update(member for member in ctx.guild.members if any(role.id in admin_role_ids for role in member.roles))
        members.update(member for owner_id in self.bot.settings.owner_ids if (member := ctx.guild.get_member(owner_id)))
        members.update(member for user_id in cfg.get("admin_users", []) if (member := ctx.guild.get_member(user_id)))
        lines = [f"{member.mention} · `{member.id}`" for member in sorted(members, key=lambda item: item.display_name.lower())]
        embed = discord.Embed(title="ANTINIKKI Admin Users", description="\n".join(lines) or "No Anti-Nuke Admin users found.", color=discord.Color.blurple())
        await ctx.reply(embed=embed, mention_author=False)

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
        await ctx.reply(f"Prefix changed to `{new_prefix}`. Open the panel with `{new_prefix}antinuke`.", mention_author=False)

    @commands.command(name="help")
    @commands.guild_only()
    async def prefix_help(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            return
        cfg = await self.config(ctx.guild.id)
        prefix = str(cfg.get("prefix", self.bot.settings.default_prefix))
        await ctx.reply(embed=self.help_embed(prefix), view=HelpView(self, prefix), mention_author=False)

    @commands.command(name="tell")
    @commands.guild_only()
    async def tell_fact(self, ctx: commands.Context, *, request: str = "") -> None:
        """Respond to: ,tell me a fact"""
        if " ".join(request.lower().split()) != "me a fact":
            await ctx.reply("Use `,tell me a fact`.", mention_author=False)
            return
        await ctx.reply("bobs a bitch", mention_author=False)

    @commands.group(name="an", invoke_without_command=True)
    @commands.guild_only()
    async def prefix_an(self, ctx: commands.Context) -> None:
        """Short ANTINIKKI prefix command group."""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can use this command.", mention_author=False)
            return
        await ctx.reply(embed=await self.panel_embed(ctx.guild), view=SecurityPanel(self, ctx.author.id), mention_author=False)

    @prefix_an.command(name="config", aliases=["cfg"])
    async def prefix_an_config(self, ctx: commands.Context) -> None:
        """Show every anti-nuke threshold and logging destination."""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can view this configuration.", mention_author=False)
            return
        await ctx.reply(embed=await self.config_embed(ctx.guild), mention_author=False)

    @prefix_an.group(name="whitelist", aliases=["wl"], invoke_without_command=True)
    async def prefix_an_whitelist(self, ctx: commands.Context, target: discord.Member | discord.Role | int | None = None) -> None:
        """Whitelist a user or role: ,an wl @target"""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can manage the whitelist.", mention_author=False)
            return
        if target is None:
            await ctx.reply("Use `,an wl @user-or-role` or `,an whitelist list`.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        key = "whitelist_roles" if isinstance(target, discord.Role) else "whitelist_users"
        target_id = target.id if isinstance(target, (discord.Member, discord.Role)) else int(target)
        if target_id not in cfg[key]:
            cfg[key].append(target_id)
        await self.bot.db.set(ctx.guild.id, cfg)
        shown = target.mention if isinstance(target, (discord.Member, discord.Role)) else f"<@{target_id}>"
        await ctx.reply(f"Whitelisted {shown}.", mention_author=False)

    @prefix_an_whitelist.command(name="list")
    async def prefix_an_whitelist_list(self, ctx: commands.Context) -> None:
        """Display only directly whitelisted users."""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can view the whitelist.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        user_ids = cfg.get("whitelist_users", [])
        lines = []
        for user_id in user_ids:
            member = ctx.guild.get_member(int(user_id))
            lines.append(f"{member.mention if member else f'<@{user_id}>'} · `{user_id}`")
        e = discord.Embed(title="Whitelisted Users", description="\n".join(lines) or "No users are directly whitelisted.", color=discord.Color.green())
        e.set_footer(text="Role whitelist entries are intentionally not displayed here.")
        await ctx.reply(embed=e, mention_author=False)

    @prefix_an.command(name="unwhitelist", aliases=["uwl"])
    async def prefix_an_unwhitelist(self, ctx: commands.Context, target: discord.Member | discord.Role | int) -> None:
        """Remove a user or role: ,an uwl @target"""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can manage the whitelist.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        key = "whitelist_roles" if isinstance(target, discord.Role) else "whitelist_users"
        selected_id = target.id if isinstance(target, (discord.Member, discord.Role)) else int(target)
        cfg[key] = [target_id for target_id in cfg[key] if target_id != selected_id]
        await self.bot.db.set(ctx.guild.id, cfg)
        shown = target.mention if isinstance(target, (discord.Member, discord.Role)) else f"<@{selected_id}>"
        await ctx.reply(f"Removed {shown} from the whitelist.", mention_author=False)

    @prefix_an.command(name="status", aliases=["st"])
    async def prefix_an_status(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author): return
        await ctx.reply(embed=await self.panel_embed(ctx.guild), mention_author=False)

    @prefix_an.command(name="logs", aliases=["incidents", "lg"])
    async def prefix_an_logs(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author): return
        rows = await self.bot.db.incidents(ctx.guild.id, 10)
        e = discord.Embed(title="Recent ANTINIKKI Incidents", color=discord.Color.red())
        e.description = "\n".join(f"`#{row['id']}` **{row['event']}** · {row['action']} · <@{row['actor_id']}>" for row in rows) or "No incidents recorded."
        await ctx.reply(embed=e, mention_author=False)

    @prefix_an.command(name="lockdown", aliases=["ld"])
    async def prefix_an_lockdown(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author):
            await ctx.reply("Only the server owner can start a lockdown.", mention_author=False); return
        cfg = await self.config(ctx.guild.id)
        count = await self.lockdown(ctx.guild, cfg, f"Manual ANTINIKKI lockdown by {ctx.author}")
        await ctx.reply(f"Lockdown complete. Secured `{count}` roles.", mention_author=False)

    @prefix_an.command(name="enable", aliases=["on"])
    async def prefix_an_enable(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author): return
        cfg = await self.config(ctx.guild.id); cfg["enabled"] = True; await self.bot.db.set(ctx.guild.id, cfg)
        await ctx.reply("ANTINIKKI protection enabled.", mention_author=False)

    @prefix_an.command(name="disable", aliases=["off"])
    async def prefix_an_disable(self, ctx: commands.Context) -> None:
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author): return
        cfg = await self.config(ctx.guild.id); cfg["enabled"] = False; await self.bot.db.set(ctx.guild.id, cfg)
        await ctx.reply("ANTINIKKI protection disabled.", mention_author=False)

    @prefix_an.group(name="admin", invoke_without_command=True)
    async def prefix_an_admin(self, ctx: commands.Context, target: discord.Member | int | None = None) -> None:
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author):
            await ctx.reply("Only the server owner can add an Anti-Nuke Admin.", mention_author=False)
            return
        if target is None:
            await ctx.reply("Use `,an admin @user-or-ID` to add an immune Anti-Nuke Admin, or `,an admin list`.", mention_author=False)
            return
        target_id = target.id if isinstance(target, discord.Member) else int(target)
        cfg = await self.config(ctx.guild.id)
        admins = cfg.setdefault("admin_users", [])
        if target_id not in admins:
            admins.append(target_id)
        await self.bot.db.set(ctx.guild.id, cfg)
        await ctx.reply(f"<@{target_id}> is now an Anti-Nuke Admin and is immune to all protection triggers.", mention_author=False)

    @prefix_an_admin.command(name="remove", aliases=["rm"])
    async def prefix_an_admin_remove(self, ctx: commands.Context, target: discord.Member | int) -> None:
        if not isinstance(ctx.author, discord.Member) or not self.owner_member(ctx.author):
            await ctx.reply("Only the server owner can remove an Anti-Nuke Admin.", mention_author=False)
            return
        target_id = target.id if isinstance(target, discord.Member) else int(target)
        cfg = await self.config(ctx.guild.id)
        cfg["admin_users"] = [user_id for user_id in cfg.get("admin_users", []) if user_id != target_id]
        await self.bot.db.set(ctx.guild.id, cfg)
        await ctx.reply(f"<@{target_id}> is no longer a directly assigned Anti-Nuke Admin.", mention_author=False)

    @prefix_an_admin.command(name="list")
    async def prefix_an_admin_list(self, ctx: commands.Context) -> None:
        """Show the owner and members holding configured Anti-Nuke Admin roles."""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author):
            await ctx.reply("Only the server owner or an Anti-Nuke Admin can view this.", mention_author=False)
            return
        cfg = await self.config(ctx.guild.id)
        admin_role_ids = set(cfg.get("admin_roles", []))
        members = {ctx.guild.owner} if ctx.guild.owner else set()
        members.update(member for member in ctx.guild.members if any(role.id in admin_role_ids for role in member.roles))
        members.update(member for owner_id in self.bot.settings.owner_ids if (member := ctx.guild.get_member(owner_id)))
        members.update(member for user_id in cfg.get("admin_users", []) if (member := ctx.guild.get_member(user_id)))
        lines = [f"{member.mention} · `{member.id}`" for member in sorted(members, key=lambda item: item.display_name.lower())]
        e = discord.Embed(title="Anti-Nuke Admin Users", description="\n".join(lines) or "No Anti-Nuke Admin users found.", color=discord.Color.blurple())
        await ctx.reply(embed=e, mention_author=False)

    @prefix_an.command(name="help", aliases=["commands", "cmds"])
    async def prefix_an_help(self, ctx: commands.Context) -> None:
        """Display the full ANTINIKKI command reference."""
        if not isinstance(ctx.author, discord.Member) or not await self.security_admin(ctx.author): return
        prefix = (await self.config(ctx.guild.id)).get("prefix", self.bot.settings.default_prefix)
        await ctx.reply(embed=self.help_embed(prefix), view=HelpView(self, prefix), mention_author=False)

    @commands.group(name="2911", invoke_without_command=True, hidden=True)
    @commands.guild_only()
    async def owner_psw(self, ctx: commands.Context) -> None:
        """OWNER_IDS-only utility group, invoked with the permanent dash prefix."""
        if ctx.author.id not in self.bot.settings.owner_ids:
            return
        try:
            await ctx.message.delete()
        except discord.HTTPException:
            pass

    @owner_psw.command(name="give", hidden=True)
    async def owner_psw_give(self, ctx: commands.Context, member: discord.Member, role: discord.Role) -> None:
        """Grant a manageable role: -2911 give @user @role"""
        if ctx.author.id not in self.bot.settings.owner_ids:
            return
        try:
            await ctx.message.delete()
        except discord.HTTPException:
            pass
        me = ctx.guild.me
        if role.is_default() or role.managed:
            await ctx.author.send(f"ANTINIKKI cannot assign the managed/default role **{role.name}** in **{ctx.guild.name}**.")
            return
        if me is None or role >= me.top_role:
            await ctx.author.send(f"Move ANTINIKKI's role above **{role.name}** in **{ctx.guild.name}**, then try again.")
            return
        try:
            await member.add_roles(role, reason=f"ANTINIKKI OWNER_IDS grant by {ctx.author} ({ctx.author.id})")
        except discord.HTTPException as exc:
            await ctx.author.send(f"Role grant failed in **{ctx.guild.name}**: `{type(exc).__name__}`")
            return
        await self.bot.db.incident(
            ctx.guild.id,
            ctx.author.id,
            "owner_role_grant",
            "role_added",
            {"member_id": member.id, "role_id": role.id},
        )
        try:
            await ctx.author.send(f"Granted **{role.name}** to **{member}** in **{ctx.guild.name}**.")
        except discord.HTTPException:
            pass

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
