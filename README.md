# ANTINIKKI

ANTINIKKI is a standalone Discord anti-nuke bot designed to detect destructive bursts, identify the responsible account through Discord's audit log, contain the account, lock dangerous role permissions, and record the incident.

## Protection

- Channel creation, deletion, and destructive updates
- Role creation, deletion, permission escalation, and hierarchy changes
- Mass bans and kicks
- Unauthorized bot additions
- Webhook creation bursts
- Server setting changes
- User and role whitelists
- Owner-only configuration
- Automatic or manual emergency lockdown
- Reversible permission lockdown with `/antinikki unlock`
- SQLite configuration and incident history
- Safe audit-log matching using both time and target ID
- Conservative default response: strip manageable roles

ANTINIKKI never attempts to punish the Discord server owner, its configured owners, itself, or whitelisted users and roles. Discord role hierarchy still applies: place ANTINIKKI's role above every role it should be able to secure.

## Northflank setup

1. Upload this repository to GitHub.
2. Create a Northflank combined service from the repository.
3. Add `DISCORD_TOKEN` as a runtime secret variable.
4. Add your Discord user ID to `OWNER_IDS`. Separate multiple IDs with commas.
5. Deploy with the included `nixpacks.toml`; the start command is `python -m antinikki`.

For persistent settings, mount a Northflank volume at `/app/data` if the service uses `/app` as its working directory. Without a volume, settings can be lost when the container is replaced.

## Discord setup

Enable **Server Members Intent** in the Discord Developer Portal. Invite ANTINIKKI with the `bot` and `applications.commands` scopes.

Also enable **Message Content Intent** if you want prefix commands. The default prefix is `!` and can be changed per server.

Required permissions:

- View Audit Log
- Manage Roles
- Manage Channels
- Manage Webhooks
- Ban Members
- Kick Members
- Moderate Members
- View Channels and Send Messages

Move the ANTINIKKI role near the top of the role list. It cannot control members or roles positioned above it.

Run `/antinikki setup` and select a private security-log channel. Then run `/antinikki status` and confirm that no required permissions are missing.

## Commands

- `/antinikki setup` — enable protection and choose a log channel
- `/antinikki status` — inspect protection and permission readiness
- `/antinikki panel` — open the security status panel
- `/antinikki enabled` — turn protection on or off
- `/antinikki incidents` — view the ten most recent security incidents
- `/antinikki whitelist` and `/antinikki unwhitelist` — manage trusted users or roles
- `/antinikki response` — choose strip roles, timeout, kick, ban, or log only
- `/antinikki rule` — configure a protection threshold and time window
- `/antinikki lockdown` — remove dangerous permissions from manageable roles immediately
- `/antinikki unlock` — restore permissions recorded during lockdown

Prefix commands:

- `!antinikki`, `!panel`, or `!security` — open the owner-only panel
- `!prefix` — show the current prefix
- `!prefix ?` — change the prefix to `?`
- `!help` — show the prefix command menu

## Important safety notes

Start with the default `strip_roles` response. Test in a private server before enabling `ban`. Whitelist trusted automation bots that legitimately create channels, roles, or webhooks. Keep the security-log channel private. Never store the bot token in GitHub; use Northflank runtime secrets.
