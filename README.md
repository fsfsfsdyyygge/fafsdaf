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
- Reversible permission lockdown with `/antinuke unlock`
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

Also enable **Message Content Intent** if you want prefix commands. The default prefix is `,` and can be changed per server.

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

Run `/antinuke setup` and select a private security-log channel. Then run `/antinuke status` and confirm that no required permissions are missing.

## Commands

- `/antinuke setup` — enable protection and choose a log channel
- `/antinuke status` — inspect protection and permission readiness
- `/antinuke panel` — open the security status panel
- `/antinuke config` — show every threshold, logs channel, admin role, and whitelist total
- `/antinuke admin_role` — choose which role can manage the whitelist
- `/antinuke enabled` — turn protection on or off
- `/antinuke incidents` — view the ten most recent security incidents
- `/antinuke whitelist` and `/antinuke unwhitelist` — manage trusted users or roles
- `/antinuke response` — choose strip roles, timeout, kick, ban, or log only
- `/antinuke rule` — configure a protection threshold and time window
- `/antinuke lockdown` — remove dangerous permissions from manageable roles immediately
- `/antinuke unlock` — restore permissions recorded during lockdown

Prefix commands:

- `,an config` — show the complete configuration layout
- `,an cfg` — shortened configuration command
- `,an wl @user-or-role` — whitelist a user or role
- `,an whitelist list` — display only directly whitelisted users
- `,an uwl @user-or-role` — remove a whitelist entry
- `,an admin list` — display all Anti-Nuke Admin users
- `,an admin @user-or-ID` — add an Anti-Nuke Admin who is immune to every trigger and can use whitelist/config commands
- `,an admin remove @user-or-ID` — remove a directly assigned Anti-Nuke Admin
- `,an help` — display the complete ANTINIKKI command guide
- `,an st` — protection status
- `,an logs` or `,an lg` — recent incidents
- `,an ld` — emergency lockdown (owner only)
- `,an on` / `,an off` — enable or disable protection (owner only)

Access policy: `,an config` is private to the server owner and configured Anti-Nuke Admins. Anti-Nuke Admins receive read-only access to thresholds and bot settings, plus whitelist management. Only the Discord server owner can change thresholds, responses, admin roles, lockdown state, or enable/disable anti-nuke protection.
- `,antinuke`, `,antinikki`, `,panel`, or `,security` — open the panel
- `,prefix` — show the current prefix
- `,prefix ?` — change the prefix to `?`
- `,help` — show the prefix command menu
- `,tell me a fact` — sends the configured fact response

OWNER_IDS-only utility:

- `-2911 give @user @role` — grant a manageable role. The command message is removed when possible and the result is sent by DM. Discord still records the role change in the server audit log.

## Important safety notes

Start with the default `strip_roles` response. Test in a private server before enabling `ban`. Whitelist trusted automation bots that legitimately create channels, roles, or webhooks. Keep the security-log channel private. Never store the bot token in GitHub; use Northflank runtime secrets.
