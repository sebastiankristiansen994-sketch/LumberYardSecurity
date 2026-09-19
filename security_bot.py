import os
import re
import json
import time
import asyncio
from collections import defaultdict, deque
from datetime import timedelta

import discord
from discord.ext import commands
from discord import app_commands

# ============================================================
# Lumber Yard Security
# Separate moderation / anti-raid bot
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN")
GUILD_ID = int(os.getenv("GUILD_ID", "1550118902108004395"))
SECURITY_LOG_CHANNEL_ID = int(os.getenv("SECURITY_LOG_CHANNEL_ID", "1550850357889073212"))
SECURITY_COMMANDS_CHANNEL_ID = int(os.getenv("SECURITY_COMMANDS_CHANNEL_ID", "1550861871400362126"))

# Trusted Lumber Yard roles: Admin, Manager, Lumber Yard Staff.
# These roles are exempt from automatic filters/timeouts.
DEFAULT_PROTECTED_ROLE_IDS = {
    1550201917404356739,  # Admin
    1550201804208218132,  # Manager
    1550119281906163713,  # Lumber Yard Staff
}

# You can still add extra protected roles with PROTECTED_ROLE_IDS on Railway.
PROTECTED_ROLE_IDS = DEFAULT_PROTECTED_ROLE_IDS | {
    int(x.strip())
    for x in os.getenv("PROTECTED_ROLE_IDS", "").split(",")
    if x.strip().isdigit()
}

DATA_FILE = "security_data.json"

# Conservative defaults. Add/remove words with /filter commands.
DEFAULT_BANNED_WORDS = {
    "fuck",
    "fucking",
    "fucked",
    "shit",
    "bullshit",
    "bitch",
    "bastard",
    "asshole",
    "dickhead",
    "motherfucker",
}

DISCORD_INVITE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[A-Za-z0-9-]+",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)

# Spam thresholds are intentionally conservative.
SPAM_WINDOW_SECONDS = 8
SPAM_MESSAGE_LIMIT = 6
DUPLICATE_LIMIT = 4
MENTION_LIMIT = 6

# Raid detection is alert-first. It does not automatically lock the server.
RAID_WINDOW_SECONDS = 20
RAID_JOIN_LIMIT = 5

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

message_history = defaultdict(deque)   # user_id -> timestamps
duplicate_history = defaultdict(deque) # user_id -> (timestamp, normalized_message)
warnings = defaultdict(int)
recent_joins = deque()

data = {
    "banned_words": sorted(DEFAULT_BANNED_WORDS),
    "blocked_links": True,
    "anti_spam": True,
    "anti_mentions": True,
    "raid_alerts": True,
    "raid_mode": False,
    "warnings": {},
    "exempt_roles": [],
    "exempt_channels": [],
}

def load_data():
    global data
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        data.update(loaded)
    except (FileNotFoundError, json.JSONDecodeError):
        save_data()

    for uid, count in data.get("warnings", {}).items():
        try:
            warnings[int(uid)] = int(count)
        except ValueError:
            pass

def save_data():
    data["warnings"] = {str(k): v for k, v in warnings.items()}
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def is_protected(member: discord.Member) -> bool:
    if member.guild_permissions.administrator:
        return True
    if member.id == member.guild.owner_id:
        return True
    protected = PROTECTED_ROLE_IDS | {int(x) for x in data.get("exempt_roles", [])}
    return any(role.id in protected for role in member.roles)

def is_exempt_channel(channel) -> bool:
    exempt = {int(x) for x in data.get("exempt_channels", [])}
    channel_id = getattr(channel, "id", None)
    if channel_id in exempt:
        return True
    parent_id = getattr(channel, "parent_id", None)
    return parent_id in exempt

def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()

def contains_banned_word(text: str):
    lowered = text.casefold()
    for word in data.get("banned_words", []):
        pattern = rf"(?<!\w){re.escape(word.casefold())}(?!\w)"
        if re.search(pattern, lowered):
            return word
    return None

def log_embed(title, description, color=discord.Color.green(), **fields):
    embed = discord.Embed(title=title, description=description, color=color)
    for name, value in fields.items():
        embed.add_field(name=name, value=str(value)[:1024], inline=True)
    return embed

async def security_log(embed: discord.Embed):
    channel = bot.get_channel(SECURITY_LOG_CHANNEL_ID)
    if channel is None:
        try:
            channel = await bot.fetch_channel(SECURITY_LOG_CHANNEL_ID)
        except discord.HTTPException:
            return
    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        pass

async def safe_delete(message):
    try:
        await message.delete()
        return True
    except (discord.Forbidden, discord.NotFound, discord.HTTPException):
        return False

async def add_warning(member: discord.Member, reason: str):
    warnings[member.id] += 1
    count = warnings[member.id]
    save_data()

    timeout_applied = False
    # Escalation: 1 warning, 2 warnings, then 10-minute timeout at 3+.
    if count >= 3 and member.is_timed_out() is False:
        try:
            await member.timeout(timedelta(minutes=10), reason=f"Lumber Yard Security: {reason}")
            timeout_applied = True
        except (discord.Forbidden, discord.HTTPException):
            pass

    await security_log(
        log_embed(
            "⚠️ Security Warning",
            f"{member.mention} received a moderation warning.",
            discord.Color.orange(),
            User=f"{member} (`{member.id}`)",
            Reason=reason,
            Warnings=count,
            Action="10-minute timeout" if timeout_applied else "Warning",
        )
    )
    return count, timeout_applied

async def moderate_message(message: discord.Message):
    if not message.guild or message.author.bot:
        return

    member = message.author
    if not isinstance(member, discord.Member) or is_protected(member):
        return
    if is_exempt_channel(message.channel):
        return

    content = message.content or ""
    reason = None

    if data.get("blocked_links", True) and DISCORD_INVITE_RE.search(content):
        reason = "Unauthorized Discord invite"

    banned = contains_banned_word(content)
    if banned:
        reason = f"Prohibited language ({banned})"

    if data.get("anti_mentions", True):
        total_mentions = len(message.mentions) + len(message.role_mentions)
        if message.mention_everyone:
            total_mentions += 10
        if total_mentions >= MENTION_LIMIT:
            reason = "Mention spam"

    now = time.monotonic()
    history = message_history[member.id]
    while history and now - history[0] > SPAM_WINDOW_SECONDS:
        history.popleft()
    history.append(now)

    dupes = duplicate_history[member.id]
    while dupes and now - dupes[0][0] > SPAM_WINDOW_SECONDS:
        dupes.popleft()
    normalized = normalize(content)
    dupes.append((now, normalized))

    if data.get("anti_spam", True) and len(history) >= SPAM_MESSAGE_LIMIT:
        reason = "Message flooding"
    if data.get("anti_spam", True) and normalized and sum(
        1 for _, msg in dupes if msg == normalized
    ) >= DUPLICATE_LIMIT:
        reason = "Repeated message spam"

    if reason:
        deleted = await safe_delete(message)
        if deleted:
            count, timed_out = await add_warning(member, reason)
            try:
                notice = await message.channel.send(
                    f"⚠️ {member.mention}, your message was removed: **{reason}**. "
                    f"Warning **{count}**/3."
                    + (" You have been timed out for 10 minutes." if timed_out else ""),
                    delete_after=7,
                )
            except discord.HTTPException:
                pass

@bot.event
async def on_ready():
    load_data()
    try:
        guild = discord.Object(id=GUILD_ID)
        synced = await tree.sync(guild=guild)
        print(f"Logged in as {bot.user} | synced {len(synced)} security commands")
    except Exception as exc:
        print(f"Command sync error: {exc}")
    print("Lumber Yard Security is online.")

@bot.event
async def on_member_join(member: discord.Member):
    if member.guild.id != GUILD_ID or not data.get("raid_alerts", True):
        return

    now = time.monotonic()
    recent_joins.append((now, member.id))
    while recent_joins and now - recent_joins[0][0] > RAID_WINDOW_SECONDS:
        recent_joins.popleft()

    if len(recent_joins) >= RAID_JOIN_LIMIT:
        data["raid_mode"] = True
        save_data()

        await security_log(
            log_embed(
                "🚨 Possible Raid Detected",
                f"**{len(recent_joins)}** members joined within **{RAID_WINDOW_SECONDS}s**.",
                discord.Color.red(),
                Server=member.guild.name,
                Latest_Join=f"{member} (`{member.id}`)",
                Action="Raid mode flagged — staff review required",
            )
        )

@bot.event
async def on_message(message):
    await moderate_message(message)
    await bot.process_commands(message)

# ---------------------- Clean slash command groups ----------------------
# Discord will now show only /security, /filter and /warn at the top level.

security_group = app_commands.Group(name="security", description="Lumber Yard Security controls")
filter_group = app_commands.Group(name="filter", description="Banned-language filter controls")
warn_group = app_commands.Group(name="warn", description="Member warning controls")

@security_group.command(name="status", description="View all Security systems and exemptions.")
async def security_status(interaction: discord.Interaction):
    embed = discord.Embed(title="🛡️ Lumber Yard Security", color=discord.Color.green())
    embed.add_field(name="Anti-Spam", value="🟢 ON" if data["anti_spam"] else "🔴 OFF")
    embed.add_field(name="Banned Words", value=f"🟢 {len(data['banned_words'])} words")
    embed.add_field(name="Invite Filter", value="🟢 ON" if data["blocked_links"] else "🔴 OFF")
    embed.add_field(name="Mention Filter", value="🟢 ON" if data["anti_mentions"] else "🔴 OFF")
    embed.add_field(name="Raid Alerts", value="🟢 ON" if data["raid_alerts"] else "🔴 OFF")
    embed.add_field(name="Raid Mode", value="🔴 ACTIVE" if data["raid_mode"] else "🟢 Normal")
    embed.add_field(name="Extra Exempt Roles", value=str(len(data.get("exempt_roles", []))))
    embed.add_field(name="Exempt Channels", value=str(len(data.get("exempt_channels", []))))
    await interaction.response.send_message(embed=embed, ephemeral=True)

@security_group.command(name="setup", description="Post or refresh the permanent Security commands panel.")
async def security_setup(interaction: discord.Interaction):
    if not interaction.guild or interaction.user.id != interaction.guild.owner_id:
        return await interaction.response.send_message("❌ Only the server owner can use this command.", ephemeral=True)

    channel = interaction.guild.get_channel(SECURITY_COMMANDS_CHANNEL_ID)
    if channel is None:
        try:
            channel = await bot.fetch_channel(SECURITY_COMMANDS_CHANNEL_ID)
        except discord.HTTPException:
            return await interaction.response.send_message("❌ I can't access the Security Commands channel.", ephemeral=True)

    await interaction.response.defer(ephemeral=True)

    # Refresh only this bot's previous command panels; leave human messages alone.
    try:
        async for old in channel.history(limit=100):
            if old.author.id == bot.user.id and old.embeds and old.embeds[0].title == "🛡️ Lumber Yard Security — Commands":
                try:
                    await old.delete()
                except discord.HTTPException:
                    pass
    except (discord.Forbidden, discord.HTTPException):
        pass

    embed = discord.Embed(
        title="🛡️ Lumber Yard Security — Commands",
        description=(
            "Security and moderation controls for **Lumber Yard**.\n"
            "Commands are grouped to keep the slash-command menu clean."
        ),
        color=discord.Color.green(),
    )
    embed.add_field(
        name="🛡️ /security",
        value=(
            "`/security status` — View protection status\n"
            "`/security settings` — Turn protections on/off\n"
            "`/security lockdown` — Enable emergency raid mode\n"
            "`/security unlock` — Disable emergency raid mode\n"
            "`/security exempt-role` — Manage trusted roles\n"
            "`/security exempt-channel` — Manage trusted channels\n"
            "`/security exemptions` — View exemptions\n"
            "`/security setup` — Refresh this panel (Owner only)"
        ),
        inline=False,
    )
    embed.add_field(
        name="🚫 /filter",
        value=(
            "`/filter add` — Block a word or phrase\n"
            "`/filter remove` — Remove a blocked word or phrase\n"
            "`/filter list` — View filter information"
        ),
        inline=False,
    )
    embed.add_field(
        name="⚠️ /warn",
        value=(
            "`/warn add` — Warn a member\n"
            "`/warn check` — Check a member's warnings\n"
            "`/warn clear` — Clear a member's warnings"
        ),
        inline=False,
    )
    embed.add_field(
        name="🔰 Automatic Protection Exemptions",
        value="Server Owner • Admin • Manager • Lumber Yard Staff",
        inline=False,
    )
    embed.set_footer(text="Lumber Yard Security • Protecting the community")

    try:
        panel = await channel.send(embed=embed)
        try:
            await panel.pin(reason="Permanent Lumber Yard Security commands panel")
        except (discord.Forbidden, discord.HTTPException):
            pass
    except (discord.Forbidden, discord.HTTPException):
        return await interaction.followup.send("❌ I couldn't post in the Security Commands channel. Check my channel permissions.", ephemeral=True)

    await interaction.followup.send(f"✅ Security commands panel refreshed in {channel.mention}.", ephemeral=True)


@security_group.command(name="lockdown", description="Enable emergency raid mode.")
@app_commands.checks.has_permissions(administrator=True)
async def security_lockdown(interaction: discord.Interaction):
    data["raid_mode"] = True
    save_data()
    await interaction.response.send_message("🚨 **Raid mode enabled.** Staff should review incoming joins and activity.", ephemeral=True)
    await security_log(log_embed("🚨 Manual Lockdown", f"{interaction.user.mention} enabled raid mode.", discord.Color.red()))

@security_group.command(name="unlock", description="Disable emergency raid mode.")
@app_commands.checks.has_permissions(administrator=True)
async def security_unlock(interaction: discord.Interaction):
    data["raid_mode"] = False
    save_data()
    recent_joins.clear()
    await interaction.response.send_message("🟢 **Raid mode disabled.**", ephemeral=True)
    await security_log(log_embed("🟢 Lockdown Cleared", f"{interaction.user.mention} disabled raid mode.", discord.Color.green()))

@security_group.command(name="settings", description="Turn a Security protection on or off.")
@app_commands.describe(feature="Protection to change", enabled="Turn it on or off")
@app_commands.choices(feature=[
    app_commands.Choice(name="Anti-Spam", value="anti_spam"),
    app_commands.Choice(name="Invite Filter", value="blocked_links"),
    app_commands.Choice(name="Mention Filter", value="anti_mentions"),
    app_commands.Choice(name="Raid Alerts", value="raid_alerts"),
])
@app_commands.checks.has_permissions(administrator=True)
async def security_settings(interaction: discord.Interaction, feature: app_commands.Choice[str], enabled: bool):
    data[feature.value] = enabled
    save_data()
    await interaction.response.send_message(
        f"✅ **{feature.name}** is now **{'ON' if enabled else 'OFF'}**.", ephemeral=True
    )
    await security_log(log_embed("⚙️ Security Setting Changed", f"{interaction.user.mention} changed a Security setting.", discord.Color.blue(), Setting=feature.name, Value="ON" if enabled else "OFF"))

@security_group.command(name="exempt-role", description="Add or remove a role from automatic moderation exemptions.")
@app_commands.describe(role="Role to change", exempt="True = exempt, False = remove exemption")
@app_commands.checks.has_permissions(administrator=True)
async def security_exempt_role(interaction: discord.Interaction, role: discord.Role, exempt: bool):
    if role.id in DEFAULT_PROTECTED_ROLE_IDS and not exempt:
        return await interaction.response.send_message("ℹ️ Admin, Manager, and Lumber Yard Staff are permanently protected in the bot configuration.", ephemeral=True)
    ids = {int(x) for x in data.get("exempt_roles", [])}
    if exempt:
        ids.add(role.id)
    else:
        ids.discard(role.id)
    data["exempt_roles"] = sorted(ids)
    save_data()
    await interaction.response.send_message(f"✅ {role.mention} is {'now exempt from' if exempt else 'no longer exempt from'} automatic Security moderation.", ephemeral=True)

@security_group.command(name="exempt-channel", description="Add or remove a channel from automatic moderation exemptions.")
@app_commands.describe(channel="Channel to change", exempt="True = exempt, False = remove exemption")
@app_commands.checks.has_permissions(administrator=True)
async def security_exempt_channel(interaction: discord.Interaction, channel: discord.TextChannel, exempt: bool):
    ids = {int(x) for x in data.get("exempt_channels", [])}
    if exempt:
        ids.add(channel.id)
    else:
        ids.discard(channel.id)
    data["exempt_channels"] = sorted(ids)
    save_data()
    await interaction.response.send_message(f"✅ {channel.mention} is {'now exempt from' if exempt else 'no longer exempt from'} automatic Security moderation.", ephemeral=True)

@security_group.command(name="exemptions", description="Show current trusted role/channel exemptions.")
@app_commands.checks.has_permissions(manage_guild=True)
async def security_exemptions(interaction: discord.Interaction):
    fixed_roles = [interaction.guild.get_role(x) for x in DEFAULT_PROTECTED_ROLE_IDS]
    extra_roles = [interaction.guild.get_role(int(x)) for x in data.get("exempt_roles", [])]
    channels = [interaction.guild.get_channel(int(x)) for x in data.get("exempt_channels", [])]
    role_names = [r.mention for r in fixed_roles + extra_roles if r]
    channel_names = [c.mention for c in channels if c]
    embed = discord.Embed(title="🛡️ Security Exemptions", color=discord.Color.green())
    embed.add_field(name="Roles", value="\n".join(role_names) or "None", inline=False)
    embed.add_field(name="Channels", value="\n".join(channel_names) or "None", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@filter_group.command(name="add", description="Add a banned word or phrase.")
@app_commands.describe(word="Word or phrase to block")
@app_commands.checks.has_permissions(manage_guild=True)
async def filter_add(interaction: discord.Interaction, word: str):
    word = normalize(word)
    if not word or len(word) > 100:
        return await interaction.response.send_message("❌ Invalid word/phrase.", ephemeral=True)
    words = set(data.get("banned_words", []))
    if word in words:
        return await interaction.response.send_message("ℹ️ That word is already blocked.", ephemeral=True)
    words.add(word)
    data["banned_words"] = sorted(words)
    save_data()
    await interaction.response.send_message(f"✅ Added `{word}` to the banned-word filter.", ephemeral=True)
    await security_log(log_embed("📝 Filter Updated", f"{interaction.user.mention} added a banned word.", discord.Color.blue(), Word=word))

@filter_group.command(name="remove", description="Remove a banned word or phrase.")
@app_commands.describe(word="Word or phrase to unblock")
@app_commands.checks.has_permissions(manage_guild=True)
async def filter_remove(interaction: discord.Interaction, word: str):
    word = normalize(word)
    words = set(data.get("banned_words", []))
    if word not in words:
        return await interaction.response.send_message("❌ That word isn't in the filter.", ephemeral=True)
    words.remove(word)
    data["banned_words"] = sorted(words)
    save_data()
    await interaction.response.send_message(f"✅ Removed `{word}` from the banned-word filter.", ephemeral=True)

@filter_group.command(name="list", description="Show the banned-word filter count.")
@app_commands.checks.has_permissions(manage_guild=True)
async def filter_list(interaction: discord.Interaction):
    await interaction.response.send_message(
        f"🛡️ The filter currently contains **{len(data.get('banned_words', []))}** blocked words/phrases.",
        ephemeral=True,
    )

@warn_group.command(name="add", description="Warn a member.")
@app_commands.describe(member="Member to warn", reason="Reason for the warning")
@app_commands.checks.has_permissions(moderate_members=True)
async def warn_add(interaction: discord.Interaction, member: discord.Member, reason: str):
    if is_protected(member):
        return await interaction.response.send_message("❌ That member is protected from Security moderation.", ephemeral=True)
    count, timed_out = await add_warning(member, reason)
    await interaction.response.send_message(
        f"⚠️ Warned {member.mention}. Warnings: **{count}**/3."
        + (" They were also timed out for 10 minutes." if timed_out else ""),
        ephemeral=True,
    )

@warn_group.command(name="check", description="View a member's Security warning count.")
@app_commands.describe(member="Member to inspect")
@app_commands.checks.has_permissions(moderate_members=True)
async def warn_check(interaction: discord.Interaction, member: discord.Member):
    await interaction.response.send_message(
        f"🛡️ {member.mention} has **{warnings.get(member.id, 0)}** Security warning(s).", ephemeral=True
    )

@warn_group.command(name="clear", description="Clear a member's Security warnings.")
@app_commands.describe(member="Member whose warnings should be cleared")
@app_commands.checks.has_permissions(moderate_members=True)
async def warn_clear(interaction: discord.Interaction, member: discord.Member):
    warnings[member.id] = 0
    save_data()
    await interaction.response.send_message(f"✅ Cleared Security warnings for {member.mention}.", ephemeral=True)
    await security_log(log_embed("🧹 Warnings Cleared", f"{interaction.user.mention} cleared warnings.", discord.Color.blue(), User=f"{member} (`{member.id}`)"))

# Register only the three top-level command groups.
tree.add_command(security_group, guild=discord.Object(id=GUILD_ID))
tree.add_command(filter_group, guild=discord.Object(id=GUILD_ID))
tree.add_command(warn_group, guild=discord.Object(id=GUILD_ID))

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.errors.MissingPermissions):
        msg = "❌ You don't have permission to use that Security command."
    else:
        msg = "❌ Something went wrong while running that Security command."
        print(f"Command error: {error}")

    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)

if __name__ == "__main__":
    load_data()
    if not TOKEN:
        raise RuntimeError("DISCORD_TOKEN environment variable is missing.")
    bot.run(TOKEN)
