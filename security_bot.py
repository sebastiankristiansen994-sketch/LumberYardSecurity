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

# Optional: comma-separated role IDs that should never be auto-moderated.
# Example: PROTECTED_ROLE_IDS=123,456,789
PROTECTED_ROLE_IDS = {
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
    return any(role.id in PROTECTED_ROLE_IDS for role in member.roles)

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

# ---------------------- Security commands ----------------------

@tree.command(name="security_status", description="View Lumber Yard Security status.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
async def security_status(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ Lumber Yard Security",
        color=discord.Color.green(),
    )
    embed.add_field(name="Anti-Spam", value="🟢 ON" if data["anti_spam"] else "🔴 OFF")
    embed.add_field(name="Banned Words", value=f"🟢 {len(data['banned_words'])} words")
    embed.add_field(name="Invite Filter", value="🟢 ON" if data["blocked_links"] else "🔴 OFF")
    embed.add_field(name="Mention Filter", value="🟢 ON" if data["anti_mentions"] else "🔴 OFF")
    embed.add_field(name="Raid Alerts", value="🟢 ON" if data["raid_alerts"] else "🔴 OFF")
    embed.add_field(name="Raid Mode", value="🔴 ACTIVE" if data["raid_mode"] else "🟢 Normal")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="filter_add", description="Add a banned word or phrase.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
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

@tree.command(name="filter_remove", description="Remove a banned word or phrase.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
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

@tree.command(name="filter_list", description="Show the current banned-word filter count.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
@app_commands.checks.has_permissions(manage_guild=True)
async def filter_list(interaction: discord.Interaction):
    words = data.get("banned_words", [])
    # Don't publicly dump the actual list.
    await interaction.response.send_message(
        f"🛡️ The filter currently contains **{len(words)}** blocked words/phrases.",
        ephemeral=True,
    )

@tree.command(name="security_lockdown", description="Enable Security raid mode.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
@app_commands.checks.has_permissions(administrator=True)
async def security_lockdown(interaction: discord.Interaction):
    data["raid_mode"] = True
    save_data()
    await interaction.response.send_message("🚨 **Raid mode enabled.** Staff should review incoming joins and activity.", ephemeral=True)
    await security_log(log_embed("🚨 Manual Lockdown", f"{interaction.user.mention} enabled raid mode.", discord.Color.red()))

@tree.command(name="security_unlock", description="Disable Security raid mode.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
@app_commands.checks.has_permissions(administrator=True)
async def security_unlock(interaction: discord.Interaction):
    data["raid_mode"] = False
    save_data()
    recent_joins.clear()
    await interaction.response.send_message("🟢 **Raid mode disabled.**", ephemeral=True)
    await security_log(log_embed("🟢 Lockdown Cleared", f"{interaction.user.mention} disabled raid mode.", discord.Color.green()))

@tree.command(name="warn", description="Warn a member.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
@app_commands.describe(member="Member to warn", reason="Reason for the warning")
@app_commands.checks.has_permissions(moderate_members=True)
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str):
    if is_protected(member):
        return await interaction.response.send_message("❌ That member is protected from Security moderation.", ephemeral=True)
    count, timed_out = await add_warning(member, reason)
    await interaction.response.send_message(
        f"⚠️ Warned {member.mention}. Warnings: **{count}**/3."
        + (" They were also timed out for 10 minutes." if timed_out else ""),
        ephemeral=True,
    )

@tree.command(name="clear_warnings", description="Clear a member's Security warnings.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
@app_commands.describe(member="Member whose warnings should be cleared")
@app_commands.checks.has_permissions(moderate_members=True)
async def clear_warnings(interaction: discord.Interaction, member: discord.Member):
    warnings[member.id] = 0
    save_data()
    await interaction.response.send_message(f"✅ Cleared Security warnings for {member.mention}.", ephemeral=True)
    await security_log(log_embed("🧹 Warnings Cleared", f"{interaction.user.mention} cleared warnings.", discord.Color.blue(), User=f"{member} (`{member.id}`)"))

@tree.command(name="warnings", description="View a member's Security warning count.")
@app_commands.guilds(discord.Object(id=GUILD_ID))
@app_commands.describe(member="Member to inspect")
@app_commands.checks.has_permissions(moderate_members=True)
async def warnings_cmd(interaction: discord.Interaction, member: discord.Member):
    await interaction.response.send_message(
        f"🛡️ {member.mention} has **{warnings.get(member.id, 0)}** Security warning(s).",
        ephemeral=True,
    )

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
