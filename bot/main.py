import os
import re
import sys
from pathlib import Path
from typing import Any

import discord
from aiohttp import web
from discord.ext import commands
from dotenv import load_dotenv


BOT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BOT_DIR.parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.firestore.notifications_repository import NotificationsRepository

load_dotenv(BACKEND_ROOT / ".env")


class ThreatIntelBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        self.web_runner = None
        self.web_site = None
        # Temporary runtime mapping. Without Firestore/database this is lost on bot restart.
        self.ticket_registry: dict[str, dict[str, Any]] = {}

    async def setup_hook(self):
        await self.tree.sync()
        print("Slash commands synced globally.")

        app = web.Application()
        app.router.add_post("/api/ticket", handle_ticket_post)
        app.router.add_post("/api/supervisor-alert", handle_supervisor_alert)
        app.router.add_post("/api/warning", handle_warning_post)
        self.web_runner = web.AppRunner(app)
        await self.web_runner.setup()
        self.web_site = web.TCPSite(self.web_runner, "127.0.0.1", 8001)
        await self.web_site.start()
        print("Bot HTTP server listening on http://127.0.0.1:8001")

    async def on_ready(self):
        print(f"Logged in as {self.user.name} (ID: {self.user.id})")
        print("Discord Threat Intel Bot is ready and listening.")

    async def create_ticket(self, payload: dict[str, Any]) -> bool:
        case_id = str(payload.get("case_id", "")).strip()
        alert_title = str(payload.get("alert_title", "")).strip()
        requester_username = str(payload.get("requester_username", "")).strip() or "junior"
        severity = str(payload.get("severity", "")).strip() or "Medium/High"
        confidence_score = payload.get("confidence_score")
        risk_explanation = str(payload.get("risk_explanation") or "Risk explanation is not available.")
        warning_preview = payload.get("warning_preview") or {}

        if not self.guilds:
            print("Error: Bot is not joined to any guilds yet.")
            return False

        guild = self.guilds[0]
        category = discord.utils.get(guild.categories, name="Tickets")
        if not category:
            try:
                category = await guild.create_category("Tickets")
                print("Created 'Tickets' category.")
            except Exception as exc:
                print(f"Failed to create category 'Tickets': {exc}")
                return False

        channel_name = _build_ticket_channel_name(alert_title, requester_username)

        try:
            channel = discord.utils.get(category.text_channels, name=channel_name)
            if not channel:
                channel = await guild.create_text_channel(
                    name=channel_name,
                    category=category,
                    topic=f"Case ID: {case_id} | Severity: {severity} | Status: open",
                )
                print(f"Created ticket channel: {channel.name}")
            else:
                print(f"Channel {channel_name} already exists.")

            self.ticket_registry[case_id] = {
                "channel_id": channel.id,
                "channel_name": channel.name,
                "alert_title": alert_title,
                "requester_username": requester_username,
                "severity": severity,
                "status": "open",
            }

            await channel.send(embed=_build_initial_warning_embed(
                case_id=case_id,
                alert_title=alert_title,
                severity=severity,
                confidence_score=confidence_score,
                risk_explanation=risk_explanation,
                warning_preview=warning_preview,
            ))
            return True
        except Exception as exc:
            print(f"Failed to create ticket channel: {exc}")
            return False

    async def send_warning_event(self, payload: dict[str, Any]) -> bool:
        case_id = str(payload.get("case_id", "")).strip()
        alert_title = str(payload.get("alert_title", "")).strip()
        warning_type = str(payload.get("warning_type", "")).strip()
        severity = str(payload.get("severity", "")).strip() or "unknown"
        confidence_score = payload.get("confidence_score")
        event_payload = payload.get("payload") or {}

        if not self.guilds:
            print("Error: Bot is not joined to any guilds yet.")
            return False

        channel = await _find_ticket_or_fallback_channel(self.guilds[0], case_id)
        if not channel:
            print(f"Error: No ticket channel found for warning event case={case_id}.")
            return False

        try:
            if warning_type == "priority_action_warning":
                await channel.send(embed=_build_priority_actions_embed(event_payload.get("priority_actions") or []))
                approval_embed = _build_approval_required_embed(event_payload.get("priority_actions") or [])
                if approval_embed:
                    await channel.send(embed=approval_embed)
            elif warning_type == "step_warning":
                await channel.send(embed=_build_step_warning_embed(
                    event_payload.get("current_step") or {},
                    event_payload.get("evidence_to_check") or [],
                ))
            elif warning_type == "escalation_warning":
                await channel.send(embed=_build_escalation_warning_embed(
                    alert_title=alert_title,
                    severity=severity,
                    confidence_score=confidence_score,
                    payload=event_payload,
                ))
            elif warning_type == "final_summary":
                await channel.send(embed=_build_final_summary_embed(
                    alert_title=alert_title,
                    severity=severity,
                    confidence_score=confidence_score,
                    payload=event_payload,
                ))
            else:
                await channel.send(embed=_build_generic_warning_embed(warning_type, event_payload))

            print(f"Sent warning event {warning_type} to channel {channel.name}")
            return True
        except Exception as exc:
            print(f"Failed to send warning event: {exc}")
            return False

    async def notify_supervisor(self, payload: dict[str, Any]) -> bool:
        case_id = str(payload.get("case_id", "")).strip()
        alert_title = str(payload.get("alert_title", "")).strip()
        struggle = str(payload.get("struggle", "")).strip()
        question = str(payload.get("question", "")).strip()
        severity = str(payload.get("severity", "")).strip() or "unknown"
        confidence_score = payload.get("confidence_score")
        current_step = str(payload.get("current_step", "")).strip() or "Not provided"
        completed_steps = payload.get("completed_steps") or []
        evidence_available = payload.get("evidence_available") or []
        current_warning = str(payload.get("current_warning", "")).strip() or "No warning text provided."

        if not self.guilds:
            print("Error: Bot is not joined to any guilds yet.")
            return False

        guild = self.guilds[0]
        channel = await _find_ticket_or_fallback_channel(guild, case_id)
        if not channel:
            print("Error: No destination channel found to notify supervisor.")
            return False

        ticket_channel_mention = channel.mention if channel.category and channel.category.name == "Tickets" else "N/A"
        tag_mention = _resolve_supervisor_mention()

        embed = discord.Embed(
            title="[ASK-FOR-HELP] Supervisor assistance requested",
            description="A junior analyst needs help with the active investigation.",
            color=discord.Color.orange(),
        )
        embed.add_field(name="Case ID", value=case_id, inline=True)
        embed.add_field(name="Alert Title", value=alert_title, inline=True)
        embed.add_field(name="Severity / Confidence", value=f"{severity} / {_format_confidence(confidence_score)}", inline=True)
        embed.add_field(name="Investigation Channel", value=ticket_channel_mention, inline=True)
        embed.add_field(name="Current Step", value=_trim(current_step), inline=False)
        embed.add_field(name="Completed Steps", value=_format_bullets(completed_steps) or "None yet", inline=False)
        embed.add_field(name="Evidence Available", value=_format_bullets(evidence_available) or "None provided", inline=False)
        embed.add_field(name="Current Warning", value=_trim(current_warning), inline=False)
        embed.add_field(name="What they are struggling with", value=_trim(struggle), inline=False)
        embed.add_field(name="Specific question", value=_trim(question), inline=False)
        embed.add_field(name="Notify", value=tag_mention, inline=False)
        embed.set_footer(text="Warning type: ask-for-help")

        try:
            await channel.send(
                content=f"{tag_mention} Supervisor assistance requested.",
                embed=embed,
                allowed_mentions=discord.AllowedMentions(users=True, roles=True),
            )
            print(f"Sent supervisor alert to channel {channel.name}")
            return True
        except Exception as exc:
            print(f"Failed to send supervisor alert: {exc}")
            return False


bot = ThreatIntelBot()


def _trim(value: Any, limit: int = 1000) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text or "N/A"
    return text[: limit - 3].rstrip() + "..."


def _format_bullets(values: list[Any], limit: int = 6) -> str:
    clean_values = [str(value).strip() for value in values if str(value).strip()]
    if not clean_values:
        return ""
    return "\n".join(f"- {_trim(value, 180)}" for value in clean_values[:limit])


def _format_confidence(value: Any) -> str:
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "unknown"


def _safe_channel_part(value: str, fallback: str) -> str:
    safe_value = re.sub(r"[^a-zA-Z0-9_-]", "-", value.strip()).lower()
    safe_value = re.sub(r"-+", "-", safe_value).strip("-")
    return safe_value or fallback


def _build_ticket_channel_name(alert_title: str, requester_username: str = "junior") -> str:
    safe_user = _safe_channel_part(requester_username, "junior")
    safe_title = _safe_channel_part(alert_title, "untitled-case")
    safe_title = re.sub(r"-+", "-", safe_title).strip("-") or "untitled-case"
    return f"{safe_user}-{safe_title}"[:95]


def _extract_case_id_from_channel(channel: discord.abc.GuildChannel) -> str:
    topic = getattr(channel, "topic", "") or ""
    match = re.search(r"Case ID:\s*([^|]+)", topic)
    return match.group(1).strip() if match else ""


def _severity_color(severity: str) -> discord.Color:
    normalized = severity.lower()
    if normalized == "critical":
        return discord.Color.red()
    if normalized in {"high", "medium/high"}:
        return discord.Color.orange()
    return discord.Color.gold()


def _resolve_supervisor_mention() -> str:
    supervisor_user_id = (
        os.getenv("DISCORD_SUPERVISOR_USER_ID")
        or os.getenv("DISCORD_ANALYST_USER_ID")
    )
    supervisor_role_id = (
        os.getenv("DISCORD_SUPERVISOR_ROLE_ID")
        or os.getenv("DISCORD_ANALYST_ROLE_ID")
        or os.getenv("DISCORD_ROLE_ID")
    )
    if supervisor_user_id:
        return f"<@{supervisor_user_id}>"
    if supervisor_role_id:
        return f"<@&{supervisor_role_id}>"
    return "@supervisor"


async def _find_ticket_or_fallback_channel(guild: discord.Guild, case_id: str) -> discord.TextChannel | None:
    category = discord.utils.get(guild.categories, name="Tickets")
    if category:
        for channel in category.text_channels:
            if channel.topic and case_id in channel.topic:
                return channel

    channel_id = os.getenv("DISCORD_ESCALATION_CHANNEL_ID")
    if channel_id:
        try:
            channel = bot.get_channel(int(channel_id)) or await bot.fetch_channel(int(channel_id))
            if isinstance(channel, discord.TextChannel):
                return channel
        except Exception as exc:
            print(f"Failed to fetch DISCORD_ESCALATION_CHANNEL_ID={channel_id}: {exc}")

    return (
        discord.utils.get(guild.text_channels, name="supervisor-alerts")
        or discord.utils.get(guild.text_channels, name="general")
        or next((ch for ch in guild.channels if isinstance(ch, discord.TextChannel)), None)
    )


def _build_initial_warning_embed(
    case_id: str,
    alert_title: str,
    severity: str,
    confidence_score: Any,
    risk_explanation: str,
    warning_preview: dict[str, Any],
) -> discord.Embed:
    message = warning_preview.get("message") or "Hunt package generated. Analyst review is required before escalation."
    recipient = warning_preview.get("recipient_role") or "soc_channel"
    should_send = bool(warning_preview.get("should_send", False))
    requires_confirmation = bool(warning_preview.get("requires_confirmation", True))

    embed = discord.Embed(
        title="[INITIAL WARNING] Hunt package generated",
        description=_trim(message, 1500),
        color=_severity_color(severity),
    )
    embed.add_field(name="Case ID", value=case_id, inline=True)
    embed.add_field(name="Alert Title", value=alert_title, inline=True)
    embed.add_field(name="Severity / Confidence", value=f"{severity} / {_format_confidence(confidence_score)}", inline=True)
    embed.add_field(name="Risk", value=_trim(risk_explanation), inline=False)
    embed.add_field(name="Recipient Role", value=str(recipient), inline=True)
    embed.add_field(name="Send Recommended", value=str(should_send), inline=True)
    embed.add_field(name="Requires Confirmation", value=str(requires_confirmation), inline=True)
    embed.set_footer(text="Warning type: initial_warning")
    return embed


def _build_priority_actions_embed(priority_actions: list[dict[str, Any]]) -> discord.Embed:
    embed = discord.Embed(
        title="[PRIORITY ACTION WARNING] First actions to reduce risk",
        description="Review these actions before continuing the investigation.",
        color=discord.Color.blue(),
    )
    if not priority_actions:
        embed.add_field(name="Priority Actions", value="No priority actions were provided.", inline=False)
        return embed

    for action in priority_actions[:5]:
        title = action.get("title") or "Priority action"
        body = (
            f"Why: {_trim(action.get('why_it_matters'), 300)}\n"
            f"When: {action.get('recommended_time') or 'not specified'}\n"
            f"Approval required: {bool(action.get('requires_approval', False))}"
        )
        embed.add_field(name=_trim(title, 250), value=_trim(body), inline=False)
    embed.set_footer(text="Warning type: priority_action_warning")
    return embed


def _build_approval_required_embed(priority_actions: list[dict[str, Any]]) -> discord.Embed | None:
    approval_actions = [action for action in priority_actions if action.get("requires_approval")]
    if not approval_actions:
        return None

    embed = discord.Embed(
        title="[APPROVAL REQUIRED] Do not perform disruptive action yet",
        description="These actions require supervisor approval before execution.",
        color=discord.Color.red(),
    )
    for action in approval_actions[:5]:
        embed.add_field(
            name=_trim(action.get("title") or "Action requiring approval", 250),
            value=_trim(action.get("why_it_matters") or "Approval is required before this action.", 900),
            inline=False,
        )
    embed.set_footer(text="Warning type: approval_required")
    return embed


def _build_step_warning_embed(current_step: dict[str, Any], evidence_to_check: list[Any]) -> discord.Embed:
    title = current_step.get("title") if isinstance(current_step, dict) else None
    description = current_step.get("description") if isinstance(current_step, dict) else None
    step_title = title or "Confirm alert context"
    step_description = description or "Validate the primary evidence before escalating the case."

    embed = discord.Embed(
        title="[STEP WARNING] Current investigation step",
        description=_trim(step_description, 1200),
        color=discord.Color.purple(),
    )
    embed.add_field(name="Current Step", value=_trim(step_title), inline=False)
    embed.add_field(name="Evidence To Check", value=_format_bullets(evidence_to_check) or "No evidence list provided.", inline=False)
    embed.set_footer(text="Warning type: step_warning")
    return embed


def _build_final_summary_template_embed() -> discord.Embed:
    embed = discord.Embed(
        title="[FINAL SUMMARY] Close ticket only after review",
        description=(
            "Before closing this ticket, summarize confirmed evidence, false-positive checks, "
            "actions taken, and whether supervisor approval was required."
        ),
        color=discord.Color.green(),
    )
    embed.add_field(
        name="Required Closure Notes",
        value=(
            "- Confirmed evidence\n"
            "- Scope of affected user/host/resource\n"
            "- False-positive decision\n"
            "- Escalation or closure reason"
        ),
        inline=False,
    )
    embed.set_footer(text="Warning type: final_summary")
    return embed


def _build_escalation_warning_embed(
    alert_title: str,
    severity: str,
    confidence_score: Any,
    payload: dict[str, Any],
) -> discord.Embed:
    embed = discord.Embed(
        title="[ESCALATION WARNING] Evidence confirmed and escalation may be needed",
        description=_trim(payload.get("escalation_condition") or "Escalation condition was confirmed by the analyst."),
        color=discord.Color.red(),
    )
    embed.add_field(name="Alert Title", value=_trim(alert_title, 250), inline=True)
    embed.add_field(name="Severity / Confidence", value=f"{severity} / {_format_confidence(confidence_score)}", inline=True)
    embed.add_field(name="Confirmed Evidence", value=_format_bullets(payload.get("confirmed_evidence") or []) or "Analyst confirmed evidence in the app.", inline=False)
    embed.add_field(name="Correlation Logic", value=_trim(payload.get("correlation_logic"), 1000), inline=False)
    embed.set_footer(text="Warning type: escalation_warning")
    return embed


def _build_final_summary_embed(
    alert_title: str,
    severity: str,
    confidence_score: Any,
    payload: dict[str, Any],
) -> discord.Embed:
    embed = discord.Embed(
        title="[FINAL SUMMARY] Case ended in hunt assistant",
        description=_trim(payload.get("summary") or "The analyst ended the case from the hunt report."),
        color=discord.Color.green(),
    )
    embed.add_field(name="Alert Title", value=_trim(alert_title, 250), inline=True)
    embed.add_field(name="Severity / Confidence", value=f"{severity} / {_format_confidence(confidence_score)}", inline=True)
    embed.add_field(name="Completed Steps", value=_format_bullets(payload.get("completed_steps") or []) or "No completed steps provided.", inline=False)
    embed.add_field(name="Evidence Reviewed", value=_format_bullets(payload.get("evidence_reviewed") or []) or "No evidence summary provided.", inline=False)
    embed.add_field(name="Recommended Response", value=_format_bullets(payload.get("recommended_response") or []) or "No response summary provided.", inline=False)
    embed.set_footer(text="Warning type: final_summary")
    return embed


def _build_generic_warning_embed(warning_type: str, payload: dict[str, Any]) -> discord.Embed:
    embed = discord.Embed(
        title=f"[{warning_type.upper() or 'WARNING'}] Hunt assistant event",
        description=_trim(payload.get("message") or "Warning event sent from hunt assistant."),
        color=discord.Color.gold(),
    )
    embed.set_footer(text=f"Warning type: {warning_type or 'unknown'}")
    return embed


async def handle_ticket_post(request):
    try:
        data = await request.json()
        case_id = data.get("case_id")
        alert_title = data.get("alert_title")
        severity = data.get("severity")

        if not case_id or not alert_title or not severity:
            return web.json_response({"status": "error", "message": "Missing required fields"}, status=400)

        success = await bot.create_ticket(data)
        if success:
            return web.json_response({"status": "success", "mapping": bot.ticket_registry.get(case_id, {})})
        return web.json_response({"status": "error", "message": "Failed to create ticket channel"}, status=500)
    except Exception as exc:
        return web.json_response({"status": "error", "message": str(exc)}, status=500)


async def handle_supervisor_alert(request):
    try:
        data = await request.json()
        case_id = data.get("case_id")
        alert_title = data.get("alert_title")
        struggle = data.get("struggle")
        question = data.get("question")

        if not case_id or not alert_title or not struggle or not question:
            return web.json_response({"status": "error", "message": "Missing required fields"}, status=400)

        success = await bot.notify_supervisor(data)
        if success:
            return web.json_response({"status": "success"})
        return web.json_response({"status": "error", "message": "Failed to notify supervisor"}, status=500)
    except Exception as exc:
        return web.json_response({"status": "error", "message": str(exc)}, status=500)


async def handle_warning_post(request):
    try:
        data = await request.json()
        case_id = data.get("case_id")
        alert_title = data.get("alert_title")
        warning_type = data.get("warning_type")

        if not case_id or not alert_title or not warning_type:
            return web.json_response({"status": "error", "message": "Missing required fields"}, status=400)

        success = await bot.send_warning_event(data)
        if success:
            return web.json_response({"status": "success"})
        return web.json_response({"status": "error", "message": "Failed to send warning"}, status=500)
    except Exception as exc:
        return web.json_response({"status": "error", "message": str(exc)}, status=500)


@bot.tree.command(name="ping", description="Responds with pong!")
async def ping(interaction: discord.Interaction):
    await interaction.response.send_message("pong!")


@bot.event
async def on_message(message: discord.Message):
    if message.author == bot.user:
        return

    print(f"[Discord Message] #{message.channel} @{message.author}: {message.content}")
    if isinstance(message.channel, discord.TextChannel):
        await _persist_ticket_reply_notification(message)
    await bot.process_commands(message)


async def _persist_ticket_reply_notification(message: discord.Message) -> None:
    channel = message.channel
    if not channel.category or channel.category.name != "Tickets":
        return

    case_id = _extract_case_id_from_channel(channel)
    if not case_id:
        return

    content = message.content.strip()
    if not content and not message.attachments:
        return

    if message.attachments:
        attachment_names = ", ".join(attachment.filename for attachment in message.attachments[:5])
        content = f"{content}\nAttachments: {attachment_names}".strip()

    try:
        notification_id = NotificationsRepository().add_discord_reply_notification(
            case_id,
            {
                "message": content,
                "author_name": str(message.author),
                "author_id": str(message.author.id),
                "channel_id": str(channel.id),
                "channel_name": channel.name,
                "message_url": message.jump_url,
            },
        )
        if notification_id:
            print(f"Stored Discord reply notification {notification_id} for case {case_id}")
    except Exception as exc:
        print(f"Failed to store Discord reply notification for case {case_id}: {exc}")


def main():
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token or token == "YOUR_DISCORD_BOT_TOKEN_HERE":
        print("Error: DISCORD_BOT_TOKEN is not configured in backend/.env")
        sys.exit(1)

    print("Starting Discord Bot...")
    bot.run(token)


if __name__ == "__main__":
    main()
