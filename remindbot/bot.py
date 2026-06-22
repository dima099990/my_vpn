#!/usr/bin/env python3
import json, time, os, asyncio
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

load_dotenv("/opt/vpnserver/.env")

BOT_TOKEN = os.getenv("REMIND_BOT_TOKEN", "")
DOMAIN = os.getenv("REMIND_DOMAIN", "remind.shocknet.online")
REMINDERS_FILE = Path("/opt/remindbot/reminders.json")
USERS_FILE = Path("/opt/remindbot/users.json")

# ── storage ──────────────────────────────────────────────────────────────────
def load_reminders() -> list:
    try:
        return json.loads(REMINDERS_FILE.read_text())
    except Exception:
        return []

def save_reminders(reminders: list):
    REMINDERS_FILE.write_text(json.dumps(reminders, indent=2, ensure_ascii=False))

def load_users() -> dict:
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {"admin_id": 0, "users": {}, "sessions": {}}

def save_users(db: dict):
    USERS_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False))

# ── handlers ─────────────────────────────────────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    kb = [
        [InlineKeyboardButton("🌐 Открыть сайт", url=f"https://{DOMAIN}")],
        [InlineKeyboardButton("➕ Добавить напоминание", callback_data="add")],
        [InlineKeyboardButton("📋 Мои напоминания", callback_data="list")],
    ]
    await update.message.reply_text(
        f"👋 Привет, {user.first_name}!\n\n"
        f"Я *RemindMe* — бот напоминаний.\n\n"
        f"Добавляй напоминания через сайт или прямо здесь.\n"
        f"Формат: `YYYY-MM-DD HH:MM текст`",
        reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")

async def cmd_remind(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "Формат: `/remind 2025-12-31 18:00 Поздравить маму`",
            parse_mode="Markdown")
        return

    try:
        dt_str = " ".join(ctx.args[:2])
        text = " ".join(ctx.args[2:])
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M")
        if dt <= datetime.now():
            await update.message.reply_text("❌ Время уже прошло.")
            return
        if not text:
            await update.message.reply_text("❌ Укажи текст напоминания.")
            return
    except ValueError:
        await update.message.reply_text(
            "❌ Неверный формат. Используй: `YYYY-MM-DD HH:MM текст`",
            parse_mode="Markdown")
        return

    reminders = load_reminders()
    import secrets
    r = {
        "id": secrets.token_hex(8),
        "tg_id": update.effective_user.id,
        "text": text,
        "remind_at": dt.isoformat(),
        "created_at": datetime.now().isoformat(),
        "sent": False,
    }
    reminders.append(r)
    save_reminders(reminders)

    await update.message.reply_text(
        f"✅ Напоминание создано!\n\n"
        f"📅 {dt.strftime('%d.%m.%Y %H:%M')}\n"
        f"📝 {text}")

async def cb_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "Отправь мне напоминание в формате:\n\n"
        "`2025-12-31 18:00 Поздравить маму`",
        parse_mode="Markdown")

async def cb_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    tg_id = query.from_user.id
    reminders = [r for r in load_reminders() if r["tg_id"] == tg_id]
    if not reminders:
        await query.edit_message_text("📋 У тебя нет напоминаний.")
        return

    lines = ["📋 *Твои напоминания:*\n"]
    for r in sorted(reminders, key=lambda x: x["remind_at"], reverse=True)[:10]:
        status = "✅" if r["sent"] else "⏳"
        try:
            dt = datetime.fromisoformat(r["remind_at"])
            time_str = dt.strftime("%d.%m %H:%M")
        except Exception:
            time_str = r["remind_at"]
        lines.append(f"{status} `{time_str}` — {r['text']}")

    kb = [[InlineKeyboardButton("« Назад", callback_data="back")]]
    await query.edit_message_text("\n".join(lines),
        reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")

async def cb_back(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    kb = [
        [InlineKeyboardButton("🌐 Открыть сайт", url=f"https://{DOMAIN}")],
        [InlineKeyboardButton("➕ Добавить напоминание", callback_data="add")],
        [InlineKeyboardButton("📋 Мои напоминания", callback_data="list")],
    ]
    await query.edit_message_text(
        "Выбери действие:",
        reply_markup=InlineKeyboardMarkup(kb))

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    parts = text.split(" ", 2)
    if len(parts) >= 3:
        try:
            dt = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M")
            remind_text = parts[2]
            if dt <= datetime.now():
                await update.message.reply_text("❌ Время уже прошло.")
                return
            if not remind_text:
                await update.message.reply_text("❌ Укажи текст.")
                return

            import secrets
            reminders = load_reminders()
            r = {
                "id": secrets.token_hex(8),
                "tg_id": update.effective_user.id,
                "text": remind_text,
                "remind_at": dt.isoformat(),
                "created_at": datetime.now().isoformat(),
                "sent": False,
            }
            reminders.append(r)
            save_reminders(reminders)
            await update.message.reply_text(
                f"✅ Напоминание создано!\n\n"
                f"📅 {dt.strftime('%d.%m.%Y %H:%M')}\n"
                f"📝 {remind_text}")
            return
        except ValueError:
            pass
    await update.message.reply_text(
        "Используй формат: `YYYY-MM-DD HH:MM текст`",
        parse_mode="Markdown")

# ── scheduler ────────────────────────────────────────────────────────────────
async def check_reminders(app):
    now = datetime.now()
    reminders = load_reminders()
    changed = False
    for r in reminders:
        if r["sent"]:
            continue
        try:
            rt = datetime.fromisoformat(r["remind_at"])
            if rt <= now:
                try:
                    await app.bot.send_message(
                        chat_id=r["tg_id"],
                        text=f"🔔 *Напоминание!*\n\n📝 {r['text']}",
                        parse_mode="Markdown")
                    r["sent"] = True
                    changed = True
                except Exception:
                    pass
        except Exception:
            pass
    if changed:
        save_reminders(reminders)

async def post_init(app):
    app.create_task(_scheduler_loop(app))

async def _scheduler_loop(app):
    while True:
        await check_reminders(app)
        await asyncio.sleep(30)

def main():
    import asyncio
    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("remind", cmd_remind))
    app.add_handler(CallbackQueryHandler(cb_add, pattern="^add$"))
    app.add_handler(CallbackQueryHandler(cb_list, pattern="^list$"))
    app.add_handler(CallbackQueryHandler(cb_back, pattern="^back$"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    print("RemindBot started")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
