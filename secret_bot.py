"""Скрытый бот-тайник. Фраза -> секрет под спойлером. Всё стирается за 30 сек.

Запуск:
    BOT_TOKEN=...  SECRET_BOT_PASSWORD=...  python secret_bot.py
Если переменные не заданы — спросит при старте.

Хранилище: Upstash Redis (если задан UPSTASH_REDIS_REST_URL), иначе локальный
файл secrets.enc. В обоих случаях данные зашифрованы мастер-паролем.

Формат store: {uid: {"pin": str|None, "items": {phrase: {"s": secret, "once": bool}}}}
"""
import asyncio, base64, getpass, hashlib, html, json, os, sys, threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.fernet import Fernet, InvalidToken
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

TTL = 30                      # секунд до удаления любого сообщения
DATA_FILE = "secrets.enc"
REDIS_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
BLOB_KEY = "secret_bot:blob"

fernet: Fernet = None         # ставится в load()
SALT = b""
store: dict = {}              # см. формат в докстринге
msg_log: dict = {}            # {chat_id: set(message_id)} — для /clear и /wipe
pending: dict = {}            # {uid: {"step": "phrase"|"secret", "phrase": str, "once": bool}}
unlocked: dict = {}           # {uid: True} — открыт ли PIN-замок (в памяти, до /lock или рестарта)
menu_snap: dict = {}          # {uid: [phrase,...]} — снимок для кнопок удаления в /list
_tasks: set = set()           # ссылки на задачи удаления, чтобы их не съел GC


# ---- хранилище (шифрованный blob в Upstash Redis или в файле) ----------
def _key(password: str, salt: bytes) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _redis(*cmd):
    req = urllib.request.Request(
        REDIS_URL, data=json.dumps(cmd).encode(),
        headers={"Authorization": f"Bearer {REDIS_TOKEN}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r).get("result")


def _read_blob():
    if REDIS_URL:
        return _redis("GET", BLOB_KEY)                       # str | None
    return open(DATA_FILE, encoding="utf-8").read() if os.path.exists(DATA_FILE) else None


def _write_blob(text: str):
    if REDIS_URL:
        _redis("SET", BLOB_KEY, text)
    else:
        open(DATA_FILE, "w", encoding="utf-8").write(text)


def _migrate():
    # старый формат {phrase: "secret"} -> новый {"pin": None, "items": {...}}
    for uid, u in list(store.items()):
        if not (isinstance(u, dict) and isinstance(u.get("items"), dict) and "pin" in u):
            old = u if isinstance(u, dict) else {}
            store[uid] = {"pin": None,
                          "items": {p: (s if isinstance(s, dict) else {"s": s, "once": False})
                                    for p, s in old.items()}}


def load(password: str):
    global fernet, store, SALT
    blob = _read_blob()
    if blob:
        obj = json.loads(blob)
        SALT = base64.b64decode(obj["salt"])
        fernet = Fernet(_key(password, SALT))
        try:
            store = json.loads(fernet.decrypt(obj["data"].encode()).decode())
        except InvalidToken:
            sys.exit("Неверный мастер-пароль — выход.")
        _migrate()
    else:
        SALT = os.urandom(16)
        fernet = Fernet(_key(password, SALT))
        store = {}
        save()


def save():
    # ponytail: синхронный HTTP в async-хендлере. Трафик низкий -> микро-задержка ок.
    token = fernet.encrypt(json.dumps(store).encode()).decode()
    _write_blob(json.dumps({"salt": base64.b64encode(SALT).decode(), "data": token}))


def _user(uid: str) -> dict:
    return store.setdefault(uid, {"pin": None, "items": {}})


def _items(uid: str) -> dict:
    return _user(uid)["items"]


# ---- автоудаление сообщений --------------------------------------------
async def _del_later(bot, chat_id, msg_id, delay):
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, msg_id)
    except Exception:
        pass  # ponytail: чужое/старое (>48ч) сообщение бот удалить не может — игнор
    msg_log.get(chat_id, set()).discard(msg_id)


def ttl_delete(context, chat_id, msg_id, delay=TTL):
    msg_log.setdefault(chat_id, set()).add(msg_id)
    t = asyncio.create_task(_del_later(context.bot, chat_id, msg_id, delay))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


async def clear_messages(context, chat_id, extra_id=None):
    ids = list(msg_log.get(chat_id, set()))
    if extra_id:
        ids.append(extra_id)
    for mid in ids:
        try:
            await context.bot.delete_message(chat_id, mid)
        except Exception:
            pass
    msg_log[chat_id] = set()


async def reply(update, context, text, **kw):
    m = await update.message.reply_text(text, **kw)
    ttl_delete(context, m.chat_id, m.message_id)
    return m


async def _guard(update, context) -> bool:
    """Заблокировано PIN-ом? Тогда отвечает 🔒 и возвращает True (для явных команд)."""
    uid = str(update.effective_user.id)
    if _user(uid)["pin"] and not unlocked.get(uid):
        await reply(update, context, "🔒 Заблокировано. Открой: /unlock КОД")
        return True
    return False


# ---- команды -----------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    await reply(update, context,
                "Тайник.\n"
                "• Спрятать:  /add\n"
                "• Секрет на один раз:  /once\n"
                "• Достать:  просто напиши свою фразу\n"
                "• Мои фразы / удалить:  /list\n"
                "• PIN-замок:  /pin 1234  (открыть /unlock 1234, закрыть /lock)\n"
                "• Стереть переписку:  /clear\n"
                "• Удалить всё:  /wipe\n\n"
                "Всё исчезает через 30 секунд.")


async def add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    if await _guard(update, context):
        return
    pending[str(update.effective_user.id)] = {"step": "phrase", "once": False}
    await reply(update, context, "Пришли кодовую фразу одним сообщением:")


async def once(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    if await _guard(update, context):
        return
    pending[str(update.effective_user.id)] = {"step": "phrase", "once": True}
    await reply(update, context, "Секрет сгорит после первого показа.\nПришли кодовую фразу:")


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    pending.pop(str(update.effective_user.id), None)
    await reply(update, context, "Отменено.")


async def list_(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    if await _guard(update, context):
        return
    uid = str(update.effective_user.id)
    phrases = list(_items(uid).keys())
    if not phrases:
        await reply(update, context, "Пусто.")
        return
    menu_snap[uid] = phrases
    kb = [[InlineKeyboardButton(f"❌ {p}", callback_data=f"del:{i}")]
          for i, p in enumerate(phrases)]
    m = await update.message.reply_text("Твои фразы (нажми, чтобы удалить):",
                                        reply_markup=InlineKeyboardMarkup(kb))
    ttl_delete(context, m.chat_id, m.message_id)


async def on_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = str(q.from_user.id)
    if _user(uid)["pin"] and not unlocked.get(uid):
        await q.answer("🔒 Открой через /unlock", show_alert=True)
        return
    await q.answer()
    i = int(q.data.split(":")[1])
    snap = menu_snap.get(uid, [])
    if 0 <= i < len(snap):
        _items(uid).pop(snap[i], None)
        save()
    phrases = list(_items(uid).keys())
    menu_snap[uid] = phrases
    try:
        if phrases:
            kb = [[InlineKeyboardButton(f"❌ {p}", callback_data=f"del:{j}")]
                  for j, p in enumerate(phrases)]
            await q.edit_message_text("Твои фразы (нажми, чтобы удалить):",
                                      reply_markup=InlineKeyboardMarkup(kb))
        else:
            await q.edit_message_text("Пусто.")
    except Exception:
        pass  # сообщение уже могло удалиться по TTL


async def pin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    uid = str(update.effective_user.id)
    u = _user(uid)
    if not context.args:
        await reply(update, context,
                    "PIN: /pin 1234 — поставить/сменить, /pin off — снять.\n"
                    "Открыть: /unlock 1234,  закрыть: /lock")
        return
    # смена/снятие требует, чтобы замок уже был открыт
    if u["pin"] and not unlocked.get(uid):
        await reply(update, context, "Сначала /unlock старым кодом.")
        return
    if context.args[0].lower() == "off":
        u["pin"] = None
        unlocked.pop(uid, None)
        save()
        await reply(update, context, "PIN снят.")
        return
    u["pin"] = context.args[0]     # ponytail: PIN лежит внутри уже зашифрованного blob; хэш не даёт выигрыша (сервер и так расшифровывает всё мастер-паролем)
    unlocked[uid] = True
    save()
    await reply(update, context, "PIN установлен. 🔒 Теперь бот открывается через /unlock КОД.")


async def unlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    uid = str(update.effective_user.id)
    u = _user(uid)
    if not u["pin"]:
        await reply(update, context, "PIN не установлен.")
        return
    if context.args and context.args[0] == u["pin"]:
        unlocked[uid] = True
        await reply(update, context, "Открыто. 🔓")
    else:
        await reply(update, context, "Неверный код.")


async def lock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    unlocked.pop(str(update.effective_user.id), None)
    await reply(update, context, "Закрыто. 🔒")


async def clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # только сообщения; фразы остаются. Молча — бот ничего после себя не оставляет.
    pending.pop(str(update.effective_user.id), None)
    await clear_messages(context, update.effective_chat.id, update.message.message_id)


async def wipe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _guard(update, context):     # под замком стереть всё нельзя
        return
    uid = str(update.effective_user.id)
    pending.pop(uid, None)
    confirmed = context.args and context.args[0].lower() in ("да", "yes", "y", "да!")
    if not confirmed:
        ttl_delete(context, update.effective_chat.id, update.message.message_id)
        await reply(update, context,
                    "Это удалит ВСЕ твои фразы, без возврата.\nТочно? Напиши:  /wipe да")
        return
    store.pop(uid, None)
    unlocked.pop(uid, None)
    try:
        save()
    except Exception:
        pass  # даже если не записалось — сообщения всё равно чистим
    await clear_messages(context, update.effective_chat.id, update.message.message_id)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    uid = str(update.effective_user.id)
    text = update.message.text.strip()

    st = pending.get(uid)
    if st:                                    # идёт диалог /add или /once
        if st["step"] == "phrase":
            st["phrase"] = text
            st["step"] = "secret"
            await reply(update, context, "Теперь пришли секрет одним сообщением:")
        else:
            phrase = st["phrase"].casefold()
            once_flag = st["once"]
            pending.pop(uid, None)
            _items(uid)[phrase] = {"s": text, "once": once_flag}
            try:
                save()
            except Exception:
                _items(uid).pop(phrase, None)   # откат, чтобы память не разошлась с хранилищем
                await reply(update, context, "Не сохранилось — попробуй ещё раз (/add).")
                return
            await reply(update, context, "Сохранено. 🔥✅" if once_flag else "Сохранено. ✅")
        return

    # обычный запрос фразы
    if _user(uid)["pin"] and not unlocked.get(uid):
        return                                # под замком — молчим (скрытность)
    entry = _items(uid).get(text.casefold())
    if entry:
        secret = entry["s"] if isinstance(entry, dict) else entry
        await reply(update, context,
                    f"<tg-spoiler>{html.escape(secret)}</tg-spoiler>", parse_mode="HTML")
        if isinstance(entry, dict) and entry.get("once"):
            _items(uid).pop(text.casefold(), None)   # сгорело
            save()
    # неизвестная фраза -> молчим (полная скрытность)


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass


def _serve_health():
    # держит открытым порт для health-чека Render и пинга cron-job.org
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8000"))), _Health).serve_forever()


async def _post_init(app):
    await app.bot.set_my_commands([
        ("add", "спрятать секрет"),
        ("once", "секрет, сгорающий после прочтения"),
        ("list", "мои фразы / удалить"),
        ("unlock", "открыть (PIN)"),
        ("lock", "закрыть"),
        ("pin", "поставить/сменить PIN"),
        ("clear", "стереть переписку"),
        ("wipe", "удалить всё"),
        ("cancel", "отмена"),
    ])


def main():
    token = os.environ.get("BOT_TOKEN") or getpass.getpass("BOT_TOKEN: ")
    password = os.environ.get("SECRET_BOT_PASSWORD") or getpass.getpass("Мастер-пароль: ")
    load(password)
    threading.Thread(target=_serve_health, daemon=True).start()
    app = Application.builder().token(token).post_init(_post_init).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("add", add))
    app.add_handler(CommandHandler("once", once))
    app.add_handler(CommandHandler("list", list_))
    app.add_handler(CommandHandler("pin", pin))
    app.add_handler(CommandHandler("unlock", unlock))
    app.add_handler(CommandHandler("lock", lock))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(CommandHandler("wipe", wipe))
    app.add_handler(CallbackQueryHandler(on_delete, pattern=r"^del:"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling()


if __name__ == "__main__":
    main()
