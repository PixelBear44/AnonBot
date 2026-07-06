"""Скрытый бот-тайник. Фраза -> секрет под спойлером. Чистится вручную: /clear, /wipe.

Запуск:
    BOT_TOKEN=...  SECRET_BOT_PASSWORD=...  python secret_bot.py
Если переменные не заданы — спросит при старте.

Хранилище: Upstash Redis (если задан UPSTASH_REDIS_REST_URL), иначе локальный
файл secrets.enc. В обоих случаях данные зашифрованы мастер-паролем.

Формат store: {uid: {"pin": str|None, "items": {phrase: {"s": secret, "once": bool}}}}
"""
import base64, getpass, hashlib, html, json, os, sys, threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.fernet import Fernet, InvalidToken
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

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


def _pin(uid: str):
    # чтение без создания пустой записи (в отличие от _user)
    u = store.get(uid)
    return u["pin"] if u else None


# ---- учёт сообщений (для ручного /clear и /wipe) -----------------------
def track(chat_id, msg_id):
    msg_log.setdefault(chat_id, set()).add(msg_id)


async def track_incoming(update, context):
    # group=-1: запоминаем ЛЮБОЕ входящее сообщение (текст, команды, фото, стикеры),
    # чтобы /clear и /wipe могли его удалить.
    m = update.effective_message
    if m:
        track(m.chat_id, m.message_id)


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
    track(m.chat_id, m.message_id)
    return m


async def _guard(update, context) -> bool:
    """Заблокировано PIN-ом? Тогда отвечает 🔒 и возвращает True (для явных команд)."""
    uid = str(update.effective_user.id)
    if _pin(uid) and not unlocked.get(uid):
        await reply(update, context, "🔒 Бот закрыт паролем. Открой: /unlock КОД")
        return True
    return False


# ---- команды -----------------------------------------------------------
HELP = (
    "🔒 <b>Тайник</b> — прячет секреты за кодовой фразой.\n\n"
    "Придумываешь фразу и прячешь за ней секрет. Потом пишешь эту фразу боту — "
    "он показывает секрет под спойлером (нажать, чтобы увидеть).\n\n"
    "<b>Команды</b>\n"
    "📥 /add — спрятать секрет (спросит фразу, потом секрет)\n"
    "🔥 /once — то же, но секрет сгорит после первого показа\n"
    "🔎 Достать — просто напиши свою фразу\n"
    "📋 /list — список твоих фраз, удалить лишние\n"
    "🔑 /pin 1234 — поставить пароль на бота\n"
    "     /unlock 1234 — открыть · /lock — закрыть\n"
    "🧹 /clear — стереть всю переписку (фразы остаются)\n"
    "💣 /wipe — удалить вообще всё (фразы + переписку)\n\n"
    "⚠️ Само ничего не удаляется — чисти через /clear или /wipe."
)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await reply(update, context, HELP, parse_mode="HTML")


async def add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _guard(update, context):
        return
    pending[str(update.effective_user.id)] = {"step": "phrase", "once": False}
    await reply(update, context, "Шаг 1 из 2.\nПришли кодовую фразу — по ней потом достанешь секрет:")


async def once(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _guard(update, context):
        return
    pending[str(update.effective_user.id)] = {"step": "phrase", "once": True}
    await reply(update, context,
                "🔥 Секрет сгорит сразу после первого показа.\n"
                "Шаг 1 из 2.\nПришли кодовую фразу:")


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    pending.pop(str(update.effective_user.id), None)
    await reply(update, context, "Отменено.")


LIST_HEADER = "📋 Твои фразы. Нажми на любую, чтобы удалить.\n(🔥 — сгорит после первого показа)"


def _list_kb(uid):
    items = _items(uid)
    return [[InlineKeyboardButton(("🔥 " if items[p].get("once") else "") + f"❌ {p}",
                                  callback_data=f"del:{i}")]
            for i, p in enumerate(items)]


async def list_(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _guard(update, context):
        return
    uid = str(update.effective_user.id)
    if not _items(uid):
        await reply(update, context, "Пусто. Спрячь первый секрет: /add")
        return
    menu_snap[uid] = list(_items(uid).keys())
    m = await update.message.reply_text(LIST_HEADER,
                                        reply_markup=InlineKeyboardMarkup(_list_kb(uid)))
    track(m.chat_id, m.message_id)


async def on_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = str(q.from_user.id)
    if _pin(uid) and not unlocked.get(uid):
        await q.answer("🔒 Открой через /unlock", show_alert=True)
        return
    i = int(q.data.split(":")[1])
    snap = menu_snap.get(uid, [])
    if 0 <= i < len(snap):
        _items(uid).pop(snap[i], None)
        save()
        await q.answer("Удалено")
    else:
        await q.answer()
    menu_snap[uid] = list(_items(uid).keys())
    try:
        if _items(uid):
            await q.edit_message_text(LIST_HEADER,
                                      reply_markup=InlineKeyboardMarkup(_list_kb(uid)))
        else:
            await q.edit_message_text("Пусто. Спрячь секрет: /add")
    except Exception:
        pass  # сообщение уже могло быть удалено через /clear


async def pin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    u = _user(uid)
    if not context.args:
        await reply(update, context,
                    "🔑 Пароль на бота.\n"
                    "Поставить или сменить:  /pin 1234\n"
                    "Снять:  /pin off\n"
                    "Открыть:  /unlock 1234  ·  Закрыть:  /lock")
        return
    # смена/снятие требует, чтобы замок уже был открыт
    if u["pin"] and not unlocked.get(uid):
        await reply(update, context, "Сначала открой старым кодом:  /unlock СТАРЫЙ_КОД")
        return
    if context.args[0].lower() == "off":
        u["pin"] = None
        unlocked.pop(uid, None)
        save()
        await reply(update, context, "Пароль снят 🔓 Бот снова открыт.")
        return
    u["pin"] = context.args[0]     # ponytail: PIN лежит внутри уже зашифрованного blob; хэш не даёт выигрыша (сервер и так расшифровывает всё мастер-паролем)
    unlocked[uid] = True
    save()
    await reply(update, context,
                "Пароль установлен ✅ Сейчас бот открыт.\n"
                "Он закроется после /lock или перезапуска — тогда открывай командой /unlock КОД.")


async def unlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if not _pin(uid):
        await reply(update, context, "Пароль не установлен. Поставить:  /pin 1234")
        return
    if context.args and context.args[0] == _pin(uid):
        unlocked[uid] = True
        await reply(update, context, "Открыто 🔓")
    else:
        await reply(update, context, "Неверный код.")


async def lock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    unlocked.pop(str(update.effective_user.id), None)
    await reply(update, context, "Закрыто 🔒 Секреты скрыты. Открыть: /unlock КОД")


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
        await reply(update, context,
                    "💣 Удалит ВСЕ твои фразы и всю переписку. Вернуть будет нельзя.\n"
                    "Точно? Напиши:  /wipe да")
        return
    store.pop(uid, None)
    unlocked.pop(uid, None)
    try:
        save()
    except Exception:
        pass  # даже если не записалось — сообщения всё равно чистим
    await clear_messages(context, update.effective_chat.id, update.message.message_id)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    text = update.message.text.strip()

    st = pending.get(uid)
    if st:                                    # идёт диалог /add или /once
        if st["step"] == "phrase":
            st["phrase"] = text
            st["step"] = "secret"
            await reply(update, context, "Шаг 2 из 2.\nТеперь пришли сам секрет:")
        else:
            phrase = st["phrase"].casefold()
            once_flag = st["once"]
            pending.pop(uid, None)
            _items(uid)[phrase] = {"s": text, "once": once_flag}
            try:
                save()
            except Exception:
                _items(uid).pop(phrase, None)   # откат, чтобы память не разошлась с хранилищем
                await reply(update, context, "⚠️ Не сохранилось — попробуй ещё раз: /add")
                return
            await reply(update, context,
                        "Готово 🔥 Секрет спрятан и сгорит после первого показа."
                        if once_flag else
                        "Готово ✅ Секрет спрятан. Напиши свою фразу, чтобы достать его.")
        return

    # обычный запрос фразы
    if _pin(uid) and not unlocked.get(uid):
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
        ("add", "📥 спрятать секрет"),
        ("once", "🔥 секрет на один показ"),
        ("list", "📋 мои фразы (удалить)"),
        ("unlock", "🔓 открыть бота паролем"),
        ("lock", "🔒 закрыть бота"),
        ("pin", "🔑 поставить/сменить пароль"),
        ("clear", "🧹 стереть переписку"),
        ("wipe", "💣 удалить всё"),
        ("help", "❓ помощь"),
    ])


def main():
    token = os.environ.get("BOT_TOKEN") or getpass.getpass("BOT_TOKEN: ")
    password = os.environ.get("SECRET_BOT_PASSWORD") or getpass.getpass("Мастер-пароль: ")
    load(password)
    threading.Thread(target=_serve_health, daemon=True).start()
    app = Application.builder().token(token).post_init(_post_init).build()
    app.add_handler(MessageHandler(filters.ALL, track_incoming), group=-1)  # учёт всех сообщений
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
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
