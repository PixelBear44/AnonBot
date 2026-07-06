"""Скрытый бот-тайник. Фраза -> секрет под спойлером. Чистится вручную: /clear, /wipe.

Запуск:
    BOT_TOKEN=...  SECRET_BOT_PASSWORD=...  python secret_bot.py
Если переменные не заданы — спросит при старте.

Хранилище: Upstash Redis (если задан UPSTASH_REDIS_REST_URL), иначе локальный
файл secrets.enc. Весь store шифруется мастер-паролем перед записью.

Код доступа (опционально, на пользователя) ДОПОЛНИТЕЛЬНО шифрует его секреты
ключом, выведенным из этого кода. Бот код не хранит -> без кода секреты не
прочитает даже сервер. Забыл код -> секреты потеряны навсегда.

Формат записи (v2):
    {uid: {"v":2, "code_salt": b64|None, "blob": str|None, "items": {...},
           "panic": str|None, "fails": int, "lock_until": float}}
    - есть код:  code_salt+blob заданы, items пустой (секреты внутри blob);
    - нет кода:  code_salt/blob = None, секреты лежат в items открыто.
"""
import base64, getpass, hashlib, html, json, os, sys, threading, time
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

UNLOCK_TIMEOUT = 300          # сек бездействия до автозакрытия кода
MAX_FAILS = 5                 # неверных попыток /unlock до паузы
LOCKOUT = 60                  # сек паузы после MAX_FAILS

fernet: Fernet = None         # мастер-шифрование store; ставится в load()
SALT = b""
store: dict = {}              # см. формат в докстринге
msg_log: dict = {}            # {chat_id: set(message_id)} — для /clear и /wipe
pending: dict = {}            # {uid: {"step","phrase","once"}} — диалог /add и /once
sess: dict = {}               # {uid: {"items": {...}, "key": bytes, "last": ts}} — открытая сессия кода
menu_snap: dict = {}          # {uid: [phrase,...]} — снимок для кнопок удаления в /list


# ---- крипто/хранилище --------------------------------------------------
def _key(code: str, salt: bytes) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", code.encode(), salt, 200_000, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _enc(items: dict, key: bytes) -> str:
    return Fernet(key).encrypt(json.dumps(items).encode()).decode()


def _dec(blob: str, key: bytes) -> dict:
    return json.loads(Fernet(key).decrypt(blob.encode()).decode())


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


def _new_user() -> dict:
    return {"v": 2, "code_salt": None, "blob": None, "items": {},
            "panic": None, "fails": 0, "lock_until": 0}


def _migrate():
    # приводим любую старую запись к формату v2
    for uid, u in list(store.items()):
        if isinstance(u, dict) and u.get("v") == 2:
            continue
        rec = _new_user()
        old_pin = None
        if isinstance(u, dict) and isinstance(u.get("items"), dict) and "pin" in u:
            old_items, old_pin = u["items"], u.get("pin")        # формат v1
        elif isinstance(u, dict):
            old_items = u                                        # самый старый {phrase: secret}
        else:
            old_items = {}
        items = {p: (s if isinstance(s, dict) else {"s": s, "once": False})
                 for p, s in old_items.items()}
        if old_pin:                                              # старый PIN -> код доступа
            salt = os.urandom(16)
            rec["code_salt"] = base64.b64encode(salt).decode()
            rec["blob"] = _enc(items, _key(old_pin, salt))
        else:
            rec["items"] = items
        store[uid] = rec


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


# ---- доступ к секретам пользователя ------------------------------------
def _user(uid: str) -> dict:
    return store.setdefault(uid, _new_user())


def _has_code(uid: str) -> bool:
    u = store.get(uid)
    return bool(u and u.get("code_salt"))


def _is_open(uid: str) -> bool:
    """Открыт ли доступ. Без кода — всегда. С кодом — если сессия жива (продлевает её)."""
    if not _has_code(uid):
        return True
    s = sess.get(uid)
    if not s:
        return False
    if time.time() - s["last"] > UNLOCK_TIMEOUT:
        sess.pop(uid, None)
        return False
    s["last"] = time.time()
    return True


def _current_items(uid: str) -> dict:
    # для кода вызывать только когда _is_open(uid) == True
    return sess[uid]["items"] if _has_code(uid) else _user(uid)["items"]


def _save_items(uid: str):
    if _has_code(uid):
        s = sess[uid]
        _user(uid)["blob"] = _enc(s["items"], s["key"])
    save()


def _wipe_user(uid: str):
    store.pop(uid, None)
    sess.pop(uid, None)
    pending.pop(uid, None)
    menu_snap.pop(uid, None)


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
    """Закрыто кодом? Отвечает 🔒 и возвращает True (для явных команд)."""
    uid = str(update.effective_user.id)
    if _has_code(uid) and not _is_open(uid):
        await reply(update, context, "🔒 Бот закрыт кодом. Открой: /unlock КОД")
        return True
    return False


# ---- команды -----------------------------------------------------------
HELP = (
    "🔒 <b>Тайник</b> — прячет секреты за кодовой фразой.\n\n"
    "Придумываешь фразу и прячешь за ней секрет. Потом пишешь эту фразу боту — "
    "он показывает секрет под спойлером (нажать, чтобы увидеть).\n\n"
    "<b>Секреты</b>\n"
    "📥 /add — спрятать секрет (спросит фразу, потом секрет)\n"
    "🔥 /once — то же, но секрет сгорит после первого показа\n"
    "🔎 Достать — просто напиши свою фразу\n"
    "📋 /list — список фраз, удалить лишние\n\n"
    "<b>Защита (по желанию)</b>\n"
    "🔑 /code МОЙКОД — зашифровать секреты кодом (сервер их не прочитает)\n"
    "🔓 /unlock МОЙКОД — открыть · 🔒 /lock — закрыть\n"
    "🆘 /panic КОД — код-ловушка: введёшь его в /unlock — всё сотрётся\n\n"
    "<b>Уборка</b>\n"
    "🧹 /clear — стереть переписку (секреты остаются)\n"
    "💣 /wipe — удалить вообще всё\n\n"
    "⚠️ Само ничего не удаляется. Забудешь код — секреты не вернуть."
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
    items = _current_items(uid)
    return [[InlineKeyboardButton(("🔥 " if items[p].get("once") else "") + f"❌ {p}",
                                  callback_data=f"del:{i}")]
            for i, p in enumerate(items)]


async def list_(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _guard(update, context):
        return
    uid = str(update.effective_user.id)
    if not _current_items(uid):
        await reply(update, context, "Пусто. Спрячь первый секрет: /add")
        return
    menu_snap[uid] = list(_current_items(uid).keys())
    m = await update.message.reply_text(LIST_HEADER,
                                        reply_markup=InlineKeyboardMarkup(_list_kb(uid)))
    track(m.chat_id, m.message_id)


async def on_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = str(q.from_user.id)
    if _has_code(uid) and not _is_open(uid):
        await q.answer("🔒 Открой через /unlock", show_alert=True)
        return
    i = int(q.data.split(":")[1])
    snap = menu_snap.get(uid, [])
    if 0 <= i < len(snap):
        _current_items(uid).pop(snap[i], None)
        _save_items(uid)
        await q.answer("Удалено")
    else:
        await q.answer()
    menu_snap[uid] = list(_current_items(uid).keys())
    try:
        if _current_items(uid):
            await q.edit_message_text(LIST_HEADER,
                                      reply_markup=InlineKeyboardMarkup(_list_kb(uid)))
        else:
            await q.edit_message_text("Пусто. Спрячь секрет: /add")
    except Exception:
        pass  # сообщение уже могло быть удалено через /clear


async def code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    u = _user(uid)
    if not context.args:
        await reply(update, context,
                    "🔑 Код доступа шифрует твои секреты — без него их не прочитает даже сервер.\n"
                    "Поставить или сменить:  /code МОЙКОД\n"
                    "Снять:  /code off\n"
                    "Открыть:  /unlock МОЙКОД  ·  Закрыть:  /lock\n"
                    "⚠️ Забудешь код — секреты не вернуть.")
        return
    if _has_code(uid) and not _is_open(uid):
        await reply(update, context, "Сначала открой старым кодом:  /unlock КОД")
        return
    if context.args[0].lower() == "off":
        if not _has_code(uid):
            await reply(update, context, "Код не установлен.")
            return
        u["items"] = dict(sess[uid]["items"])       # возвращаем секреты в открытый вид
        u["code_salt"] = None
        u["blob"] = None
        sess.pop(uid, None)
        save()
        await reply(update, context, "Код снят 🔓 Секреты больше не зашифрованы личным кодом.")
        return
    new_code = context.args[0]
    items = dict(sess[uid]["items"]) if _has_code(uid) else dict(u["items"])
    salt = os.urandom(16)
    key = _key(new_code, salt)
    u["code_salt"] = base64.b64encode(salt).decode()
    u["blob"] = _enc(items, key)
    u["items"] = {}
    u["fails"] = 0
    u["lock_until"] = 0
    sess[uid] = {"items": items, "key": key, "last": time.time()}
    save()
    await reply(update, context,
                "Код установлен ✅ Секреты зашифрованы — сервер их не прочитает.\n"
                "Сейчас открыто; закроется после /lock или бездействия.\n"
                "⚠️ Забудешь код — секреты потеряны навсегда.")


async def unlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    u = _user(uid)
    if not _has_code(uid):
        await reply(update, context, "Код не установлен. Поставить:  /code 1234")
        return
    now = time.time()
    if u.get("lock_until", 0) > now:
        await reply(update, context, f"Слишком много попыток. Подожди {int(u['lock_until'] - now)} сек.")
        return
    guess = context.args[0] if context.args else ""
    if u.get("panic") and guess == u["panic"]:               # паник-код: молча стираем всё
        _wipe_user(uid)
        await clear_messages(context, update.effective_chat.id)
        await context.bot.send_message(update.effective_chat.id, "Открыто 🔓")
        return
    try:
        items = _dec(u["blob"], _key(guess, base64.b64decode(u["code_salt"])))
    except InvalidToken:
        u["fails"] = u.get("fails", 0) + 1
        if u["fails"] >= MAX_FAILS:
            u["lock_until"] = now + LOCKOUT
            u["fails"] = 0
            save()
            await reply(update, context, f"Неверный код. Пауза {LOCKOUT} сек.")
        else:
            save()
            await reply(update, context, f"Неверный код. Осталось попыток: {MAX_FAILS - u['fails']}")
        return
    sess[uid] = {"items": items, "key": _key(guess, base64.b64decode(u["code_salt"])), "last": now}
    u["fails"] = 0
    u["lock_until"] = 0
    save()
    await reply(update, context, "Открыто 🔓")


async def lock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sess.pop(str(update.effective_user.id), None)
    await reply(update, context, "Закрыто 🔒 Секреты скрыты. Открыть: /unlock КОД")


async def panic(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    u = _user(uid)
    if not context.args:
        await reply(update, context,
                    "🆘 Паник-код — ловушка. Введёшь его в /unlock — все секреты и переписка "
                    "молча сотрутся.\nПоставить:  /panic 0000  ·  Убрать:  /panic off")
        return
    if _has_code(uid) and not _is_open(uid):
        await reply(update, context, "Сначала открой: /unlock КОД")
        return
    if context.args[0].lower() == "off":
        u["panic"] = None
        save()
        await reply(update, context, "Паник-код убран.")
        return
    cand = context.args[0]
    if _has_code(uid):                       # паник не должен совпадать с настоящим кодом
        try:
            _dec(u["blob"], _key(cand, base64.b64decode(u["code_salt"])))
            await reply(update, context, "Паник-код должен отличаться от основного кода.")
            return
        except InvalidToken:
            pass
    u["panic"] = cand
    save()
    await reply(update, context,
                "Паник-код установлен. Введёшь его в /unlock — всё сотрётся без предупреждения.")


async def clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # только сообщения; секреты остаются. Молча — бот ничего после себя не оставляет.
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
    _wipe_user(uid)
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
            if _has_code(uid) and not _is_open(uid):        # код закрылся посреди диалога
                await reply(update, context, "🔒 Бот закрылся. Открой /unlock и начни заново: /add")
                return
            _current_items(uid)[phrase] = {"s": text, "once": once_flag}
            try:
                _save_items(uid)
            except Exception:
                _current_items(uid).pop(phrase, None)   # откат, чтобы память не разошлась с хранилищем
                await reply(update, context, "⚠️ Не сохранилось — попробуй ещё раз: /add")
                return
            await reply(update, context,
                        "Готово 🔥 Секрет спрятан и сгорит после первого показа."
                        if once_flag else
                        "Готово ✅ Секрет спрятан. Напиши свою фразу, чтобы достать его.")
        return

    # обычный запрос фразы
    if _has_code(uid) and not _is_open(uid):
        return                                # под замком — молчим (скрытность)
    items = _current_items(uid)
    entry = items.get(text.casefold())
    if entry:
        secret = entry["s"] if isinstance(entry, dict) else entry
        await reply(update, context,
                    f"<tg-spoiler>{html.escape(secret)}</tg-spoiler>", parse_mode="HTML")
        if isinstance(entry, dict) and entry.get("once"):
            items.pop(text.casefold(), None)   # сгорело
            _save_items(uid)
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
        ("code", "🔑 зашифровать кодом"),
        ("unlock", "🔓 открыть"),
        ("lock", "🔒 закрыть"),
        ("panic", "🆘 паник-код"),
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
    app.add_handler(CommandHandler("code", code))
    app.add_handler(CommandHandler("pin", code))       # алиас для привычки
    app.add_handler(CommandHandler("unlock", unlock))
    app.add_handler(CommandHandler("lock", lock))
    app.add_handler(CommandHandler("panic", panic))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(CommandHandler("wipe", wipe))
    app.add_handler(CallbackQueryHandler(on_delete, pattern=r"^del:"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling()


if __name__ == "__main__":
    main()
