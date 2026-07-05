"""Скрытый бот-тайник. Фраза -> секрет под спойлером. Всё стирается за 30 сек.

Запуск:
    BOT_TOKEN=...  SECRET_BOT_PASSWORD=...  python secret_bot.py
Если переменные не заданы — спросит при старте.

Хранилище: Upstash Redis (если задан UPSTASH_REDIS_REST_URL), иначе локальный
файл secrets.enc. В обоих случаях секреты зашифрованы мастер-паролем.
"""
import asyncio, base64, getpass, hashlib, html, json, os, sys, threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.fernet import Fernet, InvalidToken
from telegram import Update
from telegram.ext import (Application, CommandHandler, ContextTypes,
                          MessageHandler, filters)

TTL = 30                      # секунд до удаления любого сообщения
DATA_FILE = "secrets.enc"
REDIS_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
BLOB_KEY = "secret_bot:blob"

fernet: Fernet = None         # ставится в load()
SALT = b""
store: dict = {}              # {user_id(str): {phrase_norm: secret}}
msg_log: dict = {}            # {chat_id: set(message_id)} — для /wipe
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
    else:
        SALT = os.urandom(16)
        fernet = Fernet(_key(password, SALT))
        store = {}
        save()


def save():
    # ponytail: синхронный HTTP в async-хендлере. Трафик низкий -> микро-задержка ок.
    token = fernet.encrypt(json.dumps(store).encode()).decode()
    _write_blob(json.dumps({"salt": base64.b64encode(SALT).decode(), "data": token}))


# ---- автоудаление сообщений --------------------------------------------
async def _del_later(bot, chat_id, msg_id, delay):
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, msg_id)
    except Exception:
        pass  # ponytail: чужое/старое (>48ч) сообщение бот удалить не может — игнор
    msg_log.get(chat_id, set()).discard(msg_id)


def ttl_delete(context, chat_id, msg_id):
    msg_log.setdefault(chat_id, set()).add(msg_id)
    t = asyncio.create_task(_del_later(context.bot, chat_id, msg_id, TTL))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


async def reply(update, context, text, **kw):
    m = await update.message.reply_text(text, **kw)
    ttl_delete(context, m.chat_id, m.message_id)
    return m


# ---- команды -----------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    await reply(update, context,
                "Тайник.\n"
                "• Спрятать:  /add фраза | секрет\n"
                "• Достать:   просто напиши фразу\n"
                "• Стереть всё:  /wipe\n\n"
                "Всё исчезает через 30 секунд.")


async def add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    text = update.message.text.partition(" ")[2]
    if "|" not in text:
        await reply(update, context, "Формат: /add фраза | секрет")
        return
    phrase, _, secret = text.partition("|")
    phrase, secret = phrase.strip().casefold(), secret.strip()
    if not phrase or not secret:
        await reply(update, context, "Пустая фраза или секрет.")
        return
    uid = str(update.effective_user.id)
    store.setdefault(uid, {})[phrase] = secret
    try:
        save()
    except Exception:
        store[uid].pop(phrase, None)          # откат, чтобы память не разошлась с хранилищем
        await reply(update, context, "Не сохранилось — попробуй ещё раз.")
        return
    await reply(update, context, "Сохранено. ✅")


async def wipe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    store.pop(str(update.effective_user.id), None)
    save()
    for mid in list(msg_log.get(chat_id, set())) + [update.message.message_id]:
        try:
            await context.bot.delete_message(chat_id, mid)
        except Exception:
            pass
    msg_log[chat_id] = set()
    m = await context.bot.send_message(chat_id, "Всё стёрто. 🧹")
    ttl_delete(context, chat_id, m.message_id)


async def lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ttl_delete(context, update.effective_chat.id, update.message.message_id)
    key = update.message.text.strip().casefold()
    secret = store.get(str(update.effective_user.id), {}).get(key)
    if secret:
        await reply(update, context,
                    f"<tg-spoiler>{html.escape(secret)}</tg-spoiler>",
                    parse_mode="HTML")
    else:
        await reply(update, context, "Нет такой фразы.")


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass


def _serve_health():
    # держит открытым порт для health-чека Render и пинга cron-job.org
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8000"))), _Health).serve_forever()


def main():
    token = os.environ.get("BOT_TOKEN") or getpass.getpass("BOT_TOKEN: ")
    password = os.environ.get("SECRET_BOT_PASSWORD") or getpass.getpass("Мастер-пароль: ")
    load(password)
    threading.Thread(target=_serve_health, daemon=True).start()
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("add", add))
    app.add_handler(CommandHandler("wipe", wipe))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lookup))
    app.run_polling()


if __name__ == "__main__":
    main()
