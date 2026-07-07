<div align="center">

# 🔒 AnonBot — a secret keeper for Telegram

**Hide secrets behind a code phrase.** Type the phrase to the bot — it shows the secret under a spoiler.
Nothing extra, everything is cleared manually, and secrets can be encrypted with a personal code.

![Python](https://img.shields.io/badge/python-3.12-blue)
![python-telegram-bot](https://img.shields.io/badge/python--telegram--bot-21%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

🌐 [Русский](README.md) · **English**

</div>

---

## What it is

A tiny Telegram bot that stores your secrets behind code phrases.
Come up with a phrase → hide text behind it → later type that phrase and the
bot reveals the secret under a spoiler. One person can create as many
`phrase → secret` pairs as they like.

Optionally everything is encrypted with your personal code, which the bot
**does not store** — then even whoever runs the bot can't read the database
contents (see the [security section](#-security--privacy) — it honestly
explains the limits).

## Features

- 🗝 **Secrets by phrase** — type a phrase, get the secret under a `spoiler`.
- 🔥 **Burn-after-reading** — `/once` creates a secret that disappears after the first view.
- 🔑 **Personal-code encryption** — `/code` encrypts your secrets; the bot never stores the code.
- 🛡 **Brute-force protection** — 5 wrong `/unlock` attempts → cooldown.
- ⏱ **Auto-lock** — the code re-locks itself after inactivity.
- 🆘 **Panic code** — enter a decoy code in `/unlock` and everything is silently wiped.
- 🤫 **Stealth** — the bot doesn't reply at all to an unknown phrase.
- 🧹 **Manual cleanup** — `/clear` wipes the chat, `/wipe` deletes everything.

## Commands

| Command | What it does |
|---|---|
| `/add` | hide a secret (asks for a phrase, then the secret) |
| `/once` | a secret that burns after the first view |
| *(type a phrase)* | reveal the secret under a spoiler |
| `/list` | list your phrases, delete unwanted ones |
| `/code CODE` | encrypt secrets with a personal code (`/code off` — remove) |
| `/unlock CODE` | open access · `/lock` — close |
| `/panic CODE` | decoy code: wipes everything when entered in `/unlock` |
| `/clear` | wipe the whole chat (secrets remain) |
| `/wipe` | delete absolutely everything |
| `/help` | help |

## 🔐 Security & privacy

An honest take on who this protects against — and who it doesn't.

**Protected:**
- Data in the database (Upstash) is encrypted with a master password (Fernet, key via PBKDF2·200k). The DB provider and the network see only ciphertext over TLS.
- With `/code`, secrets are additionally encrypted with your code, which exists neither in the database nor in the bot's code. They can't be pulled from the DB without the code.

**NOT protected (important to understand):**
- **Telegram Bot API is not end-to-end.** All messages (phrases, secrets, codes) pass through Telegram's servers in plaintext.
- **The server operator** can reach the secrets if they want: without `/code` — directly with the master password; with `/code` — by intercepting the `/unlock` input or reading process memory. A server-side bot fundamentally can't be unreachable to whoever runs it.
- **Revealed secrets stay in the chat** until you run `/clear`.
- A short `/code` (e.g. `1234`) can be brute-forced offline — use a long random phrase.

**Bottom line:** a great personal stash and protection "from prying eyes and database theft," but not a tool against the server operator or Telegram itself. For maximum safety — a strong `/code` and regular `/clear`.

## 🚀 Run your own (free, 24/7)

Full step-by-step guide in [DEPLOY.md](DEPLOY.md). In short, all on free tiers, no credit card:

1. **[@BotFather](https://t.me/BotFather)** → `/newbot` → get `BOT_TOKEN`.
2. **[Upstash](https://upstash.com)** → create a Redis DB → grab `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
3. **[Render](https://render.com)** → New → Blueprint → pick your fork of this repo → set 4 variables (`BOT_TOKEN`, `SECRET_BOT_PASSWORD` — make one up, `UPSTASH_*`) → Deploy.
4. **[cron-job.org](https://cron-job.org)** → ping the service URL every 10 minutes so Render doesn't sleep.

Done — a link like `https://t.me/YOUR_BOT` works without your PC.

> ⚠️ `SECRET_BOT_PASSWORD` is the only key to all data that isn't protected by a personal `/code`. Make it long and random, and **don't change it**: changing it = old data can no longer be decrypted.

## 🧑‍💻 Local run

```bash
pip install -r requirements.txt

# Linux/macOS
BOT_TOKEN=... SECRET_BOT_PASSWORD=... python secret_bot.py

# Windows PowerShell
$env:BOT_TOKEN="..."; $env:SECRET_BOT_PASSWORD="..."; python secret_bot.py
```

Without the variables the bot asks for them at startup. If `UPSTASH_*` isn't
set, secrets go into a local encrypted file `secrets.enc` (handy for testing).

Tests:

```bash
python test_secret_bot.py
```

## 🧱 Stack

- [python-telegram-bot](https://python-telegram-bot.org/) — Telegram Bot API (long polling)
- [cryptography](https://cryptography.io/) — Fernet (AES) + PBKDF2 for encryption
- [Upstash Redis](https://upstash.com/) — storage (encrypted blob)
- [Render](https://render.com/) — free hosting

A single file — [`secret_bot.py`](secret_bot.py), ~460 lines.

## 📄 License

MIT — use, fork, and modify freely.
