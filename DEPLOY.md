# Деплой бота-тайника (бесплатно, без карты, 24/7)

Три бесплатных сервиса. Ни один не просит карту. ~15 минут.

## 1. Бот у BotFather
1. Открой в Telegram **@BotFather** → `/newbot` → задай имя и username.
2. Скопируй **токен** (`123456:ABC...`) — это `BOT_TOKEN`.

## 2. Код на GitHub
Render деплоит из GitHub-репозитория.
1. Заведи аккаунт на **github.com** (если нет).
2. Создай новый репозиторий (можно приватный) → кнопка **"uploading an existing file"** →
   перетащи туда файлы: `secret_bot.py`, `requirements.txt`, `render.yaml`, `.gitignore`.
   (Файл `secrets.enc` не загружай — он не нужен, секреты будут в Upstash.)

## 3. Хранилище — Upstash Redis
1. Заведи аккаунт на **upstash.com** (вход через Google/GitHub, карта не нужна).
2. **Create Database** → любое имя, тип Regional, регион поближе → Create.
3. На странице базы найди блок **REST API** и скопируй:
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`

## 4. Запуск на Render
1. Заведи аккаунт на **render.com** (вход через GitHub, карта не нужна).
2. **New → Blueprint** → выбери свой репозиторий (Render прочитает `render.yaml`).
3. Он попросит заполнить 4 переменные:
   - `BOT_TOKEN` — из шага 1
   - `SECRET_BOT_PASSWORD` — придумай пароль и **запомни** (шифрует секреты; забудешь — не расшифруешь)
   - `UPSTASH_REDIS_REST_URL` и `UPSTASH_REDIS_REST_TOKEN` — из шага 3
4. **Apply / Deploy**. В логах через минуту — «Application started». Скопируй адрес сервиса
   вида `https://secret-bot-xxxx.onrender.com`.

## 5. Чтобы не засыпал — пинг
Render free засыпает после 15 мин без запросов. Будим бесплатным пингом:
1. Заведи аккаунт на **cron-job.org** (карта не нужна).
2. **Create cronjob** → URL = адрес твоего сервиса с шага 4 → интервал **каждые 10 минут** → Save.

## Готово
Ссылка для людей: `https://t.me/ТВОЙ_БОТ_username`.
Бот работает без твоего ПК. Секреты переживают перезапуски (лежат в Upstash, зашифрованы).

---
### Мелочи
- Обновить код: залей новый `secret_bot.py` в GitHub — Render передеплоит сам.
- 750 бесплатных часов Render/мес хватает ровно на один сервис 24/7.
- Локально протестить без облака: не задавай `UPSTASH_*` — секреты лягут в файл `secrets.enc`.
