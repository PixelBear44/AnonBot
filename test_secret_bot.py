"""Проверки: шифрование (round-trip + чужой пароль) и миграция старого формата.
Запуск: python test_secret_bot.py"""
import json
from cryptography.fernet import Fernet, InvalidToken
from secret_bot import _key, store, _migrate


def test_roundtrip_and_wrong_password():
    salt = b"0123456789abcdef"
    data = {"42": {"кодовая фраза": "мой секрет"}}
    token = Fernet(_key("правильный", salt)).encrypt(json.dumps(data).encode())

    assert json.loads(Fernet(_key("правильный", salt)).decrypt(token)) == data

    try:
        Fernet(_key("чужой", salt)).decrypt(token)
        assert False, "чужой пароль не должен расшифровывать"
    except InvalidToken:
        pass


def test_migrate_old_to_new():
    store.clear()
    store["7"] = {"фраза": "секрет"}                 # старый формат
    _migrate()
    u = store["7"]
    assert u["pin"] is None
    assert u["items"]["фраза"] == {"s": "секрет", "once": False}
    _migrate()                                        # повторно — не ломается
    assert store["7"]["items"]["фраза"]["s"] == "секрет"
    store.clear()


if __name__ == "__main__":
    test_roundtrip_and_wrong_password()
    test_migrate_old_to_new()
    print("ok")
