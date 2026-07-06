"""Проверки крипто- и денежного пути. Запуск: python test_secret_bot.py"""
import base64, json, os
from cryptography.fernet import Fernet, InvalidToken
from secret_bot import _key, _enc, _dec, _migrate, store


def test_master_roundtrip_and_wrong_password():
    salt = b"0123456789abcdef"
    data = {"42": {"v": 2}}
    token = Fernet(_key("правильный", salt)).encrypt(json.dumps(data).encode())
    assert json.loads(Fernet(_key("правильный", salt)).decrypt(token)) == data
    try:
        Fernet(_key("чужой", salt)).decrypt(token)
        assert False, "чужой пароль не должен расшифровывать"
    except InvalidToken:
        pass


def test_user_code_roundtrip_and_wrong():
    salt = os.urandom(16)
    key = _key("mypass", salt)
    blob = _enc({"ф": {"s": "тайна", "once": False}}, key)
    assert _dec(blob, key)["ф"]["s"] == "тайна"
    try:
        _dec(blob, _key("wrong", salt))
        assert False, "чужой код не должен расшифровывать"
    except InvalidToken:
        pass


def test_migrate_v1_no_pin():
    store.clear()
    store["7"] = {"pin": None, "items": {"фраза": {"s": "секрет", "once": False}}}
    _migrate()
    u = store["7"]
    assert u["v"] == 2 and u["code_salt"] is None and u["blob"] is None
    assert u["items"]["фраза"]["s"] == "секрет"
    store.clear()


def test_migrate_v1_with_pin_encrypts():
    store.clear()
    store["7"] = {"pin": "1234", "items": {"ф": {"s": "тайна", "once": False}}}
    _migrate()
    u = store["7"]
    assert u["v"] == 2 and u["code_salt"] and u["blob"] and u["items"] == {}
    got = _dec(u["blob"], _key("1234", base64.b64decode(u["code_salt"])))
    assert got["ф"]["s"] == "тайна"
    store.clear()


def test_migrate_very_old_bare():
    store.clear()
    store["7"] = {"фраза": "секрет"}          # самый старый формат
    _migrate()
    assert store["7"]["v"] == 2
    assert store["7"]["items"]["фраза"] == {"s": "секрет", "once": False}
    store.clear()


def test_migrate_idempotent():
    store.clear()
    store["7"] = {"pin": "1234", "items": {"ф": {"s": "x", "once": False}}}
    _migrate()
    salt1 = store["7"]["code_salt"]
    _migrate()                                 # повторно — v2 уже, не трогаем
    assert store["7"]["code_salt"] == salt1
    store.clear()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
