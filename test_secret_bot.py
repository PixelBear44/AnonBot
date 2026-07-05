"""Проверка денежного/секретного пути: шифрование переживает round-trip,
чужой пароль — не расшифровывает. Запуск: python test_secret_bot.py"""
import json
from cryptography.fernet import Fernet, InvalidToken
from secret_bot import _key


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


if __name__ == "__main__":
    test_roundtrip_and_wrong_password()
    print("ok")
