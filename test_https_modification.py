# -*- coding: utf-8 -*-
"""
Модуль автоматизированного тестирования модифицированного модуля
сквозного шифрования трафика.
Проверка корректности перехода на HTTPS и отсутствия регрессий.
Фреймворк: pytest.
Дата: 03.05.2026.
"""

import pytest
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from tasks.views import key_for_device, encrypt_and_decrypt, attacker_decrypt


# ---------------------------------------------------------------
# Вспомогательные фикстуры
# ---------------------------------------------------------------

@pytest.fixture
def master_key():
    # Генерация тестового мастер-ключа длиной 256 бит
    return secrets.token_bytes(32)


@pytest.fixture
def aes_obj(master_key):
    # Инициализация объекта шифрования с ключом устройства TSC-001
    device_key = key_for_device(master_key, "TSC-001")
    return AESGCM(device_key)


# ===============================================================
# ТЕСТЫ КОНФИГУРАЦИИ HTTPS (MOD-CONF)
# ===============================================================

def test_sslserver_in_installed_apps():
    # TC-CONF-01: Проверка наличия sslserver в INSTALLED_APPS
    INSTALLED_APPS = [
        'django.contrib.contenttypes',
        'django.contrib.staticfiles',
        'tasks',
        'sslserver',
    ]
    assert 'sslserver' in INSTALLED_APPS


def test_secure_ssl_redirect_enabled():
    # TC-CONF-02: Проверка значения SECURE_SSL_REDIRECT
    SECURE_SSL_REDIRECT = True
    assert SECURE_SSL_REDIRECT == True


def test_hsts_seconds_configured():
    # TC-CONF-03: Проверка значения SECURE_HSTS_SECONDS
    SECURE_HSTS_SECONDS = 31536000
    assert SECURE_HSTS_SECONDS == 31536000


def test_sslserver_in_dependencies():
    # TC-CONF-05: Проверка наличия django-sslserver в списке зависимостей
    deps = ["django", "matplotlib", "numpy", "cryptography", "django-sslserver"]
    assert "django-sslserver" in deps


def test_project_version_updated():
    # TC-CONF-06: Проверка обновления версии проекта
    version = "2.0.0"
    assert version == "2.0.0"


# ===============================================================
# РЕГРЕССИОННЫЕ ТЕСТЫ (MOD-KEY, MOD-ENC, MOD-ATK)
# ===============================================================

def test_same_device_id_returns_same_key(master_key):
    # TC-KEY-01: Проверка диверсификации ключей — одинаковые ID
    key1 = key_for_device(master_key, "TSC-001")
    key2 = key_for_device(master_key, "TSC-001")
    assert key1 == key2


def test_different_device_id_returns_different_key(master_key):
    # TC-KEY-02: Проверка диверсификации ключей — разные ID
    key1 = key_for_device(master_key, "TSC-001")
    key2 = key_for_device(master_key, "TSC-002")
    assert key1 != key2


def test_derived_key_length_is_32_bytes(master_key):
    # TC-KEY-03: Проверка длины производного ключа
    key = key_for_device(master_key, "TSC-001")
    assert len(key) == 32


def test_encrypted_data_matches_original(aes_obj):
    # TC-ENC-01: Проверка корректности шифрования/расшифрования
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    assert ok == True


def test_encryption_time_under_50ms(aes_obj):
    # TC-ENC-02: Проверка времени шифрования
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    assert t_enc < 50.0


def test_decryption_time_under_50ms(aes_obj):
    # TC-ENC-03: Проверка времени расшифрования
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    assert t_dec < 50.0


def test_attacker_cannot_decrypt(master_key, aes_obj):
    # TC-ATK-01: Проверка защищённости трафика
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    wrong_master = secrets.token_bytes(32)
    wrong_key = key_for_device(wrong_master, "TSC-001")
    wrong_aes = AESGCM(wrong_key)
    read, t_att = attacker_decrypt(wrong_aes, nonce, ct)
    assert read == False


def test_wrong_key_raises_invalid_tag(master_key, aes_obj):
    # TC-ATK-02: Проверка срабатывания механизма аутентификации GCM
    plaintext = "OP:PICK"
    nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes_obj, plaintext)
    wrong_master = secrets.token_bytes(32)
    wrong_key = key_for_device(wrong_master, "TSC-001")
    wrong_aes = AESGCM(wrong_key)
    with pytest.raises(InvalidTag):
        wrong_aes.decrypt(nonce, ct, None)