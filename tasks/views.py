from django.shortcuts import render
import csv
import json
import secrets
import base64
import time
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


def key_for_device(master: bytes, device_id: str) -> bytes:
    """Диверсификация ключей согласно п.4.5 ТЗ — уникальный ключ для каждого устройства."""
    return HKDF(hashes.SHA256(), 32, device_id.encode("utf-8"), b"wms-lr3").derive(master)


def encrypt_and_decrypt(aes: AESGCM, text: str):
    """Шифрование и расшифрование пакета с замером времени в миллисекундах."""
    raw = text.encode("utf-8")
    nonce = secrets.token_bytes(12)

    t0 = time.perf_counter()
    ct = aes.encrypt(nonce, raw, None)
    t_enc = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    restored = aes.decrypt(nonce, ct, None)
    t_dec = (time.perf_counter() - t0) * 1000

    return nonce, ct, len(raw), t_enc, t_dec, restored.decode() == text


def attacker_decrypt(aes_wrong: AESGCM, nonce: bytes, ct: bytes):
    """Имитация попытки злоумышленника расшифровать перехваченный пакет."""
    t0 = time.perf_counter()
    try:
        aes_wrong.decrypt(nonce, ct, None)
        t_att = (time.perf_counter() - t0) * 1000
        return True, t_att
    except InvalidTag:
        t_att = (time.perf_counter() - t0) * 1000
        return False, t_att


def index(request):
    """Главная страница — возвращает шаблон index.html."""
    return render(request, 'encryption_app/index.html')


@csrf_exempt
def encrypt(request):
    """
    Обработка POST-запроса с пакетами ТСД.
    Принимает список пакетов: [{device, user, data}, ...].
    Возвращает: таблицы результатов шифрования, атаки, статистику и пути к графикам.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Метод не поддерживается'}, status=405)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Некорректный JSON'}, status=400)

    packets = body.get('packets', [])
    if not packets:
        return JsonResponse({'error': 'Введите хотя бы один пакет'}, status=400)

    SECRET_KEY = secrets.token_bytes(32)
    ATTACKER_KEY = secrets.token_bytes(32)

    results = []
    attack_results = []
    encrypted_pairs = []

    # --- Легитимная передача ---
    for p in packets:
        device = p.get('device', '').strip()
        user = p.get('user', '').strip()
        data = p.get('data', '').strip()
        if not device or not data:
            continue

        key = key_for_device(SECRET_KEY, device)
        aes = AESGCM(key)
        nonce, ct, size, t_enc, t_dec, ok = encrypt_and_decrypt(aes, data)
        encrypted_pairs.append((device, nonce, ct))

        results.append({
            "device": device,
            "user": user,
            "data": data,
            "size": size,
            "wire_size": len(nonce) + len(ct),
            "encrypted": base64.b64encode(ct).decode()[:24] + "...",
            "t_enc": round(t_enc, 6),
            "t_dec": round(t_dec, 6),
            "status": "OK" if ok else "ОШИБКА",
        })

    if not results:
        return JsonResponse({'error': 'Нет корректных пакетов для обработки'}, status=400)

    # --- Попытка злоумышленника ---
    for (device, nonce, ct) in encrypted_pairs:
        wrong_key = key_for_device(ATTACKER_KEY, device)
        wrong_aes = AESGCM(wrong_key)
        read, t_att = attacker_decrypt(wrong_aes, nonce, ct)
        attack_results.append({
            "device": device,
            "result": "ДАННЫЕ ЗАЩИЩЕНЫ" if not read else "СКОМПРОМЕТИРОВАНЫ",
            "t_att": round(t_att, 6),
        })

    # --- Статистика ---
    successful = sum(1 for r in results if r['status'] == 'OK')
    compromised = sum(1 for r in attack_results if r['result'] == 'СКОМПРОМЕТИРОВАНЫ')
    avg_enc = round(sum(r['t_enc'] for r in results) / len(results), 6)
    avg_dec = round(sum(r['t_dec'] for r in results) / len(results), 6)

    stats = {
        "total": len(results),
        "successful": successful,
        "attacked": len(attack_results),
        "compromised": compromised,
        "avg_enc": avg_enc,
        "avg_dec": avg_dec,
        "key_hex": SECRET_KEY.hex()[:8] + "..." + SECRET_KEY.hex()[-4:],
    }

    # --- Автосохранение CSV в папку csv_exports/ (как в main.py) ---
    csv_dir = os.path.join(os.path.dirname(__file__), '..', 'csv_exports')
    os.makedirs(csv_dir, exist_ok=True)

    enc_path = os.path.join(csv_dir, 'encryption_log.csv')
    with open(enc_path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow([
            'Устройство', 'Пользователь', 'Исходный пакет',
            'Исх. размер (байт)', 'Зашифр. размер (байт)',
            'Время шифр. (мс)', 'Время расшифр. (мс)', 'Статус',
        ])
        for r in results:
            w.writerow([
                r['device'], r.get('user', ''), r['data'],
                r['size'], r['wire_size'], r['t_enc'], r['t_dec'], r['status'],
            ])

    att_path = os.path.join(csv_dir, 'attacker_log.csv')
    with open(att_path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(['Устройство', 'Результат перехвата', 'Время атаки (мс)'])
        for r in attack_results:
            w.writerow([r['device'], r['result'], r['t_att']])

    # --- Построение графиков ---
    static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
    os.makedirs(static_dir, exist_ok=True)

    n = len(results)
    x = np.arange(1, n + 1)
    enc_times = [r['t_enc'] for r in results]
    dec_times = [r['t_dec'] for r in results]
    sizes = [r['size'] for r in results]
    wire_sizes = [r['wire_size'] for r in results]

    # График 1: Время шифрования и расшифрования
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.plot(x, enc_times, 'b-o', lw=2, ms=8, label='Шифрование', alpha=0.8)
    ax.plot(x, dec_times, 'r-s', lw=2, ms=8, label='Расшифрование', alpha=0.8)
    for i, (te, td) in enumerate(zip(enc_times, dec_times)):
        ax.annotate(f'{te:.4f}', (x[i], te), textcoords="offset points",
                    xytext=(0, 10), ha='center', fontsize=8, color='blue')
        ax.annotate(f'{td:.4f}', (x[i], td), textcoords="offset points",
                    xytext=(0, -15), ha='center', fontsize=8, color='red')
    ax.set_xlabel('Номер пакета')
    ax.set_ylabel('Время (миллисекунды)')
    ax.set_title('Время шифрования и расшифрования пакетов ТСД')
    ax.set_xticks(x)
    ax.legend(loc='upper left')
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, 'chart_time.png'), dpi=120)
    plt.close()

    # График 2: Сравнение размеров пакетов
    fig, ax = plt.subplots(figsize=(14, 6))
    width = 0.35
    bars1 = ax.bar(x - width / 2, sizes, width, label='Исходные данные',
                   color='#3498DB', edgecolor='k', alpha=0.8)
    bars2 = ax.bar(x + width / 2, wire_sizes, width, label='После шифрования',
                   color='#E74C3C', edgecolor='k', alpha=0.8)
    for i, (s, w) in enumerate(zip(sizes, wire_sizes)):
        ax.text(x[i] - width / 2, s + 0.5, str(s), ha='center', va='bottom', fontsize=9)
        ax.text(x[i] + width / 2, w + 0.5, str(w), ha='center', va='bottom', fontsize=9)
    ax.set_xlabel('Номер пакета')
    ax.set_ylabel('Размер (байт)')
    ax.set_title('Сравнение размера пакетов до и после шифрования')
    ax.set_xticks(x)
    ax.legend()
    ax.grid(True, axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, 'chart_size.png'), dpi=120)
    plt.close()

    return JsonResponse({
        'results': results,
        'attack_results': attack_results,
        'stats': stats,
        'chart_time': '/static/chart_time.png',
        'chart_size': '/static/chart_size.png',
    })



# Create your views here.
